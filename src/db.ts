import { DatabaseSync } from "node:sqlite";
import path from "node:path";
import { ensureDataDir } from "./config.js";

export interface TrafficDelta {
  hourBucket: string;
  domain: string;
  node: string;
  process: string;
  isClaude: boolean;
  upBytes: number;
  downBytes: number;
  connIncrement: number;
}

export interface GuardEventRecord {
  id?: number;
  ts: string;
  domain: string;
  source: "proxy_http" | "proxy_connect" | "proxy_socks5" | "watchdog_tun" | "watchdog_mode" | "watchdog_ip";
  action: "BLOCK" | "KILL" | "WARN";
  reasonCode: string;
  message: string;
  fixHint: string;
  clashMode: string;
  node: string;
  exitIp: string;
  exitCountry: string;
  process: string;
}

export interface TrafficStatsSummary {
  rangeHours: number;
  totalUpBytes: number;
  totalDownBytes: number;
  claudeUpBytes: number;
  claudeDownBytes: number;
  otherUpBytes: number;
  otherDownBytes: number;
  hourlySeries: Array<{
    hourBucket: string;
    upBytes: number;
    downBytes: number;
    claudeBytes: number;
  }>;
  topDomains: Array<{
    domain: string;
    isClaude: boolean;
    upBytes: number;
    downBytes: number;
    totalBytes: number;
    connCount: number;
  }>;
  topNodes: Array<{
    node: string;
    upBytes: number;
    downBytes: number;
    totalBytes: number;
    connCount: number;
  }>;
  topProcesses: Array<{
    process: string;
    upBytes: number;
    downBytes: number;
    totalBytes: number;
    connCount: number;
  }>;
}

export function formatHourBucket(date = new Date()): string {
  // Format as YYYY-MM-DDTHH:00 in local time
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, "0");
  const d = String(date.getDate()).padStart(2, "0");
  const h = String(date.getHours()).padStart(2, "0");
  return `${y}-${m}-${d}T${h}:00`;
}

export class Store {
  private db: DatabaseSync;

  constructor(dbPath?: string) {
    const dir = ensureDataDir();
    const file = dbPath || path.join(dir, "claudeban.db");
    this.db = new DatabaseSync(file);
    this.init();
  }

  private init(): void {
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = NORMAL;

      CREATE TABLE IF NOT EXISTS traffic_hourly (
        hour_bucket TEXT NOT NULL,
        domain TEXT NOT NULL,
        node TEXT NOT NULL,
        process TEXT NOT NULL,
        is_claude INTEGER NOT NULL DEFAULT 0,
        up_bytes INTEGER NOT NULL DEFAULT 0,
        down_bytes INTEGER NOT NULL DEFAULT 0,
        conn_count INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (hour_bucket, domain, node, process)
      );

      CREATE INDEX IF NOT EXISTS idx_traffic_hourly_bucket ON traffic_hourly(hour_bucket);

      CREATE TABLE IF NOT EXISTS guard_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT NOT NULL,
        domain TEXT NOT NULL,
        source TEXT NOT NULL,
        action TEXT NOT NULL,
        reason_code TEXT NOT NULL,
        message TEXT NOT NULL,
        fix_hint TEXT NOT NULL,
        clash_mode TEXT NOT NULL DEFAULT '',
        node TEXT NOT NULL DEFAULT '',
        exit_ip TEXT NOT NULL DEFAULT '',
        exit_country TEXT NOT NULL DEFAULT '',
        process TEXT NOT NULL DEFAULT ''
      );

      CREATE INDEX IF NOT EXISTS idx_guard_events_ts ON guard_events(ts DESC);
    `);
  }

  recordTrafficDeltas(deltas: TrafficDelta[]): void {
    if (deltas.length === 0) return;

    const stmt = this.db.prepare(`
      INSERT INTO traffic_hourly (hour_bucket, domain, node, process, is_claude, up_bytes, down_bytes, conn_count)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(hour_bucket, domain, node, process) DO UPDATE SET
        is_claude = MAX(traffic_hourly.is_claude, excluded.is_claude),
        up_bytes = traffic_hourly.up_bytes + excluded.up_bytes,
        down_bytes = traffic_hourly.down_bytes + excluded.down_bytes,
        conn_count = traffic_hourly.conn_count + excluded.conn_count
    `);

    this.db.exec("BEGIN");
    try {
      for (const d of deltas) {
        if (d.upBytes === 0 && d.downBytes === 0 && d.connIncrement === 0) continue;
        stmt.run(
          d.hourBucket,
          d.domain || "(unknown)",
          d.node || "DIRECT",
          d.process || "(unknown)",
          d.isClaude ? 1 : 0,
          Math.max(0, Math.floor(d.upBytes)),
          Math.max(0, Math.floor(d.downBytes)),
          Math.max(0, Math.floor(d.connIncrement))
        );
      }
      this.db.exec("COMMIT");
    } catch (err) {
      this.db.exec("ROLLBACK");
      throw err;
    }
  }

  recordGuardEvent(ev: GuardEventRecord): void {
    const stmt = this.db.prepare(`
      INSERT INTO guard_events (ts, domain, source, action, reason_code, message, fix_hint, clash_mode, node, exit_ip, exit_country, process)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      ev.ts,
      ev.domain,
      ev.source,
      ev.action,
      ev.reasonCode,
      ev.message,
      ev.fixHint,
      ev.clashMode || "",
      ev.node || "",
      ev.exitIp || "",
      ev.exitCountry || "",
      ev.process || ""
    );
  }

  getStats(rangeHours = 24): TrafficStatsSummary {
    const cutoffDate = new Date(Date.now() - rangeHours * 3600 * 1000);
    const cutoffBucket = formatHourBucket(cutoffDate);

    const totals = this.db
      .prepare(
        `
        SELECT
          COALESCE(SUM(up_bytes), 0) AS totalUp,
          COALESCE(SUM(down_bytes), 0) AS totalDown,
          COALESCE(SUM(CASE WHEN is_claude = 1 THEN up_bytes ELSE 0 END), 0) AS claudeUp,
          COALESCE(SUM(CASE WHEN is_claude = 1 THEN down_bytes ELSE 0 END), 0) AS claudeDown
        FROM traffic_hourly
        WHERE hour_bucket >= ?
      `
      )
      .get(cutoffBucket) as {
      totalUp: number;
      totalDown: number;
      claudeUp: number;
      claudeDown: number;
    };

    const hourlyRows = this.db
      .prepare(
        `
        SELECT
          hour_bucket AS hourBucket,
          SUM(up_bytes) AS upBytes,
          SUM(down_bytes) AS downBytes,
          SUM(CASE WHEN is_claude = 1 THEN up_bytes + down_bytes ELSE 0 END) AS claudeBytes
        FROM traffic_hourly
        WHERE hour_bucket >= ?
        GROUP BY hour_bucket
        ORDER BY hour_bucket ASC
      `
      )
      .all(cutoffBucket) as Array<{
      hourBucket: string;
      upBytes: number;
      downBytes: number;
      claudeBytes: number;
    }>;

    const topDomains = this.db
      .prepare(
        `
        SELECT
          domain,
          MAX(is_claude) AS isClaude,
          SUM(up_bytes) AS upBytes,
          SUM(down_bytes) AS downBytes,
          SUM(up_bytes + down_bytes) AS totalBytes,
          SUM(conn_count) AS connCount
        FROM traffic_hourly
        WHERE hour_bucket >= ?
        GROUP BY domain
        ORDER BY totalBytes DESC
        LIMIT 25
      `
      )
      .all(cutoffBucket) as Array<{
      domain: string;
      isClaude: number;
      upBytes: number;
      downBytes: number;
      totalBytes: number;
      connCount: number;
    }>;

    const topNodes = this.db
      .prepare(
        `
        SELECT
          node,
          SUM(up_bytes) AS upBytes,
          SUM(down_bytes) AS downBytes,
          SUM(up_bytes + down_bytes) AS totalBytes,
          SUM(conn_count) AS connCount
        FROM traffic_hourly
        WHERE hour_bucket >= ?
        GROUP BY node
        ORDER BY totalBytes DESC
        LIMIT 20
      `
      )
      .all(cutoffBucket) as Array<{
      node: string;
      upBytes: number;
      downBytes: number;
      totalBytes: number;
      connCount: number;
    }>;

    const topProcesses = this.db
      .prepare(
        `
        SELECT
          process,
          SUM(up_bytes) AS upBytes,
          SUM(down_bytes) AS downBytes,
          SUM(up_bytes + down_bytes) AS totalBytes,
          SUM(conn_count) AS connCount
        FROM traffic_hourly
        WHERE hour_bucket >= ?
        GROUP BY process
        ORDER BY totalBytes DESC
        LIMIT 20
      `
      )
      .all(cutoffBucket) as Array<{
      process: string;
      upBytes: number;
      downBytes: number;
      totalBytes: number;
      connCount: number;
    }>;

    return {
      rangeHours,
      totalUpBytes: Number(totals.totalUp || 0),
      totalDownBytes: Number(totals.totalDown || 0),
      claudeUpBytes: Number(totals.claudeUp || 0),
      claudeDownBytes: Number(totals.claudeDown || 0),
      otherUpBytes: Math.max(0, Number(totals.totalUp || 0) - Number(totals.claudeUp || 0)),
      otherDownBytes: Math.max(0, Number(totals.totalDown || 0) - Number(totals.claudeDown || 0)),
      hourlySeries: hourlyRows.map((r) => ({
        hourBucket: r.hourBucket,
        upBytes: Number(r.upBytes || 0),
        downBytes: Number(r.downBytes || 0),
        claudeBytes: Number(r.claudeBytes || 0),
      })),
      topDomains: topDomains.map((r) => ({
        domain: r.domain,
        isClaude: Boolean(r.isClaude),
        upBytes: Number(r.upBytes || 0),
        downBytes: Number(r.downBytes || 0),
        totalBytes: Number(r.totalBytes || 0),
        connCount: Number(r.connCount || 0),
      })),
      topNodes: topNodes.map((r) => ({
        node: r.node,
        upBytes: Number(r.upBytes || 0),
        downBytes: Number(r.downBytes || 0),
        totalBytes: Number(r.totalBytes || 0),
        connCount: Number(r.connCount || 0),
      })),
      topProcesses: topProcesses.map((r) => ({
        process: r.process,
        upBytes: Number(r.upBytes || 0),
        downBytes: Number(r.downBytes || 0),
        totalBytes: Number(r.totalBytes || 0),
        connCount: Number(r.connCount || 0),
      })),
    };
  }

  getRecentEvents(limit = 100): GuardEventRecord[] {
    const rows = this.db
      .prepare(
        `
        SELECT id, ts, domain, source, action, reason_code AS reasonCode,
               message, fix_hint AS fixHint, clash_mode AS clashMode,
               node, exit_ip AS exitIp, exit_country AS exitCountry, process
        FROM guard_events
        ORDER BY id DESC
        LIMIT ?
      `
      )
      .all(limit) as unknown as GuardEventRecord[];
    return rows;
  }

  getBlockedCount(): number {
    const row = this.db
      .prepare(
        `SELECT COUNT(*) AS cnt FROM guard_events WHERE action IN ('BLOCK', 'KILL')`
      )
      .get() as { cnt: number };
    return Number(row?.cnt || 0);
  }

  clearGuardEvents(): void {
    this.db.exec("DELETE FROM guard_events");
  }

  pruneOldData(days = 90): void {
    const cutoffIso = new Date(Date.now() - days * 86400 * 1000).toISOString();
    const cutoffBucket = formatHourBucket(new Date(Date.now() - days * 86400 * 1000));
    this.db.prepare("DELETE FROM traffic_hourly WHERE hour_bucket < ?").run(cutoffBucket);
    this.db.prepare("DELETE FROM guard_events WHERE ts < ?").run(cutoffIso);
  }

  close(): void {
    this.db.close();
  }
}
