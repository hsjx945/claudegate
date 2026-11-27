import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runAutoFix } from "./auto-fixer.js";
import { saveConfig, type AppConfig } from "./config.js";
import type { Store } from "./db.js";
import type { GuardEngine } from "./guard.js";
import {
  enableGateSystemProxy,
  getLaunchAtLoginStatus,
  getSystemProxyStatus,
  restoreSystemProxy,
  setLaunchAtLogin,
} from "./macos-proxy.js";
import type { MihomoClient } from "./mihomo.js";
import {
  runNetworkDetection,
  type NetworkDetectorProbes,
  type NetworkDetectorReport,
} from "./network-detector.js";
import type { GateProxyServer } from "./proxy-server.js";
import { evaluateDomainRouting } from "./rules-engine.js";
import type { Watchdog } from "./watchdog.js";

function resolvePublicDir(): string {
  const thisDir = path.dirname(fileURLToPath(import.meta.url));
  const candidates = [
    path.resolve(thisDir, "../../public"), // dist/src -> project/public
    path.resolve(thisDir, "../public"), // src -> project/public
    path.resolve(process.cwd(), "public"),
  ];
  for (const dir of candidates) {
    if (fs.existsSync(path.join(dir, "index.html"))) {
      return dir;
    }
  }
  return candidates[0];
}

const MIME_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
};

function sendJson(res: http.ServerResponse, status: number, data: unknown): void {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Cache-Control": "no-store",
  });
  res.end(body);
}

function readJsonBody<T>(req: http.IncomingMessage): Promise<T> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > 1_048_576) {
        req.destroy();
        reject(new Error("Request body too large"));
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      const text = Buffer.concat(chunks).toString("utf8").trim();
      if (!text) {
        resolve({} as T);
        return;
      }
      try {
        resolve(JSON.parse(text) as T);
      } catch (err) {
        reject(err);
      }
    });
    req.on("error", reject);
  });
}

export class DashboardServer {
  private config: AppConfig;
  private mihomo: MihomoClient;
  private guard: GuardEngine;
  private store: Store;
  private proxyServer: GateProxyServer;
  private watchdog: Watchdog;
  private onConfigUpdated?: (cfg: AppConfig) => void;
  private clashVergeDir?: string;
  private detectorProbes?: NetworkDetectorProbes;
  private latestDetectorReport: NetworkDetectorReport | null = null;

  private server: http.Server | null = null;
  private publicDir = resolvePublicDir();

  constructor(deps: {
    config: AppConfig;
    mihomo: MihomoClient;
    guard: GuardEngine;
    store: Store;
    proxyServer: GateProxyServer;
    watchdog: Watchdog;
    onConfigUpdated?: (cfg: AppConfig) => void;
    clashVergeDir?: string;
    detectorProbes?: NetworkDetectorProbes;
  }) {
    this.config = deps.config;
    this.mihomo = deps.mihomo;
    this.guard = deps.guard;
    this.store = deps.store;
    this.proxyServer = deps.proxyServer;
    this.watchdog = deps.watchdog;
    this.onConfigUpdated = deps.onConfigUpdated;
    this.clashVergeDir = deps.clashVergeDir;
    this.detectorProbes = deps.detectorProbes;
  }

  getAddress(): { host: string; port: number } | null {
    const addr = this.server?.address();
    if (!addr || typeof addr === "string") return null;
    return { host: addr.address, port: addr.port };
  }

  start(portOverride?: number): Promise<number> {
    if (this.server) {
      return Promise.resolve(this.getAddress()?.port || this.config.dashboardPort);
    }

    const listenPort = portOverride !== undefined ? portOverride : this.config.dashboardPort;
    return new Promise((resolve, reject) => {
      const server = http.createServer((req, res) => {
        void this.handleRequest(req, res);
      });

      const onError = (err: Error) => {
        server.removeListener("listening", onListening);
        reject(err);
      };
      const onListening = () => {
        server.removeListener("error", onError);
        this.server = server;
        const addr = server.address();
        resolve(addr && typeof addr !== "string" ? addr.port : listenPort);
      };

      server.once("error", onError);
      server.once("listening", onListening);
      server.listen(listenPort, "127.0.0.1");
    });
  }

  stop(): Promise<void> {
    return new Promise((resolve) => {
      if (!this.server) {
        resolve();
        return;
      }
      const srv = this.server;
      this.server = null;
      srv.close(() => resolve());
    });
  }

  private async buildStatusPayload() {
    this.watchdog.flushTraffic();
    const clash = this.guard.getClashSnapshot();
    const exitIp = this.guard.getExitIpState();
    const claudeDecision = this.guard.evaluate("claude.ai");
    const audit = this.guard.auditAllProtectedDomains();
    const primaryNode = this.guard.getPrimaryClaudeNodeInfo();
    const gateStats = this.proxyServer.getStats();
    const systemProxy = await getSystemProxyStatus(
      this.config.proxyPort,
      this.config.upstreamPort
    );

    let health: "safe" | "warn" | "danger" = "safe";
    if (claudeDecision.action === "BLOCK" || audit.dangerCount > 0) {
      health = "danger";
    } else if (
      claudeDecision.action === "WARN" ||
      audit.warnCount > 0 ||
      audit.globalRisk ||
      (clash.connected && audit.missingExplicitRuleDomains.length > 0)
    ) {
      health = "warn";
    }

    const activeAlerts: Array<{
      level: "danger" | "warn";
      code: string;
      title: string;
      detail: string;
      fixHint: string;
      yamlSnippet?: string;
    }> = [];

    if (claudeDecision.action === "BLOCK") {
      activeAlerts.push({
        level: "danger",
        code: claudeDecision.reasonCode,
        title: "Claude 访问当前处于阻断保护状态",
        detail: claudeDecision.message,
        fixHint: claudeDecision.fixHint,
        yamlSnippet: claudeDecision.yamlSnippet,
      });
    } else if (claudeDecision.action === "WARN") {
      activeAlerts.push({
        level: "warn",
        code: claudeDecision.reasonCode,
        title: "检测到潜在路由风险",
        detail: claudeDecision.message,
        fixHint: claudeDecision.fixHint,
        yamlSnippet: claudeDecision.yamlSnippet,
      });
    }

    if (audit.globalRisk && clash.configs?.mode !== "global") {
      activeAlerts.push({
        level: "warn",
        code: "GLOBAL_GROUP_DIRECT",
        title: "GLOBAL 策略组当前指向 DIRECT（潜在手误风险）",
        detail:
          "虽然当前在规则模式下运行正常，但如果误触将 Clash Verge 切换到【全局模式 (Global)】，所有流量会立即直连！",
        fixHint:
          "建议在 Clash Verge 的「代理 -> GLOBAL」中提前选择一个合规非直连节点作为安全备份。",
      });
    }

    if (audit.missingExplicitRuleDomains.length > 0 && clash.connected) {
      activeAlerts.push({
        level: "warn",
        code: "MISSING_ECOSYSTEM_RULES",
        title: `${audit.missingExplicitRuleDomains.length} 个 Claude 关联域名未配置显式代理规则`,
        detail: `包括 ${audit.missingExplicitRuleDomains.slice(0, 6).join(", ")}${
          audit.missingExplicitRuleDomains.length > 6 ? " 等" : ""
        }，目前靠兜底规则转发。`,
        fixHint: "可在下方「规则体检」区域一键复制完整 Clash 覆写规则并粘贴到 Clash Verge。",
        yamlSnippet: audit.recommendedYamlSnippet,
      });
    }

    return {
      health,
      timestamp: new Date().toISOString(),
      gate: {
        proxyAddress: `127.0.0.1:${this.proxyServer.getAddress()?.port || this.config.proxyPort}`,
        dashboardAddress: `127.0.0.1:${this.getAddress()?.port || this.config.dashboardPort}`,
        upstreamAddress: `${this.config.upstreamHost}:${this.config.upstreamPort}`,
        stats: gateStats,
        dbBlockedTotal: this.store.getBlockedCount(),
      },
      clash: {
        connected: clash.connected,
        version: clash.version,
        endpoint: this.mihomo.getEndpoint(),
        mode: clash.configs?.mode || "unknown",
        tunEnabled: Boolean(clash.configs?.tun?.enable),
        tunDevice: clash.configs?.tun?.device || "",
        sniffing: Boolean(clash.configs?.sniffing),
        mixedPort: clash.configs?.["mixed-port"] || this.config.upstreamPort,
        primaryGroup: primaryNode.group,
        primaryChain: primaryNode.chain,
        primaryLeafNode: primaryNode.leaf,
        rulesCount: clash.rules.length,
        lastSyncAt: clash.lastSyncAt,
        lastError: clash.lastError,
      },
      exitIp,
      systemProxy,
      activeAlerts,
      hasFixableIssues: clash.connected && (health !== "safe" || Boolean(this.latestDetectorReport?.hasFixableIssues)),
      detectorSummary: this.latestDetectorReport
        ? {
            checkedAt: this.latestDetectorReport.checkedAt,
            totalScore: this.latestDetectorReport.totalScore,
            grade: this.latestDetectorReport.grade,
            networkType: this.latestDetectorReport.proxyPurity.networkType,
            hosting: this.latestDetectorReport.proxyPurity.hosting,
            proxy: this.latestDetectorReport.proxyPurity.proxy,
            dnsLeaked: this.latestDetectorReport.dnsLeak.leakedToBanned,
            ipv6Leaked: this.latestDetectorReport.ipv6Leak.leaked,
            endpoints: this.latestDetectorReport.endpoints,
          }
        : null,
    };
  }

  private async handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    try {
      const url = new URL(req.url || "/", "http://127.0.0.1");
      const pathname = url.pathname;
      const method = (req.method || "GET").toUpperCase();

      if (pathname === "/api/status" && method === "GET") {
        sendJson(res, 200, await this.buildStatusPayload());
        return;
      }

      if (pathname === "/api/audit" && method === "GET") {
        sendJson(res, 200, this.guard.auditAllProtectedDomains());
        return;
      }

      if (pathname === "/api/check" && method === "GET") {
        const domain = url.searchParams.get("domain") || "";
        if (!domain.trim()) {
          sendJson(res, 400, { error: "Missing domain query parameter" });
          return;
        }
        const clash = this.guard.getClashSnapshot();
        const decision = this.guard.evaluate(domain);
        const route = clash.connected
          ? evaluateDomainRouting(
              domain,
              clash.configs?.mode || "rule",
              clash.rules,
              clash.proxies
            )
          : null;
        sendJson(res, 200, { decision, route });
        return;
      }

      if (pathname === "/api/stats" && method === "GET") {
        this.watchdog.flushTraffic();
        const rangeParam = url.searchParams.get("range") || "24h";
        const rangeHours =
          rangeParam === "7d" ? 24 * 7 : rangeParam === "30d" ? 24 * 30 : 24;
        const stats = this.store.getStats(rangeHours);
        sendJson(res, 200, {
          ...stats,
          gateStats: this.proxyServer.getStats(),
        });
        return;
      }

      if (pathname === "/api/events" && method === "GET") {
        const limit = Math.min(500, Math.max(1, Number(url.searchParams.get("limit") || 100)));
        sendJson(res, 200, { events: this.store.getRecentEvents(limit) });
        return;
      }

      if (pathname === "/api/events" && method === "DELETE") {
        this.store.clearGuardEvents();
        sendJson(res, 200, { ok: true });
        return;
      }

      if (pathname === "/api/config" && method === "GET") {
        sendJson(res, 200, {
          ...this.config,
          launchAtLogin: getLaunchAtLoginStatus(),
        });
        return;
      }

      if (pathname === "/api/config" && method === "PUT") {
        const body = await readJsonBody<Partial<AppConfig> & { launchAtLogin?: boolean }>(req);
        const clampPort = (val: unknown, fallback: number): number => {
          const n = Number(val);
          return Number.isInteger(n) && n >= 1024 && n <= 65535 ? n : fallback;
        };
        const clampInterval = (val: unknown, fallback: number): number => {
          const n = Number(val);
          return Number.isFinite(n) ? Math.min(600, Math.max(10, Math.round(n))) : fallback;
        };

        const merged: AppConfig = {
          ...this.config,
          ...(typeof body.strictMode === "boolean" ? { strictMode: body.strictMode } : {}),
          ...(typeof body.autoKillDirectLeaks === "boolean"
            ? { autoKillDirectLeaks: body.autoKillDirectLeaks }
            : {}),
          ...(typeof body.notificationsEnabled === "boolean"
            ? { notificationsEnabled: body.notificationsEnabled }
            : {}),
          ...(body.exitIpProbeIntervalSec !== undefined
            ? { exitIpProbeIntervalSec: clampInterval(body.exitIpProbeIntervalSec, this.config.exitIpProbeIntervalSec) }
            : {}),
          ...(body.proxyPort !== undefined
            ? { proxyPort: clampPort(body.proxyPort, this.config.proxyPort) }
            : {}),
          ...(body.upstreamPort !== undefined
            ? { upstreamPort: clampPort(body.upstreamPort, this.config.upstreamPort) }
            : {}),
          ...(Array.isArray(body.bannedCountries) ? { bannedCountries: body.bannedCountries } : {}),
          ...(Array.isArray(body.protectedDomains) ? { protectedDomains: body.protectedDomains } : {}),
        };
        const saved = saveConfig(merged);
        if (typeof body.launchAtLogin === "boolean") {
          setLaunchAtLogin(body.launchAtLogin);
        }
        this.config = saved;
        this.watchdog.updateConfig(saved);
        this.proxyServer.updateConfig(saved);
        if (this.onConfigUpdated) {
          this.onConfigUpdated(saved);
        }
        sendJson(res, 200, {
          ...saved,
          launchAtLogin: getLaunchAtLoginStatus(),
        });
        return;
      }

      if (pathname === "/api/detector" && method === "GET") {
        sendJson(res, 200, { report: this.latestDetectorReport });
        return;
      }

      if (pathname === "/api/detector/run" && method === "POST") {
        await this.watchdog.syncOnce(true);
        const sysProxy = await getSystemProxyStatus(
          this.config.proxyPort,
          this.config.upstreamPort
        );
        const report = await runNetworkDetection(
          {
            config: this.config,
            guard: this.guard,
            systemProxy: sysProxy,
          },
          this.detectorProbes
        );
        this.latestDetectorReport = report;
        sendJson(res, 200, { ok: true, report });
        return;
      }

      if (pathname === "/api/actions/auto-fix" && method === "POST") {
        const body = await readJsonBody<{ includeSystemProxy?: boolean }>(req);
        const report = await runAutoFix(
          {
            config: this.config,
            mihomo: this.mihomo,
            guard: this.guard,
            store: this.store,
            watchdog: this.watchdog,
          },
          {
            includeSystemProxy: Boolean(body.includeSystemProxy),
            clashVergeDir: this.clashVergeDir,
          }
        );
        await this.watchdog.syncOnce(true);
        if (this.latestDetectorReport) {
          const sysProxy = await getSystemProxyStatus(
            this.config.proxyPort,
            this.config.upstreamPort
          );
          this.latestDetectorReport = await runNetworkDetection(
            {
              config: this.config,
              guard: this.guard,
              systemProxy: sysProxy,
            },
            this.detectorProbes
          );
        }
        sendJson(res, 200, {
          ok: report.ok,
          report,
          detectorReport: this.latestDetectorReport,
          status: await this.buildStatusPayload(),
          audit: this.guard.auditAllProtectedDomains(),
        });
        return;
      }

      if (pathname === "/api/actions/probe-ip" && method === "POST") {
        await this.watchdog.probeIpNow(true);
        sendJson(res, 200, { ok: true, exitIp: this.guard.getExitIpState() });
        return;
      }

      if (pathname === "/api/actions/proxy" && method === "POST") {
        const body = await readJsonBody<{ enable?: boolean }>(req);
        const status = body.enable
          ? await enableGateSystemProxy(this.config.proxyPort, this.config.upstreamPort)
          : await restoreSystemProxy(this.config.proxyPort, this.config.upstreamPort);
        sendJson(res, 200, { ok: true, systemProxy: status });
        return;
      }

      // Static assets
      if (method === "GET") {
        const rel = pathname === "/" ? "index.html" : pathname.replace(/^\/+/, "");
        const target = path.resolve(this.publicDir, rel);
        if (!target.startsWith(this.publicDir) || !fs.existsSync(target) || fs.statSync(target).isDirectory()) {
          res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
          res.end("Not Found");
          return;
        }
        const ext = path.extname(target).toLowerCase();
        const content = fs.readFileSync(target);
        res.writeHead(200, {
          "Content-Type": MIME_TYPES[ext] || "application/octet-stream",
          "Content-Length": content.length,
        });
        res.end(content);
        return;
      }

      sendJson(res, 404, { error: "Not Found" });
    } catch (err) {
      sendJson(res, 500, { error: (err as Error).message });
    }
  }
}
