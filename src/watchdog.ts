import { matchProtectedDomain, normalizeHost, type AppConfig } from "./config.js";
import { formatHourBucket, type Store, type TrafficDelta } from "./db.js";
import type { ExitIpProber } from "./exit-ip.js";
import type { GuardEngine } from "./guard.js";
import type { MihomoClient, MihomoConnection, MihomoRule } from "./mihomo.js";
import { getSystemProxyStatus } from "./macos-proxy.js";
import type { MacNotifier } from "./notifier.js";
import { normalizeType } from "./rules-engine.js";

interface TrackedConn {
  upload: number;
  download: number;
  domain: string;
  node: string;
  process: string;
  isClaude: boolean;
}

export class Watchdog {
  private config: AppConfig;
  private mihomo: MihomoClient;
  private exitIpProber: ExitIpProber;
  private guard: GuardEngine;
  private store: Store;
  private notifier: MacNotifier;

  private tickTimer: NodeJS.Timeout | null = null;
  private ipTimer: NodeJS.Timeout | null = null;
  private flushTimer: NodeJS.Timeout | null = null;
  private pruneTimer: NodeJS.Timeout | null = null;
  private ticking = false;

  private cachedRules: MihomoRule[] = [];
  private lastRulesFetchAt = 0;
  private lastMode = "";
  private lastPrimaryLeaf = "";
  private lastBannedIpLog = { key: "", at: 0 };
  private wasClashConnected: boolean | null = null;
  private lastOfflineAlertAt = 0;
  private lastNoProxyCheckAt = 0;
  private lastNoProxyAlertAt = 0;

  private trackedConns = new Map<string, TrackedConn>();
  private pendingDeltas = new Map<string, TrafficDelta>();
  private killedConnIds = new Set<string>();

  constructor(
    config: AppConfig,
    mihomo: MihomoClient,
    exitIpProber: ExitIpProber,
    guard: GuardEngine,
    store: Store,
    notifier: MacNotifier
  ) {
    this.config = config;
    this.mihomo = mihomo;
    this.exitIpProber = exitIpProber;
    this.guard = guard;
    this.store = store;
    this.notifier = notifier;
  }

  updateConfig(config: AppConfig): void {
    const prevIpInterval = this.config.exitIpProbeIntervalSec;
    this.config = config;
    this.mihomo.updateConfig(config);
    this.exitIpProber.updateConfig(config);
    this.guard.updateConfig(config);
    this.notifier.setEnabled(config.notificationsEnabled);

    if (this.ipTimer && prevIpInterval !== config.exitIpProbeIntervalSec) {
      clearInterval(this.ipTimer);
      const ipMs = Math.max(10, config.exitIpProbeIntervalSec || 30) * 1000;
      this.ipTimer = setInterval(() => {
        void this.probeIpNow();
      }, ipMs);
    }
  }

  async start(): Promise<void> {
    this.store.pruneOldData(90);
    await this.syncOnce();
    await this.probeIpNow();

    this.tickTimer = setInterval(() => {
      void this.syncOnce();
    }, 1000);

    const ipMs = Math.max(10, this.config.exitIpProbeIntervalSec || 30) * 1000;
    this.ipTimer = setInterval(() => {
      void this.probeIpNow();
    }, ipMs);

    this.flushTimer = setInterval(() => {
      this.flushTraffic();
    }, 10_000);

    this.pruneTimer = setInterval(() => {
      this.store.pruneOldData(90);
    }, 24 * 3600 * 1000);
  }

  stop(): void {
    if (this.tickTimer) {
      clearInterval(this.tickTimer);
      this.tickTimer = null;
    }
    if (this.ipTimer) {
      clearInterval(this.ipTimer);
      this.ipTimer = null;
    }
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
    if (this.pruneTimer) {
      clearInterval(this.pruneTimer);
      this.pruneTimer = null;
    }
    this.flushTraffic();
  }

  flushTraffic(): void {
    if (this.pendingDeltas.size === 0) return;
    const batch = Array.from(this.pendingDeltas.values());
    this.pendingDeltas.clear();
    this.store.recordTrafficDeltas(batch);
  }

  async probeIpNow(clearJump = false): Promise<void> {
    if (clearJump) {
      this.exitIpProber.clearCountryJump();
    }
    const state = await this.exitIpProber.probeNow();
    this.guard.updateExitIpState(state);

    if (state.current && this.config.bannedCountries.includes(state.current.countryCode.toUpperCase())) {
      const nodeInfo = this.guard.getPrimaryClaudeNodeInfo();
      const dedupKey = `${state.current.ip}:${state.current.countryCode}`;
      const now = Date.now();
      const msg = `当前代理出口 IP (${state.current.ip}) 位于受限地区 ${state.current.country} (${state.current.countryCode})，节点「${nodeInfo.leaf}」已触发 Claude 访问熔断！`;
      const fix = `请在 Clash Verge 将「${nodeInfo.group}」切换到美国/日本/新加坡等合规节点。`;

      if (this.lastBannedIpLog.key !== dedupKey || now - this.lastBannedIpLog.at > 5 * 60_000) {
        this.lastBannedIpLog = { key: dedupKey, at: now };
        this.store.recordGuardEvent({
          ts: new Date().toISOString(),
          domain: "claude.ai",
          source: "watchdog_ip",
          action: "BLOCK",
          reasonCode: "BANNED_EXIT_COUNTRY",
          message: msg,
          fixHint: fix,
          clashMode: this.guard.getClashSnapshot().configs?.mode || "unknown",
          node: nodeInfo.leaf,
          exitIp: state.current.ip,
          exitCountry: state.current.countryCode,
          process: "exit-ip-prober",
        });
      }
      this.notifier.notify("watchdog_ip:banned", "ClaudeGate 出口 IP 告警", `${state.current.countryCode} · ${state.current.ip}`, msg, true);
    }
  }

  async syncOnce(forceRulesRefresh = false): Promise<void> {
    if (this.ticking) return;
    this.ticking = true;

    try {
      const [versionRes, configsRes, proxiesRes] = await Promise.all([
        this.mihomo.getVersion(),
        this.mihomo.getConfigs(),
        this.mihomo.getProxies(),
      ]);

      const now = Date.now();
      const modeChanged = this.lastMode && this.lastMode !== configsRes.mode;
      if (forceRulesRefresh || this.cachedRules.length === 0 || modeChanged || now - this.lastRulesFetchAt > 15_000) {
        this.cachedRules = await this.mihomo.getRules();
        this.lastRulesFetchAt = now;
      }

      this.guard.updateClashSnapshot({
        connected: true,
        version: versionRes.version || "unknown",
        configs: configsRes,
        proxies: proxiesRes,
        rules: this.cachedRules,
        lastSyncAt: new Date().toISOString(),
        lastError: null,
      });

      const currentMode = String(configsRes.mode || "rule").toLowerCase();
      if (currentMode !== this.lastMode) {
        const prevMode = this.lastMode;
        this.lastMode = currentMode;

        if (currentMode === "direct") {
          const msg = "检测到 Clash Verge 切换为了【直连模式 (Direct)】，ClaudeGate 已自动启用全拦截防止封号！";
          const fix = "请在 Clash Verge 切回「规则模式 (Rule)」，或在控制台点击「一键切回规则模式」。";
          this.store.recordGuardEvent({
            ts: new Date().toISOString(),
            domain: "claude.ai",
            source: "watchdog_mode",
            action: "BLOCK",
            reasonCode: "CLASH_DIRECT_MODE",
            message: msg,
            fixHint: fix,
            clashMode: currentMode,
            node: "DIRECT",
            exitIp: this.exitIpProber.getState().current?.ip || "",
            exitCountry: this.exitIpProber.getState().current?.countryCode || "",
            process: "clash-verge",
          });
          this.notifier.notify(
            "watchdog_mode:direct",
            "警告：Clash Verge 已切到直连模式！",
            "Claude 访问已被门禁自动阻断",
            msg,
            true
          );
        } else if (prevMode) {
          // Mode changed (e.g. direct -> rule), re-probe exit IP
          void this.probeIpNow();
        }
      }

      // Detect Claude node change -> trigger exit IP re-probe
      const primary = this.guard.getPrimaryClaudeNodeInfo();
      if (this.lastPrimaryLeaf && primary.leaf && primary.leaf !== this.lastPrimaryLeaf) {
        this.lastPrimaryLeaf = primary.leaf;
        void this.probeIpNow();
      } else if (!this.lastPrimaryLeaf && primary.leaf) {
        this.lastPrimaryLeaf = primary.leaf;
      }

      // Poll connections for traffic accounting & TUN direct leak kill
      const connSnap = await this.mihomo.getConnections();
      await this.processConnections(connSnap.connections || [], currentMode);

      this.wasClashConnected = true;

      // Alert if neither TUN nor local proxy is active (traffic bypasses proxy completely)
      if (process.env.CLAUDEBAN_NO_NOTIFY !== "1" && !configsRes.tun?.enable && now - this.lastNoProxyCheckAt > 10_000) {
        this.lastNoProxyCheckAt = now;
        try {
          const sysProxy = await getSystemProxyStatus(this.config.proxyPort, this.config.upstreamPort);
          if (!sysProxy.pointingToGate && !sysProxy.pointingToUpstream) {
            if (now - this.lastNoProxyAlertAt > 5 * 60_000) {
              this.lastNoProxyAlertAt = now;
              const noProxyMsg =
                "检测到 Clash Verge TUN 与系统代理均未开启，当前浏览或终端请求正直接联网，存在裸连 Claude 封号风险！";
              this.store.recordGuardEvent({
                ts: new Date().toISOString(),
                domain: "claude.ai",
                source: "watchdog_mode",
                action: "WARN",
                reasonCode: "NO_PROXY_ACTIVE",
                message: noProxyMsg,
                fixHint: "请在 Clash Verge 开启 TUN，或一键将系统代理接入 ClaudeGate。",
                clashMode: currentMode,
                node: "DIRECT",
                exitIp: this.exitIpProber.getState().current?.ip || "",
                exitCountry: this.exitIpProber.getState().current?.countryCode || "",
                process: "system-proxy",
              });
              this.notifier.notify(
                "watchdog_proxy:inactive",
                "警告：当前网络未经过代理！",
                "TUN 与系统代理均未开启",
                noProxyMsg,
                true
              );
            }
          }
        } catch {
          // ignore system proxy probe error
        }
      }
    } catch (err) {
      const errMsg = (err as Error).message;
      const prev = this.guard.getClashSnapshot();
      this.guard.updateClashSnapshot({
        ...prev,
        connected: false,
        lastError: errMsg,
      });

      const now = Date.now();
      if (this.wasClashConnected !== false || now - this.lastOfflineAlertAt > 5 * 60_000) {
        this.wasClashConnected = false;
        this.lastOfflineAlertAt = now;
        const offlineMsg =
          "Clash Verge Rev 未运行或控制接口已断开，当前网络可能未受代理保护！若继续直接访问 Claude 将存在极高封号风险。";
        this.store.recordGuardEvent({
          ts: new Date().toISOString(),
          domain: "claude.ai",
          source: "watchdog_mode",
          action: "BLOCK",
          reasonCode: "CLASH_OFFLINE",
          message: offlineMsg,
          fixHint: "请立即启动 Clash Verge Rev 并确认处于 Rule 模式；开启系统代理接管后门禁会自动 0 字节拦截裸连。",
          clashMode: "offline",
          node: "DIRECT",
          exitIp: this.exitIpProber.getState().current?.ip || "",
          exitCountry: this.exitIpProber.getState().current?.countryCode || "",
          process: "clash-verge",
        });
        this.notifier.notify(
          "watchdog_clash:offline",
          "警告：Clash Verge 未运行或已断开！",
          "网络未经过代理保护",
          offlineMsg,
          true
        );
      }

      // Try re-discovering socket on disconnect
      this.mihomo.refreshEndpoint();
    } finally {
      this.ticking = false;
    }
  }

  private async processConnections(connections: MihomoConnection[], currentMode: string): Promise<void> {
    const activeIds = new Set<string>();
    const hourBucket = formatHourBucket();

    for (const conn of connections) {
      activeIds.add(conn.id);

      const rawHost =
        conn.metadata?.host ||
        conn.metadata?.sniffHost ||
        (conn.rulePayload && conn.rulePayload.includes(".") ? conn.rulePayload : "") ||
        conn.metadata?.destinationIP ||
        "";
      const domain = normalizeHost(rawHost) || "(unknown)";
      const chains = Array.isArray(conn.chains) ? conn.chains : [];
      const node = chains[0] || "DIRECT";
      const proc = conn.metadata?.process || conn.metadata?.type || "(unknown)";
      const protectedMatch = matchProtectedDomain(domain, this.config.protectedDomains);
      const isClaude = Boolean(protectedMatch);

      // Accumulate traffic delta
      const prev = this.trackedConns.get(conn.id);
      let upDelta = 0;
      let downDelta = 0;
      let connInc = 0;

      if (!prev) {
        upDelta = Math.max(0, conn.upload || 0);
        downDelta = Math.max(0, conn.download || 0);
        connInc = 1;
      } else {
        upDelta = Math.max(0, (conn.upload || 0) - prev.upload);
        downDelta = Math.max(0, (conn.download || 0) - prev.download);
      }

      this.trackedConns.set(conn.id, {
        upload: conn.upload || 0,
        download: conn.download || 0,
        domain,
        node,
        process: proc,
        isClaude,
      });

      if (upDelta > 0 || downDelta > 0 || connInc > 0) {
        const key = `${hourBucket}|${domain}|${node}|${proc}`;
        const existing = this.pendingDeltas.get(key);
        if (existing) {
          existing.upBytes += upDelta;
          existing.downBytes += downDelta;
          existing.connIncrement += connInc;
        } else {
          this.pendingDeltas.set(key, {
            hourBucket,
            domain,
            node,
            process: proc,
            isClaude,
            upBytes: upDelta,
            downBytes: downDelta,
            connIncrement: connInc,
          });
        }
      }

      // Check for TUN / direct leaks on protected Claude domains!
      const isDirectChain =
        chains.length === 0 || chains.some((c) => normalizeType(c) === "DIRECT");

      if (isClaude && isDirectChain && !this.killedConnIds.has(conn.id)) {
        this.killedConnIds.add(conn.id);
        let killed = false;
        if (this.config.autoKillDirectLeaks) {
          try {
            await this.mihomo.closeConnection(conn.id);
            killed = true;
          } catch {
            // connection may already be closed
          }
        }

        const action = killed ? "KILL" : "WARN";
        const msg = `${killed ? "已强行掐断" : "检测到"}直连泄漏连接：进程「${proc}」正通过 DIRECT 直连访问 ${domain}！`;
        const fix = `请将该进程的网络代理配置到 ClaudeGate (127.0.0.1:${this.config.proxyPort})，并检查 Clash Verge 规则确保 ${protectedMatch?.domain || domain} 走合规节点。`;

        this.store.recordGuardEvent({
          ts: new Date().toISOString(),
          domain,
          source: "watchdog_tun",
          action,
          reasonCode: "TUN_DIRECT_LEAK",
          message: msg,
          fixHint: fix,
          clashMode: currentMode,
          node: "DIRECT",
          exitIp: this.exitIpProber.getState().current?.ip || "",
          exitCountry: this.exitIpProber.getState().current?.countryCode || "",
          process: proc,
        });

        this.notifier.notify(
          `watchdog_tun:${domain}:${proc}`,
          "拦截到 Claude 直连泄漏！",
          `${proc} -> ${domain}`,
          msg,
          true
        );
      }
    }

    // Clean up closed connections
    for (const id of this.trackedConns.keys()) {
      if (!activeIds.has(id)) {
        this.trackedConns.delete(id);
        this.killedConnIds.delete(id);
      }
    }
  }
}
