import { loadConfig } from "./config.js";
import { DashboardServer } from "./dashboard-server.js";
import { Store } from "./db.js";
import { ExitIpProber } from "./exit-ip.js";
import { GuardEngine } from "./guard.js";
import {
  enableGateSystemProxy,
  getSystemProxyStatus,
  hasManagedProxyBackup,
  restoreSystemProxy,
} from "./macos-proxy.js";
import { MihomoClient } from "./mihomo.js";
import { MacNotifier } from "./notifier.js";
import { GateProxyServer } from "./proxy-server.js";
import { Watchdog } from "./watchdog.js";

async function runCheck(): Promise<void> {
  const config = loadConfig();
  const mihomo = new MihomoClient(config);
  const exitIpProber = new ExitIpProber(config);
  const guard = new GuardEngine(config);

  const ep = mihomo.getEndpoint();
  console.log("=== ClaudeGate 环境体检 (只读) ===");
  console.log(
    `Mihomo 控制端点: ${ep.kind === "unix" ? ep.socketPath : ep.baseUrl}`
  );

  try {
    const [ver, cfg, proxies, rules] = await Promise.all([
      mihomo.getVersion(),
      mihomo.getConfigs(),
      mihomo.getProxies(),
      mihomo.getRules(),
    ]);
    guard.updateClashSnapshot({
      connected: true,
      version: ver.version,
      configs: cfg,
      proxies,
      rules,
      lastSyncAt: new Date().toISOString(),
      lastError: null,
    });
    console.log(`Clash Verge / Mihomo 版本: ${ver.version}`);
    console.log(
      `当前模式: ${cfg.mode} | Mixed Port: ${cfg["mixed-port"] || config.upstreamPort} | TUN: ${
        cfg.tun?.enable ? `开启 (${cfg.tun.device || "utun"})` : "关闭"
      } | Sniffing: ${cfg.sniffing ? "开启" : "关闭"}`
    );
  } catch (err) {
    console.error(`❌ 无法连接 Clash Verge 控制接口: ${(err as Error).message}`);
    process.exitCode = 1;
    return;
  }

  console.log("正在通过上游代理探测真实出口 IP...");
  const ipState = await exitIpProber.probeNow();
  guard.updateExitIpState(ipState);

  if (ipState.current) {
    console.log(
      `真实出口 IP: ${ipState.current.ip} | 地区: ${ipState.current.country} (${ipState.current.countryCode}) | ISP: ${
        ipState.current.isp || "-"
      }`
    );
  } else {
    console.log(`⚠️ 出口 IP 探测失败: ${ipState.lastError}`);
  }

  const audit = guard.auditAllProtectedDomains();
  const primary = guard.getPrimaryClaudeNodeInfo();
  const sysProxy = await getSystemProxyStatus(config.proxyPort, config.upstreamPort);

  console.log(`Claude 主链路: ${primary.chain.join(" -> ")} (出口节点: ${primary.leaf})`);
  console.log(
    `macOS 系统代理: HTTP=${sysProxy.httpEnabled ? `${sysProxy.httpHost}:${sysProxy.httpPort}` : "off"}, SOCKS=${
      sysProxy.socksEnabled ? `${sysProxy.socksHost}:${sysProxy.socksPort}` : "off"
    }`
  );
  console.log(
    `GLOBAL 策略组风险: ${audit.globalRisk ? `🚨 警告! GLOBAL 当前指向 DIRECT` : `安全 (${audit.globalTarget})`}`
  );
  console.log(
    `受保护域名体检 (共 ${audit.totalProtected} 个): ✅ 安全 ${audit.safeCount} | ⚠️ 预警/兜底 ${audit.warnCount} | 🚨 危险/直连 ${audit.dangerCount}`
  );

  if (audit.missingExplicitRuleDomains.length > 0) {
    console.log(
      `\n以下 ${audit.missingExplicitRuleDomains.length} 个关联域名缺少显式 Clash 规则（建议补全）:`
    );
    console.log("  " + audit.missingExplicitRuleDomains.join(", "));
    console.log("\n建议追加到 Clash Verge 覆写规则 (Merge) 顶部的 YAML:");
    console.log(audit.recommendedYamlSnippet);
  }

  const claudeDecision = guard.evaluate("claude.ai");
  console.log(`\n[claude.ai 门禁评估]: ${claudeDecision.action} - ${claudeDecision.message}`);
}

async function runStart(): Promise<void> {
  const config = loadConfig();
  const store = new Store();
  const mihomo = new MihomoClient(config);
  const exitIpProber = new ExitIpProber(config);
  const guard = new GuardEngine(config);
  const notifier = new MacNotifier(config.notificationsEnabled);
  const proxyServer = new GateProxyServer(config, guard, store, notifier);
  const watchdog = new Watchdog(config, mihomo, exitIpProber, guard, store, notifier);
  const dashboard = new DashboardServer({
    config,
    mihomo,
    guard,
    store,
    proxyServer,
    watchdog,
  });

  const proxyPort = await proxyServer.start();
  const dashPort = await dashboard.start();
  await watchdog.start();

  const clash = guard.getClashSnapshot();
  const ipState = guard.getExitIpState();
  const audit = guard.auditAllProtectedDomains();

  console.log("==================================================");
  console.log("🛡️  ClaudeGate (claudeban) 已启动");
  console.log(`🚪 门禁代理地址 (HTTP/HTTPS/SOCKS5): 127.0.0.1:${proxyPort}`);
  console.log(`📊 Web 控制台 & 流量面板:          http://127.0.0.1:${dashPort}`);
  console.log(`🔗 上游 Clash Verge 端口:            ${config.upstreamHost}:${config.upstreamPort}`);
  console.log(
    `⚙️  Clash 状态: ${
      clash.connected
        ? `已连接 (${clash.version}) | 模式=${clash.configs?.mode} | 规则=${clash.rules.length}`
        : `未连接 (${clash.lastError})`
    }`
  );
  if (ipState.current) {
    console.log(
      `🌍 当前出口 IP: ${ipState.current.ip} (${ipState.current.countryCode} · ${ipState.current.country})`
    );
  }
  if (audit.globalRisk) {
    console.log("⚠️  提醒: 检测到 Clash GLOBAL 策略组指向 DIRECT，切勿误切全局模式！");
  }
  if (audit.missingExplicitRuleDomains.length > 0) {
    console.log(
      `⚠️  提醒: 有 ${audit.missingExplicitRuleDomains.length} 个 Claude 关联域名未配显式规则，请在控制台一键复制补全。`
    );
  }
  console.log("==================================================");
  console.log(
    `CLI 环境变量: export HTTP_PROXY=http://127.0.0.1:${proxyPort} HTTPS_PROXY=http://127.0.0.1:${proxyPort} ALL_PROXY=socks5://127.0.0.1:${proxyPort}`
  );

  let shuttingDown = false;
  const shutdown = async (sig: string) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`\n收到 ${sig}，正在安全退出 ClaudeGate...`);
    watchdog.stop();
    await proxyServer.stop();
    await dashboard.stop();
    if (hasManagedProxyBackup()) {
      try {
        await restoreSystemProxy(config.proxyPort, config.upstreamPort);
        console.log("已恢复 macOS 系统代理设置。");
      } catch (err) {
        console.error("恢复系统代理失败:", (err as Error).message);
      }
    }
    store.close();
    process.exit(0);
  };

  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
}

async function main(): Promise<void> {
  const cmd = (process.argv[2] || "start").toLowerCase();
  if (cmd === "check") {
    await runCheck();
    return;
  }
  if (cmd === "proxy-on") {
    const cfg = loadConfig();
    const st = await enableGateSystemProxy(cfg.proxyPort, cfg.upstreamPort);
    console.log(`✅ 已将 macOS (${st.activeService}) 系统代理接入 ClaudeGate 127.0.0.1:${cfg.proxyPort}`);
    return;
  }
  if (cmd === "proxy-off") {
    const cfg = loadConfig();
    const st = await restoreSystemProxy(cfg.proxyPort, cfg.upstreamPort);
    console.log(`✅ 已恢复 macOS (${st.activeService}) 系统代理设置。`);
    return;
  }
  if (cmd === "start") {
    await runStart();
    return;
  }

  console.log("用法: node dist/src/index.js [start | check | proxy-on | proxy-off]");
  process.exitCode = 1;
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
