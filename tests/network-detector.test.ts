import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { getDefaultConfig } from "../src/config.js";
import { DashboardServer } from "../src/dashboard-server.js";
import { Store } from "../src/db.js";
import { ExitIpProber } from "../src/exit-ip.js";
import { GuardEngine } from "../src/guard.js";
import { getSystemProxyStatus } from "../src/macos-proxy.js";
import { MihomoClient, type MihomoProxy, type MihomoRule } from "../src/mihomo.js";
import { gradeFromScore, runNetworkDetection } from "../src/network-detector.js";
import { MacNotifier } from "../src/notifier.js";
import { GateProxyServer } from "../src/proxy-server.js";
import { Watchdog } from "../src/watchdog.js";

const safeProxies: Record<string, MihomoProxy> = {
  DIRECT: { name: "DIRECT", type: "Direct" },
  GLOBAL: { name: "GLOBAL", type: "Selector", now: "Proxy", all: ["Proxy", "DIRECT"] },
  Proxy: { name: "Proxy", type: "Selector", now: "JP-01", all: ["JP-01"] },
  "JP-01": { name: "JP-01", type: "Trojan" },
};

const safeRules: MihomoRule[] = [
  { index: 0, type: "DomainSuffix", payload: "claude.ai", proxy: "Proxy" },
  { index: 1, type: "DomainSuffix", payload: "anthropic.com", proxy: "Proxy" },
  { index: 2, type: "Match", payload: "", proxy: "Proxy" },
];

test("gradeFromScore maps thresholds to S/A/B/C/F", () => {
  assert.equal(gradeFromScore(94), "S");
  assert.equal(gradeFromScore(85), "A");
  assert.equal(gradeFromScore(72), "B");
  assert.equal(gradeFromScore(55), "C");
  assert.equal(gradeFromScore(30), "F");
});

test("runNetworkDetection gives high score for clean residential JP exit and flags datacenter/DNS/IPv6 issues", async () => {
  const cfg = getDefaultConfig();
  // Limit protectedDomains in this test so all have explicit rules
  cfg.protectedDomains = [
    { domain: "claude.ai", category: "core" },
    { domain: "anthropic.com", category: "core" },
  ];

  const guard = new GuardEngine(cfg);
  guard.updateClashSnapshot({
    connected: true,
    version: "v1.19.32",
    configs: { mode: "rule", ipv6: false, tun: { enable: true, "dns-hijack": ["any:53"] } },
    proxies: safeProxies,
    rules: safeRules,
    lastSyncAt: new Date().toISOString(),
    lastError: null,
  });

  const sysProxy = await getSystemProxyStatus(17890, 7897);
  const cleanReport = await runNetworkDetection(
    { config: cfg, guard, systemProxy: { ...sysProxy, pointingToGate: true } },
    {
      probeDirectDomestic: async () => ({ ok: true, ip: "192.0.2.88", location: "Example Domestic ISP" }),
      probeProxyPurity: async () => ({
        ok: true,
        ip: "198.51.100.42",
        countryCode: "JP",
        country: "Japan",
        regionName: "Tokyo",
        city: "Tokyo",
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || "Asia/Tokyo",
        isp: "Example Residential ISP",
        org: "Example Residential ISP",
        asn: "AS64513",
        asname: "Example Residential ISP",
        mobile: false,
        proxy: false,
        hosting: false,
        networkType: "residential",
      }),
      probeStability: async () => ({
        ok: true,
        samples: 3,
        uniqueIps: ["198.51.100.42"],
        stable: true,
        ips: ["198.51.100.42", "198.51.100.42", "198.51.100.42"],
      }),
      probeDnsLeak: async () => ({
        ok: true,
        dnsIp: "198.51.100.53",
        dnsGeo: "Japan - Google LLC",
        leakedToBanned: false,
        tunDnsHijack: true,
      }),
      probeIpv6Leak: async () => ({
        mihomoIpv6Enabled: false,
        ipv6Address: null,
        leaked: false,
        detail: "IPv6 已关闭",
      }),
      probeEndpoints: async () => [
        { host: "claude.ai", role: "Web", reachable: true, statusCode: 403, latencyMs: 120, matchedRule: "DomainSuffix,claude.ai -> Proxy", leafNode: "JP-01" },
        { host: "api.anthropic.com", role: "API", reachable: true, statusCode: 404, latencyMs: 110, matchedRule: "DomainSuffix,anthropic.com -> Proxy", leafNode: "JP-01" },
        { host: "platform.claude.com", role: "Console", reachable: true, statusCode: 200, latencyMs: 130, matchedRule: "DomainSuffix,anthropic.com -> Proxy", leafNode: "JP-01" },
      ],
    }
  );

  assert.equal(cleanReport.totalScore, 100);
  assert.equal(cleanReport.grade, "S");
  assert.equal(cleanReport.findings.length, 0);

  // Now simulate DNS CN leak + IPv6 leak + hosting datacenter IP
  const riskyReport = await runNetworkDetection(
    { config: cfg, guard, systemProxy: { ...sysProxy, pointingToGate: false } },
    {
      probeDirectDomestic: async () => ({ ok: true, ip: "192.0.2.88", location: "Example Domestic ISP" }),
      probeProxyPurity: async () => ({
        ok: true,
        ip: "198.51.100.42",
        countryCode: "JP",
        country: "Japan",
        regionName: "Tokyo",
        city: "Tokyo",
        timezone: "America/Los_Angeles",
        isp: "Cloud Datacenter",
        org: "Cloud",
        asn: "AS64512",
        asname: "EXAMPLE-CLOUD",
        mobile: false,
        proxy: false,
        hosting: true,
        networkType: "datacenter",
      }),
      probeStability: async () => ({
        ok: true,
        samples: 3,
        uniqueIps: ["1.1.1.1", "2.2.2.2"],
        stable: false,
        ips: ["1.1.1.1", "2.2.2.2", "1.1.1.1"],
      }),
      probeDnsLeak: async () => ({
        ok: true,
        dnsIp: "192.0.2.53",
        dnsGeo: "China - ChinaNet",
        leakedToBanned: true,
        tunDnsHijack: false,
      }),
      probeIpv6Leak: async () => ({
        mihomoIpv6Enabled: true,
        ipv6Address: "2001:db8::1",
        leaked: true,
        detail: "IPv6 leaked",
      }),
      probeEndpoints: async () => [
        { host: "claude.ai", role: "Web", reachable: true, statusCode: 403, latencyMs: 120, matchedRule: "Proxy", leafNode: "JP-01" },
      ],
    }
  );

  assert.ok(riskyReport.totalScore < 75);
  assert.ok(riskyReport.findings.some((f) => f.id === "dns_leak"));
  assert.ok(riskyReport.findings.some((f) => f.id === "ipv6_leak" && f.fixable));
  assert.ok(riskyReport.findings.some((f) => f.id === "ip_datacenter"));
  assert.ok(riskyReport.findings.some((f) => f.id === "exit_unstable"));
});

test("POST /api/detector/run returns report and updates /api/status detectorSummary", async () => {
  process.env.CLAUDEBAN_NO_NOTIFY = "1";
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "claudeban-det-"));
  process.env.CLAUDEBAN_DATA_DIR = tmpDir;

  const mockMihomoServer = http.createServer((req, res) => {
    const url = req.url || "/";
    if (url === "/version") return res.end(JSON.stringify({ version: "v1.19.32-mock" }));
    if (url === "/configs") return res.end(JSON.stringify({ mode: "rule", ipv6: false, tun: { enable: true, "dns-hijack": ["any:53"] } }));
    if (url === "/proxies") return res.end(JSON.stringify({ proxies: safeProxies }));
    if (url === "/rules") return res.end(JSON.stringify({ rules: safeRules }));
    if (url === "/connections") return res.end(JSON.stringify({ uploadTotal: 0, downloadTotal: 0, connections: [] }));
    res.statusCode = 404;
    res.end();
  });

  await new Promise<void>((r) => mockMihomoServer.listen(0, "127.0.0.1", r));
  const mihomoPort = (mockMihomoServer.address() as net.AddressInfo).port;

  const cfg = getDefaultConfig();
  cfg.proxyPort = 0;
  cfg.dashboardPort = 0;
  cfg.mihomoTcpUrl = `http://127.0.0.1:${mihomoPort}`;

  const store = new Store(path.join(tmpDir, "test.db"));
  const mihomo = new MihomoClient(cfg, { kind: "tcp", baseUrl: cfg.mihomoTcpUrl });
  const exitIpProber = new ExitIpProber(cfg, async () => ({
    ip: "198.51.100.42",
    countryCode: "JP",
    country: "Japan",
    checkedAt: new Date().toISOString(),
    source: "mock",
  }));
  const guard = new GuardEngine(cfg);
  const notifier = new MacNotifier(false);
  const proxyServer = new GateProxyServer(cfg, guard, store, notifier);
  const watchdog = new Watchdog(cfg, mihomo, exitIpProber, guard, store, notifier);
  const dashboard = new DashboardServer({
    config: cfg,
    mihomo,
    guard,
    store,
    proxyServer,
    watchdog,
    detectorProbes: {
      probeDirectDomestic: async () => ({ ok: true, ip: "192.0.2.88", location: "Example Domestic ISP" }),
      probeProxyPurity: async () => ({
        ok: true,
        ip: "198.51.100.42",
        countryCode: "JP",
        country: "Japan",
        regionName: "Tokyo",
        city: "Tokyo",
        timezone: "Asia/Tokyo",
        isp: "Example Cloud",
        org: "Example Cloud",
        asn: "AS64512",
        asname: "EXAMPLE-CLOUD",
        mobile: false,
        proxy: false,
        hosting: true,
        networkType: "datacenter",
      }),
      probeStability: async () => ({ ok: true, samples: 3, uniqueIps: ["198.51.100.42"], stable: true, ips: ["198.51.100.42"] }),
      probeDnsLeak: async () => ({ ok: true, dnsIp: "198.51.100.53", dnsGeo: "Japan", leakedToBanned: false, tunDnsHijack: true }),
      probeIpv6Leak: async () => ({ mihomoIpv6Enabled: false, ipv6Address: null, leaked: false, detail: "ok" }),
      probeEndpoints: async () => [{ host: "claude.ai", role: "Web", reachable: true, statusCode: 403, latencyMs: 100, matchedRule: "Proxy", leafNode: "JP-01" }],
    },
  });

  try {
    await proxyServer.start(0);
    const dashPort = await dashboard.start(0);
    await watchdog.start();

    const runResp = await fetch(`http://127.0.0.1:${dashPort}/api/detector/run`, { method: "POST" });
    assert.equal(runResp.status, 200);
    const runJson = (await runResp.json()) as { ok: boolean; report: { grade: string; totalScore: number } };
    assert.equal(runJson.ok, true);
    assert.ok(runJson.report.totalScore > 0);

    const statusResp = await fetch(`http://127.0.0.1:${dashPort}/api/status`);
    const statusJson = (await statusResp.json()) as { detectorSummary: { grade: string } | null };
    assert.ok(statusJson.detectorSummary);
    assert.equal(statusJson.detectorSummary?.grade, runJson.report.grade);
  } finally {
    watchdog.stop();
    await proxyServer.stop();
    await dashboard.stop();
    store.close();
    await new Promise<void>((r) => mockMihomoServer.close(() => r()));
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
