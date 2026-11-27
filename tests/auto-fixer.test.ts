import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import vm from "node:vm";
import {
  buildPatchedRuntimeYaml,
  patchClashVergeScript,
  pickSafeReplacementNode,
} from "../src/auto-fixer.js";
import { getDefaultConfig } from "../src/config.js";
import { DashboardServer } from "../src/dashboard-server.js";
import { Store } from "../src/db.js";
import { ExitIpProber, type ExitIpInfo } from "../src/exit-ip.js";
import { GuardEngine } from "../src/guard.js";
import { MihomoClient, type MihomoProxy, type MihomoRule } from "../src/mihomo.js";
import { MacNotifier } from "../src/notifier.js";
import { GateProxyServer } from "../src/proxy-server.js";
import { Watchdog } from "../src/watchdog.js";

test("patchClashVergeScript wraps existing main(config) cleanly, executes in vm, and is idempotent", () => {
  const origScript = `
function main(config) {
  config.rules = ["GEOIP,CN,DIRECT"].concat(config.rules || []);
  return config;
}
`;
  const rules = ["DOMAIN-SUFFIX,statsig.com,Proxy", "DOMAIN-SUFFIX,sentry.io,Proxy"];
  const patched1 = patchClashVergeScript(origScript, rules);
  const patched2 = patchClashVergeScript(patched1, rules);

  assert.equal(patched1, patched2);
  assert.equal(patched1.match(/CLAUDEGATE_AUTO_RULES_START/g)?.length, 1);

  const sandbox: Record<string, unknown> = {};
  vm.createContext(sandbox);
  vm.runInContext(patched1, sandbox);
  const mainFn = sandbox.main as (cfg: { rules: string[] }) => { rules: string[] };
  const result = mainFn({ rules: ["MATCH,Others"] });

  assert.equal(result.rules[0], "DOMAIN-SUFFIX,statsig.com,Proxy");
  assert.equal(result.rules[1], "DOMAIN-SUFFIX,sentry.io,Proxy");
  assert.equal(result.rules[2], "GEOIP,CN,DIRECT");
  assert.equal(result.rules[3], "MATCH,Others");
});

test("buildPatchedRuntimeYaml prepends rules and strips external-controller-unix", () => {
  const origYaml = `mode: rule
external-controller-unix: /tmp/verge-mihomo.sock
rules:
- DOMAIN-SUFFIX,claude.ai,Proxy
- MATCH,Others
`;
  const patched = buildPatchedRuntimeYaml(origYaml, [
    "DOMAIN-SUFFIX,claude.ai,Proxy",
    "DOMAIN-SUFFIX,statsig.com,Proxy",
  ]);
  assert.ok(!patched.includes("external-controller-unix"));
  assert.equal(patched.match(/DOMAIN-SUFFIX,claude\.ai,Proxy/g)?.length, 1);
  assert.ok(patched.includes("rules:\n- DOMAIN-SUFFIX,statsig.com,Proxy\n- DOMAIN-SUFFIX,claude.ai,Proxy"));
});

test("pickSafeReplacementNode skips DIRECT, info banners, and banned countries", () => {
  const proxies: Record<string, MihomoProxy> = {
    Proxy: {
      name: "Proxy",
      type: "Selector",
      now: "HK-01",
      all: ["DIRECT", "剩余流量：100GB", "香港 01", "HK-01", "俄罗斯 CN2", "日本.东京 03", "US-LA"],
    },
  };
  const chosen = pickSafeReplacementNode("Proxy", proxies, ["CN", "HK", "RU"]);
  assert.equal(chosen, "日本.东京 03");
});

test("POST /api/actions/auto-fix repairs mode, GLOBAL, banned node, missing rules, and preserves Steam selection", async () => {
  process.env.CLAUDEBAN_NO_NOTIFY = "1";
  const tmpDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "claudeban-autofix-data-"));
  const tmpVergeDir = fs.mkdtempSync(path.join(os.tmpdir(), "claudeban-autofix-verge-"));
  process.env.CLAUDEBAN_DATA_DIR = tmpDataDir;

  fs.mkdirSync(path.join(tmpVergeDir, "profiles"), { recursive: true });
  fs.writeFileSync(
    path.join(tmpVergeDir, "profiles", "Script.js"),
    `function main(config) {\n  return config;\n}\n`,
    "utf8"
  );
  fs.writeFileSync(
    path.join(tmpVergeDir, "clash-verge.yaml"),
    `mode: direct\nexternal-controller-unix: /tmp/test.sock\nrules:\n- DOMAIN-SUFFIX,claude.ai,Proxy\n- DOMAIN-SUFFIX,anthropic.com,Proxy\n- MATCH,Others\n`,
    "utf8"
  );

  // Mock Mihomo state
  let mockMode = "direct";
  let mockGlobalNow = "DIRECT";
  let mockProxyNow = "HK-01";
  let mockSteamNow = "TW-05";
  let reloadedPayload = "";
  let mockRules: MihomoRule[] = [
    { index: 0, type: "DomainSuffix", payload: "claude.ai", proxy: "Proxy" },
    { index: 1, type: "DomainSuffix", payload: "anthropic.com", proxy: "Proxy" },
    { index: 2, type: "Match", payload: "", proxy: "Others" },
  ];

  const mockMihomoServer = http.createServer((req, res) => {
    const url = req.url || "/";
    const method = (req.method || "GET").toUpperCase();
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const bodyStr = Buffer.concat(chunks).toString("utf8");
      if (url === "/version") {
        res.end(JSON.stringify({ version: "v1.19.32-mock", meta: true }));
        return;
      }
      if (url === "/configs" && method === "GET") {
        res.end(JSON.stringify({ mode: mockMode, "mixed-port": 7897, tun: { enable: true } }));
        return;
      }
      if (url === "/configs" && method === "PATCH") {
        const body = JSON.parse(bodyStr) as { mode?: string };
        if (body.mode) mockMode = body.mode;
        res.statusCode = 204;
        res.end();
        return;
      }
      if (url.startsWith("/configs") && method === "PUT") {
        const body = JSON.parse(bodyStr) as { path?: string; payload?: string };
        assert.equal(body.path, "");
        assert.equal(typeof body.payload, "string");
        reloadedPayload = body.payload || "";
        // Parse rules from inline YAML payload so /rules reflects live reload!
        const ruleLines = reloadedPayload
          .split("\n")
          .filter((l) => l.trim().startsWith("- DOMAIN"))
          .map((l, i) => {
            const [t, p, g] = l.trim().replace(/^-\s*/, "").split(",");
            return {
              index: i,
              type: t === "DOMAIN" ? "Domain" : "DomainSuffix",
              payload: p,
              proxy: g,
            };
          });
        mockRules = [...ruleLines, { index: ruleLines.length, type: "Match", payload: "", proxy: "Others" }];
        // Simulate Mihomo resetting selections on reload so we verify auto-fixer restores Steam!
        mockSteamNow = "DIRECT";
        res.statusCode = 204;
        res.end();
        return;
      }
      if (url === "/proxies" && method === "GET") {
        res.end(
          JSON.stringify({
            proxies: {
              DIRECT: { name: "DIRECT", type: "Direct" },
              GLOBAL: { name: "GLOBAL", type: "Selector", now: mockGlobalNow, all: ["DIRECT", "Proxy"] },
              Proxy: { name: "Proxy", type: "Selector", now: mockProxyNow, all: ["HK-01", "JP-Tokyo-03"] },
              Steam: { name: "Steam", type: "Selector", now: mockSteamNow, all: ["DIRECT", "TW-05"] },
              Others: { name: "Others", type: "Selector", now: "Proxy", all: ["Proxy"] },
              "HK-01": { name: "HK-01", type: "Trojan" },
              "JP-Tokyo-03": { name: "JP-Tokyo-03", type: "Trojan" },
              "TW-05": { name: "TW-05", type: "Trojan" },
            },
          })
        );
        return;
      }
      if (url.startsWith("/proxies/") && method === "PUT") {
        const group = decodeURIComponent(url.slice("/proxies/".length));
        const body = JSON.parse(bodyStr) as { name: string };
        if (group === "GLOBAL") mockGlobalNow = body.name;
        if (group === "Proxy") mockProxyNow = body.name;
        if (group === "Steam") mockSteamNow = body.name;
        res.statusCode = 204;
        res.end();
        return;
      }
      if (url === "/rules") {
        res.end(JSON.stringify({ rules: mockRules }));
        return;
      }
      if (url === "/connections") {
        res.end(JSON.stringify({ uploadTotal: 0, downloadTotal: 0, connections: [] }));
        return;
      }
      res.statusCode = 404;
      res.end();
    });
  });

  await new Promise<void>((r) => mockMihomoServer.listen(0, "127.0.0.1", r));
  const mihomoPort = (mockMihomoServer.address() as net.AddressInfo).port;

  const cfg = getDefaultConfig();
  cfg.proxyPort = 0;
  cfg.dashboardPort = 0;
  cfg.mihomoTcpUrl = `http://127.0.0.1:${mihomoPort}`;

  const store = new Store(path.join(tmpDataDir, "test.db"));
  const mihomo = new MihomoClient(cfg, { kind: "tcp", baseUrl: cfg.mihomoTcpUrl });
  const exitIpProber = new ExitIpProber(cfg, async (): Promise<ExitIpInfo> => ({
    ip: mockProxyNow === "HK-01" ? "203.0.113.1" : "198.51.100.42",
    countryCode: mockProxyNow === "HK-01" ? "HK" : "JP",
    country: mockProxyNow === "HK-01" ? "Hong Kong" : "Japan",
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
    clashVergeDir: tmpVergeDir,
  });

  try {
    await proxyServer.start(0);
    const dashPort = await dashboard.start(0);
    await watchdog.start();

    const resp = await fetch(`http://127.0.0.1:${dashPort}/api/actions/auto-fix`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    assert.equal(resp.status, 200);
    const data = (await resp.json()) as {
      ok: boolean;
      report: { fixedCount: number; failedCount: number };
      status: { health: string; hasFixableIssues: boolean };
      audit: { missingExplicitRuleDomains: string[]; globalRisk: boolean };
    };

    assert.equal(data.ok, true);
    assert.equal(data.report.failedCount, 0);
    assert.equal(data.report.fixedCount, 4); // mode, GLOBAL, banned node, missing rules
    assert.equal(mockMode, "rule");
    assert.equal(mockGlobalNow, "Proxy");
    assert.equal(mockProxyNow, "JP-Tokyo-03");
    assert.equal(mockSteamNow, "TW-05"); // preserved across reload!
    assert.ok(reloadedPayload.includes("DOMAIN-SUFFIX,statsig.com,Proxy"));
    assert.equal(data.audit.globalRisk, false);
    assert.equal(data.audit.missingExplicitRuleDomains.length, 0);

    // Verify Script.js was backed up and patched
    const backupFiles = fs.readdirSync(path.join(tmpDataDir, "backups"));
    assert.ok(backupFiles.some((f) => f.startsWith("Script.js.")));
    const scriptAfter = fs.readFileSync(path.join(tmpVergeDir, "profiles", "Script.js"), "utf8");
    assert.ok(scriptAfter.includes("DOMAIN-SUFFIX,statsig.com,Proxy"));
  } finally {
    watchdog.stop();
    await proxyServer.stop();
    await dashboard.stop();
    store.close();
    await new Promise<void>((r) => mockMihomoServer.close(() => r()));
    fs.rmSync(tmpDataDir, { recursive: true, force: true });
    fs.rmSync(tmpVergeDir, { recursive: true, force: true });
  }
});
