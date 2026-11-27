import assert from "node:assert/strict";
import test from "node:test";
import { getDefaultConfig } from "../src/config.js";
import { ExitIpProber } from "../src/exit-ip.js";
import { GuardEngine } from "../src/guard.js";
import type { MihomoProxy, MihomoRule } from "../src/mihomo.js";

const baseProxies: Record<string, MihomoProxy> = {
  DIRECT: { name: "DIRECT", type: "Direct" },
  GLOBAL: { name: "GLOBAL", type: "Selector", now: "DIRECT", all: ["DIRECT", "Proxy"] },
  Proxy: { name: "Proxy", type: "Selector", now: "JP-01", all: ["JP-01", "US-01"] },
  Others: { name: "Others", type: "Selector", now: "Proxy", all: ["Proxy", "DIRECT"] },
  "JP-01": { name: "JP-01", type: "Trojan" },
};

const baseRules: MihomoRule[] = [
  { index: 0, type: "DomainSuffix", payload: "claude.ai", proxy: "Proxy" },
  { index: 1, type: "DomainSuffix", payload: "anthropic.com", proxy: "Proxy" },
  { index: 2, type: "DomainSuffix", payload: "stripe.com", proxy: "DIRECT" },
  { index: 3, type: "Match", payload: "", proxy: "Others" },
];

test("GuardEngine passes non-protected domains even when Clash is offline", () => {
  const guard = new GuardEngine(getDefaultConfig());
  const d = guard.evaluate("example.com");
  assert.equal(d.action, "ALLOW");
  assert.equal(d.isProtected, false);
});

test("GuardEngine blocks protected domains when Clash is offline", () => {
  const guard = new GuardEngine(getDefaultConfig());
  const d = guard.evaluate("claude.ai");
  assert.equal(d.action, "BLOCK");
  assert.equal(d.reasonCode, "CLASH_OFFLINE");
});

test("GuardEngine blocks when Clash is in direct mode", () => {
  const guard = new GuardEngine(getDefaultConfig());
  guard.updateClashSnapshot({
    connected: true,
    version: "v1.19.32",
    configs: { mode: "direct" },
    proxies: baseProxies,
    rules: baseRules,
    lastSyncAt: new Date().toISOString(),
    lastError: null,
  });
  const d = guard.evaluate("claude.ai");
  assert.equal(d.action, "BLOCK");
  assert.equal(d.reasonCode, "CLASH_DIRECT_MODE");
});

test("GuardEngine blocks when Clash is in global mode with GLOBAL -> DIRECT", () => {
  const guard = new GuardEngine(getDefaultConfig());
  guard.updateClashSnapshot({
    connected: true,
    version: "v1.19.32",
    configs: { mode: "global" },
    proxies: baseProxies,
    rules: baseRules,
    lastSyncAt: new Date().toISOString(),
    lastError: null,
  });
  const d = guard.evaluate("api.anthropic.com");
  assert.equal(d.action, "BLOCK");
  assert.equal(d.reasonCode, "CLASH_GLOBAL_DIRECT");
});

test("GuardEngine blocks when protected domain rule routes to DIRECT and generates YAML", () => {
  const guard = new GuardEngine(getDefaultConfig());
  guard.updateClashSnapshot({
    connected: true,
    version: "v1.19.32",
    configs: { mode: "rule" },
    proxies: baseProxies,
    rules: baseRules,
    lastSyncAt: new Date().toISOString(),
    lastError: null,
  });
  guard.updateExitIpState({
    current: {
      ip: "198.51.100.1",
      countryCode: "JP",
      country: "Japan",
      checkedAt: new Date().toISOString(),
      source: "test",
    },
    previous: null,
    countryJumped: false,
    lastCheckedAt: new Date().toISOString(),
    lastError: null,
  });
  const d = guard.evaluate("js.stripe.com");
  assert.equal(d.action, "BLOCK");
  assert.equal(d.reasonCode, "RULE_ROUTES_DIRECT");
  assert.ok(d.yamlSnippet?.includes("DOMAIN-SUFFIX,stripe.com,Proxy"));
});

test("GuardEngine blocks when exit IP is in banned country (CN or HK)", () => {
  const guard = new GuardEngine(getDefaultConfig());
  guard.updateClashSnapshot({
    connected: true,
    version: "v1.19.32",
    configs: { mode: "rule" },
    proxies: baseProxies,
    rules: baseRules,
    lastSyncAt: new Date().toISOString(),
    lastError: null,
  });
  for (const cc of ["CN", "HK"]) {
    guard.updateExitIpState({
      current: {
        ip: "192.0.2.10",
        countryCode: cc,
        country: cc === "CN" ? "China" : "Hong Kong",
        checkedAt: new Date().toISOString(),
        source: "test",
      },
      previous: null,
      countryJumped: false,
      lastCheckedAt: new Date().toISOString(),
      lastError: null,
    });
    const d = guard.evaluate("claude.ai");
    assert.equal(d.action, "BLOCK");
    assert.equal(d.reasonCode, "BANNED_EXIT_COUNTRY");
  }
});

test("GuardEngine allows claude.ai safely when mode=rule, rule=Proxy, exit=US", () => {
  const guard = new GuardEngine(getDefaultConfig());
  guard.updateClashSnapshot({
    connected: true,
    version: "v1.19.32",
    configs: { mode: "rule" },
    proxies: baseProxies,
    rules: baseRules,
    lastSyncAt: new Date().toISOString(),
    lastError: null,
  });
  guard.updateExitIpState({
    current: {
      ip: "8.8.8.8",
      countryCode: "US",
      country: "United States",
      checkedAt: new Date().toISOString(),
      source: "test",
    },
    previous: null,
    countryJumped: false,
    lastCheckedAt: new Date().toISOString(),
    lastError: null,
  });
  const d = guard.evaluate("claude.ai");
  assert.equal(d.action, "ALLOW");
  assert.equal(d.reasonCode, "SAFE");
});

test("GuardEngine warns (or blocks in strictMode) on cross-country IP jump", () => {
  const cfg = getDefaultConfig();
  const guard = new GuardEngine(cfg);
  guard.updateClashSnapshot({
    connected: true,
    version: "v1.19.32",
    configs: { mode: "rule" },
    proxies: baseProxies,
    rules: baseRules,
    lastSyncAt: new Date().toISOString(),
    lastError: null,
  });
  guard.updateExitIpState({
    current: {
      ip: "8.8.8.8",
      countryCode: "US",
      country: "United States",
      checkedAt: new Date().toISOString(),
      source: "test",
    },
    previous: {
      ip: "1.1.1.1",
      countryCode: "JP",
      country: "Japan",
      checkedAt: new Date().toISOString(),
      source: "test",
    },
    countryJumped: true,
    lastCheckedAt: new Date().toISOString(),
    lastError: null,
  });

  assert.equal(guard.evaluate("claude.ai").action, "WARN");
  guard.updateConfig({ ...cfg, strictMode: true });
  assert.equal(guard.evaluate("claude.ai").action, "BLOCK");
  assert.equal(guard.evaluate("claude.ai").reasonCode, "EXIT_IP_JUMPED");
});

test("ExitIpProber ignores CN->JP recovery as jump and clears jump once stable", async () => {
  let step = 0;
  const sequence = [
    { ip: "192.0.2.10", countryCode: "CN", country: "China" },
    { ip: "198.51.100.42", countryCode: "JP", country: "Japan" },
    { ip: "8.8.8.8", countryCode: "US", country: "United States" },
    { ip: "8.8.8.9", countryCode: "US", country: "United States" },
  ];
  const prober = new ExitIpProber(getDefaultConfig(), async () => {
    const item = sequence[step++];
    return { ...item, checkedAt: new Date().toISOString(), source: "test" };
  });

  await prober.probeNow();
  const afterRecover = await prober.probeNow(); // CN -> JP recovery
  assert.equal(afterRecover.countryJumped, false);

  const afterJump = await prober.probeNow(); // JP -> US cross-country jump
  assert.equal(afterJump.countryJumped, true);

  const afterStable = await prober.probeNow(); // US -> US stable
  assert.equal(afterStable.countryJumped, false);
});
