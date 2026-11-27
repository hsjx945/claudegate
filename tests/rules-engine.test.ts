import assert from "node:assert/strict";
import test from "node:test";
import type { MihomoProxy, MihomoRule } from "../src/mihomo.js";
import { evaluateDomainRouting, resolveProxyChain } from "../src/rules-engine.js";

const sampleProxies: Record<string, MihomoProxy> = {
  DIRECT: { name: "DIRECT", type: "Direct" },
  REJECT: { name: "REJECT", type: "Reject" },
  GLOBAL: { name: "GLOBAL", type: "Selector", now: "DIRECT", all: ["DIRECT", "Proxy"] },
  Proxy: { name: "Proxy", type: "Selector", now: "JP-Tokyo-01", all: ["JP-Tokyo-01", "US-LA-01"] },
  Others: { name: "Others", type: "Selector", now: "Proxy", all: ["Proxy", "DIRECT"] },
  AutoFast: { name: "AutoFast", type: "URLTest", now: "US-LA-01", all: ["US-LA-01", "SG-01"] },
  "JP-Tokyo-01": { name: "JP-Tokyo-01", type: "Shadowsocks" },
  "US-LA-01": { name: "US-LA-01", type: "Trojan" },
};

const sampleRules: MihomoRule[] = [
  { index: 0, type: "DomainSuffix", payload: "anthropic.com", proxy: "Proxy" },
  { index: 1, type: "DomainSuffix", payload: "claude.ai", proxy: "Proxy" },
  { index: 2, type: "Domain", payload: "http-intake.logs.us5.datadoghq.com", proxy: "AutoFast" },
  { index: 3, type: "DomainKeyword", payload: "bilibili", proxy: "DIRECT" },
  { index: 4, type: "Match", payload: "", proxy: "Others" },
];

test("resolveProxyChain resolves nested Selector chains", () => {
  const res = resolveProxyChain("Others", sampleProxies);
  assert.deepEqual(res.chain, ["Others", "Proxy", "JP-Tokyo-01"]);
  assert.equal(res.leaf, "JP-Tokyo-01");
  assert.equal(res.isDirect, false);
  assert.equal(res.hasAutoGroup, false);
});

test("evaluateDomainRouting matches PascalCase DomainSuffix safely", () => {
  const res = evaluateDomainRouting("api.anthropic.com", "rule", sampleRules, sampleProxies);
  assert.equal(res.explicitDomainRule, true);
  assert.equal(res.leafNode, "JP-Tokyo-01");
  assert.equal(res.isDirect, false);
  assert.equal(res.riskLevel, "safe");
});

test("evaluateDomainRouting flags missing explicit domain rule falling back to Match", () => {
  const res = evaluateDomainRouting("statsig.com", "rule", sampleRules, sampleProxies);
  assert.equal(res.explicitDomainRule, false);
  assert.equal(res.matchedRule?.type, "Match");
  assert.equal(res.leafNode, "JP-Tokyo-01");
  assert.equal(res.riskLevel, "warn");
});

test("evaluateDomainRouting flags URLTest auto group warning", () => {
  const res = evaluateDomainRouting(
    "http-intake.logs.us5.datadoghq.com",
    "rule",
    sampleRules,
    sampleProxies
  );
  assert.equal(res.explicitDomainRule, true);
  assert.equal(res.hasAutoGroup, true);
  assert.equal(res.autoGroupName, "AutoFast");
  assert.equal(res.riskLevel, "warn");
});

test("evaluateDomainRouting flags direct mode as danger", () => {
  const res = evaluateDomainRouting("claude.ai", "direct", sampleRules, sampleProxies);
  assert.equal(res.isDirect, true);
  assert.equal(res.leafNode, "DIRECT");
  assert.equal(res.riskLevel, "danger");
});

test("evaluateDomainRouting flags global mode when GLOBAL -> DIRECT", () => {
  const res = evaluateDomainRouting("claude.ai", "global", sampleRules, sampleProxies);
  assert.equal(res.isDirect, true);
  assert.equal(res.leafNode, "DIRECT");
  assert.equal(res.riskLevel, "danger");
});
