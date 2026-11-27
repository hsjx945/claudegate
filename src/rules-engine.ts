import { normalizeHost } from "./config.js";
import type { MihomoProxy, MihomoRule } from "./mihomo.js";

export interface ProxyChainResolution {
  chain: string[];
  leaf: string;
  isDirect: boolean;
  isReject: boolean;
  hasAutoGroup: boolean;
  autoGroupName?: string;
}

export interface MatchedRuleInfo {
  index: number;
  type: string;
  payload: string;
  proxy: string;
}

export interface RouteEvaluation {
  domain: string;
  mode: string;
  matchedRule: MatchedRuleInfo | null;
  explicitDomainRule: boolean;
  chain: string[];
  leafNode: string;
  isDirect: boolean;
  isReject: boolean;
  hasAutoGroup: boolean;
  autoGroupName?: string;
  riskLevel: "safe" | "warn" | "danger";
  warnings: string[];
}

const AUTO_GROUP_TYPES = new Set(["URLTEST", "FALLBACK", "LOADBALANCE"]);
const DIRECT_TARGETS = new Set(["DIRECT"]);
const REJECT_TARGETS = new Set(["REJECT", "REJECTDROP"]);

export function normalizeType(raw: string): string {
  return String(raw || "")
    .trim()
    .toUpperCase()
    .replace(/[-_\s]/g, "");
}

export function resolveProxyChain(
  startProxy: string,
  proxies: Record<string, MihomoProxy>
): ProxyChainResolution {
  const chain: string[] = [];
  const visited = new Set<string>();
  let current = startProxy;
  let hasAutoGroup = false;
  let autoGroupName: string | undefined;

  while (current && !visited.has(current)) {
    visited.add(current);
    chain.push(current);

    const upper = normalizeType(current);
    if (DIRECT_TARGETS.has(upper)) {
      return {
        chain,
        leaf: "DIRECT",
        isDirect: true,
        isReject: false,
        hasAutoGroup,
        autoGroupName,
      };
    }
    if (REJECT_TARGETS.has(upper)) {
      return {
        chain,
        leaf: "REJECT",
        isDirect: false,
        isReject: true,
        hasAutoGroup,
        autoGroupName,
      };
    }

    const entry = proxies[current];
    if (!entry) {
      break;
    }

    const groupType = normalizeType(entry.type);
    if (AUTO_GROUP_TYPES.has(groupType)) {
      hasAutoGroup = true;
      if (!autoGroupName) {
        autoGroupName = current;
      }
    }

    if (entry.now && typeof entry.now === "string") {
      current = entry.now;
      continue;
    }

    break;
  }

  const leaf = chain.length > 0 ? chain[chain.length - 1] : startProxy || "DIRECT";
  const leafNorm = normalizeType(leaf);
  return {
    chain,
    leaf,
    isDirect: DIRECT_TARGETS.has(leafNorm),
    isReject: REJECT_TARGETS.has(leafNorm),
    hasAutoGroup,
    autoGroupName,
  };
}

function matchDomainRule(cleanDomain: string, rule: MihomoRule): boolean {
  const normType = normalizeType(rule.type);
  const payload = normalizeHost(rule.payload || "");
  if (!payload && normType !== "MATCH") return false;

  switch (normType) {
    case "DOMAIN":
      return cleanDomain === payload;
    case "DOMAINSUFFIX":
      return cleanDomain === payload || cleanDomain.endsWith(`.${payload}`);
    case "DOMAINKEYWORD":
      return cleanDomain.includes(payload);
    default:
      return false;
  }
}

export function evaluateDomainRouting(
  domain: string,
  mode: string,
  rules: MihomoRule[],
  proxies: Record<string, MihomoProxy>
): RouteEvaluation {
  const cleanDomain = normalizeHost(domain);
  const normMode = String(mode || "rule").trim().toLowerCase();
  const warnings: string[] = [];

  if (normMode === "direct") {
    return {
      domain: cleanDomain,
      mode: normMode,
      matchedRule: null,
      explicitDomainRule: false,
      chain: ["DIRECT"],
      leafNode: "DIRECT",
      isDirect: true,
      isReject: false,
      hasAutoGroup: false,
      riskLevel: "danger",
      warnings: ["Clash Verge 当前处于【直连模式 (direct)】，所有流量将直接通过本地真实 IP 发出！"],
    };
  }

  if (normMode === "global") {
    const resolution = resolveProxyChain("GLOBAL", proxies);
    if (resolution.isDirect) {
      warnings.push("Clash Verge 处于【全局模式 (global)】，但 GLOBAL 策略组当前指向 DIRECT 直连！");
    }
    if (resolution.hasAutoGroup) {
      warnings.push(
        `GLOBAL 链路包含自动切换策略组「${resolution.autoGroupName}」，可能导致出口 IP 跳变触发风控。`
      );
    }
    return {
      domain: cleanDomain,
      mode: normMode,
      matchedRule: null,
      explicitDomainRule: false,
      chain: resolution.chain,
      leafNode: resolution.leaf,
      isDirect: resolution.isDirect,
      isReject: resolution.isReject,
      hasAutoGroup: resolution.hasAutoGroup,
      autoGroupName: resolution.autoGroupName,
      riskLevel: resolution.isDirect ? "danger" : resolution.hasAutoGroup ? "warn" : "safe",
      warnings,
    };
  }

  // Rule mode (default)
  let matchedRule: MatchedRuleInfo | null = null;
  let explicitDomainRule = false;
  let fallbackMatchRule: MatchedRuleInfo | null = null;

  for (let i = 0; i < rules.length; i++) {
    const r = rules[i];
    const normType = normalizeType(r.type);
    const idx = typeof r.index === "number" ? r.index : i;

    if (normType === "MATCH") {
      if (!fallbackMatchRule) {
        fallbackMatchRule = {
          index: idx,
          type: r.type,
          payload: r.payload,
          proxy: r.proxy,
        };
      }
      continue;
    }

    if (matchDomainRule(cleanDomain, r)) {
      matchedRule = {
        index: idx,
        type: r.type,
        payload: r.payload,
        proxy: r.proxy,
      };
      explicitDomainRule = true;
      break;
    }
  }

  const effectiveRule = matchedRule || fallbackMatchRule;
  if (!effectiveRule) {
    return {
      domain: cleanDomain,
      mode: normMode,
      matchedRule: null,
      explicitDomainRule: false,
      chain: ["DIRECT"],
      leafNode: "DIRECT",
      isDirect: true,
      isReject: false,
      hasAutoGroup: false,
      riskLevel: "danger",
      warnings: ["未匹配到任何 Clash 规则（也无 MATCH 兜底规则），默认将走直连！"],
    };
  }

  const resolution = resolveProxyChain(effectiveRule.proxy, proxies);

  if (!explicitDomainRule) {
    warnings.push(
      `域名 ${cleanDomain} 未命中显式代理规则，目前仅靠兜底规则 (${effectiveRule.type} -> ${effectiveRule.proxy}) 转发；若调整兜底策略可能泄漏。`
    );
  }
  if (resolution.isDirect) {
    warnings.push(
      `域名 ${cleanDomain} 命中规则 [${effectiveRule.type}, ${effectiveRule.payload || "*"}] -> ${effectiveRule.proxy}，最终解析为 DIRECT 直连！`
    );
  }
  if (resolution.hasAutoGroup) {
    warnings.push(
      `代理链经过自动测速/负载均衡组「${resolution.autoGroupName}」，可能导致出口 IP 跨区跳变。`
    );
  }

  let riskLevel: "safe" | "warn" | "danger" = "safe";
  if (resolution.isDirect) {
    riskLevel = "danger";
  } else if (!explicitDomainRule || resolution.hasAutoGroup) {
    riskLevel = "warn";
  }

  return {
    domain: cleanDomain,
    mode: normMode,
    matchedRule: effectiveRule,
    explicitDomainRule,
    chain: resolution.chain,
    leafNode: resolution.leaf,
    isDirect: resolution.isDirect,
    isReject: resolution.isReject,
    hasAutoGroup: resolution.hasAutoGroup,
    autoGroupName: resolution.autoGroupName,
    riskLevel,
    warnings,
  };
}

export function findPrimaryProxyGroupName(
  proxies: Record<string, MihomoProxy>,
  rules?: MihomoRule[]
): string {
  if (Array.isArray(rules) && rules.length > 0) {
    for (const target of ["claude.ai", "anthropic.com"]) {
      const m = rules.find((r) => {
        const t = normalizeType(r.type);
        const p = normalizeHost(r.payload || "");
        return (t === "DOMAINSUFFIX" || t === "DOMAIN") && p === target;
      });
      if (
        m &&
        m.proxy &&
        proxies[m.proxy] &&
        !DIRECT_TARGETS.has(normalizeType(m.proxy)) &&
        !REJECT_TARGETS.has(normalizeType(m.proxy))
      ) {
        return m.proxy;
      }
    }
  }

  const candidates = ["Claude", "Proxy", "PROXY", "AI", "GPT", "节点选择", "代理", "Others"];
  for (const name of candidates) {
    if (proxies[name]) {
      return name;
    }
  }
  for (const [name, p] of Object.entries(proxies)) {
    if (
      Array.isArray(p.all) &&
      name !== "GLOBAL" &&
      normalizeType(p.now || "") !== "DIRECT"
    ) {
      return name;
    }
  }
  return "Proxy";
}
