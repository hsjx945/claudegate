import {
  matchProtectedDomain,
  normalizeHost,
  type AppConfig,
  type ProtectedDomainEntry,
} from "./config.js";
import { detectBannedRegionHintInNodeName, type ExitIpState } from "./exit-ip.js";
import type { MihomoConfigs, MihomoProxy, MihomoRule } from "./mihomo.js";
import {
  evaluateDomainRouting,
  findPrimaryProxyGroupName,
  resolveProxyChain,
  type RouteEvaluation,
} from "./rules-engine.js";

export type GuardAction = "ALLOW" | "WARN" | "BLOCK";

export type GuardReasonCode =
  | "NON_PROTECTED"
  | "SAFE"
  | "CLASH_OFFLINE"
  | "CLASH_DIRECT_MODE"
  | "CLASH_GLOBAL_DIRECT"
  | "RULE_ROUTES_DIRECT"
  | "BANNED_EXIT_COUNTRY"
  | "NODE_NAME_BANNED_HINT"
  | "EXIT_IP_UNKNOWN"
  | "EXIT_IP_JUMPED"
  | "AUTO_PROXY_GROUP"
  | "MISSING_EXPLICIT_RULE";

export interface GuardDecision {
  action: GuardAction;
  isProtected: boolean;
  protectedEntry: ProtectedDomainEntry | null;
  domain: string;
  reasonCode: GuardReasonCode;
  message: string;
  fixHint: string;
  yamlSnippet?: string;
  route?: RouteEvaluation;
  clashMode: string;
  exitIp?: string;
  exitCountry?: string;
}

export interface ClashSnapshot {
  connected: boolean;
  version: string;
  configs: MihomoConfigs | null;
  proxies: Record<string, MihomoProxy>;
  rules: MihomoRule[];
  lastSyncAt: string | null;
  lastError: string | null;
}

export interface DomainAuditItem {
  domain: string;
  category: string;
  note?: string;
  route: RouteEvaluation;
  decision: GuardDecision;
}

export interface FullAuditReport {
  generatedAt: string;
  clashConnected: boolean;
  clashMode: string;
  globalTarget: string | null;
  globalRisk: boolean;
  primaryProxyGroup: string;
  totalProtected: number;
  safeCount: number;
  warnCount: number;
  dangerCount: number;
  missingExplicitRuleDomains: string[];
  recommendedYamlSnippet: string;
  items: DomainAuditItem[];
}

export class GuardEngine {
  private config: AppConfig;
  private clash: ClashSnapshot = {
    connected: false,
    version: "",
    configs: null,
    proxies: {},
    rules: [],
    lastSyncAt: null,
    lastError: "尚未连接 Clash Verge",
  };
  private exitIp: ExitIpState = {
    current: null,
    previous: null,
    countryJumped: false,
    lastCheckedAt: null,
    lastError: null,
  };

  constructor(config: AppConfig) {
    this.config = config;
  }

  updateConfig(config: AppConfig): void {
    this.config = config;
  }

  updateClashSnapshot(snapshot: ClashSnapshot): void {
    this.clash = snapshot;
  }

  updateExitIpState(state: ExitIpState): void {
    this.exitIp = state;
  }

  getClashSnapshot(): ClashSnapshot {
    return this.clash;
  }

  getExitIpState(): ExitIpState {
    return this.exitIp;
  }

  getPrimaryClaudeNodeInfo(): { group: string; chain: string[]; leaf: string } {
    if (!this.clash.connected) {
      return { group: "未知", chain: [], leaf: "未知" };
    }
    const evalRes = evaluateDomainRouting(
      "claude.ai",
      this.clash.configs?.mode || "rule",
      this.clash.rules,
      this.clash.proxies
    );
    const group = evalRes.matchedRule?.proxy || findPrimaryProxyGroupName(this.clash.proxies, this.clash.rules);
    return {
      group,
      chain: evalRes.chain,
      leaf: evalRes.leafNode,
    };
  }

  buildYamlRuleForDomain(domain: string, matchedEntry?: ProtectedDomainEntry | null): string {
    const targetDomain = matchedEntry?.domain || normalizeHost(domain);
    const group = findPrimaryProxyGroupName(this.clash.proxies, this.clash.rules);
    const isExactHost = targetDomain.split(".").length >= 4 || targetDomain.startsWith("http-intake.");
    const ruleType = isExactHost ? "DOMAIN" : "DOMAIN-SUFFIX";
    return `  - ${ruleType},${targetDomain},${group}`;
  }

  evaluate(host: string): GuardDecision {
    const cleanDomain = normalizeHost(host);
    const matched = matchProtectedDomain(cleanDomain, this.config.protectedDomains);
    const clashMode = String(this.clash.configs?.mode || "unknown").toLowerCase();
    const exitIpStr = this.exitIp.current?.ip;
    const exitCountry = this.exitIp.current?.countryCode;

    if (!matched) {
      return {
        action: "ALLOW",
        isProtected: false,
        protectedEntry: null,
        domain: cleanDomain,
        reasonCode: "NON_PROTECTED",
        message: "非 Claude 受保护域名，正常放行。",
        fixHint: "",
        clashMode,
        exitIp: exitIpStr,
        exitCountry,
      };
    }

    // 1. Clash Verge offline -> Fail-Closed BLOCK
    if (!this.clash.connected || !this.clash.configs) {
      return {
        action: "BLOCK",
        isProtected: true,
        protectedEntry: matched,
        domain: cleanDomain,
        reasonCode: "CLASH_OFFLINE",
        message: `已拦截 ${cleanDomain}：无法连接到 Clash Verge 控制接口（${this.clash.lastError || "未运行"}），为防止直连封号已强制阻断！`,
        fixHint:
          "请启动 Clash Verge 并确认代理服务正常运行（默认端口 7897），然后再刷新重试。",
        clashMode: "offline",
        exitIp: exitIpStr,
        exitCountry,
      };
    }

    // 2. Clash Verge in Direct Mode -> BLOCK
    if (clashMode === "direct") {
      return {
        action: "BLOCK",
        isProtected: true,
        protectedEntry: matched,
        domain: cleanDomain,
        reasonCode: "CLASH_DIRECT_MODE",
        message: `已拦截 ${cleanDomain}：检测到 Clash Verge 当前处于【直连模式 (Direct)】，直接访问会导致中国 IP 泄漏并封号！`,
        fixHint:
          "请在 Clash Verge 主界面将出站模式从「直连」切换为「规则 (Rule)」，或点击控制台的「一键修复全部隐患」按钮。",
        clashMode,
        exitIp: exitIpStr,
        exitCountry,
      };
    }

    // 3. Evaluate domain routing under current mode/rules/proxies
    const route = evaluateDomainRouting(
      cleanDomain,
      clashMode,
      this.clash.rules,
      this.clash.proxies
    );

    if (clashMode === "global" && route.isDirect) {
      return {
        action: "BLOCK",
        isProtected: true,
        protectedEntry: matched,
        domain: cleanDomain,
        reasonCode: "CLASH_GLOBAL_DIRECT",
        message: `已拦截 ${cleanDomain}：Clash Verge 当前为【全局模式 (Global)】，但 GLOBAL 策略组选中的是 DIRECT 直连！`,
        fixHint:
          "请立即将 Clash Verge 切换回「规则 (Rule)」模式，或在 GLOBAL 策略组中选择美国/日本等合规静态节点。",
        route,
        clashMode,
        exitIp: exitIpStr,
        exitCountry,
      };
    }

    // 4. Rule routes to DIRECT (or Reject? No, direct is leak!)
    if (route.isDirect) {
      const yamlLine = this.buildYamlRuleForDomain(cleanDomain, matched);
      return {
        action: "BLOCK",
        isProtected: true,
        protectedEntry: matched,
        domain: cleanDomain,
        reasonCode: "RULE_ROUTES_DIRECT",
        message: `已拦截 ${cleanDomain}：当前 Clash 规则将此域名路由到了 DIRECT 直连（匹配：${route.matchedRule ? `${route.matchedRule.type},${route.matchedRule.payload} -> ${route.matchedRule.proxy}` : "无规则"}）！`,
        fixHint: `请在 Clash Verge -> 订阅 -> 右键「编辑规则/覆写(Merge)」中，将以下规则添加到 rules 最顶部：\n${yamlLine}`,
        yamlSnippet: yamlLine,
        route,
        clashMode,
        exitIp: exitIpStr,
        exitCountry,
      };
    }

    // 5. Check real Exit IP country
    if (this.exitIp.current) {
      const cc = this.exitIp.current.countryCode.toUpperCase();
      if (this.config.bannedCountries.includes(cc)) {
        return {
          action: "BLOCK",
          isProtected: true,
          protectedEntry: matched,
          domain: cleanDomain,
          reasonCode: "BANNED_EXIT_COUNTRY",
          message: `已拦截 ${cleanDomain}：检测到当前代理出口 IP (${this.exitIp.current.ip}) 位于受限地区【${this.exitIp.current.country} (${cc})】，节点「${route.leafNode}」极易导致 Claude 封号！`,
          fixHint: `请在 Clash Verge 中将「${route.matchedRule?.proxy || findPrimaryProxyGroupName(this.clash.proxies, this.clash.rules)}」策略组切换到美国、日本、新加坡等非受限地区原生/静态节点，然后点击「重新检测出口 IP」。`,
          route,
          clashMode,
          exitIp: exitIpStr,
          exitCountry: cc,
        };
      }
    } else {
      // Exit IP not probed yet or failed; check node name hint first
      const nodeHint = detectBannedRegionHintInNodeName(route.leafNode);
      if (nodeHint && this.config.bannedCountries.includes(nodeHint.code)) {
        return {
          action: "BLOCK",
          isProtected: true,
          protectedEntry: matched,
          domain: cleanDomain,
          reasonCode: "NODE_NAME_BANNED_HINT",
          message: `已拦截 ${cleanDomain}：出口 IP 尚未完成探测，但当前节点「${route.leafNode}」名称疑似受限地区（${nodeHint.label}）！`,
          fixHint:
            "请在 Clash Verge 切换到美国、日本或新加坡等安全地区节点，并在控制台点击「重新检测出口 IP」。",
          route,
          clashMode,
        };
      }

      if (this.config.strictMode) {
        return {
          action: "BLOCK",
          isProtected: true,
          protectedEntry: matched,
          domain: cleanDomain,
          reasonCode: "EXIT_IP_UNKNOWN",
          message: `严格模式已拦截 ${cleanDomain}：当前代理出口 IP 状态未知（${this.exitIp.lastError || "正在初始化探测"}）。`,
          fixHint: "请等待出口 IP 探测完成或在控制台点击「重新检测出口 IP」。",
          route,
          clashMode,
        };
      }
    }

    // 6. Warnings (or BLOCK if strictMode is enabled)
    const warnOrBlock: GuardAction = this.config.strictMode ? "BLOCK" : "WARN";

    if (this.exitIp.countryJumped && this.exitIp.previous && this.exitIp.current) {
      return {
        action: warnOrBlock,
        isProtected: true,
        protectedEntry: matched,
        domain: cleanDomain,
        reasonCode: "EXIT_IP_JUMPED",
        message: `${warnOrBlock === "BLOCK" ? "严格模式已拦截" : "风险预警"} ${cleanDomain}：检测到出口国家从 ${this.exitIp.previous.countryCode} (${this.exitIp.previous.ip}) 跳变为 ${this.exitIp.current.countryCode} (${this.exitIp.current.ip})，频繁跨国跳变容易触发风控！`,
        fixHint:
          "建议在 Clash Verge 为 Claude 固定单一国家/地区的优质静态节点，避免在多个国家节点间频繁切换。",
        route,
        clashMode,
        exitIp: exitIpStr,
        exitCountry,
      };
    }

    if (route.hasAutoGroup) {
      return {
        action: warnOrBlock,
        isProtected: true,
        protectedEntry: matched,
        domain: cleanDomain,
        reasonCode: "AUTO_PROXY_GROUP",
        message: `${warnOrBlock === "BLOCK" ? "严格模式已拦截" : "风险预警"} ${cleanDomain}：策略组「${route.autoGroupName}」为自动测速/负载均衡模式，会自动切换节点导致 IP 跳变！`,
        fixHint: `请在 Clash Verge 中将「${route.autoGroupName}」改为手动选择 (Select) 策略组，或为 Claude 单独指定固定节点。`,
        route,
        clashMode,
        exitIp: exitIpStr,
        exitCountry,
      };
    }

    if (!route.explicitDomainRule && clashMode === "rule") {
      const yamlLine = this.buildYamlRuleForDomain(cleanDomain, matched);
      return {
        action: "WARN",
        isProtected: true,
        protectedEntry: matched,
        domain: cleanDomain,
        reasonCode: "MISSING_EXPLICIT_RULE",
        message: `放行但有隐患 (${cleanDomain})：Clash 未配置该域名的显式规则，当前靠兜底规则 (${route.matchedRule?.proxy || "MATCH"}) -> 「${route.leafNode}」转发。`,
        fixHint: `建议在 Clash Verge 覆写规则顶部补全显式规则，防止修改默认策略时泄漏：\n${yamlLine}`,
        yamlSnippet: yamlLine,
        route,
        clashMode,
        exitIp: exitIpStr,
        exitCountry,
      };
    }

    return {
      action: "ALLOW",
      isProtected: true,
      protectedEntry: matched,
      domain: cleanDomain,
      reasonCode: "SAFE",
      message: `安全放行 ${cleanDomain} -> 节点「${route.leafNode}」${exitIpStr ? ` (${exitCountry} · ${exitIpStr})` : ""}`,
      fixHint: "",
      route,
      clashMode,
      exitIp: exitIpStr,
      exitCountry,
    };
  }

  auditAllProtectedDomains(): FullAuditReport {
    const clashMode = String(this.clash.configs?.mode || "offline").toLowerCase();
    const primaryGroup = findPrimaryProxyGroupName(this.clash.proxies, this.clash.rules);
    const globalRes = this.clash.connected
      ? resolveProxyChain("GLOBAL", this.clash.proxies)
      : null;

    const items: DomainAuditItem[] = [];
    const missingDomains: string[] = [];
    const yamlLines: string[] = [];

    let safeCount = 0;
    let warnCount = 0;
    let dangerCount = 0;

    for (const entry of this.config.protectedDomains) {
      const route = this.clash.connected
        ? evaluateDomainRouting(entry.domain, clashMode, this.clash.rules, this.clash.proxies)
        : evaluateDomainRouting(entry.domain, "direct", [], {});
      const decision = this.evaluate(entry.domain);

      if (decision.action === "BLOCK" || route.riskLevel === "danger") {
        dangerCount++;
      } else if (decision.action === "WARN" || route.riskLevel === "warn") {
        warnCount++;
      } else {
        safeCount++;
      }

      const ruleCheck = this.clash.connected
        ? evaluateDomainRouting(entry.domain, "rule", this.clash.rules, this.clash.proxies)
        : route;
      if (this.clash.connected && (!ruleCheck.explicitDomainRule || ruleCheck.isDirect)) {
        missingDomains.push(entry.domain);
        yamlLines.push(this.buildYamlRuleForDomain(entry.domain, entry));
      }

      items.push({
        domain: entry.domain,
        category: entry.category,
        note: entry.note,
        route,
        decision,
      });
    }

    const recommendedYamlSnippet =
      yamlLines.length > 0
        ? `# 将以下规则添加到 Clash Verge 覆写 (Merge / Script) 的 rules 最顶部：\nrules:\n${yamlLines.join("\n")}`
        : "# 所有受保护的 Claude 生态域名均已配置显式代理规则！";

    return {
      generatedAt: new Date().toISOString(),
      clashConnected: this.clash.connected,
      clashMode,
      globalTarget: globalRes ? globalRes.leaf : null,
      globalRisk: Boolean(globalRes && globalRes.isDirect),
      primaryProxyGroup: primaryGroup,
      totalProtected: this.config.protectedDomains.length,
      safeCount,
      warnCount,
      dangerCount,
      missingExplicitRuleDomains: missingDomains,
      recommendedYamlSnippet,
      items,
    };
  }
}
