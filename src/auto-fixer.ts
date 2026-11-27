import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ensureDataDir, type AppConfig } from "./config.js";
import type { Store } from "./db.js";
import type { GuardEngine } from "./guard.js";
import { enableGateSystemProxy, getSystemProxyStatus } from "./macos-proxy.js";
import type { MihomoClient, MihomoProxy } from "./mihomo.js";
import { normalizeType, resolveProxyChain } from "./rules-engine.js";
import type { Watchdog } from "./watchdog.js";

export interface AutoFixOptions {
  includeSystemProxy?: boolean;
  clashVergeDir?: string;
}

export interface AutoFixStepResult {
  id: string;
  title: string;
  status: "fixed" | "skipped" | "failed";
  detail: string;
  backupPath?: string;
}

export interface AutoFixReport {
  ok: boolean;
  timestamp: string;
  fixedCount: number;
  skippedCount: number;
  failedCount: number;
  steps: AutoFixStepResult[];
}

const SCRIPT_START_MARKER = "// >>> CLAUDEGATE_AUTO_RULES_START";
const SCRIPT_END_MARKER = "// <<< CLAUDEGATE_AUTO_RULES_END";

const SKIP_NODE_PATTERN =
  /^(DIRECT|REJECT|REJECT-DROP|PASS)$/i;
const INFO_OR_BANNED_NODE_PATTERN =
  /剩余流量|套餐到期|官网|客户端|测试|香港|Hong\s*Kong|(^|[^a-zA-Z])HK([^a-zA-Z]|$)|中国|内地|大陆|(^|[^a-zA-Z])CN([^a-zA-Z]|$)|澳门|Macau|Macao|(^|[^a-zA-Z])MO([^a-zA-Z]|$)|俄罗斯|Russia|(^|[^a-zA-Z])RU([^a-zA-Z]|$)/i;
const PREFERRED_NODE_PATTERN =
  /美国|US|United\s*States|日本|JP|Japan|新加坡|SG|Singapore|台湾|TW|Taiwan|英国|UK|德国|DE|韩国|KR/i;

export function getDefaultClashVergeDir(): string {
  return path.join(
    os.homedir(),
    "Library/Application Support/io.github.clash-verge-rev.clash-verge-rev"
  );
}

export function pickSafeReplacementNode(
  groupName: string,
  proxies: Record<string, MihomoProxy>,
  bannedCountries: string[]
): string | null {
  const group = proxies[groupName];
  if (!group || !Array.isArray(group.all)) return null;

  const bannedReList = bannedCountries.map((c) => new RegExp(`(^|[^a-zA-Z])${c}([^a-zA-Z]|$)`, "i"));
  const candidates: string[] = [];

  for (const name of group.all) {
    if (SKIP_NODE_PATTERN.test(name)) continue;
    if (INFO_OR_BANNED_NODE_PATTERN.test(name)) continue;
    if (bannedReList.some((re) => re.test(name))) continue;
    // If candidate is itself a subgroup that resolves to DIRECT, skip it
    if (proxies[name]?.all) {
      const res = resolveProxyChain(name, proxies);
      if (res.isDirect || res.isReject) continue;
    }
    candidates.push(name);
  }

  if (candidates.length === 0) return null;
  const preferred = candidates.find((c) => PREFERRED_NODE_PATTERN.test(c));
  return preferred || candidates[0];
}

export function patchClashVergeScript(
  scriptContent: string,
  ruleLines: string[],
  opts: { disableIpv6?: boolean } = {}
): string {
  const startIdx = scriptContent.indexOf(SCRIPT_START_MARKER);
  const endIdx = scriptContent.indexOf(SCRIPT_END_MARKER);
  let base = scriptContent;
  if (startIdx !== -1 && endIdx !== -1 && endIdx > startIdx) {
    base =
      scriptContent.slice(0, startIdx).trimEnd() +
      "\n" +
      scriptContent.slice(endIdx + SCRIPT_END_MARKER.length).trimStart();
  }
  base = base.trimEnd();

  const cleanRules = Array.from(
    new Set(ruleLines.map((l) => l.trim().replace(/^-\s*/, "")).filter(Boolean))
  );
  const hasMainDecl = /\bfunction\s+main\s*\(/.test(base) || /\b(var|let|const)\s+main\s*=/.test(base);
  const disableIpv6 = opts.disableIpv6 !== false;

  const blockLines = [
    SCRIPT_START_MARKER,
    ";(function () {",
    `  var __cgRules = ${JSON.stringify(cleanRules, null, 2).replace(/\n/g, "\n  ")};`,
    "  function __cgApply(cfg) {",
    '    if (!cfg || typeof cfg !== "object") return cfg;',
    ...(disableIpv6 ? ["    cfg.ipv6 = false;"] : []),
    "    var existing = Array.isArray(cfg.rules) ? cfg.rules : [];",
    "    var seen = {};",
    "    var merged = [];",
    "    for (var i = 0; i < __cgRules.length; i++) {",
    "      if (!seen[__cgRules[i]]) {",
    "        seen[__cgRules[i]] = true;",
    "        merged.push(__cgRules[i]);",
    "      }",
    "    }",
    "    for (var j = 0; j < existing.length; j++) {",
    "      if (!seen[existing[j]]) {",
    "        seen[existing[j]] = true;",
    "        merged.push(existing[j]);",
    "      }",
    "    }",
    "    cfg.rules = merged;",
    "    return cfg;",
    "  }",
    hasMainDecl
      ? [
          "  var __cgOrigMain = main;",
          "  main = function (config) {",
          "    return __cgApply(__cgOrigMain(config));",
          "  };",
        ].join("\n")
      : [
          "  globalThis.main = function (config) {",
          "    return __cgApply(config);",
          "  };",
        ].join("\n"),
    "})();",
    SCRIPT_END_MARKER,
  ];

  const block = blockLines.join("\n");
  if (!base) {
    return `${block}\n`;
  }
  return `${base}\n\n${block}\n`;
}

export function buildPatchedRuntimeYaml(
  originalYaml: string,
  missingRuleLines: string[],
  opts: { disableIpv6?: boolean } = {}
): string {
  const normalizedRules = Array.from(
    new Set(
      missingRuleLines
        .map((r) => r.trim().replace(/^-\s*/, ""))
        .filter(Boolean)
    )
  );

  // Strip external-controller(-unix) so live Mihomo keeps its running privileged control listeners
  let lines = originalYaml
    .split(/\r?\n/)
    .filter((line) => !/^external-controller(-unix)?\s*:/.test(line));

  if (opts.disableIpv6) {
    let foundIpv6 = false;
    lines = lines.map((line) => {
      if (/^ipv6\s*:/.test(line)) {
        foundIpv6 = true;
        return "ipv6: false";
      }
      return line;
    });
    if (!foundIpv6) {
      lines.unshift("ipv6: false");
    }
  }
  const rulesIdx = lines.findIndex((line) => /^rules\s*:\s*$/.test(line));
  if (rulesIdx === -1) {
    const appended = normalizedRules.map((r) => `- ${r}`);
    return [...lines, "rules:", ...appended, ""].join("\n");
  }

  const existingRuleSet = new Set<string>();
  for (let i = rulesIdx + 1; i < lines.length; i++) {
    const l = lines[i].trim();
    if (!l || l.startsWith("#")) continue;
    if (!l.startsWith("-") && /^[a-zA-Z0-9_-]+\s*:/.test(l)) break;
    if (l.startsWith("-")) {
      existingRuleSet.add(l.replace(/^-\s*/, "").trim());
    }
  }

  const toInsert = normalizedRules
    .filter((r) => !existingRuleSet.has(r))
    .map((r) => `- ${r}`);

  const out = [
    ...lines.slice(0, rulesIdx + 1),
    ...toInsert,
    ...lines.slice(rulesIdx + 1),
  ];
  return out.join("\n");
}

function saveBackupFile(sourcePath: string, label: string): string | undefined {
  if (!fs.existsSync(sourcePath)) return undefined;
  const backupDir = path.join(ensureDataDir(), "backups");
  fs.mkdirSync(backupDir, { recursive: true });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const backupPath = path.join(backupDir, `${label}.${stamp}.bak`);
  fs.copyFileSync(sourcePath, backupPath);
  return backupPath;
}

export async function runAutoFix(
  deps: {
    config: AppConfig;
    mihomo: MihomoClient;
    guard: GuardEngine;
    store: Store;
    watchdog: Watchdog;
  },
  options: AutoFixOptions = {}
): Promise<AutoFixReport> {
  const steps: AutoFixStepResult[] = [];
  const { config, mihomo, guard, store, watchdog } = deps;
  const vergeDir = options.clashVergeDir || getDefaultClashVergeDir();

  // Sync latest snapshot first
  await watchdog.syncOnce();
  let clash = guard.getClashSnapshot();

  if (!clash.connected || !clash.configs) {
    steps.push({
      id: "clash_connection",
      title: "连接 Clash Verge 控制接口",
      status: "failed",
      detail: `无法连接 Clash Verge (${clash.lastError || "未启动"})，请先启动 Clash Verge 后再执行一键修复。`,
    });
    return {
      ok: false,
      timestamp: new Date().toISOString(),
      fixedCount: 0,
      skippedCount: 0,
      failedCount: 1,
      steps,
    };
  }

  // 1. Fix Clash Mode -> rule
  const currentMode = String(clash.configs.mode || "rule").toLowerCase();
  const globalRes = resolveProxyChain("GLOBAL", clash.proxies);
  if (currentMode === "direct" || (currentMode === "global" && globalRes.isDirect)) {
    try {
      await mihomo.patchConfigs({ mode: "rule" });
      steps.push({
        id: "fix_mode",
        title: "恢复 Clash Verge 为规则模式 (Rule)",
        status: "fixed",
        detail: `已将出站模式从 ${currentMode.toUpperCase()} 自动切换回 RULE 模式。`,
      });
    } catch (err) {
      steps.push({
        id: "fix_mode",
        title: "恢复 Clash Verge 为规则模式 (Rule)",
        status: "failed",
        detail: `切换失败: ${(err as Error).message}`,
      });
    }
  } else {
    steps.push({
      id: "fix_mode",
      title: "检查 Clash Verge 出站模式",
      status: "skipped",
      detail: `当前已是 ${currentMode.toUpperCase()} 模式，无需修改。`,
    });
  }

  // Refresh after potential mode fix
  await watchdog.syncOnce();
  clash = guard.getClashSnapshot();
  const auditBefore = guard.auditAllProtectedDomains();
  const primaryGroup = auditBefore.primaryProxyGroup;

  // 2. Fix GLOBAL group pointing to DIRECT
  const latestGlobalRes = resolveProxyChain("GLOBAL", clash.proxies);
  const globalGroup = clash.proxies["GLOBAL"];
  if (latestGlobalRes.isDirect && globalGroup && Array.isArray(globalGroup.all)) {
    const safeGlobalTarget = globalGroup.all.includes(primaryGroup)
      ? primaryGroup
      : pickSafeReplacementNode("GLOBAL", clash.proxies, config.bannedCountries);
    if (safeGlobalTarget) {
      try {
        await mihomo.selectProxy("GLOBAL", safeGlobalTarget);
        steps.push({
          id: "fix_global_group",
          title: "消除 GLOBAL 策略组直连隐患",
          status: "fixed",
          detail: `已将 GLOBAL 策略组从 DIRECT 切换为「${safeGlobalTarget}」（即使误切全局模式也不会裸连）。`,
        });
      } catch (err) {
        steps.push({
          id: "fix_global_group",
          title: "消除 GLOBAL 策略组直连隐患",
          status: "failed",
          detail: `修改 GLOBAL 失败: ${(err as Error).message}`,
        });
      }
    } else {
      steps.push({
        id: "fix_global_group",
        title: "消除 GLOBAL 策略组直连隐患",
        status: "failed",
        detail: "未在 GLOBAL 中找到合适的非受限替代节点。",
      });
    }
  } else {
    steps.push({
      id: "fix_global_group",
      title: "检查 GLOBAL 策略组",
      status: "skipped",
      detail: `GLOBAL 当前指向「${latestGlobalRes.leaf}」，无直连风险。`,
    });
  }

  // 3. Fix Banned Exit IP / DIRECT primary node
  const primaryInfo = guard.getPrimaryClaudeNodeInfo();
  const exitState = guard.getExitIpState();
  const exitCountry = exitState.current?.countryCode?.toUpperCase() || "";
  const isBannedExit = Boolean(exitCountry && config.bannedCountries.includes(exitCountry));
  const isPrimaryDirect = normalizeType(primaryInfo.leaf) === "DIRECT";

  if (isBannedExit || isPrimaryDirect) {
    const candidate = pickSafeReplacementNode(
      primaryGroup,
      clash.proxies,
      config.bannedCountries
    );
    if (candidate) {
      try {
        await mihomo.selectProxy(primaryGroup, candidate);
        await watchdog.probeIpNow();
        const newIp = guard.getExitIpState().current;
        steps.push({
          id: "fix_banned_node",
          title: "切换 Claude 主策略组到合规节点",
          status: "fixed",
          detail: `已将「${primaryGroup}」切换为「${candidate}」${
            newIp ? `（当前出口 IP: ${newIp.countryCode} · ${newIp.ip}）` : ""
          }。`,
        });
      } catch (err) {
        steps.push({
          id: "fix_banned_node",
          title: "切换 Claude 主策略组到合规节点",
          status: "failed",
          detail: `切换节点失败: ${(err as Error).message}`,
        });
      }
    } else {
      steps.push({
        id: "fix_banned_node",
        title: "切换 Claude 主策略组到合规节点",
        status: "failed",
        detail: `出口位于受限地区 (${exitCountry || "DIRECT"})，且未在「${primaryGroup}」中找到可用的美/日/新安全节点。`,
      });
    }
  } else {
    steps.push({
      id: "fix_banned_node",
      title: "检查 Claude 节点出口地区",
      status: "skipped",
      detail: `当前出口为 ${exitCountry || "合规地区"}（节点「${primaryInfo.leaf}」），无需切换。`,
    });
  }

  // 4. Fix Missing Explicit Claude Rules & IPv6 Leak (Persist in Script.js + Hot-reload runtime YAML)
  await watchdog.syncOnce();
  clash = guard.getClashSnapshot();
  const auditForRules = guard.auditAllProtectedDomains();
  const ipv6Enabled = Boolean(clash.configs?.ipv6);
  const needsRules = auditForRules.missingExplicitRuleDomains.length > 0;

  if (needsRules || ipv6Enabled) {
    const ruleLines = auditForRules.items
      .filter((item) => !item.route.explicitDomainRule || item.route.isDirect)
      .map((item) => guard.buildYamlRuleForDomain(item.domain, { domain: item.domain, category: "custom" }).trim().replace(/^-\s*/, ""));

    const scriptPath = path.join(vergeDir, "profiles", "Script.js");
    const runtimeYamlPath = path.join(vergeDir, "clash-verge.yaml");
    let scriptBackup: string | undefined;

    try {
      let existingScript = "";
      if (fs.existsSync(scriptPath)) {
        existingScript = fs.readFileSync(scriptPath, "utf8");
      } else {
        fs.mkdirSync(path.dirname(scriptPath), { recursive: true });
      }
      const patchedScript = patchClashVergeScript(existingScript, ruleLines, {
        disableIpv6: true,
      });
      if (patchedScript !== existingScript) {
        if (fs.existsSync(scriptPath)) {
          scriptBackup = saveBackupFile(scriptPath, "Script.js");
        }
        fs.writeFileSync(scriptPath, patchedScript, "utf8");
      }

      const liveProxies = await mihomo.getProxies();
      const savedSelections: Array<{ group: string; now: string }> = [];
      for (const [name, p] of Object.entries(liveProxies)) {
        if (
          normalizeType(p.type) === "SELECTOR" &&
          typeof p.now === "string" &&
          p.now.length > 0
        ) {
          savedSelections.push({ group: name, now: p.now });
        }
      }

      let hotReloaded = false;
      if (fs.existsSync(runtimeYamlPath)) {
        const origYaml = fs.readFileSync(runtimeYamlPath, "utf8");
        const patchedYaml = buildPatchedRuntimeYaml(origYaml, ruleLines, {
          disableIpv6: ipv6Enabled,
        });
        await mihomo.reloadConfigPayload(patchedYaml);
        hotReloaded = true;

        for (const sel of savedSelections) {
          try {
            await mihomo.selectProxy(sel.group, sel.now);
          } catch {
            // ignore
          }
        }
      }

      if (needsRules) {
        steps.push({
          id: "fix_missing_rules",
          title: `补全 ${ruleLines.length} 条 Claude 生态显式代理规则`,
          status: "fixed",
          backupPath: scriptBackup,
          detail: hotReloaded
            ? `已写入 Clash Verge 全局脚本 Script.js（订阅更新不丢失），并已热重载立即生效（已保留原有节点选择）。`
            : `已写入 Clash Verge 全局脚本 Script.js；请在 Clash Verge 刷新配置使其立即生效。`,
        });
      }
      if (ipv6Enabled) {
        steps.push({
          id: "fix_ipv6_leak",
          title: "关闭 Clash Verge IPv6 防泄漏",
          status: "fixed",
          detail: "已将 Clash 配置设为 ipv6: false 并热重载，防止 IPv6 流量绕过代理。",
        });
      }
    } catch (err) {
      steps.push({
        id: "fix_missing_rules",
        title: "补全规则与关闭 IPv6",
        status: "failed",
        backupPath: scriptBackup,
        detail: `规则/IPv6 自动写入或重载失败: ${(err as Error).message}`,
      });
    }
  } else {
    steps.push({
      id: "fix_missing_rules",
      title: "检查 Claude 生态域名规则与 IPv6",
      status: "skipped",
      detail: `全部 ${auditForRules.totalProtected} 个受保护域名均已配置显式代理规则，且 IPv6 已关闭。`,
    });
  }

  // 5. Optional: Enable macOS System Proxy to Gate
  if (options.includeSystemProxy) {
    try {
      const sys = await getSystemProxyStatus(config.proxyPort, config.upstreamPort);
      if (!sys.pointingToGate) {
        await enableGateSystemProxy(config.proxyPort, config.upstreamPort);
        steps.push({
          id: "fix_system_proxy",
          title: "接入 macOS 系统代理到 ClaudeGate",
          status: "fixed",
          detail: `已将 ${sys.activeService || "macOS"} 系统代理指向 127.0.0.1:${config.proxyPort}。`,
        });
      } else {
        steps.push({
          id: "fix_system_proxy",
          title: "检查 macOS 系统代理",
          status: "skipped",
          detail: `系统代理已指向 ClaudeGate (127.0.0.1:${config.proxyPort})。`,
        });
      }
    } catch (err) {
      steps.push({
        id: "fix_system_proxy",
        title: "接入 macOS 系统代理到 ClaudeGate",
        status: "failed",
        detail: `设置系统代理失败: ${(err as Error).message}`,
      });
    }
  }

  // Force final sync & refresh rules cache
  await watchdog.syncOnce(true);
  await watchdog.probeIpNow(true);

  const fixedCount = steps.filter((s) => s.status === "fixed").length;
  const skippedCount = steps.filter((s) => s.status === "skipped").length;
  const failedCount = steps.filter((s) => s.status === "failed").length;

  if (fixedCount > 0 || failedCount > 0) {
    store.recordGuardEvent({
      ts: new Date().toISOString(),
      domain: "claude.ai",
      source: "watchdog_mode",
      action: "WARN",
      reasonCode: "AUTO_FIX_EXECUTED",
      message: `执行一键修复完成：修复 ${fixedCount} 项，跳过 ${skippedCount} 项，失败 ${failedCount} 项。`,
      fixHint: steps
        .filter((s) => s.status === "fixed")
        .map((s) => s.title)
        .join("；"),
      clashMode: guard.getClashSnapshot().configs?.mode || "rule",
      node: guard.getPrimaryClaudeNodeInfo().leaf,
      exitIp: guard.getExitIpState().current?.ip || "",
      exitCountry: guard.getExitIpState().current?.countryCode || "",
      process: "auto-fixer",
    });
  }

  return {
    ok: failedCount === 0,
    timestamp: new Date().toISOString(),
    fixedCount,
    skippedCount,
    failedCount,
    steps,
  };
}
