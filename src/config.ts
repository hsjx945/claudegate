import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export type DomainCategory =
  | "core"
  | "artifacts"
  | "mcp"
  | "telemetry"
  | "billing"
  | "support"
  | "custom";

export interface ProtectedDomainEntry {
  domain: string;
  category: DomainCategory;
  note?: string;
}

export interface AppConfig {
  proxyPort: number;
  dashboardPort: number;
  upstreamHost: string;
  upstreamPort: number;
  mihomoSocketPath: string;
  mihomoTcpUrl: string;
  mihomoSecret: string;
  bannedCountries: string[];
  strictMode: boolean;
  autoKillDirectLeaks: boolean;
  notificationsEnabled: boolean;
  exitIpProbeIntervalSec: number;
  protectedDomains: ProtectedDomainEntry[];
}

export const DEFAULT_PROTECTED_DOMAINS: ProtectedDomainEntry[] = [
  // Core Anthropic & Claude
  { domain: "anthropic.com", category: "core", note: "Anthropic 核心域名与 API" },
  { domain: "claude.ai", category: "core", note: "Claude Web 主站" },
  { domain: "claude.com", category: "core", note: "Claude 跳转与主域" },
  { domain: "claude.app", category: "core", note: "Claude 客户端" },
  { domain: "claude.dev", category: "core", note: "Claude 开发者域" },
  { domain: "claude.new", category: "core", note: "Claude 快捷入口" },
  { domain: "claude.site", category: "core", note: "Claude 站点" },
  { domain: "clau.de", category: "core", note: "Claude 短域名" },
  { domain: "chatbotclaude.com", category: "core", note: "Claude 关联域" },
  { domain: "ant.dev", category: "core", note: "Anthropic 开发者域" },
  { domain: "antspace.dev", category: "core", note: "Anthropic 服务域" },
  { domain: "anthropic.team", category: "core", note: "Anthropic Team" },
  { domain: "claudeacademy.com", category: "core", note: "Claude Academy" },
  { domain: "claudestudio.com", category: "core", note: "Claude Studio" },
  { domain: "servd-anthropic-website.b-cdn.net", category: "core", note: "Anthropic 官网 CDN" },
  // Artifacts & Downloads
  { domain: "claudeusercontent.com", category: "artifacts", note: "Artifacts 与用户内容" },
  { domain: "downloads.claude.ai", category: "artifacts", note: "Claude Code / 客户端下载" },
  // MCP
  { domain: "modelcontextprotocol.io", category: "mcp", note: "MCP 官方域" },
  { domain: "claudemcpclient.com", category: "mcp", note: "Claude MCP 客户端域" },
  { domain: "claudemcpcontent.com", category: "mcp", note: "Claude MCP 内容域" },
  // Telemetry & Logging
  { domain: "sentry.io", category: "telemetry", note: "错误日志上报 (Sentry)" },
  { domain: "statsig.com", category: "telemetry", note: "功能开关与实验 (Statsig)" },
  { domain: "growthbook.io", category: "telemetry", note: "灰度实验 (GrowthBook)" },
  { domain: "usefathom.com", category: "telemetry", note: "访问统计 (Fathom)" },
  { domain: "http-intake.logs.us5.datadoghq.com", category: "telemetry", note: "Claude Code 日志上报" },
  { domain: "browser-intake-us5-datadoghq.com", category: "telemetry", note: "浏览器端日志上报" },
  // Billing & Support
  { domain: "stripe.com", category: "billing", note: "订阅与支付风控 (Stripe)" },
  { domain: "intercom.io", category: "support", note: "客服组件 (Intercom)" },
  { domain: "intercomcdn.com", category: "support", note: "客服静态资源 (Intercom CDN)" },
];

export const DEFAULT_BANNED_COUNTRIES = ["CN", "HK", "MO", "RU", "KP", "IR", "BY", "SY", "CU"];

export function getDataDir(): string {
  const custom = process.env.CLAUDEBAN_DATA_DIR;
  if (custom && custom.trim()) {
    return path.resolve(custom.trim());
  }
  return path.join(os.homedir(), ".claudeban");
}

export function ensureDataDir(): string {
  const dir = getDataDir();
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

export function getConfigPath(): string {
  return path.join(getDataDir(), "config.json");
}

export function getDefaultConfig(): AppConfig {
  return {
    proxyPort: 17890,
    dashboardPort: 17891,
    upstreamHost: "127.0.0.1",
    upstreamPort: 7897,
    mihomoSocketPath: "",
    mihomoTcpUrl: "http://127.0.0.1:9097",
    mihomoSecret: "",
    bannedCountries: [...DEFAULT_BANNED_COUNTRIES],
    strictMode: false,
    autoKillDirectLeaks: true,
    notificationsEnabled: true,
    exitIpProbeIntervalSec: 30,
    protectedDomains: DEFAULT_PROTECTED_DOMAINS.map((d) => ({ ...d })),
  };
}

export function loadConfig(): AppConfig {
  ensureDataDir();
  const cfgPath = getConfigPath();
  const defaults = getDefaultConfig();
  if (!fs.existsSync(cfgPath)) {
    fs.writeFileSync(cfgPath, JSON.stringify(defaults, null, 2), "utf8");
    return defaults;
  }
  try {
    const raw = JSON.parse(fs.readFileSync(cfgPath, "utf8")) as Partial<AppConfig>;
    return {
      ...defaults,
      ...raw,
      bannedCountries: Array.isArray(raw.bannedCountries)
        ? raw.bannedCountries.map((c) => String(c).trim().toUpperCase()).filter(Boolean)
        : defaults.bannedCountries,
      protectedDomains: Array.isArray(raw.protectedDomains)
        ? raw.protectedDomains
            .filter((d) => d && typeof d.domain === "string" && d.domain.trim())
            .map((d) => ({
              domain: normalizeHost(d.domain),
              category: d.category || "custom",
              note: d.note,
            }))
        : defaults.protectedDomains,
    };
  } catch {
    return defaults;
  }
}

export function saveConfig(config: AppConfig): AppConfig {
  ensureDataDir();
  const normalized: AppConfig = {
    ...config,
    bannedCountries: config.bannedCountries.map((c) => c.trim().toUpperCase()).filter(Boolean),
    protectedDomains: config.protectedDomains
      .map((d) => ({
        domain: normalizeHost(d.domain),
        category: d.category || "custom",
        note: d.note,
      }))
      .filter((d) => Boolean(d.domain)),
  };
  fs.writeFileSync(getConfigPath(), JSON.stringify(normalized, null, 2), "utf8");
  return normalized;
}

export function normalizeHost(host: string): string {
  let clean = host.trim().toLowerCase();
  if (clean.startsWith("[")) {
    const idx = clean.indexOf("]");
    if (idx !== -1) {
      clean = clean.slice(1, idx);
    }
  } else {
    const colonCount = (clean.match(/:/g) || []).length;
    if (colonCount === 1) {
      clean = clean.split(":")[0];
    }
  }
  while (clean.endsWith(".")) {
    clean = clean.slice(0, -1);
  }
  return clean;
}

export function matchProtectedDomain(
  host: string,
  domains: ProtectedDomainEntry[]
): ProtectedDomainEntry | null {
  const clean = normalizeHost(host);
  if (!clean) return null;
  // Sort longest domain first for most specific match
  const sorted = [...domains].sort((a, b) => b.domain.length - a.domain.length);
  for (const entry of sorted) {
    const target = normalizeHost(entry.domain);
    if (!target) continue;
    if (clean === target || clean.endsWith(`.${target}`)) {
      return entry;
    }
  }
  return null;
}
