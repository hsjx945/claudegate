import crypto from "node:crypto";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import type { AppConfig } from "./config.js";
import type { GuardEngine } from "./guard.js";
import type { SystemProxyStatus } from "./macos-proxy.js";
import { evaluateDomainRouting, resolveProxyChain } from "./rules-engine.js";

export type GradeLetter = "S" | "A" | "B" | "C" | "F";

export interface DirectDomesticInfo {
  ok: boolean;
  ip: string;
  location: string;
  error?: string;
}

export interface ProxyIpPurityInfo {
  ok: boolean;
  ip: string;
  countryCode: string;
  country: string;
  regionName: string;
  city: string;
  timezone: string;
  isp: string;
  org: string;
  asn: string;
  asname: string;
  mobile: boolean;
  proxy: boolean;
  hosting: boolean;
  networkType: "residential" | "mobile" | "datacenter" | "proxy" | "unknown";
  cfColo?: string;
  cfTls?: string;
  cfHttp?: string;
  error?: string;
}

export interface ExitStabilityInfo {
  ok: boolean;
  samples: number;
  uniqueIps: string[];
  stable: boolean;
  ips: string[];
  error?: string;
}

export interface DnsLeakInfo {
  ok: boolean;
  dnsIp: string;
  dnsGeo: string;
  ednsIp?: string;
  ednsGeo?: string;
  leakedToBanned: boolean;
  tunDnsHijack: boolean;
  error?: string;
}

export interface Ipv6LeakInfo {
  mihomoIpv6Enabled: boolean;
  ipv6Address: string | null;
  leaked: boolean;
  detail: string;
}

export interface EndpointProbeResult {
  host: string;
  role: string;
  reachable: boolean;
  statusCode: number | null;
  latencyMs: number | null;
  matchedRule: string;
  leafNode: string;
  error?: string;
}

export interface DimensionScore {
  id: "regionCompliance" | "ipPurity" | "leakProtection" | "envConsistency" | "routingSplit";
  label: string;
  score: number;
  maxScore: number;
  status: "safe" | "warn" | "danger";
  summary: string;
}

export interface AuditFinding {
  id: string;
  severity: "safe" | "warn" | "danger";
  title: string;
  detail: string;
  fixable: boolean;
  fixHint: string;
}

export interface NetworkDetectorReport {
  checkedAt: string;
  durationMs: number;
  totalScore: number;
  grade: GradeLetter;
  dimensions: DimensionScore[];
  directDomestic: DirectDomesticInfo;
  proxyPurity: ProxyIpPurityInfo;
  stability: ExitStabilityInfo;
  dnsLeak: DnsLeakInfo;
  ipv6Leak: Ipv6LeakInfo;
  endpoints: EndpointProbeResult[];
  envInfo: {
    systemTimezone: string;
    systemOffsetMinutes: number;
    proxyTimezone?: string;
    timezoneMatched: boolean | null;
    clashMode: string;
    tunEnabled: boolean;
    systemProxyToGate: boolean;
  };
  findings: AuditFinding[];
  hasFixableIssues: boolean;
}

export interface NetworkDetectorProbes {
  probeDirectDomestic?: () => Promise<DirectDomesticInfo>;
  probeProxyPurity?: () => Promise<ProxyIpPurityInfo>;
  probeStability?: () => Promise<ExitStabilityInfo>;
  probeDnsLeak?: () => Promise<DnsLeakInfo>;
  probeIpv6Leak?: (mihomoIpv6Enabled: boolean) => Promise<Ipv6LeakInfo>;
  probeEndpoints?: () => Promise<EndpointProbeResult[]>;
}

const BANNED_GEO_PATTERN =
  /\b(china|hong kong|macau|macao|russia|cn|hk|mo|ru|iran|north korea|belarus)\b|中国|香港|澳门|俄罗斯/i;

function httpGetViaProxy(
  proxyHost: string,
  proxyPort: number,
  targetUrl: string,
  timeoutMs = 4500
): Promise<string> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: proxyHost,
        port: proxyPort,
        path: targetUrl,
        method: "GET",
        headers: {
          Host: new URL(targetUrl).host,
          "User-Agent": "ClaudeGate/0.1",
          Connection: "close",
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          if ((res.statusCode || 0) >= 400) {
            reject(new Error(`HTTP ${res.statusCode}`));
            return;
          }
          resolve(text);
        });
      }
    );
    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error(`Timeout (${timeoutMs}ms)`));
    });
    req.on("error", reject);
    req.end();
  });
}

function httpsRequestViaConnectProxy(
  proxyHost: string,
  proxyPort: number,
  targetHost: string,
  targetPath: string,
  method = "GET",
  timeoutMs = 5000
): Promise<{ statusCode: number; headersRaw: string; body: string; latencyMs: number }> {
  const start = Date.now();
  return new Promise((resolve, reject) => {
    let settled = false;
    const finishErr = (err: Error) => {
      if (!settled) {
        settled = true;
        reject(err);
      }
    };

    const socket = net.connect(proxyPort, proxyHost);
    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      finishErr(new Error(`CONNECT timeout (${timeoutMs}ms)`));
    });
    socket.on("error", finishErr);

    socket.once("connect", () => {
      socket.write(
        `CONNECT ${targetHost}:443 HTTP/1.1\r\nHost: ${targetHost}:443\r\nConnection: keep-alive\r\n\r\n`
      );
    });

    let headerBuf = Buffer.alloc(0);
    const onData = (chunk: Buffer) => {
      headerBuf = Buffer.concat([headerBuf, chunk]);
      const idx = headerBuf.indexOf("\r\n\r\n");
      if (idx === -1) return;

      socket.removeListener("data", onData);
      const headerStr = headerBuf.subarray(0, idx).toString("utf8");
      const statusLine = headerStr.split("\r\n")[0] || "";
      if (!/\s200\s/.test(statusLine)) {
        socket.destroy();
        finishErr(new Error(`Upstream CONNECT failed: ${statusLine}`));
        return;
      }

      const tlsSocket = tls.connect({
        socket,
        servername: targetHost,
      });
      tlsSocket.setTimeout(timeoutMs, () => {
        tlsSocket.destroy();
        finishErr(new Error(`TLS timeout (${timeoutMs}ms)`));
      });
      tlsSocket.on("error", finishErr);
      tlsSocket.once("secureConnect", () => {
        tlsSocket.write(
          `${method} ${targetPath} HTTP/1.1\r\nHost: ${targetHost}\r\nUser-Agent: Mozilla/5.0 ClaudeGate/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n`
        );
      });

      const respChunks: Buffer[] = [];
      let totalBytes = 0;
      tlsSocket.on("data", (c: Buffer) => {
        totalBytes += c.length;
        if (totalBytes <= 65536) {
          respChunks.push(c);
        }
      });
      tlsSocket.on("end", () => {
        if (settled) return;
        settled = true;
        const full = Buffer.concat(respChunks).toString("utf8");
        const bodyIdx = full.indexOf("\r\n\r\n");
        const headersRaw = bodyIdx !== -1 ? full.slice(0, bodyIdx) : full;
        const body = bodyIdx !== -1 ? full.slice(bodyIdx + 4) : "";
        const codeMatch = headersRaw.split("\r\n")[0]?.match(/\s(\d{3})\b/);
        const statusCode = codeMatch ? Number(codeMatch[1]) : 0;
        resolve({
          statusCode,
          headersRaw,
          body,
          latencyMs: Date.now() - start,
        });
      });
    };

    socket.on("data", onData);
  });
}

function directHttpsGet(urlStr: string, timeoutMs = 3500): Promise<string> {
  return new Promise((resolve, reject) => {
    const req = https.get(
      urlStr,
      {
        headers: { "User-Agent": "ClaudeGate/0.1", Connection: "close" },
        timeout: timeoutMs,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
      }
    );
    req.on("timeout", () => {
      req.destroy(new Error(`Timeout (${timeoutMs}ms)`));
    });
    req.on("error", reject);
  });
}

function parseCfTrace(text: string): Record<string, string> {
  const map: Record<string, string> = {};
  for (const line of text.split("\n")) {
    const eq = line.indexOf("=");
    if (eq > 0) {
      map[line.slice(0, eq).trim()] = line.slice(eq + 1).trim();
    }
  }
  return map;
}

function getTimezoneOffsetMinutes(timeZone: string): number | null {
  try {
    const now = new Date();
    const utcDate = new Date(now.toLocaleString("en-US", { timeZone: "UTC" }));
    const tzDate = new Date(now.toLocaleString("en-US", { timeZone }));
    return Math.round((tzDate.getTime() - utcDate.getTime()) / 60_000);
  } catch {
    return null;
  }
}

export async function defaultProbeDirectDomestic(): Promise<DirectDomesticInfo> {
  try {
    const raw = await directHttpsGet("https://myip.ipip.net/json", 3500);
    const parsed = JSON.parse(raw) as { ret?: string; data?: { ip?: string; location?: string[] } };
    if (parsed.ret === "ok" && parsed.data?.ip) {
      return {
        ok: true,
        ip: parsed.data.ip,
        location: (parsed.data.location || []).filter(Boolean).join(" · "),
      };
    }
    return { ok: false, ip: "", location: "", error: "无效的国内 IP 返回格式" };
  } catch (err) {
    return { ok: false, ip: "", location: "", error: (err as Error).message };
  }
}

export async function defaultProbeProxyPurity(
  proxyHost: string,
  proxyPort: number
): Promise<ProxyIpPurityInfo> {
  try {
    const [ipApiRaw, cfTraceRes] = await Promise.all([
      httpGetViaProxy(
        proxyHost,
        proxyPort,
        "http://ip-api.com/json/?fields=status,message,country,countryCode,regionName,city,timezone,isp,org,as,asname,mobile,proxy,hosting,query",
        4500
      ),
      httpsRequestViaConnectProxy(proxyHost, proxyPort, "cloudflare.com", "/cdn-cgi/trace", "GET", 4500).catch(
        () => null
      ),
    ]);

    const data = JSON.parse(ipApiRaw) as Record<string, unknown>;
    if (data.status !== "success" || !data.query) {
      throw new Error(String(data.message || "ip-api query failed"));
    }

    const cf = cfTraceRes ? parseCfTrace(cfTraceRes.body) : {};
    const proxyFlag = Boolean(data.proxy);
    const hostingFlag = Boolean(data.hosting);
    const mobileFlag = Boolean(data.mobile);

    let networkType: ProxyIpPurityInfo["networkType"] = "residential";
    if (proxyFlag) networkType = "proxy";
    else if (hostingFlag) networkType = "datacenter";
    else if (mobileFlag) networkType = "mobile";

    return {
      ok: true,
      ip: String(data.query),
      countryCode: String(data.countryCode || "").toUpperCase(),
      country: String(data.country || data.countryCode || ""),
      regionName: String(data.regionName || ""),
      city: String(data.city || ""),
      timezone: String(data.timezone || ""),
      isp: String(data.isp || ""),
      org: String(data.org || ""),
      asn: String(data.as || ""),
      asname: String(data.asname || ""),
      mobile: mobileFlag,
      proxy: proxyFlag,
      hosting: hostingFlag,
      networkType,
      cfColo: cf.colo,
      cfTls: cf.tls,
      cfHttp: cf.http,
    };
  } catch (err) {
    return {
      ok: false,
      ip: "",
      countryCode: "",
      country: "",
      regionName: "",
      city: "",
      timezone: "",
      isp: "",
      org: "",
      asn: "",
      asname: "",
      mobile: false,
      proxy: false,
      hosting: false,
      networkType: "unknown",
      error: (err as Error).message,
    };
  }
}

export async function defaultProbeExitStability(
  proxyHost: string,
  proxyPort: number
): Promise<ExitStabilityInfo> {
  const ips: string[] = [];
  try {
    for (let i = 0; i < 3; i++) {
      let ip = "";
      try {
        const raw = await httpGetViaProxy(
          proxyHost,
          proxyPort,
          "http://ip-api.com/line/?fields=query",
          3500
        );
        ip = raw.trim();
      } catch {
        const res = await httpsRequestViaConnectProxy(
          proxyHost,
          proxyPort,
          "cloudflare.com",
          "/cdn-cgi/trace",
          "GET",
          5000
        );
        ip = parseCfTrace(res.body).ip || "";
      }
      if (ip) ips.push(ip);
    }
    const uniqueIps = Array.from(new Set(ips));
    return {
      ok: ips.length > 0,
      samples: ips.length,
      uniqueIps,
      stable: uniqueIps.length === 1 && ips.length >= 2,
      ips,
    };
  } catch (err) {
    const uniqueIps = Array.from(new Set(ips));
    return {
      ok: ips.length > 0,
      samples: ips.length,
      uniqueIps,
      stable: uniqueIps.length === 1 && ips.length >= 2,
      ips,
      error: (err as Error).message,
    };
  }
}

export async function defaultProbeDnsLeak(
  proxyHost: string,
  proxyPort: number,
  tunDnsHijack: boolean
): Promise<DnsLeakInfo> {
  try {
    const rand = crypto.randomBytes(16).toString("hex");
    const raw = await httpGetViaProxy(
      proxyHost,
      proxyPort,
      `http://${rand}.edns.ip-api.com/json`,
      4500
    );
    const data = JSON.parse(raw) as {
      dns?: { ip?: string; geo?: string };
      edns?: { ip?: string; geo?: string };
    };
    const dnsIp = data.dns?.ip || "";
    const dnsGeo = data.dns?.geo || "";
    const ednsIp = data.edns?.ip;
    const ednsGeo = data.edns?.geo;
    const leaked = BANNED_GEO_PATTERN.test(dnsGeo) || Boolean(ednsGeo && BANNED_GEO_PATTERN.test(ednsGeo));

    return {
      ok: Boolean(dnsIp),
      dnsIp,
      dnsGeo,
      ednsIp,
      ednsGeo,
      leakedToBanned: leaked,
      tunDnsHijack,
    };
  } catch (err) {
    return {
      ok: false,
      dnsIp: "",
      dnsGeo: "",
      leakedToBanned: false,
      tunDnsHijack,
      error: (err as Error).message,
    };
  }
}

export async function defaultProbeIpv6Leak(
  proxyHost: string,
  proxyPort: number,
  mihomoIpv6Enabled: boolean
): Promise<Ipv6LeakInfo> {
  try {
    const raw = await httpGetViaProxy(proxyHost, proxyPort, "http://v6.ident.me/", 2200);
    const ip = raw.trim();
    if (ip.includes(":")) {
      return {
        mihomoIpv6Enabled,
        ipv6Address: ip,
        leaked: true,
        detail: `检测到代理/网络返回了 IPv6 地址 (${ip})，存在 IPv6 分流或关联风险`,
      };
    }
  } catch {
    // Expected when IPv6 is disabled or blocked cleanly
  }
  return {
    mihomoIpv6Enabled,
    ipv6Address: null,
    leaked: mihomoIpv6Enabled,
    detail: mihomoIpv6Enabled
      ? "Mihomo 配置开启了 ipv6: true，建议设为 false 以防 IPv6 泄漏"
      : "IPv6 已关闭，无 IPv6 泄漏风险",
  };
}

export async function defaultProbeAnthropicEndpoints(
  proxyHost: string,
  proxyPort: number,
  guard: GuardEngine
): Promise<EndpointProbeResult[]> {
  const targets = [
    { host: "claude.ai", role: "Web 主站" },
    { host: "api.anthropic.com", role: "API & CLI" },
    { host: "platform.claude.com", role: "Console & OAuth" },
  ];
  const clash = guard.getClashSnapshot();
  const mode = clash.configs?.mode || "rule";

  return Promise.all(
    targets.map(async (t) => {
      const route = clash.connected
        ? evaluateDomainRouting(t.host, mode, clash.rules, clash.proxies)
        : null;
      const matchedRule = route?.matchedRule
        ? `${route.matchedRule.type}${route.matchedRule.payload ? `,${route.matchedRule.payload}` : ""} -> ${route.matchedRule.proxy}`
        : mode === "global"
        ? "GLOBAL"
        : "未连接";
      const leafNode = route?.leafNode || "未知";

      try {
        const res = await httpsRequestViaConnectProxy(proxyHost, proxyPort, t.host, "/", "HEAD", 5000);
        const geoBlocked = res.statusCode === 451 || /unsupported country|region/i.test(res.body);
        return {
          host: t.host,
          role: t.role,
          reachable: !geoBlocked && res.statusCode > 0,
          statusCode: res.statusCode,
          latencyMs: res.latencyMs,
          matchedRule,
          leafNode,
          error: geoBlocked ? `地区受限 (HTTP ${res.statusCode})` : undefined,
        };
      } catch (err) {
        return {
          host: t.host,
          role: t.role,
          reachable: false,
          statusCode: null,
          latencyMs: null,
          matchedRule,
          leafNode,
          error: (err as Error).message,
        };
      }
    })
  );
}

export function gradeFromScore(score: number): GradeLetter {
  if (score >= 90) return "S";
  if (score >= 80) return "A";
  if (score >= 68) return "B";
  if (score >= 50) return "C";
  return "F";
}

export async function runNetworkDetection(
  deps: {
    config: AppConfig;
    guard: GuardEngine;
    systemProxy: SystemProxyStatus;
  },
  probes: NetworkDetectorProbes = {}
): Promise<NetworkDetectorReport> {
  const startMs = Date.now();
  const { config, guard, systemProxy } = deps;
  const clash = guard.getClashSnapshot();
  const audit = guard.auditAllProtectedDomains();
  const clashMode = String(clash.configs?.mode || "offline").toLowerCase();
  const tunEnabled = Boolean(clash.configs?.tun?.enable);
  const tunDnsHijack =
    tunEnabled &&
    Array.isArray(clash.configs?.tun?.["dns-hijack"]) &&
    (clash.configs?.tun?.["dns-hijack"] as unknown[]).length > 0;
  const mihomoIpv6Enabled = Boolean(clash.configs?.ipv6);

  const [directDomestic, proxyPurity, stability, dnsLeak, ipv6Leak, endpoints] = await Promise.all([
    probes.probeDirectDomestic ? probes.probeDirectDomestic() : defaultProbeDirectDomestic(),
    probes.probeProxyPurity
      ? probes.probeProxyPurity()
      : defaultProbeProxyPurity(config.upstreamHost, config.upstreamPort),
    probes.probeStability
      ? probes.probeStability()
      : defaultProbeExitStability(config.upstreamHost, config.upstreamPort),
    probes.probeDnsLeak
      ? probes.probeDnsLeak()
      : defaultProbeDnsLeak(config.upstreamHost, config.upstreamPort, tunDnsHijack),
    probes.probeIpv6Leak
      ? probes.probeIpv6Leak(mihomoIpv6Enabled)
      : defaultProbeIpv6Leak(config.upstreamHost, config.upstreamPort, mihomoIpv6Enabled),
    probes.probeEndpoints
      ? probes.probeEndpoints()
      : defaultProbeAnthropicEndpoints(config.upstreamHost, config.upstreamPort, guard),
  ]);

  const findings: AuditFinding[] = [];

  // 1. Region Compliance (20 pts)
  let regionScore = 0;
  const exitCC = proxyPurity.countryCode.toUpperCase();
  const isBannedCountry = Boolean(exitCC && config.bannedCountries.includes(exitCC));
  if (!clash.connected) {
    regionScore = 0;
    findings.push({
      id: "clash_offline",
      severity: "danger",
      title: "Clash Verge 未连接",
      detail: "无法读取 Clash Verge 运行状态，存在裸连风险。",
      fixable: false,
      fixHint: "请先启动 Clash Verge。",
    });
  } else if (clashMode === "direct") {
    regionScore = 0;
    findings.push({
      id: "direct_mode",
      severity: "danger",
      title: "Clash Verge 处于直连模式",
      detail: "所有请求将绕过代理直接通过中国 IP 访问 Claude。",
      fixable: true,
      fixHint: "点击「一键修复」自动切换回 RULE 模式。",
    });
  } else if (!proxyPurity.ok) {
    regionScore = 8;
    findings.push({
      id: "exit_probe_failed",
      severity: "warn",
      title: "代理出口 IP 探测失败",
      detail: proxyPurity.error || "无法探测代理出口归属地。",
      fixable: false,
      fixHint: "请检查 Clash Verge 节点连通性。",
    });
  } else if (isBannedCountry) {
    regionScore = 0;
    findings.push({
      id: "banned_country",
      severity: "danger",
      title: `出口地区受限 (${proxyPurity.country} · ${exitCC})`,
      detail: `Anthropic 不支持 ${exitCC} 地区访问，极易触发封号。`,
      fixable: true,
      fixHint: "点击「一键修复」自动切换到美国/日本/新加坡等合规节点。",
    });
  } else {
    regionScore = 20;
  }

  // 2. IP Purity (20 pts)
  let purityScore = 10;
  if (proxyPurity.ok) {
    if (proxyPurity.proxy) {
      purityScore = 6;
      findings.push({
        id: "ip_proxy_flagged",
        severity: "danger",
        title: "出口 IP 被标记为公开代理/VPN",
        detail: `${proxyPurity.isp || proxyPurity.asn} 被 IP 库标记为 proxy=true，风控风险较高。`,
        fixable: false,
        fixHint: "建议更换更纯净的静态原生 ISP 或住宅节点。",
      });
    } else if (proxyPurity.hosting) {
      purityScore = 13;
      findings.push({
        id: "ip_datacenter",
        severity: "warn",
        title: "出口 IP 属于数据中心机房 (Datacenter)",
        detail: `${proxyPurity.isp || proxyPurity.asn} 为机房 ASN（hosting=true），正常可用但不如原生住宅 IP 稳健。`,
        fixable: false,
        fixHint: "如遇频繁验证或封号风险，建议优先使用原生 ISP / 住宅节点。",
      });
    } else if (proxyPurity.mobile) {
      purityScore = 18;
    } else {
      purityScore = 20;
    }
  }

  // 3. Leak Protection (20 pts)
  let leakScore = 0;
  if (dnsLeak.ok && !dnsLeak.leakedToBanned) {
    leakScore += 8;
  } else if (dnsLeak.leakedToBanned) {
    findings.push({
      id: "dns_leak",
      severity: "danger",
      title: "检测到 DNS 解析出口落入受限地区",
      detail: `DNS 出口为 ${dnsLeak.dnsGeo} (${dnsLeak.dnsIp})，可能泄露真实地理位置。`,
      fixable: false,
      fixHint: "请在 Clash Verge 开启 TUN dns-hijack 与 fake-ip/remote DNS。",
    });
  } else {
    leakScore += 4;
  }

  if (!ipv6Leak.leaked) {
    leakScore += 6;
  } else {
    findings.push({
      id: "ipv6_leak",
      severity: "warn",
      title: "存在 IPv6 启用或泄漏风险",
      detail: ipv6Leak.detail,
      fixable: true,
      fixHint: "点击「一键修复」自动在 Clash Verge 中禁用 ipv6。",
    });
  }

  if (systemProxy.pointingToGate) {
    leakScore += 6;
  } else if (tunEnabled) {
    leakScore += 4;
    findings.push({
      id: "system_proxy_not_gated",
      severity: "warn",
      title: "macOS 系统代理尚未经过 ClaudeGate 前置门禁",
      detail: "当前仅靠 Clash TUN + Watchdog 事后监控；接入系统代理可实现 0 字节事前阻断。",
      fixable: true,
      fixHint: "点击「接入系统代理」或勾选一键修复中的「同时接入系统代理」。",
    });
  } else {
    findings.push({
      id: "no_gate_or_tun",
      severity: "danger",
      title: "既未接入系统代理也未开启 TUN 模式",
      detail: "应用请求可能绕过门禁与 Clash 直接连网。",
      fixable: true,
      fixHint: "点击「一键修复」并接入系统代理。",
    });
  }

  // 4. Environment Consistency (20 pts)
  const systemTimezone = Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  const systemOffsetMinutes = -new Date().getTimezoneOffset();
  const proxyOffsetMinutes = proxyPurity.timezone ? getTimezoneOffsetMinutes(proxyPurity.timezone) : null;
  const timezoneMatched =
    proxyOffsetMinutes === null ? null : Math.abs(proxyOffsetMinutes - systemOffsetMinutes) <= 60;

  let envScore = 0;
  if (proxyPurity.ok) envScore += 8;
  if (stability.ok && stability.stable) {
    envScore += 6;
  } else if (stability.ok && !stability.stable) {
    findings.push({
      id: "exit_unstable",
      severity: "warn",
      title: "出口 IP 在连续采样中发生变化",
      detail: `3 次探测出现了多个出口 IP (${stability.uniqueIps.join(", ")})，可能开启了负载均衡或轮询。`,
      fixable: false,
      fixHint: "请在 Clash Verge 为 Claude 固定单一静态节点。",
    });
  } else {
    envScore += 2;
  }

  if (timezoneMatched === true) {
    envScore += 6;
  } else if (timezoneMatched === false) {
    envScore += 3;
    findings.push({
      id: "timezone_mismatch",
      severity: "warn",
      title: "系统时区与代理出口时区不一致",
      detail: `本机时区 ${systemTimezone}，代理节点时区 ${proxyPurity.timezone}；网页版 Claude 可能检测时区差异。`,
      fixable: false,
      fixHint: "建议优先选用与本机时区相近（如日本/新加坡/台湾）的合规节点。",
    });
  } else {
    envScore += 4;
  }

  // 5. Routing Split & Endpoint Reachability (20 pts)
  let routingScore = 0;
  if (clash.connected) {
    if (clashMode === "rule") routingScore += 5;
    else {
      findings.push({
        id: "not_rule_mode",
        severity: "warn",
        title: `Clash 当前为 ${clashMode.toUpperCase()} 模式`,
        detail: "建议长期保持 RULE 规则分流模式，确保国内流量直连、Claude 走固定代理。",
        fixable: true,
        fixHint: "点击「一键修复」切换回 RULE 模式。",
      });
    }

    if (!audit.globalRisk) routingScore += 5;
    else {
      findings.push({
        id: "global_direct_risk",
        severity: "warn",
        title: "GLOBAL 策略组指向 DIRECT",
        detail: "一旦误切全局模式会导致全部流量裸连。",
        fixable: true,
        fixHint: "点击「一键修复」将 GLOBAL 指向主代理组。",
      });
    }

    if (audit.missingExplicitRuleDomains.length === 0) routingScore += 6;
    else {
      findings.push({
        id: "missing_rules",
        severity: "warn",
        title: `${audit.missingExplicitRuleDomains.length} 个 Claude 关联域名缺少显式规则`,
        detail: "依赖兜底规则可能因规则变化而直连泄漏。",
        fixable: true,
        fixHint: "点击「一键修复」自动写入 Script.js 并热重载生效。",
      });
    }

    const claudeRoute = evaluateDomainRouting("claude.ai", clashMode, clash.rules, clash.proxies);
    const hasAutoGroup = claudeRoute.hasAutoGroup || resolveProxyChain(audit.primaryProxyGroup, clash.proxies).hasAutoGroup;
    if (!hasAutoGroup && endpoints.every((e) => e.reachable)) {
      routingScore += 4;
    } else if (endpoints.some((e) => !e.reachable)) {
      routingScore += 1;
      const unreachable = endpoints.filter((e) => !e.reachable).map((e) => e.host);
      findings.push({
        id: "endpoint_unreachable",
        severity: "danger",
        title: "部分 Anthropic 端点不可达",
        detail: `无法通过当前代理访问：${unreachable.join(", ")}`,
        fixable: false,
        fixHint: "请检查当前 Clash 节点是否可用或尝试切换节点。",
      });
    } else {
      routingScore += 2;
    }
  }

  const totalScore = Math.max(
    0,
    Math.min(100, regionScore + purityScore + leakScore + envScore + routingScore)
  );
  const grade = gradeFromScore(totalScore);

  const dimensions: DimensionScore[] = [
    {
      id: "regionCompliance",
      label: "地区合规",
      score: regionScore,
      maxScore: 20,
      status: regionScore >= 18 ? "safe" : regionScore >= 10 ? "warn" : "danger",
      summary: isBannedCountry ? `受限 (${exitCC})` : exitCC || "未知",
    },
    {
      id: "ipPurity",
      label: "IP 纯净度",
      score: purityScore,
      maxScore: 20,
      status: purityScore >= 18 ? "safe" : purityScore >= 12 ? "warn" : "danger",
      summary:
        proxyPurity.networkType === "residential"
          ? "住宅/原生"
          : proxyPurity.networkType === "datacenter"
          ? "机房 IP"
          : proxyPurity.networkType === "proxy"
          ? "代理标记"
          : proxyPurity.networkType === "mobile"
          ? "移动网络"
          : "未知",
    },
    {
      id: "leakProtection",
      label: "防泄露",
      score: leakScore,
      maxScore: 20,
      status: leakScore >= 16 ? "safe" : leakScore >= 10 ? "warn" : "danger",
      summary: dnsLeak.leakedToBanned ? "DNS 泄露" : ipv6Leak.leaked ? "IPv6 风险" : "防护正常",
    },
    {
      id: "envConsistency",
      label: "环境一致",
      score: envScore,
      maxScore: 20,
      status: envScore >= 16 ? "safe" : envScore >= 10 ? "warn" : "danger",
      summary: timezoneMatched === false ? "时区偏移" : stability.stable ? "稳定一致" : "待核验",
    },
    {
      id: "routingSplit",
      label: "分流路径",
      score: routingScore,
      maxScore: 20,
      status: routingScore >= 16 ? "safe" : routingScore >= 10 ? "warn" : "danger",
      summary: audit.missingExplicitRuleDomains.length === 0 ? "规则完备" : `缺 ${audit.missingExplicitRuleDomains.length} 条`,
    },
  ];

  return {
    checkedAt: new Date().toISOString(),
    durationMs: Date.now() - startMs,
    totalScore,
    grade,
    dimensions,
    directDomestic,
    proxyPurity,
    stability,
    dnsLeak,
    ipv6Leak,
    endpoints,
    envInfo: {
      systemTimezone,
      systemOffsetMinutes,
      proxyTimezone: proxyPurity.timezone || undefined,
      timezoneMatched,
      clashMode,
      tunEnabled,
      systemProxyToGate: systemProxy.pointingToGate,
    },
    findings,
    hasFixableIssues: findings.some((f) => f.fixable),
  };
}
