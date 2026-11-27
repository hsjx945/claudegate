import http from "node:http";
import net from "node:net";
import tls from "node:tls";
import type { AppConfig } from "./config.js";

export interface ExitIpInfo {
  ip: string;
  countryCode: string;
  country: string;
  regionName?: string;
  city?: string;
  isp?: string;
  asn?: string;
  checkedAt: string;
  source: string;
}

export type ProbeFn = () => Promise<ExitIpInfo>;

export interface ExitIpState {
  current: ExitIpInfo | null;
  previous: ExitIpInfo | null;
  countryJumped: boolean;
  lastCheckedAt: string | null;
  lastError: string | null;
}

const BANNED_NODE_NAME_PATTERNS: Array<{ pattern: RegExp; code: string; label: string }> = [
  { pattern: /(^|[^a-zA-Z])(HK|Hong\s*Kong)([^a-zA-Z]|$)|香港/i, code: "HK", label: "香港" },
  { pattern: /(^|[^a-zA-Z])(CN|China)([^a-zA-Z]|$)|中国|内地|大陆/i, code: "CN", label: "中国大陆" },
  { pattern: /(^|[^a-zA-Z])(MO|Macau|Macao)([^a-zA-Z]|$)|澳门/i, code: "MO", label: "澳门" },
  { pattern: /(^|[^a-zA-Z])(RU|Russia)([^a-zA-Z]|$)|俄罗斯/i, code: "RU", label: "俄罗斯" },
];

export function detectBannedRegionHintInNodeName(nodeName: string): { code: string; label: string } | null {
  for (const item of BANNED_NODE_NAME_PATTERNS) {
    if (item.pattern.test(nodeName)) {
      return { code: item.code, label: item.label };
    }
  }
  return null;
}

function httpGetViaProxy(
  proxyHost: string,
  proxyPort: number,
  targetUrl: string,
  timeoutMs = 5000
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
            reject(new Error(`HTTP ${res.statusCode}: ${text.slice(0, 120)}`));
            return;
          }
          resolve(text);
        });
      }
    );
    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error(`Proxy HTTP probe timeout (${timeoutMs}ms)`));
    });
    req.on("error", reject);
    req.end();
  });
}

function httpsGetViaConnectProxy(
  proxyHost: string,
  proxyPort: number,
  targetHost: string,
  targetPath: string,
  timeoutMs = 5000
): Promise<string> {
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
      finishErr(new Error(`CONNECT probe timeout (${timeoutMs}ms)`));
    });
    socket.on("error", (e) => finishErr(e));

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
        finishErr(new Error(`TLS probe timeout (${timeoutMs}ms)`));
      });
      tlsSocket.on("error", (e) => finishErr(e));
      tlsSocket.once("secureConnect", () => {
        tlsSocket.write(
          `GET ${targetPath} HTTP/1.1\r\nHost: ${targetHost}\r\nUser-Agent: ClaudeGate/0.1\r\nConnection: close\r\n\r\n`
        );
      });

      const respChunks: Buffer[] = [];
      tlsSocket.on("data", (c: Buffer) => respChunks.push(c));
      tlsSocket.on("end", () => {
        if (settled) return;
        settled = true;
        const full = Buffer.concat(respChunks).toString("utf8");
        const bodyIdx = full.indexOf("\r\n\r\n");
        resolve(bodyIdx !== -1 ? full.slice(bodyIdx + 4) : full);
      });
    };

    socket.on("data", onData);
  });
}

export async function defaultProbeExitIpViaProxy(
  proxyHost: string,
  proxyPort: number
): Promise<ExitIpInfo> {
  // Primary: ip-api.com (rich ASN/ISP/countryCode)
  try {
    const raw = await httpGetViaProxy(
      proxyHost,
      proxyPort,
      "http://ip-api.com/json/?fields=status,message,country,countryCode,regionName,city,isp,org,as,query",
      4500
    );
    const data = JSON.parse(raw) as {
      status?: string;
      message?: string;
      country?: string;
      countryCode?: string;
      regionName?: string;
      city?: string;
      isp?: string;
      org?: string;
      as?: string;
      query?: string;
    };
    if (data.status === "success" && data.query && data.countryCode) {
      return {
        ip: data.query,
        countryCode: data.countryCode.toUpperCase(),
        country: data.country || data.countryCode,
        regionName: data.regionName,
        city: data.city,
        isp: data.isp || data.org,
        asn: data.as,
        checkedAt: new Date().toISOString(),
        source: "ip-api.com",
      };
    }
  } catch {
    // fallback below
  }

  // Fallback: cloudflare cdn-cgi/trace over HTTPS CONNECT
  const trace = await httpsGetViaConnectProxy(
    proxyHost,
    proxyPort,
    "cloudflare.com",
    "/cdn-cgi/trace",
    4500
  );
  const lines = trace.split("\n");
  const map: Record<string, string> = {};
  for (const line of lines) {
    const eq = line.indexOf("=");
    if (eq > 0) {
      map[line.slice(0, eq).trim()] = line.slice(eq + 1).trim();
    }
  }
  if (!map.ip || !map.loc) {
    throw new Error("Cloudflare trace returned incomplete IP/loc data");
  }
  return {
    ip: map.ip,
    countryCode: map.loc.toUpperCase(),
    country: map.loc.toUpperCase(),
    checkedAt: new Date().toISOString(),
    source: "cloudflare-trace",
  };
}

export class ExitIpProber {
  private config: AppConfig;
  private probeFn?: ProbeFn;
  private state: ExitIpState = {
    current: null,
    previous: null,
    countryJumped: false,
    lastCheckedAt: null,
    lastError: null,
  };
  private probingPromise: Promise<ExitIpState> | null = null;

  constructor(config: AppConfig, customProbeFn?: ProbeFn) {
    this.config = config;
    this.probeFn = customProbeFn;
  }

  updateConfig(config: AppConfig): void {
    this.config = config;
  }

  getState(): ExitIpState {
    return { ...this.state };
  }

  clearCountryJump(): void {
    this.state.countryJumped = false;
  }

  async probeNow(): Promise<ExitIpState> {
    if (this.probingPromise) {
      return this.probingPromise;
    }

    this.probingPromise = (async () => {
      try {
        const info = this.probeFn
          ? await this.probeFn()
          : await defaultProbeExitIpViaProxy(this.config.upstreamHost, this.config.upstreamPort);

        const prev = this.state.current;
        const banned = new Set(this.config.bannedCountries.map((c) => c.toUpperCase()));
        let jumped = false;
        if (
          prev &&
          prev.countryCode &&
          info.countryCode &&
          prev.countryCode !== info.countryCode &&
          !banned.has(prev.countryCode.toUpperCase()) &&
          !banned.has(info.countryCode.toUpperCase())
        ) {
          jumped = true;
        }
        this.state = {
          current: info,
          previous: prev,
          countryJumped: jumped,
          lastCheckedAt: new Date().toISOString(),
          lastError: null,
        };
      } catch (err) {
        this.state = {
          ...this.state,
          lastCheckedAt: new Date().toISOString(),
          lastError: (err as Error).message,
        };
      } finally {
        this.probingPromise = null;
      }
      return this.getState();
    })();

    return this.probingPromise;
  }
}
