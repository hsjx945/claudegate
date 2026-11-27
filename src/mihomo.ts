import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import type { AppConfig } from "./config.js";

export interface MihomoVersion {
  version: string;
  meta?: boolean;
}

export interface MihomoConfigs {
  port?: number;
  "socks-port"?: number;
  "mixed-port"?: number;
  mode: string;
  "allow-lan"?: boolean;
  "log-level"?: string;
  sniffing?: boolean;
  tun?: {
    enable?: boolean;
    device?: string;
    stack?: string;
    "auto-route"?: boolean;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

export interface MihomoProxy {
  name: string;
  type: string;
  now?: string;
  all?: string[];
  alive?: boolean;
  [key: string]: unknown;
}

export interface MihomoRule {
  index?: number;
  type: string;
  payload: string;
  proxy: string;
  size?: number;
}

export interface MihomoConnectionMetadata {
  network?: string;
  type?: string;
  sourceIP?: string;
  destinationIP?: string;
  sourcePort?: string;
  destinationPort?: string;
  host?: string;
  dnsMode?: string;
  process?: string;
  processPath?: string;
  remoteDestination?: string;
  sniffHost?: string;
}

export interface MihomoConnection {
  id: string;
  metadata: MihomoConnectionMetadata;
  upload: number;
  download: number;
  start: string;
  chains: string[];
  rule: string;
  rulePayload: string;
}

export interface MihomoConnectionsSnapshot {
  downloadTotal: number;
  uploadTotal: number;
  connections: MihomoConnection[] | null;
}

export interface MihomoEndpoint {
  kind: "unix" | "tcp";
  socketPath?: string;
  baseUrl?: string;
  secret?: string;
}

export function discoverMihomoEndpoint(config: AppConfig): MihomoEndpoint {
  if (config.mihomoSocketPath && config.mihomoSocketPath.trim()) {
    const explicit = config.mihomoSocketPath.trim();
    if (fs.existsSync(explicit)) {
      return { kind: "unix", socketPath: explicit };
    }
  }

  const uid = typeof process.getuid === "function" ? process.getuid() : 501;
  const candidateSockets = [
    `/var/run/clash-verge-service/users/${uid}/verge-mihomo.sock`,
    path.join(os.tmpdir(), "verge-mihomo.sock"),
    "/tmp/verge/verge-mihomo.sock",
    "/tmp/verge-mihomo.sock",
  ];

  for (const sock of candidateSockets) {
    try {
      if (fs.existsSync(sock)) {
        return { kind: "unix", socketPath: sock };
      }
    } catch {
      // ignore permission/stat errors
    }
  }

  return {
    kind: "tcp",
    baseUrl: config.mihomoTcpUrl || "http://127.0.0.1:9097",
    secret: config.mihomoSecret || "",
  };
}

export class MihomoClient {
  private config: AppConfig;
  private endpoint: MihomoEndpoint;
  private readonly timeoutMs = 3000;

  constructor(config: AppConfig, customEndpoint?: MihomoEndpoint) {
    this.config = config;
    this.endpoint = customEndpoint || discoverMihomoEndpoint(config);
  }

  updateConfig(config: AppConfig): void {
    this.config = config;
    this.endpoint = discoverMihomoEndpoint(config);
  }

  refreshEndpoint(): MihomoEndpoint {
    this.endpoint = discoverMihomoEndpoint(this.config);
    return this.endpoint;
  }

  getEndpoint(): MihomoEndpoint {
    return this.endpoint;
  }

  private request<T>(
    method: string,
    reqPath: string,
    body?: unknown,
    timeoutOverrideMs?: number
  ): Promise<T> {
    const reqTimeout = timeoutOverrideMs ?? this.timeoutMs;
    return new Promise((resolve, reject) => {
      const payload = body !== undefined ? JSON.stringify(body) : undefined;
      const headers: Record<string, string> = {};
      if (payload !== undefined) {
        headers["Content-Type"] = "application/json";
        headers["Content-Length"] = String(Buffer.byteLength(payload));
      }
      if (this.endpoint.secret) {
        headers["Authorization"] = `Bearer ${this.endpoint.secret}`;
      }

      let options: http.RequestOptions;
      if (this.endpoint.kind === "unix" && this.endpoint.socketPath) {
        options = {
          socketPath: this.endpoint.socketPath,
          path: reqPath,
          method,
          headers,
        };
      } else {
        const url = new URL(reqPath, this.endpoint.baseUrl || "http://127.0.0.1:9097");
        options = {
          hostname: url.hostname,
          port: url.port ? Number(url.port) : 80,
          path: url.pathname + url.search,
          method,
          headers,
        };
      }

      const req = http.request(options, (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          const status = res.statusCode || 0;
          if (status >= 400) {
            reject(new Error(`Mihomo HTTP ${status} on ${method} ${reqPath}: ${text.slice(0, 200)}`));
            return;
          }
          if (!text.trim()) {
            resolve(undefined as T);
            return;
          }
          try {
            resolve(JSON.parse(text) as T);
          } catch (err) {
            reject(new Error(`Invalid JSON from Mihomo ${reqPath}: ${(err as Error).message}`));
          }
        });
      });

      req.setTimeout(reqTimeout, () => {
        req.destroy(new Error(`Mihomo request timeout (${reqTimeout}ms): ${method} ${reqPath}`));
      });

      req.on("error", (err) => {
        reject(err);
      });

      if (payload !== undefined) {
        req.write(payload);
      }
      req.end();
    });
  }

  async getVersion(): Promise<MihomoVersion> {
    return this.request<MihomoVersion>("GET", "/version");
  }

  async getConfigs(): Promise<MihomoConfigs> {
    return this.request<MihomoConfigs>("GET", "/configs");
  }

  async patchConfigs(patch: Partial<{ mode: string }>): Promise<void> {
    await this.request<void>("PATCH", "/configs", patch);
  }

  async reloadConfigPayload(yamlPayload: string): Promise<void> {
    await this.request<void>(
      "PUT",
      "/configs?force=true",
      { path: "", payload: yamlPayload },
      10_000
    );
  }

  async selectProxy(group: string, name: string): Promise<void> {
    await this.request<void>("PUT", `/proxies/${encodeURIComponent(group)}`, { name });
  }

  async getProxies(): Promise<Record<string, MihomoProxy>> {
    const res = await this.request<{ proxies?: Record<string, MihomoProxy> }>("GET", "/proxies");
    return res?.proxies || {};
  }

  async getRules(): Promise<MihomoRule[]> {
    const res = await this.request<{ rules?: MihomoRule[] }>("GET", "/rules");
    return res?.rules || [];
  }

  async getConnections(): Promise<MihomoConnectionsSnapshot> {
    return this.request<MihomoConnectionsSnapshot>("GET", "/connections");
  }

  async closeConnection(id: string): Promise<void> {
    await this.request<void>("DELETE", `/connections/${encodeURIComponent(id)}`);
  }
}
