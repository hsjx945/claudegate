import net from "node:net";
import { normalizeHost, type AppConfig } from "./config.js";
import type { Store } from "./db.js";
import type { GuardDecision, GuardEngine } from "./guard.js";
import type { MacNotifier } from "./notifier.js";

export interface GateProxyStats {
  startedAt: string;
  listening: boolean;
  totalRequests: number;
  protectedRequests: number;
  allowedRequests: number;
  warnedRequests: number;
  blockedRequests: number;
  upBytes: number;
  downBytes: number;
  activeConnections: number;
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderHtmlBlockPage(decision: GuardDecision, dashboardPort: number): string {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <title>ClaudeGate 门禁已拦截直连风险</title>
  <style>
    body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "PingFang SC", sans-serif; background: #0d1117; color: #e6edf3; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    .card { max-width: 680px; background: #161b22; border: 1px solid #f85149; border-radius: 12px; padding: 28px 32px; box-shadow: 0 12px 32px rgba(0,0,0,0.45); }
    .badge { display: inline-block; background: rgba(248,81,73,0.16); color: #ff7b72; border: 1px solid rgba(248,81,73,0.4); padding: 4px 10px; border-radius: 999px; font-size: 12px; font-weight: 600; }
    h1 { margin: 14px 0 8px; font-size: 22px; color: #ff7b72; }
    p { line-height: 1.65; color: #c9d1d9; }
    .box { background: #0d1117; border: 1px solid #30363d; border-radius: 8px; padding: 14px 16px; margin: 16px 0; white-space: pre-wrap; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; color: #79c0ff; }
    .btn { display: inline-block; margin-top: 8px; background: #238636; color: #fff; text-decoration: none; padding: 10px 16px; border-radius: 8px; font-weight: 600; font-size: 14px; }
    .meta { font-size: 12px; color: #8b949e; margin-top: 16px; }
  </style>
</head>
<body>
  <div class="card">
    <span class="badge">CLAUDEGATE 拦截 · ${escapeHtml(decision.reasonCode)}</span>
    <h1>已阻止访问 ${escapeHtml(decision.domain)}（防封号保护）</h1>
    <p>${escapeHtml(decision.message)}</p>
    <div class="box">${escapeHtml(decision.fixHint)}</div>
    <a class="btn" href="http://127.0.0.1:${dashboardPort}/" target="_blank">打开 ClaudeGate 控制台修复</a>
    <div class="meta">当前 Clash 模式: ${escapeHtml(decision.clashMode)} | 出口 IP: ${escapeHtml(decision.exitIp || "未知")} (${escapeHtml(decision.exitCountry || "-")})</div>
  </div>
</body>
</html>`;
}

function parseTargetHostPort(rawHostPort: string, defaultPort: number): { host: string; port: number } {
  const trimmed = rawHostPort.trim();
  if (trimmed.startsWith("[")) {
    const end = trimmed.indexOf("]");
    if (end !== -1) {
      const host = trimmed.slice(1, end);
      const rest = trimmed.slice(end + 1);
      const port = rest.startsWith(":") ? Number(rest.slice(1)) || defaultPort : defaultPort;
      return { host: normalizeHost(host), port };
    }
  }
  const idx = trimmed.lastIndexOf(":");
  if (idx > 0 && !trimmed.slice(0, idx).includes(":")) {
    const host = trimmed.slice(0, idx);
    const port = Number(trimmed.slice(idx + 1)) || defaultPort;
    return { host: normalizeHost(host), port };
  }
  return { host: normalizeHost(trimmed), port: defaultPort };
}

export class GateProxyServer {
  private config: AppConfig;
  private guard: GuardEngine;
  private store: Store;
  private notifier: MacNotifier;
  private server: net.Server | null = null;
  private sockets = new Set<net.Socket>();
  private stats: GateProxyStats = {
    startedAt: new Date().toISOString(),
    listening: false,
    totalRequests: 0,
    protectedRequests: 0,
    allowedRequests: 0,
    warnedRequests: 0,
    blockedRequests: 0,
    upBytes: 0,
    downBytes: 0,
    activeConnections: 0,
  };

  constructor(config: AppConfig, guard: GuardEngine, store: Store, notifier: MacNotifier) {
    this.config = config;
    this.guard = guard;
    this.store = store;
    this.notifier = notifier;
  }

  updateConfig(config: AppConfig): void {
    this.config = config;
  }

  getStats(): GateProxyStats {
    return {
      ...this.stats,
      activeConnections: this.sockets.size,
    };
  }

  getAddress(): { host: string; port: number } | null {
    const addr = this.server?.address();
    if (!addr || typeof addr === "string") return null;
    return { host: addr.address, port: addr.port };
  }

  start(portOverride?: number): Promise<number> {
    if (this.server) {
      const addr = this.getAddress();
      return Promise.resolve(addr?.port || this.config.proxyPort);
    }

    const listenPort = portOverride !== undefined ? portOverride : this.config.proxyPort;
    return new Promise((resolve, reject) => {
      const server = net.createServer((clientSocket) => {
        this.handleConnection(clientSocket);
      });

      const onError = (err: Error) => {
        server.removeListener("listening", onListening);
        reject(err);
      };
      const onListening = () => {
        server.removeListener("error", onError);
        this.server = server;
        this.stats.listening = true;
        this.stats.startedAt = new Date().toISOString();
        const addr = server.address();
        const actualPort = addr && typeof addr !== "string" ? addr.port : listenPort;
        resolve(actualPort);
      };

      server.once("error", onError);
      server.once("listening", onListening);
      server.listen(listenPort, "127.0.0.1");
    });
  }

  stop(): Promise<void> {
    return new Promise((resolve) => {
      this.stats.listening = false;
      for (const s of this.sockets) {
        s.destroy();
      }
      this.sockets.clear();
      if (!this.server) {
        resolve();
        return;
      }
      const srv = this.server;
      this.server = null;
      srv.close(() => resolve());
    });
  }

  private trackSocket(socket: net.Socket): void {
    this.sockets.add(socket);
    socket.setNoDelay(true);
    socket.setTimeout(120_000, () => {
      socket.destroy();
    });
    socket.on("close", () => {
      this.sockets.delete(socket);
    });
    socket.on("error", () => {
      socket.destroy();
    });
  }

  private recordDecision(
    decision: GuardDecision,
    source: "proxy_http" | "proxy_connect" | "proxy_socks5"
  ): void {
    this.stats.totalRequests++;
    if (decision.isProtected) {
      this.stats.protectedRequests++;
    }

    if (decision.action === "BLOCK") {
      this.stats.blockedRequests++;
      const nodeInfo = this.guard.getPrimaryClaudeNodeInfo();
      this.store.recordGuardEvent({
        ts: new Date().toISOString(),
        domain: decision.domain,
        source,
        action: "BLOCK",
        reasonCode: decision.reasonCode,
        message: decision.message,
        fixHint: decision.fixHint,
        clashMode: decision.clashMode,
        node: decision.route?.leafNode || nodeInfo.leaf,
        exitIp: decision.exitIp || "",
        exitCountry: decision.exitCountry || "",
        process: source,
      });
      this.notifier.notify(
        `${decision.reasonCode}:${decision.domain}`,
        "ClaudeGate 已拦截直连风险！",
        decision.domain,
        decision.message,
        true
      );
      return;
    }

    if (decision.action === "WARN") {
      this.stats.warnedRequests++;
      this.stats.allowedRequests++;
      if (decision.reasonCode !== "MISSING_EXPLICIT_RULE") {
        const nodeInfo = this.guard.getPrimaryClaudeNodeInfo();
        this.store.recordGuardEvent({
          ts: new Date().toISOString(),
          domain: decision.domain,
          source,
          action: "WARN",
          reasonCode: decision.reasonCode,
          message: decision.message,
          fixHint: decision.fixHint,
          clashMode: decision.clashMode,
          node: decision.route?.leafNode || nodeInfo.leaf,
          exitIp: decision.exitIp || "",
          exitCountry: decision.exitCountry || "",
          process: source,
        });
      }
      return;
    }

    this.stats.allowedRequests++;
  }

  private handleConnection(client: net.Socket): void {
    this.trackSocket(client);

    let firstBuf = Buffer.alloc(0);
    let dispatched = false;

    const cleanup = () => {
      client.removeListener("data", onInitialData);
    };

    const onInitialData = (chunk: Buffer) => {
      if (dispatched) return;
      firstBuf = Buffer.concat([firstBuf, chunk]);
      if (firstBuf.length === 0) return;

      // SOCKS5 starts with 0x05
      if (firstBuf[0] === 0x05) {
        dispatched = true;
        cleanup();
        this.handleSocks5(client, firstBuf);
        return;
      }

      // HTTP / HTTPS CONNECT: wait until \r\n\r\n (cap at 32KB)
      const headerEnd = firstBuf.indexOf("\r\n\r\n");
      if (headerEnd === -1) {
        if (firstBuf.length > 32768) {
          dispatched = true;
          cleanup();
          client.end("HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n");
        }
        return;
      }

      dispatched = true;
      cleanup();
      this.handleHttp(client, firstBuf, headerEnd);
    };

    client.on("data", onInitialData);
  }

  private handleHttp(client: net.Socket, buf: Buffer, headerEnd: number): void {
    const headerStr = buf.subarray(0, headerEnd).toString("latin1");
    const rest = buf.subarray(headerEnd + 4);
    const lines = headerStr.split("\r\n");
    const requestLine = lines[0] || "";
    const parts = requestLine.split(" ");
    const method = (parts[0] || "").toUpperCase();
    const target = parts[1] || "";

    if (method === "CONNECT") {
      const { host, port } = parseTargetHostPort(target, 443);
      if (!host) {
        client.end("HTTP/1.1 400 Bad Request\r\n\r\n");
        return;
      }

      const decision = this.guard.evaluate(host);
      this.recordDecision(decision, "proxy_connect");

      if (decision.action === "BLOCK") {
        const body = `${decision.message}\n\n${decision.fixHint}\n`;
        const bodyBuf = Buffer.from(body, "utf8");
        client.end(
          `HTTP/1.1 503 Service Unavailable\r\n` +
            `Content-Type: text/plain; charset=utf-8\r\n` +
            `Content-Length: ${bodyBuf.length}\r\n` +
            `X-ClaudeGate-Blocked: ${decision.reasonCode}\r\n` +
            `Connection: close\r\n\r\n` +
            body
        );
        return;
      }

      // Connect to upstream Clash proxy and perform HTTP CONNECT (pure TCP pass-through, no MITM)
      const upstream = net.connect(this.config.upstreamPort, this.config.upstreamHost);
      this.trackSocket(upstream);

      upstream.once("error", () => {
        if (!client.destroyed) {
          client.end("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\nUpstream proxy unavailable\n");
        }
      });

      upstream.once("connect", () => {
        upstream.write(
          `CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\nProxy-Connection: keep-alive\r\n\r\n`
        );
      });

      let upBuf = Buffer.alloc(0);
      const onUpData = (chunk: Buffer) => {
        upBuf = Buffer.concat([upBuf, chunk]);
        const idx = upBuf.indexOf("\r\n\r\n");
        if (idx === -1) {
          if (upBuf.length > 16384) {
            upstream.destroy();
            client.destroy();
          }
          return;
        }
        upstream.removeListener("data", onUpData);
        const upHeader = upBuf.subarray(0, idx).toString("latin1");
        const upRest = upBuf.subarray(idx + 4);
        const statusLine = upHeader.split("\r\n")[0] || "";

        if (!/\s200\s/.test(statusLine)) {
          client.end(`${upHeader}\r\n\r\n`);
          upstream.destroy();
          return;
        }

        client.write("HTTP/1.1 200 Connection Established\r\nProxy-Agent: ClaudeGate/0.1\r\n\r\n");
        if (rest.length > 0) {
          this.stats.upBytes += rest.length;
          upstream.write(rest);
        }
        if (upRest.length > 0) {
          this.stats.downBytes += upRest.length;
          client.write(upRest);
        }
        this.bridgeStreams(client, upstream);
      };

      upstream.on("data", onUpData);
      return;
    }

    // Plain HTTP Proxy request
    let host = "";
    try {
      if (/^https?:\/\//i.test(target)) {
        host = normalizeHost(new URL(target).hostname);
      }
    } catch {
      // ignore URL parse error
    }
    if (!host) {
      for (let i = 1; i < lines.length; i++) {
        const m = lines[i].match(/^host:\s*(.+)$/i);
        if (m) {
          host = parseTargetHostPort(m[1], 80).host;
          break;
        }
      }
    }

    if (!host) {
      client.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\nMissing Host\n");
      return;
    }

    const decision = this.guard.evaluate(host);
    this.recordDecision(decision, "proxy_http");

    if (decision.action === "BLOCK") {
      const html = renderHtmlBlockPage(decision, this.config.dashboardPort);
      const htmlBuf = Buffer.from(html, "utf8");
      client.end(
        `HTTP/1.1 503 Service Unavailable\r\n` +
          `Content-Type: text/html; charset=utf-8\r\n` +
          `Content-Length: ${htmlBuf.length}\r\n` +
          `X-ClaudeGate-Blocked: ${decision.reasonCode}\r\n` +
          `Connection: close\r\n\r\n` +
          html
      );
      return;
    }

    const upstream = net.connect(this.config.upstreamPort, this.config.upstreamHost);
    this.trackSocket(upstream);

    upstream.once("error", () => {
      if (!client.destroyed) {
        client.end("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\nUpstream proxy unavailable\n");
      }
    });

    upstream.once("connect", () => {
      this.stats.upBytes += buf.length;
      upstream.write(buf);
      this.bridgeStreams(client, upstream);
    });
  }

  private handleSocks5(client: net.Socket, initial: Buffer): void {
    let buffer = initial;
    let stage: "greeting" | "request" = "greeting";

    const failAndClose = (rep = 0x01) => {
      if (!client.destroyed) {
        client.end(Buffer.from([0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
      }
    };

    const processBuffer = () => {
      if (stage === "greeting") {
        if (buffer.length < 2) return;
        const nMethods = buffer[1];
        if (buffer.length < 2 + nMethods) return;
        // Consume greeting
        buffer = buffer.subarray(2 + nMethods);
        stage = "request";
        // Reply: version 5, no-auth (0x00)
        client.write(Buffer.from([0x05, 0x00]));
      }

      if (stage === "request") {
        if (buffer.length < 4) return;
        const ver = buffer[0];
        const cmd = buffer[1];
        const atyp = buffer[3];
        if (ver !== 0x05 || cmd !== 0x01) {
          client.removeListener("data", onData);
          failAndClose(0x07); // Command not supported
          return;
        }

        let host = "";
        let addrEnd = 0;

        if (atyp === 0x01) {
          // IPv4
          if (buffer.length < 10) return;
          host = `${buffer[4]}.${buffer[5]}.${buffer[6]}.${buffer[7]}`;
          addrEnd = 8;
        } else if (atyp === 0x03) {
          // Domain
          if (buffer.length < 5) return;
          const len = buffer[4];
          if (buffer.length < 5 + len + 2) return;
          host = buffer.subarray(5, 5 + len).toString("utf8");
          addrEnd = 5 + len;
        } else if (atyp === 0x04) {
          // IPv6
          if (buffer.length < 22) return;
          const parts: string[] = [];
          for (let i = 4; i < 20; i += 2) {
            parts.push(buffer.readUInt16BE(i).toString(16));
          }
          host = parts.join(":");
          addrEnd = 20;
        } else {
          client.removeListener("data", onData);
          failAndClose(0x08); // Address type not supported
          return;
        }

        const rawReqPacket = buffer.subarray(0, addrEnd + 2);
        const leftover = buffer.subarray(addrEnd + 2);
        client.removeListener("data", onData);

        const decision = this.guard.evaluate(host);
        this.recordDecision(decision, "proxy_socks5");

        if (decision.action === "BLOCK") {
          failAndClose(0x02); // Connection not allowed by ruleset
          return;
        }

        this.forwardSocks5Upstream(client, rawReqPacket, leftover);
      }
    };

    const onData = (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      processBuffer();
    };

    client.on("data", onData);
    processBuffer();
  }

  private forwardSocks5Upstream(
    client: net.Socket,
    rawReqPacket: Buffer,
    leftover: Buffer
  ): void {
    const upstream = net.connect(this.config.upstreamPort, this.config.upstreamHost);
    this.trackSocket(upstream);

    let upStage: "greeting" | "reply" = "greeting";
    let upBuf = Buffer.alloc(0);

    upstream.once("error", () => {
      if (!client.destroyed) {
        client.end(Buffer.from([0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
      }
    });

    upstream.once("connect", () => {
      // Send SOCKS5 greeting (no auth)
      upstream.write(Buffer.from([0x05, 0x01, 0x00]));
    });

    const onUpData = (chunk: Buffer) => {
      upBuf = Buffer.concat([upBuf, chunk]);

      if (upStage === "greeting") {
        if (upBuf.length < 2) return;
        if (upBuf[0] !== 0x05 || upBuf[1] !== 0x00) {
          upstream.removeListener("data", onUpData);
          upstream.destroy();
          client.end(Buffer.from([0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
          return;
        }
        upBuf = upBuf.subarray(2);
        upStage = "reply";
        upstream.write(rawReqPacket);
      }

      if (upStage === "reply") {
        if (upBuf.length < 4) return;
        const atyp = upBuf[3];
        let needed = 0;
        if (atyp === 0x01) needed = 10;
        else if (atyp === 0x03) {
          if (upBuf.length < 5) return;
          needed = 5 + upBuf[4] + 2;
        } else if (atyp === 0x04) needed = 22;
        else needed = upBuf.length;

        if (upBuf.length < needed) return;
        const replyPacket = upBuf.subarray(0, needed);
        const upLeftover = upBuf.subarray(needed);
        upstream.removeListener("data", onUpData);

        client.write(replyPacket);
        if (replyPacket[1] !== 0x00) {
          upstream.destroy();
          client.destroy();
          return;
        }

        if (leftover.length > 0) {
          this.stats.upBytes += leftover.length;
          upstream.write(leftover);
        }
        if (upLeftover.length > 0) {
          this.stats.downBytes += upLeftover.length;
          client.write(upLeftover);
        }
        this.bridgeStreams(client, upstream);
      }
    };

    upstream.on("data", onUpData);
  }

  private bridgeStreams(client: net.Socket, upstream: net.Socket): void {
    client.on("data", (chunk: Buffer) => {
      this.stats.upBytes += chunk.length;
      if (!upstream.destroyed) {
        const ok = upstream.write(chunk);
        if (!ok) client.pause();
      }
    });

    upstream.on("drain", () => {
      if (!client.destroyed) client.resume();
    });

    upstream.on("data", (chunk: Buffer) => {
      this.stats.downBytes += chunk.length;
      if (!client.destroyed) {
        const ok = client.write(chunk);
        if (!ok) upstream.pause();
      }
    });

    client.on("drain", () => {
      if (!upstream.destroyed) upstream.resume();
    });

    const closeBoth = () => {
      if (!client.destroyed) client.destroy();
      if (!upstream.destroyed) upstream.destroy();
    };

    client.once("end", () => {
      if (!upstream.destroyed) upstream.end();
    });
    upstream.once("end", () => {
      if (!client.destroyed) client.end();
    });
    client.once("close", closeBoth);
    upstream.once("close", closeBoth);
  }
}
