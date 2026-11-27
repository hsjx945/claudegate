import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { getDefaultConfig } from "../src/config.js";
import { DashboardServer } from "../src/dashboard-server.js";
import { Store } from "../src/db.js";
import { ExitIpProber, type ExitIpInfo } from "../src/exit-ip.js";
import { GuardEngine } from "../src/guard.js";
import { MihomoClient, type MihomoConnection } from "../src/mihomo.js";
import { MacNotifier } from "../src/notifier.js";
import { GateProxyServer } from "../src/proxy-server.js";
import { Watchdog } from "../src/watchdog.js";

function httpProxyRequest(
  proxyPort: number,
  targetUrl: string
): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        hostname: "127.0.0.1",
        port: proxyPort,
        path: targetUrl,
        method: "GET",
        headers: { Host: new URL(targetUrl).host },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () =>
          resolve({
            status: res.statusCode || 0,
            headers: res.headers,
            body: Buffer.concat(chunks).toString("utf8"),
          })
        );
      }
    );
    req.on("error", reject);
    req.end();
  });
}

function httpConnectRequest(
  proxyPort: number,
  targetHost: string,
  targetPort: number
): Promise<{ statusLine: string; headersRaw: string; body: string }> {
  return new Promise((resolve, reject) => {
    const sock = net.connect(proxyPort, "127.0.0.1");
    sock.on("error", reject);
    sock.once("connect", () => {
      sock.write(`CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n\r\n`);
    });
    let buf = Buffer.alloc(0);
    let established = false;
    sock.on("data", (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      if (!established) {
        const idx = buf.indexOf("\r\n\r\n");
        if (idx === -1) return;
        const header = buf.subarray(0, idx).toString("utf8");
        const statusLine = header.split("\r\n")[0] || "";
        if (!/\s200\s/.test(statusLine)) {
          const rest = buf.subarray(idx + 4).toString("utf8");
          sock.destroy();
          resolve({ statusLine, headersRaw: header, body: rest });
          return;
        }
        established = true;
        buf = buf.subarray(idx + 4);
        sock.write("PING_TUNNEL");
      }
      if (established && buf.toString("utf8").includes("ECHO:PING_TUNNEL")) {
        const data = buf.toString("utf8");
        sock.destroy();
        resolve({ statusLine: "HTTP/1.1 200 Connection Established", headersRaw: "", body: data });
      }
    });
  });
}

function socks5ConnectRequest(
  proxyPort: number,
  targetHost: string,
  targetPort: number
): Promise<{ replyCode: number; echo: string }> {
  return new Promise((resolve, reject) => {
    const sock = net.connect(proxyPort, "127.0.0.1");
    sock.on("error", reject);
    let step: "greeting" | "connect" | "data" = "greeting";
    let buf = Buffer.alloc(0);

    sock.once("connect", () => {
      sock.write(Buffer.from([0x05, 0x01, 0x00]));
    });

    sock.on("data", (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      if (step === "greeting") {
        if (buf.length < 2) return;
        assert.equal(buf[0], 0x05);
        assert.equal(buf[1], 0x00);
        buf = buf.subarray(2);
        step = "connect";
        const hostBuf = Buffer.from(targetHost, "utf8");
        const portBuf = Buffer.alloc(2);
        portBuf.writeUInt16BE(targetPort, 0);
        sock.write(
          Buffer.concat([
            Buffer.from([0x05, 0x01, 0x00, 0x03, hostBuf.length]),
            hostBuf,
            portBuf,
          ])
        );
      } else if (step === "connect") {
        if (buf.length < 4) return;
        const atyp = buf[3];
        const needed = atyp === 0x01 ? 10 : atyp === 0x03 ? 5 + (buf[4] || 0) + 2 : 10;
        if (buf.length < needed) return;
        const replyCode = buf[1];
        buf = buf.subarray(needed);
        if (replyCode !== 0x00) {
          sock.destroy();
          resolve({ replyCode, echo: "" });
          return;
        }
        step = "data";
        sock.write("SOCKS_PING");
      }

      if (step === "data" && buf.toString("utf8").includes("ECHO:SOCKS_PING")) {
        const echo = buf.toString("utf8");
        sock.destroy();
        resolve({ replyCode: 0x00, echo });
      }
    });
  });
}

test("E2E: Gate proxy, Watchdog TUN kill, Exit IP block, and Dashboard API", async () => {
  process.env.CLAUDEBAN_NO_NOTIFY = "1";
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "claudeban-e2e-"));
  process.env.CLAUDEBAN_DATA_DIR = tmpDir;

  // 1. Mock Mihomo controller state
  let mockMode = "rule";
  const killedIds: string[] = [];
  let mockConnections: MihomoConnection[] = [];

  const mockMihomoServer = http.createServer((req, res) => {
    const url = req.url || "/";
    if (url === "/version") {
      res.end(JSON.stringify({ version: "v1.19.32-mock", meta: true }));
      return;
    }
    if (url === "/configs" && req.method === "GET") {
      res.end(JSON.stringify({ mode: mockMode, "mixed-port": 7897, tun: { enable: true, device: "utun1024" } }));
      return;
    }
    if (url === "/configs" && req.method === "PATCH") {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as { mode?: string };
        if (body.mode) mockMode = body.mode;
        res.statusCode = 204;
        res.end();
      });
      return;
    }
    if (url === "/proxies") {
      res.end(
        JSON.stringify({
          proxies: {
            DIRECT: { name: "DIRECT", type: "Direct" },
            GLOBAL: { name: "GLOBAL", type: "Selector", now: "DIRECT", all: ["DIRECT", "Proxy"] },
            Proxy: { name: "Proxy", type: "Selector", now: "JP-Tokyo", all: ["JP-Tokyo"] },
            Others: { name: "Others", type: "Selector", now: "Proxy", all: ["Proxy"] },
            "JP-Tokyo": { name: "JP-Tokyo", type: "Trojan" },
          },
        })
      );
      return;
    }
    if (url === "/rules") {
      res.end(
        JSON.stringify({
          rules: [
            { index: 0, type: "DomainSuffix", payload: "claude.ai", proxy: "Proxy" },
            { index: 1, type: "DomainSuffix", payload: "anthropic.com", proxy: "Proxy" },
            { index: 2, type: "Match", payload: "", proxy: "Others" },
          ],
        })
      );
      return;
    }
    if (url === "/connections") {
      res.end(JSON.stringify({ uploadTotal: 1000, downloadTotal: 2000, connections: mockConnections }));
      return;
    }
    if (url.startsWith("/connections/") && req.method === "DELETE") {
      const id = decodeURIComponent(url.slice("/connections/".length));
      killedIds.push(id);
      mockConnections = mockConnections.filter((c) => c.id !== id);
      res.statusCode = 204;
      res.end();
      return;
    }
    res.statusCode = 404;
    res.end();
  });

  await new Promise<void>((r) => mockMihomoServer.listen(0, "127.0.0.1", r));
  const mihomoPort = (mockMihomoServer.address() as net.AddressInfo).port;

  // 2. Mock upstream proxy server (supports HTTP, CONNECT, SOCKS5 echo) & tracks connection count
  let upstreamConnectCount = 0;
  const mockUpstreamServer = net.createServer((sock) => {
    upstreamConnectCount++;
    sock.on("error", () => {});
    let buf = Buffer.alloc(0);
    let mode: "init" | "socks_req" | "tunnel" = "init";

    sock.on("data", (chunk: Buffer) => {
      if (mode === "tunnel") {
        sock.write("ECHO:" + chunk.toString("utf8"));
        return;
      }
      buf = Buffer.concat([buf, chunk]);
      if (mode === "init" && buf[0] === 0x05) {
        if (buf.length < 2 + buf[1]) return;
        buf = buf.subarray(2 + buf[1]);
        mode = "socks_req";
        sock.write(Buffer.from([0x05, 0x00]));
      }
      if (mode === "socks_req") {
        if (buf.length < 5) return;
        const needed = buf[3] === 0x03 ? 5 + buf[4] + 2 : 10;
        if (buf.length < needed) return;
        buf = buf.subarray(needed);
        mode = "tunnel";
        sock.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80]));
        if (buf.length > 0) sock.write("ECHO:" + buf.toString("utf8"));
        return;
      }
      const idx = buf.indexOf("\r\n\r\n");
      if (idx !== -1) {
        const header = buf.subarray(0, idx).toString("utf8");
        if (header.startsWith("CONNECT ")) {
          mode = "tunnel";
          sock.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        } else {
          sock.end("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nUP_OK\r\n");
        }
      }
    });
  });

  await new Promise<void>((r) => mockUpstreamServer.listen(0, "127.0.0.1", r));
  const upstreamPort = (mockUpstreamServer.address() as net.AddressInfo).port;

  // 3. Boot ClaudeGate stack
  let mockExitIp: ExitIpInfo = {
    ip: "198.51.100.20",
    countryCode: "JP",
    country: "Japan",
    isp: "Cloudflare",
    checkedAt: new Date().toISOString(),
    source: "mock",
  };

  const cfg = getDefaultConfig();
  cfg.proxyPort = 0;
  cfg.dashboardPort = 0;
  cfg.upstreamHost = "127.0.0.1";
  cfg.upstreamPort = upstreamPort;
  cfg.mihomoTcpUrl = `http://127.0.0.1:${mihomoPort}`;

  const store = new Store(path.join(tmpDir, "test.db"));
  const mihomo = new MihomoClient(cfg, { kind: "tcp", baseUrl: cfg.mihomoTcpUrl });
  const exitIpProber = new ExitIpProber(cfg, async () => ({
    ...mockExitIp,
    checkedAt: new Date().toISOString(),
  }));
  const guard = new GuardEngine(cfg);
  const notifier = new MacNotifier(false);
  const proxyServer = new GateProxyServer(cfg, guard, store, notifier);
  const watchdog = new Watchdog(cfg, mihomo, exitIpProber, guard, store, notifier);
  const dashboard = new DashboardServer({
    config: cfg,
    mihomo,
    guard,
    store,
    proxyServer,
    watchdog,
  });

  try {
    const gatePort = await proxyServer.start(0);
    const dashPort = await dashboard.start(0);
    await watchdog.start();

    // Case A: Safe mode (rule + JP exit IP) -> HTTP, CONNECT, SOCKS5 to claude.ai succeed
    const httpRes = await httpProxyRequest(gatePort, "http://claude.ai/test");
    assert.equal(httpRes.status, 200);
    assert.ok(httpRes.body.includes("UP_OK"));

    const connRes = await httpConnectRequest(gatePort, "claude.ai", 443);
    assert.ok(connRes.statusLine.includes("200"));
    assert.equal(connRes.body, "ECHO:PING_TUNNEL");

    const socksRes = await socks5ConnectRequest(gatePort, "claude.ai", 443);
    assert.equal(socksRes.replyCode, 0x00);
    assert.equal(socksRes.echo, "ECHO:SOCKS_PING");
    assert.equal(upstreamConnectCount, 3);

    // Case B: Switch Clash to DIRECT mode -> claude.ai MUST be blocked with 0 upstream connections!
    mockMode = "direct";
    await watchdog.syncOnce();

    const countBeforeBlock = upstreamConnectCount;
    const blockedConnect = await httpConnectRequest(gatePort, "claude.ai", 443);
    assert.ok(blockedConnect.statusLine.includes("503"));
    assert.ok(blockedConnect.headersRaw.includes("X-ClaudeGate-Blocked: CLASH_DIRECT_MODE"));

    const blockedSocks = await socks5ConnectRequest(gatePort, "api.anthropic.com", 443);
    assert.equal(blockedSocks.replyCode, 0x02);
    assert.equal(upstreamConnectCount, countBeforeBlock); // 0 bytes / 0 connections leaked upstream!

    // Dashboard auto-fix action restores rule mode
    const fixResp = await fetch(`http://127.0.0.1:${dashPort}/api/actions/auto-fix`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    assert.equal(fixResp.status, 200);
    assert.equal(mockMode, "rule");

    // Case C: Banned exit IP (CN) blocks api.anthropic.com but allows non-Claude example.com
    mockExitIp = {
      ip: "192.0.2.10",
      countryCode: "CN",
      country: "China",
      checkedAt: new Date().toISOString(),
      source: "mock",
    };
    await watchdog.probeIpNow();

    const countBeforeCnBlock = upstreamConnectCount;
    const cnBlocked = await httpConnectRequest(gatePort, "api.anthropic.com", 443);
    assert.ok(cnBlocked.statusLine.includes("503"));
    assert.ok(cnBlocked.headersRaw.includes("X-ClaudeGate-Blocked: BANNED_EXIT_COUNTRY"));
    assert.equal(upstreamConnectCount, countBeforeCnBlock);

    const nonClaudeAllowed = await httpConnectRequest(gatePort, "example.com", 443);
    assert.ok(nonClaudeAllowed.statusLine.includes("200"));
    assert.equal(upstreamConnectCount, countBeforeCnBlock + 1);

    // Case D: Watchdog detects TUN DIRECT leak connection and kills it + records traffic
    mockExitIp.countryCode = "JP";
    mockExitIp.country = "Japan";
    await watchdog.probeIpNow();

    mockConnections = [
      {
        id: "leak-conn-1",
        upload: 1200,
        download: 4500,
        start: new Date().toISOString(),
        chains: ["DIRECT"],
        rule: "Match",
        rulePayload: "",
        metadata: {
          host: "claude.ai",
          process: "curl",
          destinationPort: "443",
        },
      },
    ];
    await watchdog.syncOnce();
    assert.ok(killedIds.includes("leak-conn-1"));

    // Verify Dashboard APIs & SQLite persistence
    const statusJson = (await (await fetch(`http://127.0.0.1:${dashPort}/api/status`)).json()) as {
      clash: { mode: string };
    };
    assert.equal(statusJson.clash.mode, "rule");

    const auditJson = (await (await fetch(`http://127.0.0.1:${dashPort}/api/audit`)).json()) as {
      globalRisk: boolean;
      missingExplicitRuleDomains: string[];
    };
    assert.equal(auditJson.globalRisk, true);
    assert.ok(auditJson.missingExplicitRuleDomains.includes("statsig.com"));

    const statsJson = (await (await fetch(`http://127.0.0.1:${dashPort}/api/stats?range=24h`)).json()) as {
      claudeUpBytes: number;
      claudeDownBytes: number;
    };
    assert.equal(statsJson.claudeUpBytes, 1200);
    assert.equal(statsJson.claudeDownBytes, 4500);

    const eventsJson = (await (await fetch(`http://127.0.0.1:${dashPort}/api/events`)).json()) as {
      events: Array<{ action: string; reasonCode: string }>;
    };
    assert.ok(eventsJson.events.some((e) => e.action === "KILL" && e.reasonCode === "TUN_DIRECT_LEAK"));
    assert.ok(eventsJson.events.some((e) => e.action === "BLOCK" && e.reasonCode === "CLASH_DIRECT_MODE"));

    // Verify DELETE /api/events clears audit log
    const clearResp = await fetch(`http://127.0.0.1:${dashPort}/api/events`, { method: "DELETE" });
    assert.equal(clearResp.status, 200);
    const eventsAfterClear = (await (await fetch(`http://127.0.0.1:${dashPort}/api/events`)).json()) as {
      events: Array<unknown>;
    };
    assert.equal(eventsAfterClear.events.length, 0);

    // Verify PUT /api/config updates probe interval and isolated launchAtLogin plist
    const testPlistPath = path.join(tmpDir, "test.launchagent.plist");
    process.env.CLAUDEBAN_LAUNCH_AGENT_PATH = testPlistPath;
    const putCfgResp = await fetch(`http://127.0.0.1:${dashPort}/api/config`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ exitIpProbeIntervalSec: 60, launchAtLogin: true }),
    });
    assert.equal(putCfgResp.status, 200);
    const putCfgJson = (await putCfgResp.json()) as { exitIpProbeIntervalSec: number; launchAtLogin: boolean };
    assert.equal(putCfgJson.exitIpProbeIntervalSec, 60);
    assert.equal(putCfgJson.launchAtLogin, true);
    assert.equal(fs.existsSync(testPlistPath), true);

    const disableLaunchResp = await fetch(`http://127.0.0.1:${dashPort}/api/config`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ launchAtLogin: false }),
    });
    const disableJson = (await disableLaunchResp.json()) as { launchAtLogin: boolean };
    assert.equal(disableJson.launchAtLogin, false);
    assert.equal(fs.existsSync(testPlistPath), false);
    delete process.env.CLAUDEBAN_LAUNCH_AGENT_PATH;
  } finally {
    watchdog.stop();
    await proxyServer.stop();
    await dashboard.stop();
    store.close();
    await new Promise<void>((r) => mockMihomoServer.close(() => r()));
    await new Promise<void>((r) => mockUpstreamServer.close(() => r()));
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
