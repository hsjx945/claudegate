import { execFile } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { ensureDataDir, getDataDir } from "./config.js";

const execFileAsync = promisify(execFile);

export interface SystemProxyStatus {
  platform: string;
  activeService: string | null;
  httpEnabled: boolean;
  httpHost: string;
  httpPort: number;
  httpsEnabled: boolean;
  httpsHost: string;
  httpsPort: number;
  socksEnabled: boolean;
  socksHost: string;
  socksPort: number;
  pointingToGate: boolean;
  pointingToUpstream: boolean;
  managedByGate: boolean;
}

interface SavedProxyBackup {
  service: string;
  httpEnabled: boolean;
  httpHost: string;
  httpPort: number;
  httpsEnabled: boolean;
  httpsHost: string;
  httpsPort: number;
  socksEnabled: boolean;
  socksHost: string;
  socksPort: number;
}

function getBackupPath(): string {
  return path.join(getDataDir(), "prev-proxy.json");
}

function parseScutilProxy(stdout: string): Omit<
  SystemProxyStatus,
  "platform" | "activeService" | "pointingToGate" | "pointingToUpstream" | "managedByGate"
> {
  const getVal = (key: string): string => {
    const m = stdout.match(new RegExp(`^\\s*${key}\\s*:\\s*(.+)$`, "m"));
    return m ? m[1].trim() : "";
  };
  return {
    httpEnabled: getVal("HTTPEnable") === "1",
    httpHost: getVal("HTTPProxy"),
    httpPort: Number(getVal("HTTPPort") || 0),
    httpsEnabled: getVal("HTTPSEnable") === "1",
    httpsHost: getVal("HTTPSProxy"),
    httpsPort: Number(getVal("HTTPSPort") || 0),
    socksEnabled: getVal("SOCKSEnable") === "1",
    socksHost: getVal("SOCKSProxy"),
    socksPort: Number(getVal("SOCKSPort") || 0),
  };
}

export async function detectActiveNetworkService(): Promise<string | null> {
  if (process.platform !== "darwin") return null;

  let defaultIface = "";
  try {
    const { stdout } = await execFileAsync("route", ["-n", "get", "default"], { timeout: 2000 });
    const m = stdout.match(/interface:\s*(\S+)/);
    if (m) defaultIface = m[1];
  } catch {
    // ignore
  }

  try {
    const { stdout } = await execFileAsync("networksetup", ["-listnetworkserviceorder"], {
      timeout: 2000,
    });
    const lines = stdout.split("\n");
    let currentService: string | null = null;
    const services: Array<{ name: string; device: string }> = [];

    for (const line of lines) {
      const svcMatch = line.match(/^\(\d+\)\s+(.+)$/);
      if (svcMatch) {
        currentService = svcMatch[1].trim();
        continue;
      }
      const devMatch = line.match(/Device:\s*([^)]+)\)/);
      if (devMatch && currentService) {
        services.push({ name: currentService, device: devMatch[1].trim() });
        currentService = null;
      }
    }

    if (defaultIface) {
      const matched = services.find((s) => s.device === defaultIface);
      if (matched) return matched.name;
    }

    const wifi = services.find((s) => /wi-?fi/i.test(s.name));
    if (wifi) return wifi.name;

    return services[0]?.name || null;
  } catch {
    return null;
  }
}

export async function getSystemProxyStatus(
  gatePort: number,
  upstreamPort: number
): Promise<SystemProxyStatus> {
  if (process.platform !== "darwin") {
    return {
      platform: process.platform,
      activeService: null,
      httpEnabled: false,
      httpHost: "",
      httpPort: 0,
      httpsEnabled: false,
      httpsHost: "",
      httpsPort: 0,
      socksEnabled: false,
      socksHost: "",
      socksPort: 0,
      pointingToGate: false,
      pointingToUpstream: false,
      managedByGate: fs.existsSync(getBackupPath()),
    };
  }

  const [scutilRes, activeService] = await Promise.all([
    execFileAsync("scutil", ["--proxy"], { timeout: 2000 }).catch(() => ({ stdout: "" })),
    detectActiveNetworkService(),
  ]);

  const parsed = parseScutilProxy(scutilRes.stdout || "");
  const isLocal = (h: string) => h === "127.0.0.1" || h === "localhost";
  const pointingToGate =
    parsed.httpEnabled &&
    parsed.httpsEnabled &&
    isLocal(parsed.httpHost) &&
    isLocal(parsed.httpsHost) &&
    parsed.httpPort === gatePort &&
    parsed.httpsPort === gatePort;

  const pointingToUpstream =
    parsed.httpEnabled &&
    parsed.httpsEnabled &&
    isLocal(parsed.httpHost) &&
    isLocal(parsed.httpsHost) &&
    parsed.httpPort === upstreamPort &&
    parsed.httpsPort === upstreamPort;

  return {
    platform: process.platform,
    activeService,
    ...parsed,
    pointingToGate,
    pointingToUpstream,
    managedByGate: fs.existsSync(getBackupPath()),
  };
}

export async function enableGateSystemProxy(
  gatePort: number,
  upstreamPort: number
): Promise<SystemProxyStatus> {
  if (process.platform !== "darwin") {
    throw new Error("System proxy automation is only supported on macOS.");
  }
  const current = await getSystemProxyStatus(gatePort, upstreamPort);
  if (!current.activeService) {
    throw new Error("未检测到活跃的 macOS 网络服务（如 Wi-Fi），无法设置系统代理。");
  }

  const backupPath = getBackupPath();
  if (!fs.existsSync(backupPath) && !current.pointingToGate) {
    ensureDataDir();
    const backup: SavedProxyBackup = {
      service: current.activeService,
      httpEnabled: current.httpEnabled,
      httpHost: current.httpHost,
      httpPort: current.httpPort,
      httpsEnabled: current.httpsEnabled,
      httpsHost: current.httpsHost,
      httpsPort: current.httpsPort,
      socksEnabled: current.socksEnabled,
      socksHost: current.socksHost,
      socksPort: current.socksPort,
    };
    fs.writeFileSync(backupPath, JSON.stringify(backup, null, 2), "utf8");
  }

  const svc = current.activeService;
  await execFileAsync("networksetup", ["-setwebproxy", svc, "127.0.0.1", String(gatePort)]);
  await execFileAsync("networksetup", ["-setsecurewebproxy", svc, "127.0.0.1", String(gatePort)]);
  await execFileAsync("networksetup", ["-setsocksfirewallproxy", svc, "127.0.0.1", String(gatePort)]);
  await execFileAsync("networksetup", ["-setwebproxystate", svc, "on"]);
  await execFileAsync("networksetup", ["-setsecurewebproxystate", svc, "on"]);
  await execFileAsync("networksetup", ["-setsocksfirewallproxystate", svc, "on"]);

  return getSystemProxyStatus(gatePort, upstreamPort);
}

export async function restoreSystemProxy(
  gatePort: number,
  upstreamPort: number
): Promise<SystemProxyStatus> {
  if (process.platform !== "darwin") {
    return getSystemProxyStatus(gatePort, upstreamPort);
  }
  const backupPath = getBackupPath();
  let backup: SavedProxyBackup | null = null;
  if (fs.existsSync(backupPath)) {
    try {
      backup = JSON.parse(fs.readFileSync(backupPath, "utf8")) as SavedProxyBackup;
    } catch {
      backup = null;
    }
  }

  const svc = backup?.service || (await detectActiveNetworkService());
  if (svc) {
    if (backup && backup.httpEnabled && backup.httpHost && backup.httpPort) {
      await execFileAsync("networksetup", ["-setwebproxy", svc, backup.httpHost, String(backup.httpPort)]);
      await execFileAsync("networksetup", ["-setwebproxystate", svc, "on"]);
    } else if (!backup) {
      await execFileAsync("networksetup", ["-setwebproxy", svc, "127.0.0.1", String(upstreamPort)]);
      await execFileAsync("networksetup", ["-setwebproxystate", svc, "on"]);
    } else {
      await execFileAsync("networksetup", ["-setwebproxystate", svc, "off"]);
    }

    if (backup && backup.httpsEnabled && backup.httpsHost && backup.httpsPort) {
      await execFileAsync("networksetup", [
        "-setsecurewebproxy",
        svc,
        backup.httpsHost,
        String(backup.httpsPort),
      ]);
      await execFileAsync("networksetup", ["-setsecurewebproxystate", svc, "on"]);
    } else if (!backup) {
      await execFileAsync("networksetup", [
        "-setsecurewebproxy",
        svc,
        "127.0.0.1",
        String(upstreamPort),
      ]);
      await execFileAsync("networksetup", ["-setsecurewebproxystate", svc, "on"]);
    } else {
      await execFileAsync("networksetup", ["-setsecurewebproxystate", svc, "off"]);
    }

    if (backup && backup.socksEnabled && backup.socksHost && backup.socksPort) {
      await execFileAsync("networksetup", [
        "-setsocksfirewallproxy",
        svc,
        backup.socksHost,
        String(backup.socksPort),
      ]);
      await execFileAsync("networksetup", ["-setsocksfirewallproxystate", svc, "on"]);
    } else if (!backup) {
      await execFileAsync("networksetup", [
        "-setsocksfirewallproxy",
        svc,
        "127.0.0.1",
        String(upstreamPort),
      ]);
      await execFileAsync("networksetup", ["-setsocksfirewallproxystate", svc, "on"]);
    } else {
      await execFileAsync("networksetup", ["-setsocksfirewallproxystate", svc, "off"]);
    }
  }

  if (fs.existsSync(backupPath)) {
    fs.unlinkSync(backupPath);
  }
  return getSystemProxyStatus(gatePort, upstreamPort);
}

export function hasManagedProxyBackup(): boolean {
  return fs.existsSync(getBackupPath());
}

const LAUNCH_AGENT_LABEL = "com.claudeban.claudegate";

export function getLaunchAtLoginPath(): string {
  const custom = process.env.CLAUDEBAN_LAUNCH_AGENT_PATH;
  if (custom && custom.trim()) {
    return path.resolve(custom.trim());
  }
  return path.join(os.homedir(), "Library", "LaunchAgents", `${LAUNCH_AGENT_LABEL}.plist`);
}

export function getLaunchAtLoginStatus(): boolean {
  if (process.platform !== "darwin") return false;
  return fs.existsSync(getLaunchAtLoginPath());
}

function escapeXml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export function setLaunchAtLogin(enable: boolean): boolean {
  if (process.platform !== "darwin") return false;
  const plistPath = getLaunchAtLoginPath();

  if (!enable) {
    if (fs.existsSync(plistPath)) {
      fs.unlinkSync(plistPath);
    }
    return false;
  }

  const execPath =
    process.env.CLAUDEGATE_APP_EXEC || "/Applications/ClaudeGate.app/Contents/MacOS/ClaudeGate";
  fs.mkdirSync(path.dirname(plistPath), { recursive: true });
  const plistXml = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${LAUNCH_AGENT_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${escapeXml(execPath)}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <false/>
</dict>
</plist>
`;
  fs.writeFileSync(plistPath, plistXml, "utf8");
  return true;
}
