import { execFile } from "node:child_process";

function escapeAppleScriptString(input: string): string {
  return input
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/[\r\n]+/g, " ")
    .slice(0, 220);
}

export class MacNotifier {
  private enabled: boolean;
  private lastSentAt = new Map<string, number>();
  private readonly cooldownMs = 15_000;

  constructor(enabled = true) {
    this.enabled = enabled;
  }

  setEnabled(enabled: boolean): void {
    this.enabled = enabled;
  }

  notify(key: string, title: string, subtitle: string, message: string, urgent = true): void {
    if (!this.enabled) return;
    if (process.env.CLAUDEBAN_NO_NOTIFY === "1") return;
    if (process.platform !== "darwin") return;

    const now = Date.now();
    const prev = this.lastSentAt.get(key) || 0;
    if (now - prev < this.cooldownMs) {
      return;
    }
    this.lastSentAt.set(key, now);

    const safeTitle = escapeAppleScriptString(title);
    const safeSub = escapeAppleScriptString(subtitle);
    const safeMsg = escapeAppleScriptString(message);
    const soundPart = urgent ? ' sound name "Basso"' : "";
    const script = `display notification "${safeMsg}" with title "${safeTitle}" subtitle "${safeSub}"${soundPart}`;

    execFile("osascript", ["-e", script], { timeout: 2000 }, () => {
      // Ignore notification errors in headless/CI contexts
    });
  }
}
