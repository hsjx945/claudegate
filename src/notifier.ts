import { execFile } from "node:child_process";

function sanitizeMessage(input: string): string {
  return input.replace(/[\r\n]+/g, " ").trim().slice(0, 220);
}

function escapeAppleScriptString(input: string): string {
  return sanitizeMessage(input).replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

function escapePowerShellSingleQuoted(input: string): string {
  return sanitizeMessage(input).replace(/'/g, "''");
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

    const now = Date.now();
    const prev = this.lastSentAt.get(key) || 0;
    if (now - prev < this.cooldownMs) {
      return;
    }
    this.lastSentAt.set(key, now);

    if (process.platform === "darwin") {
      const safeTitle = escapeAppleScriptString(title);
      const safeSub = escapeAppleScriptString(subtitle);
      const safeMsg = escapeAppleScriptString(message);
      const soundPart = urgent ? "" : ' sound name "Glass"';
      const script = `display notification "${safeMsg}" with title "${safeTitle}" subtitle "${safeSub}"${soundPart}`;

      execFile("osascript", ["-e", script], { timeout: 2500 }, () => {
        // Ignore notification errors in headless/CI contexts
      });

      if (urgent) {
        // Play system alert sound directly so urgent blocks stay audible even if banner sounds are muted
        execFile("afplay", ["/System/Library/Sounds/Basso.aiff"], { timeout: 3000 }, () => {
          // Ignore sound playback errors in headless/CI contexts
        });
      }
      return;
    }

    if (process.platform === "win32") {
      const psTitle = escapePowerShellSingleQuoted(subtitle ? `${title} - ${subtitle}` : title);
      const psMsg = escapePowerShellSingleQuoted(message);
      const iconKind = urgent ? "Warning" : "Info";
      const playSound = urgent ? "[System.Media.SystemSounds]::Exclamation.Play();" : "";
      const psScript =
        "Add-Type -AssemblyName System.Windows.Forms;" +
        "Add-Type -AssemblyName System.Drawing;" +
        playSound +
        "$n = New-Object System.Windows.Forms.NotifyIcon;" +
        `$n.Icon = [System.Drawing.SystemIcons]::${iconKind};` +
        "$n.Visible = $true;" +
        `$n.ShowBalloonTip(6000, '${psTitle}', '${psMsg}', [System.Windows.Forms.ToolTipIcon]::${iconKind});` +
        "Start-Sleep -Milliseconds 6500;" +
        "$n.Dispose();";

      execFile(
        "powershell.exe",
        ["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", psScript],
        { timeout: 10_000, windowsHide: true },
        () => {
          // Ignore notification errors in headless/CI contexts
        }
      );
    }
  }
}

export const SystemNotifier = MacNotifier;
