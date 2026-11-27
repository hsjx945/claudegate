using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Media;
using System.Net;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;

namespace ClaudeGateTray
{
    internal sealed class EngineManager
    {
        private Process _process;
        private bool _ownsProcess;
        private readonly object _lock = new object();
        private readonly string _baseUrl = "http://127.0.0.1:17891";

        public string BaseUrl { get { return _baseUrl; } }

        private string GetBaseDir()
        {
            return AppDomain.CurrentDomain.BaseDirectory;
        }

        private string ResolveNodeExecutable()
        {
            string bundled = Path.Combine(GetBaseDir(), "runtime", "node.exe");
            if (File.Exists(bundled)) return bundled;

            string pathEnv = Environment.GetEnvironmentVariable("PATH") ?? "";
            foreach (string dir in pathEnv.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries))
            {
                try
                {
                    string candidate = Path.Combine(dir.Trim(), "node.exe");
                    if (File.Exists(candidate)) return candidate;
                }
                catch { }
            }
            return null;
        }

        private string ResolveEntrypoint()
        {
            string entry = Path.Combine(GetBaseDir(), "engine", "dist", "src", "index.js");
            return File.Exists(entry) ? entry : null;
        }

        private bool IsEngineRunning()
        {
            try
            {
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(_baseUrl + "/api/status");
                req.Method = "GET";
                req.Timeout = 800;
                using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
                {
                    return resp.StatusCode == HttpStatusCode.OK;
                }
            }
            catch
            {
                return false;
            }
        }

        public void StartIfNeeded()
        {
            lock (_lock)
            {
                if (_process != null && !_process.HasExited) return;
                if (IsEngineRunning())
                {
                    _ownsProcess = false;
                    return;
                }

                string nodeBin = ResolveNodeExecutable();
                string entry = ResolveEntrypoint();
                if (string.IsNullOrEmpty(nodeBin) || string.IsNullOrEmpty(entry)) return;

                string dataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".claudeban");
                Directory.CreateDirectory(dataDir);
                string logPath = Path.Combine(dataDir, "engine.log");

                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = nodeBin;
                psi.Arguments = "\"" + entry + "\" start";
                psi.WorkingDirectory = Path.GetDirectoryName(Path.GetDirectoryName(Path.GetDirectoryName(entry)));
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                psi.EnvironmentVariables["CLAUDEGATE_APP_EXEC"] = Application.ExecutablePath;

                Process proc = new Process();
                proc.StartInfo = psi;
                proc.EnableRaisingEvents = true;

                StreamWriter writer = new StreamWriter(new FileStream(logPath, FileMode.Append, FileAccess.Write, FileShare.ReadWrite), Encoding.UTF8);
                writer.AutoFlush = true;

                proc.OutputDataReceived += delegate(object s, DataReceivedEventArgs e)
                {
                    if (e.Data != null)
                    {
                        try { writer.WriteLine(e.Data); } catch { }
                    }
                };
                proc.ErrorDataReceived += delegate(object s, DataReceivedEventArgs e)
                {
                    if (e.Data != null)
                    {
                        try { writer.WriteLine(e.Data); } catch { }
                    }
                };
                proc.Exited += delegate
                {
                    lock (_lock) { _ownsProcess = false; }
                    try { writer.Dispose(); } catch { }
                };

                proc.Start();
                proc.BeginOutputReadLine();
                proc.BeginErrorReadLine();
                _process = proc;
                _ownsProcess = true;
            }
        }

        public void StopIfOwned()
        {
            Process p = null;
            bool owned = false;
            lock (_lock)
            {
                p = _process;
                owned = _ownsProcess;
                _process = null;
                _ownsProcess = false;
            }
            if (!owned || p == null) return;
            try
            {
                if (!p.HasExited)
                {
                    p.Kill();
                    p.WaitForExit(1500);
                }
            }
            catch { }
        }
    }

    internal sealed class TrayApplicationContext : ApplicationContext
    {
        private readonly EngineManager _engine = new EngineManager();
        private readonly NotifyIcon _trayIcon;
        private readonly ContextMenuStrip _menu;
        private readonly System.Windows.Forms.Timer _pollTimer;
        private readonly JavaScriptSerializer _json = new JavaScriptSerializer();

        private readonly ToolStripMenuItem _itemHealth;
        private readonly ToolStripMenuItem _itemClash;
        private readonly ToolStripMenuItem _itemExitIp;
        private readonly ToolStripMenuItem _itemNode;
        private readonly ToolStripMenuItem _itemTraffic;
        private readonly ToolStripMenuItem _itemSysProxyInfo;

        private readonly ToolStripMenuItem _itemOpenDashboard;
        private readonly ToolStripMenuItem _itemAutoFix;
        private readonly ToolStripMenuItem _itemToggleProxy;
        private readonly ToolStripMenuItem _itemProbeIp;
        private readonly ToolStripMenuItem _itemLaunchAtLogin;
        private readonly ToolStripMenuItem _itemQuit;

        private readonly Icon _iconSafe;
        private readonly Icon _iconWarn;
        private readonly Icon _iconDanger;

        private string _lastHealth = "";
        private bool _pointingToGate = false;
        private bool _launchAtLogin = false;

        public TrayApplicationContext()
        {
            _iconSafe = CreateShieldIcon(Color.FromArgb(16, 185, 129));
            _iconWarn = CreateShieldIcon(Color.FromArgb(245, 158, 11));
            _iconDanger = CreateShieldIcon(Color.FromArgb(239, 68, 68));

            _menu = new ContextMenuStrip();

            _itemHealth = MakeInfoItem("正在启动门禁引擎...");
            _itemClash = MakeInfoItem("Clash Verge: 连接中...");
            _itemExitIp = MakeInfoItem("出口 IP: 探测中...");
            _itemNode = MakeInfoItem("主节点: -");
            _itemTraffic = MakeInfoItem("24h 流量: -");
            _itemSysProxyInfo = MakeInfoItem("系统代理: 检测中...");

            _itemOpenDashboard = new ToolStripMenuItem("打开 ClaudeGate 控制台...", null, OnOpenDashboard);
            _itemOpenDashboard.Font = new Font(_itemOpenDashboard.Font, FontStyle.Bold);
            _itemAutoFix = new ToolStripMenuItem("⚡ 一键修复全部安全隐患", null, OnAutoFix);
            _itemToggleProxy = new ToolStripMenuItem("🔌 系统代理接管 (17890)", null, OnToggleProxy);
            _itemProbeIp = new ToolStripMenuItem("🔄 重新检测出口 IP", null, OnProbeIp);
            _itemLaunchAtLogin = new ToolStripMenuItem("🚀 开机自动启动", null, OnToggleLaunchAtLogin);
            _itemQuit = new ToolStripMenuItem("退出 ClaudeGate", null, OnQuit);

            _menu.Items.Add(_itemHealth);
            _menu.Items.Add(_itemClash);
            _menu.Items.Add(_itemExitIp);
            _menu.Items.Add(_itemNode);
            _menu.Items.Add(_itemTraffic);
            _menu.Items.Add(_itemSysProxyInfo);
            _menu.Items.Add(new ToolStripSeparator());
            _menu.Items.Add(_itemOpenDashboard);
            _menu.Items.Add(_itemAutoFix);
            _menu.Items.Add(_itemToggleProxy);
            _menu.Items.Add(_itemProbeIp);
            _menu.Items.Add(new ToolStripSeparator());
            _menu.Items.Add(_itemLaunchAtLogin);
            _menu.Items.Add(_itemQuit);

            _trayIcon = new NotifyIcon();
            _trayIcon.Icon = _iconWarn;
            _trayIcon.Text = "ClaudeGate · 启动中...";
            _trayIcon.ContextMenuStrip = _menu;
            _trayIcon.Visible = true;
            _trayIcon.DoubleClick += OnOpenDashboard;

            Thread starter = new Thread(delegate() { _engine.StartIfNeeded(); });
            starter.IsBackground = true;
            starter.Start();

            _pollTimer = new System.Windows.Forms.Timer();
            _pollTimer.Interval = 2500;
            _pollTimer.Tick += delegate { RefreshStatusAsync(); };
            _pollTimer.Start();

            RefreshStatusAsync();
        }

        private static ToolStripMenuItem MakeInfoItem(string text)
        {
            ToolStripMenuItem item = new ToolStripMenuItem(text);
            item.Enabled = false;
            return item;
        }

        private static Icon CreateShieldIcon(Color dotColor)
        {
            using (Bitmap bmp = new Bitmap(32, 32))
            using (Graphics g = Graphics.FromImage(bmp))
            {
                g.SmoothingMode = SmoothingMode.AntiAlias;
                g.Clear(Color.Transparent);

                using (GraphicsPath path = new GraphicsPath())
                {
                    Point[] pts = new Point[]
                    {
                        new Point(16, 2),
                        new Point(28, 7),
                        new Point(27, 17),
                        new Point(16, 29),
                        new Point(5, 17),
                        new Point(4, 7)
                    };
                    path.AddPolygon(pts);
                    using (LinearGradientBrush fill = new LinearGradientBrush(
                        new Rectangle(4, 2, 24, 27),
                        Color.FromArgb(30, 41, 59),
                        Color.FromArgb(15, 23, 42),
                        90f))
                    {
                        g.FillPath(fill, path);
                    }
                    using (Pen border = new Pen(Color.FromArgb(148, 163, 184), 1.6f))
                    {
                        g.DrawPath(border, path);
                    }
                }

                using (SolidBrush dotBrush = new SolidBrush(dotColor))
                {
                    g.FillEllipse(dotBrush, 10, 10, 12, 12);
                }
                using (Pen ring = new Pen(Color.White, 1.4f))
                {
                    g.DrawEllipse(ring, 10, 10, 12, 12);
                }

                return Icon.FromHandle(bmp.GetHicon());
            }
        }

        private void RefreshStatusAsync()
        {
            ThreadPool.QueueUserWorkItem(delegate
            {
                try
                {
                    string statusRaw = HttpGet(_engine.BaseUrl + "/api/status");
                    string cfgRaw = HttpGet(_engine.BaseUrl + "/api/config");
                    Dictionary<string, object> status = _json.Deserialize<Dictionary<string, object>>(statusRaw);
                    Dictionary<string, object> cfg = _json.Deserialize<Dictionary<string, object>>(cfgRaw);

                    string health = GetStr(status, "health", "warn");
                    Dictionary<string, object> clash = GetMap(status, "clash");
                    Dictionary<string, object> exitIp = GetMap(status, "exitIp");
                    Dictionary<string, object> currentIp = GetMap(exitIp, "current");
                    Dictionary<string, object> sysProxy = GetMap(status, "systemProxy");
                    Dictionary<string, object> gate = GetMap(status, "gate");
                    Dictionary<string, object> traffic24h = GetMap(status, "traffic24h");

                    bool connected = GetBool(clash, "connected");
                    string mode = GetStr(clash, "mode", "unknown").ToUpperInvariant();
                    bool tun = GetBool(clash, "tunEnabled");
                    string version = GetStr(clash, "version", "-");
                    string node = GetStr(clash, "primaryLeafNode", "-");

                    string cc = currentIp != null ? GetStr(currentIp, "countryCode", "?") : "?";
                    string ipStr = currentIp != null ? GetStr(currentIp, "ip", "探测中...") : "探测中...";
                    string isp = currentIp != null ? GetStr(currentIp, "isp", "") : "";

                    long claudeTotal = GetLong(traffic24h, "claudeUpBytes") + GetLong(traffic24h, "claudeDownBytes");
                    long allTotal = GetLong(traffic24h, "totalUpBytes") + GetLong(traffic24h, "totalDownBytes");
                    long blockedTotal = GetLong(gate, "dbBlockedTotal");

                    bool toGate = GetBool(sysProxy, "pointingToGate");
                    bool toUpstream = GetBool(sysProxy, "pointingToUpstream");
                    bool launch = GetBool(cfg, "launchAtLogin");

                    RunOnUiThread(delegate
                    {
                        _pointingToGate = toGate;
                        _launchAtLogin = launch;
                        _itemLaunchAtLogin.Checked = launch;
                        _itemToggleProxy.Checked = toGate;
                        _itemToggleProxy.Text = toGate
                            ? "✅ 系统代理已接入 ClaudeGate (点击恢复)"
                            : "🔌 系统代理接管 (127.0.0.1:17890)";

                        if (health == "danger")
                        {
                            _trayIcon.Icon = _iconDanger;
                            _itemHealth.Text = "🚨 危险：检测到直连或受限出口！";
                        }
                        else if (health == "warn")
                        {
                            _trayIcon.Icon = _iconWarn;
                            _itemHealth.Text = "⚠️ 警告：存在代理规则或未接入隐患";
                        }
                        else
                        {
                            _trayIcon.Icon = _iconSafe;
                            _itemHealth.Text = "● 门禁安全 · 代理链路合规";
                        }

                        _itemClash.Text = connected
                            ? string.Format("Clash Verge: {0} 模式 · TUN {1} · {2}", mode, tun ? "开" : "关", version)
                            : "Clash Verge: 未连接";
                        _itemExitIp.Text = string.Format("出口 IP: {0} · {1}{2}", cc, ipStr, string.IsNullOrEmpty(isp) ? "" : " · " + isp);
                        _itemNode.Text = string.Format("主节点: {0} (累计拦截 {1} 次)", node, blockedTotal);
                        _itemTraffic.Text = string.Format("24h 流量: Claude {0} / 全网 {1}", FormatBytes(claudeTotal), FormatBytes(allTotal));
                        _itemSysProxyInfo.Text = toGate
                            ? "系统代理: 已接管 (17890)"
                            : (toUpstream ? "系统代理: 直连 Clash (7897)" : (tun ? "系统代理: 未接管 (仅 TUN)" : "⚠️ 系统代理与 TUN 均未开启"));

                        string tip = string.Format("ClaudeGate [{0}] {1} · {2}", cc, mode, health.ToUpperInvariant());
                        _trayIcon.Text = tip.Length > 63 ? tip.Substring(0, 63) : tip;

                        if (_lastHealth != "danger" && health == "danger")
                        {
                            try { SystemSounds.Exclamation.Play(); } catch { }
                            _trayIcon.ShowBalloonTip(5000, "ClaudeGate 高危告警", "检测到直连或受限地区出口，访问已被阻断！", ToolTipIcon.Error);
                        }
                        _lastHealth = health;
                    });
                }
                catch
                {
                    RunOnUiThread(delegate
                    {
                        _trayIcon.Icon = _iconWarn;
                        _trayIcon.Text = "ClaudeGate · 引擎连接中...";
                        _itemHealth.Text = "正在等待本地引擎响应...";
                    });
                }
            });
        }

        private void RunOnUiThread(MethodInvoker action)
        {
            if (_menu != null && !_menu.IsDisposed)
            {
                try
                {
                    if (_menu.IsHandleCreated)
                    {
                        _menu.BeginInvoke(action);
                        return;
                    }
                }
                catch { }
            }
            try { action(); } catch { }
        }

        private void OnOpenDashboard(object sender, EventArgs e)
        {
            _engine.StartIfNeeded();
            string url = _engine.BaseUrl;
            try
            {
                string[] browsers = new string[]
                {
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), @"Microsoft\Edge\Application\msedge.exe"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Microsoft\Edge\Application\msedge.exe"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Google\Chrome\Application\chrome.exe"),
                    Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Google\Chrome\Application\chrome.exe")
                };
                foreach (string b in browsers)
                {
                    if (File.Exists(b))
                    {
                        Process.Start(b, "--app=" + url + " --window-size=1220,820");
                        return;
                    }
                }
            }
            catch { }

            try { Process.Start(new ProcessStartInfo(url) { UseShellExecute = true }); } catch { }
        }

        private void OnAutoFix(object sender, EventArgs e)
        {
            ThreadPool.QueueUserWorkItem(delegate
            {
                try
                {
                    HttpPost(_engine.BaseUrl + "/api/actions/auto-fix", "{}");
                    RefreshStatusAsync();
                    RunOnUiThread(delegate
                    {
                        _trayIcon.ShowBalloonTip(4000, "ClaudeGate 一键修复完成", "已检查并修复代理模式、节点与显式规则。", ToolTipIcon.Info);
                    });
                }
                catch { }
            });
        }

        private void OnToggleProxy(object sender, EventArgs e)
        {
            bool enable = !_pointingToGate;
            ThreadPool.QueueUserWorkItem(delegate
            {
                try
                {
                    HttpPost(_engine.BaseUrl + "/api/actions/proxy", enable ? "{\"enable\":true}" : "{\"enable\":false}");
                    RefreshStatusAsync();
                }
                catch { }
            });
        }

        private void OnProbeIp(object sender, EventArgs e)
        {
            ThreadPool.QueueUserWorkItem(delegate
            {
                try
                {
                    HttpPost(_engine.BaseUrl + "/api/actions/probe-ip", "{}");
                    RefreshStatusAsync();
                }
                catch { }
            });
        }

        private void OnToggleLaunchAtLogin(object sender, EventArgs e)
        {
            bool next = !_launchAtLogin;
            ThreadPool.QueueUserWorkItem(delegate
            {
                try
                {
                    HttpPut(_engine.BaseUrl + "/api/config", next ? "{\"launchAtLogin\":true}" : "{\"launchAtLogin\":false}");
                    RefreshStatusAsync();
                }
                catch { }
            });
        }

        private void OnQuit(object sender, EventArgs e)
        {
            _pollTimer.Stop();
            _trayIcon.Visible = false;
            _engine.StopIfOwned();
            ExitThread();
        }

        private static string HttpGet(string url)
        {
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
            req.Method = "GET";
            req.Timeout = 1800;
            using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
            using (StreamReader reader = new StreamReader(resp.GetResponseStream(), Encoding.UTF8))
            {
                return reader.ReadToEnd();
            }
        }

        private static string HttpPost(string url, string jsonBody)
        {
            return HttpSend("POST", url, jsonBody);
        }

        private static string HttpPut(string url, string jsonBody)
        {
            return HttpSend("PUT", url, jsonBody);
        }

        private static string HttpSend(string method, string url, string jsonBody)
        {
            byte[] data = Encoding.UTF8.GetBytes(jsonBody);
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
            req.Method = method;
            req.ContentType = "application/json";
            req.ContentLength = data.Length;
            req.Timeout = 8000;
            using (Stream reqStream = req.GetRequestStream())
            {
                reqStream.Write(data, 0, data.Length);
            }
            using (HttpWebResponse resp = (HttpWebResponse)req.GetResponse())
            using (StreamReader reader = new StreamReader(resp.GetResponseStream(), Encoding.UTF8))
            {
                return reader.ReadToEnd();
            }
        }

        private static Dictionary<string, object> GetMap(Dictionary<string, object> dict, string key)
        {
            object val;
            if (dict != null && dict.TryGetValue(key, out val))
            {
                return val as Dictionary<string, object>;
            }
            return null;
        }

        private static string GetStr(Dictionary<string, object> dict, string key, string fallback)
        {
            object val;
            if (dict != null && dict.TryGetValue(key, out val) && val != null)
            {
                return val.ToString();
            }
            return fallback;
        }

        private static bool GetBool(Dictionary<string, object> dict, string key)
        {
            object val;
            if (dict != null && dict.TryGetValue(key, out val) && val is bool)
            {
                return (bool)val;
            }
            return false;
        }

        private static long GetLong(Dictionary<string, object> dict, string key)
        {
            object val;
            if (dict != null && dict.TryGetValue(key, out val) && val != null)
            {
                long parsed;
                if (long.TryParse(val.ToString(), out parsed)) return parsed;
            }
            return 0;
        }

        private static string FormatBytes(long bytes)
        {
            if (bytes < 1024) return bytes + " B";
            if (bytes < 1024 * 1024) return (bytes / 1024.0).ToString("F1") + " KB";
            if (bytes < 1024L * 1024 * 1024) return (bytes / (1024.0 * 1024.0)).ToString("F2") + " MB";
            return (bytes / (1024.0 * 1024.0 * 1024.0)).ToString("F2") + " GB";
        }
    }

    internal static class Program
    {
        [STAThread]
        private static void Main()
        {
            bool createdNew;
            using (Mutex mutex = new Mutex(true, "Local\\ClaudeGateTraySingleton", out createdNew))
            {
                if (!createdNew)
                {
                    try
                    {
                        Process.Start(new ProcessStartInfo("http://127.0.0.1:17891") { UseShellExecute = true });
                    }
                    catch { }
                    return;
                }
                Application.EnableVisualStyles();
                Application.SetCompatibleTextRenderingDefault(false);
                Application.Run(new TrayApplicationContext());
            }
        }
    }
}
