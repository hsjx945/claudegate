let currentRange = "24h";
let currentRank = "domains";
let cachedStats = null;
let cachedAudit = null;
let cachedConfig = null;
let lastStatus = null;
let lastDetectorReport = null;
let maskIps = localStorage.getItem("cg_mask_ip") === "1";

function applyTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  localStorage.setItem("cg_theme", theme);
  const btn = document.getElementById("btn-theme-toggle");
  if (btn) btn.textContent = theme === "dark" ? "🌙" : "☀️";
}
applyTheme(localStorage.getItem("cg_theme") || "light");

function updateMaskButton() {
  const btn = document.getElementById("btn-mask-ip");
  if (btn) {
    btn.textContent = maskIps ? "🙈" : "👁️";
    btn.title = maskIps ? "当前已脱敏 IP（点击显示完整 IP）" : "当前显示完整 IP（点击脱敏隐藏）";
  }
}
updateMaskButton();

function maskIp(ip) {
  if (!ip) return "—";
  if (!maskIps) return ip;
  if (ip.includes(":")) {
    const parts = ip.split(":");
    return `${parts.slice(0, 2).join(":")}:****:${parts[parts.length - 1] || ""}`;
  }
  const parts = ip.split(".");
  if (parts.length === 4) return `${parts[0]}.${parts[1]}.*.*`;
  return ip;
}

function esc(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function fmtBytes(bytes) {
  const b = Number(bytes || 0);
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  if (b < 1024 * 1024 * 1024) return `${(b / 1024 / 1024).toFixed(2)} MB`;
  return `${(b / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function fmtTime(iso) {
  if (!iso) return "-";
  return new Date(iso).toLocaleString("zh-CN", { hour12: false });
}

async function copyText(text) {
  if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.copyText) {
    window.webkit.messageHandlers.copyText.postMessage(text);
    return;
  }
  await navigator.clipboard.writeText(text);
}

async function api(url, opts) {
  const res = await fetch(url, opts);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

function switchTab(tabName) {
  document.querySelectorAll(".nav-pill").forEach((b) => {
    b.classList.toggle("active", b.dataset.tab === tabName);
  });
  document.querySelectorAll(".tab-panel").forEach((p) => {
    p.classList.toggle("active", p.id === `tab-${tabName}`);
  });
}

document.querySelectorAll(".nav-pill").forEach((btn) => {
  btn.addEventListener("click", () => switchTab(btn.dataset.tab));
});
document.getElementById("btn-goto-detector").addEventListener("click", () => {
  switchTab("detector");
  runFullNetworkDetector();
});

function renderStatus(data) {
  lastStatus = data;
  const c = data.clash;
  const ip = data.exitIp?.current;
  const det = data.detectorSummary;

  document.getElementById("chip-clash-mode").textContent = c.connected
    ? `Clash: ${String(c.mode).toUpperCase()} · ${c.version}`
    : "Clash: 未连接";
  document.getElementById("chip-tun-status").textContent = c.connected
    ? `TUN: ${c.tunEnabled ? "开启" : "关闭"}`
    : "TUN: -";
  document.getElementById("chip-sys-proxy").textContent = data.systemProxy?.pointingToGate
    ? "系统代理: 已接管 (17890)"
    : "系统代理: 未接管 (仅 TUN)";

  // Sync system proxy checkbox in Settings
  const sysProxyToggle = document.getElementById("cfg-sys-proxy");
  if (sysProxyToggle) {
    sysProxyToggle.checked = Boolean(data.systemProxy?.pointingToGate);
  }

  // KPI 1: Health
  const hBadge = document.getElementById("kpi-health-badge");
  const hVal = document.getElementById("kpi-health-val");
  const hSub = document.getElementById("kpi-health-sub");
  const hBar = document.getElementById("kpi-health-bar");
  if (data.health === "safe") {
    hBadge.className = "status-pill safe";
    hBadge.textContent = "安全";
    hVal.textContent = det ? `${det.totalScore}% · ${det.grade}级` : "100% 安全";
    hSub.textContent = "直连阻断与分流规则正常";
    if (hBar) {
      hBar.className = "progress-fill green";
      hBar.style.width = `${det ? Math.max(8, Math.min(100, det.totalScore)) : 100}%`;
    }
  } else if (data.health === "warn") {
    hBadge.className = "status-pill warn";
    hBadge.textContent = "有隐患";
    hVal.textContent = `${(data.activeAlerts || []).length} 项预警`;
    hSub.textContent = "建议执行一键修复补全防护";
    if (hBar) {
      hBar.className = "progress-fill warn";
      hBar.style.width = `${det ? Math.max(12, Math.min(100, det.totalScore)) : 68}%`;
    }
  } else {
    hBadge.className = "status-pill danger";
    hBadge.textContent = "高危拦截";
    hVal.textContent = "已阻断";
    hSub.textContent = "检测到直连或受限地区出口！";
    if (hBar) {
      hBar.className = "progress-fill danger";
      hBar.style.width = `${det ? Math.max(10, Math.min(100, det.totalScore)) : 22}%`;
    }
  }
  document.getElementById("kpi-health-foot").textContent = `规则 ${c.rulesCount || 0} 条 · 零解密透传`;

  // KPI 2: Exit IP & Purity
  document.getElementById("kpi-exit-ip").textContent = ip
    ? `${ip.countryCode} · ${maskIp(ip.ip)}`
    : "探测中...";
  document.getElementById("kpi-exit-sub").textContent = `主节点: ${c.primaryLeafNode || "-"}`;
  document.getElementById("kpi-exit-isp").textContent = ip?.isp || "-";

  const purityBadge = document.getElementById("kpi-purity-badge");
  if (det) {
    if (det.proxy) {
      purityBadge.className = "status-pill danger";
      purityBadge.textContent = "代理标记";
    } else if (det.hosting) {
      purityBadge.className = "status-pill warn";
      purityBadge.textContent = "机房 IP";
    } else {
      purityBadge.className = "status-pill safe";
      purityBadge.textContent = "住宅/原生";
    }
  } else {
    purityBadge.className = "status-pill neutral";
    purityBadge.textContent = "待体检";
  }

  // KPI 3: Endpoints
  const epBadge = document.getElementById("kpi-ep-badge");
  const epList = document.getElementById("ov-endpoints-list");
  if (det && det.endpoints) {
    const allOk = det.endpoints.every((e) => e.reachable);
    epBadge.className = `status-pill ${allOk ? "safe" : "danger"}`;
    epBadge.textContent = allOk ? "全部可达" : "部分异常";
    epList.innerHTML = det.endpoints
      .map(
        (e) => `<div class="ep-mini-row">
        <span class="mono">${esc(e.host)}</span>
        <span class="status-pill ${e.reachable ? "safe" : "danger"}">${
          e.reachable ? `${e.statusCode} · ${e.latencyMs}ms` : e.error || "不可达"
        }</span>
      </div>`
      )
      .join("");
  }

  // KPI 4: Gate requests & blocked count
  const gs = data.gate.stats;
  document.getElementById("kpi-gate-reqs").textContent = `门禁已检 ${gs.totalRequests} 次 · 拦截 ${data.gate.dbBlockedTotal} 次`;

  // Bottom Left Card
  document.getElementById("ov-gate-addr").textContent = data.gate.proxyAddress;
  document.getElementById("ov-proxy-tag").textContent = data.gate.proxyAddress;
  document.getElementById("ov-upstream-addr").textContent = data.gate.upstreamAddress;
  document.getElementById("ov-primary-chain").textContent = (c.primaryChain || []).join(" → ") || "-";
  document.getElementById("ov-proxy-dot").className = `dot-status ${data.systemProxy?.pointingToGate ? "" : "warn"}`;

  const proxyBtn = document.getElementById("btn-toggle-proxy");
  proxyBtn.textContent = data.systemProxy?.pointingToGate
    ? `✅ 系统代理已接管（点击恢复 ${data.gate.upstreamAddress}）`
    : `🔌 将系统代理接入 ClaudeGate (${data.gate.proxyAddress})`;

  document.getElementById("cli-snippet").textContent =
    `export HTTP_PROXY=http://${data.gate.proxyAddress} HTTPS_PROXY=http://${data.gate.proxyAddress} ALL_PROXY=socks5://${data.gate.proxyAddress} NO_PROXY=localhost,127.0.0.1,::1`;

  // Bottom Right Card
  const fixPill = document.getElementById("ov-fix-status-pill");
  const alertsEl = document.getElementById("ov-alerts-list");
  const alerts = data.activeAlerts || [];
  if (alerts.length === 0) {
    fixPill.className = "status-pill safe";
    fixPill.textContent = "全部安全";
    alertsEl.innerHTML = `<div class="ov-alert-ok">✅ 当前 Clash 规则、出口地区与 Claude 关联域名均配置正常。</div>`;
  } else {
    fixPill.className = `status-pill ${data.health === "danger" ? "danger" : "warn"}`;
    fixPill.textContent = `${alerts.length} 项待处理`;
    alertsEl.innerHTML = alerts
      .map(
        (a) => `<div class="ov-alert-item ${esc(a.level)}">
          <strong>${esc(a.title)}</strong>
          <div class="muted-sm" style="color:inherit;opacity:0.9">${esc(a.detail)}</div>
        </div>`
      )
      .join("");
  }
}

async function runWebRtcProbe() {
  const pill = document.getElementById("det-webrtc-pill");
  const kv = document.getElementById("det-webrtc-kv");
  if (typeof RTCPeerConnection === "undefined") {
    pill.className = "status-pill neutral";
    pill.textContent = "环境不支持";
    kv.innerHTML = `<div class="kv-item"><span class="kv-k">WebRTC 状态</span><span class="kv-v">当前 WebView 禁用了 RTCPeerConnection</span></div>`;
    return null;
  }

  pill.className = "status-pill neutral";
  pill.textContent = "探测中...";

  return new Promise((resolve) => {
    const publicIps = new Set();
    const localIps = new Set();
    let finished = false;
    let pc;

    const finish = () => {
      if (finished) return;
      finished = true;
      try { pc?.close(); } catch {}
      const pubs = Array.from(publicIps);
      const locs = Array.from(localIps);
      const directIp = lastDetectorReport?.directDomestic?.ip;
      const proxyIp = lastDetectorReport?.proxyPurity?.ip;
      const leakedReal = pubs.some((ip) => (directIp && ip === directIp) || (proxyIp && ip !== proxyIp));

      if (pubs.length === 0) {
        pill.className = "status-pill safe";
        pill.textContent = "无公网 UDP 泄露";
      } else if (leakedReal) {
        pill.className = "status-pill danger";
        pill.textContent = "存在 UDP IP 泄露";
      } else {
        pill.className = "status-pill safe";
        pill.textContent = "与代理出口一致";
      }

      kv.innerHTML = `
        <div class="kv-item"><span class="kv-k">UDP 探测结果</span><span class="kv-v">${
          pubs.length === 0 ? "未捕获到公网 UDP 候选地址（安全）" : leakedReal ? "🚨 捕获到真实公网 IP" : "与当前代理一致"
        }</span></div>
        <div class="kv-item"><span class="kv-k">公网候选 IP</span><span class="kv-v mono">${pubs.length ? pubs.map(maskIp).join(", ") : "无"}</span></div>
        <div class="kv-item"><span class="kv-k">本地 / mDNS 候选</span><span class="kv-v mono">${locs.length ? locs.join(", ") : "无"}</span></div>
      `;
      resolve({ publicIps: pubs, localIps: locs, leakedReal });
    };

    try {
      pc = new RTCPeerConnection({
        iceServers: [{ urls: "stun:stun.cloudflare.com:3478" }, { urls: "stun:stun.l.google.com:19302" }],
      });
      pc.createDataChannel("cg");
      pc.onicecandidate = (ev) => {
        if (!ev.candidate) {
          finish();
          return;
        }
        const cand = ev.candidate.candidate || "";
        const fields = cand.trim().split(/\s+/);
        const addr = fields.length >= 6 ? fields[4] : "";
        if (!addr) return;
        if (
          addr.endsWith(".local") ||
          addr.startsWith("10.") ||
          addr.startsWith("192.168.") ||
          /^172\.(1[6-9]|2\d|3[01])\./.test(addr) ||
          addr.startsWith("127.") ||
          addr.startsWith("fe80:")
        ) {
          localIps.add(addr);
        } else {
          publicIps.add(addr);
        }
      };
      pc.createOffer().then((offer) => pc.setLocalDescription(offer)).catch(() => finish());
      setTimeout(finish, 3000);
    } catch {
      finish();
    }
  });
}

function renderDetectorReport(report) {
  if (!report) return;
  lastDetectorReport = report;

  document.getElementById("det-hero-title").textContent = `综合评级 ${report.grade} 级 · ${report.totalScore} / 100 分`;
  document.getElementById("det-hero-sub").textContent =
    `检测完成于 ${fmtTime(report.checkedAt)}（耗时 ${(report.durationMs / 1000).toFixed(2)}s）· 共 ${report.findings.length} 条风控审计发现`;
  document.getElementById("det-score-text").textContent = `${report.totalScore} / 100`;

  document.querySelectorAll(".grade-scale .g-pill").forEach((el) => {
    el.className = "g-pill";
    if (el.dataset.g === report.grade) el.classList.add(`active-${report.grade}`);
  });

  document.getElementById("det-dim-pills").innerHTML = report.dimensions
    .map(
      (d) => `<div class="dim-pill">
        <span>${esc(d.label)} (${d.score}/${d.maxScore})</span>
        <strong style="color:var(--${d.status === "safe" ? "green" : d.status === "warn" ? "yellow" : "red"})">${esc(d.summary)}</strong>
      </div>`
    )
    .join("");

  document.getElementById("btn-det-autofix").classList.toggle("hidden", !report.hasFixableIssues);

  const dd = report.directDomestic;
  document.getElementById("det-direct-ip").textContent = dd.ok ? maskIp(dd.ip) : "不可达";
  document.getElementById("det-direct-loc").textContent = dd.ok ? dd.location || "国内直连" : dd.error || "探测失败";

  const pp = report.proxyPurity;
  document.getElementById("det-proxy-ip").textContent = pp.ok ? maskIp(pp.ip) : "失败";
  document.getElementById("det-proxy-loc").textContent = pp.ok ? `${pp.countryCode} · ${pp.country} ${pp.city || ""}` : pp.error || "探测失败";

  const st = report.stability;
  document.getElementById("det-stability-val").textContent = st.ok
    ? st.stable ? "✅ 出口稳定一致" : `⚠️ 存在漂移 (${st.uniqueIps.length} 个 IP)`
    : "探测失败";
  document.getElementById("det-stability-sub").textContent = st.ok
    ? `${st.samples} 次采样: ${st.uniqueIps.map(maskIp).join(", ")}`
    : st.error || "-";

  const pPill = document.getElementById("det-purity-pill");
  pPill.className = `status-pill ${pp.proxy ? "danger" : pp.hosting ? "warn" : pp.ok ? "safe" : "neutral"}`;
  pPill.textContent = pp.networkType === "residential" ? "住宅/原生" : pp.networkType === "datacenter" ? "机房 IP" : pp.networkType === "proxy" ? "代理标记" : pp.networkType === "mobile" ? "移动网络" : "未知";
  document.getElementById("det-purity-kv").innerHTML = `
    <div class="kv-item"><span class="kv-k">网络性质</span><span class="kv-v">${esc(pPill.textContent)}</span></div>
    <div class="kv-item"><span class="kv-k">ISP / 机构</span><span class="kv-v">${esc(pp.isp || pp.org || "-")}</span></div>
    <div class="kv-item"><span class="kv-k">ASN</span><span class="kv-v mono">${esc(pp.asn || "-")}</span></div>
    <div class="kv-item"><span class="kv-k">IPv6 泄露检查</span><span class="kv-v">${esc(report.ipv6Leak.detail)}</span></div>
    <div class="kv-item"><span class="kv-k">风险标签</span><span class="kv-v mono">机房:${pp.hosting} · Proxy:${pp.proxy} · Mobile:${pp.mobile}</span></div>
  `;

  const dns = report.dnsLeak;
  const dnsPill = document.getElementById("det-dns-pill");
  dnsPill.className = `status-pill ${dns.leakedToBanned ? "danger" : dns.ok ? "safe" : "warn"}`;
  dnsPill.textContent = dns.leakedToBanned ? "存在泄露" : dns.ok ? "无泄露" : "探测受限";
  document.getElementById("det-dns-kv").innerHTML = `
    <div class="kv-item"><span class="kv-k">DNS 解析出口 IP</span><span class="kv-v mono">${dns.ok ? maskIp(dns.dnsIp) : dns.error || "-"}</span></div>
    <div class="kv-item"><span class="kv-k">DNS 归属地</span><span class="kv-v">${esc(dns.dnsGeo || "-")}</span></div>
    <div class="kv-item"><span class="kv-k">EDNS 网段</span><span class="kv-v mono">${dns.ednsIp ? `${maskIp(dns.ednsIp)} (${esc(dns.ednsGeo || "")})` : "无 EDNS 泄露"}</span></div>
    <div class="kv-item"><span class="kv-k">Clash TUN DNS 劫持</span><span class="kv-v">${dns.tunDnsHijack ? "✅ 已开启 (any:53)" : "未开启"}</span></div>
  `;

  const env = report.envInfo;
  const envPill = document.getElementById("det-env-pill");
  envPill.className = `status-pill ${env.timezoneMatched === false ? "warn" : "safe"}`;
  envPill.textContent = env.timezoneMatched === false ? "时区存在差异" : "环境一致";
  document.getElementById("det-env-kv").innerHTML = `
    <div class="kv-item"><span class="kv-k">系统时区 vs 出口时区</span><span class="kv-v">${esc(env.systemTimezone)} vs ${esc(env.proxyTimezone || "未知")}</span></div>
    <div class="kv-item"><span class="kv-k">浏览器首选语言</span><span class="kv-v">${esc((navigator.languages || [navigator.language]).join(", "))}</span></div>
    <div class="kv-item"><span class="kv-k">Cloudflare Edge / TLS</span><span class="kv-v mono">${esc(pp.cfColo || "-")} · ${esc(pp.cfTls || "-")}</span></div>
    <div class="kv-item"><span class="kv-k">门禁系统代理接管</span><span class="kv-v">${env.systemProxyToGate ? "✅ 已接管 (17890)" : "⚠️ 未接管"}</span></div>
  `;

  document.getElementById("det-endpoints-grid").innerHTML = report.endpoints
    .map(
      (ep) => `<div class="ep-card">
        <div class="panel-head-row" style="margin-bottom:6px">
          <span class="ep-host">${esc(ep.host)}</span>
          <span class="status-pill ${ep.reachable ? "safe" : "danger"}">${
            ep.reachable ? `HTTP ${ep.statusCode} · ${ep.latencyMs}ms` : ep.error || "不可达"
          }</span>
        </div>
        <div class="ep-role">${esc(ep.role)} · 节点: ${esc(ep.leafNode)}</div>
        <div class="muted-sm mono" style="margin-top:4px">${esc(ep.matchedRule)}</div>
      </div>`
    )
    .join("");

  const fBox = document.getElementById("det-findings-list");
  if (report.findings.length === 0) {
    fBox.innerHTML = `<div class="finding-item safe"><div><strong>✅ 全部检查通过</strong><div class="muted-sm">当前出口地区、DNS、IPv6 与分流规则均符合 Claude 防封要求。</div></div></div>`;
  } else {
    fBox.innerHTML = report.findings
      .map(
        (f) => `<div class="finding-item ${esc(f.severity)}">
          <div>
            <strong>${f.severity === "danger" ? "🚨" : "⚠️"} ${esc(f.title)}</strong>
            <div class="muted-sm" style="color:var(--text);opacity:0.85">${esc(f.detail)}</div>
            <div class="muted-sm">建议: ${esc(f.fixHint)}</div>
          </div>
          ${f.fixable ? '<span class="status-pill safe">支持一键修复</span>' : '<span class="status-pill neutral">需手动调整</span>'}
        </div>`
      )
      .join("");
  }
}

async function runFullNetworkDetector() {
  const btn = document.getElementById("btn-run-detector");
  btn.disabled = true;
  btn.textContent = "⏳ 正在执行 7 项深度探针...";
  try {
    const [res] = await Promise.all([
      api("/api/detector/run", { method: "POST" }),
      runWebRtcProbe(),
    ]);
    renderDetectorReport(res.report);
    await refreshAll();
  } catch (err) {
    alert(`网络体检失败: ${err.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = "🔍 开始深度检测 →";
  }
}

function renderChart(series) {
  const box = document.getElementById("chart-container");
  if (!series || series.length === 0) {
    box.innerHTML = `<div class="muted" style="text-align:center;padding:42px 0;">暂无历史流量数据（连接活动后每 10 秒自动聚合入库）</div>`;
    return;
  }
  const maxVal = Math.max(1, ...series.map((s) => Number(s.upBytes || 0) + Number(s.downBytes || 0)));
  const w = 960;
  const h = 135;
  const padL = 10;
  const padR = 10;
  const padB = 22;
  const barAreaH = h - padB - 10;
  const step = (w - padL - padR) / series.length;
  const barW = Math.max(4, Math.min(28, step * 0.65));

  const bars = series
    .map((s, idx) => {
      const total = Number(s.upBytes || 0) + Number(s.downBytes || 0);
      const claude = Number(s.claudeBytes || 0);
      const totalH = Math.max(2, (total / maxVal) * barAreaH);
      const claudeH = Math.max(0, (claude / maxVal) * barAreaH);
      const x = padL + idx * step + (step - barW) / 2;
      const y = h - padB - totalH;
      const cy = h - padB - claudeH;
      const label = s.hourBucket.slice(11, 16);
      const showLbl = series.length <= 16 || idx % Math.ceil(series.length / 12) === 0;
      return `
        <g>
          <title>${esc(s.hourBucket)} | 总流量 ${fmtBytes(total)} | Claude ${fmtBytes(claude)}</title>
          <rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${barW.toFixed(1)}" height="${totalH.toFixed(1)}" rx="2" fill="#94a3b8" />
          ${claudeH > 0 ? `<rect x="${x.toFixed(1)}" y="${cy.toFixed(1)}" width="${barW.toFixed(1)}" height="${claudeH.toFixed(1)}" rx="2" fill="#2563eb" />` : ""}
          ${showLbl ? `<text x="${(x + barW / 2).toFixed(1)}" y="${h - 5}" text-anchor="middle" fill="#64748b" font-size="10">${esc(label)}</text>` : ""}
        </g>`;
    })
    .join("");

  box.innerHTML = `
    <div style="display:flex;justify-content:space-between;font-size:12px;color:var(--muted);margin-bottom:6px;">
      <span>每小时流量分布（蓝色：Claude 生态 · 灰色：其他全网）</span>
      <span>峰值: ${fmtBytes(maxVal)}/h</span>
    </div>
    <svg viewBox="0 0 ${w} ${h}" style="width:100%;height:135px;display:block;">${bars}</svg>`;
}

function renderRanking() {
  if (!cachedStats) return;
  const thead = document.querySelector("#ranking-table thead");
  const tbody = document.querySelector("#ranking-table tbody");

  if (currentRank === "domains") {
    thead.innerHTML = `<tr><th>域名</th><th>上行</th><th>下行</th><th>总流量</th><th>连接数</th></tr>`;
    const rows = cachedStats.topDomains || [];
    tbody.innerHTML = rows.length
      ? rows
          .map(
            (r) => `<tr>
          <td class="mono">${esc(r.domain)}${r.isClaude ? ' <span class="status-pill safe">Claude</span>' : ""}</td>
          <td>${fmtBytes(r.upBytes)}</td>
          <td>${fmtBytes(r.downBytes)}</td>
          <td><strong>${fmtBytes(r.totalBytes)}</strong></td>
          <td>${r.connCount}</td>
        </tr>`
          )
          .join("")
      : `<tr><td colspan="5" class="muted">暂无数据</td></tr>`;
  } else if (currentRank === "nodes") {
    thead.innerHTML = `<tr><th>代理节点 / 出站</th><th>上行</th><th>下行</th><th>总流量</th><th>连接数</th></tr>`;
    const rows = cachedStats.topNodes || [];
    tbody.innerHTML = rows.length
      ? rows
          .map(
            (r) => `<tr>
          <td>${esc(r.node)}</td>
          <td>${fmtBytes(r.upBytes)}</td>
          <td>${fmtBytes(r.downBytes)}</td>
          <td><strong>${fmtBytes(r.totalBytes)}</strong></td>
          <td>${r.connCount}</td>
        </tr>`
          )
          .join("")
      : `<tr><td colspan="5" class="muted">暂无数据</td></tr>`;
  } else {
    thead.innerHTML = `<tr><th>本地进程</th><th>上行</th><th>下行</th><th>总流量</th><th>连接数</th></tr>`;
    const rows = cachedStats.topProcesses || [];
    tbody.innerHTML = rows.length
      ? rows
          .map(
            (r) => `<tr>
          <td class="mono">${esc(r.process)}</td>
          <td>${fmtBytes(r.upBytes)}</td>
          <td>${fmtBytes(r.downBytes)}</td>
          <td><strong>${fmtBytes(r.totalBytes)}</strong></td>
          <td>${r.connCount}</td>
        </tr>`
          )
          .join("")
      : `<tr><td colspan="5" class="muted">暂无数据</td></tr>`;
  }
}

function renderStats(data) {
  cachedStats = data;
  document.getElementById("lbl-range").textContent = currentRange;
  const claudeTotal = Number(data.claudeUpBytes || 0) + Number(data.claudeDownBytes || 0);
  const allTotal = Number(data.totalUpBytes || 0) + Number(data.totalDownBytes || 0);
  document.getElementById("kpi-claude-traffic").textContent = fmtBytes(claudeTotal);
  document.getElementById("kpi-total-traffic").textContent = `全网总流量: ${fmtBytes(allTotal)}`;
  document.getElementById("val-claude-traffic").textContent = fmtBytes(claudeTotal);
  document.getElementById("sub-total-traffic").textContent = `${fmtBytes(allTotal)} (↑${fmtBytes(data.totalUpBytes)} ↓${fmtBytes(data.totalDownBytes)})`;
  renderChart(data.hourlySeries);
  renderRanking();
}

function renderAudit(data) {
  cachedAudit = data;
  const missingCount = (data.missingExplicitRuleDomains || []).length;
  document.getElementById("btn-rules-autofix").classList.toggle("hidden", missingCount === 0);
  document.getElementById("rules-summary-badge").textContent =
    `共 ${data.totalProtected} 项 · 安全 ${data.safeCount} · 预警 ${data.warnCount} · 危险 ${data.dangerCount}`;

  const q = (document.getElementById("input-filter-rules").value || "").trim().toLowerCase();
  const tbody = document.getElementById("audit-tbody");
  tbody.innerHTML = (data.items || [])
    .filter((item) => !q || item.domain.toLowerCase().includes(q) || item.category.toLowerCase().includes(q))
    .map((item) => {
      const r = item.route;
      const d = item.decision;
      let pillClass = "safe";
      let pillText = "✅ 安全放行";
      if (d.action === "BLOCK") {
        pillClass = "danger";
        pillText = "🚨 拦截阻断";
      } else if (d.action === "WARN" || r.riskLevel === "warn") {
        pillClass = "warn";
        pillText = r.explicitDomainRule ? "⚠️ 有预警" : "⚠️ 靠兜底规则";
      }
      const ruleText = r.matchedRule
        ? `${r.matchedRule.type}${r.matchedRule.payload ? `,${r.matchedRule.payload}` : ""} → ${r.matchedRule.proxy}`
        : "无匹配规则";
      return `<tr>
        <td class="mono">${esc(item.domain)}</td>
        <td>${esc(item.category)}</td>
        <td class="mono">${esc(ruleText)}</td>
        <td>${esc(r.leafNode)}</td>
        <td><span class="status-pill ${pillClass}">${pillText}</span></td>
        <td><button class="btn btn-sm btn-outline btn-remove-domain" data-domain="${esc(item.domain)}">移除</button></td>
      </tr>`;
    })
    .join("");

  tbody.querySelectorAll(".btn-remove-domain").forEach((btn) => {
    btn.addEventListener("click", async () => {
      if (!cachedConfig) return;
      const target = btn.dataset.domain;
      cachedConfig.protectedDomains = (cachedConfig.protectedDomains || []).filter((x) => x.domain !== target);
      cachedConfig = await api("/api/config", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(cachedConfig),
      });
      await refreshAll();
    });
  });
}

function renderEvents(data) {
  const tbody = document.getElementById("events-tbody");
  const rows = data.events || [];
  tbody.innerHTML = rows.length
    ? rows
        .map((ev) => {
          const pillCls = ev.action === "WARN" ? "warn" : "danger";
          return `<tr>
          <td class="mono">${esc(fmtTime(ev.ts))}</td>
          <td><span class="status-pill ${pillCls}">${esc(ev.action)}</span></td>
          <td class="mono">${esc(ev.domain)}</td>
          <td class="mono">${esc(ev.source)}</td>
          <td>
            <div>${esc(ev.message)}</div>
            ${ev.fixHint ? `<div style="color:var(--primary);font-size:12px;margin-top:3px;">建议: ${esc(ev.fixHint)}</div>` : ""}
          </td>
        </tr>`;
        })
        .join("")
    : `<tr><td colspan="5" class="muted">暂无拦截或告警记录（系统运行安全）</td></tr>`;
}

function renderConfig(cfg) {
  cachedConfig = cfg;
  document.getElementById("cfg-launch-at-login").checked = Boolean(cfg.launchAtLogin);
  document.getElementById("cfg-strict-mode").checked = Boolean(cfg.strictMode);
  document.getElementById("cfg-auto-kill").checked = Boolean(cfg.autoKillDirectLeaks);
  document.getElementById("cfg-notify").checked = Boolean(cfg.notificationsEnabled);
  document.getElementById("cfg-banned-countries").value = (cfg.bannedCountries || []).join(",");
  document.getElementById("cfg-probe-interval").value = String(cfg.exitIpProbeIntervalSec || 30);
  document.getElementById("cfg-proxy-port").value = String(cfg.proxyPort || 17890);
  document.getElementById("cfg-upstream-port").value = String(cfg.upstreamPort || 7897);
}

function renderAutoFixReport(report) {
  const box = document.getElementById("fix-report-box");
  if (!report) {
    box.classList.add("hidden");
    return;
  }
  box.classList.remove("hidden");
  const rows = (report.steps || [])
    .map((s) => {
      const icon = s.status === "fixed" ? "✅" : s.status === "failed" ? "❌" : "⏭️";
      return `<div class="fix-step">
        <div>${icon}</div>
        <div>
          <div><strong>${esc(s.title)}</strong></div>
          <div class="fix-step-detail">${esc(s.detail)}</div>
        </div>
      </div>`;
    })
    .join("");
  box.innerHTML = `
    <div class="fix-report-head">
      <span>⚡ 修复完成：修复 ${report.fixedCount} 项 · 跳过 ${report.skippedCount} 项 · 失败 ${report.failedCount} 项</span>
      <button id="btn-close-fix-report" class="btn btn-sm btn-outline">收起</button>
    </div>
    ${rows}
  `;
  document.getElementById("btn-close-fix-report").addEventListener("click", () => {
    box.classList.add("hidden");
  });
}

async function runOneClickAutoFix() {
  const btn = document.getElementById("btn-auto-fix");
  const detBtn = document.getElementById("btn-det-autofix");
  const rulesBtn = document.getElementById("btn-rules-autofix");
  const includeSysProxy = Boolean(document.getElementById("chk-fix-include-proxy")?.checked);

  const prev = btn.textContent;
  [btn, detBtn, rulesBtn].forEach((b) => {
    if (b) b.disabled = true;
  });
  btn.textContent = "⏳ 正在自动修复...";

  try {
    const res = await api("/api/actions/auto-fix", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ includeSystemProxy: includeSysProxy }),
    });
    renderAutoFixReport(res.report);
    if (res.detectorReport) {
      renderDetectorReport(res.detectorReport);
    }
    await refreshAll();
  } catch (err) {
    alert(`一键修复失败: ${err.message}`);
  } finally {
    [btn, detBtn, rulesBtn].forEach((b) => {
      if (b) b.disabled = false;
    });
    btn.textContent = prev;
  }
}

async function runDomainCheck() {
  const input = document.getElementById("input-check-domain");
  const box = document.getElementById("check-result");
  const domain = input.value.trim();
  if (!domain) return;
  try {
    const { decision, route } = await api(`/api/check?domain=${encodeURIComponent(domain)}`);
    box.classList.remove("hidden");
    const color =
      decision.action === "BLOCK" ? "var(--red)" : decision.action === "WARN" ? "var(--yellow)" : "var(--green)";
    box.innerHTML = `
      <div style="font-weight:700;color:${color}">[${esc(decision.action)}] ${esc(decision.message)}</div>
      ${route ? `<div class="muted-sm">路由链: ${esc(route.chain.join(" → "))} | 命中规则: ${route.matchedRule ? esc(`${route.matchedRule.type},${route.matchedRule.payload} -> ${route.matchedRule.proxy}`) : "无"}</div>` : ""}
      ${decision.fixHint ? `<div class="muted-sm" style="margin-top:4px;color:var(--primary)">${esc(decision.fixHint)}</div>` : ""}
    `;
  } catch (err) {
    box.classList.remove("hidden");
    box.textContent = `检测失败: ${err.message}`;
  }
}

async function refreshAll() {
  try {
    const [status, stats, audit, events] = await Promise.all([
      api("/api/status"),
      api(`/api/stats?range=${currentRange}`),
      api("/api/audit"),
      api("/api/events?limit=50"),
    ]);
    renderStatus(status);
    renderStats(stats);
    renderAudit(audit);
    renderEvents(events);
  } catch (err) {
    console.error("Refresh failed:", err);
  }
}

function showSaveToast(msg) {
  const el = document.getElementById("save-toast");
  el.textContent = msg;
  setTimeout(() => {
    if (el.textContent === msg) el.textContent = "";
  }, 2500);
}

// Event Listeners
document.getElementById("btn-theme-toggle").addEventListener("click", () => {
  const curr = document.documentElement.getAttribute("data-theme") || "light";
  applyTheme(curr === "light" ? "dark" : "light");
});

document.getElementById("btn-mask-ip").addEventListener("click", () => {
  maskIps = !maskIps;
  localStorage.setItem("cg_mask_ip", maskIps ? "1" : "0");
  updateMaskButton();
  if (lastStatus) renderStatus(lastStatus);
  if (lastDetectorReport) renderDetectorReport(lastDetectorReport);
});

document.getElementById("btn-run-detector").addEventListener("click", runFullNetworkDetector);
document.getElementById("btn-auto-fix").addEventListener("click", runOneClickAutoFix);
document.getElementById("btn-det-autofix").addEventListener("click", runOneClickAutoFix);
document.getElementById("btn-rules-autofix").addEventListener("click", runOneClickAutoFix);

document.getElementById("btn-ov-probe-ip").addEventListener("click", async () => {
  await api("/api/actions/probe-ip", { method: "POST" });
  await refreshAll();
});

document.getElementById("btn-toggle-proxy").addEventListener("click", async () => {
  const enable = !lastStatus?.systemProxy?.pointingToGate;
  await api("/api/actions/proxy", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ enable }),
  });
  await refreshAll();
});

document.getElementById("cfg-sys-proxy").addEventListener("change", async (e) => {
  const enable = e.target.checked;
  await api("/api/actions/proxy", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ enable }),
  });
  showSaveToast(enable ? "✅ 已开启系统代理接管" : "✅ 已恢复原有系统代理");
  await refreshAll();
});

document.getElementById("cfg-launch-at-login").addEventListener("change", async (e) => {
  const launchAtLogin = e.target.checked;
  cachedConfig = await api("/api/config", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ launchAtLogin }),
  });
  showSaveToast(launchAtLogin ? "✅ 已开启开机自启动" : "✅ 已关闭开机自启动");
});

document.getElementById("btn-clear-events").addEventListener("click", async () => {
  await api("/api/events", { method: "DELETE" });
  await refreshAll();
});

document.getElementById("btn-check-domain").addEventListener("click", runDomainCheck);
document.getElementById("input-check-domain").addEventListener("keydown", (e) => {
  if (e.key === "Enter") runDomainCheck();
});
document.getElementById("input-filter-rules").addEventListener("input", () => {
  if (cachedAudit) renderAudit(cachedAudit);
});

document.getElementById("btn-copy-cli").addEventListener("click", async () => {
  await copyText(document.getElementById("cli-snippet").textContent || "");
  const btn = document.getElementById("btn-copy-cli");
  btn.textContent = "✅ 已复制";
  setTimeout(() => (btn.textContent = "复制 CLI"), 2000);
});

document.querySelectorAll("#range-tabs .seg-tab").forEach((btn) => {
  btn.addEventListener("click", async () => {
    document.querySelectorAll("#range-tabs .seg-tab").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    currentRange = btn.dataset.range;
    renderStats(await api(`/api/stats?range=${currentRange}`));
  });
});

document.querySelectorAll("#ranking-tabs .seg-tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("#ranking-tabs .seg-tab").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    currentRank = btn.dataset.rank;
    renderRanking();
  });
});

document.getElementById("btn-add-domain").addEventListener("click", async () => {
  if (!cachedConfig) return;
  const input = document.getElementById("cfg-new-domain");
  const d = input.value.trim().toLowerCase();
  if (!d) return;
  if (!cachedConfig.protectedDomains.some((x) => x.domain === d)) {
    cachedConfig.protectedDomains.push({ domain: d, category: "custom", note: "用户自定义" });
  }
  cachedConfig = await api("/api/config", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(cachedConfig),
  });
  input.value = "";
  showSaveToast(`已添加 ${d}`);
  await refreshAll();
});

document.getElementById("btn-save-config").addEventListener("click", async () => {
  if (!cachedConfig) return;
  const updated = {
    ...cachedConfig,
    launchAtLogin: document.getElementById("cfg-launch-at-login").checked,
    strictMode: document.getElementById("cfg-strict-mode").checked,
    autoKillDirectLeaks: document.getElementById("cfg-auto-kill").checked,
    notificationsEnabled: document.getElementById("cfg-notify").checked,
    exitIpProbeIntervalSec: Number(document.getElementById("cfg-probe-interval").value || 30),
    proxyPort: Number(document.getElementById("cfg-proxy-port").value || 17890),
    upstreamPort: Number(document.getElementById("cfg-upstream-port").value || 7897),
    bannedCountries: document
      .getElementById("cfg-banned-countries")
      .value.split(",")
      .map((s) => s.trim().toUpperCase())
      .filter(Boolean),
  };
  cachedConfig = await api("/api/config", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(updated),
  });
  showSaveToast("✅ 设置已保存并生效");
  await refreshAll();
});

(async () => {
  try {
    const [cfg, det] = await Promise.all([api("/api/config"), api("/api/detector")]);
    renderConfig(cfg);
    if (det.report) renderDetectorReport(det.report);
  } catch {}
  await refreshAll();
  setInterval(refreshAll, 3000);
})();
