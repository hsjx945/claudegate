import AppKit
import Foundation
import WebKit

// MARK: - API Models

struct GateStatusPayload: Decodable {
    struct GateInfo: Decodable {
        struct GateStats: Decodable {
            let totalRequests: Int
            let protectedRequests: Int
            let blockedRequests: Int
        }
        let proxyAddress: String
        let dashboardAddress: String
        let upstreamAddress: String
        let stats: GateStats
        let dbBlockedTotal: Int
    }

    struct ClashInfo: Decodable {
        let connected: Bool
        let version: String
        let mode: String
        let tunEnabled: Bool
        let primaryGroup: String
        let primaryLeafNode: String
        let rulesCount: Int
        let lastError: String?
    }

    struct ExitIpWrapper: Decodable {
        struct ExitIpCurrent: Decodable {
            let ip: String
            let countryCode: String
            let country: String
            let isp: String?
        }
        let current: ExitIpCurrent?
        let lastError: String?
    }

    struct SystemProxyInfo: Decodable {
        let activeService: String?
        let pointingToGate: Bool
        let pointingToUpstream: Bool
    }

    let health: String
    let gate: GateInfo
    let clash: ClashInfo
    let exitIp: ExitIpWrapper?
    let systemProxy: SystemProxyInfo?
    let hasFixableIssues: Bool?
}

struct AutoFixResponse: Decodable {
    struct Step: Decodable {
        let id: String
        let title: String
        let status: String
        let detail: String
    }
    struct Report: Decodable {
        let ok: Bool
        let fixedCount: Int
        let skippedCount: Int
        let failedCount: Int
        let steps: [Step]
    }
    let ok: Bool
    let report: Report
}

struct StatsPayload: Decodable {
    let totalUpBytes: Double
    let totalDownBytes: Double
    let claudeUpBytes: Double
    let claudeDownBytes: Double
}

// MARK: - High-Contrast Menu Status Card

final class StatusMenuCardView: NSView {
    private let cardBox = NSView()
    private let dotView = NSView()
    private let titleLabel = NSTextField(labelWithString: "正在启动...")
    private let modeBadge = NSTextField(labelWithString: "-")

    private let exitVal = NSTextField(labelWithString: "-")
    private let nodeVal = NSTextField(labelWithString: "-")
    private let trafficVal = NSTextField(labelWithString: "-")
    private let proxyVal = NSTextField(labelWithString: "-")

    override init(frame frameRect: NSRect) {
        super.init(frame: NSRect(x: 0, y: 0, width: 326, height: 146))
        setupUI()
    }

    required init?(coder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    private func makeKeyLabel(_ text: String) -> NSTextField {
        let lbl = NSTextField(labelWithString: text)
        lbl.font = NSFont.systemFont(ofSize: 11.5, weight: .regular)
        lbl.textColor = NSColor.secondaryLabelColor
        return lbl
    }

    private func makeValLabel() -> NSTextField {
        let lbl = NSTextField(labelWithString: "-")
        lbl.font = NSFont.systemFont(ofSize: 12, weight: .semibold)
        lbl.textColor = NSColor.labelColor
        lbl.alignment = .right
        lbl.lineBreakMode = .byTruncatingMiddle
        lbl.maximumNumberOfLines = 1
        return lbl
    }

    private func setupUI() {
        cardBox.wantsLayer = true
        cardBox.layer?.cornerRadius = 9
        cardBox.layer?.backgroundColor = NSColor.quaternaryLabelColor.withAlphaComponent(0.14).cgColor
        cardBox.layer?.borderWidth = 0.5
        cardBox.layer?.borderColor = NSColor.separatorColor.cgColor
        cardBox.translatesAutoresizingMaskIntoConstraints = false
        addSubview(cardBox)

        NSLayoutConstraint.activate([
            cardBox.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 12),
            cardBox.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -12),
            cardBox.topAnchor.constraint(equalTo: topAnchor, constant: 6),
            cardBox.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -6),
        ])

        dotView.wantsLayer = true
        dotView.layer?.cornerRadius = 4.5
        dotView.layer?.backgroundColor = NSColor.systemGray.cgColor
        dotView.translatesAutoresizingMaskIntoConstraints = false
        NSLayoutConstraint.activate([
            dotView.widthAnchor.constraint(equalToConstant: 9),
            dotView.heightAnchor.constraint(equalToConstant: 9),
        ])

        titleLabel.font = NSFont.systemFont(ofSize: 13, weight: .bold)
        titleLabel.textColor = NSColor.labelColor

        modeBadge.font = NSFont.monospacedSystemFont(ofSize: 10.5, weight: .semibold)
        modeBadge.textColor = NSColor.secondaryLabelColor
        modeBadge.alignment = .right

        let headerRow = NSStackView(views: [dotView, titleLabel, NSView(), modeBadge])
        headerRow.orientation = .horizontal
        headerRow.alignment = .centerY
        headerRow.spacing = 6

        let divider = NSBox()
        divider.boxType = .separator

        exitVal.font = NSFont.monospacedSystemFont(ofSize: 11.5, weight: .semibold)
        let r1 = makeRow(key: "出口 IP", valField: exitVal)
        let r2 = makeRow(key: "主节点", valField: nodeVal)
        let r3 = makeRow(key: "24h 流量", valField: trafficVal)
        let r4 = makeRow(key: "系统代理", valField: proxyVal)

        let stack = NSStackView(views: [headerRow, divider, r1, r2, r3, r4])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 6
        stack.translatesAutoresizingMaskIntoConstraints = false
        cardBox.addSubview(stack)

        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: cardBox.leadingAnchor, constant: 11),
            stack.trailingAnchor.constraint(equalTo: cardBox.trailingAnchor, constant: -11),
            stack.topAnchor.constraint(equalTo: cardBox.topAnchor, constant: 9),
            stack.bottomAnchor.constraint(equalTo: cardBox.bottomAnchor, constant: -9),
            headerRow.widthAnchor.constraint(equalTo: stack.widthAnchor),
            divider.widthAnchor.constraint(equalTo: stack.widthAnchor),
            r1.widthAnchor.constraint(equalTo: stack.widthAnchor),
            r2.widthAnchor.constraint(equalTo: stack.widthAnchor),
            r3.widthAnchor.constraint(equalTo: stack.widthAnchor),
            r4.widthAnchor.constraint(equalTo: stack.widthAnchor),
        ])
    }

    private func makeRow(key: String, valField: NSTextField) -> NSStackView {
        let k = makeKeyLabel(key)
        k.setContentHuggingPriority(.required, for: .horizontal)
        valField.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)
        let row = NSStackView(views: [k, valField])
        row.orientation = .horizontal
        row.distribution = .fill
        row.spacing = 8
        return row
    }

    func update(status: GateStatusPayload?, trafficText: String) {
        guard let status = status else {
            dotView.layer?.backgroundColor = NSColor.systemRed.cgColor
            titleLabel.stringValue = "引擎正在连接..."
            titleLabel.textColor = NSColor.labelColor
            modeBadge.stringValue = "-"
            exitVal.stringValue = "-"
            nodeVal.stringValue = "-"
            trafficVal.stringValue = trafficText
            proxyVal.stringValue = "-"
            return
        }

        switch status.health {
        case "safe":
            dotView.layer?.backgroundColor = NSColor.systemGreen.cgColor
            titleLabel.stringValue = "门禁安全"
            titleLabel.textColor = NSColor.systemGreen
        case "warn":
            dotView.layer?.backgroundColor = NSColor.systemOrange.cgColor
            titleLabel.stringValue = "存在配置隐患"
            titleLabel.textColor = NSColor.systemOrange
        default:
            dotView.layer?.backgroundColor = NSColor.systemRed.cgColor
            titleLabel.stringValue = "已拦截直连风险"
            titleLabel.textColor = NSColor.systemRed
        }

        if status.clash.connected {
            modeBadge.stringValue = "\(status.clash.mode.uppercased()) · TUN \(status.clash.tunEnabled ? "开" : "关")"
        } else {
            modeBadge.stringValue = "Clash 未连接"
        }

        if let ip = status.exitIp?.current {
            exitVal.stringValue = "\(ip.countryCode) · \(ip.ip)"
        } else {
            exitVal.stringValue = status.exitIp?.lastError ?? "探测中..."
        }

        nodeVal.stringValue = status.clash.primaryLeafNode
        trafficVal.stringValue = trafficText

        if status.systemProxy?.pointingToGate == true {
            proxyVal.stringValue = "已接管 (17890)"
            proxyVal.textColor = NSColor.systemGreen
        } else {
            proxyVal.stringValue = "未接管 (仅 TUN 监听)"
            proxyVal.textColor = NSColor.secondaryLabelColor
        }
    }
}

// MARK: - Engine Process Manager

final class EngineManager {
    private var process: Process?
    private var ownsProcess = false
    private let lock = NSLock()
    private let dashboardBaseUrl = URL(string: "http://127.0.0.1:17891")!

    func dataDir() -> URL {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let dir = home.appendingPathComponent(".claudeban", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    func logFileUrl() -> URL {
        return dataDir().appendingPathComponent("engine.log")
    }

    private func resolveNodeExecutable() -> String? {
        let fm = FileManager.default
        if let resPath = Bundle.main.resourcePath {
            let bundledNode = URL(fileURLWithPath: resPath).appendingPathComponent("runtime/node").path
            if fm.isExecutableFile(atPath: bundledNode) {
                return bundledNode
            }
            let nodePathFile = URL(fileURLWithPath: resPath).appendingPathComponent("engine/node-path.txt")
            if let raw = try? String(contentsOf: nodePathFile, encoding: .utf8) {
                let candidate = raw.trimmingCharacters(in: .whitespacesAndNewlines)
                if !candidate.isEmpty && fm.isExecutableFile(atPath: candidate) {
                    return candidate
                }
            }
        }
        let nvmBase = fm.homeDirectoryForCurrentUser.appendingPathComponent(".nvm/versions/node")
        if let versions = try? fm.contentsOfDirectory(atPath: nvmBase.path) {
            let sorted = versions.sorted { $0.compare($1, options: .numeric) == .orderedDescending }
            for ver in sorted {
                let bin = nvmBase.appendingPathComponent("\(ver)/bin/node").path
                if fm.isExecutableFile(atPath: bin) {
                    return bin
                }
            }
        }
        for candidate in ["/opt/homebrew/bin/node", "/usr/local/bin/node", "/usr/bin/node"] {
            if fm.isExecutableFile(atPath: candidate) {
                return candidate
            }
        }
        return nil
    }

    private func resolveEngineEntrypoint() -> String? {
        guard let resPath = Bundle.main.resourcePath else { return nil }
        let entry = URL(fileURLWithPath: resPath).appendingPathComponent("engine/dist/src/index.js").path
        return FileManager.default.fileExists(atPath: entry) ? entry : nil
    }

    private func isEngineAlreadyRunning() -> Bool {
        let sem = DispatchSemaphore(value: 0)
        var alive = false
        var req = URLRequest(url: dashboardBaseUrl.appendingPathComponent("api/status"))
        req.timeoutInterval = 0.8
        URLSession.shared.dataTask(with: req) { _, resp, _ in
            if let http = resp as? HTTPURLResponse, http.statusCode == 200 {
                alive = true
            }
            sem.signal()
        }.resume()
        _ = sem.wait(timeout: .now() + 1.0)
        return alive
    }

    func startIfNeeded() {
        lock.lock()
        defer { lock.unlock() }

        if let p = process, p.isRunning { return }
        if isEngineAlreadyRunning() {
            ownsProcess = false
            return
        }
        guard let nodeBin = resolveNodeExecutable(), let entry = resolveEngineEntrypoint() else {
            return
        }

        let logUrl = logFileUrl()
        if !FileManager.default.fileExists(atPath: logUrl.path) {
            FileManager.default.createFile(atPath: logUrl.path, contents: nil)
        }
        let logHandle = try? FileHandle(forWritingTo: logUrl)
        logHandle?.seekToEndOfFile()

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: nodeBin)
        proc.arguments = [entry, "start"]
        proc.currentDirectoryURL = URL(fileURLWithPath: entry)
            .deletingLastPathComponent()
            .deletingLastPathComponent()
            .deletingLastPathComponent()

        var env = ProcessInfo.processInfo.environment
        let nodeDir = URL(fileURLWithPath: nodeBin).deletingLastPathComponent().path
        env["PATH"] = "\(nodeDir):/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
        env["CLAUDEGATE_APP_EXEC"] = Bundle.main.executablePath ?? (Bundle.main.bundlePath + "/Contents/MacOS/ClaudeGate")
        proc.environment = env

        if let handle = logHandle {
            proc.standardOutput = handle
            proc.standardError = handle
        }
        proc.terminationHandler = { [weak self] _ in
            self?.lock.lock()
            self?.ownsProcess = false
            self?.lock.unlock()
        }

        do {
            try proc.run()
            process = proc
            ownsProcess = true
        } catch {}
    }

    func stopIfOwned() {
        lock.lock()
        let proc = process
        let owned = ownsProcess
        process = nil
        ownsProcess = false
        lock.unlock()

        guard owned, let p = proc, p.isRunning else { return }
        kill(p.processIdentifier, SIGTERM)
        let deadline = Date().addingTimeInterval(1.8)
        while p.isRunning && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.05)
        }
        if p.isRunning {
            p.terminate()
        }
    }
}

// MARK: - AppDelegate

final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate, WKScriptMessageHandler {
    private let engine = EngineManager()
    private let apiBase = URL(string: "http://127.0.0.1:17891")!
    private let launchAgentLabel = "com.claudeban.claudegate"

    private var statusItem: NSStatusItem!
    private var pollTimer: Timer?

    private let menu = NSMenu()
    private let statusCardView = StatusMenuCardView()
    private let itemStatusCard = NSMenuItem()

    private let itemAutoFix = NSMenuItem(title: "⚡ 一键修复全部安全隐患", action: #selector(onAutoFix), keyEquivalent: "f")
    private let itemOpenWindow = NSMenuItem(title: "📊 打开 ClaudeGate 控制台...", action: #selector(onOpenWindow), keyEquivalent: "d")
    private let itemToggleProxy = NSMenuItem(title: "🔌 系统代理接管 (17890)", action: #selector(onToggleSystemProxy), keyEquivalent: "")
    private let itemProbeIp = NSMenuItem(title: "🔄 重新检测出口 IP", action: #selector(onProbeIp), keyEquivalent: "r")
    private let itemLaunchAtLogin = NSMenuItem(title: "🚀 开机自动启动", action: #selector(onToggleLaunchAtLogin), keyEquivalent: "")
    private let itemQuit = NSMenuItem(title: "退出 ClaudeGate", action: #selector(onQuit), keyEquivalent: "q")

    private var lastStatus: GateStatusPayload?
    private var lastTrafficText = "Claude 0 B · 全网 0 B"
    private var dashboardWindow: NSWindow?
    private var webView: WKWebView?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        setupMenuBar()

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            self?.engine.startIfNeeded()
            DispatchQueue.main.async {
                self?.refreshAll()
            }
        }

        pollTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            self?.refreshAll()
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        pollTimer?.invalidate()
        engine.stopIfOwned()
    }

    private func makeSectionHeader(_ title: String) -> NSMenuItem {
        if #available(macOS 14.0, *) {
            return NSMenuItem.sectionHeader(title: title)
        }
        let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
        item.isEnabled = false
        return item
    }

    private func setupMenuBar() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        updateStatusButton(health: "loading", titleText: " 启动中")

        itemStatusCard.view = statusCardView

        itemAutoFix.target = self
        itemAutoFix.isHidden = true
        itemOpenWindow.target = self
        itemToggleProxy.target = self
        itemProbeIp.target = self
        itemLaunchAtLogin.target = self
        itemQuit.target = self

        itemLaunchAtLogin.state = FileManager.default.fileExists(atPath: launchAgentUrl().path) ? .on : .off

        menu.addItem(itemStatusCard)
        menu.addItem(NSMenuItem.separator())
        menu.addItem(makeSectionHeader("快捷操作"))
        menu.addItem(itemAutoFix)
        menu.addItem(itemOpenWindow)
        menu.addItem(itemToggleProxy)
        menu.addItem(itemProbeIp)
        menu.addItem(NSMenuItem.separator())
        menu.addItem(makeSectionHeader("应用"))
        menu.addItem(itemLaunchAtLogin)
        menu.addItem(itemQuit)

        statusItem.menu = menu
    }

    private func updateStatusButton(health: String, titleText: String) {
        guard let button = statusItem.button else { return }
        let symbolName: String
        let color: NSColor

        switch health {
        case "safe":
            symbolName = "checkmark.shield.fill"
            color = NSColor.systemGreen
        case "warn":
            symbolName = "exclamationmark.shield.fill"
            color = NSColor.systemOrange
        case "danger":
            symbolName = "xmark.shield.fill"
            color = NSColor.systemRed
        default:
            symbolName = "shield.lefthalf.filled"
            color = NSColor.labelColor
        }

        if let baseImg = NSImage(systemSymbolName: symbolName, accessibilityDescription: "ClaudeGate") {
            let config = NSImage.SymbolConfiguration(pointSize: 14, weight: .semibold)
                .applying(NSImage.SymbolConfiguration(paletteColors: [color]))
            let configured = baseImg.withSymbolConfiguration(config) ?? baseImg
            configured.isTemplate = false
            button.image = configured
        }
        button.imagePosition = .imageLeading
        button.title = titleText
    }

    // MARK: - Polling & Updates

    private func refreshAll() {
        fetchJSON(path: "/api/status", type: GateStatusPayload.self) { [weak self] payload in
            guard let self = self else { return }
            self.lastStatus = payload
            self.applyStatusUI(payload)
        } onError: { [weak self] _ in
            guard let self = self else { return }
            self.updateStatusButton(health: "danger", titleText: " 离线")
            self.statusCardView.update(status: nil, trafficText: self.lastTrafficText)
        }

        fetchJSON(path: "/api/stats?range=24h", type: StatsPayload.self) { [weak self] stats in
            guard let self = self else { return }
            let claudeTotal = stats.claudeUpBytes + stats.claudeDownBytes
            let allTotal = stats.totalUpBytes + stats.totalDownBytes
            self.lastTrafficText = "Claude \(self.formatBytes(claudeTotal)) · 全网 \(self.formatBytes(allTotal))"
            self.statusCardView.update(status: self.lastStatus, trafficText: self.lastTrafficText)
        } onError: { _ in }
    }

    private func applyStatusUI(_ status: GateStatusPayload) {
        let cc = status.exitIp?.current?.countryCode ?? ""

        switch status.health {
        case "safe":
            updateStatusButton(health: "safe", titleText: cc.isEmpty ? " 安全" : " \(cc)")
        case "warn":
            updateStatusButton(health: "warn", titleText: cc.isEmpty ? " 预警" : " \(cc) !")
        default:
            updateStatusButton(health: "danger", titleText: " 已拦截")
        }

        statusCardView.update(status: status, trafficText: lastTrafficText)
        itemAutoFix.isHidden = !(status.hasFixableIssues ?? false)
        itemToggleProxy.state = (status.systemProxy?.pointingToGate == true) ? .on : .off
        itemToggleProxy.title = (status.systemProxy?.pointingToGate == true)
            ? "🔌 系统代理已接管 (点击恢复 Clash)"
            : "🔌 系统代理接管 (127.0.0.1:17890)"
        itemLaunchAtLogin.state = FileManager.default.fileExists(atPath: launchAgentUrl().path) ? .on : .off
    }

    // MARK: - Actions

    @objc private func onOpenWindow() {
        if dashboardWindow == nil {
            let config = WKWebViewConfiguration()
            config.userContentController.add(self, name: "copyText")

            let wv = WKWebView(frame: NSRect(x: 0, y: 0, width: 1240, height: 820), configuration: config)
            wv.autoresizingMask = [.width, .height]

            let win = NSWindow(
                contentRect: NSRect(x: 0, y: 0, width: 1240, height: 820),
                styleMask: [.titled, .closable, .miniaturizable, .resizable],
                backing: .buffered,
                defer: false
            )
            win.title = "ClaudeGate · Claude 防封号门禁与网络体检"
            win.backgroundColor = NSColor.windowBackgroundColor
            win.center()
            win.delegate = self
            win.contentView = wv

            self.webView = wv
            self.dashboardWindow = win
        }

        webView?.load(URLRequest(url: apiBase))
        dashboardWindow?.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        sender.orderOut(nil)
        return false
    }

    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        if message.name == "copyText", let text = message.body as? String {
            copyToClipboard(text)
        }
    }

    @objc private func onAutoFix() {
        guard let url = URL(string: "/api/actions/auto-fix", relativeTo: apiBase) else { return }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.timeoutInterval = 15.0
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try? JSONSerialization.data(withJSONObject: [:])

        URLSession.shared.dataTask(with: req) { [weak self] data, _, err in
            DispatchQueue.main.async {
                guard let self = self else { return }
                self.refreshAll()
                if let err = err {
                    self.showSimpleAlert(title: "一键修复失败", message: err.localizedDescription)
                    return
                }
                guard let data = data, let decoded = try? JSONDecoder().decode(AutoFixResponse.self, from: data) else {
                    self.showSimpleAlert(title: "一键修复完成", message: "请刷新控制台查看最新状态。")
                    return
                }
                let lines = decoded.report.steps.map { step -> String in
                    let icon = step.status == "fixed" ? "✅" : (step.status == "failed" ? "❌" : "⏭️")
                    return "\(icon) \(step.title)\n   \(step.detail)"
                }
                self.showSimpleAlert(
                    title: "一键修复完成 (修复 \(decoded.report.fixedCount) 项 · 失败 \(decoded.report.failedCount) 项)",
                    message: lines.joined(separator: "\n\n")
                )
            }
        }.resume()
    }

    @objc private func onProbeIp() {
        postJSON(path: "/api/actions/probe-ip", body: [:]) { [weak self] in
            self?.refreshAll()
        }
    }

    @objc private func onToggleSystemProxy() {
        let currentlyEnabled = lastStatus?.systemProxy?.pointingToGate ?? false
        postJSON(path: "/api/actions/proxy", body: ["enable": !currentlyEnabled]) { [weak self] in
            self?.refreshAll()
        }
    }

    @objc private func onToggleLaunchAtLogin() {
        let plistUrl = launchAgentUrl()
        let fm = FileManager.default

        if fm.fileExists(atPath: plistUrl.path) {
            try? fm.removeItem(at: plistUrl)
            itemLaunchAtLogin.state = .off
        } else {
            let dir = plistUrl.deletingLastPathComponent()
            try? fm.createDirectory(at: dir, withIntermediateDirectories: true)
            let execPath = Bundle.main.executablePath ?? (Bundle.main.bundlePath + "/Contents/MacOS/ClaudeGate")
            let plist: [String: Any] = [
                "Label": launchAgentLabel,
                "ProgramArguments": [execPath],
                "RunAtLoad": true,
                "KeepAlive": false,
            ]
            if let data = try? PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0) {
                try? data.write(to: plistUrl)
                itemLaunchAtLogin.state = .on
            }
        }
    }

    @objc private func onQuit() {
        NSApp.terminate(nil)
    }

    // MARK: - Helpers

    private func launchAgentUrl() -> URL {
        return FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/\(launchAgentLabel).plist")
    }

    private func copyToClipboard(_ text: String) {
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(text, forType: .string)
    }

    private func showSimpleAlert(title: String, message: String) {
        DispatchQueue.main.async {
            let alert = NSAlert()
            alert.messageText = title
            alert.informativeText = message
            alert.alertStyle = .informational
            alert.addButton(withTitle: "好的")
            NSApp.activate(ignoringOtherApps: true)
            alert.runModal()
        }
    }

    private func formatBytes(_ bytes: Double) -> String {
        if bytes < 1024 { return "\(Int(bytes)) B" }
        if bytes < 1024 * 1024 { return String(format: "%.1f KB", bytes / 1024) }
        if bytes < 1024 * 1024 * 1024 { return String(format: "%.2f MB", bytes / 1024 / 1024) }
        return String(format: "%.2f GB", bytes / 1024 / 1024 / 1024)
    }

    private func fetchJSON<T: Decodable>(
        path: String,
        type: T.Type,
        onSuccess: @escaping (T) -> Void,
        onError: @escaping (Error) -> Void
    ) {
        guard let url = URL(string: path, relativeTo: apiBase) else { return }
        var req = URLRequest(url: url)
        req.timeoutInterval = 2.0
        URLSession.shared.dataTask(with: req) { data, resp, err in
            if let err = err {
                DispatchQueue.main.async { onError(err) }
                return
            }
            guard let data = data, let http = resp as? HTTPURLResponse, http.statusCode < 400 else {
                DispatchQueue.main.async {
                    onError(NSError(domain: "ClaudeGate", code: -1, userInfo: [NSLocalizedDescriptionKey: "HTTP error"]))
                }
                return
            }
            do {
                let decoded = try JSONDecoder().decode(T.self, from: data)
                DispatchQueue.main.async { onSuccess(decoded) }
            } catch {
                DispatchQueue.main.async { onError(error) }
            }
        }.resume()
    }

    private func postJSON(path: String, body: [String: Any], completion: @escaping () -> Void) {
        guard let url = URL(string: path, relativeTo: apiBase) else { return }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.timeoutInterval = 5.0
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try? JSONSerialization.data(withJSONObject: body)
        URLSession.shared.dataTask(with: req) { _, _, _ in
            DispatchQueue.main.async { completion() }
        }.resume()
    }
}

// MARK: - Entry Point

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()
