import AppKit
import Foundation

/// The host app's 連線設定 (PR-C): set, change and clear the connection
/// password, and edit the whitelist (`allowedIPs`) and the blacklist
/// (`blockedIPs`) in listen.plist. The control service notices every change
/// (policy watch) and applies it; nothing here talks to it directly.
///
/// Order of writes, so a failure never leaves the host more open than asked:
/// - set / change: Keychain first, then `passwordSet = true`. If the plist
///   write fails, the Keychain goes back to what it was.
/// - clear: `passwordSet = false` first, then the Keychain item goes. Not
///   allowed with an empty whitelist (that would lock every viewer out).
/// - whitelist: `allowedIPs` replaces `clientIP` and `allowedIPsSource`
///   (the migration copy); `listen.plist.pre-0.4` is written first if it is
///   not there yet. An empty whitelist needs a password.
/// - blacklist: through ListenPlistBlocklist (same lock and replace as the
///   control service's own blocks). An addition applies at once; a removal
///   restarts the control service (AuthGuard.refreshStoreLocked).
///
/// The Keychain item is written by this same signed binary, which is what
/// the control service runs, so its default access list lets the service
/// read it without an Allow prompt.
enum ConnectionSettings {
    struct State: Equatable {
        var hasPlist: Bool
        var passwordSet: Bool
        var whitelist: [String]
        var followsClientIP: Bool
        var blacklist: [String]
        /// r2 item 6: each block with its time and reason (design §10).
        var blocks: [BlockedEntry] = []
    }

    enum Outcome: Equatable {
        case ok(String)
        case refused(String)

        var message: String {
            switch self {
            case .ok(let m), .refused(let m): return m
            }
        }
        var ok: Bool { if case .ok = self { return true } else { return false } }
    }

    static var defaultURL: URL { ListenConfig.plistURL }

    static func read(url: URL) -> [String: Any]? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        return (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) as? [String: Any]
    }

    static func state(url: URL) -> State {
        guard let plist = read(url: url) else {
            return State(hasPlist: false, passwordSet: false, whitelist: [], followsClientIP: false, blacklist: [])
        }
        return state(plist: plist)
    }

    static func state(plist: [String: Any]) -> State {
        let follows = ListenMigration.followsClientIP(plist)
        var whitelist: [String]
        if let raw = plist["allowedIPs"] as? [Any], !follows {
            whitelist = raw.compactMap { $0 as? String }
        } else if let client = plist["clientIP"] as? String, ListenConfig.isIPv4(client) {
            whitelist = [client]
        } else {
            whitelist = []
        }
        whitelist = dedupe(whitelist)
        let blocks = ListenPlistBlocklist.entries(in: plist)
        return State(hasPlist: true,
                     passwordSet: plist["passwordSet"] as? Bool == true,
                     whitelist: whitelist,
                     followsClientIP: follows,
                     blacklist: blocks.map(\.ip),
                     blocks: blocks)
    }

    /// r2 (Pepper's PR-C review, item 3): every password and whitelist
    /// change runs whole under one exclusive flock (`<listen.plist>.settings.lock`),
    /// so the Keychain write and the plist write of one change never
    /// interleave with another's: two windows, or a set racing a clear,
    /// cannot leave passwordSet = true with no Keychain item (which would
    /// refuse every viewer). The listen.plist lock is still taken inside it
    /// for each plist write (the control service shares that one), so the
    /// order is always settings lock, then plist lock.
    static func transaction(url: URL, wait: TimeInterval = 5, _ body: () -> Outcome) -> Outcome {
        ListenConfig.withFileLock(URL(fileURLWithPath: url.path + ".settings"), wait: wait, body)
            ?? .refused("另一個連線設定正在儲存，請稍後再試。")
    }

    /// One IPv4 address per line, or separated by commas or spaces. Returns
    /// the addresses (order kept, no duplicates) and anything that is not one.
    static func parseIPs(_ text: String) -> (ips: [String], invalid: [String]) {
        let parts = text.split(whereSeparator: { $0 == "\n" || $0 == "," || $0 == " " || $0 == "\t" || $0 == "\r" })
            .map { String($0) }
            .filter { !$0.isEmpty }
        let invalid = parts.filter { !ListenConfig.isIPv4($0) }
        return (dedupe(parts.filter { ListenConfig.isIPv4($0) }), invalid)
    }

    private static func dedupe(_ ips: [String]) -> [String] {
        var seen = Set<String>()
        return ips.filter { seen.insert($0).inserted }
    }

    /// Read-modify-write of listen.plist under its flock, replaced
    /// atomically. `body` returns nil to write, or a refusal (nothing written).
    static func update(url: URL, _ body: (inout [String: Any]) -> String?) -> Outcome? {
        let result = ListenConfig.withFileLock(url) { () -> Outcome? in
            guard var dict = read(url: url) else { return .refused("找不到 listen.plist，無法儲存（network.conf 設定請先改用 listen.plist）。") }
            if let refusal = body(&dict) { return .refused(refusal) }
            let tmp = url.deletingLastPathComponent()
                .appendingPathComponent(".\(url.lastPathComponent).\(getpid()).\(UUID().uuidString.prefix(8))")
            guard let data = try? PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0),
                  (try? data.write(to: tmp)) != nil else { return .refused("寫入 listen.plist 失敗。") }
            guard rename(tmp.path, url.path) == 0 else {
                unlink(tmp.path)
                return .refused("寫入 listen.plist 失敗。")
            }
            return nil
        }
        guard let result else { return .refused("listen.plist 正被其他程式使用，請稍後再試。") }
        return result
    }

    /// The listen.plist as it was before 0.4 settings changed it, once.
    static func ensureBackup(url: URL) -> Bool {
        let backup = URL(fileURLWithPath: url.path + ".pre-0.4")
        if FileManager.default.fileExists(atPath: backup.path) { return true }
        guard let data = try? Data(contentsOf: url) else { return false }
        return (try? data.write(to: backup, options: .atomic)) != nil
    }

    static func problemText(_ problems: [ConnAuth.PasswordProblem]) -> String {
        problems.map { p -> String in
            switch p {
            case .tooShort: return "最少 \(ConnAuth.minPasswordLength) 個字"
            case .noUpper: return "要有大楷字母 (A-Z)"
            case .noLower: return "要有細楷字母 (a-z)"
            case .noSymbol: return "要有符號（唔係字母、數字或空格）"
            }
        }.joined(separator: "；")
    }

    // MARK: Password

    static func setPassword(_ password: String, confirm: String, url: URL, store: ConnSecretStore,
                            iterations: UInt32 = ConnAuth.iterations) -> Outcome {
        guard password == confirm else { return .refused("兩次輸入嘅密碼唔一樣。") }
        let problems = ConnAuth.passwordProblems(password)
        guard problems.isEmpty else { return .refused("密碼唔夠強：" + problemText(problems)) }
        return transaction(url: url) { setPasswordLocked(password, url: url, store: store, iterations: iterations) }
    }

    private static func setPasswordLocked(_ password: String, url: URL, store: ConnSecretStore, iterations: UInt32) -> Outcome {
        guard read(url: url) != nil else { return .refused("找不到 listen.plist，無法設定密碼。") }
        let old = store.load()
        // The host id stays across changes; the salt is new every time, so
        // every remembered viewer needs the new password.
        guard let secret = ConnSecret.make(password: password, hostID: old?.hostID, iterations: iterations) else {
            return .refused("無法產生密碼金鑰。")
        }
        guard store.save(secret) else { return .refused("無法寫入鑰匙圈 (Keychain)。") }
        let written = update(url: url) { dict in
            dict["passwordSet"] = true
            return nil
        }
        if let written, !written.ok {
            // Put the Keychain back so it matches passwordSet.
            if let old { _ = store.save(old) } else { store.delete() }
            return written
        }
        return .ok(old == nil ? "已設定連線密碼。" : "已更改連線密碼；已記住密碼嘅 viewer 要重新輸入。")
    }

    static let emptyWhitelistClearRefusal = "白名單係空嘅：清除密碼之後冇 viewer 可以連線。請先加白名單 IP。"

    static func clearPassword(url: URL, store: ConnSecretStore) -> Outcome {
        transaction(url: url) {
            guard read(url: url) != nil else { return .refused("找不到 listen.plist。") }
            // The whitelist is checked again on the plist that is written,
            // under its lock (r2 item 3), not on an earlier read.
            let written = update(url: url) { dict in
                if state(plist: dict).whitelist.isEmpty { return emptyWhitelistClearRefusal }
                dict["passwordSet"] = false
                return nil
            }
            if let written, !written.ok { return written }
            guard store.delete() else { return .refused("passwordSet 已關，但鑰匙圈項目刪除失敗。") }
            return .ok("已清除連線密碼：白名單上嘅 IP 可以直接連線（過渡模式）。")
        }
    }

    // MARK: Lists

    static func saveWhitelist(_ text: String, url: URL) -> Outcome {
        let parsed = parseIPs(text)
        guard parsed.invalid.isEmpty else { return .refused("唔係 IPv4 地址：" + parsed.invalid.joined(separator: ", ")) }
        return transaction(url: url) { saveWhitelistLocked(parsed.ips, url: url) }
    }

    private static func saveWhitelistLocked(_ ips: [String], url: URL) -> Outcome {
        guard ensureBackup(url: url) else { return .refused("無法寫入 listen.plist.pre-0.4 備份，冇改動。") }
        let result = update(url: url) { dict in
            if ips.isEmpty && dict["passwordSet"] as? Bool != true {
                return "未設定密碼時白名單唔可以係空（會冇人可以連線）。"
            }
            dict["allowedIPs"] = ips
            // The whitelist is now edited here: it no longer follows clientIP.
            dict.removeValue(forKey: ListenMigration.sourceKey)
            dict.removeValue(forKey: "clientIP")
            return nil
        }
        if let result { return result }
        return .ok(ips.isEmpty ? "白名單已清空：任何 IP 都要輸入密碼。" : "白名單已儲存（\(ips.count) 個 IP）。")
    }

    static func saveBlacklist(_ text: String, url: URL) -> Outcome {
        let parsed = parseIPs(text)
        guard parsed.invalid.isEmpty else { return .refused("唔係 IPv4 地址：" + parsed.invalid.joined(separator: ", ")) }
        let current = Set(state(url: url).blacklist)
        let want = Set(parsed.ips)
        let adding = parsed.ips.filter { !current.contains($0) }.map { BlockedEntry(ip: $0, at: Date(), reason: "manual") }
        let removing = current.subtracting(want)
        if adding.isEmpty && removing.isEmpty { return .ok("黑名單冇改動。") }
        guard ListenPlistBlocklist(url: url).update(adding: adding, removing: removing) != nil else {
            return .refused("黑名單儲存失敗。")
        }
        return .ok("黑名單已儲存（\(want.count) 個 IP）。")
    }

    /// r2 item 6: one row's 解除封鎖 (design §10). Restarts the control
    /// service like any blacklist removal.
    static func unblock(_ ip: String, url: URL) -> Outcome {
        guard ListenConfig.isIPv4(ip) else { return .refused("唔係 IPv4 地址：" + ip) }
        guard state(url: url).blacklist.contains(ip) else { return .ok("\(ip) 已經唔喺黑名單。") }
        guard ListenPlistBlocklist(url: url).update(adding: [], removing: [ip]) != nil else {
            return .refused("解除封鎖失敗。")
        }
        return .ok("已解除封鎖 \(ip)。")
    }

    /// r2 item 6: 人手加 IP 落黑名單 (design §10); applies at once.
    static func block(_ text: String, url: URL) -> Outcome {
        let ip = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard ListenConfig.isIPv4(ip) else { return .refused("唔係 IPv4 地址：" + ip) }
        guard !state(url: url).blacklist.contains(ip) else { return .ok("\(ip) 已經喺黑名單。") }
        guard ListenPlistBlocklist(url: url).update(adding: [BlockedEntry(ip: ip, at: Date(), reason: "manual")],
                                                    removing: []) != nil else {
            return .refused("黑名單儲存失敗。")
        }
        return .ok("已封鎖 \(ip)。")
    }

    /// How a block's reason reads in the window.
    static func reasonText(_ reason: String) -> String {
        if reason == "manual" { return "人手加入" }
        if let n = Int(reason.split(separator: " ").first ?? ""), reason.hasSuffix("wrong passwords") {
            return "錯密碼 \(n) 次"
        }
        return reason
    }

    static func failureReasonText(_ reason: String) -> String {
        switch reason {
        case "wrong_password": return "密碼錯"
        case "timeout": return "逾時冇回應"
        case "bad_response": return "回應格式錯"
        default: return reason
        }
    }
}

// MARK: Window

/// The 連線設定 window. Plain AppKit; runs modally from the launcher.
@MainActor
final class ConnectionSettingsWindow: NSObject, NSWindowDelegate {
    private let url: URL
    private let store: ConnSecretStore
    private let window: NSWindow
    private let banner = NSTextField(wrappingLabelWithString: "")
    private let passwordStatus = NSTextField(labelWithString: "")
    private let newPassword = NSSecureTextField()
    private let confirmPassword = NSSecureTextField()
    private let clearButton = NSButton(title: "清除密碼", target: nil, action: nil)
    private let clearNote = NSTextField(wrappingLabelWithString: "")
    private let whitelistView = NSTextView()
    // r2 item 6 (design §10): one row per block (IP, 幾時封, 點解封, 解除封鎖),
    // a field to add one by hand, and the recent counted auth failures.
    private let blockRows = NSStackView()
    private var blockIPs: [String] = []
    private let addBlockField = NSTextField()
    private let failuresView = NSTextView()
    private let failureLogURL: URL
    private let status = NSTextField(wrappingLabelWithString: "")

    private static let timeFormat: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return f
    }()

    init(url: URL = ConnectionSettings.defaultURL, store: ConnSecretStore = KeychainSecretStore(),
         failureLogURL: URL = AuthFailureLog.defaultURL) {
        self.url = url
        self.store = store
        self.failureLogURL = failureLogURL
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 520, height: 760),
                          styleMask: [.titled, .closable], backing: .buffered, defer: false)
        super.init()
        window.title = "JerisLink 連線設定"
        window.delegate = self
        window.isReleasedWhenClosed = false
        build()
        reload()
    }

    func runModal() {
        window.center()
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
        NSApp.runModal(for: window)
    }

    func windowWillClose(_ notification: Notification) {
        NSApp.stopModal()
    }

    private func section(_ title: String) -> NSTextField {
        let t = NSTextField(labelWithString: title)
        t.font = .boldSystemFont(ofSize: NSFont.systemFontSize)
        return t
    }

    private func listEditor(_ view: NSTextView) -> NSScrollView {
        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        view.isRichText = false
        view.font = .monospacedSystemFont(ofSize: NSFont.systemFontSize, weight: .regular)
        view.isAutomaticQuoteSubstitutionEnabled = false
        view.isAutomaticDashSubstitutionEnabled = false
        view.isAutomaticTextReplacementEnabled = false
        view.autoresizingMask = [.width]
        view.isVerticallyResizable = true
        scroll.documentView = view
        scroll.heightAnchor.constraint(equalToConstant: 80).isActive = true
        return scroll
    }

    /// A fixed-height scrolling box around `content` (top-aligned).
    private func scrollBox(_ content: NSView, height: CGFloat) -> NSScrollView {
        let scroll = NSScrollView()
        scroll.hasVerticalScroller = true
        scroll.borderType = .bezelBorder
        let doc = FlippedView()
        doc.translatesAutoresizingMaskIntoConstraints = false
        content.translatesAutoresizingMaskIntoConstraints = false
        doc.addSubview(content)
        scroll.documentView = doc
        NSLayoutConstraint.activate([
            content.leadingAnchor.constraint(equalTo: doc.leadingAnchor, constant: 4),
            content.trailingAnchor.constraint(equalTo: doc.trailingAnchor, constant: -4),
            content.topAnchor.constraint(equalTo: doc.topAnchor, constant: 4),
            content.bottomAnchor.constraint(equalTo: doc.bottomAnchor, constant: -4),
            doc.widthAnchor.constraint(equalTo: scroll.contentView.widthAnchor),
            scroll.heightAnchor.constraint(equalToConstant: height),
        ])
        return scroll
    }

    private func button(_ title: String, _ action: Selector) -> NSButton {
        let b = NSButton(title: title, target: self, action: action)
        b.bezelStyle = .rounded
        return b
    }

    private func build() {
        banner.drawsBackground = true
        banner.backgroundColor = NSColor.systemYellow.withAlphaComponent(0.35)
        banner.textColor = .labelColor
        banner.stringValue = "⚠️ 未設定連線密碼：白名單上嘅 IP 唔使密碼就可以連線同控制呢部 Mac，UDP 亦冇驗證。建議設定密碼。"

        newPassword.placeholderString = "新密碼（最少 \(ConnAuth.minPasswordLength) 個字，大細楷同符號）"
        confirmPassword.placeholderString = "再輸入一次"
        clearButton.target = self
        clearButton.action = #selector(clearPassword)
        clearButton.bezelStyle = .rounded

        let pwButtons = NSStackView(views: [button("設定／更改密碼", #selector(setPassword)), clearButton])
        let wlLabel = NSTextField(wrappingLabelWithString: "白名單：每行一個 IPv4。空白 = 任何 IP 都要密碼（要先設定密碼）。")
        let blLabel = NSTextField(wrappingLabelWithString: "黑名單：永遠拒絕（優先過白名單）。錯密碼太多次會自動加入。")
        let flLabel = NSTextField(wrappingLabelWithString: "最近 auth 失敗（最新喺最底，最多 \(AuthFailureLog.limit) 條）")
        for l in [wlLabel, blLabel, flLabel, clearNote] { l.textColor = .secondaryLabelColor }
        clearNote.stringValue = "白名單係空嘅時候唔可以清除密碼（清除之後冇 viewer 可以連線）。"

        blockRows.orientation = .vertical
        blockRows.alignment = .leading
        blockRows.spacing = 4
        addBlockField.placeholderString = "IPv4，例如 100.64.0.99"
        addBlockField.widthAnchor.constraint(equalToConstant: 200).isActive = true
        let addRow = NSStackView(views: [addBlockField, button("加入黑名單", #selector(addBlock))])
        failuresView.isEditable = false
        failuresView.isRichText = false
        failuresView.font = .monospacedSystemFont(ofSize: NSFont.smallSystemFontSize, weight: .regular)
        failuresView.autoresizingMask = [.width]
        let failuresScroll = NSScrollView()
        failuresScroll.hasVerticalScroller = true
        failuresScroll.borderType = .bezelBorder
        failuresScroll.documentView = failuresView
        failuresScroll.heightAnchor.constraint(equalToConstant: 100).isActive = true

        let stack = NSStackView(views: [
            banner,
            section("連線密碼"), passwordStatus, newPassword, confirmPassword, pwButtons, clearNote,
            section("白名單"), wlLabel, listEditor(whitelistView), button("儲存白名單", #selector(saveWhitelist)),
            section("黑名單"), blLabel, scrollBox(blockRows, height: 110), addRow,
            section("最近 auth 失敗"), flLabel, failuresScroll, button("重新整理", #selector(refresh)),
            status,
        ])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 8
        stack.edgeInsets = NSEdgeInsets(top: 16, left: 16, bottom: 16, right: 16)
        stack.translatesAutoresizingMaskIntoConstraints = false
        for v in stack.arrangedSubviews where !(v is NSButton) && !(v is NSStackView) {
            v.widthAnchor.constraint(equalTo: stack.widthAnchor, constant: -32).isActive = true
        }
        let content = NSView()
        content.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            stack.trailingAnchor.constraint(equalTo: content.trailingAnchor),
            stack.topAnchor.constraint(equalTo: content.topAnchor),
            stack.bottomAnchor.constraint(lessThanOrEqualTo: content.bottomAnchor),
            content.widthAnchor.constraint(equalToConstant: 520),
        ])
        window.contentView = content
    }

    private func reload() {
        let s = ConnectionSettings.state(url: url)
        banner.isHidden = s.passwordSet || !s.hasPlist
        passwordStatus.stringValue = !s.hasPlist ? "找不到 listen.plist：請先完成 JerisLink 安裝設定。"
            : s.passwordSet ? "狀態：已設定密碼" : "狀態：未設定密碼（過渡模式）"
        // Design §10: 清除密碼 only with a non-empty whitelist (the store
        // checks again under its lock, r2 item 3).
        clearButton.isEnabled = s.passwordSet && !s.whitelist.isEmpty
        clearNote.isHidden = !(s.passwordSet && s.whitelist.isEmpty)
        clearButton.toolTip = clearNote.isHidden ? nil : clearNote.stringValue
        whitelistView.string = s.whitelist.joined(separator: "\n")

        for v in blockRows.arrangedSubviews { blockRows.removeArrangedSubview(v); v.removeFromSuperview() }
        blockIPs = s.blocks.map(\.ip)
        if s.blocks.isEmpty {
            let none = NSTextField(labelWithString: "（冇封鎖）")
            none.textColor = .secondaryLabelColor
            blockRows.addArrangedSubview(none)
        }
        for (i, b) in s.blocks.enumerated() {
            let text = NSTextField(labelWithString:
                "\(b.ip)  ·  \(Self.timeFormat.string(from: b.at))  ·  \(ConnectionSettings.reasonText(b.reason))")
            text.font = .monospacedSystemFont(ofSize: NSFont.smallSystemFontSize, weight: .regular)
            let unblock = button("解除封鎖", #selector(unblockRow(_:)))
            unblock.tag = i
            unblock.controlSize = .small
            blockRows.addArrangedSubview(NSStackView(views: [text, unblock]))
        }

        let failures = AuthFailureLog.load(url: failureLogURL)
        failuresView.string = failures.isEmpty ? "（冇紀錄）" : failures.map {
            "\(Self.timeFormat.string(from: $0.at))  \($0.ip)  \(ConnectionSettings.failureReasonText($0.reason))（第 \($0.failures) 次）"
        }.joined(separator: "\n")
    }

    private func show(_ outcome: ConnectionSettings.Outcome) {
        status.stringValue = outcome.message
        status.textColor = outcome.ok ? .systemGreen : .systemRed
        reload()
    }

    @objc private func setPassword() {
        let pw = newPassword.stringValue
        let again = confirmPassword.stringValue
        newPassword.stringValue = ""
        confirmPassword.stringValue = ""
        status.stringValue = "處理中…"
        status.textColor = .secondaryLabelColor
        status.display()
        show(ConnectionSettings.setPassword(pw, confirm: again, url: url, store: store))
    }

    @objc private func clearPassword() {
        let alert = NSAlert()
        alert.messageText = "清除連線密碼？"
        alert.informativeText = "清除之後，白名單上嘅 IP 唔使密碼就可以連線，UDP 亦唔會再驗證。"
        alert.addButton(withTitle: "清除")
        alert.addButton(withTitle: "取消")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        show(ConnectionSettings.clearPassword(url: url, store: store))
    }

    @objc private func saveWhitelist() {
        show(ConnectionSettings.saveWhitelist(whitelistView.string, url: url))
    }

    @objc private func unblockRow(_ sender: NSButton) {
        guard blockIPs.indices.contains(sender.tag) else { return }
        show(ConnectionSettings.unblock(blockIPs[sender.tag], url: url))
    }

    @objc private func addBlock() {
        let text = addBlockField.stringValue
        let outcome = ConnectionSettings.block(text, url: url)
        if outcome.ok { addBlockField.stringValue = "" }
        show(outcome)
    }

    @objc private func refresh() {
        status.stringValue = ""
        reload()
    }
}

/// Top-left origin, so a scrolling list starts at its first row.
private final class FlippedView: NSView {
    override var isFlipped: Bool { true }
}

// MARK: Self-test

/// `JerisLinkHost --self-test` part for 連線設定: every write path on a
/// temporary listen.plist with an in-memory secret store.
enum ConnectionSettingsSelfTest {
    static func run() -> Int32 {
        var failures = 0
        func expect(_ ok: Bool, _ name: String) {
            print("\(ok ? "PASS" : "FAIL") conn-settings: \(name)")
            if !ok { failures += 1 }
        }
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("jl-connsettings-\(getpid())-\(UUID().uuidString.prefix(6))")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("listen.plist")
        func write(_ d: [String: Any]) {
            let data = try! PropertyListSerialization.data(fromPropertyList: d, format: .xml, options: 0)
            try! data.write(to: url)
        }
        let store = MemorySecretStore()
        let it: UInt32 = 1000  // fast PBKDF2 for the test

        // Nothing there.
        expect(!ConnectionSettings.state(url: url).hasPlist, "no listen.plist: state says so")
        expect(!ConnectionSettings.setPassword("Abcdefgh1!x", confirm: "Abcdefgh1!x", url: url, store: store, iterations: it).ok
               && store.load() == nil, "no listen.plist: no password set, Keychain untouched")

        // A migrated 0.3 plist.
        write(["mode": "tailnet", "bindIP": "100.64.0.10", "clientIP": "100.64.0.20",
               "allowedIPs": ["100.64.0.20"], "allowedIPsSource": "clientIP", "passwordSet": false])
        var s = ConnectionSettings.state(url: url)
        expect(s.hasPlist && !s.passwordSet && s.whitelist == ["100.64.0.20"] && s.followsClientIP,
               "migrated plist: whitelist follows clientIP, no password (banner shown)")

        // Password rules.
        expect(!ConnectionSettings.setPassword("Abcdefgh1!x", confirm: "Abcdefgh1!y", url: url, store: store, iterations: it).ok,
               "set: two different entries refused")
        let weak = ConnectionSettings.setPassword("short", confirm: "short", url: url, store: store, iterations: it)
        expect(!weak.ok && weak.message.contains("最少") && store.load() == nil, "set: weak password refused, Keychain untouched")

        // Set.
        let set = ConnectionSettings.setPassword("Abcdefgh1!x", confirm: "Abcdefgh1!x", url: url, store: store, iterations: it)
        let first = store.load()
        s = ConnectionSettings.state(url: url)
        expect(set.ok && s.passwordSet && first != nil, "set: Keychain written and passwordSet = true")
        if let first {
            expect(ConnAuth.deriveKey(password: "Abcdefgh1!x", salt: first.salt, iterations: first.iterations) == first.key,
                   "set: stored K is PBKDF2 of the password")
            expect(AuthPolicy.resolve(plist: ConnectionSettings.read(url: url), clientIP: "100.64.0.20", secretLoaded: true)
                   == .password(whitelist: ["100.64.0.20"]), "set: the control service's policy is now password")
        }

        // Change: same host id, new salt.
        let change = ConnectionSettings.setPassword("Zyxwvuts9#q", confirm: "Zyxwvuts9#q", url: url, store: store, iterations: it)
        let second = store.load()
        expect(change.ok && second?.hostID == first?.hostID && second?.salt != first?.salt,
               "change: host id kept, new salt (remembered viewers must re-enter)")

        // Whitelist edits.
        let bad = ConnectionSettings.saveWhitelist("100.64.0.20\nnot-an-ip", url: url)
        expect(!bad.ok && ConnectionSettings.state(url: url).whitelist == ["100.64.0.20"], "whitelist: invalid entry refused, nothing written")
        let wl = ConnectionSettings.saveWhitelist("100.64.0.21, 100.64.0.22\n100.64.0.21", url: url)
        let afterWL = ConnectionSettings.read(url: url) ?? [:]
        expect(wl.ok && afterWL["allowedIPs"] as? [String] == ["100.64.0.21", "100.64.0.22"]
               && afterWL["clientIP"] == nil && afterWL[ListenMigration.sourceKey] == nil,
               "whitelist: saved, deduped; clientIP and allowedIPsSource removed")
        let backupURL = URL(fileURLWithPath: url.path + ".pre-0.4")
        let backup = ConnectionSettings.read(url: backupURL)
        expect(backup?["clientIP"] as? String == "100.64.0.20", "whitelist: listen.plist.pre-0.4 backup kept with the old clientIP")
        expect(ListenConfig.resolve(plist: afterWL, conf: (nil, nil), local: [LocalAddress(interface: "utun4", ip: "100.64.0.10")])
               == .ready(ListenEndpoint(mode: .tailnet, bindIP: "100.64.0.10", clientIP: "", source: "listen.plist")),
               "whitelist: the endpoint still resolves without clientIP")
        expect(ConnectionSettings.saveWhitelist("", url: url).ok && ConnectionSettings.state(url: url).whitelist.isEmpty,
               "whitelist: empty allowed with a password (any IP must authenticate)")

        // Clear refused with an empty whitelist.
        let clearEmpty = ConnectionSettings.clearPassword(url: url, store: store)
        expect(!clearEmpty.ok && ConnectionSettings.state(url: url).passwordSet && store.load() != nil,
               "clear: refused with an empty whitelist, password kept")
        _ = ConnectionSettings.saveWhitelist("100.64.0.21", url: url)
        let clear = ConnectionSettings.clearPassword(url: url, store: store)
        s = ConnectionSettings.state(url: url)
        expect(clear.ok && !s.passwordSet && store.load() == nil, "clear: passwordSet false and Keychain item gone")
        expect(!ConnectionSettings.saveWhitelist("", url: url).ok && ConnectionSettings.state(url: url).whitelist == ["100.64.0.21"],
               "whitelist: empty refused without a password")
        expect(AuthPolicy.resolve(plist: ConnectionSettings.read(url: url), clientIP: nil, secretLoaded: false)
               == .transition(whitelist: ["100.64.0.21"]), "clear: the control service's policy is transition")

        // Blacklist.
        expect(ConnectionSettings.saveBlacklist("100.64.0.99\n100.64.0.98", url: url).ok
               && ConnectionSettings.state(url: url).blacklist == ["100.64.0.99", "100.64.0.98"], "blacklist: two added")
        expect(!ConnectionSettings.saveBlacklist("999.1.1.1", url: url).ok, "blacklist: invalid entry refused")
        expect(ConnectionSettings.saveBlacklist("100.64.0.98", url: url).ok
               && ConnectionSettings.state(url: url).blacklist == ["100.64.0.98"], "blacklist: one removed")
        let keys = ConnectionSettings.read(url: url) ?? [:]
        expect(keys["bindIP"] as? String == "100.64.0.10" && keys["mode"] as? String == "tailnet",
               "other listen.plist keys untouched")

        // Plist write fails: the Keychain goes back.
        let roStore = MemorySecretStore()
        let roDir = dir.appendingPathComponent("ro")
        try? FileManager.default.createDirectory(at: roDir, withIntermediateDirectories: true)
        let roURL = roDir.appendingPathComponent("listen.plist")
        try? (try? PropertyListSerialization.data(fromPropertyList: ["mode": "tailnet", "allowedIPs": ["100.64.0.20"]] as [String: Any],
                                                   format: .xml, options: 0))?.write(to: roURL)
        _ = ListenConfig.withFileLock(roURL) { () }  // the lock files exist before the folder goes read-only
        _ = ListenConfig.withFileLock(URL(fileURLWithPath: roURL.path + ".settings")) { () }
        chmod(roDir.path, 0o500)
        let roSet = ConnectionSettings.setPassword("Abcdefgh1!x", confirm: "Abcdefgh1!x", url: roURL, store: roStore, iterations: it)
        chmod(roDir.path, 0o700)
        expect(!roSet.ok && roStore.load() == nil, "set: plist not writable, Keychain rolled back")

        // r2 item 6: block rows with time and reason, unblock one, add one.
        let blocks = ConnectionSettings.state(url: url).blocks
        expect(blocks.count == 1 && blocks.first?.ip == "100.64.0.98" && blocks.first?.reason == "manual",
               "blocks: each block keeps its time and reason")
        expect(ConnectionSettings.reasonText("20 wrong passwords") == "錯密碼 20 次"
               && ConnectionSettings.reasonText("manual") == "人手加入", "blocks: reason text")
        expect(!ConnectionSettings.block("1.2.3", url: url).ok, "blocks: add refuses a non-IPv4")
        expect(ConnectionSettings.block(" 100.64.0.97 ", url: url).ok
               && ConnectionSettings.state(url: url).blacklist == ["100.64.0.98", "100.64.0.97"], "blocks: add one by hand")
        expect(ConnectionSettings.unblock("100.64.0.98", url: url).ok
               && ConnectionSettings.state(url: url).blacklist == ["100.64.0.97"], "blocks: 解除封鎖 removes only that row")

        // r2 item 3: the clear condition is checked on the plist it writes.
        _ = ConnectionSettings.setPassword("Abcdefgh1!x", confirm: "Abcdefgh1!x", url: url, store: store, iterations: it)
        var raced = ConnectionSettings.read(url: url) ?? [:]
        raced["allowedIPs"] = [String]()
        write(raced)
        let clearRaced = ConnectionSettings.clearPassword(url: url, store: store)
        expect(!clearRaced.ok && clearRaced.message == ConnectionSettings.emptyWhitelistClearRefusal
               && ConnectionSettings.state(url: url).passwordSet && store.load() != nil,
               "clear: whitelist emptied after the window read it: refused under the lock, password kept")
        _ = ConnectionSettings.saveWhitelist("100.64.0.21", url: url)

        // r2 item 3: concurrent set / clear never leave passwordSet without the Keychain item.
        var mismatches = 0
        for round in 0..<20 {
            DispatchQueue.concurrentPerform(iterations: 6) { i in
                if (i + round) % 2 == 0 {
                    _ = ConnectionSettings.setPassword("Abcdefgh1!x", confirm: "Abcdefgh1!x", url: url, store: store, iterations: it)
                } else {
                    _ = ConnectionSettings.clearPassword(url: url, store: store)
                }
            }
            if ConnectionSettings.state(url: url).passwordSet != (store.load() != nil) { mismatches += 1 }
        }
        expect(mismatches == 0, "concurrent set/clear: passwordSet matches the Keychain after every round (mismatches=\(mismatches))")
        let held = ConnectionSettings.transaction(url: url) {
            ConnectionSettings.transaction(url: url, wait: 0.1) { .ok("inner") }
        }
        expect(!held.ok, "transaction: a second change waits for the first and gives up after its wait")

        // r2 item 6: recent auth failures.
        let flURL = dir.appendingPathComponent("auth-failures.plist")
        let fl = AuthFailureLog(url: flURL)
        for n in 1...25 { fl.record(ip: "100.64.0.\(n)", reason: "wrong_password", failures: n) }
        fl.flush()
        let recs = AuthFailureLog.load(url: flURL)
        var st = stat()
        expect(recs.count == AuthFailureLog.limit && recs.first?.ip == "100.64.0.6" && recs.last?.failures == 25,
               "failure log: newest \(AuthFailureLog.limit) kept, oldest dropped")
        expect(stat(flURL.path, &st) == 0 && st.st_mode & 0o777 == 0o600, "failure log: file mode 0600")
        return failures == 0 ? 0 : 1
    }
}
