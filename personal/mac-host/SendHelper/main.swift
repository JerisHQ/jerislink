import AppKit
import Darwin

/// "JerisLink Send.app": the Finder Service "Send to JerisLink" (F5b,
/// design r2 section 3c). Lives inside JerisLink.app at
/// Contents/Library/Helpers/ with its own bundle id, so the control agent
/// can tell it apart by code signature.
///
/// Finder gives it the selected files. It refuses folders, opens each file
/// itself (no symlinks) and hands the open files to the control agent over
/// the send socket (SendSocketWire.swift, compiled in). The agent offers
/// them to the connected PC, which saves them to Downloads\JerisLink. Only a
/// reply other than ok shows an alert. Then it quits.

enum SendHelper {
    static let maxFiles = SendWire.maxFiles

    enum Prepared {
        case files([(name: [UInt8], fd: Int32)])
        case refused(String)
    }

    /// Checks and opens the selection. Every descriptor in `.files` is the
    /// caller's to close.
    static func prepare(_ paths: [String]) -> Prepared {
        guard !paths.isEmpty else { return .refused("Select one or more files to send.") }
        guard paths.count <= maxFiles else { return .refused("Send at most 1,000 files at a time.") }
        var st = stat()
        for p in paths where lstat(p, &st) == 0 && (st.st_mode & S_IFMT) == S_IFDIR {
            return .refused("Folders aren't supported yet.")
        }
        var out: [(name: [UInt8], fd: Int32)] = []
        func fail(_ msg: String) -> Prepared {
            for f in out { close(f.fd) }
            return .refused(msg)
        }
        for p in paths {
            let leaf = (p as NSString).lastPathComponent.precomposedStringWithCanonicalMapping
            let fd = open(p, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else {
                return fail(errno == ELOOP ? "\u{201C}\(leaf)\u{201D} is a link. Send the original file instead."
                                           : "Couldn't read \u{201C}\(leaf)\u{201D}.")
            }
            guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else {
                close(fd)
                return fail("\u{201C}\(leaf)\u{201D} isn't a regular file.")
            }
            out.append((Array(leaf.utf8), fd))
        }
        return .files(out)
    }

    /// The alert for an agent reply; nil for ok.
    static func message(for reply: String?) -> String? {
        guard let reply else { return "JerisLink is not running on this Mac. Open JerisLink, then try again." }
        switch SendWire.Reply(rawValue: reply) {
        case .ok?: return nil
        case .notConnected?: return "JerisLink is not connected. Connect from your PC first, then try again."
        case .busy?: return "A transfer is already running. Wait for it to finish, then try again."
        case .oldViewer?: return "Update JerisLink on this PC to receive files from the Mac."
        case .tooBig?: return "That's too much to send at once (at most 1,000 files and 20 GB)."
        case .badName?: return "A file name can't be used on the PC. Rename the file, then try again."
        case .noSpace?: return "The PC couldn't save the files. Check the free space in Downloads."
        default: return "The files couldn't be sent. Try again."
        }
    }

    /// Sends `paths`; returns the alert to show, or nil.
    static func send(_ paths: [String]) -> String? {
        switch prepare(paths) {
        case .refused(let msg): return msg
        case .files(let files):
            defer { for f in files { close(f.fd) } }
            return message(for: SendWire.submit(files))
        }
    }

    /// Up to 1,000 files are open at once; the default soft limit is 256.
    static func raiseOpenFileLimit() {
        var rl = rlimit()
        guard getrlimit(RLIMIT_NOFILE, &rl) == 0, rl.rlim_cur < 4096 else { return }
        rl.rlim_cur = min(4096, rl.rlim_max)
        _ = setrlimit(RLIMIT_NOFILE, &rl)
    }

    static func alert(_ text: String) {
        NSApp.activate(ignoringOtherApps: true)
        let a = NSAlert()
        a.messageText = "Send to JerisLink"
        a.informativeText = text
        a.alertStyle = .warning
        a.addButton(withTitle: "OK")
        a.runModal()
    }

    static func selfTest() -> Bool {
        var ok = true
        func expect(_ c: Bool, _ name: String) {
            print("\(c ? "PASS" : "FAIL") send helper: \(name)")
            if !c { ok = false }
        }
        let dir = NSTemporaryDirectory() + "jl-send-helper-\(getpid())"
        try? FileManager.default.createDirectory(atPath: dir + "/folder", withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let file = dir + "/Cafe\u{0301}.txt"
        FileManager.default.createFile(atPath: file, contents: Data("hi".utf8))
        try? FileManager.default.createSymbolicLink(atPath: dir + "/link.txt", withDestinationPath: file)

        if case .refused(let m) = prepare([file, dir + "/folder"]) { expect(m == "Folders aren't supported yet.", "folders refused") }
        else { expect(false, "folders refused") }
        if case .refused(let m) = prepare([dir + "/link.txt"]) { expect(m.contains("is a link"), "symlink refused") }
        else { expect(false, "symlink refused") }
        if case .refused(let m) = prepare(Array(repeating: file, count: maxFiles + 1)) { expect(m.contains("1,000"), "over 1,000 refused") }
        else { expect(false, "over 1,000 refused") }
        if case .files(let f) = prepare([file]) {
            expect(f.count == 1 && f[0].name == Array("Caf\u{00E9}.txt".utf8) && f[0].fd >= 0, "file opened, name NFC")
            f.forEach { close($0.fd) }
        } else { expect(false, "file opened") }
        expect(message(for: "ok") == nil, "ok shows nothing")
        for r in SendWire.Reply.allCases where r != .ok {
            expect(message(for: r.rawValue) != nil, "\(r.rawValue) shows an alert")
        }
        expect(message(for: nil)?.contains("not running") == true, "no agent: not running")
        expect(message(for: "something_new") != nil, "unknown reply shows an alert")
        // Agent not listening at a missing path: nil reply, never a hang.
        expect(SendWire.submit([], path: dir + "/none.sock", timeout: 2) == nil, "missing socket answers nil")
        let services = Bundle.main.object(forInfoDictionaryKey: "NSServices") as? [[String: Any]]
        if Bundle.main.bundleIdentifier == SendWire.helperBundleID {
            expect(services?.first?["NSMessage"] as? String == "sendToJerisLink", "Info.plist declares the service")
        }
        print(ok ? "send helper self-test: ok" : "send helper self-test: FAILED")
        return ok
    }
}

final class ServiceProvider: NSObject {
    private(set) var handled = false

    /// NSMessage "sendToJerisLink" (selector sendToJerisLink:userData:error:).
    @objc func sendToJerisLink(_ pboard: NSPasteboard, userData: String?,
                               error: AutoreleasingUnsafeMutablePointer<NSString?>) {
        handled = true
        let urls = pboard.readObjects(forClasses: [NSURL.self], options: [.urlReadingFileURLsOnly: true]) as? [URL] ?? []
        let paths = urls.filter(\.isFileURL).map { $0.standardizedFileURL.path }
        if let text = SendHelper.send(paths) { SendHelper.alert(text) }
        // Let the service call return to Finder before quitting.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { NSApp.terminate(nil) }
    }
}

if CommandLine.arguments.contains("--self-test") {
    exit(SendHelper.selfTest() ? 0 : 1)
}
if CommandLine.arguments.contains("--version") {
    let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "dev"
    print("JerisLink Send v\(version)")
    exit(0)
}

SendHelper.raiseOpenFileLimit()
let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let provider = ServiceProvider()
app.servicesProvider = provider
// Opened by hand (or by Launch Services) with nothing to send: quit.
DispatchQueue.main.asyncAfter(deadline: .now() + 20) {
    if !provider.handled { NSApp.terminate(nil) }
}
app.run()
