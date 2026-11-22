import AppKit
import Foundation
import Darwin

/// Where a drop on the viewer (purpose=send, F4) lands on the Mac, and the
/// REVEAL (0x5C) that opens it again (design r2 D11, D12, 3b).
///
/// - Destination: `~/Downloads/JerisLink`. Downloads sits behind macOS
///   "Files & Folders": the first mkdir/open shows a prompt and blocks in the
///   kernel until someone clicks, so the open goes through its own
///   `FileOpenGate` and the session thread waits at most 2.5 s. Still
///   waiting: the viewer hears `macPermission` and the user drops again after
///   clicking Allow. Refused (EPERM/EACCES): `~/JerisLink Received`, which
///   needs no permission.
/// - Items are moved out of staging with RENAME_EXCL, so nothing already in
///   the folder is ever replaced; a clash becomes Finder-style `name 2.ext`.
/// - Finder opens the folder (never the files) when a send completes, and
///   again on REVEAL. The viewer never sends a path: REVEAL names a transfer
///   and the host opens the folder it used for it.
///
/// Logs carry no names (D15).
final class FileSendFolder: @unchecked Sendable {  // mutable state behind `lock`
    enum Resolved {
        case fd(Int32, URL)   // caller closes the fd
        case pending          // a macOS privacy prompt is most likely up
        case failed
    }

    let primary: URL
    let fallback: URL
    private let gate: FileOpenGate
    private let fallbackOpener: FileOpenGate.Opener
    private let openFolder: @Sendable (URL) -> Void
    private let lock = NSLock()
    private var byTransfer: [UInt32: URL] = [:]
    private var order: [UInt32] = []
    private var last: URL?
    private static let remembered = 32

    static let shared = FileSendFolder()

    static var defaultPrimary: URL {
        let downloads = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Downloads", isDirectory: true)
        return downloads.appendingPathComponent("JerisLink", isDirectory: true)
    }

    static var defaultFallback: URL {
        URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("JerisLink Received", isDirectory: true)
    }

    /// mkdir (one level, the parent must exist) then open the folder itself
    /// with no symlink at the leaf.
    static let folderOpener: FileOpenGate.Opener = { path in
        if mkdir(path, 0o755) != 0, errno != EEXIST { return (-1, errno) }
        let fd = Darwin.open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        return (fd, fd >= 0 ? 0 : errno)
    }

    static let finderOpen: @Sendable (URL) -> Void = { url in
        Task { @MainActor in _ = NSWorkspace.shared.open(url) }
    }

    init(primary: URL = FileSendFolder.defaultPrimary, fallback: URL = FileSendFolder.defaultFallback,
         primaryOpener: @escaping FileOpenGate.Opener = FileSendFolder.folderOpener,
         fallbackOpener: @escaping FileOpenGate.Opener = FileSendFolder.folderOpener,
         openFolder: @escaping @Sendable (URL) -> Void = FileSendFolder.finderOpen) {
        self.primary = primary
        self.fallback = fallback
        self.gate = FileOpenGate(opener: primaryOpener)
        self.fallbackOpener = fallbackOpener
        self.openFolder = openFolder
    }

    /// Opens the destination folder for a new send, creating it if needed.
    func resolve(waitMs: Int = 2500) -> Resolved {
        switch gate.open(primary.path, waitMs: waitMs) {
        case .fd(let fd):
            return .fd(fd, primary)
        case .pending:
            return .pending
        case .denied, .failed:
            // Downloads refused (or missing): the home folder needs no prompt.
            let (fd, _) = fallbackOpener(fallback.path)
            return fd >= 0 ? .fd(fd, fallback) : .failed
        }
    }

    /// Moves each top-level item from `fromFD` into `destFD`, never replacing
    /// anything: "name", then "name 2", "name 3", ... Returns how many moved;
    /// stops at the first item that cannot be moved.
    /// r13: `live` is asked right before each item's rename; false stops
    /// (ECANCELED) with nothing more moved.
    static func moveAll(_ names: [String], from fromFD: Int32, to destFD: Int32,
                        live: () -> Bool = { true }) -> (moved: Int, renamed: Int, error: Int32) {
        var moved = 0
        var renamed = 0
        for name in names {
            guard live() else { return (moved, renamed, ECANCELED) }
            var n = 1
            while true {
                let target = n == 1 ? name : FilePathSafety.clashName(name, attempt: n)
                if renameatx_np(fromFD, name, destFD, target, UInt32(RENAME_EXCL)) == 0 {
                    moved += 1
                    if n > 1 { renamed += 1 }
                    break
                }
                let err = errno
                guard err == EEXIST, n < 10_000 else { return (moved, renamed, err) }
                n += 1
            }
        }
        return (moved, renamed, 0)
    }

    /// A send finished into `folder`: remember it for REVEAL and open it.
    func completed(transfer: UInt32, folder: URL) {
        lock.lock()
        if byTransfer.updateValue(folder, forKey: transfer) == nil { order.append(transfer) }
        while order.count > Self.remembered { byTransfer.removeValue(forKey: order.removeFirst()) }
        last = folder
        lock.unlock()
        openFolder(folder)
    }

    /// REVEAL: opens the folder `transfer` went to. An id this process does
    /// not know (the host restarted) opens the folder sends go to now, if it
    /// exists. Runs off the session thread: a stat under Downloads can wait
    /// on a privacy prompt. `done` (tests) hears whether a folder opened.
    func reveal(transfer: UInt32, done: (@Sendable (Bool) -> Void)? = nil) {
        lock.lock()
        let known = byTransfer[transfer]
        let recent = last
        lock.unlock()
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            // Not `done?(revealNow(...))`: optional chaining would skip the
            // reveal itself when no callback is given.
            let opened = revealNow(transfer: transfer, known: known, recent: recent)
            done?(opened)
        }
    }

    private func revealNow(transfer: UInt32, known: URL?, recent: URL?) -> Bool {
        let fm = FileManager.default
        var isDir: ObjCBool = false
        let candidates = [known, recent, primary, fallback].compactMap { $0 }
        guard let folder = candidates.first(where: { fm.fileExists(atPath: $0.path, isDirectory: &isDir) && isDir.boolValue }) else {
            print("file.reveal=none transfer=\(transfer)")
            return false
        }
        print("file.reveal=\(known != nil ? "ok" : "unknown") transfer=\(transfer)")
        openFolder(folder)
        return true
    }
}
