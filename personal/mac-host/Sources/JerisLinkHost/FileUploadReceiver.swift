import Foundation
import Darwin
import CryptoKit

/// Receives Windows->Mac paste uploads on one file session (design r2, F2).
///
/// Wire order, sender (viewer) -> receiver (host):
///   OFFER(paste) ENTRY x entries   -> REPLY ok | REJECT status
///   DATA... FILE_END per file, files in entry order, dirs carry no data
///                                  <- PROGRESS(committed) every 1 MiB and per FILE_END
///                                  <- RESULT(ok, files) once the pasteboard holds the URLs
/// Either side may CANCEL; the host answers RESULT(cancelled).
///
/// Staging: `<root>/<uuid>/parts/<index>.jlpart` is written with O_EXCL,
/// hashed, stamped with mtime and `com.apple.quarantine`, then renamed with
/// RENAME_EXCL into `<root>/<uuid>/files/<path>`. Every directory under the
/// transfer folder is opened relative to its parent with O_NOFOLLOW, so a
/// received path can never leave it. Partial transfers are removed at once;
/// the last completed paste stays until the next one (Finder copies from
/// it) or the 24 h startup sweep.
///
/// Runs on the file session's own thread. The only main-thread work is the
/// pasteboard write, through `ClipboardBackend`. Logs carry no names (D15).
final class FileUploadReceiver {
    typealias Message = FileProto.Message

    static let progressStep: UInt64 = 1 << 20
    /// Free space kept on the staging volume beyond the offer.
    static let freeSpaceMargin: UInt64 = 1 << 30
    static let sweepAge: TimeInterval = 24 * 3600

    static var defaultRoot: URL {
        let caches = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Caches")
        return caches.appendingPathComponent("org.jeris.jerislink/incoming", isDirectory: true)
    }

    struct Entry {
        let kind: UInt8
        let size: UInt64
        let mtime: Int64
        let path: String   // validated, NFC
    }

    private enum State {
        case idle
        case collecting(transfer: UInt32, entries: UInt32, total: UInt64, list: [Entry], keys: Set<String>)
        case receiving(Transfer)
    }

    private final class Transfer {
        let id: UInt32
        let entries: [Entry]
        let total: UInt64
        let dir: URL
        let dirFD: Int32
        let partsFD: Int32
        let filesFD: Int32
        var cursor = 0              // next entry index that may carry data
        var fileFD: Int32 = -1
        var received: UInt64 = 0    // bytes of entries[cursor]
        var hasher = SHA256()
        var committed: UInt64 = 0
        var lastProgress: UInt64 = 0
        var filesOK: UInt32 = 0

        init(id: UInt32, entries: [Entry], total: UInt64, dir: URL, dirFD: Int32, partsFD: Int32, filesFD: Int32) {
            self.id = id; self.entries = entries; self.total = total
            self.dir = dir; self.dirFD = dirFD; self.partsFD = partsFD; self.filesFD = filesFD
        }
    }

    /// What the session loop must do after a message.
    struct Step {
        var send: [Message] = []
        /// Close the session (malformed or out-of-order transfer traffic).
        var close: String?
    }

    private let root: URL
    private let clipboard: ClipboardBackend
    private let freeSpace: (URL) -> UInt64?
    private var state = State.idle
    /// A transfer this side ended (failed or cancelled): the sender may still
    /// have DATA in flight for it, which is dropped instead of closing.
    private var ended: UInt32?
    /// The last completed paste's folder: Finder may still copy from it.
    private static let keptLock = NSLock()
    nonisolated(unsafe) private static var keptDir: URL?
    nonisolated(unsafe) private static var sweptRoots: Set<String> = []

    private(set) var completed: UInt64 = 0
    private(set) var failed: UInt64 = 0
    private(set) var cancelled: UInt64 = 0
    private(set) var bytesIn: UInt64 = 0

    init(root: URL = FileUploadReceiver.defaultRoot, clipboard: ClipboardBackend,
         freeSpace: @escaping (URL) -> UInt64? = FileUploadReceiver.availableBytes) {
        self.root = root
        self.clipboard = clipboard
        self.freeSpace = freeSpace
        Self.sweepOnce(root)
    }

    deinit { abort(reason: "session_end") }

    var isActive: Bool {
        if case .idle = state { return false }
        return true
    }

    // MARK: Messages

    func handle(_ msg: Message) -> Step {
        if let ended {
            switch msg {
            case .entry(let t, _, _, _, _, _), .data(let t, _, _, _), .fileEnd(let t, _, _):
                if t == ended { return Step() }
            default: break
            }
        }
        switch msg {
        case let .offer(t, purpose, entries, total):
            return offer(t, purpose: purpose, entries: entries, total: total)
        case let .entry(t, index, kind, size, mtime, path):
            return entry(t, index: index, kind: kind, size: size, mtime: mtime, raw: path)
        case let .data(t, index, offset, bytes):
            return data(t, index: index, offset: offset, bytes: bytes)
        case let .fileEnd(t, index, sha):
            return fileEnd(t, index: index, sha: sha)
        case let .cancel(t, _):
            return cancel(t)
        default:
            return Step()
        }
    }

    /// The session is ending (peer closed, drop, idle, stop): remove partial data.
    func abort(reason: String) {
        switch state {
        case .idle:
            return
        case .collecting:
            state = .idle
        case .receiving(let tr):
            failed += 1
            print("file.upload=failed transfer=\(tr.id) reason=\(reason) files_ok=\(tr.filesOK)")
            discard(tr)
            state = .idle
        }
    }

    private func offer(_ t: UInt32, purpose: UInt8, entries: UInt32, total: UInt64) -> Step {
        func reject(_ status: UInt8) -> Step { Step(send: [.reply(transfer: t, status: status)]) }
        guard case .idle = state else { return reject(FileProto.Status.busy) }
        guard purpose == FileProto.Purpose.paste else { return reject(FileProto.Status.denied) }
        guard entries >= 1, entries <= FileProto.maxEntries, total <= FileProto.maxTotalBytes else {
            return reject(FileProto.Status.tooBig)
        }
        ended = nil
        state = .collecting(transfer: t, entries: entries, total: total, list: [], keys: [])
        return Step()
    }

    private func entry(_ t: UInt32, index: UInt32, kind: UInt8, size: UInt64, mtime: Int64, raw: [UInt8]) -> Step {
        guard case .collecting(let id, let count, let total, var list, var keys) = state, id == t else {
            return Step(close: "unexpected_entry")
        }
        func reject(_ status: UInt8) -> Step {
            state = .idle
            ended = t
            print("file.upload=rejected transfer=\(t) status=\(status)")
            return Step(send: [.reply(transfer: t, status: status)])
        }
        guard index == UInt32(list.count) else { return Step(close: "entry_order") }
        guard case .ok(let path) = FilePathSafety.validate(raw) else { return reject(FileProto.Status.badPath) }
        guard kind == FileProto.EntryKind.file || size == 0 else { return reject(FileProto.Status.badPath) }
        // APFS is case-insensitive by default, and so is the sender: one name per folder.
        let key = path.lowercased()
        guard !keys.contains(key) else { return reject(FileProto.Status.badPath) }
        // A file cannot also be a folder another entry lives in.
        let parents = Self.parentPaths(of: key)
        for p in parents where keys.contains(p) {
            guard let owner = list.first(where: { $0.path.lowercased() == p }), owner.kind == FileProto.EntryKind.dir else {
                return reject(FileProto.Status.badPath)
            }
        }
        keys.insert(key)
        list.append(Entry(kind: kind, size: size, mtime: mtime, path: path))
        if UInt32(list.count) < count {
            state = .collecting(transfer: id, entries: count, total: total, list: list, keys: keys)
            return Step()
        }
        // Last entry: check the offer as a whole, then accept.
        var sum: UInt64 = 0
        for e in list {
            let (s, over) = sum.addingReportingOverflow(e.size)
            guard !over else { return reject(FileProto.Status.tooBig) }
            sum = s
        }
        guard sum == total else { return reject(FileProto.Status.badPath) }
        // A file whose path is under another file's path is caught by mkdirat at write time.
        if let free = freeSpace(root), free < total &+ Self.freeSpaceMargin { return reject(FileProto.Status.noSpace) }
        guard let tr = makeTransfer(id: t, entries: list, total: total) else { return reject(FileProto.Status.failed) }
        state = .receiving(tr)
        print("file.upload=accepted transfer=\(t) entries=\(list.count) bytes=\(total)")
        var step = Step(send: [.reply(transfer: t, status: FileProto.Status.ok)])
        step.send += advance(tr)
        return step
    }

    private func data(_ t: UInt32, index: UInt32, offset: UInt64, bytes: [UInt8]) -> Step {
        guard case .receiving(let tr) = state, tr.id == t else { return Step(close: "unexpected_data") }
        guard Int(index) == tr.cursor, tr.cursor < tr.entries.count else { return Step(close: "data_order") }
        let e = tr.entries[tr.cursor]
        guard e.kind == FileProto.EntryKind.file, offset == tr.received,
              UInt64(bytes.count) <= e.size - tr.received else { return Step(close: "data_range") }
        if tr.fileFD < 0, !openPart(tr) { return fail(tr, "open") }
        let ok = bytes.withUnsafeBytes { buf -> Bool in
            var off = 0
            while off < buf.count {
                let n = Darwin.write(tr.fileFD, buf.baseAddress!.advanced(by: off), buf.count - off)
                if n < 0 { if errno == EINTR { continue }; return false }
                off += n
            }
            return true
        }
        guard ok else { return fail(tr, "write") }
        tr.hasher.update(data: bytes)
        tr.received += UInt64(bytes.count)
        tr.committed += UInt64(bytes.count)
        bytesIn += UInt64(bytes.count)
        var step = Step()
        if tr.committed - tr.lastProgress >= Self.progressStep {
            tr.lastProgress = tr.committed
            step.send.append(.progress(transfer: t, committed: tr.committed))
        }
        return step
    }

    private func fileEnd(_ t: UInt32, index: UInt32, sha: [UInt8]) -> Step {
        guard case .receiving(let tr) = state, tr.id == t else { return Step(close: "unexpected_end") }
        guard Int(index) == tr.cursor, tr.cursor < tr.entries.count,
              tr.entries[tr.cursor].kind == FileProto.EntryKind.file else { return Step(close: "end_order") }
        let e = tr.entries[tr.cursor]
        guard tr.received == e.size else { return fail(tr, "short") }
        if tr.fileFD < 0, !openPart(tr) { return fail(tr, "open") }
        let digest = Array(tr.hasher.finalize())
        guard digest == sha else { return fail(tr, "hash") }
        guard finishPart(tr, entry: e) else { return fail(tr, "commit") }
        tr.filesOK += 1
        tr.cursor += 1
        tr.received = 0
        tr.hasher = SHA256()
        tr.lastProgress = tr.committed
        var step = Step(send: [.progress(transfer: t, committed: tr.committed)])
        step.send += advance(tr)
        return step
    }

    private func cancel(_ t: UInt32) -> Step {
        switch state {
        case .collecting(let id, _, _, _, _) where id == t:
            state = .idle
        case .receiving(let tr) where tr.id == t:
            discard(tr)
            state = .idle
        default:
            return Step()
        }
        cancelled += 1
        ended = t
        print("file.upload=cancelled transfer=\(t)")
        return Step(send: [.result(transfer: t, status: FileProto.Status.cancelled, filesOK: 0)])
    }

    /// Skip directory entries (made at accept time); finish when all are done.
    private func advance(_ tr: Transfer) -> [Message] {
        while tr.cursor < tr.entries.count, tr.entries[tr.cursor].kind == FileProto.EntryKind.dir { tr.cursor += 1 }
        guard tr.cursor == tr.entries.count else { return [] }
        // Every entry is in place: hand the top-level items to the pasteboard.
        var tops: [String] = []
        for e in tr.entries {
            let first = String(e.path.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)[0])
            if !tops.contains(first) { tops.append(first) }
        }
        let filesDir = tr.dir.appendingPathComponent("files", isDirectory: true)
        let urls = tops.map { filesDir.appendingPathComponent($0) }
        guard clipboard.writeFileURLs(urls) != nil else { return [failMessage(tr, "pasteboard")] }
        let ok = tr.filesOK
        closeFDs(tr)
        Self.keep(tr.dir)
        state = .idle
        completed += 1
        print("file.upload=done transfer=\(tr.id) files=\(ok) bytes=\(tr.committed)")
        return [.result(transfer: tr.id, status: FileProto.Status.ok, filesOK: ok)]
    }

    private func fail(_ tr: Transfer, _ why: String) -> Step {
        Step(send: [failMessage(tr, why)])
    }

    private func failMessage(_ tr: Transfer, _ why: String) -> Message {
        failed += 1
        print("file.upload=failed transfer=\(tr.id) reason=\(why) files_ok=\(tr.filesOK)")
        discard(tr)
        state = .idle
        ended = tr.id
        return .result(transfer: tr.id, status: FileProto.Status.failed, filesOK: tr.filesOK)
    }

    // MARK: Disk

    private func makeTransfer(id: UInt32, entries: [Entry], total: UInt64) -> Transfer? {
        guard Self.mkdirs(root) else { return nil }
        let rootFD = Darwin.open(root.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard rootFD >= 0 else { return nil }
        defer { Darwin.close(rootFD) }
        let name = UUID().uuidString
        guard mkdirat(rootFD, name, 0o700) == 0 else { return nil }
        let dir = root.appendingPathComponent(name, isDirectory: true)
        let dirFD = openat(rootFD, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard dirFD >= 0 else { try? FileManager.default.removeItem(at: dir); return nil }
        guard mkdirat(dirFD, "parts", 0o700) == 0, mkdirat(dirFD, "files", 0o700) == 0 else {
            Darwin.close(dirFD); try? FileManager.default.removeItem(at: dir); return nil
        }
        let partsFD = openat(dirFD, "parts", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        let filesFD = openat(dirFD, "files", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        let tr = Transfer(id: id, entries: entries, total: total, dir: dir, dirFD: dirFD, partsFD: partsFD, filesFD: filesFD)
        guard partsFD >= 0, filesFD >= 0 else { discard(tr); return nil }
        // Folders first, so empty ones survive and files find their parents.
        for e in entries where e.kind == FileProto.EntryKind.dir {
            guard let fd = Self.openDir(filesFD, components: Self.components(e.path), create: true) else {
                discard(tr); return nil
            }
            Darwin.close(fd)
        }
        return tr
    }

    private func openPart(_ tr: Transfer) -> Bool {
        tr.fileFD = openat(tr.partsFD, "\(tr.cursor).jlpart", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        return tr.fileFD >= 0
    }

    private func finishPart(_ tr: Transfer, entry e: Entry) -> Bool {
        let fd = tr.fileFD
        tr.fileFD = -1
        defer { Darwin.close(fd) }
        Self.setQuarantine(fd)
        _ = fchmod(fd, 0o644)
        var times = [timespec(tv_sec: Int(e.mtime), tv_nsec: 0), timespec(tv_sec: Int(e.mtime), tv_nsec: 0)]
        if e.mtime > 0 { _ = futimens(fd, &times) }
        var parts = Self.components(e.path)
        let leaf = parts.removeLast()
        guard let parentFD = Self.openDir(tr.filesFD, components: parts, create: true) else { return false }
        defer { Darwin.close(parentFD) }
        return renameatx_np(tr.partsFD, "\(tr.cursor).jlpart", parentFD, leaf, UInt32(RENAME_EXCL)) == 0
    }

    private func closeFDs(_ tr: Transfer) {
        for fd in [tr.fileFD, tr.partsFD, tr.filesFD, tr.dirFD] where fd >= 0 { Darwin.close(fd) }
        tr.fileFD = -1
    }

    private func discard(_ tr: Transfer) {
        closeFDs(tr)
        try? FileManager.default.removeItem(at: tr.dir)
    }

    /// Open (and optionally create) `components` under `base`, one level at a
    /// time with O_NOFOLLOW, so no symlink or `..` can redirect the walk.
    /// Returns an fd the caller closes.
    static func openDir(_ base: Int32, components: [String], create: Bool) -> Int32? {
        var fd = dup(base)
        guard fd >= 0 else { return nil }
        for c in components {
            if create, mkdirat(fd, c, 0o755) != 0, errno != EEXIST { Darwin.close(fd); return nil }
            let next = openat(fd, c, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            Darwin.close(fd)
            guard next >= 0 else { return nil }
            fd = next
        }
        return fd
    }

    static func components(_ path: String) -> [String] {
        path.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
    }

    static func parentPaths(of path: String) -> [String] {
        var out: [String] = []
        var parts = components(path)
        while parts.count > 1 {
            parts.removeLast()
            out.append(parts.joined(separator: "/"))
        }
        return out
    }

    /// Same mark a browser download gets, so Gatekeeper checks received apps.
    static func setQuarantine(_ fd: Int32) {
        let value = String(format: "0081;%08x;JerisLink;", UInt32(truncatingIfNeeded: Int(Date().timeIntervalSince1970)))
        _ = value.withCString { fsetxattr(fd, "com.apple.quarantine", $0, Int(strlen($0)), 0, 0) }
    }

    static func availableBytes(_ url: URL) -> UInt64? {
        var probe = url
        while !FileManager.default.fileExists(atPath: probe.path), probe.pathComponents.count > 1 {
            probe.deleteLastPathComponent()
        }
        var s = statfs()
        guard statfs(probe.path, &s) == 0 else { return nil }
        return UInt64(s.f_bavail) &* UInt64(s.f_bsize)
    }

    private static func mkdirs(_ url: URL) -> Bool {
        do {
            try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true,
                                                    attributes: [.posixPermissions: 0o700])
            return true
        } catch { return false }
    }

    private static func keep(_ dir: URL) {
        keptLock.lock()
        let old = keptDir
        keptDir = dir
        keptLock.unlock()
        if let old, old != dir { try? FileManager.default.removeItem(at: old) }
    }

    /// Once per process and root: remove transfer folders older than 24 h
    /// (crashed sessions, old pastes).
    static func sweepOnce(_ root: URL, now: Date = Date()) {
        keptLock.lock()
        let first = sweptRoots.insert(root.path).inserted
        keptLock.unlock()
        guard first else { return }
        sweep(root, now: now)
    }

    @discardableResult
    static func sweep(_ root: URL, now: Date = Date()) -> Int {
        let fm = FileManager.default
        guard let items = try? fm.contentsOfDirectory(at: root, includingPropertiesForKeys: [.contentModificationDateKey],
                                                      options: [.skipsHiddenFiles]) else { return 0 }
        var removed = 0
        for item in items {
            let mod = (try? item.resourceValues(forKeys: [.contentModificationDateKey]))?.contentModificationDate ?? .distantPast
            if now.timeIntervalSince(mod) > sweepAge, (try? fm.removeItem(at: item)) != nil { removed += 1 }
        }
        if removed > 0 { print("file.staging_sweep removed=\(removed)") }
        return removed
    }
}
