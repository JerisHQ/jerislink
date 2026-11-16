import Foundation
import Darwin
import CryptoKit

/// Mac->Windows paste (F3), the host half. Design r2 section 4 and the
/// "Windows clipboard detail (PR-F3)" section.
///
/// One per file session whose viewer said HELLO caps `announce`. When the
/// user copies files in Finder, `announce(urls:)` walks them and returns an
/// OFFER purpose=announce plus one ENTRY per file or folder: a manifest with
/// no data. The viewer puts a lazy clipboard object on Windows; only when
/// Explorer pastes does the viewer pull bytes with REQUEST, which `serve`
/// answers with DATA and, at the end of each file, FILE_END with its SHA-256.
/// Copy with no paste moves no file data.
///
/// Reads are sequential per file: a REQUEST at offset 0 (re)starts a file,
/// one at the file's next offset continues it, anything else is refused. Each
/// open is `O_NOFOLLOW` and must match the device, inode and size seen when
/// the manifest was built, so a file swapped for a symlink or another file
/// after the copy is never served. Not thread-safe: the session thread owns
/// it. Logs carry no names (D15).
final class FileAnnouncer {
    typealias Message = FileProto.Message

    struct Item: Equatable {
        var kind: UInt8
        var size: UInt64
        var mtime: Int64
        var path: [UInt8]       // NFC, '/'-separated, relative
        var full: String        // absolute path on this Mac
        var dev: UInt64
        var ino: UInt64
    }

    enum Built: Equatable {
        case ok([Item], total: UInt64, skipped: Int)
        case refused(String)
    }

    /// Largest REQUEST served in one go; the viewer asks for less.
    static let maxRequest: UInt32 = 4 << 20
    /// Files held open at once (Explorer pulls one or two at a time).
    static let maxOpen = 8

    /// The live announce, if any.
    private(set) var current: UInt32?
    private var items: [Item] = []
    private var nextID: UInt32 = 0
    private var readers: [UInt32: Reader] = [:]
    private var readerOrder: [UInt32] = []

    private(set) var announces: UInt64 = 0
    private(set) var refusedAnnounces: UInt64 = 0
    private(set) var filesServed: UInt64 = 0
    private(set) var bytesOut: UInt64 = 0

    private final class Reader {
        let fd: Int32
        var next: UInt64 = 0
        var hasher = SHA256()
        init(fd: Int32) { self.fd = fd }
        deinit { Darwin.close(fd) }
    }

    /// Opens files off the session thread (macOS privacy prompts, F3 r2).
    let gate: FileOpenGate
    /// How long a REQUEST waits for its open before the viewer hears
    /// `macPermission`.
    let openWaitMs: Int

    init(firstID: UInt32 = UInt32.random(in: 1...0x3fff_ffff), gate: FileOpenGate = .shared, openWaitMs: Int = 2500) {
        nextID = firstID
        self.gate = gate
        self.openWaitMs = openWaitMs
    }

    deinit { closeAll() }

    // MARK: Announce

    /// The pasteboard changed. `urls` are its file URLs, nil or empty when it
    /// holds no files (or holds this host's own F2 paste). Returns what to
    /// send: CANCEL for the announce it replaces, then OFFER + ENTRYs.
    func announce(urls: [URL]?) -> [Message] {
        var out: [Message] = []
        if let old = current {
            out.append(.cancel(transfer: old, reason: FileProto.Status.cancelled))
            drop()
        }
        guard let urls, !urls.isEmpty else { return out }
        switch Self.build(urls) {
        case .refused(let why):
            refusedAnnounces += 1
            print("file.announce=skipped reason=\(why)")
        case let .ok(list, total, skipped):
            // Host ids are even, viewer upload ids are odd: never the same.
            nextID = nextID &+ 1
            if nextID == 0 { nextID = 1 }
            let id = nextID << 1
            current = id
            items = list
            announces += 1
            out.append(.offer(transfer: id, purpose: FileProto.Purpose.announce, entries: UInt32(list.count), total: total))
            for (i, it) in list.enumerated() {
                out.append(.entry(transfer: id, index: UInt32(i), kind: it.kind, size: it.size, mtime: it.mtime, path: it.path))
            }
            let files = list.filter { $0.kind == FileProto.EntryKind.file }.count
            print("file.announce transfer=\(id) entries=\(list.count) files=\(files) bytes=\(total) skipped=\(skipped)")
            // Surface a Files & Folders prompt now, at copy time, not mid-paste.
            gate.probe(Self.probePaths(list))
        }
        return out
    }

    /// The viewer cancelled or refused the announce (it could not offer
    /// those names to Explorer): forget it.
    func cancel(_ t: UInt32) {
        guard t == current else { return }
        drop()
    }

    func close() { drop() }

    private func drop() {
        current = nil
        items = []
        closeAll()
    }

    private func closeAll() {
        readers.removeAll()
        readerOrder.removeAll()
    }

    // MARK: Serve

    /// Answers one REQUEST through `send`. Returns false only when `send`
    /// failed (the session must close); a refused request is answered with
    /// REPLY `failed`, or `macPermission` when macOS privacy settings or an
    /// open prompt on the Mac hold the file (F3 r2), and the session goes on.
    func serve(transfer t: UInt32, index: UInt32, offset: UInt64, length: UInt32,
               send: (Message) -> Bool) -> Bool {
        func refuse(_ why: String, _ status: UInt8 = FileProto.Status.failed) -> Bool {
            if t == current {
                readers.removeValue(forKey: index)
                readerOrder.removeAll { $0 == index }
            }
            print("file.pull transfer=\(t) result=failed:\(why)")
            return send(.reply(transfer: t, status: status))
        }
        guard t == current, Int(index) < items.count else { return refuse("unknown") }
        let item = items[Int(index)]
        guard item.kind == FileProto.EntryKind.file else { return refuse("not_file") }
        guard offset <= item.size else { return refuse("offset") }

        let reader: Reader
        if offset == 0 {
            readers.removeValue(forKey: index)
            readerOrder.removeAll { $0 == index }
            let fd: Int32
            switch openChecked(item) {
            case .fd(let f): fd = f
            case .pending: return refuse("mac_permission_pending", FileProto.Status.macPermission)
            case .denied: return refuse("mac_permission_denied", FileProto.Status.macPermission)
            case .failed: return refuse("open")
            }
            reader = Reader(fd: fd)
            readers[index] = reader
            readerOrder.append(index)
            while readerOrder.count > Self.maxOpen {
                readers.removeValue(forKey: readerOrder.removeFirst())
            }
        } else {
            guard let r = readers[index], r.next == offset else { return refuse("sequence") }
            reader = r
        }

        let end = min(item.size, offset + UInt64(min(length, Self.maxRequest)))
        var buf = [UInt8](repeating: 0, count: Int(FileProto.maxChunk))
        while reader.next < end {
            let want = Int(min(UInt64(FileProto.maxChunk), end - reader.next))
            let n = buf.withUnsafeMutableBytes { Darwin.read(reader.fd, $0.baseAddress!, want) }
            if n <= 0 { return refuse("read") }
            let chunk = Array(buf[0..<n])
            reader.hasher.update(data: chunk)
            guard send(.data(transfer: t, index: index, offset: reader.next, bytes: chunk)) else { return false }
            reader.next += UInt64(n)
            bytesOut += UInt64(n)
        }
        if reader.next == item.size {
            readers.removeValue(forKey: index)
            readerOrder.removeAll { $0 == index }
            // A file that grew since the copy is not what was announced.
            var extra: UInt8 = 0
            if Darwin.read(reader.fd, &extra, 1) != 0 { return refuse("changed") }
            filesServed += 1
            return send(.fileEnd(transfer: t, index: index, sha256: Array(reader.hasher.finalize())))
        }
        return true
    }

    /// Opens a manifest file for reading through the gate: no symlink at the
    /// leaf, and the same file (device, inode, size) as when it was copied.
    /// `.fd` only for that file; a different file is `.failed`.
    func openChecked(_ item: Item) -> FileOpenGate.Result {
        let fd: Int32
        switch gate.open(item.full, waitMs: openWaitMs) {
        case .fd(let f): fd = f
        case let other: return other
        }
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG,
              UInt64(st.st_dev) == item.dev, UInt64(st.st_ino) == item.ino, UInt64(st.st_size) == item.size else {
            Darwin.close(fd)
            return .failed
        }
        return .fd(fd)
    }

    /// One file per distinct folder of the copy, at most four: enough for TCC
    /// to ask about each protected place once.
    static func probePaths(_ list: [Item]) -> [String] {
        var seen = Set<String>()
        var out: [String] = []
        for it in list where it.kind == FileProto.EntryKind.file {
            let dir = (it.full as NSString).deletingLastPathComponent
            guard seen.insert(dir).inserted else { continue }
            out.append(it.full)
            if out.count == 4 { break }
        }
        return out
    }

    // MARK: Manifest

    /// Walks the copied items depth first, parents before children, children
    /// sorted by name. Symlinks and anything not a file or folder are skipped
    /// and counted. Limits are the wire limits. A name the path rules refuse
    /// refuses the whole announce, so Windows never gets part of a copy.
    static func build(_ urls: [URL]) -> Built {
        var out: [Item] = []
        var total: UInt64 = 0
        var skipped = 0

        func add(_ full: String, _ rel: String) -> Built? {
            var st = stat()
            guard lstat(full, &st) == 0 else { return .refused(errno == EPERM || errno == EACCES ? "unreadable" : "missing") }
            let type = st.st_mode & S_IFMT
            guard type == S_IFREG || type == S_IFDIR else { skipped += 1; return nil }
            guard case .ok(let nfc) = FilePathSafety.validate(rel) else { return .refused("bad_path") }
            guard out.count < Int(FileProto.maxEntries) else { return .refused("too_many") }
            let isDir = type == S_IFDIR
            let size = isDir ? 0 : UInt64(st.st_size)
            total += size
            guard total <= FileProto.maxTotalBytes else { return .refused("too_big") }
            out.append(Item(kind: isDir ? FileProto.EntryKind.dir : FileProto.EntryKind.file, size: size,
                            mtime: Int64(st.st_mtimespec.tv_sec), path: Array(nfc.utf8), full: full,
                            dev: UInt64(st.st_dev), ino: UInt64(st.st_ino)))
            guard isDir else { return nil }
            let children: [String]
            do { children = try FileManager.default.contentsOfDirectory(atPath: full) } catch {
                return .refused("unreadable")
            }
            for name in children.sorted() {
                if let stop = add(full + "/" + name, rel + "/" + name) { return stop }
            }
            return nil
        }

        for url in urls {
            guard url.isFileURL else { continue }
            let full = url.standardizedFileURL.path
            let leaf = (full as NSString).lastPathComponent
            guard !leaf.isEmpty, leaf != "/" else { return .refused("bad_path") }
            if let stop = add(full, leaf) { return stop }
        }
        if out.isEmpty { return .refused(skipped > 0 ? "only_links" : "empty") }
        return .ok(out, total: total, skipped: skipped)
    }
}
