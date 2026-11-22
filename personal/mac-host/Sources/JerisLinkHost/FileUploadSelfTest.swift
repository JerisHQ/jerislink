import Foundation
import CryptoKit
import Darwin

/// `JerisLinkHost --self-test` part for paste uploads (F2) and drops
/// (purpose=send, F4): the receiver state machine against a temp staging
/// folder, a fake pasteboard and a temp send folder. The
/// socket end-to-end case is in ControlServiceSelfTest.
enum FileUploadSelfTest {
    typealias M = FileProto.Message

    static func run(_ expect: (Bool, String) -> Void) {
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("jl-upload-selftest-\(getpid())-\(UInt32.random(in: 1...UInt32.max))", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: base) }
        happyPath(base.appendingPathComponent("happy"), expect)
        rejections(base.appendingPathComponent("reject"), expect)
        failures(base.appendingPathComponent("fail"), expect)
        sweep(base.appendingPathComponent("sweep"), expect)
        sends(base.appendingPathComponent("send"), expect)
    }

    // MARK: Helpers

    static func sha(_ b: [UInt8]) -> [UInt8] { Array(SHA256.hash(data: b)) }

    static func entry(_ t: UInt32, _ i: UInt32, _ path: String, size: Int, dir: Bool = false, mtime: Int64 = 1_700_000_000) -> M {
        .entry(transfer: t, index: i, kind: dir ? FileProto.EntryKind.dir : FileProto.EntryKind.file,
               size: UInt64(size), mtime: mtime, path: Array(path.utf8))
    }

    /// DATA chunks for one file, at most 32 KiB each.
    static func chunks(_ t: UInt32, _ i: UInt32, _ bytes: [UInt8]) -> [M] {
        stride(from: 0, to: bytes.count, by: Int(FileProto.maxChunk)).map { off in
            .data(transfer: t, index: i, offset: UInt64(off),
                  bytes: Array(bytes[off..<min(bytes.count, off + Int(FileProto.maxChunk))]))
        }
    }

    static func feed(_ r: FileUploadReceiver, _ msgs: [M]) -> (sent: [M], closed: String?) {
        var sent: [M] = []
        for m in msgs {
            let step = r.handle(m)
            sent += step.send
            if let c = step.close { return (sent, c) }
        }
        return (sent, nil)
    }

    static func transferDirs(_ root: URL) -> [URL] {
        (try? FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: nil)) ?? []
    }

    static func jlparts(_ root: URL) -> Int {
        guard let e = FileManager.default.enumerator(atPath: root.path) else { return 0 }
        return e.compactMap { $0 as? String }.filter { $0.hasSuffix(".jlpart") }.count
    }

    // MARK: Cases

    private static func happyPath(_ root: URL, _ expect: (Bool, String) -> Void) {
        let board = UploadFakeClipboard()
        let r = FileUploadReceiver(root: root, clipboard: board, freeSpace: { _ in 1 << 40 })
        let a = Array("hello".utf8)
        let b = (0..<70_000).map { UInt8($0 & 0xff) }
        let t: UInt32 = 5
        var msgs: [M] = [.offer(transfer: t, purpose: FileProto.Purpose.paste, entries: 5, total: UInt64(a.count + b.count)),
                         entry(t, 0, "a.txt", size: a.count),
                         entry(t, 1, "dir", size: 0, dir: true),
                         entry(t, 2, "dir/b.bin", size: b.count),
                         entry(t, 3, "dir/empty", size: 0),
                         entry(t, 4, "dir/sub", size: 0, dir: true)]
        let (accept, c0) = feed(r, msgs)
        expect(c0 == nil && accept == [.reply(transfer: t, status: FileProto.Status.ok)], "upload: 5-entry paste offer accepted")
        expect(jlparts(root) == 0, "upload: no .jlpart before data")
        msgs = chunks(t, 0, a) + [.fileEnd(transfer: t, index: 0, sha256: sha(a))]
            + chunks(t, 2, b) + [.fileEnd(transfer: t, index: 2, sha256: sha(b))]
            + [.fileEnd(transfer: t, index: 3, sha256: sha([]))]
        let (out, c1) = feed(r, msgs)
        expect(c1 == nil, "upload: data stream accepted in order")
        let progress = out.compactMap { m -> UInt64? in if case let .progress(_, c) = m { return c }; return nil }
        expect(progress == [5, UInt64(5 + b.count), UInt64(5 + b.count)], "upload: PROGRESS after each FILE_END (\(progress))")
        expect(out.last == .result(transfer: t, status: FileProto.Status.ok, filesOK: 3), "upload: RESULT ok with 3 files")
        let urls = board.fileURLs
        expect(urls.map(\.lastPathComponent) == ["a.txt", "dir"], "upload: pasteboard holds the two top-level items")
        let files = urls.first?.deletingLastPathComponent()
        let readA = files.flatMap { try? Data(contentsOf: $0.appendingPathComponent("a.txt")) }
        let readB = files.flatMap { try? Data(contentsOf: $0.appendingPathComponent("dir/b.bin")) }
        expect(readA.map(Array.init) == a && readB.map(Array.init) == b, "upload: staged contents match")
        var isDir: ObjCBool = false
        let sub = files.map { FileManager.default.fileExists(atPath: $0.appendingPathComponent("dir/sub").path, isDirectory: &isDir) } ?? false
        expect(sub && isDir.boolValue, "upload: empty folder entry is created")
        let emptySize = files.flatMap { try? FileManager.default.attributesOfItem(atPath: $0.appendingPathComponent("dir/empty").path)[.size] as? Int }
        expect(emptySize == 0, "upload: zero-byte file is created")
        expect(jlparts(root) == 0, "upload: no .jlpart left after success")
        if let f = files?.appendingPathComponent("a.txt") {
            let q = getxattr(f.path, "com.apple.quarantine", nil, 0, 0, 0)
            expect(q > 0, "upload: received file carries com.apple.quarantine")
            let m = (try? FileManager.default.attributesOfItem(atPath: f.path)[.modificationDate] as? Date)?.timeIntervalSince1970
            expect(m == 1_700_000_000, "upload: mtime from ENTRY applied")
        }
        expect(r.completed == 1 && r.bytesIn == UInt64(a.count + b.count), "upload: counters (completed=\(r.completed) bytes=\(r.bytesIn))")

        // A second paste replaces the kept staging of the first.
        let t2: UInt32 = 6
        let (out2, _) = feed(r, [.offer(transfer: t2, purpose: FileProto.Purpose.paste, entries: 1, total: 1),
                                 entry(t2, 0, "x", size: 1), .data(transfer: t2, index: 0, offset: 0, bytes: [7]),
                                 .fileEnd(transfer: t2, index: 0, sha256: sha([7]))])
        expect(out2.last == .result(transfer: t2, status: FileProto.Status.ok, filesOK: 1), "upload: second paste ok")
        expect(transferDirs(root).count == 1, "upload: only the latest paste staging is kept (\(transferDirs(root).count))")
    }

    private static func rejections(_ root: URL, _ expect: (Bool, String) -> Void) {
        let board = UploadFakeClipboard()
        func fresh(free: UInt64 = 1 << 40) -> FileUploadReceiver {
            FileUploadReceiver(root: root, clipboard: board, freeSpace: { _ in free })
        }
        func offer(_ t: UInt32, _ n: UInt32, _ total: UInt64, purpose: UInt8 = FileProto.Purpose.paste) -> M {
            .offer(transfer: t, purpose: purpose, entries: n, total: total)
        }
        let bad = feed(fresh(), [offer(1, 1, 1), entry(1, 0, "../x", size: 1)]).sent
        expect(bad == [.reply(transfer: 1, status: FileProto.Status.badPath)], "upload: ../ path rejected bad_path")
        let abs = feed(fresh(), [offer(1, 1, 1), entry(1, 0, "/etc/x", size: 1)]).sent
        expect(abs == [.reply(transfer: 1, status: FileProto.Status.badPath)], "upload: absolute path rejected bad_path")
        let dup = feed(fresh(), [offer(1, 2, 2), entry(1, 0, "A.txt", size: 1), entry(1, 1, "a.TXT", size: 1)]).sent
        expect(dup == [.reply(transfer: 1, status: FileProto.Status.badPath)], "upload: case-insensitive duplicate rejected")
        let under = feed(fresh(), [offer(1, 2, 2), entry(1, 0, "f", size: 1), entry(1, 1, "f/g", size: 1)]).sent
        expect(under == [.reply(transfer: 1, status: FileProto.Status.badPath)], "upload: path under a file rejected")
        let sum = feed(fresh(), [offer(1, 1, 9), entry(1, 0, "a", size: 1)]).sent
        expect(sum == [.reply(transfer: 1, status: FileProto.Status.badPath)], "upload: sizes not matching total rejected")
        let dirSize = feed(fresh(), [offer(1, 1, 5), entry(1, 0, "d", size: 5, dir: true)]).sent
        expect(dirSize == [.reply(transfer: 1, status: FileProto.Status.badPath)], "upload: folder with a size rejected")
        let space = feed(fresh(free: 100), [offer(1, 1, 10), entry(1, 0, "a", size: 10)]).sent
        expect(space == [.reply(transfer: 1, status: FileProto.Status.noSpace)], "upload: not enough free space rejected no_space")
        let big = feed(fresh(), [offer(1, 1, FileProto.maxTotalBytes + 1)]).sent
        expect(big == [.reply(transfer: 1, status: FileProto.Status.tooBig)], "upload: over 20 GiB rejected too_big")
        let many = feed(fresh(), [offer(1, FileProto.maxEntries + 1, 0)]).sent
        expect(many == [.reply(transfer: 1, status: FileProto.Status.tooBig)], "upload: over 10000 entries rejected too_big")
        let push = feed(fresh(), [offer(1, 1, 1, purpose: FileProto.Purpose.push)]).sent
        expect(push == [.reply(transfer: 1, status: FileProto.Status.denied)], "upload: purpose push still denied until F5")
        let busy = feed(fresh(), [offer(1, 2, 2), offer(2, 1, 1)]).sent
        expect(busy == [.reply(transfer: 2, status: FileProto.Status.busy)], "upload: second offer while one runs is busy")
        let order = feed(fresh(), [offer(1, 2, 2), entry(1, 1, "a", size: 1)])
        expect(order.closed == "entry_order", "upload: entry out of order closes the session")
        let stray = feed(fresh(), [.data(transfer: 3, index: 0, offset: 0, bytes: [1])])
        expect(stray.closed == "unexpected_data", "upload: DATA with no transfer closes the session")
        expect(transferDirs(root).isEmpty, "upload: rejected offers leave no staging folder")
        expect(board.fileURLs.isEmpty, "upload: rejected offers leave the pasteboard alone")
    }

    private static func failures(_ root: URL, _ expect: (Bool, String) -> Void) {
        let board = UploadFakeClipboard()
        let data = [UInt8](repeating: 0x5A, count: 100_000)
        func start(_ r: FileUploadReceiver, _ t: UInt32) -> [M] {
            feed(r, [.offer(transfer: t, purpose: FileProto.Purpose.paste, entries: 2, total: UInt64(data.count + 3)),
                     entry(t, 0, "big.bin", size: data.count), entry(t, 1, "small", size: 3)]).sent
        }

        // Wrong hash: RESULT failed, folder removed, late DATA ignored.
        let r1 = FileUploadReceiver(root: root, clipboard: board, freeSpace: { _ in 1 << 40 })
        _ = start(r1, 1)
        let (h, hc) = feed(r1, chunks(1, 0, data) + [.fileEnd(transfer: 1, index: 0, sha256: sha([1]))])
        expect(hc == nil && h.last == .result(transfer: 1, status: FileProto.Status.failed, filesOK: 0), "upload: hash mismatch fails the transfer")
        expect(transferDirs(root).isEmpty && jlparts(root) == 0, "upload: failed transfer leaves no staging or .jlpart")
        let late = feed(r1, [.data(transfer: 1, index: 1, offset: 0, bytes: [1, 2, 3])])
        expect(late.closed == nil && late.sent.isEmpty, "upload: DATA still in flight for a failed transfer is dropped")

        // Cancel from the viewer halfway.
        let r2 = FileUploadReceiver(root: root, clipboard: board, freeSpace: { _ in 1 << 40 })
        _ = start(r2, 2)
        _ = feed(r2, Array(chunks(2, 0, data).prefix(2)))
        expect(jlparts(root) == 1, "upload: a .jlpart exists while a file is half written")
        let (cx, _) = feed(r2, [.cancel(transfer: 2, reason: FileProto.Status.cancelled)])
        expect(cx == [.result(transfer: 2, status: FileProto.Status.cancelled, filesOK: 0)], "upload: CANCEL answered with RESULT cancelled")
        expect(transferDirs(root).isEmpty && jlparts(root) == 0, "upload: cancel leaves no staging or .jlpart")

        // Session drop halfway.
        let r3 = FileUploadReceiver(root: root, clipboard: board, freeSpace: { _ in 1 << 40 })
        _ = start(r3, 3)
        _ = feed(r3, Array(chunks(3, 0, data).prefix(1)))
        r3.abort(reason: "peer_closed")
        expect(transferDirs(root).isEmpty && jlparts(root) == 0 && r3.failed == 1, "upload: session drop removes partial files")

        // Too many bytes for a file closes the session.
        let r4 = FileUploadReceiver(root: root, clipboard: board, freeSpace: { _ in 1 << 40 })
        _ = feed(r4, [.offer(transfer: 4, purpose: FileProto.Purpose.paste, entries: 1, total: 2), entry(4, 0, "a", size: 2)])
        let over = feed(r4, [.data(transfer: 4, index: 0, offset: 0, bytes: [1, 2, 3])])
        expect(over.closed == "data_range", "upload: DATA past the file size closes the session")
        r4.abort(reason: "data_range")
        expect(transferDirs(root).isEmpty, "upload: closed session removes its staging")

        // Pasteboard write fails: RESULT failed, staging removed.
        let broken = UploadFakeClipboard(); broken.failWrites = true
        let r5 = FileUploadReceiver(root: root, clipboard: broken, freeSpace: { _ in 1 << 40 })
        let (pb, _) = feed(r5, [.offer(transfer: 5, purpose: FileProto.Purpose.paste, entries: 1, total: 1), entry(5, 0, "a", size: 1),
                                .data(transfer: 5, index: 0, offset: 0, bytes: [9]), .fileEnd(transfer: 5, index: 0, sha256: sha([9]))])
        expect(pb.last == .result(transfer: 5, status: FileProto.Status.failed, filesOK: 1) && transferDirs(root).isEmpty,
               "upload: pasteboard failure reports failed and cleans up")
    }

    private static func sweep(_ root: URL, _ expect: (Bool, String) -> Void) {
        let fm = FileManager.default
        try? fm.createDirectory(at: root.appendingPathComponent("old/parts"), withIntermediateDirectories: true)
        try? fm.createDirectory(at: root.appendingPathComponent("new"), withIntermediateDirectories: true)
        try? fm.setAttributes([.modificationDate: Date().addingTimeInterval(-25 * 3600)], ofItemAtPath: root.appendingPathComponent("old").path)
        let removed = FileUploadReceiver.sweep(root)
        expect(removed == 1 && transferDirs(root).map(\.lastPathComponent) == ["new"], "upload: startup sweep removes staging older than 24 h only")
    }
}

extension FileUploadSelfTest {
    /// One file drop, start to RESULT.
    static func dropOne(_ r: FileUploadReceiver, _ t: UInt32, _ path: String, _ body: [UInt8]) -> [M] {
        feed(r, [.offer(transfer: t, purpose: FileProto.Purpose.send, entries: 1, total: UInt64(body.count)),
                 entry(t, 0, path, size: body.count)] + chunks(t, 0, body) +
                [.fileEnd(transfer: t, index: 0, sha256: sha(body))]).sent
    }

    static func hasQuarantine(_ url: URL) -> Bool {
        getxattr(url.path, "com.apple.quarantine", nil, 0, 0, XATTR_NOFOLLOW) > 0
    }

    fileprivate static func sends(_ base: URL, _ expect: (Bool, String) -> Void) {
        let fm = FileManager.default
        let staging = base.appendingPathComponent("staging")
        try? fm.createDirectory(at: base.appendingPathComponent("Downloads"), withIntermediateDirectories: true)
        let primary = base.appendingPathComponent("Downloads/JerisLink", isDirectory: true)
        let fallback = base.appendingPathComponent("JerisLink Received", isDirectory: true)
        let board = UploadFakeClipboard()

        // Downloads allowed: a folder and files, clash numbering, quarantine.
        let opened = OpenedFolders()
        let folder = FileSendFolder(primary: primary, fallback: fallback, openFolder: { opened.add($0) })
        let r = FileUploadReceiver(root: staging, clipboard: board, freeSpace: { _ in 1 << 40 }, sendFolder: folder)
        let one = dropOne(r, 1, "report.pdf", [1, 2, 3])
        expect(one.first == .reply(transfer: 1, status: FileProto.Status.ok) &&
               one.last == .result(transfer: 1, status: FileProto.Status.ok, filesOK: 1), "send: drop accepted and done")
        _ = dropOne(r, 2, "report.pdf", [4])
        _ = dropOne(r, 3, "report.pdf", [5])
        _ = dropOne(r, 4, ".profile", [6])
        _ = dropOne(r, 5, ".profile", [7])
        _ = dropOne(r, 6, "README", [8])
        _ = dropOne(r, 7, "README", [9])
        let tree: [M] = [.offer(transfer: 8, purpose: FileProto.Purpose.send, entries: 3, total: 1),
                         entry(8, 0, "My.app", size: 0, dir: true), entry(8, 1, "My.app/Contents", size: 0, dir: true),
                         entry(8, 2, "My.app/Contents/run", size: 1)] + chunks(8, 2, [42]) +
                        [.fileEnd(transfer: 8, index: 2, sha256: sha([42]))]
        let treeOut = feed(r, tree).sent
        _ = feed(r, [.offer(transfer: 9, purpose: FileProto.Purpose.send, entries: 1, total: 0), entry(9, 0, "My.app", size: 0, dir: true)])
        expect(treeOut.last == .result(transfer: 8, status: FileProto.Status.ok, filesOK: 1), "send: a folder drop is done")
        let names = Set((try? fm.contentsOfDirectory(atPath: primary.path)) ?? [])
        let want: Set<String> = ["report.pdf", "report 2.pdf", "report 3.pdf", ".profile", ".profile 2", "README", "README 2",
                                 "My.app", "My 2.app"]
        expect(names == want, "send: Finder-style clash names, dotfiles and no extension (\(names.sorted()))")
        expect((try? Data(contentsOf: primary.appendingPathComponent("report 3.pdf"))).map(Array.init) == [5],
               "send: nothing already there is replaced")
        expect(hasQuarantine(primary.appendingPathComponent("report 2.pdf")) && hasQuarantine(primary.appendingPathComponent("My.app")) &&
               hasQuarantine(primary.appendingPathComponent("My.app/Contents/run")),
               "send: files and the .app folder carry com.apple.quarantine")
        expect(transferDirs(staging).isEmpty, "send: no staging left after sends")
        expect(board.fileURLs.isEmpty, "send: the pasteboard is left alone")
        expect(opened.count == 9 && Set(opened.all) == [primary], "send: Finder opens the folder after every send (\(opened.count))")
        let revealed = DispatchSemaphore(value: 0)
        let hit = OpenedFolders()
        folder.reveal(transfer: 2, done: { ok in if ok { hit.add(primary) }; revealed.signal() })
        _ = revealed.wait(timeout: .now() + 3)
        folder.reveal(transfer: 999, done: { ok in if ok { hit.add(primary) }; revealed.signal() })
        _ = revealed.wait(timeout: .now() + 3)
        expect(hit.count == 2 && opened.count == 11, "send: REVEAL opens the folder for a known and an unknown transfer")

        // Downloads refused: the home fallback, which needs no permission.
        let deniedOpened = OpenedFolders()
        let denied = FileSendFolder(primary: base.appendingPathComponent("Downloads/Refused", isDirectory: true), fallback: fallback,
                                    primaryOpener: { _ in (-1, EPERM) }, openFolder: { deniedOpened.add($0) })
        let r2 = FileUploadReceiver(root: staging, clipboard: board, freeSpace: { _ in 1 << 40 }, sendFolder: denied)
        let out2 = dropOne(r2, 1, "a.txt", [1])
        expect(out2.last == .result(transfer: 1, status: FileProto.Status.ok, filesOK: 1) &&
               fm.fileExists(atPath: fallback.appendingPathComponent("a.txt").path) && deniedOpened.all == [fallback],
               "send: Downloads refused falls back to ~/JerisLink Received and opens it")

        // Prompt still up: mac_permission, nothing staged, then a retry works.
        let release = DispatchSemaphore(value: 0)
        let slow = FileSendFolder(primary: primary, fallback: fallback,
                                  primaryOpener: { p in
                                      _ = release.wait(timeout: .now() + 5); release.signal()  // once released, stays released
                                      return FileSendFolder.folderOpener(p)
                                  },
                                  openFolder: { _ in })
        let r3 = FileUploadReceiver(root: staging, clipboard: board, freeSpace: { _ in 1 << 40 }, sendFolder: slow)
        let t0 = Date()
        let pend = feed(r3, [.offer(transfer: 1, purpose: FileProto.Purpose.send, entries: 1, total: 1), entry(1, 0, "b.txt", size: 1)]).sent
        let waited = Date().timeIntervalSince(t0)
        expect(pend == [.reply(transfer: 1, status: FileProto.Status.macPermission)] && waited < 4,
               "send: a pending privacy prompt answers mac_permission within the wait (\(String(format: "%.1f", waited)) s)")
        expect(transferDirs(staging).isEmpty, "send: mac_permission leaves no staging")
        release.signal()
        var retry: [M] = []
        for _ in 0..<20 where retry.last != .result(transfer: 2, status: FileProto.Status.ok, filesOK: 1) {
            retry = dropOne(r3, 2, "b.txt", [1])
            if retry.last != .result(transfer: 2, status: FileProto.Status.ok, filesOK: 1) { usleep(100_000) }
        }
        expect(retry.last == .result(transfer: 2, status: FileProto.Status.ok, filesOK: 1), "send: after Allow, the next drop goes through")

        // Paste still uses the pasteboard, not the send folder.
        let p = feed(r, [.offer(transfer: 30, purpose: FileProto.Purpose.paste, entries: 1, total: 1), entry(30, 0, "p.txt", size: 1),
                         .data(transfer: 30, index: 0, offset: 0, bytes: [3]), .fileEnd(transfer: 30, index: 0, sha256: sha([3]))]).sent
        expect(p.last == .result(transfer: 30, status: FileProto.Status.ok, filesOK: 1) && board.fileURLs.count == 1 &&
               !fm.fileExists(atPath: primary.appendingPathComponent("p.txt").path), "send: a paste still goes to the pasteboard")
    }
}

/// Folders a test FileSendFolder was asked to open.
final class OpenedFolders: @unchecked Sendable {
    private let lock = NSLock()
    private var urls: [URL] = []
    func add(_ u: URL) { lock.lock(); urls.append(u); lock.unlock() }
    var all: [URL] { lock.lock(); defer { lock.unlock() }; return urls }
    var count: Int { all.count }
}

/// Pasteboard stand-in for the upload cases.
final class UploadFakeClipboard: ClipboardBackend, @unchecked Sendable {
    private let lock = NSLock()
    private var count = 1
    private var urls: [URL] = []
    private var mark: Int?
    var failWrites = false

    var fileURLs: [URL] { lock.lock(); defer { lock.unlock() }; return urls }
    func changeCount() -> Int { lock.lock(); defer { lock.unlock() }; return count }
    func readText() -> String? { nil }
    func writeText(_ text: String) -> Int? { lock.lock(); defer { lock.unlock() }; count += 1; return count }
    func writeFileURLs(_ u: [URL]) -> Int? {
        lock.lock(); defer { lock.unlock() }
        if failWrites { return nil }
        count += 1; urls = u; mark = count
        return count
    }
    func ownFileWriteChangeCount() -> Int? { lock.lock(); defer { lock.unlock() }; return mark }
}
