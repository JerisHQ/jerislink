import Foundation
import CryptoKit
import Darwin

/// `JerisLinkHost --self-test` part for Mac->Windows paste (F3): the manifest
/// walk, announce replacement and REQUEST serving against a temp folder. The
/// socket end-to-end case is in ControlServiceSelfTest.
enum FileAnnounceSelfTest {
    typealias M = FileProto.Message

    static func run(_ expect: (Bool, String) -> Void) {
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("jl-announce-selftest-\(getpid())-\(UInt32.random(in: 1...UInt32.max))", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: base) }
        manifest(base.appendingPathComponent("walk"), expect)
        announces(base.appendingPathComponent("ann"), expect)
        serving(base.appendingPathComponent("serve"), expect)
        refusals(base.appendingPathComponent("refuse"), expect)
    }

    static func body(_ n: Int, seed: Int = 3) -> [UInt8] { (0..<n).map { UInt8(($0 * seed + 11) & 0xff) } }

    /// Every DATA byte and the FILE_END of one serve call.
    static func collect(_ a: FileAnnouncer, _ t: UInt32, _ i: UInt32, _ off: UInt64, _ len: UInt32) -> (ok: Bool, msgs: [M], bytes: [UInt8]) {
        var msgs: [M] = []
        let ok = a.serve(transfer: t, index: i, offset: off, length: len) { msgs.append($0); return true }
        var bytes: [UInt8] = []
        for case let .data(_, _, _, b) in msgs { bytes += b }
        return (ok, msgs, bytes)
    }

    private static func write(_ url: URL, _ b: [UInt8]) {
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: url.path, contents: Data(b))
    }

    private static func manifest(_ root: URL, _ expect: (Bool, String) -> Void) {
        let fm = FileManager.default
        write(root.appendingPathComponent("Photos/b.jpg"), body(70_000))
        write(root.appendingPathComponent("Photos/a/empty.txt"), [])
        write(root.appendingPathComponent("note.txt"), body(5))
        try? fm.createSymbolicLink(atPath: root.appendingPathComponent("Photos/link").path, withDestinationPath: "/etc/hosts")
        // Finder hands decomposed names; the manifest sends NFC.
        write(root.appendingPathComponent("Cafe\u{301}.txt"), body(1))

        let built = FileAnnouncer.build([root.appendingPathComponent("Photos"), root.appendingPathComponent("note.txt"),
                                         root.appendingPathComponent("Cafe\u{301}.txt")])
        guard case let .ok(items, total, skipped) = built else { expect(false, "announce: walk builds a manifest (\(built))"); return }
        let paths = items.map { String(decoding: $0.path, as: UTF8.self) }
        expect(paths == ["Photos", "Photos/a", "Photos/a/empty.txt", "Photos/b.jpg", "note.txt", "Caf\u{e9}.txt"],
               "announce: depth first, parents first, sorted children (\(paths))")
        expect(Array("Caf\u{e9}.txt".utf8) == items.last?.path, "announce: names are sent NFC")
        expect(total == 70_006 && skipped == 1, "announce: total bytes and skipped symlink (\(total), \(skipped))")
        expect(items[0].kind == FileProto.EntryKind.dir && items[3].size == 70_000, "announce: kinds and sizes")

        let onlyLink = FileAnnouncer.build([root.appendingPathComponent("Photos/link")])
        expect(onlyLink == .refused("only_links"), "announce: a copied symlink alone is refused")
        write(root.appendingPathComponent("odd\\name.txt"), [1])
        expect(FileAnnouncer.build([root.appendingPathComponent("odd\\name.txt")]) == .refused("bad_path"),
               "announce: a name the path rules refuse refuses the announce")
        expect(FileAnnouncer.build([root.appendingPathComponent("gone.txt")]) == .refused("missing"),
               "announce: a missing item refuses the announce")
    }

    private static func announces(_ root: URL, _ expect: (Bool, String) -> Void) {
        write(root.appendingPathComponent("one.bin"), body(10))
        let a = FileAnnouncer(firstID: 100)
        let first = a.announce(urls: [root.appendingPathComponent("one.bin")])
        guard case let .offer(t1, purpose, entries, total)? = first.first else { expect(false, "announce: OFFER first"); return }
        expect(purpose == FileProto.Purpose.announce && entries == 1 && total == 10 && first.count == 2,
               "announce: OFFER purpose=announce + one ENTRY")
        expect(t1 % 2 == 0 && t1 != 0 && a.current == t1, "announce: host transfer ids are even and current")
        let second = a.announce(urls: [root.appendingPathComponent("one.bin")])
        expect(second.first == .cancel(transfer: t1, reason: FileProto.Status.cancelled) && second.count == 3,
               "announce: a new copy cancels the old announce first")
        let t2 = a.current
        expect(a.announce(urls: nil) == [.cancel(transfer: t2!, reason: FileProto.Status.cancelled)] && a.current == nil,
               "announce: copying something else cancels it and announces nothing")
        expect(a.announce(urls: nil).isEmpty, "announce: nothing live, nothing to cancel")
        expect(a.announces == 2, "announce: count")
    }

    private static func serving(_ root: URL, _ expect: (Bool, String) -> Void) {
        let big = body(100_000, seed: 7)
        write(root.appendingPathComponent("dir/big.bin"), big)
        write(root.appendingPathComponent("dir/zero.bin"), [])
        let a = FileAnnouncer(firstID: 5)
        _ = a.announce(urls: [root.appendingPathComponent("dir")])
        guard let t = a.current else { expect(false, "serve: announce live"); return }
        // dir, dir/big.bin (1), dir/zero.bin (2)
        let r1 = collect(a, t, 1, 0, 65_536)
        expect(r1.ok && r1.bytes == Array(big[0..<65_536]) && r1.msgs.count == 2, "serve: first 64 KiB as two DATA chunks")
        let r2 = collect(a, t, 1, 65_536, 1 << 20)
        let sha = Array(SHA256.hash(data: big))
        expect(r2.ok && r2.bytes == Array(big[65_536...]), "serve: the rest, clipped to the file size")
        expect(r2.msgs.last == .fileEnd(transfer: t, index: 1, sha256: sha), "serve: FILE_END with the SHA-256 of the whole file")
        let again = collect(a, t, 1, 0, 200_000)
        expect(again.bytes == big && again.msgs.last == .fileEnd(transfer: t, index: 1, sha256: sha), "serve: offset 0 restarts a file")
        let zero = collect(a, t, 2, 0, 1 << 20)
        expect(zero.msgs == [.fileEnd(transfer: t, index: 2, sha256: Array(SHA256.hash(data: Data())))], "serve: empty file is FILE_END only")
        expect(a.filesServed == 3 && a.bytesOut == UInt64(2 * big.count), "serve: counters (\(a.filesServed), \(a.bytesOut))")

        let failed = M.reply(transfer: t, status: FileProto.Status.failed)
        expect(collect(a, t, 1, 4096, 10).msgs == [failed], "serve: out of sequence offset is refused")
        expect(collect(a, t, 0, 0, 10).msgs == [failed], "serve: a folder entry is refused")
        expect(collect(a, t, 9, 0, 10).msgs == [failed], "serve: an unknown index is refused")
        expect(collect(a, t &+ 2, 1, 0, 10).msgs == [failed], "serve: an unknown transfer is refused")
        let capped = collect(a, t, 1, 0, UInt32.max)
        expect(capped.bytes.count == big.count, "serve: request length is capped, file size bounds it")

        // Swapped for a symlink after the copy: never served.
        let swapped = root.appendingPathComponent("dir/big.bin")
        try? FileManager.default.removeItem(at: swapped)
        try? FileManager.default.createSymbolicLink(atPath: swapped.path, withDestinationPath: "/etc/hosts")
        expect(collect(a, t, 1, 0, 10).msgs == [failed], "serve: a file swapped for a symlink is refused")
        try? FileManager.default.removeItem(at: swapped)
        write(swapped, body(100_000, seed: 9))
        expect(collect(a, t, 1, 0, 10).msgs == [failed], "serve: a file replaced after the copy is refused")

        let sendFails = a.serve(transfer: t, index: 2, offset: 0, length: 1) { _ in false }
        expect(!sendFails, "serve: a send failure is reported to the session")
        a.cancel(t)
        expect(a.current == nil && collect(a, t, 2, 0, 1).msgs == [failed], "serve: a cancelled announce serves nothing")
    }

    private static func refusals(_ root: URL, _ expect: (Bool, String) -> Void) {
        write(root.appendingPathComponent("a.bin"), [1])
        let a = FileAnnouncer(firstID: 1)
        _ = a.announce(urls: [root.appendingPathComponent("a.bin")])
        let t = a.current
        a.cancel(12345)
        expect(a.current == t, "refuse: CANCEL of another transfer leaves the announce")
        expect(a.announce(urls: [root.appendingPathComponent("nope")]).count == 1 && a.current == nil && a.refusedAnnounces == 1,
               "refuse: a copy that cannot be announced still cancels the old one")
    }
}
