import Foundation

/// `JerisLinkHost --self-test` part for the file transfer codec and path
/// rules (F1). The end-to-end file session checks are in
/// ControlServiceSelfTest, next to the other listener tests.
enum FileProtocolSelfTest {
    static func run() -> Int32 {
        var failures = 0
        func expect(_ ok: Bool, _ name: String) {
            print("\(ok ? "PASS" : "FAIL") \(name)")
            if !ok { failures += 1 }
        }
        codec(expect)
        paths(expect)
        clashNames(expect)
        FileUploadSelfTest.run(expect)
        FileAnnounceSelfTest.run(expect)
        return failures == 0 ? 0 : 1
    }

    private static func codec(_ expect: (Bool, String) -> Void) {
        typealias M = FileProto.Message
        let all: [M] = [
            .hello(proto: 1, caps: 0x0005),
            .helloAck(proto: 1, caps: 0, maxChunk: FileProto.maxChunk, maxTotal: FileProto.maxTotalBytes),
            .offer(transfer: 0x01020304, purpose: FileProto.Purpose.push, entries: 3, total: 1 << 40),
            .entry(transfer: 7, index: 2, kind: FileProto.EntryKind.file, size: 12345, mtime: -1, path: Array("a/b.txt".utf8)),
            .reply(transfer: 7, status: FileProto.Status.badPath),
            .data(transfer: 7, index: 2, offset: 1 << 33, bytes: [UInt8](repeating: 0xAB, count: Int(FileProto.maxChunk))),
            .fileEnd(transfer: 7, index: 2, sha256: [UInt8](repeating: 9, count: 32)),
            .result(transfer: 7, status: FileProto.Status.ok, filesOK: 3),
            .cancel(transfer: 7, reason: FileProto.Status.cancelled),
            .request(transfer: 7, index: 2, offset: 0, length: 4 << 20),
            .progress(transfer: 7, committed: 99),
            .ping(token: [1, 2, 3, 4]),
            .reveal(transfer: 7),
        ]
        let types = Set(all.map(\.type))
        expect(types == Set((0x50...0x5C).map { UInt8($0) }), "file codec: one message per type 0x50-0x5C")
        for m in all {
            guard let bytes = m.encode() else { expect(false, "file codec: encode 0x\(String(m.type, radix: 16))"); continue }
            expect(FileProto.decode(type: m.type, payload: bytes) == m, "file codec: 0x\(String(m.type, radix: 16)) round trip")
            if !bytes.isEmpty {
                expect(FileProto.decode(type: m.type, payload: Array(bytes.dropLast())) == nil
                       || m.type == FileProto.MsgType.data || m.type == FileProto.MsgType.entry,
                       "file codec: 0x\(String(m.type, radix: 16)) one byte short is rejected (variable types excepted)")
            }
        }
        // Fixed-size messages refuse extra bytes.
        expect(FileProto.decode(type: 0x50, payload: [1, 0, 0, 0]) == nil, "file codec: HELLO with 4 bytes rejected")
        expect(FileProto.decode(type: 0x5B, payload: [1, 2, 3, 4, 5]) == nil, "file codec: PING with 5 bytes rejected")
        // Byte order is big-endian.
        expect(M.hello(proto: 1, caps: 0x0102).encode() == [1, 1, 2], "file codec: HELLO caps big-endian")
        expect(M.reply(transfer: 0x0A0B0C0D, status: 4).encode() == [0x0A, 0x0B, 0x0C, 0x0D, 4], "file codec: REPLY layout")
        // Bounds.
        let chunkPlusOne = [UInt8](repeating: 0, count: 16 + Int(FileProto.maxChunk) + 1)
        expect(FileProto.decode(type: 0x55, payload: chunkPlusOne) == nil, "file codec: DATA over 32 KiB rejected")
        expect(M.data(transfer: 1, index: 0, offset: 0, bytes: [UInt8](repeating: 0, count: Int(FileProto.maxChunk) + 1)).encode() == nil,
               "file codec: DATA over 32 KiB not encoded")
        expect(FileProto.decode(type: 0x53, payload: [UInt8](repeating: 0, count: 25)) == nil, "file codec: ENTRY with empty path rejected")
        let longPath = [UInt8](repeating: 0, count: 25 + FilePathSafety.maxPathBytes + 1)
        expect(FileProto.decode(type: 0x53, payload: longPath) == nil, "file codec: ENTRY path over 1024 bytes rejected")
        var badKind = M.entry(transfer: 1, index: 0, kind: 0, size: 0, mtime: 0, path: [0x61]).encode()!
        badKind[8] = 2
        expect(FileProto.decode(type: 0x53, payload: badKind) == nil, "file codec: ENTRY unknown kind rejected")
        var badPurpose = M.offer(transfer: 1, purpose: 1, entries: 1, total: 1).encode()!
        badPurpose[4] = 0
        expect(FileProto.decode(type: 0x52, payload: badPurpose) == nil, "file codec: OFFER purpose 0 rejected")
        badPurpose[4] = 5
        expect(FileProto.decode(type: 0x52, payload: badPurpose) == nil, "file codec: OFFER purpose 5 rejected")
        expect(FileProto.decode(type: 0x5D, payload: []) == nil && FileProto.decode(type: 0x4F, payload: []) == nil,
               "file codec: types outside 0x50-0x5C rejected")
        expect(M.fileEnd(transfer: 1, index: 0, sha256: [1]).encode() == nil, "file codec: FILE_END needs 32-byte hash")
        expect(FileProto.Caps.host == FileProto.Caps.upload | FileProto.Caps.announce, "file codec: F3 host advertises upload and announce")
    }

    private static func paths(_ expect: (Bool, String) -> Void) {
        func ok(_ s: String) -> Bool { if case .ok = FilePathSafety.validate(s) { return true }; return false }
        func rej(_ s: String, _ r: FilePathSafety.Rejection) -> Bool { FilePathSafety.validate(s) == .rejected(r) }

        expect(ok("report.pdf") && ok("Photos/2026/IMG 0001.HEIC") && ok("~$draft.docx") && ok(".profile"),
               "path: ordinary relative names accepted")
        expect(ok("ab:c.txt"), "path: ':' inside a Mac name accepted (not a drive)")
        expect(rej("", .empty), "path: empty rejected")
        expect(rej("/etc/passwd", .absolute), "path: absolute rejected")
        expect(rej("..", .dotComponent) && rej("../x", .dotComponent) && rej("a/../../x", .dotComponent) && rej("a/./b", .dotComponent),
               "path: '.' and '..' components rejected")
        // A combining mark after '/' must not hide the slash (Swift Characters would join them).
        expect(rej("../\u{338}x", .dotComponent) && rej("a/\u{301}/../b", .dotComponent),
               "path: combining mark after '/' does not hide '..'")
        expect(rej("a\\..\\b", .backslash) && rej("dir\\file", .backslash), "path: backslash rejected")
        expect(rej("C:", .driveLetter) && rej("c:/Windows", .driveLetter) && rej("Z:file", .driveLetter), "path: drive letter rejected")
        expect(rej("a//b", .emptyComponent) && rej("a/", .emptyComponent), "path: empty component rejected")
        expect(rej("a\u{0}b", .controlChar) && rej("a\nb", .controlChar) && rej("a\u{7F}", .controlChar), "path: NUL and control chars rejected")
        expect(FilePathSafety.validate([0x61, 0xFF, 0x62]) == .rejected(.notUTF8), "path: invalid UTF-8 rejected")
        expect(FilePathSafety.validate([0x61, 0xC0, 0xAF]) == .rejected(.notUTF8), "path: overlong UTF-8 '/' rejected")
        let c255 = String(repeating: "a", count: 255)
        expect(ok(c255) && rej(c255 + "a", .componentTooLong), "path: component limit 255 bytes")
        let deep32 = Array(repeating: "d", count: 32).joined(separator: "/")
        expect(ok(deep32) && rej(deep32 + "/d", .tooDeep), "path: depth limit 32")
        let long = Array(repeating: String(repeating: "x", count: 200), count: 6).joined(separator: "/")
        expect(rej(long, .pathTooLong), "path: total limit 1024 bytes")
        // NFD "Café" (e + U+0301) becomes NFC (U+00E9). Swift's String ==
        // ignores normalisation, so compare the UTF-8 bytes.
        func nfcBytes(_ v: FilePathSafety.Verdict) -> [UInt8]? { if case .ok(let s) = v { return Array(s.utf8) }; return nil }
        let want = Array("Caf\u{E9}.txt".utf8)
        let nfd = "Cafe\u{301}.txt"
        expect(Array(nfd.utf8) != want && nfcBytes(FilePathSafety.validate(nfd)) == want, "path: NFD normalised to NFC")
        expect(nfcBytes(FilePathSafety.validate(Array(nfd.utf8))) == want, "path: NFD bytes normalised to NFC")
    }

    private static func clashNames(_ expect: (Bool, String) -> Void) {
        expect(FilePathSafety.clashName("report.pdf", attempt: 2) == "report 2.pdf", "clash: report 2.pdf")
        expect(FilePathSafety.clashName("notes", attempt: 3) == "notes 3", "clash: no extension")
        expect(FilePathSafety.clashName(".profile", attempt: 2) == ".profile 2", "clash: dotfile keeps its name")
        expect(FilePathSafety.clashName("a.tar.gz", attempt: 2) == "a.tar 2.gz", "clash: last dot is the extension")
        let long = String(repeating: "é", count: 126) + ".txt"   // 252 + 4 bytes
        let named = FilePathSafety.clashName(long, attempt: 10)
        expect(named.utf8.count <= 255 && named.hasSuffix(" 10.txt"), "clash: shortened to 255 bytes on a character boundary")
    }
}
