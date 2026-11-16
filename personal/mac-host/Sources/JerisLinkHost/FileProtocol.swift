import Foundation

/// File transfer wire (MRC1 types 0x50-0x5C), design r2 section 4.
///
/// A viewer opens a dedicated TCP connection to the control port and sends
/// FILE_HELLO first; the connection is then a file session and carries only
/// these types. All integers are big-endian. Decoding is strict: a payload
/// whose length does not match its type is rejected, and the session closes.
///
/// F1 ships the codec for every type so later PRs add behaviour only, never
/// wire. The host answers HELLO and PING, receives paste uploads (F2),
/// announces Finder copies and serves REQUEST pulls (F3), and refuses every
/// other request.
enum FileProto {
    static let version: UInt8 = 1

    enum MsgType {
        static let hello: UInt8 = 0x50
        static let helloAck: UInt8 = 0x51
        static let offer: UInt8 = 0x52
        static let entry: UInt8 = 0x53
        static let reply: UInt8 = 0x54      // ACCEPT (status ok) / REJECT
        static let data: UInt8 = 0x55
        static let fileEnd: UInt8 = 0x56
        static let result: UInt8 = 0x57
        static let cancel: UInt8 = 0x58
        static let request: UInt8 = 0x59
        static let progress: UInt8 = 0x5A
        static let ping: UInt8 = 0x5B
        static let reveal: UInt8 = 0x5C
    }

    enum Purpose {
        static let paste: UInt8 = 1     // Win->Mac paste, Mac->Win paste pull
        static let send: UInt8 = 2      // Windows Send to, drop on the viewer
        static let announce: UInt8 = 3  // Finder Cmd+C manifest, no data
        static let push: UInt8 = 4      // Finder "Send to JerisLink"
        static func isKnown(_ p: UInt8) -> Bool { p >= 1 && p <= 4 }
    }

    /// Capability bits in HELLO / HELLO_ACK. A side advertises only what it
    /// already implements; bits 8-15 are reserved and must be ignored.
    enum Caps {
        static let upload: UInt16 = 1 << 0       // F2: receives paste/send uploads
        static let pushService: UInt16 = 1 << 1  // F5b: Finder Send to JerisLink
        static let reveal: UInt16 = 1 << 2       // F4: 0x5C opens the received folder
        static let announce: UInt16 = 1 << 3     // F3: Cmd+C manifests, serves REQUEST
        /// What this build implements. F2: paste uploads. F3: Cmd+C
        /// announces and REQUEST pulls, on sessions whose viewer asks for them.
        static let host: UInt16 = upload | announce
    }

    enum Status {
        static let ok: UInt8 = 0
        static let tooBig: UInt8 = 1
        static let noSpace: UInt8 = 2
        static let busy: UInt8 = 3
        static let denied: UInt8 = 4
        static let badPath: UInt8 = 5
        static let failed: UInt8 = 6
        static let cancelled: UInt8 = 7
        /// F3 r2: macOS privacy settings (TCC Files & Folders) blocked the read,
        /// or a prompt asking for it is still open on the Mac. Additive.
        static let macPermission: UInt8 = 8
    }

    enum EntryKind {
        static let file: UInt8 = 0
        static let dir: UInt8 = 1
    }

    static let maxChunk: UInt16 = 32 * 1024
    static let maxTotalBytes: UInt64 = 20 * 1024 * 1024 * 1024
    static let maxEntries: UInt32 = 10_000
    /// Largest file-session payload: DATA header (16) + one chunk.
    static let maxPayload = 16 + Int(maxChunk)
    /// A file session with no message for this long is closed. The viewer
    /// pings every 15 s.
    static let idleTimeoutSeconds: Double = 60

    enum Message: Equatable {
        case hello(proto: UInt8, caps: UInt16)
        case helloAck(proto: UInt8, caps: UInt16, maxChunk: UInt16, maxTotal: UInt64)
        case offer(transfer: UInt32, purpose: UInt8, entries: UInt32, total: UInt64)
        case entry(transfer: UInt32, index: UInt32, kind: UInt8, size: UInt64, mtime: Int64, path: [UInt8])
        case reply(transfer: UInt32, status: UInt8)
        case data(transfer: UInt32, index: UInt32, offset: UInt64, bytes: [UInt8])
        case fileEnd(transfer: UInt32, index: UInt32, sha256: [UInt8])
        case result(transfer: UInt32, status: UInt8, filesOK: UInt32)
        case cancel(transfer: UInt32, reason: UInt8)
        case request(transfer: UInt32, index: UInt32, offset: UInt64, length: UInt32)
        case progress(transfer: UInt32, committed: UInt64)
        case ping(token: [UInt8])
        case reveal(transfer: UInt32)

        var type: UInt8 {
            switch self {
            case .hello: return MsgType.hello
            case .helloAck: return MsgType.helloAck
            case .offer: return MsgType.offer
            case .entry: return MsgType.entry
            case .reply: return MsgType.reply
            case .data: return MsgType.data
            case .fileEnd: return MsgType.fileEnd
            case .result: return MsgType.result
            case .cancel: return MsgType.cancel
            case .request: return MsgType.request
            case .progress: return MsgType.progress
            case .ping: return MsgType.ping
            case .reveal: return MsgType.reveal
            }
        }

        /// nil when the message cannot be encoded (a field over its limit).
        func encode() -> [UInt8]? {
            var w = Writer()
            switch self {
            case let .hello(proto, caps):
                w.u8(proto); w.u16(caps)
            case let .helloAck(proto, caps, maxChunk, maxTotal):
                w.u8(proto); w.u16(caps); w.u16(maxChunk); w.u64(maxTotal)
            case let .offer(t, purpose, entries, total):
                w.u32(t); w.u8(purpose); w.u32(entries); w.u64(total)
            case let .entry(t, index, kind, size, mtime, path):
                guard !path.isEmpty, path.count <= FilePathSafety.maxPathBytes else { return nil }
                w.u32(t); w.u32(index); w.u8(kind); w.u64(size); w.u64(UInt64(bitPattern: mtime)); w.bytes(path)
            case let .reply(t, status):
                w.u32(t); w.u8(status)
            case let .data(t, index, offset, bytes):
                guard bytes.count <= Int(FileProto.maxChunk) else { return nil }
                w.u32(t); w.u32(index); w.u64(offset); w.bytes(bytes)
            case let .fileEnd(t, index, sha):
                guard sha.count == 32 else { return nil }
                w.u32(t); w.u32(index); w.bytes(sha)
            case let .result(t, status, ok):
                w.u32(t); w.u8(status); w.u32(ok)
            case let .cancel(t, reason):
                w.u32(t); w.u8(reason)
            case let .request(t, index, offset, length):
                w.u32(t); w.u32(index); w.u64(offset); w.u32(length)
            case let .progress(t, committed):
                w.u32(t); w.u64(committed)
            case let .ping(token):
                guard token.count == 4 else { return nil }
                w.bytes(token)
            case let .reveal(t):
                w.u32(t)
            }
            return w.out
        }
    }

    /// Strict decode: exact lengths for fixed-size messages, bounded
    /// variable parts, known purpose/kind values. nil for anything else.
    static func decode(type: UInt8, payload p: [UInt8]) -> Message? {
        var r = Reader(p)
        let msg: Message?
        switch type {
        case MsgType.hello:
            guard p.count == 3 else { return nil }
            msg = .hello(proto: r.u8(), caps: r.u16())
        case MsgType.helloAck:
            guard p.count == 13 else { return nil }
            msg = .helloAck(proto: r.u8(), caps: r.u16(), maxChunk: r.u16(), maxTotal: r.u64())
        case MsgType.offer:
            guard p.count == 17 else { return nil }
            let t = r.u32(), purpose = r.u8(), entries = r.u32(), total = r.u64()
            guard Purpose.isKnown(purpose) else { return nil }
            msg = .offer(transfer: t, purpose: purpose, entries: entries, total: total)
        case MsgType.entry:
            guard p.count > 25, p.count - 25 <= FilePathSafety.maxPathBytes else { return nil }
            let t = r.u32(), index = r.u32(), kind = r.u8(), size = r.u64()
            let mtime = Int64(bitPattern: r.u64())
            guard kind == EntryKind.file || kind == EntryKind.dir else { return nil }
            msg = .entry(transfer: t, index: index, kind: kind, size: size, mtime: mtime, path: r.rest())
        case MsgType.reply:
            guard p.count == 5 else { return nil }
            msg = .reply(transfer: r.u32(), status: r.u8())
        case MsgType.data:
            guard p.count >= 16, p.count - 16 <= Int(maxChunk) else { return nil }
            msg = .data(transfer: r.u32(), index: r.u32(), offset: r.u64(), bytes: r.rest())
        case MsgType.fileEnd:
            guard p.count == 40 else { return nil }
            msg = .fileEnd(transfer: r.u32(), index: r.u32(), sha256: r.rest())
        case MsgType.result:
            guard p.count == 9 else { return nil }
            msg = .result(transfer: r.u32(), status: r.u8(), filesOK: r.u32())
        case MsgType.cancel:
            guard p.count == 5 else { return nil }
            msg = .cancel(transfer: r.u32(), reason: r.u8())
        case MsgType.request:
            guard p.count == 20 else { return nil }
            msg = .request(transfer: r.u32(), index: r.u32(), offset: r.u64(), length: r.u32())
        case MsgType.progress:
            guard p.count == 12 else { return nil }
            msg = .progress(transfer: r.u32(), committed: r.u64())
        case MsgType.ping:
            guard p.count == 4 else { return nil }
            msg = .ping(token: p)
        case MsgType.reveal:
            guard p.count == 4 else { return nil }
            msg = .reveal(transfer: r.u32())
        default:
            return nil
        }
        return msg
    }

    private struct Writer {
        var out: [UInt8] = []
        mutating func u8(_ v: UInt8) { out.append(v) }
        mutating func u16(_ v: UInt16) { out.append(UInt8(v >> 8)); out.append(UInt8(v & 0xff)) }
        mutating func u32(_ v: UInt32) { for s in stride(from: 24, through: 0, by: -8) { out.append(UInt8((v >> UInt32(s)) & 0xff)) } }
        mutating func u64(_ v: UInt64) { for s in stride(from: 56, through: 0, by: -8) { out.append(UInt8((v >> UInt64(s)) & 0xff)) } }
        mutating func bytes(_ b: [UInt8]) { out.append(contentsOf: b) }
    }

    /// Callers check the payload length first; reads never run past it.
    private struct Reader {
        let p: [UInt8]
        var i = 0
        init(_ p: [UInt8]) { self.p = p }
        mutating func u8() -> UInt8 { defer { i += 1 }; return p[i] }
        mutating func u16() -> UInt16 { UInt16(u8()) << 8 | UInt16(u8()) }
        mutating func u32() -> UInt32 { var v: UInt32 = 0; for _ in 0..<4 { v = v << 8 | UInt32(u8()) }; return v }
        mutating func u64() -> UInt64 { var v: UInt64 = 0; for _ in 0..<8 { v = v << 8 | UInt64(u8()) }; return v }
        mutating func rest() -> [UInt8] { defer { i = p.count }; return Array(p[i...]) }
    }
}
