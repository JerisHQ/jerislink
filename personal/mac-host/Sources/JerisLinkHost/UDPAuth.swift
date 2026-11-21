import CommonCrypto
import Darwin
import Foundation

/// UDP tags (design v0.4.0 §5.1, PR-C).
///
/// In password mode every UDP datagram in both directions (MRM1 input and
/// feedback, MR02 video, MRA1 audio, pongs and cursor shapes) ends with an
/// 8-byte tag:
///
///     K_s = HMAC-SHA256(K, "jl-udp" | host_nonce | client_nonce | session_id)
///     tag = HMAC-SHA256(K_s, "v2h" or "h2v" | datagram without the tag)[0..8]
///
/// K_s comes from the control channel's AUTH, so a new session (reconnect,
/// replaced viewer) makes every old tag useless. The direction string stops
/// a datagram from being reflected back to its sender. A tagged datagram
/// sets bit 0x80 of byte 4 (the version byte of MRM1, MR02 and MRA1), which
/// 0.3.x parsers reject, so they never take a tagged datagram for theirs.
/// The tag covers that byte too.
///
/// Transition mode (no password) sends and accepts untagged datagrams only,
/// as in 0.3, so 0.3.x viewers keep working.
enum UDPTag {
    static let bytes = ConnAuth.tagBytes
    static let flag: UInt8 = 0x80
    static let versionByte = 4
}

/// Precomputed HMAC-SHA256 state for one session key and one direction:
/// the key schedule and the direction string are hashed once, so each
/// datagram costs one context copy plus the hash of its own bytes.
/// Safe to share across threads: `tag` copies the base context and never
/// writes to it.
struct UDPTagger: Sendable {
    let hostToViewer: Bool
    private let base: CCHmacContext

    init(sessionKey: [UInt8], hostToViewer: Bool) {
        self.hostToViewer = hostToViewer
        var ctx = CCHmacContext()
        CCHmacInit(&ctx, CCHmacAlgorithm(kCCHmacAlgSHA256), sessionKey, sessionKey.count)
        let dir = Array((hostToViewer ? "h2v" : "v2h").utf8)
        CCHmacUpdate(&ctx, dir, dir.count)
        base = ctx
    }

    /// The 8-byte tag of `count` bytes at `p`, written to `out`.
    func tag(_ p: UnsafeRawPointer, _ count: Int, into out: UnsafeMutableRawPointer) {
        var ctx = base
        CCHmacUpdate(&ctx, p, count)
        // Stack scratch: no heap allocation per datagram.
        withUnsafeTemporaryAllocation(byteCount: Int(CC_SHA256_DIGEST_LENGTH), alignment: 1) { mac in
            CCHmacFinal(&ctx, mac.baseAddress!)
            out.copyMemory(from: mac.baseAddress!, byteCount: UDPTag.bytes)
        }
    }

    /// Sends `packet` sealed (flag set, tag appended) without touching it:
    /// one copy into stack scratch, then `body` gets the sealed bytes.
    func withSealed<R>(_ packet: UnsafeRawBufferPointer, _ body: (UnsafeRawBufferPointer) -> R) -> R {
        let n = packet.count
        return withUnsafeTemporaryAllocation(byteCount: n + UDPTag.bytes, alignment: 1) { buf in
            if let src = packet.baseAddress, n > 0 { buf.baseAddress!.copyMemory(from: src, byteCount: n) }
            if n > UDPTag.versionByte { buf[UDPTag.versionByte] |= UDPTag.flag }
            tag(UnsafeRawPointer(buf.baseAddress!), n, into: buf.baseAddress! + n)
            return body(UnsafeRawBufferPointer(buf))
        }
    }

    func tag(_ bytes: [UInt8]) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: UDPTag.bytes)
        bytes.withUnsafeBytes { raw in
            out.withUnsafeMutableBytes { tag(raw.baseAddress ?? UnsafeRawPointer(bitPattern: 1)!, bytes.count, into: $0.baseAddress!) }
        }
        return out
    }

    /// Sets the tag flag and appends the tag (sending side).
    func seal(_ packet: inout Data) {
        guard packet.count > UDPTag.versionByte else { return }
        let i = packet.startIndex + UDPTag.versionByte
        packet[i] |= UDPTag.flag
        var t = [UInt8](repeating: 0, count: UDPTag.bytes)
        packet.withUnsafeBytes { raw in
            t.withUnsafeMutableBytes { tag(raw.baseAddress!, raw.count, into: $0.baseAddress!) }
        }
        packet.append(contentsOf: t)
    }

    func seal(_ packet: [UInt8]) -> [UInt8] {
        var d = Data(packet)
        seal(&d)
        return [UInt8](d)
    }

    /// Receiving side: true when `count` bytes at `p` carry the flag and a
    /// tag that matches (constant time). The caller then parses
    /// `count - UDPTag.bytes` bytes with the flag cleared.
    func verify(_ p: UnsafeRawPointer, _ count: Int) -> Bool {
        guard count > UDPTag.bytes + UDPTag.versionByte,
              p.load(fromByteOffset: UDPTag.versionByte, as: UInt8.self) & UDPTag.flag != 0 else { return false }
        let body = count - UDPTag.bytes
        return withUnsafeTemporaryAllocation(byteCount: UDPTag.bytes, alignment: 1) { want in
            tag(p, body, into: want.baseAddress!)
            var diff: UInt8 = 0
            for i in 0..<UDPTag.bytes { diff |= want[i] ^ p.load(fromByteOffset: body + i, as: UInt8.self) }
            return diff == 0
        }
    }
}

/// The viewer the video service serves, as the control service announced
/// it over the session link (SessionLink): the peer IP of the live control
/// session and, in password mode, its UDP session key. nil: no session,
/// nothing is sent and no input is taken.
struct UDPPeerSession: Equatable, Sendable {
    /// Moves on with every announcement, so a reconnect from the same IP
    /// with a new key is a new session too.
    var generation: UInt64
    var peerIP: String
    /// nil in transition mode (untagged datagrams, as 0.3).
    var sessionKey: [UInt8]?
    /// r4 (Pepper's r3 review, item 3): a random number the control service
    /// picks once when it starts. The generation starts again at 1 after a
    /// restart; (boot, generation) is never reused.
    var boot: UInt64 = 0

    /// The session as audio and the UDP paths name it.
    struct ID: Hashable, Sendable, CustomStringConvertible {
        var boot: UInt64
        var generation: UInt64
        var description: String { "\(generation)/\(String(boot, radix: 16))" }
    }

    var id: ID { ID(boot: boot, generation: generation) }
    var tagged: Bool { sessionKey != nil }
    var summary: String { "gen=\(id) peer=\(peerIP) udp=\(tagged ? "tagged" : "untagged")" }
}

/// Thread-safe holder of the current session for the video service's UDP
/// paths, with the taggers built once per session.
final class UDPSessionState: @unchecked Sendable {
    struct Snapshot {
        var session: UDPPeerSession
        var address: in_addr
        /// h2v, for what the host sends.
        var send: UDPTagger?
        /// v2h, for what the host receives.
        var receive: UDPTagger?
    }

    private let lock = NSLock()
    private var current: Snapshot?
    private var handlers: [@Sendable (UDPPeerSession?) -> Void] = []
    /// Password mode as this process started (listen.plist): an untagged
    /// session announced while it is on is refused (no stream, no input).
    let requireTags: Bool

    init(requireTags: Bool) { self.requireTags = requireTags }

    var snapshot: Snapshot? { lock.lock(); defer { lock.unlock() }; return current }
    var session: UDPPeerSession? { snapshot?.session }

    /// Called for every change, on the caller's thread, after the state moved.
    func onChange(_ handler: @escaping @Sendable (UDPPeerSession?) -> Void) {
        lock.lock(); handlers.append(handler); lock.unlock()
    }

    /// Applies an announcement. Returns false when it was refused (then the
    /// state is no session).
    @discardableResult func set(_ session: UDPPeerSession?) -> Bool {
        var next: Snapshot?
        var refused = false
        if let session {
            var addr = in_addr()
            if inet_pton(AF_INET, session.peerIP, &addr) != 1 {
                refused = true
            } else if requireTags && !session.tagged {
                refused = true
            } else {
                next = Snapshot(session: session, address: addr,
                                send: session.sessionKey.map { UDPTagger(sessionKey: $0, hostToViewer: true) },
                                receive: session.sessionKey.map { UDPTagger(sessionKey: $0, hostToViewer: false) })
            }
        }
        lock.lock()
        let changed = current?.session != next?.session
        current = next
        let run = handlers
        lock.unlock()
        if refused {
            print("udp.session_refused reason=\(requireTags ? "untagged_in_password_mode" : "bad_peer") (nothing sent, no input)")
            fflush(stdout)
        }
        if changed {
            print("udp.session \(next?.session.summary ?? "none (nothing sent, no input)")")
            fflush(stdout)
            run.forEach { $0(next?.session) }
        }
        return !refused
    }
}

/// `udp.bad_tag peer=… n=…` at most once per `interval` (design §5.1): a
/// flood of forged datagrams cannot flood the log. Counts every drop.
final class BadTagLog: @unchecked Sendable {
    private let lock = NSLock()
    private let interval: TimeInterval
    private let now: () -> TimeInterval
    private let write: (String) -> Void
    private var pending: UInt64 = 0
    private var lastPeer = "-"
    private var lastReason = "-"
    private var lastLog: TimeInterval = -.infinity
    private(set) var total: UInt64 = 0
    private let entry: String

    init(entry: String, interval: TimeInterval = 10,
         now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
         write: @escaping (String) -> Void = { print($0); fflush(stdout) }) {
        self.entry = entry
        self.interval = interval
        self.now = now
        self.write = write
    }

    /// One dropped datagram. Never answers the sender.
    func drop(peer: String, reason: String) {
        lock.lock()
        total &+= 1
        pending &+= 1
        lastPeer = peer
        lastReason = reason
        let t = now()
        guard t - lastLog >= interval else { lock.unlock(); return }
        lastLog = t
        let line = "udp.bad_tag entry=\(entry) peer=\(lastPeer) reason=\(lastReason) n=\(pending) total=\(total)"
        pending = 0
        lock.unlock()
        write(line)
    }
}
