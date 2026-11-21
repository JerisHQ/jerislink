import Darwin
import Foundation
import Security

/// The session link (PR-C): the control service tells the video service
/// which viewer the UDP paths serve, and with which key.
///
/// The control service is the only process that sees AUTH, so it owns the
/// session (SessionBroker). The video service sends video and audio, and
/// takes MRM1 input, only for the session announced here (design §5): the
/// peer IP of the authenticated control connection and, in password mode,
/// K_s for the UDP tags. Nothing announced, or the link down: nothing is
/// sent and no input is taken.
///
/// Transport: a unix stream socket in the same 0700 per-user folder as the
/// send socket, mode 0600. The server checks every peer's uid and its code
/// signature (by audit token) against this executable's own designated
/// requirement, so only another JerisLinkHost of this build can read K_s.
///
/// Wire, server to client only, one frame per change and one on connect:
///
///     "JLS1" type(1) len(2, BE) body
///     type 1 session: gen(8) ipLen(1) ip(ASCII) hasKey(1) [key(32)]
///     type 0 none:    gen(8)
enum SessionLinkWire {
    static let magic: [UInt8] = Array("JLS1".utf8)
    static let typeNone: UInt8 = 0
    static let typeSession: UInt8 = 1
    static let maxBody = 8 + 1 + 15 + 1 + ConnAuth.keyBytes

    static var socketPath: String {
        if let path = ProcessInfo.processInfo.environment["JERISLINK_SESSION_SOCKET"], !path.isEmpty { return path }
        return SendWire.socketDirectory + "/session.sock"
    }

    static func encode(_ s: UDPPeerSession?, generation: UInt64) -> [UInt8] {
        var body = be64(generation)
        let type: UInt8
        if let s, s.peerIP.utf8.count <= 15 {
            type = typeSession
            body.append(UInt8(s.peerIP.utf8.count))
            body.append(contentsOf: Array(s.peerIP.utf8))
            if let key = s.sessionKey, key.count == ConnAuth.keyBytes {
                body.append(1)
                body.append(contentsOf: key)
            } else {
                body.append(0)
            }
        } else {
            type = typeNone
        }
        return magic + [type, UInt8(body.count >> 8), UInt8(body.count & 0xff)] + body
    }

    /// One frame: its generation and the session (nil: none).
    struct Frame: Equatable {
        var generation: UInt64
        var session: UDPPeerSession?
    }

    /// nil: malformed (the client drops the link). r2: a "none" frame keeps
    /// its generation too, so an old one is refused like any other.
    static func decode(type: UInt8, body: [UInt8]) -> Frame? {
        guard body.count >= 8 else { return nil }
        let gen = body[0..<8].reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
        switch type {
        case typeNone:
            return body.count == 8 ? Frame(generation: gen, session: nil) : nil
        case typeSession:
            guard body.count >= 10 else { return nil }
            let ipLen = Int(body[8])
            guard ipLen >= 7, ipLen <= 15, body.count >= 9 + ipLen + 1 else { return nil }
            guard let ip = String(bytes: body[9..<(9 + ipLen)], encoding: .ascii), ListenConfig.isIPv4(ip) else { return nil }
            let hasKey = body[9 + ipLen]
            let rest = body.count - (10 + ipLen)
            switch (hasKey, rest) {
            case (0, 0): return Frame(generation: gen, session: UDPPeerSession(generation: gen, peerIP: ip, sessionKey: nil))
            case (1, ConnAuth.keyBytes):
                return Frame(generation: gen, session: UDPPeerSession(generation: gen, peerIP: ip, sessionKey: Array(body[(10 + ipLen)...])))
            default: return nil
            }
        default:
            return nil
        }
    }

    private static func be64(_ v: UInt64) -> [UInt8] { (0..<8).map { UInt8(truncatingIfNeeded: v >> (56 - 8 * $0)) } }
}

/// Which viewer the UDP paths serve, kept by the control service (design
/// §5, §5.2).
///
/// - Password mode: the latest control-channel (chan 1) AUTH. A new one
///   replaces the old session at once (old K_s void) and closes the old
///   control connection, plus the old viewer's other connections when it
///   came from another address (`auth.replaced`). The session ends when its
///   control connection closes.
/// - Transition mode: the newest open connection the whitelist admitted,
///   untagged (0.3 behaviour). Nothing is closed: one viewer opens several
///   connections (control, clipboard, file, ping).
final class SessionBroker: @unchecked Sendable {
    struct Entry {
        var token: UInt64
        var peerIP: String
        var channel: ConnAuth.Channel?
        var sessionKey: [UInt8]?
        var close: @Sendable () -> Void
    }

    let passwordMode: Bool
    private let lock = NSLock()
    /// Held from a change through its listeners (taken before `lock`).
    private let orderLock = NSLock()
    private var entries: [Entry] = []
    private var nextToken: UInt64 = 0
    private var generation: UInt64 = 0
    private var announced: UDPPeerSession?
    private var listeners: [@Sendable (UDPPeerSession?, UInt64) -> Void] = []
    private let log: (String) -> Void
    private var replacedCount: UInt64 = 0
    /// Connections closed by a newer AUTH.
    var replaced: UInt64 { lock.lock(); defer { lock.unlock() }; return replacedCount }

    init(passwordMode: Bool, log: @escaping (String) -> Void = { print($0); fflush(stdout) }) {
        self.passwordMode = passwordMode
        self.log = log
    }

    /// The session and its generation as of now.
    var current: (UDPPeerSession?, UInt64) {
        lock.lock(); defer { lock.unlock() }
        return (announced, generation)
    }

    /// The viewer the UDP paths serve now (the relay's blacklist check).
    var activePeerIP: String? { current.0?.peerIP }

    /// Called with every change (and its generation), outside `lock` and
    /// in generation order (under `orderLock`): a listener must not call
    /// `begin` or `end`.
    func onChange(_ handler: @escaping @Sendable (UDPPeerSession?, UInt64) -> Void) {
        lock.lock(); listeners.append(handler); lock.unlock()
    }

    /// One admitted connection. Password mode: only the control channel,
    /// with its K_s. Returns the token for `end`.
    func begin(peerIP: String, channel: ConnAuth.Channel?, sessionKey: [UInt8]?,
               close: @escaping @Sendable () -> Void) -> UInt64 {
        var kicked: [Entry] = []
        // r2 (Pepper's PR-C review, item 1): the change and its listeners
        // run under `orderLock`, so two changes never reach the listeners
        // (and the session link's serial send queue) in the other order.
        orderLock.lock()
        lock.lock()
        nextToken &+= 1
        let token = nextToken
        if passwordMode && channel == .control {
            // §5.2: one viewer at a time; the newest AUTH wins.
            kicked = entries.filter { $0.channel == .control || $0.peerIP != peerIP }
            entries.removeAll { e in kicked.contains { $0.token == e.token } }
        }
        entries.append(Entry(token: token, peerIP: peerIP, channel: channel, sessionKey: sessionKey, close: close))
        replacedCount &+= UInt64(kicked.count)
        let change = recomputeLocked()
        lock.unlock()
        publish(change)
        orderLock.unlock()
        // After the new session is announced, so the old K_s is void before
        // the old viewer hears it was replaced. Outside both locks: a close
        // may end its connection (`end`) on this thread.
        for e in kicked {
            log("auth.replaced old_peer=\(e.peerIP) chan=\(e.channel?.name ?? "open") new_peer=\(peerIP); old connection closed")
            e.close()
        }
        return token
    }

    func end(_ token: UInt64) {
        orderLock.lock()
        lock.lock()
        entries.removeAll { $0.token == token }
        let change = recomputeLocked()
        lock.unlock()
        publish(change)
        orderLock.unlock()
    }

    /// The announced session from `entries`. Caller holds `lock`.
    private func recomputeLocked() -> (UDPPeerSession?, UInt64, [@Sendable (UDPPeerSession?, UInt64) -> Void])? {
        let source: Entry?
        if passwordMode {
            source = entries.last { $0.channel == .control && $0.sessionKey != nil }
        } else {
            source = entries.last
        }
        let wanted = source.map { (ip: $0.peerIP, key: $0.sessionKey) }
        let same = wanted?.ip == announced?.peerIP && wanted?.key == announced?.sessionKey && (wanted == nil) == (announced == nil)
        if same { return nil }
        generation &+= 1
        announced = wanted.map { UDPPeerSession(generation: generation, peerIP: $0.ip, sessionKey: $0.key) }
        return (announced, generation, listeners)
    }

    private func publish(_ change: (UDPPeerSession?, UInt64, [@Sendable (UDPPeerSession?, UInt64) -> Void])?) {
        guard let (session, gen, run) = change else { return }
        log("session.link gen=\(gen) \(session.map { "peer=\($0.peerIP) udp=\($0.tagged ? "tagged" : "untagged")" } ?? "none")")
        run.forEach { $0(session, gen) }
    }
}

/// The control service's end of the session link.
final class SessionLinkServer: @unchecked Sendable {
    typealias PeerCheck = @Sendable (Int32) -> Bool

    let path: String
    private let broker: SessionBroker
    private let peerCheck: PeerCheck
    private let lock = NSLock()
    private var listenFD: Int32 = -1
    private var clients: Set<Int32> = []
    /// Serializes frames so every client sees the changes in order.
    private let sendQueue = DispatchQueue(label: "JerisLink.SessionLink.send")
    private(set) var refusedPeers: UInt64 = 0

    init(path: String = SessionLinkWire.socketPath, broker: SessionBroker,
         peerCheck: @escaping PeerCheck = { SessionLinkServer.isSameProgram($0) }) {
        self.path = path
        self.broker = broker
        self.peerCheck = peerCheck
    }

    func start() throws {
        try SendSocketServer.prepareDirectory((path as NSString).deletingLastPathComponent)
        var st = stat()
        if lstat(path, &st) == 0 {
            guard (st.st_mode & S_IFMT) == S_IFSOCK else { throw Self.error("session socket path is not a socket") }
            unlink(path)
        }
        let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw Self.error("session socket failed errno=\(errno)") }
        _ = fcntl(fd, F_SETFD, FD_CLOEXEC)
        guard var addr = SendWire.address(path) else { Darwin.close(fd); throw Self.error("session socket path too long") }
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard rc == 0, chmod(path, 0o600) == 0, Darwin.listen(fd, 4) == 0 else {
            let e = errno
            Darwin.close(fd)
            throw Self.error("session socket bind/listen failed errno=\(e)")
        }
        lock.lock(); listenFD = fd; lock.unlock()
        broker.onChange { [weak self] session, gen in self?.broadcast(session, gen) }
        let t = Thread { [self] in acceptLoop(fd) }
        t.name = "JerisLink.SessionLink"
        t.start()
        print("session.link_socket=listening")
    }

    func stop() {
        lock.lock()
        let fd = listenFD
        listenFD = -1
        let open = clients
        clients.removeAll()
        lock.unlock()
        for c in open { Darwin.shutdown(c, SHUT_RDWR); Darwin.close(c) }
        if fd >= 0 { Darwin.shutdown(fd, SHUT_RDWR); Darwin.close(fd); unlink(path) }
    }

    private func acceptLoop(_ fd: Int32) {
        while true {
            let c = Darwin.accept(fd, nil, nil)
            if c < 0 {
                if errno == EINTR || errno == ECONNABORTED { continue }
                lock.lock(); let open = listenFD == fd; lock.unlock()
                if !open { return }
                usleep(100_000)
                continue
            }
            _ = fcntl(c, F_SETFD, FD_CLOEXEC)
            SendWire.setTimeouts(c, seconds: 2)
            var uid: uid_t = 0
            var gid: gid_t = 0
            guard getpeereid(c, &uid, &gid) == 0, uid == getuid(), peerCheck(c) else {
                lock.lock(); refusedPeers &+= 1; lock.unlock()
                print("session.link peer=refused")
                Darwin.close(c)
                continue
            }
            // Registered and sent the current state in the send queue, so a
            // change made meanwhile is never sent before it.
            sendQueue.async { [self] in
                lock.lock(); clients.insert(c); lock.unlock()
                let (session, gen) = broker.current
                if !SendWire.send(c, SessionLinkWire.encode(session, generation: gen)) { drop(c) }
            }
        }
    }

    private func broadcast(_ session: UDPPeerSession?, _ gen: UInt64) {
        let frame = SessionLinkWire.encode(session, generation: gen)
        sendQueue.async { [self] in
            lock.lock(); let open = clients; lock.unlock()
            for c in open where !SendWire.send(c, frame) { drop(c) }
        }
    }

    private func drop(_ c: Int32) {
        lock.lock(); let had = clients.remove(c) != nil; lock.unlock()
        if had { Darwin.close(c) }
    }

    // MARK: Peer check

    /// True when the process at the other end of `sock` (by audit token)
    /// satisfies this executable's own designated requirement: the same
    /// signed JerisLinkHost (Developer ID: same identifier and team; ad hoc
    /// builds: the same cdhash).
    static func isSameProgram(_ sock: Int32) -> Bool {
        var token = audit_token_t()
        var len = socklen_t(MemoryLayout<audit_token_t>.size)
        guard getsockopt(sock, 0 /* SOL_LOCAL */, 6 /* LOCAL_PEERTOKEN */, &token, &len) == 0,
              Int(len) == MemoryLayout<audit_token_t>.size else { return false }
        guard let requirement = ownRequirement else { return false }
        let tokenData = withUnsafeBytes(of: &token) { Data($0) }
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: tokenData] as CFDictionary,
                                             SecCSFlags(), &code) == errSecSuccess, let code else { return false }
        return SecCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess
    }

    nonisolated(unsafe) private static let ownRequirement: SecRequirement? = {
        var me: SecCode?
        guard SecCodeCopySelf(SecCSFlags(), &me) == errSecSuccess, let me else { return nil }
        var staticMe: SecStaticCode?
        guard SecCodeCopyStaticCode(me, SecCSFlags(), &staticMe) == errSecSuccess, let staticMe else { return nil }
        var req: SecRequirement?
        guard SecCodeCopyDesignatedRequirement(staticMe, SecCSFlags(), &req) == errSecSuccess else { return nil }
        return req
    }()

    private static func error(_ s: String) -> NSError {
        NSError(domain: "JerisLink.SessionLink", code: 1, userInfo: [NSLocalizedDescriptionKey: s])
    }
}

/// The video service's end: keeps `state` in step with the control
/// service. Link down (control service restarting, not started yet):
/// no session.
final class SessionLinkClient: @unchecked Sendable {
    private let path: String
    private let state: UDPSessionState
    private let retry: TimeInterval
    private let lock = NSLock()
    private var stopped = false
    private var fd: Int32 = -1
    private let serverCheck: @Sendable (Int32) -> Bool

    init(path: String = SessionLinkWire.socketPath, state: UDPSessionState, retry: TimeInterval = 0.5,
         serverCheck: @escaping @Sendable (Int32) -> Bool = { SessionLinkServer.isSameProgram($0) }) {
        self.path = path
        self.state = state
        self.retry = retry
        self.serverCheck = serverCheck
    }

    func start() {
        let t = Thread { [self] in run() }
        t.name = "JerisLink.SessionLinkClient"
        t.start()
    }

    func stop() {
        lock.lock(); stopped = true; let s = fd; lock.unlock()
        if s >= 0 { Darwin.shutdown(s, SHUT_RDWR) }
    }

    private var isStopped: Bool { lock.lock(); defer { lock.unlock() }; return stopped }

    private func run() {
        var logged = false
        while !isStopped {
            if let s = connect() {
                lock.lock(); fd = s; lock.unlock()
                print("session.link_client=connected")
                fflush(stdout)
                logged = false
                readLoop(s)
                lock.lock(); fd = -1; lock.unlock()
                Darwin.close(s)
                state.set(nil)
                print("session.link_client=disconnected (no session until it is back)")
                fflush(stdout)
            } else if !logged {
                print("session.link_client=waiting (control service not reachable; nothing sent)")
                fflush(stdout)
                logged = true
            }
            Thread.sleep(forTimeInterval: retry)
        }
    }

    private func connect() -> Int32? {
        let s = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard s >= 0 else { return nil }
        _ = fcntl(s, F_SETFD, FD_CLOEXEC)
        var one: Int32 = 1
        setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        guard var addr = SendWire.address(path) else { Darwin.close(s); return nil }
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(s, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard rc == 0 else { Darwin.close(s); return nil }
        // The server must be the same program too: K_s is only taken from it.
        guard serverCheck(s) else {
            print("session.link_client server=refused")
            Darwin.close(s)
            return nil
        }
        return s
    }

    /// r2 (Pepper's PR-C review, item 1): a frame older than the last one
    /// on this connection is refused, "none" included, so an old K_s or
    /// destination never comes back. The same generation again is fine (the
    /// state sent on connect can repeat a change). A new connection starts
    /// over: a restarted control service counts from 1, and the state was
    /// cleared when the old link went down.
    static func accept(_ frame: SessionLinkWire.Frame, after last: UInt64?) -> Bool {
        guard let last else { return true }
        return frame.generation >= last
    }

    private func readLoop(_ s: Int32) {
        var none: [Int32] = []
        var last: UInt64?
        while !isStopped {
            guard let head = SendWire.receive(s, 7, fds: &none), none.isEmpty,
                  Array(head[0..<4]) == SessionLinkWire.magic else { return }
            let len = Int(head[5]) << 8 | Int(head[6])
            guard len <= SessionLinkWire.maxBody, let body = SendWire.receive(s, len, fds: &none), none.isEmpty,
                  let frame = SessionLinkWire.decode(type: head[4], body: body) else { return }
            guard Self.accept(frame, after: last) else {
                print("session.link_client stale gen=\(frame.generation) last=\(last ?? 0); ignored")
                fflush(stdout)
                continue
            }
            last = frame.generation
            state.set(frame.session)
        }
    }
}

/// r2 (Pepper's PR-C review, item 2): how SessionBroker ends a connection
/// that a newer AUTH replaced. `kick` (any thread) shuts the read side, so
/// the connection's loop sees EOF and takes no more input, and the handler
/// can still write the "replaced" notice. A handler stuck writing to a
/// viewer that stopped reading is cut off fully after `hardCloseAfter`.
/// `finish` (the handler, before its fd is closed) makes a late kick a
/// no-op, so a reused descriptor number is never touched.
final class KickHandle: @unchecked Sendable {
    static let hardCloseAfter: TimeInterval = 2
    /// r3: how long the control channel keeps a kicked socket open after
    /// the "replaced" notice and FIN (below hardCloseAfter).
    static let noticeLinger: TimeInterval = 1
    private let lock = NSLock()
    private var fd: Int32
    private var wasKicked = false

    init(_ fd: Int32) { self.fd = fd }

    var kicked: Bool { lock.lock(); defer { lock.unlock() }; return wasKicked }

    func kick() {
        lock.lock()
        defer { lock.unlock() }
        guard fd >= 0, !wasKicked else { return }
        wasKicked = true
        Darwin.shutdown(fd, SHUT_RD)
        DispatchQueue.global().asyncAfter(deadline: .now() + Self.hardCloseAfter) { [self] in
            lock.lock(); defer { lock.unlock() }
            if fd >= 0 { Darwin.shutdown(fd, SHUT_RDWR) }
        }
    }

    func finish() {
        lock.lock(); fd = -1; lock.unlock()
    }
}
