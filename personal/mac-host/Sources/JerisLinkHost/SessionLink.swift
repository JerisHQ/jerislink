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
///     type 1 session: gen(8) boot(8) ipLen(1) ip(ASCII) hasKey(1) [key(32)]
///     type 0 none:    gen(8) boot(8)
///
/// r4: boot is the control service's random start number
/// (UDPPeerSession.boot), so a session after a restart never has the same
/// identity as one before it.
enum SessionLinkWire {
    static let magic: [UInt8] = Array("JLS1".utf8)
    static let typeNone: UInt8 = 0
    static let typeSession: UInt8 = 1
    static let maxBody = 8 + 8 + 1 + 15 + 1 + ConnAuth.keyBytes

    static var socketPath: String {
        if let path = ProcessInfo.processInfo.environment["JERISLINK_SESSION_SOCKET"], !path.isEmpty { return path }
        return SendWire.socketDirectory + "/session.sock"
    }

    static func encode(_ s: UDPPeerSession?, generation: UInt64, boot: UInt64? = nil) -> [UInt8] {
        var body = be64(generation) + be64(boot ?? s?.boot ?? 0)
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

    /// One frame: its generation, the session (nil: none) and the control
    /// service's boot number.
    struct Frame: Equatable {
        var generation: UInt64
        var session: UDPPeerSession?
        var boot: UInt64 = 0
    }

    /// nil: malformed (the client drops the link). r2: a "none" frame keeps
    /// its generation too, so an old one is refused like any other.
    static func decode(type: UInt8, body all: [UInt8]) -> Frame? {
        guard all.count >= 16 else { return nil }
        let gen = all[0..<8].reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
        let boot = all[8..<16].reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
        let body = Array(all[16...])
        switch type {
        case typeNone:
            return body.isEmpty ? Frame(generation: gen, session: nil, boot: boot) : nil
        case typeSession:
            guard body.count >= 2 else { return nil }
            let ipLen = Int(body[0])
            guard ipLen >= 7, ipLen <= 15, body.count >= 1 + ipLen + 1 else { return nil }
            guard let ip = String(bytes: body[1..<(1 + ipLen)], encoding: .ascii), ListenConfig.isIPv4(ip) else { return nil }
            let hasKey = body[1 + ipLen]
            let rest = body.count - (2 + ipLen)
            switch (hasKey, rest) {
            case (0, 0):
                return Frame(generation: gen, session: UDPPeerSession(generation: gen, peerIP: ip, sessionKey: nil, boot: boot), boot: boot)
            case (1, ConnAuth.keyBytes):
                return Frame(generation: gen, session: UDPPeerSession(generation: gen, peerIP: ip, sessionKey: Array(body[(2 + ipLen)...]),
                                                                      boot: boot), boot: boot)
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
        /// r4: the AUTH_RESULT session_id of this connection (password mode).
        var authSession: [UInt8]?
        var close: @Sendable () -> Void
    }

    let passwordMode: Bool
    /// r4 (Pepper's r3 review, item 3): picked once per start, never 0, so
    /// (boot, generation) names one session even across restarts.
    let boot: UInt64
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
    private var resumeRefusedCount: UInt64 = 0
    /// r5 (Pepper's r4 review, item 1): the control sessions a reconnect may
    /// name. Set by every admitted control AUTH and kept after its connection
    /// closes, so a replaced viewer stays replaced when the viewer that took
    /// over has gone too: only a new attempt (no resume id) starts over.
    /// Holds the newest session, plus the one before it when the newest
    /// named it (the same viewer reconnecting; another of its channels may
    /// still name the older id). Empty: no control AUTH since this start.
    private var accepted: [[UInt8]] = []
    /// r6 (Pepper's r5 review): control AUTHs whose AUTH_OK is on its way,
    /// by reservation. Their ids already count for `resumeRefused` (the
    /// viewer's other channels may name one right after OK), but nothing
    /// else changes until `admit(reservation:)`: the live viewer keeps the
    /// session, and `discard` (OK not sent) leaves no trace.
    private var pendingIDs: [UInt64: [UInt8]] = [:]
    private var nextReservation: UInt64 = 0
    /// The newest reservation admitted. An older one admitted later lost
    /// to a newer AUTH (reservation order is AUTH order).
    private var admittedReservation: UInt64 = 0
    /// r7 (Pepper's r6 review): woken when a pending id is admitted or
    /// dropped, for the other channels waiting on it (`awaitPending`).
    /// Taken before `lock`, never under it.
    private let pendingCond = NSCondition()
    private var waiting = 0
    /// r7 self-test: connections waiting in `awaitPending` now.
    var waitingForTest: Int { lock.lock(); defer { lock.unlock() }; return waiting }
    /// r8 (Pepper's r7 review, item 1): how each reservation ended, and the
    /// reservation behind each id. Kept after the reservation ends, so a
    /// channel naming an id is judged by that reservation's own outcome
    /// whenever it asks: a discard before it waits no longer looks like "no
    /// pending id" (which, right after a host start, let it in).
    enum ReservationEnd: Equatable { case admitted, discarded, lost }
    private var reservationOf: [[UInt8]: UInt64] = [:]
    private var reservationID: [UInt64: [UInt8]] = [:]
    private var ended: [UInt64: ReservationEnd] = [:]
    private var endedOrder: [UInt64] = []
    /// An ended reservation was forgotten (more than `keptEnded`).
    private var forgotEnded = false
    static let keptEnded = 1024
    /// r8 self-test only: runs when a wait reached its deadline with the
    /// takeover still pending, before the result is decided. nil in the app.
    var atDeadlineForTest: (@Sendable (UInt64) -> Void)?
    /// Connections closed by a newer AUTH.
    var replaced: UInt64 { lock.lock(); defer { lock.unlock() }; return replacedCount }
    /// r4: reconnects refused because another viewer holds the session.
    var resumesRefused: UInt64 { lock.lock(); defer { lock.unlock() }; return resumeRefusedCount }

    init(passwordMode: Bool, boot: UInt64? = nil, log: @escaping (String) -> Void = { print($0); fflush(stdout) }) {
        self.passwordMode = passwordMode
        self.boot = boot ?? Self.randomBoot()
        self.log = log
    }

    static func randomBoot() -> UInt64 {
        let v = ConnAuth.random(8).reduce(UInt64(0)) { $0 << 8 | UInt64($1) }
        return v == 0 ? 1 : v
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

    /// r4 (Pepper's r3 review, item 1): a viewer reconnecting on its own
    /// names the control session it had (`resume`, the session_id of its
    /// last control AUTH). r5 (Pepper's r4 review, item 1): refused unless it
    /// names the newest control session (or the one that session replaced on
    /// the same viewer's own reconnect), whether or not the viewer holding the
    /// newest session is still connected. A replaced viewer, notice or not,
    /// stays replaced until the user starts a new attempt. No control AUTH
    /// since this start: allowed.
    func resumeRefused(_ resume: [UInt8]?) -> Bool {
        guard passwordMode, let resume else { return false }
        lock.lock(); defer { lock.unlock() }
        return refusedLocked(resume)
    }

    private func refusedLocked(_ resume: [UInt8]) -> Bool {
        // r8: an id from a reservation is judged by how that reservation
        // ended: pending is let in (to wait), discarded or lost is refused.
        if let r = reservationOf[resume] {
            switch ended[r] {
            case nil: return false
            case .discarded?, .lost?: return true
            case .admitted?: break
            }
        }
        // No control AUTH since this start: allowed, unless an ended
        // reservation was forgotten (the id may be one of those).
        if accepted.isEmpty { return forgotEnded }
        return !accepted.contains(resume)
    }

    /// r8: under `lock`. Records how `reservation` ended; the oldest ended
    /// ones are forgotten past `keptEnded`.
    private func endLocked(_ reservation: UInt64, _ how: ReservationEnd) {
        guard ended[reservation] == nil, reservationID[reservation] != nil else { return }
        ended[reservation] = how
        endedOrder.append(reservation)
        while endedOrder.count > Self.keptEnded {
            let old = endedOrder.removeFirst()
            ended.removeValue(forKey: old)
            if let id = reservationID.removeValue(forKey: old), reservationOf[id] == old {
                reservationOf.removeValue(forKey: id)
            }
            forgotEnded = true
        }
    }

    /// r6: a control AUTH (password mode) before its AUTH_OK goes out. nil:
    /// refused (`resumeRefused`). Otherwise the reservation for
    /// `admit(reservation:)` once OK was sent, or `discard` if it was not.
    /// Nothing is kicked and the session does not change here.
    func reserve(authSession: [UInt8], resume: [UInt8]?) -> UInt64? {
        lock.lock(); defer { lock.unlock() }
        if passwordMode, let resume, refusedLocked(resume) {
            resumeRefusedCount &+= 1
            return nil
        }
        nextReservation &+= 1
        pendingIDs[nextReservation] = authSession
        reservationOf[authSession] = nextReservation
        reservationID[nextReservation] = authSession
        return nextReservation
    }

    /// r6: the AUTH_OK of `reservation` was not sent. Its id is dropped;
    /// the live viewer, the session and the ids a reconnect may name stay
    /// as they were.
    func discard(_ reservation: UInt64) {
        lock.lock()
        if pendingIDs.removeValue(forKey: reservation) != nil { endLocked(reservation, .discarded) }
        lock.unlock()
        wakePending()
    }

    /// r7: how the wait of a clipboard, file or ping AUTH on a pending id
    /// ended.
    enum PendingWait: Equatable {
        /// `resume` named no reservation: nothing to wait for.
        case none
        /// Its takeover was admitted; `admit` may let the channel in.
        case admitted
        /// Its takeover was discarded (OK not sent) or lost to a newer AUTH:
        /// the channel must close unused (REPLACED).
        case dropped
        /// r8 (Pepper's r7 review, item 2): still pending at the deadline.
        /// Not a loss: the channel closes without REPLACED and the viewer
        /// reconnects as after any dropped connection.
        case timedOut
    }

    /// r8 (Pepper's r7 review, item 1): the reservation `resume` names, in
    /// any state (pending or ended), taken when the channel authenticates.
    /// nil: not a reservation's id (or transition mode).
    func pendingReservation(_ resume: [UInt8]?) -> UInt64? {
        guard passwordMode, let resume else { return nil }
        lock.lock(); defer { lock.unlock() }
        return reservationOf[resume]
    }

    /// r7: `awaitReservation` for the reservation `resume` names; `.none`
    /// when it names none.
    func awaitPending(_ resume: [UInt8]?, timeout: TimeInterval = 5) -> PendingWait {
        guard let r = pendingReservation(resume) else { return .none }
        return awaitReservation(r, timeout: timeout)
    }

    /// r7 (Pepper's r6 review): a channel whose AUTH names a pending
    /// reservation (password mode) waits here, before its OK and before any
    /// of its messages are read, until that takeover ends. So no clipboard or
    /// file data is handled for a control session that never took over, and
    /// a dropped one leaves no channel open. r8: the result is that
    /// reservation's own outcome, read under `lock` after the wait, so an
    /// admit landing at the deadline counts; still pending is `.timedOut`.
    func awaitReservation(_ reservation: UInt64, timeout: TimeInterval = 5) -> PendingWait {
        func pendingLocked() -> Bool { pendingIDs[reservation] != nil }
        pendingCond.lock()
        lock.lock()
        var pending = pendingLocked()
        if pending { waiting += 1 }
        let counted = pending
        lock.unlock()
        let deadline = Date().addingTimeInterval(timeout)
        while pending {
            let now = Date()
            if now >= deadline { break }
            // Sliced, so a wake between the check and the wait is not missed
            // for long.
            pendingCond.wait(until: min(deadline, now.addingTimeInterval(0.05)))
            lock.lock(); pending = pendingLocked(); lock.unlock()
        }
        pendingCond.unlock()
        if pending, let hook = atDeadlineForTest { hook(reservation) }
        lock.lock(); defer { lock.unlock() }
        if counted { waiting -= 1 }
        switch ended[reservation] {
        case .admitted?: return .admitted
        case .discarded?, .lost?: return .dropped
        case nil: return pendingLocked() ? .timedOut : .dropped
        }
    }

    private func wakePending() {
        pendingCond.lock(); pendingCond.broadcast(); pendingCond.unlock()
    }

    /// One admitted connection. Password mode: only the control channel,
    /// with its K_s. Returns the token for `end`.
    func begin(peerIP: String, channel: ConnAuth.Channel?, sessionKey: [UInt8]?,
               close: @escaping @Sendable () -> Void) -> UInt64 {
        admit(peerIP: peerIP, channel: channel, sessionKey: sessionKey, authSession: nil, resume: nil, close: close)!
    }

    /// `begin` with the AUTH session_id and the session a reconnect names.
    /// nil: refused (`resumeRefused`, checked again here under the lock so
    /// no AUTH can come in between), or (r6) `reservation` lost to a newer
    /// control AUTH; nothing changed and nothing is kicked. `reservation`:
    /// from `reserve`, after this connection's AUTH_OK went out.
    func admit(peerIP: String, channel: ConnAuth.Channel?, sessionKey: [UInt8]?, authSession: [UInt8]?,
               resume: [UInt8]?, reservation: UInt64? = nil, waitedOn: UInt64? = nil,
               close: @escaping @Sendable () -> Void) -> UInt64? {
        var kicked: [Entry] = []
        // r2 (Pepper's PR-C review, item 1): the change and its listeners
        // run under `orderLock`, so two changes never reach the listeners
        // (and the session link's serial send queue) in the other order.
        orderLock.lock()
        lock.lock()
        if let reservation {
            let held = pendingIDs.removeValue(forKey: reservation)
            if held == nil || reservation < admittedReservation {
                endLocked(reservation, .lost)
                replacedCount &+= 1
                lock.unlock()
                orderLock.unlock()
                wakePending()
                log("auth.replaced chan=\(channel?.name ?? "open") peer=\(peerIP) stage=admit; a newer AUTH took the session first")
                return nil
            }
        }
        // r8: a channel that waited on a reservation goes in only if that
        // reservation was admitted (and its id is still valid).
        let waitedLost = waitedOn.map { ended[$0] != .admitted } ?? false
        if passwordMode, let resume, waitedLost || refusedLocked(resume) {
            if let reservation { endLocked(reservation, .lost) }
            resumeRefusedCount &+= 1
            lock.unlock()
            orderLock.unlock()
            if reservation != nil { wakePending() }
            return nil
        }
        if let reservation { admittedReservation = reservation; endLocked(reservation, .admitted) }
        nextToken &+= 1
        let token = nextToken
        if passwordMode && channel == .control {
            // §5.2: one viewer at a time; the newest AUTH wins.
            kicked = entries.filter { $0.channel == .control || $0.peerIP != peerIP }
            entries.removeAll { e in kicked.contains { $0.token == e.token } }
        }
        let entry = Entry(token: token, peerIP: peerIP, channel: channel, sessionKey: sessionKey,
                          authSession: authSession, close: close)
        if passwordMode && channel == .control, let authSession {
            // r5: the newest session; the one before it stays valid only for
            // the same viewer's own reconnect (which named it).
            let chained = resume != nil && accepted.first == resume
            accepted = chained ? [authSession, resume!] : [authSession]
        }
        entries.append(entry)
        replacedCount &+= UInt64(kicked.count)
        let change = recomputeLocked()
        lock.unlock()
        publish(change)
        orderLock.unlock()
        // r7: the channels waiting on this takeover's id may go on.
        if reservation != nil { wakePending() }
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
        announced = wanted.map { UDPPeerSession(generation: generation, peerIP: $0.ip, sessionKey: $0.key, boot: boot) }
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
                if !SendWire.send(c, SessionLinkWire.encode(session, generation: gen, boot: broker.boot)) { drop(c) }
            }
        }
    }

    private func broadcast(_ session: UDPPeerSession?, _ gen: UInt64) {
        let frame = SessionLinkWire.encode(session, generation: gen, boot: broker.boot)
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
    /// cleared when the old link went down. r4: the frame's boot number goes
    /// into the session it announces, so a generation counted again after a
    /// restart still names a different session (UDPPeerSession.ID).
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
/// that a newer AUTH replaced. `kick` (any thread) stops the connection's
/// loop, so it takes no more input, and the handler can still write the
/// "replaced" notice. A handler stuck writing to a viewer that stopped
/// reading is cut off fully after `hardCloseAfter`. `finish` (the handler,
/// before its fd is closed) makes a late kick a no-op, so a reused
/// descriptor number is never touched.
///
/// r4: a connection that gets the notice (`wake`: the control channel) is
/// woken through a pipe instead of a read-side shutdown. On macOS, input
/// that reaches a socket after `shutdown(SHUT_RD)` is answered with an RST,
/// so a viewer still sending mouse input reset its own connection before
/// the notice could be written (`auth.replaced_notice sent=0`). Other
/// channels still shut the read side.
final class KickHandle: @unchecked Sendable {
    static let hardCloseAfter: TimeInterval = 2
    /// r3: how long the control channel keeps a kicked socket open after
    /// the "replaced" notice and FIN (below hardCloseAfter).
    static let noticeLinger: TimeInterval = 1
    private let lock = NSLock()
    private var fd: Int32
    private var wasKicked = false
    private var wakeRead: Int32 = -1
    private var wakeWrite: Int32 = -1

    init(_ fd: Int32, wake: Bool = false) {
        self.fd = fd
        var p: [Int32] = [-1, -1]
        if wake, Darwin.pipe(&p) == 0 {
            _ = Darwin.fcntl(p[1], F_SETFL, Darwin.fcntl(p[1], F_GETFL) | O_NONBLOCK)
            wakeRead = p[0]
            wakeWrite = p[1]
        }
    }

    deinit {
        if wakeRead >= 0 { Darwin.close(wakeRead) }
        if wakeWrite >= 0 { Darwin.close(wakeWrite) }
    }

    /// r4: readable once kicked (-1 when this handle shuts the read side).
    var wakeFD: Int32 { wakeRead }

    var kicked: Bool { lock.lock(); defer { lock.unlock() }; return wasKicked }

    func kick() {
        lock.lock()
        defer { lock.unlock() }
        guard fd >= 0, !wasKicked else { return }
        wasKicked = true
        if wakeWrite >= 0 {
            var one: UInt8 = 1
            _ = Darwin.write(wakeWrite, &one, 1)
        } else {
            Darwin.shutdown(fd, SHUT_RD)
        }
        DispatchQueue.global().asyncAfter(deadline: .now() + Self.hardCloseAfter) { [self] in
            lock.lock(); defer { lock.unlock() }
            if fd >= 0 { Darwin.shutdown(fd, SHUT_RDWR) }
        }
    }

    func finish() {
        lock.lock(); fd = -1; lock.unlock()
    }

    /// r4: after the notice and FIN, reads and drops what the viewer still
    /// sends until it closes, for at most `noticeLinger`. Closing with input
    /// unread would send an RST, and Windows may then throw away a notice
    /// the viewer has not read yet.
    static func drainAfterNotice(_ fd: Int32) {
        let deadline = ProcessInfo.processInfo.systemUptime + noticeLinger
        var scratch = [UInt8](repeating: 0, count: 4096)
        while true {
            let left = deadline - ProcessInfo.processInfo.systemUptime
            if left <= 0 { return }
            var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let ready = Darwin.poll(&pfd, 1, Int32(max(1, left * 1000)))
            if ready < 0 && errno == EINTR { continue }
            if ready <= 0 { return }
            let n = scratch.withUnsafeMutableBytes { Darwin.recv(fd, $0.baseAddress!, 4096, 0) }
            if n < 0 && (errno == EINTR || errno == EAGAIN) { continue }
            if n <= 0 { return }
        }
    }
}
