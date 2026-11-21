import Foundation
import Darwin
import Carbon
import AppKit

final class ControlServer: @unchecked Sendable {
    private let bindIP: String
    private let allowedClientIP: String?
    private let port: UInt16
    private let injectRequested: Bool
    private let queue = DispatchQueue(label: "JerisLink.ControlServer")
    private let lock = NSLock()
    private var serverFD: Int32 = -1
    private var clientFDs: Set<Int32> = []
    /// Sockets set to close with RST (resetPeer); `lock`.
    private var resetFDs: Set<Int32> = []
    private var stopping = false
    private var inputHelper: InputHelperClient?
    private let videoSettings = VideoSettingsController()
    private var shiftDown = false
    private var capsAlphaMode = false
    private var capsTemporaryInputSourceID: String?
    private static let usInputSourceID = "com.apple.keylayout.US"

    private(set) var messages: UInt64 = 0
    private(set) var keyEvents: UInt64 = 0
    private(set) var mouseEvents: UInt64 = 0
    /// Input helper send failures: counted, and logged at most once per 10 s.
    private var sendFailures = LogRateLimiter()
    private let sendFailuresLock = NSLock()
    private(set) var clipboardSent: UInt64 = 0
    private(set) var clipboardReceived: UInt64 = 0
    private(set) var rejectedClients: UInt64 = 0
    private(set) var settingsRejected: UInt64 = 0
    private(set) var fileSessions: UInt64 = 0
    private(set) var fileRefused: UInt64 = 0
    private(set) var fileUploads: UInt64 = 0
    private(set) var fileUploadsFailed: UInt64 = 0
    private(set) var fileRxBytes: UInt64 = 0
    private var fileAnnounces: UInt64 = 0
    private var filePulls: UInt64 = 0
    private var fileTxBytes: UInt64 = 0
    private var filePushes: UInt64 = 0
    /// Open file sessions that announce Finder copies (F3). While one is
    /// open the text clipboard session leaves file copies alone, so the
    /// filename text Finder also puts on the pasteboard does not replace the
    /// file object on the Windows clipboard.
    private var announceSessions = 0
    private let fileStatsLock = NSLock()
    /// When a Mac->Windows paste last pulled bytes (systemUptime seconds).
    /// While that is recent, pasteboard changes wait: a Mac copy made
    /// mid-paste must not cancel the announce Explorer is reading, nor
    /// replace the Windows clipboard under it (F3 r3). 0: never.
    private var lastPullServe: TimeInterval = 0
    /// How long a paste counts as running after its last REQUEST. Explorer
    /// asks again within milliseconds while it copies, so this only bridges
    /// the gap between files; the waiting copy syncs once it has passed.
    static let pullHoldSeconds: TimeInterval = 3
    /// Uploads (paste or Send to) running in this server's file sessions.
    private var uploadsActive = 0
    /// Open file sessions whose viewer shows NOTICE (caps notice).
    private var noticeSessions = 0
    /// Bumped for each refused Cmd+V; every notice session sends one NOTICE
    /// per bump on its next poll (it owns its socket, so no cross-thread send).
    private var noticeSeq: UInt64 = 0
    private var finderPastesRefused: UInt64 = 0
    /// r10: frames and bytes this host wrote to each viewer address (send
    /// calls that wrote at least one byte). Read by the self-test.
    private var txByPeer: [String: (sends: UInt64, bytes: UInt64)] = [:]
    private let txLock = NSLock()
    /// r10, self-test only: called with the frame type just before an
    /// admitted viewer's frame asks the policy and its peer (`sendChecked`),
    /// so a test can land a block between handling a request and its reply.
    /// Set before start(); nil in the app.
    var beforeCheckedSend: (@Sendable (UInt8) -> Void)?
    /// r6, self-test only: true makes this AUTH_OK fail as a send to a
    /// viewer that went away would (nothing is written). Set before start();
    /// nil in the app.
    var failAuthOKForTest: (@Sendable (ConnAuth.Channel) -> Bool)?
    /// r10: how long a handshake frame (CHALLENGE, RESULT) may wait for the
    /// viewer's window before the connection is dropped.
    static let handshakeSendSeconds: TimeInterval = 5
    /// Cmd+V to Finder while a transfer runs (FinderPasteGate).
    private var pasteGate = FinderPasteGate()
    /// The frontmost Mac app (a fake in the self-test).
    private let frontmostApp: () -> String?
    /// The viewer allowed to change video settings (JERISLINK_CLIENT_IP),
    /// read for every request so a network.conf change applies at once.
    private let settingsClientIP: () -> String?
    /// Read PROXY headers from loopback peers (legacy `tailscale serve`
    /// forward). Off for `--service control`, whose sockets see real peers.
    private let acceptProxy: Bool
    /// Tell the input helper when a viewer input session starts and ends
    /// (MRI1 SESSION_START / SESSION_END). On for viewer-facing listeners;
    /// off for the loopback relay, whose client is the long-lived video
    /// service.
    private let announceInputSessions: Bool
    /// Answer FILE_HELLO (0x50). Only the viewer-facing direct listener;
    /// the loopback relay and the legacy listeners refuse it (design D13).
    private let allowFileSessions: Bool
    /// FORCE_QUIT_OPEN (0x60) and CLIPBOARD_HELLO (0x30) act for the viewer
    /// beyond keys and mouse. False on the loopback relay: its one real
    /// client (the video service) sends only mouse moves, and a loopback
    /// peer (or an old `tailscale serve` forward to 38411) cannot prove it
    /// is the configured viewer. Elsewhere SettingsAuthority decides.
    private let allowSensitiveControl: Bool
    /// The loopback relay (#58 r2): only the video service's mouse relay may
    /// connect (RelayCaller), and it may send MOUSE_MOVE_ABS_NORM (0x24) only.
    /// Any other message closes the connection.
    private let relayMouseOnly: Bool
    private let relayCaller: (_ clientPort: UInt16, _ serverPort: UInt16) -> RelayCaller.Decision
    private(set) var relayRejected: UInt64 = 0
    /// Where paste uploads are staged (a temp folder in the self-test).
    private let fileStagingRoot: URL
    /// Where drops land and what REVEAL opens (a temp folder in the self-test).
    private let fileSendFolder: FileSendFolder
    private static let maxClipboardBytes = 60 * 1024
    /// Pasteboard access for clipboard sessions (a fake in the self-test).
    private let clipboard: ClipboardBackend
    /// Current keyboard input source, cached from the system notification so
    /// the per-key Caps check never asks TIS on the main thread.
    private let inputSources: InputSourceCache
    /// Finder "Send to JerisLink" jobs for file sessions (F5b).
    private let pushBroker: PushBroker
    /// Connection password gate (v0.4.0). nil: the listener checks only
    /// `allowedClientIP`, as in 0.3 (legacy listeners, loopback relay).
    private let authGate: AuthGate?
    /// Asked for every accepted connection before anything is read: false
    /// closes it. The control service re-reads its policy here, the legacy
    /// listeners whether a password is set (LegacyAuthWatch).
    private let admitConnection: (@Sendable () -> Bool)?
    /// Asked again for every message on an open connection (r4): false
    /// closes it before the message is handled, so a policy change stops an
    /// open connection (the mouse relay included) on its next message, not on
    /// the next periodic check. Callers make it one stat while listen.plist
    /// is unchanged (PolicyWatch.stillCurrent, LegacyAuthWatch.check).
    private let admitMessage: (@Sendable () -> Bool)?
    /// r8: asked with the connection's peer address next to `admitMessage`,
    /// on every message and every file or clipboard session loop turn:
    /// false closes that connection only. The control service asks the
    /// guard's blacklist (AuthGuard.inputRefusal), so a block added while
    /// the connection is open (pending journal or listen.plist) stops that
    /// viewer's sessions on their next message; other viewers go on.
    private let admitPeerMessage: (@Sendable (String) -> Bool)?
    private(set) var authFailures: UInt64 = 0
    /// r4: reconnects refused because another viewer holds the session.
    private(set) var resumesRefused: UInt64 = 0
    /// PR-C: which viewer the UDP paths serve (the session link to the
    /// video service). Every admitted connection registers here; in password
    /// mode the control channel carries K_s and a new one replaces the old
    /// session. nil: legacy listeners and the loopback relay.
    private let sessionBroker: SessionBroker?
    /// Zero-MAC probes answered without counting (item 5, PR-C).
    private(set) var probesUncounted: UInt64 = 0
    /// r2: 0.3.x viewers answered AUTH_REQUIRED without counting a try.
    private(set) var oldViewersUncounted: UInt64 = 0
    /// r2: repeated refusals (a viewer reconnecting in a loop) log once per 10 s.
    let authLog = AuthLogThrottle()

    init(bindIP: String, allowedClientIP: String?, port: UInt16, inject: Bool,
         settingsClientIP: @escaping () -> String? = { ListenConfig.configuredClientIP() },
         acceptProxy: Bool = true,
         inputHelper: InputHelperClient? = nil,
         announceInputSessions: Bool = true,
         allowFileSessions: Bool = false,
         allowSensitiveControl: Bool = true,
         relayMouseOnly: Bool = false,
         relayCaller: @escaping (_ clientPort: UInt16, _ serverPort: UInt16) -> RelayCaller.Decision = RelayCaller.check,
         fileStagingRoot: URL = FileUploadReceiver.defaultRoot,
         fileSendFolder: FileSendFolder = .shared,
         clipboard: ClipboardBackend = SystemClipboard.shared,
         inputSources: InputSourceCache = .shared,
         pushBroker: PushBroker = .shared,
         authGate: AuthGate? = nil,
         admitConnection: (@Sendable () -> Bool)? = nil,
         admitMessage: (@Sendable () -> Bool)? = nil,
         admitPeerMessage: (@Sendable (String) -> Bool)? = nil,
         sessionBroker: SessionBroker? = nil,
         frontmostApp: @escaping () -> String? = { FrontmostApp.bundleID() }) {
        self.bindIP = bindIP
        self.clipboard = clipboard
        self.inputSources = inputSources
        self.pushBroker = pushBroker
        self.authGate = authGate
        self.admitConnection = admitConnection
        self.admitMessage = admitMessage
        self.admitPeerMessage = admitPeerMessage
        self.sessionBroker = sessionBroker
        self.frontmostApp = frontmostApp
        self.announceInputSessions = announceInputSessions
        self.allowFileSessions = allowFileSessions
        self.allowSensitiveControl = allowSensitiveControl
        self.relayMouseOnly = relayMouseOnly
        self.relayCaller = relayCaller
        self.fileStagingRoot = fileStagingRoot
        self.fileSendFolder = fileSendFolder
        self.inputHelper = inputHelper
        self.acceptProxy = acceptProxy
        self.allowedClientIP = allowedClientIP
        self.port = port
        self.injectRequested = inject
        self.settingsClientIP = settingsClientIP
    }

    /// The legacy listeners: `--control-only`, and control inside the video
    /// host (--bind-ip/--client-ip). `globalClientIP` is the network.conf
    /// viewer (a fixed value in the self-test).
    static func legacyListener(bindIP: String, allowedClientIP: String?, port: UInt16, inject: Bool,
                               globalClientIP: @escaping () -> String? = { ListenConfig.configuredClientIP() },
                               clipboard: ClipboardBackend = SystemClipboard.shared,
                               admit: (@Sendable () -> Bool)? = nil) -> ControlServer {
        // The listener's own --control-client-ip wins; network.conf only decides when it is not set.
        ControlServer(bindIP: bindIP, allowedClientIP: allowedClientIP, port: port, inject: inject,
                      settingsClientIP: { allowedClientIP ?? globalClientIP() }, clipboard: clipboard,
                      admitConnection: admit, admitMessage: admit)
    }

    func start() throws {
        let fd = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw NSError(domain: "JerisLink.Control", code: 1, userInfo: [NSLocalizedDescriptionKey: "control socket failed errno=\(errno)"]) }

        var yes: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        let pton = bindIP.withCString { inet_pton(AF_INET, $0, &addr.sin_addr) }
        guard pton == 1 else {
            Darwin.close(fd)
            throw NSError(domain: "JerisLink.Control", code: 2, userInfo: [NSLocalizedDescriptionKey: "invalid control bind IP \(bindIP)"])
        }

        let rc = withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard rc == 0 else {
            let e = errno
            Darwin.close(fd)
            throw NSError(domain: "JerisLink.Control", code: 3, userInfo: [NSLocalizedDescriptionKey: "control bind failed errno=\(e)"])
        }
        guard Darwin.listen(fd, 4) == 0 else {
            let e = errno
            Darwin.close(fd)
            throw NSError(domain: "JerisLink.Control", code: 4, userInfo: [NSLocalizedDescriptionKey: "control listen failed errno=\(e)"])
        }

        lock.lock()
        serverFD = fd
        stopping = false
        lock.unlock()

        inputSources.start()

        var helperOK = false
        if injectRequested {
            // Keep the client object even when the Helper is not reachable yet.
            // InputHelperClient reconnects lazily on send, which removes the
            // boot-order dependency where the Host had to start after the app.
            // A caller running several servers passes one shared client: the
            // helper serves a single connection at a time.
            let helper = inputHelper ?? InputHelperClient()
            inputHelper = helper
            helperOK = helper.ping()
        }
        let info = Bundle.main.infoDictionary
        let version = info?["CFBundleShortVersionString"] as? String ?? "dev"
        let build = info?["JLBuildSHA"] as? String ?? "dev"
        print("Control MRC1: version=\(version) build=\(build) \(bindIP):\(port), allowedClient=\(allowedClientIP ?? "any"), inject=\(injectRequested ? "requested" : "off"), inputHelper=\(helperOK ? "ready" : "unavailable")")
        if injectRequested && !helperOK {
            print("Control warning: JerisLink Input Helper is not reachable yet; input will reconnect lazily when the next event arrives.")
        }

        queue.async { [weak self] in self?.acceptLoop() }
    }

    func stop() {
        lock.lock()
        stopping = true
        let s = serverFD
        let clients = Array(clientFDs)
        serverFD = -1
        lock.unlock()

        // Client handlers own close(); shutdown is enough to wake any blocked
        // recv/poll without risking a descriptor being closed twice.
        for c in clients { Darwin.shutdown(c, SHUT_RDWR) }
        if s >= 0 { Darwin.shutdown(s, SHUT_RDWR); Darwin.close(s) }
    }

    private var helperSendFailures: UInt64 {
        sendFailuresLock.lock(); defer { sendFailuresLock.unlock() }
        return sendFailures.total
    }

    /// One send failure per input event is possible while the helper is
    /// down, so log the first and then at most one per 10 s.
    private func warnSendFailed(_ what: String) {
        sendFailuresLock.lock()
        let folded = sendFailures.record(nowNs: DispatchTime.now().uptimeNanoseconds)
        sendFailuresLock.unlock()
        guard let folded else { return }
        print("Control warning: input helper \(what) send failed" + (folded > 0 ? " (\(folded) more since the last warning)" : ""))
    }

    func statsLine() -> String {
        "control_messages=\(messages) control_key_events=\(keyEvents) control_mouse_events=\(mouseEvents) clipboard_tx=\(clipboardSent) clipboard_rx=\(clipboardReceived) control_rejected_clients=\(rejectedClients) auth_failures=\(authFailures) settings_rejected=\(settingsRejected) relay_rejected=\(relayRejected) file_sessions=\(fileSessions) file_refused=\(fileRefused) \(fileStatsText()) helper_send_failures=\(helperSendFailures) main_hops=\(MainThreadHops.total)"
    }

    private func acceptLoop() {
        while true {
            lock.lock()
            let shouldStop = stopping
            let s = serverFD
            lock.unlock()
            if shouldStop || s < 0 { break }

            var peer = sockaddr_in()
            var peerLen = socklen_t(MemoryLayout<sockaddr_in>.size)
            let c = withUnsafeMutablePointer(to: &peer) { p -> Int32 in
                p.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.accept(s, $0, &peerLen)
                }
            }
            if c < 0 {
                lock.lock(); let nowStopping = stopping; lock.unlock()
                if nowStopping { break }
                continue
            }

            var noSigPipe: Int32 = 1
            setsockopt(c, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))
            let keepAlive = Self.enableKeepAlive(c)

            let peerIP = String(cString: inet_ntoa(peer.sin_addr))
            // r11: fail closed. Without the send timeout a send() that finds
            // the buffer short of room could wait on a stalled viewer for good.
            if !sendSliceSetter(c) {
                rejectedClients += 1
                print("Control reject peer=\(peerIP) reason=send_timeout_unset on \(bindIP):\(port); connection closed")
                Darwin.close(c)
                continue
            }
            // r12: fail closed too. Every write to a viewer must be
            // non-blocking (sendPacket); a socket that cannot be made so
            // is not served.
            if !nonBlockingSetter(c) {
                rejectedClients += 1
                print("Control reject peer=\(peerIP) reason=nonblocking_unset on \(bindIP):\(port); connection closed")
                Darwin.close(c)
                continue
            }
            if let allowedClientIP, peerIP != allowedClientIP {
                rejectedClients += 1
                print("Control reject peer=\(peerIP) expected=\(allowedClientIP) on \(bindIP):\(port); connection closed")
                Darwin.close(c)
                continue
            }
            if let admitConnection, !admitConnection() {
                rejectedClients += 1
                print("Control reject peer=\(peerIP) reason=policy_changed on \(bindIP):\(port); connection closed")
                Darwin.close(c)
                continue
            }

            lock.lock(); clientFDs.insert(c); lock.unlock()
            let peerPort = UInt16(bigEndian: peer.sin_port)
            print("Control client connected: \(peerIP):\(peerPort) keepalive=\(keepAlive ? Self.keepAliveSummary : "off")")
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                guard let self else {
                    Darwin.close(c)
                    return
                }
                self.handleClient(c, tcpPeerIP: peerIP, tcpPeerPort: peerPort)
                self.lock.lock()
                self.clientFDs.remove(c)
                let reset = self.resetFDs.remove(c) != nil
                self.lock.unlock()
                if reset { Self.settleBeforeReset(c) }
                Darwin.close(c)
                print("Control client disconnected: \(peerIP):\(peerPort)")
            }
        }
    }

    /// TCP keepalive on each viewer connection: after `keepAliveIdle` s with
    /// nothing received, probe every `keepAliveInterval` s, and give up after
    /// `keepAliveCount` unanswered probes (about 25 s). A viewer that vanished
    /// (killed, asleep, off the network) sends no FIN, and an input or
    /// clipboard session blocks in recv until the socket errors, which on an
    /// idle connection never happens: it held its input session open with no
    /// end. A live
    /// viewer's TCP stack answers the probes, idle or not.
    static let keepAliveIdle: Int32 = 10
    static let keepAliveInterval: Int32 = 5
    static let keepAliveCount: Int32 = 3
    static var keepAliveSummary: String { "\(keepAliveIdle)/\(keepAliveInterval)/\(keepAliveCount)" }

    /// Returns false when any option was refused (the connection still runs).
    static func enableKeepAlive(_ fd: Int32) -> Bool {
        func set(_ level: Int32, _ name: Int32, _ value: Int32) -> Bool {
            var v = value
            return setsockopt(fd, level, name, &v, socklen_t(MemoryLayout<Int32>.size)) == 0
        }
        let on = set(SOL_SOCKET, SO_KEEPALIVE, 1)
        let idle = set(IPPROTO_TCP, TCP_KEEPALIVE, keepAliveIdle)
        let interval = set(IPPROTO_TCP, TCP_KEEPINTVL, keepAliveInterval)
        let count = set(IPPROTO_TCP, TCP_KEEPCNT, keepAliveCount)
        return on && idle && interval && count
    }

    private func handleClient(_ fd: Int32, tcpPeerIP: String, tcpPeerPort: UInt16) {
        if relayMouseOnly {
            if case .reject(let reason) = relayCaller(tcpPeerPort, port) {
                relayRejected += 1
                print("Control relay reject peer=\(tcpPeerIP):\(tcpPeerPort) on \(bindIP):\(port) reason=\(reason); connection closed")
                return
            }
        }
        var pending: [UInt8]?
        var peer = ControlPeer(ip: tcpPeerIP, verified: !ControlPeer.isLoopback(tcpPeerIP))
        // Only a local forwarder (tailscale serve --proxy-protocol) may name
        // another address; a remote client cannot claim one.
        if acceptProxy && ControlPeer.isLoopback(tcpPeerIP) {
            guard let first = recvExact(fd, count: 8) else { return }
            switch ProxyProtocol.parse(first: first, read: { self.recvExact(fd, count: $0) }) {
            case .notProxy:
                pending = first
            case .proxy(let source):
                if let source { peer = ControlPeer(ip: source, verified: true) }
                print("Control PROXY peer=\(source ?? "local") via=\(tcpPeerIP)")
            case .invalid(let reason):
                print("Control bad PROXY header (\(reason)) via=\(tcpPeerIP)")
                return
            }
        }
        // Connection password (v0.4.0): blacklist, whitelist, waits, then
        // AUTH before any other message. In transition mode only the address
        // checks run. `authChannel` is the channel the viewer authenticated
        // for; the connection is held to it.
        var authChannel: ConnAuth.Channel?
        var udpSessionKey: [UInt8]?
        var authOK: AuthOK?
        if let authGate {
            // The policy this gate holds was replaced (ControlService.PolicyWatch):
            // nothing more is admitted under it.
            if authGate.isRevoked {
                print("Control reject peer=\(peer.ip) reason=policy_revoked; connection closed")
                return
            }
            if authGate.requiresPassword {
                guard pending == nil, let ok = authenticate(fd, peer: peer, gate: authGate) else { return }
                authChannel = ok.channel
                authOK = ok
                udpSessionKey = ok.channel == .control ? ok.sessionKey : nil
            } else {
                guard admitWithoutPassword(fd, peer: peer, gate: authGate) else { return }
            }
        }
        let authenticated = authChannel != nil
        // The gate let this connection in: a password-authenticated viewer,
        // or in transition mode a whitelisted address seen on the real
        // socket (the direct listener reads no PROXY header). Either is a
        // configured viewer for VIDEO_CONFIG_SET and the sensitive messages,
        // now that the whitelist replaces clientIP.
        let gateAdmitted = authenticated || (authGate != nil && !acceptProxy && peer.verified)
        if let sessionBroker, authGate != nil {
            // r2 (Pepper's PR-C review, item 2): a newer AUTH ends this
            // connection through `kick` (any thread). The loop below returns
            // at once and takes no more input (r4: a control connection is
            // woken through `wakeFD`, other channels shut the read side); the
            // control channel then tells the viewer it was replaced, so it stops
            // reconnecting instead of taking the session back.
            let kick = KickHandle(fd, wake: authChannel == .control)
            /// REPLACED and close: a refused reconnect, or (r6) a takeover
            /// that lost to a newer one while its OK went out.
            func refuse(stage: String, lost: Bool) {
                kick.finish()
                if !lost { lock.lock(); resumesRefused += 1; lock.unlock() }
                let sent = sendPacket(fd, type: ConnAuth.MsgType.result, payload: ConnAuth.Result.replaced.payload)
                let what = lost ? "auth.replaced_late" : "auth.resume_refused"
                authLog.log(what, peer: peer.ip,
                            "\(what) peer=\(peer.ip) chan=\(authChannel?.name ?? "open") stage=\(stage) sent=\(sent ? 1 : 0) counted=0")
                if sent {
                    Darwin.shutdown(fd, SHUT_WR)
                    KickHandle.drainAfterNotice(fd)
                }
            }
            // r6 (Pepper's r5 review): a password-mode control AUTH takes
            // over only after its OK went out. Until then its id is pending
            // (`reserve`): a clipboard or file AUTH naming it right after OK is
            // let in (r5 item 2), but the live viewer, its video and the ids
            // it may reconnect with stay as they are. OK not sent: the
            // pending id is dropped and nothing else changes.
            var reservation: UInt64?
            if let authOK, authChannel == .control, sessionBroker.passwordMode {
                guard let r = sessionBroker.reserve(authSession: authOK.sessionID, resume: authOK.resume) else {
                    refuse(stage: "reserve", lost: false)
                    return
                }
                guard sendAuthOK(fd, peerIP: peer.ip, authOK) else {
                    sessionBroker.discard(r)
                    kick.finish()
                    print("auth.ok_unsent peer=\(peer.ip) chan=control; pending session dropped, live viewer kept")
                    return
                }
                reservation = r
            }
            // r4: the reconnect check again, now atomically with taking the
            // session (an AUTH may have finished since `authenticate`).
            guard let token = sessionBroker.admit(peerIP: peer.ip, channel: authChannel, sessionKey: udpSessionKey,
                                                  authSession: authChannel == .control ? authOK?.sessionID : nil,
                                                  resume: authOK?.resume, reservation: reservation,
                                                  close: { kick.kick() }) else {
                refuse(stage: "admit", lost: reservation != nil)
                return
            }
            // Other channels: OK once the connection is in the broker. A
            // failed OK only ends this connection (it holds no session id).
            if reservation == nil, let authOK, !sendAuthOK(fd, peerIP: peer.ip, authOK) {
                sessionBroker.end(token)
                kick.finish()
                return
            }
            defer {
                sessionBroker.end(token)
                kick.finish()
            }
            serveAdmitted(fd, peer: peer, pending: pending, authChannel: authChannel, gateAdmitted: gateAdmitted,
                          wake: kick.wakeFD)
            if kick.kicked && authChannel == .control {
                let sent = sendPacket(fd, type: ConnAuth.MsgType.result, payload: ConnAuth.Result.replaced.payload)
                print("auth.replaced_notice peer=\(peer.ip) sent=\(sent ? 1 : 0)")
                // r3 (Pepper's r2 review, item 1): FIN after the notice, then
                // keep the socket open a moment instead of closing it at once.
                // A close with input still unread on our side sends an RST,
                // and Windows may throw away a notice the viewer has not read
                // yet; the viewer would then reconnect and take the session back.
                // r4: the viewer's input is read and dropped until it closes
                // (at most `noticeLinger`), so nothing is left unread at close.
                if sent {
                    Darwin.shutdown(fd, SHUT_WR)
                    KickHandle.drainAfterNotice(fd)
                }
            }
        } else {
            if let authOK, !sendAuthOK(fd, peerIP: peer.ip, authOK) { return }
            serveAdmitted(fd, peer: peer, pending: pending, authChannel: authChannel, gateAdmitted: gateAdmitted)
        }
    }

    /// The message loop of one admitted connection.
    private func serveAdmitted(_ fd: Int32, peer: ControlPeer, pending: [UInt8]?,
                               authChannel: ConnAuth.Channel?, gateAdmitted: Bool, wake: Int32 = -1) {
        let authenticated = gateAdmitted
        // A connection is an input session only once it sends its first key
        // or mouse message; clipboard, PING and VIDEO_CONFIG sessions never
        // are. One bool test per message, one helper message per session edge.
        // A START that did not reach the helper (helper down) is retried on
        // the next input message, and the input message that failed it is
        // dropped: input reaches the helper only inside a session it knows.
        // END is sent only for a started session. The relay listener has no
        // lifecycle and forwards as before.
        let sessionID = Self.sessionIDs.next()
        var sessionStarted = false
        defer { if sessionStarted { endInputSession(sessionID) } }
        var firstHeader: [UInt8]? = pending
        var connectionMessages = 0
        while true {
            let next: [UInt8]?
            if let firstHeader { next = firstHeader } else { next = recvExact(fd, count: 8, wake: wake) }
            firstHeader = nil
            guard let header = next else { return }
            guard header[0] == 0x4d, header[1] == 0x52, header[2] == 0x43, header[3] == 0x31, header[4] == 1 else {
                print("Control bad header")
                return
            }
            let type = header[5]
            let length = Int(UInt16(header[6]) << 8 | UInt16(header[7]))
            guard length <= Self.maxClipboardBytes, let payload = recvExact(fd, count: length, wake: wake) else { return }
            if let admitMessage, !admitMessage() {
                rejectedClients += 1
                print("Control reject peer=\(peer.ip) reason=policy_changed type=0x\(String(type, radix: 16)) on \(bindIP):\(port); open connection closed")
                resetPeer(fd)
                return
            }
            if let admitPeerMessage, !admitPeerMessage(peer.ip) {
                rejectedClients += 1
                print("Control reject peer=\(peer.ip) reason=peer_refused type=0x\(String(type, radix: 16)) on \(bindIP):\(port); open connection closed")
                resetPeer(fd)
                return
            }
            // Transition mode: a v0.4 viewer's probe learns that this host
            // has no password yet. Not counted, so FILE_HELLO can follow.
            if type == ConnAuth.MsgType.response, let authGate, !authGate.requiresPassword {
                guard sendChecked(fd, peerIP: peer.ip, kind: "control", type: ConnAuth.MsgType.result,
                                  payload: ConnAuth.Result.openIPOnly.payload) == .sent else { return }
                continue
            }
            messages += 1
            connectionMessages += 1
            if let authChannel, !Self.channelAllows(authChannel, type: type, first: connectionMessages == 1) {
                print("auth.channel_mismatch peer=\(peer.ip) chan=\(authChannel.name) type=0x\(String(type, radix: 16)); connection closed")
                return
            }
            if relayMouseOnly && type != 0x24 {
                relayRejected += 1
                if type == FileProto.MsgType.hello {
                    fileRefused += 1
                    print("file.session=refused")
                }
                print("Control relay reject type=0x\(String(type, radix: 16)) on \(bindIP):\(port) reason=mouse-move-only; connection closed")
                return
            }
            if !sessionStarted && announceInputSessions && Self.isInputMessage(type) {
                pasteGate = FinderPasteGate()  // no Cmd held over from an earlier viewer
                sessionStarted = startInputSession(sessionID)
                if !sessionStarted { continue }
            }

            switch type {
            case FileProto.MsgType.hello: // FILE_HELLO: dedicate this TCP session to file transfer.
                // Only as the first message, and only on the direct listener.
                guard allowFileSessions, connectionMessages == 1,
                      case .hello(let proto, let peerCaps)? = FileProto.decode(type: type, payload: payload), proto >= 1 else {
                    fileRefused += 1
                    print("file.session=refused")
                    return
                }
                handleFileSession(fd, peerCaps: peerCaps, peerIP: peer.ip)
                return
            case 0x30: // CLIPBOARD_HELLO: dedicate this TCP session to clipboard sync.
                guard payload.isEmpty else { return }
                guard sensitiveAllowed(type: type, peer: peer, authenticated: authenticated) else { return }
                print("Clipboard session connected")
                handleClipboardSession(fd, peerIP: peer.ip)
                print("Clipboard session ended")
                return
            case 0x01: // PING
                if payload.count == 4 {
                    guard sendChecked(fd, peerIP: peer.ip, kind: "control", type: 0x02, payload: payload) == .sent else { return }
                }
            case 0x40: // VIDEO_CONFIG_SET v1
                let clientIP = settingsClientIP()
                let ack: VideoSettingsAck
                // A password-authenticated viewer is the configured viewer.
                switch authenticated ? .allow : SettingsAuthority.check(peer: peer, clientIP: clientIP) {
                case .allow:
                    ack = videoSettings.apply(request: payload)
                case .reject(let reason):
                    settingsRejected += 1
                    print("Video config reject peer=\(peer.ip) verified=\(peer.verified) expected=\(clientIP ?? "unset") reason=\(reason); settings unchanged")
                    ack = videoSettings.currentAck(ignored: true)
                }
                // r10: the ACK asks again; a block that landed while the
                // settings were applied gets no reply.
                guard sendChecked(fd, peerIP: peer.ip, kind: "control", type: 0x41, payload: ack.payload) == .sent else { return }
                print("Video config ACK status=\(ack.status) codec=\(ack.codec) bitrate_mbps=\(ack.bitrateMbps) flags=0x\(String(ack.flags, radix: 16)) remote_size=\(ack.framebufferWidth)x\(ack.framebufferHeight)")
            case 0x10: // KEY
                if payload.count == 3 {
                    let down = payload[0] != 0
                    let semantic = UInt16(payload[1]) << 8 | UInt16(payload[2])
                    handleKey(semantic: semantic, down: down)
                }
            case 0x20: // MOUSE_MOVE_REL
                if payload.count == 4 {
                    let dx = Int16(bitPattern: UInt16(payload[0]) << 8 | UInt16(payload[1]))
                    let dy = Int16(bitPattern: UInt16(payload[2]) << 8 | UInt16(payload[3]))
                    handleMouseMove(dx: dx, dy: dy)
                }
            case 0x21: // MOUSE_BUTTON
                if payload.count == 2 {
                    handleMouseButton(button: payload[0], down: payload[1] != 0)
                }
            case 0x25: // MOUSE_BUTTON_EXT (button, down, clickCount)
                if payload.count == 3 {
                    handleMouseButtonExtended(button: payload[0], down: payload[1] != 0, clickCount: payload[2])
                }
            case 0x22: // MOUSE_SCROLL
                if payload.count == 4 {
                    let dx = Int16(bitPattern: UInt16(payload[0]) << 8 | UInt16(payload[1]))
                    let dy = Int16(bitPattern: UInt16(payload[2]) << 8 | UInt16(payload[3]))
                    handleScroll(dx: dx, dy: dy)
                }
            case 0x23: // MOUSE_MOVE_ABS (legacy pixel coordinates)
                if payload.count == 4 {
                    let x = UInt16(payload[0]) << 8 | UInt16(payload[1])
                    let y = UInt16(payload[2]) << 8 | UInt16(payload[3])
                    handleMouseMoveAbsolute(x: x, y: y)
                }
            case 0x24: // MOUSE_MOVE_ABS_NORM (0...65535)
                if payload.count == 4 {
                    let nx = UInt16(payload[0]) << 8 | UInt16(payload[1])
                    let ny = UInt16(payload[2]) << 8 | UInt16(payload[3])
                    handleMouseMoveNormalized(nx: nx, ny: ny)
                }
            case 0x60: // FORCE_QUIT_OPEN, empty payload
                if payload.isEmpty, sensitiveAllowed(type: type, peer: peer, authenticated: authenticated) { handleForceQuitOpen() }
            default:
                print("Control unknown type=\(type) len=\(length)")
            }
        }
    }

    /// FORCE_QUIT_OPEN and CLIPBOARD_HELLO: refused on the loopback relay,
    /// and elsewhere allowed only for the configured viewer (the same check
    /// as VIDEO_CONFIG_SET), so a peer that cannot be verified gets neither.
    private func sensitiveAllowed(type: UInt8, peer: ControlPeer, authenticated: Bool) -> Bool {
        let reason: String
        if !allowSensitiveControl {
            reason = "relay"
        } else if authenticated {
            return true
        } else {
            let clientIP = settingsClientIP()
            switch SettingsAuthority.check(peer: peer, clientIP: clientIP) {
            case .allow: return true
            case .reject(let why): reason = why
            }
        }
        print("Control sensitive reject type=0x\(String(type, radix: 16)) peer=\(peer.ip) verified=\(peer.verified) on \(bindIP):\(port) reason=\(reason)")
        return false
    }

    private static func isInputMessage(_ type: UInt8) -> Bool {
        switch type {
        case 0x10, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x60: return true
        default: return false
        }
    }

    /// Returns true when SESSION_START reached the helper, so SESSION_END is
    /// sent only for a session the helper knows about.
    private func startInputSession(_ id: UInt32) -> Bool {
        guard announceInputSessions, injectRequested, let helper = inputHelper else { return false }
        return helper.sendSessionStart(id: id)
    }

    private func endInputSession(_ id: UInt32) {
        guard let helper = inputHelper else { return }
        _ = helper.sendSessionEnd(id: id)
    }

    /// Input session ids, unique per process (shared by every listener, as
    /// is the one helper connection). 0 is never used.
    private final class SessionIDCounter: @unchecked Sendable {
        private let lock = NSLock()
        private var last: UInt32 = 0
        func next() -> UInt32 {
            lock.lock(); defer { lock.unlock() }
            last &+= 1
            if last == 0 { last = 1 }
            return last
        }
    }
    private static let sessionIDs = SessionIDCounter()

    private func announceSessionsOpen() -> Bool {
        fileStatsLock.lock(); defer { fileStatsLock.unlock() }
        return announceSessions > 0
    }

    private func notePullServe() {
        fileStatsLock.lock(); lastPullServe = ProcessInfo.processInfo.systemUptime; fileStatsLock.unlock()
    }

    /// A paste is pulling now: leave the pasteboard change for later.
    private func pullHeld() -> Bool {
        fileStatsLock.lock(); defer { fileStatsLock.unlock() }
        return lastPullServe > 0 && ProcessInfo.processInfo.systemUptime - lastPullServe < Self.pullHoldSeconds
    }

    /// Keep `uploadsActive` in step with one session's receiver.
    private func noteUpload(_ was: inout Bool, active: Bool) {
        guard was != active else { return }
        was = active
        fileStatsLock.lock(); uploadsActive += active ? 1 : -1; fileStatsLock.unlock()
    }

    /// A Cmd+V for Finder now would land mid-transfer: an upload is running
    /// or a paste is pulling, a viewer can show the notice (so nothing is
    /// eaten silently), and Finder is frontmost (checked last: a main-thread
    /// hop).
    private func finderPasteBlocked() -> Bool {
        fileStatsLock.lock()
        let running = uploadsActive > 0 || (lastPullServe > 0 &&
            ProcessInfo.processInfo.systemUptime - lastPullServe < Self.pullHoldSeconds)
        let canNotify = noticeSessions > 0
        fileStatsLock.unlock()
        guard running, canNotify else { return false }
        return frontmostApp() == FinderPasteGate.finderBundleID
    }

    private func requestPasteBusyNotice() {
        fileStatsLock.lock(); noticeSeq &+= 1; finderPastesRefused += 1; fileStatsLock.unlock()
    }

    private func currentNoticeSeq() -> UInt64 {
        fileStatsLock.lock(); defer { fileStatsLock.unlock() }
        return noticeSeq
    }

    private func fileStatsText() -> String {
        fileStatsLock.lock(); defer { fileStatsLock.unlock() }
        return "file_uploads=\(fileUploads) file_upload_failed=\(fileUploadsFailed) file_rx_bytes=\(fileRxBytes) file_announces=\(fileAnnounces) file_pulls=\(filePulls) file_tx_bytes=\(fileTxBytes) file_pushes=\(filePushes) finder_paste_refused=\(finderPastesRefused)"
    }

    /// A file session: HELLO_ACK with this build's caps, PING echo, paste
    /// and send uploads through `FileUploadReceiver` (F2, F4), REVEAL (F4,
    /// no reply), and REJECT `denied` for every other request until F5
    /// implements them. A viewer whose HELLO
    /// carries caps `announce` gets Finder copies announced on this session
    /// and pulls their bytes with REQUEST (F3, `FileAnnouncer`); the
    /// pasteboard is checked on each 100 ms poll by its change count only. Any malformed or
    /// unexpected message closes the session, and a session that ends with
    /// an upload running removes its partial files. Runs on this client's own
    /// thread; only the final pasteboard write hops to the main thread. Logs
    /// carry no file names (D15): only open/closed and counts.
    private func handleFileSession(_ fd: Int32, peerCaps: UInt16, peerIP: String) {
        fileSessions += 1
        let receiver = FileUploadReceiver(root: fileStagingRoot, clipboard: clipboard, sendFolder: fileSendFolder)
        let announcer: FileAnnouncer? = (peerCaps & FileProto.Caps.announce) != 0 ? FileAnnouncer() : nil
        // A copy made before the session opened is not announced: the viewer
        // connecting must not replace what the Windows clipboard holds.
        var lastChangeCount = clipboard.changeCount()
        if announcer != nil {
            fileStatsLock.lock(); announceSessions += 1; fileStatsLock.unlock()
        }
        let ack = FileProto.Message.helloAck(proto: FileProto.version, caps: FileProto.Caps.host,
                                             maxChunk: FileProto.maxChunk, maxTotal: FileProto.maxTotalBytes)
        guard let ackBytes = ack.encode(),
              sendChecked(fd, peerIP: peerIP, kind: "file", type: ack.type, payload: ackBytes) == .sent else { return }
        print("file.session=open caps=0x\(String(FileProto.Caps.host, radix: 16)) peer_caps=0x\(String(peerCaps, radix: 16))")
        // r9: every frame to the viewer asks first (the policy, then this
        // peer's block), so a block that lands mid-transfer stops a 4 MiB
        // pull or push before its next frame, not after it; the session
        // then closes and the socket with it. One stat each per frame.
        // r10: and again while a frame waits for a viewer that stopped
        // reading (sendChecked), so the wait cannot outlast the block.
        var revoked = false
        func sendGuarded(_ type: UInt8, _ payload: [UInt8]) -> Bool {
            switch sendChecked(fd, peerIP: peerIP, kind: "file", type: type, payload: payload) {
            case .sent: return true
            case .refused: revoked = true; return false
            case .failed: return false
            }
        }
        func sendMessage(_ m: FileProto.Message) -> Bool {
            guard let bytes = m.encode() else { return false }
            return sendGuarded(m.type, bytes)
        }
        func sendAll(_ msgs: [FileProto.Message]) -> Bool {
            for out in msgs {
                guard sendMessage(out) else { return false }
            }
            return true
        }
        // r3: this viewer shows NOTICE; refused Finder pastes are told here.
        let showsNotice = (peerCaps & FileProto.Caps.notice) != 0
        var lastNotice: UInt64 = 0
        if showsNotice {
            fileStatsLock.lock(); noticeSessions += 1; lastNotice = noticeSeq; fileStatsLock.unlock()
        }
        var uploading = false
        var received = 0
        var refused = 0
        var reason = "peer_closed"
        // F5b: Finder pushes go to the newest session; one at a time.
        let pushSession = pushBroker.register(peerCaps: peerCaps)
        var push: PushSender?
        func endPush() {
            guard let p = push else { return }
            p.close()
            fileStatsLock.lock(); filePushes += 1; fileTxBytes += p.bytesOut; fileStatsLock.unlock()
            pushBroker.finished(p.job)
            push = nil
        }
        defer {
            if revoked { reason = "policy_changed" }
            // r10: a session the policy ended is reset, not drained.
            if reason == "policy_changed" { resetPeer(fd) }
            endPush()
            pushBroker.unregister(pushSession)
            receiver.abort(reason: reason)
            noteUpload(&uploading, active: false)
            if showsNotice { fileStatsLock.lock(); noticeSessions -= 1; fileStatsLock.unlock() }
            announcer?.close()
            fileStatsLock.lock()
            fileUploads += receiver.completed
            fileUploadsFailed += receiver.failed
            fileRxBytes += receiver.bytesIn
            if let announcer {
                announceSessions -= 1
                fileAnnounces += announcer.announces
                filePulls += announcer.filesServed
                fileTxBytes += announcer.bytesOut
            }
            fileStatsLock.unlock()
            print("file.session=closed reason=\(reason) messages=\(received) refused=\(refused)")
        }
        var lastMessage = Date()

        while true {
            lock.lock(); let shouldStop = stopping; lock.unlock()
            if shouldStop { reason = "stopping"; return }
            // r5 (B3): nothing more is sent or served once the policy moved.
            if sessionRevoked("file", peerIP: peerIP) { reason = "policy_changed"; return }
            if Date().timeIntervalSince(lastMessage) > FileProto.idleTimeoutSeconds { reason = "idle"; return }
            if showsNotice {
                let seq = currentNoticeSeq()
                if seq != lastNotice {
                    lastNotice = seq
                    guard sendAll([.notice(code: FileProto.Notice.pasteBusy)]) else { reason = "send_failed"; return }
                }
            }
            if let p = push, p.ended { endPush() }
            if let p = push, !p.accepted, p.job.isAbandoned {
                guard sendAll(p.abandon()) else { reason = "send_failed"; return }
                endPush()
            }
            if push == nil, let job = pushBroker.take(session: pushSession) {
                let p = PushSender(job: job)
                push = p
                guard sendAll(p.start()) else { reason = "send_failed"; return }
            }
            if let announcer {
                let changeCount = clipboard.changeCount()
                // Mid-paste the change waits (lastChangeCount stays), so the
                // announce Explorer is reading stays served.
                if changeCount != lastChangeCount, !pullHeld() {
                    lastChangeCount = changeCount
                    // This host's own F2 paste holds staging files Windows
                    // already has: never announce them back.
                    let urls = clipboard.ownFileWriteChangeCount() == changeCount ? nil : clipboard.readFileURLs()
                    guard sendAll(announcer.announce(urls: urls)) else { reason = "send_failed"; return }
                }
            }

            var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let ready = Darwin.poll(&pfd, 1, 100)
            if ready < 0 {
                if errno == EINTR { continue }
                reason = "poll_error"; return
            }
            if ready == 0 { continue }
            if (pfd.revents & Int16(POLLERR | POLLNVAL)) != 0 { reason = "socket_error"; return }

            guard let header = recvExact(fd, count: 8) else { return }
            guard header[0] == 0x4d, header[1] == 0x52, header[2] == 0x43, header[3] == 0x31, header[4] == 1 else {
                reason = "bad_header"; return
            }
            let type = header[5]
            let length = Int(UInt16(header[6]) << 8 | UInt16(header[7]))
            guard length <= FileProto.maxPayload else { reason = "too_long"; return }
            guard let payload = recvExact(fd, count: length) else { return }
            if sessionRevoked("file", peerIP: peerIP) { reason = "policy_changed"; return }
            received += 1
            lastMessage = Date()
            pushBroker.heard(pushSession)

            guard let msg = FileProto.decode(type: type, payload: payload) else { reason = "malformed"; return }
            switch msg {
            case .ping:
                guard sendGuarded(type, payload) else { reason = "send_failed"; return }
            case .request(let t, let index, let offset, let length) where push != nil && t == push?.transfer:
                guard let p = push, p.serve(index: index, offset: offset, length: length, send: sendMessage) else {
                    reason = "send_failed"; return
                }
                lastMessage = Date()
            case .reply(let t, let status) where push != nil && t == push?.transfer:
                push?.reply(status)
            case .result(let t, let status, let filesOK) where push != nil && t == push?.transfer:
                push?.result(status: status, filesOK: filesOK)
            case .cancel(let t, _) where push != nil && t == push?.transfer:
                push?.cancelled()
            case .request(let t, let index, let offset, let length):
                guard let announcer else {
                    refused += 1
                    guard sendAll([.reply(transfer: t, status: FileProto.Status.denied)]) else { reason = "send_failed"; return }
                    continue
                }
                if t == announcer.current { notePullServe() }
                guard announcer.serve(transfer: t, index: index, offset: offset, length: length, send: sendMessage) else {
                    reason = "send_failed"; return
                }
                // Serving can take a while on a slow link; it is activity.
                lastMessage = Date()
            case .cancel(let t, _) where announcer != nil && t == announcer?.current,
                 .reply(let t, _) where announcer != nil && t == announcer?.current:
                // The viewer dropped the announce (cleared, or names Windows
                // cannot take).
                announcer?.cancel(t)
            case .offer(_, FileProto.Purpose.paste, _, _), .offer(_, FileProto.Purpose.send, _, _),
                 .entry, .data, .fileEnd, .cancel:
                let step = receiver.handle(msg)
                noteUpload(&uploading, active: receiver.isActive)
                for out in step.send {
                    guard sendMessage(out) else { reason = "send_failed"; return }
                }
                if let why = step.close { reason = why; return }
            case .reveal(let transfer):
                // F4: Finder opens the folder that send went to. No reply.
                receiver.reveal(transfer)
            case .offer(let transfer, _, _, _):
                refused += 1
                guard sendMessage(.reply(transfer: transfer, status: FileProto.Status.denied)) else {
                    reason = "send_failed"; return
                }
            case .hello, .helloAck, .notice:
                reason = "unexpected"; return
            case .reply, .result, .progress:
                // Host-to-viewer messages: nothing to answer.
                break
            }
        }
    }

    /// r5 (B3): the dedicated file and clipboard sessions leave the main
    /// message loop, so they ask `admitMessage` themselves: on every loop
    /// turn (nothing is sent or written after a policy change) and again
    /// before an inbound message is handled. One stat while listen.plist is
    /// unchanged.
    /// r8: and `admitPeerMessage` for this session's peer.
    private func sessionRevoked(_ kind: String, peerIP: String) -> Bool {
        if let admitMessage, !admitMessage() {
            rejectedClients += 1
            print("Control reject reason=policy_changed session=\(kind) on \(bindIP):\(port); open connection closed")
            return true
        }
        if let admitPeerMessage, !admitPeerMessage(peerIP) {
            rejectedClients += 1
            print("Control reject peer=\(peerIP) reason=peer_refused session=\(kind) on \(bindIP):\(port); open connection closed")
            return true
        }
        return false
    }

    private func handleClipboardSession(_ fd: Int32, peerIP: String) {
        // Each 100 ms poll reads only the change count, on this thread. The
        // contents are read (on the main thread) only when the count moved.
        var lastChangeCount = clipboard.changeCount()
        var lastSentText = clipboard.readText()
        var lastRemoteApplied: String?

        while true {
            lock.lock(); let shouldStop = stopping; lock.unlock()
            if shouldStop { return }
            // r5 (B3): no clipboard read or write once the policy moved.
            if sessionRevoked("clipboard", peerIP: peerIP) { resetPeer(fd); return }

            var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let ready = Darwin.poll(&pfd, 1, 100)
            if ready < 0 {
                if errno == EINTR { continue }
                return
            }
            if ready > 0 {
                if (pfd.revents & Int16(POLLERR | POLLHUP | POLLNVAL)) != 0 { return }
                if (pfd.revents & Int16(POLLIN)) != 0 {
                    guard let header = recvExact(fd, count: 8) else { return }
                    guard header[0] == 0x4d, header[1] == 0x52, header[2] == 0x43,
                          header[3] == 0x31, header[4] == 1 else { return }
                    let type = header[5]
                    let length = Int(UInt16(header[6]) << 8 | UInt16(header[7]))
                    guard length <= Self.maxClipboardBytes,
                          let payload = recvExact(fd, count: length) else { return }
                    if sessionRevoked("clipboard", peerIP: peerIP) { resetPeer(fd); return }

                    if type == 0x31 {
                        guard let text = String(data: Data(payload), encoding: .utf8) else {
                            print("Clipboard rejected invalid UTF-8")
                            continue
                        }
                        if clipboard.readText() != text {
                            guard let updated = clipboard.writeText(text) else {
                                print("Clipboard remote apply failed")
                                continue
                            }
                            lastChangeCount = updated
                        } else {
                            lastChangeCount = clipboard.changeCount()
                        }
                        lastRemoteApplied = text
                        lastSentText = text
                        clipboardReceived += 1
                        print("Clipboard RX bytes=\(payload.count)")
                    } else if type == 0x01, payload.count == 4 {
                        guard sendChecked(fd, peerIP: peerIP, kind: "clipboard", type: 0x02, payload: payload) == .sent else { return }
                    }
                }
            }

            let changeCount = clipboard.changeCount()
            if changeCount == lastChangeCount { continue }
            // Mid-paste, Windows keeps the file object Explorer is reading;
            // this copy syncs once the paste is quiet.
            if pullHeld() { continue }
            lastChangeCount = changeCount
            // Our own file-URL write (Windows->Mac paste): Windows already
            // holds those files; never send the staging path back as text.
            if clipboard.ownFileWriteChangeCount() == changeCount { continue }
            // A Finder copy goes to Windows as files on the file session
            // (F3); its filename text must not overwrite them there.
            if announceSessionsOpen(), clipboard.readFileURLs() != nil { continue }
            let text = clipboard.readText()
            let settled = clipboard.changeCount()
            if clipboard.ownFileWriteChangeCount() == settled { lastChangeCount = settled; continue }
            guard let text else { continue }
            let payload = Array(text.utf8)
            if payload.count > Self.maxClipboardBytes {
                print("Clipboard skip oversize bytes=\(payload.count)")
                continue
            }
            if text == lastRemoteApplied {
                lastRemoteApplied = nil
                lastSentText = text
                continue
            }
            if text == lastSentText { continue }
            // r5 (B3): the policy may have moved during the 100 ms poll.
            // r10: sendChecked asks it right before the frame.
            guard sendChecked(fd, peerIP: peerIP, kind: "clipboard", type: 0x31, payload: payload) == .sent else { return }
            lastSentText = text
            clipboardSent += 1
            print("Clipboard TX bytes=\(payload.count)")
        }
    }

    private func handleCapsLock(down: Bool) {
        // Caps Lock is a latch/status key, so one key-down toggles the remote
        // state and the matching key-up carries no additional action.
        guard down else { return }
        // One fresh TIS read per Caps press (not per key); it also refreshes
        // the cache in case the change notification has not arrived yet.
        let backend = inputSources.backend
        let current = backend.currentID()
        inputSources.store(current)

        if let saved = capsTemporaryInputSourceID {
            if current == Self.usInputSourceID && backend.select(id: saved) {
                inputSources.store(saved)
                capsTemporaryInputSourceID = nil
                capsAlphaMode = false
                return
            }
            // The user changed input source through another shortcut while in
            // temporary ABC mode; discard the stale restore target.
            capsTemporaryInputSourceID = nil
        }

        if let current, current != Self.usInputSourceID {
            if backend.select(id: Self.usInputSourceID) {
                inputSources.store(Self.usInputSourceID)
                capsTemporaryInputSourceID = current
                capsAlphaMode = false
                return
            }
        }

        capsAlphaMode.toggle()
    }

    private func handleKey(semantic: UInt16, down: Bool) {
        // Keys are never logged (privacy): only keyEvents counts them.
        keyEvents += 1

        switch pasteGate.key(semantic: semantic, down: down, refuse: { finderPasteBlocked() }) {
        case .pass:
            break
        case .refused:
            // Finder would save the text clipboard as a .textClipping file.
            print("file.paste=refused reason=busy_finder")
            requestPasteBusyNotice()
            return
        case .swallow:
            return
        }

        if semantic == 20 { // Windows VK_CAPITAL / Caps Lock.
            handleCapsLock(down: down)
            return
        }

        // If an external shortcut changed away from U.S. while alpha Caps mode
        // was active, do not leak synthetic Shift into an input method. The
        // cache follows the system's input-source notification; no TIS call
        // and no main-thread hop per key.
        if capsAlphaMode, inputSources.current != Self.usInputSourceID {
            capsAlphaMode = false
        }

        let cg = Self.macKeyCode(semantic)

        if semantic == 4 { shiftDown = down }
        guard injectRequested, let cg, let helper = inputHelper else { return }

        if capsAlphaMode && (65...90).contains(semantic) {
            // Real Caps Lock is Shift XOR Caps for letters. Temporarily invert
            // the Shift state for this key event, then restore the physical
            // remote Shift state immediately afterwards.
            let preOK = helper.sendKey(cgCode: 56, down: !shiftDown)
            let keyOK = helper.sendKey(cgCode: UInt16(cg), down: down)
            let postOK = helper.sendKey(cgCode: 56, down: shiftDown)
            if !(preOK && keyOK && postOK) {
                warnSendFailed("caps-aware key")
            }
            return
        }

        if !helper.sendKey(cgCode: UInt16(cg), down: down) {
            warnSendFailed("key")
        }
    }



    private func handleMouseMove(dx: Int16, dy: Int16) {
        mouseEvents += 1
        guard injectRequested, let helper = inputHelper else { return }
        if !helper.sendMouseMove(dx: dx, dy: dy) {
            warnSendFailed("mouse-move")
        }
    }

    private func handleMouseMoveAbsolute(x: UInt16, y: UInt16) {
        mouseEvents += 1
        guard injectRequested, let helper = inputHelper else { return }
        if !helper.sendMouseMoveAbsolute(x: x, y: y) {
            warnSendFailed("absolute mouse-move")
        }
    }

    private func handleMouseMoveNormalized(nx: UInt16, ny: UInt16) {
        mouseEvents += 1
        guard injectRequested, let helper = inputHelper else { return }
        if !helper.sendMouseMoveNormalized(nx: nx, ny: ny) {
            warnSendFailed("normalized mouse-move")
        }
    }

    private func handleMouseButton(button: UInt8, down: Bool) {
        mouseEvents += 1
        guard injectRequested, let helper = inputHelper else { return }
        if !helper.sendMouseButton(button: button, down: down) {
            warnSendFailed("mouse-button")
        }
    }

    private func handleMouseButtonExtended(button: UInt8, down: Bool, clickCount: UInt8) {
        mouseEvents += 1
        guard injectRequested, let helper = inputHelper else { return }
        if !helper.sendMouseButtonExtended(button: button, down: down, clickCount: clickCount) {
            warnSendFailed("extended mouse-button")
        }
    }

    /// The viewer's Force Quit button. A synthetic Command+Option+Escape
    /// reaches loginwindow but does not open the window, so the helper presses
    /// Apple menu > Force Quit through Accessibility instead.
    private func handleForceQuitOpen() {
        guard injectRequested, let helper = inputHelper else { return }
        let ok = helper.sendForceQuitOpen()
        print("control.force_quit=requested ok=\(ok)")
        if !ok { warnSendFailed("force-quit") }
    }

    private func handleScroll(dx: Int16, dy: Int16) {
        mouseEvents += 1
        guard injectRequested, let helper = inputHelper else { return }
        if !helper.sendScroll(dx: dx, dy: dy) {
            warnSendFailed("scroll")
        }
    }

    // MARK: Connection password (v0.4.0)

    /// Password mode: address checks and waits, then CHALLENGE, then one
    /// RESPONSE within `gate.timeout` (monotonic clock). Returns the channel
    /// the viewer proved it holds K for, or nil (connection closes). The
    /// answer is settled by `AuthGuard.settle`, which checks the waits again
    /// under the same lock, so a challenge sent before a wait or a blacklist
    /// entry cannot get OK afterwards. Never logs nonces, K or MACs.
    ///
    /// PR-C: an all-zero MAC is a v0.4 viewer's transition probe that
    /// crossed a late CHALLENGE (conn_auth.hpp afterProbeRace), not a
    /// password: it is answered FAIL with the tries left as they are, after
    /// the same admission check, and never counted. A real MAC is all zero
    /// with probability 2^-256.
    private func authenticate(_ fd: Int32, peer: ControlPeer, gate: AuthGate) -> AuthOK? {
        guard let secret = gate.secret else { return nil }
        let ip = peer.ip
        let admission = gate.guardian.admit(ip)
        guard admission == .challenge else {
            refuse(fd, ip: ip, admission: admission, afterChallenge: false)
            return nil
        }
        let hostNonce = ConnAuth.random(ConnAuth.nonceBytes)
        let challenge = ConnAuth.Challenge(hostNonce: hostNonce, salt: secret.salt, iterations: secret.iterations,
                                           kdfID: ConnAuth.kdfPBKDF2SHA256, hostID: secret.hostID)
        guard sendPacket(fd, type: ConnAuth.MsgType.challenge, payload: challenge.payload) else { return nil }

        let deadline = ProcessInfo.processInfo.systemUptime + gate.timeout
        let header: [UInt8]
        switch recvExact(fd, count: 8, deadline: deadline) {
        case .ok(let bytes): header = bytes
        case .timeout:
            settleFailure(fd, ip: ip, gate: gate, reason: "timeout", reply: nil)
            return nil
        case let other:
            noteNoResponse(ip: ip, outcome: other)
            return nil
        }
        let type = header[5]
        let length = Int(UInt16(header[6]) << 8 | UInt16(header[7]))
        let isMRC1 = header[0] == 0x4d && header[1] == 0x52 && header[2] == 0x43 && header[3] == 0x31 && header[4] == 1
        if isMRC1, type != ConnAuth.MsgType.response, Self.isLegacyFirstHeader(type: type, length: length) {
            // A 0.3.x viewer (PING, KEY, CLIPBOARD_HELLO, FILE_HELLO...).
            // r2 (Pepper's PR-C review, item 8): no password was tried, so it
            // is not counted. A 0.3.x viewer reconnects in a loop; counting
            // each attempt locked its address out within seconds.
            // r3 (item 4): only a header that a real 0.3.x viewer sends, with
            // its exact length, is exempt. Anything else is counted below.
            lock.lock(); oldViewersUncounted += 1; lock.unlock()
            _ = sendPacket(fd, type: ConnAuth.MsgType.result, payload: ConnAuth.Result.authRequired.payload)
            authLog.log("auth.old_viewer", peer: ip, "auth.old_viewer peer=\(ip) type=0x\(String(type, radix: 16)) counted=0")
            return nil
        }
        guard isMRC1, type == ConnAuth.MsgType.response else {
            settleFailure(fd, ip: ip, gate: gate, reason: "bad_header", reply: nil)
            return nil
        }
        guard length == ConnAuth.Response.size || length == ConnAuth.Response.resumeSize else {
            settleFailure(fd, ip: ip, gate: gate, reason: "bad_response", reply: nil)
            return nil
        }
        let body: [UInt8]
        switch recvExact(fd, count: length, deadline: deadline) {
        case .ok(let bytes): body = bytes
        case .timeout:
            settleFailure(fd, ip: ip, gate: gate, reason: "timeout", reply: nil)
            return nil
        case let other:
            noteNoResponse(ip: ip, outcome: other)
            return nil
        }
        guard let response = ConnAuth.Response.decode(body) else {
            settleFailure(fd, ip: ip, gate: gate, reason: "bad_response", reply: nil)
            return nil
        }
        if response.mac.allSatisfy({ $0 == 0 }) {
            switch gate.guardian.probe(ip) {
            case .refused(let admission):
                refuse(fd, ip: ip, admission: admission, afterChallenge: true)
            case .triesLeft(let tries):
                lock.lock(); probesUncounted += 1; lock.unlock()
                _ = sendPacket(fd, type: ConnAuth.MsgType.result, payload: ConnAuth.Result.fail(triesLeft: tries).payload)
                authLog.log("auth.probe_race", peer: ip, "auth.probe_race peer=\(ip) tries=\(tries) counted=0")
            }
            return nil
        }
        var matched: ConnAuth.Channel?
        let settlement = gate.guardian.settle(ip) {
            matched = ConnAuth.matchChannel(mac: response.mac, key: secret.key, hostNonce: hostNonce,
                                            clientNonce: response.clientNonce, hostID: secret.hostID,
                                            resume: response.resume)
            return matched != nil
        }
        guard settlement == .ok, let channel = matched else {
            finishFailure(fd, ip: ip, settlement: settlement, reason: "wrong_password", reply: nil,
                          failureLog: gate.failureLog)
            return nil
        }
        // r4 (Pepper's r3 review, item 1): a reconnect from a viewer that
        // another viewer replaced. The password was right (nothing counted),
        // but the session is not taken back: it is told it was replaced, and
        // stops, even if it never read the notice on its old connection.
        if let sessionBroker, sessionBroker.resumeRefused(response.resume) {
            refuseResume(fd, ip: ip, channel: channel, resume: response.resume)
            return nil
        }
        let sessionID = ConnAuth.random(ConnAuth.sessionIDBytes)
        let macH = ConnAuth.macHost(key: secret.key, hostNonce: hostNonce, clientNonce: response.clientNonce, channel: channel)
        let sessionKey = ConnAuth.sessionKey(key: secret.key, hostNonce: hostNonce,
                                             clientNonce: response.clientNonce, sessionID: sessionID)
        // r5 (Pepper's r4 review, item 2): OK is not sent here. The caller
        // sends it (`sendAuthOK`) once the session broker has taken this
        // session, so a viewer never holds a session id the host does not
        // know yet (its next channel's AUTH would name it and be refused).
        return AuthOK(channel: channel, sessionKey: sessionKey, sessionID: sessionID, resume: response.resume, macH: macH)
    }

    /// r5: AUTH_RESULT ok, after the broker admitted the session. r10: OK is
    /// the first frame of an admitted session: it asks too.
    private func sendAuthOK(_ fd: Int32, peerIP ip: String, _ ok: AuthOK) -> Bool {
        if let fail = failAuthOKForTest, fail(ok.channel) { return false }
        guard sendChecked(fd, peerIP: ip, kind: "auth", type: ConnAuth.MsgType.result,
                          payload: ConnAuth.Result.ok(macH: ok.macH, sessionID: ok.sessionID).payload) == .sent else { return false }
        print("auth.ok peer=\(ip) chan=\(ok.channel.name) session=\(ConnAuth.hex(ok.sessionID))")
        return true
    }

    /// r4: answers a refused reconnect (`.replaced`, the same status as the
    /// notice) and logs it. Not a failure: no try is counted.
    private func refuseResume(_ fd: Int32, ip: String, channel: ConnAuth.Channel, resume: [UInt8]?) {
        lock.lock(); resumesRefused += 1; lock.unlock()
        let sent = sendPacket(fd, type: ConnAuth.MsgType.result, payload: ConnAuth.Result.replaced.payload)
        authLog.log("auth.resume_refused", peer: ip,
                    "auth.resume_refused peer=\(ip) chan=\(channel.name) resume=\(resume.map(ConnAuth.hex) ?? "-") sent=\(sent ? 1 : 0) counted=0")
        if sent {
            Darwin.shutdown(fd, SHUT_WR)
            KickHandle.drainAfterNotice(fd)
        }
    }

    /// An authenticated connection: its channel and its UDP session key
    /// (K_s, design §5.1; used for the control channel only).
    struct AuthOK {
        var channel: ConnAuth.Channel
        var sessionKey: [UInt8]
        /// r4: the session_id sent in OK, and the one a reconnect named.
        var sessionID: [UInt8]
        var resume: [UInt8]?
        /// r5: mac_h for the OK that `sendAuthOK` sends.
        var macH: [UInt8]
    }

    /// No challenge, or a challenge whose answer came after a wait or the
    /// blacklist started: the viewer learns why, nothing is counted.
    private func refuse(_ fd: Int32, ip: String, admission: AuthGuard.Admission, afterChallenge: Bool) {
        let note = afterChallenge ? " after_challenge=1 counted=0" : ""
        switch admission {
        case .blocked:
            _ = sendPacket(fd, type: ConnAuth.MsgType.result, payload: ConnAuth.Result.blocked.payload)
            authLog.log("auth.blocked", peer: ip, "auth.blocked peer=\(ip)\(note); connection closed")
        case .notAllowed:
            rejectedClients += 1
            print("Control reject peer=\(ip) expected=whitelist on \(bindIP):\(port)\(note); connection closed")
        case .locked(let retry, let stage):
            _ = sendPacket(fd, type: ConnAuth.MsgType.result, payload: ConnAuth.Result.locked(retrySeconds: retry).payload)
            authLog.log("auth.locked", peer: ip, "auth.locked peer=\(ip) retry_s=\(retry) stage=\(stage)\(note); connection closed")
        case .globalLocked(let retry):
            _ = sendPacket(fd, type: ConnAuth.MsgType.result, payload: ConnAuth.Result.locked(retrySeconds: retry).payload)
            authLog.log("auth.global_locked", peer: ip, "auth.global_locked peer=\(ip) retry_s=\(retry)\(note); connection closed")
        case .challenge:
            break
        }
    }

    /// The viewer closed (or the socket failed) before answering: no
    /// password was tried, so nothing is counted.
    private func noteNoResponse(ip: String, outcome: RecvOutcome) {
        switch outcome {
        case .error(let code): authLog.log("auth.no_response", peer: ip, "auth.no_response peer=\(ip) reason=read_error errno=\(code) counted=0")
        default: authLog.log("auth.no_response", peer: ip, "auth.no_response peer=\(ip) reason=closed counted=0")
        }
    }

    /// A timeout, an old viewer or a malformed answer: settled like a wrong
    /// password, so the waits are checked again first.
    private func settleFailure(_ fd: Int32, ip: String, gate: AuthGate, reason: String, reply: ConnAuth.Result?) {
        finishFailure(fd, ip: ip, settlement: gate.guardian.settle(ip) { false }, reason: reason, reply: reply,
                      failureLog: gate.failureLog)
    }

    /// Answers a failed settlement. `reply` overrides the plain FAIL
    /// (AUTH_REQUIRED for an old viewer); LOCKED and BLOCKED always win so
    /// the viewer learns the wait. The blacklist log says whether
    /// listen.plist was really written.
    private func finishFailure(_ fd: Int32, ip: String, settlement: AuthGuard.Settlement, reason: String, reply: ConnAuth.Result?,
                               failureLog: AuthFailureLog?) {
        let r: AuthGuard.Failure
        switch settlement {
        case .ok:
            return
        case .refused(let admission):
            refuse(fd, ip: ip, admission: admission, afterChallenge: true)
            return
        case .failed(let failure):
            r = failure
        }
        lock.lock(); authFailures += 1; lock.unlock()   // connections settle concurrently
        failureLog?.record(ip: ip, reason: reason, failures: r.failures)   // r2 item 6: shown in 連線設定
        let result: ConnAuth.Result
        switch r.outcome {
        case .retry(let tries):
            result = reply ?? .fail(triesLeft: tries)
            print("auth.fail peer=\(ip) chan=unknown reason=\(reason) failures=\(r.failures) tries=\(tries)")
        case .locked(let retry, let stage):
            result = .locked(retrySeconds: retry)
            print("auth.fail peer=\(ip) chan=unknown reason=\(reason) failures=\(r.failures)")
            print("auth.locked peer=\(ip) retry_s=\(retry) stage=\(stage)")
        case .blacklisted(let persisted):
            result = .blocked
            print("auth.fail peer=\(ip) chan=unknown reason=\(reason) failures=\(r.failures)")
            print(persisted
                  ? "auth.blocked peer=\(ip) failures=\(r.failures) persisted=listen.plist"
                  : "auth.blocked peer=\(ip) failures=\(r.failures) persisted=no attempts=\(AuthGuard.saveAttempts) (blocked in memory until restart)")
        }
        if r.globalTriggered {
            print("auth.global_locked retry_s=\(UInt32(AuthGuard.globalWait))")
        }
        _ = sendPacket(fd, type: ConnAuth.MsgType.result, payload: result.payload)
    }

    /// Transition mode (no password yet): the 0.3 address check against the
    /// whitelist, plus the blacklist. No challenge, nothing counted.
    private func admitWithoutPassword(_ fd: Int32, peer: ControlPeer, gate: AuthGate) -> Bool {
        if let why = gate.guardian.lockdownReason() {
            rejectedClients += 1
            print("auth.lockdown_hold reason=\(why) peer=\(peer.ip) on \(bindIP):\(port); connection closed")
            return false
        }
        if gate.guardian.isBlocked(peer.ip) {
            _ = sendPacket(fd, type: ConnAuth.MsgType.result, payload: ConnAuth.Result.blocked.payload)
            authLog.log("auth.blocked", peer: peer.ip, "auth.blocked peer=\(peer.ip); connection closed")
            return false
        }
        let whitelist = gate.guardian.whitelist
        if whitelist.isEmpty || !whitelist.contains(peer.ip) {
            rejectedClients += 1
            print("Control reject peer=\(peer.ip) expected=whitelist on \(bindIP):\(port); connection closed")
            return false
        }
        return true
    }

    /// r3 (Pepper's r2 review, item 4): the first header a real 0.3.x viewer
    /// sends, with that message's exact payload length. Only these skip the
    /// failure count when a password is required.
    static func isLegacyFirstHeader(type: UInt8, length: Int) -> Bool {
        switch type {
        case 0x01: return length == 4                    // PING
        case 0x10: return length == 3                    // KEY
        case 0x20, 0x22, 0x23, 0x24: return length == 4  // mouse move / scroll
        case 0x21: return length == 2                    // MOUSE_BUTTON
        case 0x25: return length == 3                    // MOUSE_BUTTON_EXT
        case 0x30: return length == 0                    // CLIPBOARD_HELLO
        case 0x40: return length == 6                    // VIDEO_CONFIG_SET v1
        case FileProto.MsgType.hello: return length == 3 // FILE_HELLO
        case 0x60: return length == 0                    // FORCE_QUIT_OPEN
        default: return false
        }
    }

    /// The connection stays on the channel it authenticated for: a MAC for
    /// the ping channel cannot open a file session, and so on.
    static func channelAllows(_ channel: ConnAuth.Channel, type: UInt8, first: Bool) -> Bool {
        switch channel {
        case .ping: return type == 0x01
        case .clipboard: return !first || type == 0x30
        case .file: return !first || type == FileProto.MsgType.hello
        case .control: return type != 0x30 && type != FileProto.MsgType.hello
        }
    }

    /// How a deadline read ended. `closed` (the peer shut down) and `error`
    /// are not timeouts: no answer was tried.
    enum RecvOutcome {
        case ok([UInt8])
        case timeout
        case closed
        case error(Int32)
    }

    /// recvExact with an absolute deadline on the monotonic clock
    /// (`ProcessInfo.systemUptime`), polling before each read, so a wall
    /// clock change cannot stretch or cut the AUTH window.
    private func recvExact(_ fd: Int32, count: Int, deadline: TimeInterval) -> RecvOutcome {
        if count == 0 { return .ok([]) }
        var out = [UInt8](repeating: 0, count: count)
        var offset = 0
        while offset < count {
            let remaining = deadline - ProcessInfo.processInfo.systemUptime
            if remaining <= 0 { return .timeout }
            var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let ready = Darwin.poll(&pfd, 1, Int32(max(1, min(remaining * 1000, 60_000))))
            if ready < 0 {
                if errno == EINTR { continue }
                return .error(errno)
            }
            if ready == 0 { continue }   // the loop re-checks the deadline
            let n = out.withUnsafeMutableBytes { raw -> Int in
                Darwin.recv(fd, raw.baseAddress!.advanced(by: offset), count - offset, 0)
            }
            if n == 0 { return .closed }
            if n < 0 {
                if errno == EINTR || errno == EAGAIN { continue }
                return .error(errno)
            }
            offset += n
        }
        return .ok(out)
    }

    /// r12: viewer sockets are O_NONBLOCK, so a read with nothing there
    /// waits in poll(POLLIN) with no timeout, as the blocking recv did
    /// before: `stop()`'s shutdown still wakes it (recv then sees EOF).
    /// r4: with `wake` (a kicked control connection, `KickHandle.wakeFD`) it
    /// also returns nil once that fd is readable, checked before every read
    /// so a viewer that keeps sending cannot hold the loop.
    private func recvExact(_ fd: Int32, count: Int, wake: Int32 = -1) -> [UInt8]? {
        if count == 0 { return [] }
        var out = [UInt8](repeating: 0, count: count)
        var offset = 0
        while offset < count {
            if wake >= 0 {
                var pfds = [pollfd(fd: fd, events: Int16(POLLIN), revents: 0),
                            pollfd(fd: wake, events: Int16(POLLIN), revents: 0)]
                if Darwin.poll(&pfds, 2, -1) < 0 {
                    if errno == EINTR { continue }
                    return nil
                }
                if pfds[1].revents != 0 { return nil }
            }
            let n = out.withUnsafeMutableBytes { raw -> Int in
                Darwin.recv(fd, raw.baseAddress!.advanced(by: offset), count - offset, 0)
            }
            if n > 0 { offset += n; continue }
            if n == 0 { return nil }
            let e = errno
            if e == EINTR { continue }
            guard e == EAGAIN else { return nil }
            if wake >= 0 { continue }   // r4: the poll above waits on both
            var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            if Darwin.poll(&pfd, 1, -1) < 0 && errno != EINTR { return nil }
        }
        return out
    }

    enum CheckedSend: Equatable { case sent, refused, failed }

    /// r10: the one way a frame reaches an admitted viewer (control replies,
    /// file and clipboard sessions). It asks the policy and this peer's block
    /// (`sessionRevoked`) right before the frame, and again after every wait
    /// for the viewer's window, so a viewer that stopped reading cannot hold
    /// the thread past a block. A refusal resets the socket (`resetPeer`).
    private func sendChecked(_ fd: Int32, peerIP: String, kind: String, type: UInt8,
                             payload: [UInt8]) -> CheckedSend {
        beforeCheckedSend?(type)
        var refused = false
        let ok = sendPacket(fd, type: type, payload: payload, peerIP: peerIP) {
            if self.sessionRevoked(kind, peerIP: peerIP) { refused = true }
            return refused
        }
        if refused { resetPeer(fd); return .refused }
        return ok ? .sent : .failed
    }

    /// r10: a refused viewer's socket closes with RST (SO_LINGER 0) when
    /// the handler returns: what the kernel still holds for it is dropped,
    /// not delivered, and the close does not wait for its window.
    private func resetPeer(_ fd: Int32) {
        var l = linger(l_onoff: 1, l_linger: 0)
        setsockopt(fd, SOL_SOCKET, SO_LINGER, &l, socklen_t(MemoryLayout<linger>.size))
        lock.lock(); resetFDs.insert(fd); lock.unlock()
    }

    /// Before the RST close: give the segment already in flight time to be
    /// acknowledged (two smoothed RTTs, 20 to 200 ms). Nothing more is
    /// written. A viewer takes an RST only at exactly the sequence it
    /// expects next (RFC 5961); one sent while data is in flight gets a
    /// challenge ACK, which a Mac in stealth mode (net.inet.tcp.blackhole)
    /// never answers, so that viewer would not learn of the close.
    static func settleBeforeReset(_ fd: Int32) {
        var info = tcp_connection_info()
        var len = socklen_t(MemoryLayout<tcp_connection_info>.size)
        let srtt = getsockopt(fd, IPPROTO_TCP, TCP_CONNECTION_INFO, &info, &len) == 0 ? Int(info.tcpi_srtt) : 0
        usleep(useconds_t(min(200, max(20, 2 * srtt)) * 1000))
    }

    /// Frames and bytes this host wrote to `peer` (r10, self-test).
    func txCount(peer: String) -> (sends: UInt64, bytes: UInt64) {
        txLock.lock(); defer { txLock.unlock() }
        return txByPeer[peer] ?? (0, 0)
    }

    /// The longest one send() may block before it returns (r10): a viewer
    /// that stopped reading cannot hold a writer longer than this between
    /// two checks. Set per connection as SO_SNDTIMEO (MSG_DONTWAIT is not
    /// honoured by a blocking TCP socket on macOS: send still waits).
    static let sendSliceMillis: Int32 = 100

    /// SO_SNDTIMEO = `sendSliceMillis` on a viewer socket (r10). r11: false
    /// when the kernel refuses it; the accept loop then closes the
    /// connection instead of serving it without the timeout.
    static func setSendSlice(_ fd: Int32) -> Bool {
        var tv = timeval(tv_sec: 0, tv_usec: __darwin_suseconds_t(sendSliceMillis * 1000))
        return setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size)) == 0
    }

    /// Sets the send timeout on an accepted socket (r11). The self-test
    /// swaps it for one that fails, to see the connection refused.
    var sendSliceSetter: (Int32) -> Bool = ControlServer.setSendSlice

    /// O_NONBLOCK on a viewer socket (r12): false when fcntl fails, and the
    /// accept loop then closes the connection.
    static func setNonBlocking(_ fd: Int32) -> Bool {
        let flags = fcntl(fd, F_GETFL)
        guard flags >= 0 else { return false }
        return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0
    }

    /// Makes an accepted socket non-blocking (r12); swapped by the self-test.
    var nonBlockingSetter: (Int32) -> Bool = ControlServer.setNonBlocking

    /// Self-test only (r12): stands in for the kernel's send(), to model a
    /// write the kernel cannot take although poll said writable.
    var sendHook: ((Int32, String?, UnsafeRawPointer, Int) -> Int)?

    private var sendCallMaxNanos: UInt64 = 0

    /// The longest one send() call to a viewer took (r12, self-test): a
    /// non-blocking write returns at once; one that waited shows here.
    var longestSendCallMillis: Double {
        txLock.lock(); defer { txLock.unlock() }
        return Double(sendCallMaxNanos) / 1_000_000
    }

    /// One MRC1 frame. r12: the socket is O_NONBLOCK, so send() never waits
    /// in the kernel; a write it cannot take returns EAGAIN (or short). The
    /// wait for room is poll(POLLOUT) in `sendSliceMillis` slices. After
    /// every wake (room, a slice with none, a signal) `revoked` is asked
    /// first (an admitted viewer, via sendChecked), and only then is the
    /// rest written; EAGAIN or a short write goes back to poll. Without
    /// `revoked` (handshake frames) the wait ends after
    /// `handshakeSendSeconds`.
    private func sendPacket(_ fd: Int32, type: UInt8, payload: [UInt8], peerIP: String? = nil,
                            revoked: (() -> Bool)? = nil) -> Bool {
        let length = UInt16(payload.count)
        let bytes: [UInt8] = [0x4d, 0x52, 0x43, 0x31, 1, type, UInt8(length >> 8), UInt8(length & 0xff)] + payload
        let deadline = revoked == nil ? ProcessInfo.processInfo.systemUptime + Self.handshakeSendSeconds : .infinity
        var offset = 0
        while offset < bytes.count {
            var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            let ready = Darwin.poll(&pfd, 1, Self.sendSliceMillis)
            if ready < 0 && errno != EINTR { return false }
            if let revoked, revoked() { return false }
            if ProcessInfo.processInfo.systemUptime > deadline { return false }
            lock.lock(); let shouldStop = stopping; lock.unlock()
            if shouldStop { return false }
            guard ready > 0 else { continue }
            guard pfd.revents & Int16(POLLOUT) != 0 else { return false }
            let started = DispatchTime.now().uptimeNanoseconds
            let n = bytes.withUnsafeBytes { raw -> Int in
                let p = raw.baseAddress!.advanced(by: offset), len = bytes.count - offset
                if let sendHook { return sendHook(fd, peerIP, p, len) }
                return Darwin.send(fd, p, len, 0)
            }
            let sendErrno = errno
            let took = DispatchTime.now().uptimeNanoseconds &- started
            txLock.lock(); sendCallMaxNanos = max(sendCallMaxNanos, took); txLock.unlock()
            if n > 0 {
                offset += n
                if let peerIP {
                    txLock.lock()
                    var t = txByPeer[peerIP] ?? (0, 0)
                    t.sends &+= 1; t.bytes &+= UInt64(n)
                    txByPeer[peerIP] = t
                    txLock.unlock()
                }
            } else {
                guard n < 0, sendErrno == EAGAIN || sendErrno == EINTR else { return false }
            }
        }
        return true
    }

    private static func macKeyCode(_ code: UInt16) -> UInt16? {
        switch code {
        // Modifiers / status keys.
        case 1: return 59; case 2: return 58; case 3: return 55; case 4: return 56
        case 20: return 57      // Caps Lock (handled contextually above)

        // Letters A-Z.
        case 65: return 0;  case 66: return 11; case 67: return 8;  case 68: return 2
        case 69: return 14; case 70: return 3;  case 71: return 5;  case 72: return 4
        case 73: return 34; case 74: return 38; case 75: return 40; case 76: return 37
        case 77: return 46; case 78: return 45; case 79: return 31; case 80: return 35
        case 81: return 12; case 82: return 15; case 83: return 1;  case 84: return 17
        case 85: return 32; case 86: return 9;  case 87: return 13; case 88: return 7
        case 89: return 16; case 90: return 6

        // Number row 0-9.
        case 48: return 29; case 49: return 18; case 50: return 19; case 51: return 20
        case 52: return 21; case 53: return 23; case 54: return 22; case 55: return 26
        case 56: return 28; case 57: return 25

        // Editing/navigation.
        case 8: return 51       // Backspace -> Mac Delete
        case 9: return 48       // Tab
        case 13: return 36      // Return
        case 27: return 53      // Escape
        case 32: return 49      // Space
        case 33: return 116     // Page Up
        case 34: return 121     // Page Down
        case 35: return 119     // End
        case 36: return 115     // Home
        case 37: return 123     // Left
        case 38: return 126     // Up
        case 39: return 124     // Right
        case 40: return 125     // Down
        case 45: return 114     // Insert -> Help/Insert-style key
        case 46: return 117     // Forward Delete

        // US/HK punctuation physical keys (Windows VK_OEM_* semantics).
        case 186: return 41     // ; :
        case 187: return 24     // = +
        case 188: return 43     // , <
        case 189: return 27     // - _
        case 190: return 47     // . >
        case 191: return 44     // / ?
        case 192: return 50     // ` ~
        case 219: return 33     // [ {
        case 220: return 42     // \\ |
        case 221: return 30     // ] }
        case 222: return 39     // ' "

        // Numpad 0-9 and operators.
        case 96: return 82; case 97: return 83; case 98: return 84; case 99: return 85
        case 100: return 86; case 101: return 87; case 102: return 88; case 103: return 89
        case 104: return 91; case 105: return 92
        case 106: return 67     // *
        case 107: return 69     // +
        case 109: return 78     // -
        case 110: return 65     // .
        case 111: return 75     // /

        // Function keys F1-F12.
        case 112: return 122; case 113: return 120; case 114: return 99;  case 115: return 118
        case 116: return 96;  case 117: return 97;  case 118: return 98;  case 119: return 100
        case 120: return 101; case 121: return 109; case 122: return 103; case 123: return 111

        default: return nil
        }
    }
}
