import Foundation

/// `--service control`: the control/keyboard service as a launchd agent.
///
/// Replaces `--control-only --bind-ip 127.0.0.1 --control-port 38411` behind
/// `tailscale serve`. It binds control directly on the listen endpoint
/// (bindIP:38400), so the socket sees the real viewer address and only the
/// configured viewer is accepted, as on mouse UDP. Unknown peers are logged
/// and closed.
///
/// It also keeps a loopback listener (127.0.0.1:38411 by default) for the
/// video service's mouse relay (MouseMoveUDPServer -> LocalControlMouseClient),
/// which is a local process. That listener accepts 127.0.0.1 only and never
/// reads PROXY headers, so it cannot claim the viewer's address.
///
/// Both listeners share one InputHelperClient. The input helper serves a
/// single connection at a time, so a second connection would wait in its
/// backlog forever: that is what stopped keyboard and mouse in the first P1
/// install (the relay's start-up ping never returned, so the relay never
/// accepted the video service's mouse connection).
enum ControlService {
    /// Keeps the running servers alive for the life of the process.
    nonisolated(unsafe) private static var running: [ControlServer] = []

    // ISO8601DateFormatter is thread-safe; make it once, not per line.
    nonisolated(unsafe) private static let stampFormatter = ISO8601DateFormatter()

    static func log(_ message: String) {
        let stamp = stampFormatter.string(from: Date())
        print("\(stamp) control-service: \(message)")
        fflush(stdout)
    }

    /// Start the direct listener on bindIP:port and, unless it is the same
    /// socket, the loopback relay listener on 127.0.0.1:relayPort. Both use
    /// `helper`. Only the direct listener answers FILE_HELLO (0x50). On
    /// failure, servers already started are stopped.
    static func startServers(bindIP: String, clientIP: String, port: UInt16, relayPort: UInt16,
                             inject: Bool, helper: InputHelperClient,
                             gate: AuthGate? = nil,
                             broker: SessionBroker? = nil,
                             admit: (@Sendable () -> Bool)? = nil,
                             admitMessage: (@Sendable () -> Bool)? = nil) throws -> [ControlServer] {
        var servers: [ControlServer] = []
        // r6 (B5): while the pending journal does not read nobody gets in and
        // nothing already open goes on. Every message on both listeners
        // (file and clipboard sessions included) and every relay connection
        // asks the guard first; the direct listener's new connections ask
        // it in the gate already.
        // r7 (B5): the relay carries the moves of one viewer, the UDP
        // client the video service accepts, so its connections and messages
        // also ask the guard's blacklist for that address, blocks restored
        // from the pending journal included. PR-C: that viewer is the
        // session peer (SessionBroker), not clientIP; with no session the
        // relay carries nothing.
        let held = lockdownCheck(gate)
        let relayViewer: @Sendable () -> String?
        if let broker { relayViewer = { broker.activePeerIP } } else { relayViewer = { clientIP } }
        let relayHeld = lockdownCheck(gate, viewerIP: relayViewer)
        let messageOK: @Sendable () -> Bool = { !held() && (admitMessage?() ?? true) }
        let relayMessageOK: @Sendable () -> Bool = { !relayHeld() && (admitMessage?() ?? true) }
        let relayAdmit: @Sendable () -> Bool = { !relayHeld() && (admit?() ?? true) }
        do {
            // With a gate the whitelist, blacklist and password live in the
            // gate; without one (legacy callers) the 0.3 single-IP check.
            let direct = ControlServer(bindIP: bindIP, allowedClientIP: gate == nil ? clientIP : nil,
                                       port: port, inject: inject,
                                       settingsClientIP: { clientIP.isEmpty ? nil : clientIP }, acceptProxy: false,
                                       inputHelper: helper, allowFileSessions: true, authGate: gate,
                                       admitConnection: admit, admitMessage: messageOK,
                                       admitPeerMessage: peerCheck(gate), sessionBroker: broker)
            try direct.start()
            servers.append(direct)
            let relayIsDirect = bindIP == ListenConfig.loopbackIP && relayPort == port
            // Password mode: the relay carries UDP mouse input only when it
            // is bound to the authenticated session (PR-C: the video service
            // takes MRM1 input only with a valid tag under the session key
            // announced over the session link). Without that link the relay
            // stays closed, as before.
            let relayAllowed = !(gate?.requiresPassword ?? false) || broker != nil
            if relayPort != 0 && !relayIsDirect && relayAllowed {
                let relay = ControlServer(bindIP: ListenConfig.loopbackIP, allowedClientIP: ListenConfig.loopbackIP,
                                          port: relayPort, inject: inject,
                                          settingsClientIP: { clientIP.isEmpty ? nil : clientIP }, acceptProxy: false,
                                          inputHelper: helper, announceInputSessions: false,
                                          allowSensitiveControl: false, relayMouseOnly: true,
                                          admitConnection: relayAdmit, admitMessage: relayMessageOK)
                try relay.start()
                servers.append(relay)
            }
        } catch {
            servers.forEach { $0.stop() }
            throw error
        }
        return servers
    }

    /// True while the guard holds every admission (B5: the pending journal
    /// does not read) and, with `viewerIP` (r7, the mouse relay), while
    /// that address is on the blacklist. Logs at most once a second; the
    /// listeners log each refused connection or message themselves.
    static func lockdownCheck(_ gate: AuthGate?, viewerIP: (@Sendable () -> String?)? = nil) -> @Sendable () -> Bool {
        guard let guardian = gate?.guardian else { return { false } }
        let throttle = OncePerInterval(1)
        return {
            let why: String?
            var entry = "open_connection"
            if let viewerIP {
                if let ip = viewerIP() {
                    why = guardian.inputRefusal(ip)
                    entry = "relay peer=\(ip)"
                } else {
                    // PR-C: no session, no viewer to move the mouse for.
                    why = guardian.lockdownReason() ?? "no_session"
                    entry = "relay"
                }
            } else {
                why = guardian.lockdownReason()
            }
            guard let why else { return false }
            if throttle.due() {
                log("auth.lockdown_hold reason=\(why) entry=\(entry); refused or closed")
            }
            return true
        }
    }

    /// r8: for the direct listener's open connections (control, clipboard,
    /// file and ping alike): false while the guard refuses input from that
    /// peer (`AuthGuard.inputRefusal`: the journal lockdown, listen.plist
    /// `blockedIPs`, blocks restored from the pending journal). A block
    /// added while a connection is open closes it on its next message, not
    /// on a policy-watch tick; other viewers' connections go on. Logs at
    /// most once a second; the listener logs each closed connection itself.
    static func peerCheck(_ gate: AuthGate?) -> (@Sendable (String) -> Bool)? {
        guard let guardian = gate?.guardian else { return nil }
        let throttle = OncePerInterval(1)
        return { ip in
            guard let why = guardian.inputRefusal(ip) else { return true }
            if throttle.due() {
                log("auth.peer_refused peer=\(ip) reason=\(why) entry=open_connection; closed")
            }
            return false
        }
    }

    static func raiseOpenFileLimit(to want: rlim_t) {
        var rl = rlimit()
        guard getrlimit(RLIMIT_NOFILE, &rl) == 0, rl.rlim_cur < want else { return }
        rl.rlim_cur = min(want, rl.rlim_max)
        _ = setrlimit(RLIMIT_NOFILE, &rl)
    }

    static func run(_ o: Options) async -> Never {
        // stdout is a file under launchd: flush every line so ControlServer's
        // print() output (connects, warnings) reaches the log promptly.
        setvbuf(stdout, nil, _IOLBF, 0)
        LogFiles.startCapping()
        if let migrated = ListenMigration.migrate(url: ListenConfig.plistURL) { log(migrated) }
        // One read of listen.plist decides both the endpoint and the auth
        // policy, so they cannot come from two different versions of it.
        let (endpoint, plist) = await ListenConfig.waitForEndpointWithPlist(log: log)
        log("starting control \(endpoint.summary) port=\(o.controlPort) relay=\(o.relayPort == 0 ? "off" : "127.0.0.1:\(o.relayPort)")")
        let secret = wantsPassword(plist) ? KeychainSecretStore().load() : nil
        let blocklist = ListenPlistBlocklist(url: ListenConfig.plistURL)
        let journal = PendingBlockFile(url: ListenConfig.pendingBlocksURL)
        let (gate, snapshot) = authGate(clientIP: endpoint.clientIP, plist: plist, secret: secret, blocklist: blocklist,
                                        journal: journal)
        let plistURL = ListenConfig.plistURL
        let watch = PolicyWatch(started: endpoint, snapshot: snapshot, gate: gate,
                                read: { ListenConfig.currentWithPlist() },
                                loadSecret: { KeychainSecretStore().load() },
                                stamp: { ListenFileStamp.of(plistURL) })
        watch.setOnChange { _ in
            running.forEach { $0.stop() }
            // A block in neither listen.plist nor the pending journal would
            // be gone after the restart: stay up, admitting nobody, until one
            // of them is written.
            _ = watch.waitUntilDurable()
            exit(0)
        }
        if gate == nil {
            // Refused: no listener at all until listen.plist changes.
            watch.start()
            while true { try? await Task.sleep(for: .seconds(3600)) }
        }
        // PR-C: the video service serves only the viewer this broker
        // announces over the session link.
        let broker = SessionBroker(passwordMode: gate?.requiresPassword == true) { log($0) }
        let sessionLink = SessionLinkServer(broker: broker)
        do { try sessionLink.start() } catch {
            // Without the link the video service sends nothing: say so.
            log("session.link_socket=off (\(error.localizedDescription)); no video, audio or UDP input until it works")
        }
        do {
            running = try startServers(bindIP: endpoint.bindIP, clientIP: endpoint.clientIP,
                                       port: o.controlPort, relayPort: o.relayPort,
                                       inject: o.controlInject, helper: InputHelperClient(), gate: gate,
                                       broker: broker,
                                       admit: { watch.admitNew() },
                                       admitMessage: { watch.stillCurrent() })
        } catch {
            // Usually the address went away between the check and bind();
            // launchd restarts us after ThrottleInterval and we wait again.
            log("start failed: \(error.localizedDescription)")
            exit(1)
        }
        log("listening: \(running.count) listener(s), one input helper connection")
        // F5b: Finder "Send to JerisLink". A push holds up to 1,000 open
        // files; launchd's soft limit is 256.
        raiseOpenFileLimit(to: 4096)
        let sendSocket = SendSocketServer()
        do { try sendSocket.start() } catch { log("send socket off: \(error.localizedDescription)") }
        // Register the Finder Service helper off the main path; Launch Services
        // and pbs calls can take a few seconds. Logs carry no paths.
        Task.detached(priority: .utility) {
            guard let registered = JerisLinkSendService.ensureRegistered() else {
                log("file.push_service=absent")
                return
            }
            let pbs = JerisLinkSendService.refreshServicesMenu()
            log("file.push_service=\(registered ? "registered" : "register_failed") pbs_update=\(pbs.map(String.init) ?? "failed")")
        }
        watch.start()
        while true {
            try? await Task.sleep(for: .seconds(3600))
        }
    }
}

extension ControlService {
    static func wantsPassword(_ plist: [String: Any]?) -> Bool {
        (plist?["passwordSet"] as? Bool) == true
    }

    /// v0.4.0 connection password, from the listen.plist contents the
    /// endpoint came from. The Keychain is read (by the caller) only when
    /// that plist says a password was set, so a host without one never
    /// touches it. Returns nil when the configuration must refuse every
    /// connection (logged as config.refused). Password mode also refuses
    /// when the blacklist cannot be written: a block that cannot be stored
    /// would be lost on the next restart.
    static func authGate(clientIP: String, plist: [String: Any]?, secret: ConnSecret?,
                         blocklist: BlocklistStore,
                         journal: PendingBlockStore? = nil) -> (AuthGate?, AuthConfigSnapshot) {
        let snapshot = AuthConfigSnapshot.read(plist: plist, secret: secret)
        var policy = AuthPolicy.resolve(plist: plist, clientIP: clientIP, secretLoaded: secret != nil)
        if case .password = policy, !blocklist.writable() {
            policy = .refused(reason: "blocklist_unwritable")
        }
        if case .refused(let reason) = policy {
            log("config.refused reason=\(reason)")
            return (nil, snapshot)
        }
        log("auth.policy \(policy.summary)")
        return (AuthGate.make(policy: policy, secret: secret, blocklist: blocklist, journal: journal), snapshot)
    }
}

/// Watches the settings one control-service process started with: the
/// endpoint and the auth inputs (passwordSet, allowedIPs, allowedIPsSource,
/// the password, blockedIPs edited outside the service), all from one read
/// of listen.plist per check.
///
/// - `admitNew` runs for every accepted connection: when the settings no
///   longer match it refuses that connection, and the change is applied
///   at once. While the endpoint is waiting for its address it refuses
///   every new connection (r4).
/// - `stillCurrent` runs for every message on an open connection, the
///   loopback mouse relay included (r4): one stat while listen.plist is
///   unchanged, the same check as `admitNew` when it moved.
/// - `start` checks every second as well, so connections already open are
///   closed without waiting for a new one or a message.
/// Applying a change revokes the gate first (nothing more is admitted under
/// the old policy), then calls the change handler, which in the service
/// stops every listener and exits; launchd starts the new policy. Only an
/// address that went down with the settings unchanged (`transient`) waits
/// for a second check before exiting; nothing new is admitted meanwhile.
final class PolicyWatch: @unchecked Sendable {
    enum Verdict: Equatable {
        case current
        case transient(String)
        case changed(String)
    }

    let started: ListenEndpoint
    let snapshot: AuthConfigSnapshot
    let gate: AuthGate?
    private let read: @Sendable () -> (ListenResolution, [String: Any]?)
    private let loadSecret: @Sendable () -> ConnSecret?
    private let stamp: (@Sendable () -> ListenFileStamp?)?
    private let lock = NSLock()
    private var applied: String?
    private var onChange: (@Sendable (String) -> Void)?
    /// listen.plist as of the last check that found everything current.
    private var verifiedStamp: ListenFileStamp?

    init(started: ListenEndpoint, snapshot: AuthConfigSnapshot, gate: AuthGate?,
         read: @escaping @Sendable () -> (ListenResolution, [String: Any]?),
         loadSecret: @escaping @Sendable () -> ConnSecret?,
         stamp: (@Sendable () -> ListenFileStamp?)? = nil) {
        self.started = started
        self.snapshot = snapshot
        self.gate = gate
        self.read = read
        self.loadSecret = loadSecret
        self.stamp = stamp
    }

    func setOnChange(_ handler: @escaping @Sendable (String) -> Void) {
        lock.lock(); onChange = handler; lock.unlock()
    }

    /// The change already applied, if any.
    var appliedChange: String? { lock.lock(); defer { lock.unlock() }; return applied }

    func evaluate() -> Verdict {
        // Taken before the read: a write after it moves the stamp again.
        let before = stamp?()
        let guardian = gate?.guardian
        let persistedBefore = guardian?.persistedIPs
        let (resolution, plist) = read()
        var waiting: String?
        switch resolution {
        case .ready(let ep) where ep == started: break
        case .ready(let ep): return .changed("endpoint changed to \(ep.summary)")
        case .notConfigured(let reason): return .changed("not configured: \(reason)")
        case .waiting(let reason):
            // B3 r4: settings naming another endpoint are a change now, and
            // the auth inputs below are compared while waiting as well.
            if let plist, ListenConfig.targetDiffers(plist: plist, from: started) {
                return .changed("endpoint changed, new address not up yet: \(reason)")
            }
            waiting = reason
        }
        let secret = ControlService.wantsPassword(plist) ? loadSecret() : nil
        let now = AuthConfigSnapshot.read(plist: plist, secret: secret)
        if now != snapshot { return .changed("config.auth_changed keys=\(now.changes(from: snapshot))") }
        if let guardian, let persistedBefore {
            let inFile = Set((plist.map(ListenPlistBlocklist.entries(in:)) ?? []).map(\.ip))
            // A write by the guard between the two reads is not an outside edit.
            if inFile != persistedBefore && guardian.persistedIPs == persistedBefore {
                return .changed("config.auth_changed keys=blockedIPs")
            }
        }
        if let waiting { return .transient(waiting) }
        if let before { lock.lock(); verifiedStamp = before; lock.unlock() }
        return .current
    }

    /// For each accepted connection.
    func admitNew() -> Bool {
        if appliedChange != nil { return false }
        switch evaluate() {
        case .current: return true
        case .changed(let what): apply(what); return false
        // B3 r4: the address this process listens on is not the current
        // one; nothing new until it is back or the service restarts.
        case .transient: return false
        }
    }

    /// For each message on an open connection.
    func stillCurrent() -> Bool {
        if appliedChange != nil { return false }
        if let now = stamp?() {
            lock.lock(); let known = verifiedStamp; lock.unlock()
            if now == known { return true }
        }
        return admitNew()
    }

    /// One periodic check; returns the transient count to carry.
    @discardableResult func tick(transientMisses: Int = 0) -> Int {
        gate?.guardian.probeJournal()
        _ = gate?.guardian.retryPending(force: false)
        switch evaluate() {
        case .current: return 0
        case .changed(let what): apply(what); return 0
        case .transient(let what):
            if transientMisses + 1 >= 2 { apply(what); return 0 }
            return transientMisses + 1
        }
    }

    func start(interval: TimeInterval = 1) {
        let t = Thread { [self] in
            var misses = 0
            while appliedChange == nil {
                Thread.sleep(forTimeInterval: interval)
                misses = tick(transientMisses: misses)
            }
        }
        t.name = "policy-watch"
        t.start()
    }

    func apply(_ what: String) {
        lock.lock()
        guard applied == nil else { lock.unlock(); return }
        applied = what
        let handler = onChange
        lock.unlock()
        gate?.revoke()
        if let guardian = gate?.guardian, !guardian.retryPending(force: true) {
            ControlService.log("auth.lockdown_unpersisted peers=\(guardian.pendingIPs.count) journal=\(guardian.isDurable ? "saved" : "not_saved") (listen.plist not writable)")
        }
        ControlService.log("stopping: \(what) (was \(started.summary)); admissions under the old policy stopped, launchd restarts the service")
        handler?(what)
    }

    /// B5 r4: blocks the guard holds only in memory must not be lost by
    /// exiting. Returns once every pending block is in listen.plist or the
    /// pending journal (at once when there is none), retrying every
    /// `interval`; false only when `maxWait` ran out. The gate is already
    /// revoked, so nothing is admitted while this waits.
    @discardableResult func waitUntilDurable(interval: TimeInterval = 1, maxWait: TimeInterval? = nil) -> Bool {
        guard let guardian = gate?.guardian else { return true }
        let deadline = maxWait.map { Date().addingTimeInterval($0) }
        var logged = false
        while true {
            if guardian.retryPending(force: true) || guardian.isDurable { return true }
            if !logged {
                ControlService.log("auth.lockdown_hold peers=\(guardian.pendingIPs.count) (neither listen.plist nor the pending journal can be written; not exiting, admitting nobody)")
                logged = true
            }
            if let deadline, Date() >= deadline { return false }
            Thread.sleep(forTimeInterval: interval)
            _ = guardian.saveJournal()
        }
    }
}

/// True at most once per `interval` (log throttling).
final class OncePerInterval: @unchecked Sendable {
    private let lock = NSLock()
    private let interval: TimeInterval
    private var last: TimeInterval = -.infinity
    init(_ interval: TimeInterval) { self.interval = interval }
    func due() -> Bool {
        let t = ProcessInfo.processInfo.systemUptime
        lock.lock(); defer { lock.unlock() }
        guard t - last >= interval else { return false }
        last = t
        return true
    }
}
