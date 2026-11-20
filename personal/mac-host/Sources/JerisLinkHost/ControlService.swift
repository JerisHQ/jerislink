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
                             admit: (@Sendable () -> Bool)? = nil) throws -> [ControlServer] {
        var servers: [ControlServer] = []
        do {
            // With a gate the whitelist, blacklist and password live in the
            // gate; without one (legacy callers) the 0.3 single-IP check.
            let direct = ControlServer(bindIP: bindIP, allowedClientIP: gate == nil ? clientIP : nil,
                                       port: port, inject: inject,
                                       settingsClientIP: { clientIP }, acceptProxy: false,
                                       inputHelper: helper, allowFileSessions: true, authGate: gate,
                                       admitConnection: admit)
            try direct.start()
            servers.append(direct)
            let relayIsDirect = bindIP == ListenConfig.loopbackIP && relayPort == port
            // Password mode: the relay carries UDP mouse input that is only
            // IP-checked (MouseMoveUDPServer), so it stays closed until PR-C
            // binds that input to an authenticated session.
            let relayAllowed = !(gate?.requiresPassword ?? false)
            if relayPort != 0 && !relayIsDirect && relayAllowed {
                let relay = ControlServer(bindIP: ListenConfig.loopbackIP, allowedClientIP: ListenConfig.loopbackIP,
                                          port: relayPort, inject: inject,
                                          settingsClientIP: { clientIP }, acceptProxy: false,
                                          inputHelper: helper, announceInputSessions: false,
                                          allowSensitiveControl: false, relayMouseOnly: true,
                                          admitConnection: admit)
                try relay.start()
                servers.append(relay)
            }
        } catch {
            servers.forEach { $0.stop() }
            throw error
        }
        return servers
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
        let (gate, snapshot) = authGate(clientIP: endpoint.clientIP, plist: plist, secret: secret, blocklist: blocklist)
        let watch = PolicyWatch(started: endpoint, snapshot: snapshot, gate: gate,
                                read: { ListenConfig.currentWithPlist() },
                                loadSecret: { KeychainSecretStore().load() })
        watch.setOnChange { _ in
            running.forEach { $0.stop() }
            exit(0)
        }
        if gate == nil {
            // Refused: no listener at all until listen.plist changes.
            watch.start()
            while true { try? await Task.sleep(for: .seconds(3600)) }
        }
        if gate?.requiresPassword == true && o.relayPort != 0 {
            log("relay off: password mode (UDP mouse input waits for session binding, PR-C)")
        }
        do {
            running = try startServers(bindIP: endpoint.bindIP, clientIP: endpoint.clientIP,
                                       port: o.controlPort, relayPort: o.relayPort,
                                       inject: o.controlInject, helper: InputHelperClient(), gate: gate,
                                       admit: { watch.admitNew() })
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
                         blocklist: BlocklistStore) -> (AuthGate?, AuthConfigSnapshot) {
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
        return (AuthGate.make(policy: policy, secret: secret, blocklist: blocklist), snapshot)
    }
}

/// Watches the settings one control-service process started with: the
/// endpoint and the auth inputs (passwordSet, allowedIPs, allowedIPsSource,
/// the password, blockedIPs edited outside the service), all from one read
/// of listen.plist per check.
///
/// - `admitNew` runs for every accepted connection: when the settings no
///   longer match it refuses that connection, and the change is applied
///   at once.
/// - `start` checks every second as well, so connections already open are
///   closed without waiting for a new one.
/// Applying a change revokes the gate first (nothing more is admitted under
/// the old policy), then calls the change handler, which in the service
/// stops every listener and exits; launchd starts the new policy. Only an
/// address that went down (`waiting`) keeps the older two-checks rule, since
/// nothing can connect over it anyway.
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
    private let lock = NSLock()
    private var applied: String?
    private var onChange: (@Sendable (String) -> Void)?

    init(started: ListenEndpoint, snapshot: AuthConfigSnapshot, gate: AuthGate?,
         read: @escaping @Sendable () -> (ListenResolution, [String: Any]?),
         loadSecret: @escaping @Sendable () -> ConnSecret?) {
        self.started = started
        self.snapshot = snapshot
        self.gate = gate
        self.read = read
        self.loadSecret = loadSecret
    }

    func setOnChange(_ handler: @escaping @Sendable (String) -> Void) {
        lock.lock(); onChange = handler; lock.unlock()
    }

    /// The change already applied, if any.
    var appliedChange: String? { lock.lock(); defer { lock.unlock() }; return applied }

    func evaluate() -> Verdict {
        let guardian = gate?.guardian
        let before = guardian?.persistedIPs
        let (resolution, plist) = read()
        switch resolution {
        case .ready(let ep) where ep == started: break
        case .ready(let ep): return .changed("endpoint changed to \(ep.summary)")
        case .notConfigured(let reason): return .changed("not configured: \(reason)")
        case .waiting(let reason): return .transient(reason)
        }
        let secret = ControlService.wantsPassword(plist) ? loadSecret() : nil
        let now = AuthConfigSnapshot.read(plist: plist, secret: secret)
        if now != snapshot { return .changed("config.auth_changed keys=\(now.changes(from: snapshot))") }
        if let guardian, let before {
            let inFile = Set((plist.map(ListenPlistBlocklist.entries(in:)) ?? []).map(\.ip))
            // A write by the guard between the two reads is not an outside edit.
            if inFile != before && guardian.persistedIPs == before {
                return .changed("config.auth_changed keys=blockedIPs")
            }
        }
        return .current
    }

    /// For each accepted connection.
    func admitNew() -> Bool {
        if appliedChange != nil { return false }
        if case .changed(let what) = evaluate() {
            apply(what)
            return false
        }
        return true
    }

    /// One periodic check; returns the transient count to carry.
    @discardableResult func tick(transientMisses: Int = 0) -> Int {
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
            ControlService.log("auth.lockdown_unpersisted peers=\(guardian.pendingIPs.count) (listen.plist not writable; password mode refuses to start until it is)")
        }
        ControlService.log("stopping: \(what) (was \(started.summary)); admissions under the old policy stopped, launchd restarts the service")
        handler?(what)
    }
}
