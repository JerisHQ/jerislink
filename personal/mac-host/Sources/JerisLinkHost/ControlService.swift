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
                             gate: AuthGate? = nil) throws -> [ControlServer] {
        var servers: [ControlServer] = []
        do {
            // With a gate the whitelist, blacklist and password live in the
            // gate; without one (legacy callers) the 0.3 single-IP check.
            let direct = ControlServer(bindIP: bindIP, allowedClientIP: gate == nil ? clientIP : nil,
                                       port: port, inject: inject,
                                       settingsClientIP: { clientIP }, acceptProxy: false,
                                       inputHelper: helper, allowFileSessions: true, authGate: gate)
            try direct.start()
            servers.append(direct)
            let relayIsDirect = bindIP == ListenConfig.loopbackIP && relayPort == port
            if relayPort != 0 && !relayIsDirect {
                let relay = ControlServer(bindIP: ListenConfig.loopbackIP, allowedClientIP: ListenConfig.loopbackIP,
                                          port: relayPort, inject: inject,
                                          settingsClientIP: { clientIP }, acceptProxy: false,
                                          inputHelper: helper, announceInputSessions: false,
                                          allowSensitiveControl: false, relayMouseOnly: true)
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
        let endpoint = await ListenConfig.waitForEndpoint(log: log)
        log("starting control \(endpoint.summary) port=\(o.controlPort) relay=\(o.relayPort == 0 ? "off" : "127.0.0.1:\(o.relayPort)")")
        let gate = authGate(clientIP: endpoint.clientIP)
        if gate == nil {
            // Refused: no listener at all until listen.plist changes.
            ListenConfig.exitWhenEndpointChanges(from: endpoint, log: log)
            while true { try? await Task.sleep(for: .seconds(3600)) }
        }
        do {
            running = try startServers(bindIP: endpoint.bindIP, clientIP: endpoint.clientIP,
                                       port: o.controlPort, relayPort: o.relayPort,
                                       inject: o.controlInject, helper: InputHelperClient(), gate: gate)
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
        ListenConfig.exitWhenEndpointChanges(from: endpoint, log: log)
        while true {
            try? await Task.sleep(for: .seconds(3600))
        }
    }
}

extension ControlService {
    /// v0.4.0 connection password. The Keychain is read only when
    /// listen.plist says a password was set, so a host without one never
    /// touches it. Returns nil when the configuration must refuse every
    /// connection (logged as config.refused).
    static func authGate(clientIP: String) -> AuthGate? {
        let plist = ListenConfig.readPlist()
        let wantsPassword = (plist?["passwordSet"] as? Bool) == true
        let secret = wantsPassword ? KeychainSecretStore().load() : nil
        let policy = AuthPolicy.resolve(plist: plist, clientIP: clientIP, secretLoaded: secret != nil)
        if case .refused(let reason) = policy {
            log("config.refused reason=\(reason)")
            return nil
        }
        log("auth.policy \(policy.summary)")
        return AuthGate.make(policy: policy, secret: secret,
                             blocklist: ListenPlistBlocklist(url: ListenConfig.plistURL))
    }
}
