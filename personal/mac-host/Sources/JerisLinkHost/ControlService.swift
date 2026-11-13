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

    static func log(_ message: String) {
        let stamp = ISO8601DateFormatter().string(from: Date())
        print("\(stamp) control-service: \(message)")
        fflush(stdout)
    }

    /// Start the direct listener on bindIP:port and, unless it is the same
    /// socket, the loopback relay listener on 127.0.0.1:relayPort. Both use
    /// `helper`. On failure, servers already started are stopped.
    static func startServers(bindIP: String, clientIP: String, port: UInt16, relayPort: UInt16,
                             inject: Bool, helper: InputHelperClient) throws -> [ControlServer] {
        var servers: [ControlServer] = []
        do {
            let direct = ControlServer(bindIP: bindIP, allowedClientIP: clientIP,
                                       port: port, inject: inject,
                                       settingsClientIP: { clientIP }, acceptProxy: false,
                                       inputHelper: helper)
            try direct.start()
            servers.append(direct)
            let relayIsDirect = bindIP == ListenConfig.loopbackIP && relayPort == port
            if relayPort != 0 && !relayIsDirect {
                let relay = ControlServer(bindIP: ListenConfig.loopbackIP, allowedClientIP: ListenConfig.loopbackIP,
                                          port: relayPort, inject: inject,
                                          settingsClientIP: { clientIP }, acceptProxy: false,
                                          inputHelper: helper, reconnectHelperOnClient: false)
                try relay.start()
                servers.append(relay)
            }
        } catch {
            servers.forEach { $0.stop() }
            throw error
        }
        return servers
    }

    static func run(_ o: Options) async -> Never {
        // stdout is a file under launchd: flush every line so ControlServer's
        // print() output (connects, keys, warnings) reaches the log promptly.
        setvbuf(stdout, nil, _IOLBF, 0)
        let endpoint = await ListenConfig.waitForEndpoint(log: log)
        log("starting control \(endpoint.summary) port=\(o.controlPort) relay=\(o.relayPort == 0 ? "off" : "127.0.0.1:\(o.relayPort)")")
        do {
            running = try startServers(bindIP: endpoint.bindIP, clientIP: endpoint.clientIP,
                                       port: o.controlPort, relayPort: o.relayPort,
                                       inject: o.controlInject, helper: InputHelperClient())
        } catch {
            // Usually the address went away between the check and bind();
            // launchd restarts us after ThrottleInterval and we wait again.
            log("start failed: \(error.localizedDescription)")
            exit(1)
        }
        log("listening: \(running.count) listener(s), one input helper connection")
        ListenConfig.exitWhenEndpointChanges(from: endpoint, log: log)
        while true {
            try? await Task.sleep(for: .seconds(3600))
        }
    }
}
