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
enum ControlService {
    static func log(_ message: String) {
        let stamp = ISO8601DateFormatter().string(from: Date())
        print("\(stamp) control-service: \(message)")
        fflush(stdout)
    }

    static func run(_ o: Options) async -> Never {
        let endpoint = await ListenConfig.waitForEndpoint(log: log)
        log("starting control \(endpoint.summary) port=\(o.controlPort) relay=\(o.relayPort == 0 ? "off" : "127.0.0.1:\(o.relayPort)")")
        let client = endpoint.clientIP
        var servers: [ControlServer] = []
        do {
            let direct = ControlServer(bindIP: endpoint.bindIP, allowedClientIP: client,
                                       port: o.controlPort, inject: o.controlInject,
                                       settingsClientIP: { client }, acceptProxy: false)
            try direct.start()
            servers.append(direct)
            let relayIsDirect = endpoint.bindIP == ListenConfig.loopbackIP && o.relayPort == o.controlPort
            if o.relayPort != 0 && !relayIsDirect {
                let relay = ControlServer(bindIP: ListenConfig.loopbackIP, allowedClientIP: ListenConfig.loopbackIP,
                                          port: o.relayPort, inject: o.controlInject,
                                          settingsClientIP: { client }, acceptProxy: false)
                try relay.start()
                servers.append(relay)
            }
        } catch {
            // Usually the address went away between the check and bind();
            // launchd restarts us after ThrottleInterval and we wait again.
            log("start failed: \(error.localizedDescription)")
            servers.forEach { $0.stop() }
            exit(1)
        }
        ListenConfig.exitWhenEndpointChanges(from: endpoint, log: log)
        while true {
            try? await Task.sleep(for: .seconds(3600))
        }
    }
}
