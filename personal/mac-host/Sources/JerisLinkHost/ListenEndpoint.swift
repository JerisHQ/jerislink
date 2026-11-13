import Darwin
import Foundation

/// Where the host listens (listen-interface design, phase 1).
///
/// Video send, mouse UDP and control TCP all take their addresses from one
/// `ListenEndpoint`, so the screen and the input can never point at different
/// interfaces. Phase 1 knows two modes:
/// - `loopback`: 127.0.0.1 only (local tests, SSH port forwards);
/// - `tailnet`: this Mac's tailnet address, one allowed viewer.
///
/// Source of truth: `listen.plist` (keys `mode`, `clientIP`, optional
/// `bindIP`). Without it, `network.conf` (JERISLINK_BIND_IP and
/// JERISLINK_CLIENT_IP) is read as before, so existing installs keep working.
/// When listen.plist exists it wins, and its mode never falls back to another
/// interface: if the address is gone the services wait for it.
enum ListenMode: String, Equatable {
    case loopback
    case tailnet
}

struct ListenEndpoint: Equatable {
    var mode: ListenMode
    var bindIP: String
    var clientIP: String
    var source: String

    var summary: String { "mode=\(mode.rawValue) bind=\(bindIP) client=\(clientIP) source=\(source)" }
}

enum ListenResolution: Equatable {
    case ready(ListenEndpoint)
    /// Settings are missing or invalid; the reason is for the log.
    case notConfigured(String)
    /// Settings are fine but the address is not up on this Mac yet.
    case waiting(String)
}

struct LocalAddress: Equatable {
    var interface: String
    var ip: String
}

enum ListenConfig {
    static let loopbackIP = "127.0.0.1"

    static var plistURL: URL {
        if let path = ProcessInfo.processInfo.environment["JERISLINK_LISTEN_PLIST"], !path.isEmpty {
            return URL(fileURLWithPath: path)
        }
        return VideoService.supportDirectory.appendingPathComponent("listen.plist")
    }

    /// Tailscale's CGNAT range 100.64.0.0/10.
    static func isTailnetIPv4(_ ip: String) -> Bool {
        var addr = in_addr()
        guard inet_pton(AF_INET, ip, &addr) == 1 else { return false }
        let host = UInt32(bigEndian: addr.s_addr)
        return host & 0xFFC0_0000 == 0x6440_0000
    }

    static func isIPv4(_ ip: String) -> Bool {
        var addr = in_addr()
        return inet_pton(AF_INET, ip, &addr) == 1
    }

    /// Pure resolver, used by the services and the self-test.
    /// - plist: contents of listen.plist, nil when the file does not exist.
    /// - conf: JERISLINK_BIND_IP / JERISLINK_CLIENT_IP from network.conf or the environment.
    /// - local: IPv4 addresses currently on this Mac.
    static func resolve(plist: [String: Any]?, conf: (bindIP: String?, clientIP: String?),
                        local: [LocalAddress]) -> ListenResolution {
        let localIPs = Set(local.map(\.ip))
        guard let plist else {
            guard let bindIP = conf.bindIP, let clientIP = conf.clientIP else {
                return .notConfigured("no listen.plist, and network.conf has no JERISLINK_BIND_IP/JERISLINK_CLIENT_IP")
            }
            let mode: ListenMode = bindIP == loopbackIP ? .loopback : .tailnet
            let ep = ListenEndpoint(mode: mode, bindIP: bindIP, clientIP: clientIP, source: "network.conf")
            return localIPs.contains(bindIP) ? .ready(ep) : .waiting("\(bindIP) is not on a local interface")
        }

        let rawMode = (plist["mode"] as? String)?.lowercased() ?? ""
        guard let mode = ListenMode(rawValue: rawMode) else {
            return .notConfigured("listen.plist mode \"\(rawMode)\" is not loopback or tailnet")
        }
        switch mode {
        case .loopback:
            // The viewer reaches a loopback host only from this Mac (or through
            // a local port forward), so its address is always 127.0.0.1.
            return .ready(ListenEndpoint(mode: .loopback, bindIP: loopbackIP, clientIP: loopbackIP,
                                         source: "listen.plist"))
        case .tailnet:
            guard let clientIP = plist["clientIP"] as? String, isTailnetIPv4(clientIP) else {
                return .notConfigured("listen.plist tailnet mode needs clientIP in 100.64.0.0/10")
            }
            if let bindIP = plist["bindIP"] as? String, !bindIP.isEmpty {
                guard isTailnetIPv4(bindIP) else {
                    return .notConfigured("listen.plist bindIP \(bindIP) is not a tailnet address")
                }
                let ep = ListenEndpoint(mode: .tailnet, bindIP: bindIP, clientIP: clientIP, source: "listen.plist")
                return localIPs.contains(bindIP) ? .ready(ep) : .waiting("tailnet address \(bindIP) is not up")
            }
            let tailnet = local.filter { $0.interface.hasPrefix("utun") && isTailnetIPv4($0.ip) }
                .map(\.ip).sorted()
            guard let bindIP = tailnet.first else {
                return .waiting("no tailnet address on this Mac (Tailscale not connected)")
            }
            return .ready(ListenEndpoint(mode: .tailnet, bindIP: bindIP, clientIP: clientIP, source: "listen.plist"))
        }
    }

    static func readPlist() -> [String: Any]? {
        guard let data = try? Data(contentsOf: plistURL) else { return nil }
        let parsed = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        // An unreadable file must not fall back to network.conf.
        return parsed as? [String: Any] ?? ["mode": "invalid"]
    }

    static func localAddresses() -> [LocalAddress] {
        var result: [LocalAddress] = []
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return result }
        defer { freeifaddrs(head) }
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let entry = cursor {
            if let addr = entry.pointee.ifa_addr, addr.pointee.sa_family == UInt8(AF_INET) {
                var buffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sin in
                    var address = sin.pointee.sin_addr
                    _ = inet_ntop(AF_INET, &address, &buffer, socklen_t(INET_ADDRSTRLEN))
                }
                result.append(LocalAddress(interface: String(cString: entry.pointee.ifa_name),
                                           ip: String(cString: buffer)))
            }
            cursor = entry.pointee.ifa_next
        }
        return result
    }

    static func current() -> ListenResolution {
        resolve(plist: readPlist(), conf: VideoService.loadAddresses(), local: localAddresses())
    }

    /// The configured viewer, even while its interface is down.
    static func configuredClientIP() -> String? {
        if let plist = readPlist() {
            switch ListenMode(rawValue: (plist["mode"] as? String)?.lowercased() ?? "") {
            case .loopback: return loopbackIP
            case .tailnet: return plist["clientIP"] as? String
            case nil: return nil
            }
        }
        return VideoService.loadAddresses().clientIP
    }

    /// Blocks until the endpoint is ready. Logs each new reason once.
    static func waitForEndpoint(log: (String) -> Void) async -> ListenEndpoint {
        var lastReason: String?
        while true {
            switch current() {
            case .ready(let ep):
                return ep
            case .notConfigured(let reason):
                if reason != lastReason { log("not configured: \(reason) (\(plistURL.path))"); lastReason = reason }
                try? await Task.sleep(for: .seconds(5))
            case .waiting(let reason):
                if reason != lastReason { log("waiting: \(reason); not listening on any other interface"); lastReason = reason }
                try? await Task.sleep(for: .seconds(2))
            }
        }
    }

    /// Stop-and-wait (design D5): checks every 2 s and exits when the endpoint
    /// this process started with is no longer the current one for two checks
    /// in a row (address gone, mode or viewer changed). launchd (KeepAlive)
    /// starts the service again, and it waits in `waitForEndpoint`. The video
    /// and control services both do this, so they always move together.
    static func exitWhenEndpointChanges(from started: ListenEndpoint, log: @escaping @Sendable (String) -> Void) {
        Task.detached {
            var misses = 0
            while true {
                try? await Task.sleep(for: .seconds(2))
                let now = current()
                if now == .ready(started) { misses = 0; continue }
                misses += 1
                if misses >= 2 {
                    let what: String
                    switch now {
                    case .ready(let ep): what = "endpoint changed to \(ep.summary)"
                    case .notConfigured(let reason): what = "not configured: \(reason)"
                    case .waiting(let reason): what = reason
                    }
                    log("stopping: \(what) (was \(started.summary)); launchd restarts the service, which waits for the endpoint")
                    exit(0)
                }
            }
        }
    }
}

/// `JerisLinkHost --self-test` part for the resolver. Pure; touches no files.
enum ListenConfigSelfTest {
    static func run() -> Int32 {
        var failures = 0
        func expect(_ ok: Bool, _ name: String) {
            print("\(ok ? "PASS" : "FAIL") \(name)")
            if !ok { failures += 1 }
        }
        let mac = [LocalAddress(interface: "lo0", ip: "127.0.0.1"),
                   LocalAddress(interface: "en0", ip: "192.168.1.20"),
                   LocalAddress(interface: "utun4", ip: "100.64.0.10")]
        let offline = [LocalAddress(interface: "lo0", ip: "127.0.0.1"),
                       LocalAddress(interface: "en0", ip: "192.168.1.20")]
        let noConf: (bindIP: String?, clientIP: String?) = (nil, nil)
        let legacy: (bindIP: String?, clientIP: String?) = ("100.64.0.10", "100.64.0.20")

        expect(ListenConfig.resolve(plist: nil, conf: legacy, local: mac)
               == .ready(ListenEndpoint(mode: .tailnet, bindIP: "100.64.0.10", clientIP: "100.64.0.20", source: "network.conf")),
               "network.conf fallback keeps today's addresses")
        if case .waiting = ListenConfig.resolve(plist: nil, conf: legacy, local: offline) {
            expect(true, "network.conf waits while the tailnet address is down")
        } else { expect(false, "network.conf waits while the tailnet address is down") }
        if case .notConfigured = ListenConfig.resolve(plist: nil, conf: noConf, local: mac) {
            expect(true, "no settings at all is not configured")
        } else { expect(false, "no settings at all is not configured") }

        expect(ListenConfig.resolve(plist: ["mode": "tailnet", "clientIP": "100.64.0.20"], conf: noConf, local: mac)
               == .ready(ListenEndpoint(mode: .tailnet, bindIP: "100.64.0.10", clientIP: "100.64.0.20", source: "listen.plist")),
               "tailnet mode finds this Mac's tailnet address on utun")
        expect(ListenConfig.resolve(plist: ["mode": "tailnet", "clientIP": "100.64.0.20"], conf: legacy, local: offline)
               == .waiting("no tailnet address on this Mac (Tailscale not connected)"),
               "tailnet down: waits, never falls back to en0 or network.conf")
        expect(ListenConfig.resolve(plist: ["mode": "tailnet", "clientIP": "192.168.1.30"], conf: legacy, local: mac)
               == .notConfigured("listen.plist tailnet mode needs clientIP in 100.64.0.0/10"),
               "tailnet mode rejects a LAN viewer address")
        expect(ListenConfig.resolve(plist: ["mode": "tailnet", "clientIP": "100.64.0.20", "bindIP": "192.168.1.20"],
                                    conf: noConf, local: mac)
               == .notConfigured("listen.plist bindIP 192.168.1.20 is not a tailnet address"),
               "tailnet mode rejects a LAN bind address")
        expect(ListenConfig.resolve(plist: ["mode": "loopback", "clientIP": "100.64.0.20"], conf: legacy, local: offline)
               == .ready(ListenEndpoint(mode: .loopback, bindIP: "127.0.0.1", clientIP: "127.0.0.1", source: "listen.plist")),
               "loopback mode binds and allows 127.0.0.1 only")
        expect(ListenConfig.resolve(plist: ["mode": "lan"], conf: legacy, local: mac)
               == .notConfigured("listen.plist mode \"lan\" is not loopback or tailnet"),
               "unknown mode (lan) is refused, not widened")
        expect(ListenConfig.isTailnetIPv4("100.127.255.254") && !ListenConfig.isTailnetIPv4("100.128.0.1")
               && !ListenConfig.isTailnetIPv4("100.63.255.255"), "100.64.0.0/10 bounds")

        print(failures == 0 ? "LISTEN SELFTEST OK" : "LISTEN SELFTEST FAILED failures=\(failures)")
        return failures == 0 ? 0 : 1
    }
}
