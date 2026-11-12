import Darwin
import Foundation

/// `--service video`: the video host as a launchd agent.
///
/// Replaces the old video-watchdog.zsh. It reads the network addresses from
/// network.conf (or the environment), waits until this Mac's address is up on a
/// local interface (Tailscale running), reads the persisted codec/bitrate, and
/// then runs the normal 24-hour video session. launchd (KeepAlive) restarts it
/// when it exits, crashes, or is restarted by the control service.
enum VideoService {
    static var supportDirectory: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/JerisLink", isDirectory: true)
    }

    static var networkConfURL: URL {
        if let path = ProcessInfo.processInfo.environment["JERISLINK_NETWORK_CONF"], !path.isEmpty {
            return URL(fileURLWithPath: path)
        }
        return supportDirectory.appendingPathComponent("network.conf")
    }

    /// Parses the simple `KEY=value` lines of network.conf (a zsh file).
    static func parseConf(_ text: String) -> [String: String] {
        var values: [String: String] = [:]
        for raw in text.split(whereSeparator: \.isNewline) {
            var line = String(raw)
            if let hash = line.firstIndex(of: "#") { line = String(line[..<hash]) }
            line = line.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("export ") { line = String(line.dropFirst(7)).trimmingCharacters(in: .whitespaces) }
            guard let eq = line.firstIndex(of: "=") else { continue }
            let key = line[..<eq].trimmingCharacters(in: .whitespaces)
            var value = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)
            if value.count >= 2, let first = value.first, first == value.last, first == "\"" || first == "'" {
                value = String(value.dropFirst().dropLast())
            }
            if !key.isEmpty { values[key] = value }
        }
        return values
    }

    /// network.conf wins over the environment, as in the old watchdog.
    static func loadAddresses() -> (bindIP: String?, clientIP: String?) {
        let env = ProcessInfo.processInfo.environment
        var conf: [String: String] = [:]
        if let text = try? String(contentsOf: networkConfURL, encoding: .utf8) {
            conf = parseConf(text)
        }
        func pick(_ key: String) -> String? {
            let value = conf[key] ?? env[key]
            guard let value, !value.isEmpty else { return nil }
            return value
        }
        return (pick("JERISLINK_BIND_IP"), pick("JERISLINK_CLIENT_IP"))
    }

    static func localIPv4Addresses() -> Set<String> {
        var result = Set<String>()
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
                result.insert(String(cString: buffer))
            }
            cursor = entry.pointee.ifa_next
        }
        return result
    }

    static func log(_ message: String) {
        let stamp = ISO8601DateFormatter().string(from: Date())
        print("\(stamp) video-service: \(message)")
        fflush(stdout)
    }

    /// Blocks until the service is configured and the bind address is up, then
    /// returns the production video options.
    static func resolveOptions(base: Options) async -> Options {
        var loggedNotConfigured = false
        var loggedWaiting = false
        while true {
            let (bindIP, clientIP) = loadAddresses()
            guard let bindIP, let clientIP else {
                if !loggedNotConfigured {
                    log("not configured: set JERISLINK_BIND_IP and JERISLINK_CLIENT_IP in \(networkConfURL.path)")
                    loggedNotConfigured = true
                }
                try? await Task.sleep(for: .seconds(5))
                continue
            }
            guard localIPv4Addresses().contains(bindIP) else {
                if !loggedWaiting {
                    log("waiting for \(bindIP) on a local interface (Tailscale running) before starting video")
                    loggedWaiting = true
                }
                try? await Task.sleep(for: .seconds(1))
                continue
            }

            let persisted = VideoSettingsController.readPersisted()
            let codec: VideoCodec = persisted.codec == "hevc" ? .hevc : .h264
            let bitrate = (4...100).contains(persisted.bitrateMbps) ? persisted.bitrateMbps : 25
            log("starting video bind=\(bindIP) client=\(clientIP) codec=\(codec.rawValue) bitrate=\(bitrate) Mbps")

            var o = base
            o.durationSeconds = 86400
            o.fps = 60
            o.bitrateMbps = bitrate
            o.codec = codec
            o.colorRange = "full"
            o.keyframeInterval = 60
            o.h264Profile = "constrained-high"
            o.captureQueueDepth = 2
            o.bindIP = bindIP
            o.clientIP = clientIP
            o.controlClientIP = clientIP
            o.clientPort = 38402
            o.packetBytes = 1200
            o.mouseUDPPort = 38412
            o.controlServerEnabled = false
            o.captureCursor = false
            o.outputPath = "/dev/null"
            return o
        }
    }
}
