import Darwin
import Foundation

/// Who is on the other end of a control connection.
///
/// In production the control service listens on 127.0.0.1:38411 and Tailscale
/// forwards tailnet port 38400 to it (`tailscale serve --tcp 38400`). Without
/// more information every viewer then looks like 127.0.0.1. When the forward is
/// set up with `--proxy-protocol 2` (or 1), Tailscale sends a PROXY header with
/// the viewer's real tailnet address first; `ControlPeer` reads it.
struct ControlPeer: Equatable {
    /// Address used for policy decisions and logs.
    let ip: String
    /// True when `ip` is the real remote address: a direct connection, or a
    /// PROXY header received over loopback. False for a loopback connection
    /// without a header (the forwarding proxy hides the real viewer).
    let verified: Bool

    static func isLoopback(_ ip: String) -> Bool {
        ip == "::1" || ip.hasPrefix("127.")
    }
}

/// PROXY protocol v1 and v2 header parsing (haproxy spec), for the few bytes
/// a control connection starts with.
enum ProxyProtocol {
    enum Result: Equatable {
        /// The first bytes are not a PROXY header; they belong to the normal stream.
        case notProxy
        /// A valid header. `source` is nil for v2 LOCAL / v1 UNKNOWN (no address).
        case proxy(source: String?)
        case invalid(String)
    }

    static let v2Signature: [UInt8] = [0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a]
    private static let v1Prefix: [UInt8] = Array("PROXY ".utf8)

    /// `first` is the first 8 bytes already read from the connection; `read(n)`
    /// reads exactly n more bytes or returns nil.
    static func parse(first: [UInt8], read: (Int) -> [UInt8]?) -> Result {
        guard first.count == 8 else { return .invalid("short read") }
        if first == Array(v2Signature.prefix(8)) {
            return parseV2(read: read)
        }
        if Array(first.prefix(6)) == v1Prefix {
            return parseV1(first: first, read: read)
        }
        return .notProxy
    }

    private static func parseV2(read: (Int) -> [UInt8]?) -> Result {
        guard let rest = read(8) else { return .invalid("v2 truncated") }
        guard Array(rest.prefix(4)) == Array(v2Signature.suffix(4)) else { return .invalid("v2 signature") }
        let verCmd = rest[4]
        let family = rest[5]
        let length = Int(rest[6]) << 8 | Int(rest[7])
        guard verCmd >> 4 == 2 else { return .invalid("v2 version") }
        guard length <= 512 else { return .invalid("v2 length \(length)") }
        let body: [UInt8]
        if length > 0 {
            guard let b = read(length) else { return .invalid("v2 body truncated") }
            body = b
        } else {
            body = []
        }
        switch verCmd & 0x0f {
        case 0x0: return .proxy(source: nil) // LOCAL: health check by the proxy itself
        case 0x1: break                      // PROXY
        default: return .invalid("v2 command")
        }
        switch family >> 4 {
        case 0x1: // AF_INET: src(4) dst(4) sport(2) dport(2)
            guard body.count >= 12 else { return .invalid("v2 inet length") }
            return .proxy(source: body[0..<4].map(String.init).joined(separator: "."))
        case 0x2: // AF_INET6: src(16) dst(16) sport(2) dport(2)
            guard body.count >= 36 else { return .invalid("v2 inet6 length") }
            return .proxy(source: ipv6String(Array(body[0..<16])))
        case 0x0:
            return .proxy(source: nil)
        default:
            return .invalid("v2 family")
        }
    }

    private static func parseV1(first: [UInt8], read: (Int) -> [UInt8]?) -> Result {
        var line = first
        // The v1 header is at most 107 bytes including CRLF.
        while !(line.count >= 2 && line[line.count - 2] == 0x0d && line[line.count - 1] == 0x0a) {
            guard line.count < 107, let b = read(1) else { return .invalid("v1 unterminated") }
            line += b
        }
        guard let text = String(bytes: line.dropLast(2), encoding: .ascii) else { return .invalid("v1 encoding") }
        let parts = text.split(separator: " ").map(String.init)
        guard parts.count >= 2, parts[0] == "PROXY" else { return .invalid("v1 syntax") }
        switch parts[1] {
        case "UNKNOWN":
            return .proxy(source: nil)
        case "TCP4", "TCP6":
            guard parts.count == 6 else { return .invalid("v1 fields") }
            let family = parts[1] == "TCP4" ? AF_INET : AF_INET6
            guard isValidAddress(parts[2], family: family) else { return .invalid("v1 address") }
            return .proxy(source: normalize(parts[2]))
        default:
            return .invalid("v1 protocol")
        }
    }

    private static func isValidAddress(_ s: String, family: Int32) -> Bool {
        var buf = [UInt8](repeating: 0, count: 16)
        return s.withCString { inet_pton(family, $0, &buf) } == 1
    }

    private static func ipv6String(_ bytes: [UInt8]) -> String {
        // IPv4-mapped (::ffff:a.b.c.d) reads as the plain IPv4 address.
        if bytes[0..<10].allSatisfy({ $0 == 0 }) && bytes[10] == 0xff && bytes[11] == 0xff {
            return bytes[12..<16].map(String.init).joined(separator: ".")
        }
        var addr = in6_addr()
        withUnsafeMutableBytes(of: &addr) { raw in
            for i in 0..<16 { raw[i] = bytes[i] }
        }
        var out = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        _ = inet_ntop(AF_INET6, &addr, &out, socklen_t(INET6_ADDRSTRLEN))
        return String(cString: out)
    }

    private static func normalize(_ s: String) -> String {
        let lower = s.lowercased()
        if lower.hasPrefix("::ffff:"), !lower.dropFirst(7).contains(":") {
            return String(lower.dropFirst(7))
        }
        return s
    }
}

/// Only the configured viewer (JERISLINK_CLIENT_IP in network.conf) may change
/// the persisted video settings; any other control client gets the current
/// settings back unchanged.
enum SettingsAuthority {
    enum Decision: Equatable {
        case allow
        case reject(String)
    }

    static func check(peer: ControlPeer, clientIP: String?) -> Decision {
        guard let clientIP, !clientIP.isEmpty else {
            // No viewer configured: nothing to compare against (legacy setup).
            return .allow
        }
        if peer.verified {
            return peer.ip == clientIP ? .allow : .reject("other-address")
        }
        // Loopback without a PROXY header: the real viewer is unknown.
        if ControlPeer.isLoopback(clientIP) { return .allow }
        return .reject("unverified-peer")
    }
}

/// `JerisLinkHost --self-test`: checks PROXY parsing, the settings policy and
/// that an identical settings request does not restart video. Exit code 0 on
/// success. Uses a temporary settings file and never restarts anything.
enum ControlPeerSelfTest {
    static func run() -> Int32 {
        var failures = 0
        func expect(_ ok: Bool, _ name: String) {
            print("\(ok ? "PASS" : "FAIL") \(name)")
            if !ok { failures += 1 }
        }

        func parse(_ bytes: [UInt8]) -> ProxyProtocol.Result {
            var stream = bytes
            func take(_ n: Int) -> [UInt8]? {
                guard stream.count >= n else { return nil }
                let out = Array(stream.prefix(n))
                stream.removeFirst(n)
                return out
            }
            guard let first = take(8) else { return .invalid("short read") }
            return ProxyProtocol.parse(first: first, read: take)
        }

        let mrc1: [UInt8] = [0x4d, 0x52, 0x43, 0x31, 1, 0x01, 0, 4, 0, 0, 0, 1]
        expect(parse(mrc1) == .notProxy, "plain MRC1 stream is not a PROXY header")
        expect(parse(Array("PROXY TCP4 100.64.0.6 127.0.0.1 51234 38411\r\n".utf8)) == .proxy(source: "100.64.0.6"),
               "v1 TCP4 source")
        expect(parse(Array("PROXY UNKNOWN\r\n".utf8)) == .proxy(source: nil), "v1 UNKNOWN")
        expect(parse(Array("PROXY TCP4 bogus 127.0.0.1 1 2\r\n".utf8)) == .invalid("v1 address"), "v1 bad address rejected")
        let v2Inet = ProxyProtocol.v2Signature + [0x21, 0x11, 0x00, 0x0c,
                                                  100, 64, 0, 20, 127, 0, 0, 1, 0xc8, 0x00, 0x95, 0xdb]
        expect(parse(v2Inet) == .proxy(source: "100.64.0.20"), "v2 TCP4 source")
        var mapped = [UInt8](repeating: 0, count: 10) + [0xff, 0xff, 100, 64, 0, 6]
        mapped += [UInt8](repeating: 0, count: 15) + [1] + [0, 1, 0, 2]
        let v2Mapped = ProxyProtocol.v2Signature + [0x21, 0x21, 0x00, 0x24] + mapped
        expect(parse(v2Mapped) == .proxy(source: "100.64.0.6"), "v2 TCP6 v4-mapped source")
        expect(parse(ProxyProtocol.v2Signature + [0x20, 0x00, 0x00, 0x00]) == .proxy(source: nil), "v2 LOCAL")
        expect(parse(ProxyProtocol.v2Signature + [0x21, 0x11, 0x00, 0x0c, 1, 2]) == .invalid("v2 body truncated"),
               "v2 truncated body rejected")

        let client = "100.64.0.20"
        expect(SettingsAuthority.check(peer: ControlPeer(ip: client, verified: true), clientIP: client) == .allow,
               "configured client may change settings")
        expect(SettingsAuthority.check(peer: ControlPeer(ip: "100.64.0.6", verified: true), clientIP: client)
               == .reject("other-address"), "second address is rejected")
        expect(SettingsAuthority.check(peer: ControlPeer(ip: "127.0.0.1", verified: false), clientIP: client)
               == .reject("unverified-peer"), "unverified loopback peer is rejected")
        expect(SettingsAuthority.check(peer: ControlPeer(ip: "127.0.0.1", verified: false), clientIP: "127.0.0.1")
               == .allow, "loopback client config allows loopback")
        expect(SettingsAuthority.check(peer: ControlPeer(ip: "100.64.0.6", verified: true), clientIP: nil) == .allow,
               "no configured client keeps the legacy behaviour")

        // Identical requests: one restart for the first change, none after.
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("jerislink-selftest-\(getpid())", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let plist = dir.appendingPathComponent("video-settings.plist")
        var restarts = 0
        let controller = VideoSettingsController(fileURL: plist, restart: { restarts += 1 })
        let hevc18: [UInt8] = [1, 2, 0x03, 0, 0, 18]
        let first = controller.apply(request: hevc18)
        let second = controller.apply(request: hevc18)
        let third = controller.apply(request: hevc18)
        expect(first.status == 0 && first.flags & 0x01 != 0 && restarts == 1, "first change restarts once")
        expect(second.status == 0 && second.flags & 0x01 == 0 && third.flags & 0x01 == 0 && restarts == 1,
               "repeated identical request does not restart")
        let ignored = controller.currentAck(ignored: true)
        expect(ignored.status == 0 && ignored.codec == 2 && ignored.bitrateMbps == 18 && ignored.flags & 0x10 != 0
               && ignored.flags & 0x01 == 0 && restarts == 1, "ignored request reports current settings, no restart")

        print(failures == 0 ? "SELFTEST OK" : "SELFTEST FAILED failures=\(failures)")
        return failures == 0 ? 0 : 1
    }
}
