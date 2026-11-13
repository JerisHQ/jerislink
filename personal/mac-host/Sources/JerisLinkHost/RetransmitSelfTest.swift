import Foundation
import Darwin

/// `JerisLinkHost --self-test` part for NACK retransmit (MRM1 0x41) and the
/// RTT ping (0x43 -> 0x44). Pure checks for the cache, the budget and range
/// expansion, then loopback checks with the real UDPFrameSender and
/// MouseMoveUDPServer. Nothing leaves 127.0.0.1.
enum RetransmitSelfTest {
    static func run() -> Int32 {
        var failures = 0
        func expect(_ ok: Bool, _ name: String) {
            print("\(ok ? "PASS" : "FAIL") \(name)")
            if !ok { failures += 1 }
        }
        typealias R = UDPFrameSender.NackRange

        // Range expansion.
        expect(UDPFrameSender.packetIndices(for: [R(start: 2, count: 3), R(start: 4, count: 2)], packetCount: 10) == [2, 3, 4, 5],
               "nack: overlapping ranges merge")
        expect(UDPFrameSender.packetIndices(for: [.wholeFrame], packetCount: 5) == [0, 1, 2, 3, 4],
               "nack: (0, 0xFFFF) means the whole frame")
        expect(UDPFrameSender.packetIndices(for: [R(start: 8, count: 10)], packetCount: 10) == [8, 9],
               "nack: range clipped at frame end")
        expect(UDPFrameSender.packetIndices(for: [R(start: 12, count: 1)], packetCount: 10).isEmpty,
               "nack: range past frame end ignored")

        // Cache eviction.
        let ms: UInt64 = 1_000_000
        var cache = RetransmitFrameCache()
        let small = Data(repeating: 7, count: 1000)
        for id in 1...33 { cache.insert(frameID: UInt64(id), data: small, keyFrame: false, packetCount: 1, now: UInt64(id) * ms) }
        expect(cache.entries.count == 32 && cache.lookup(frameID: 1, now: 34 * ms) == nil && cache.lookup(frameID: 2, now: 34 * ms) != nil,
               "cache: keeps 32 frames, evicts oldest")
        expect(cache.lookup(frameID: 33, now: 33 * ms + 250 * ms) != nil && cache.lookup(frameID: 33, now: 33 * ms + 251 * ms) == nil,
               "cache: frame older than 250 ms is not served")
        var big = RetransmitFrameCache()
        let mib = Data(repeating: 1, count: 1024 * 1024)
        for id in 1...5 { big.insert(frameID: UInt64(id), data: mib, keyFrame: true, packetCount: 900, now: ms) }
        expect(big.entries.count == 4 && big.bytes == 4 * 1024 * 1024 && big.lookup(frameID: 1, now: ms) == nil,
               "cache: keeps at most 4 MiB")
        cache.insert(frameID: 1, data: small, keyFrame: true, packetCount: 1, now: 40 * ms)
        expect(cache.entries.count == 1 && cache.resets == 1, "cache: frameID going back (encoder restart) clears it")

        // Budget: 20 Mbps -> 20% of 250 KB per 100 ms = 50,000 bytes, sliding.
        var budget = RetransmitBudget(videoBitrateMbps: 20)
        expect(budget.bytesPerWindow == 50_000, "budget: 20% of bitrate per 100 ms")
        expect(budget.take(30_000, now: 1_000 * ms), "budget: first send allowed")
        expect(budget.take(20_000, now: 1_099 * ms), "budget: up to the limit allowed")
        expect(!budget.take(1, now: 1_099 * ms), "budget: one byte over refused")
        expect(!budget.take(30_000, now: 1_100 * ms - 1), "budget: first send still counted just before 100 ms")
        expect(budget.take(30_000, now: 1_100 * ms), "budget: first send leaves the window at 100 ms")
        // A fixed window would reset at 1_100 ms and allow a full 50 KB burst
        // right after the 20 KB sent at 1_099 ms; the sliding one must not.
        expect(!budget.take(1, now: 1_150 * ms), "budget: no reset burst across a window edge")
        expect(budget.take(20_000, now: 1_199 * ms), "budget: 1_099 ms send gone at 1_199 ms")
        expect(budget.used == 50_000, "budget: used counts only the last 100 ms")
        var backwards = RetransmitBudget(videoBitrateMbps: 20)
        _ = backwards.take(50_000, now: 2_000 * ms)
        expect(backwards.take(50_000, now: 1_000 * ms), "budget: clock going backwards empties the window")
        var many = RetransmitBudget(videoBitrateMbps: 20)
        var allowed = 0
        for i in stride(from: 0, to: 10_000, by: 2) where many.take(1_000, now: UInt64(i) * ms) { allowed += 1 }
        expect(allowed == 5_000 && many.used == 50_000, "budget: steady 1 KB per 2 ms (exactly 20%) always fits")
        expect(!many.take(1_000, now: 9_999 * ms), "budget: one more in that window refused")

        // Control sequence numbers survive the UInt32 wrap.
        expect(MouseMoveUDPServer.isNewer(1, than: 0) && !MouseMoveUDPServer.isNewer(0, than: 0) && !MouseMoveUDPServer.isNewer(0, than: 1),
               "seq: plain order")
        expect(MouseMoveUDPServer.isNewer(0, than: UInt32.max) && MouseMoveUDPServer.isNewer(1, than: 0),
               "seq: UInt32.max -> 0 -> 1 accepted")
        expect(!MouseMoveUDPServer.isNewer(UInt32.max, than: 0) && !MouseMoveUDPServer.isNewer(UInt32.max - 5, than: 1),
               "seq: pre-wrap packet after the wrap is stale")

        // Packet format: a retransmit is the original plus flag 0x04.
        let frame = Data((0..<3000).map { UInt8($0 & 0xff) })
        let original = UDPFrameSender.makePacket(frameID: 9, data: frame, keyFrame: true, packetIndex: 2, packetCount: 3,
                                                 payloadCapacity: 1180, retransmit: false)
        var resent = UDPFrameSender.makePacket(frameID: 9, data: frame, keyFrame: true, packetIndex: 2, packetCount: 3,
                                               payloadCapacity: 1180, retransmit: true)
        expect(original[5] == 0x03 && resent[5] == 0x07, "packet: key+last flags, retransmit adds 0x04")
        resent[5] = original[5]
        expect(resent == original, "packet: retransmit otherwise byte-identical")

        // NACK parsing.
        var nack: [UInt8] = [0x4d, 0x52, 0x4d, 0x31, 1, 0x41, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 1, 2, 2, 0, 3, 0, 2, 0xff, 0xff, 0, 1]
        let parsed = MouseMoveUDPServer.parseNack(nack, length: nack.count)
        expect(parsed?.0 == 0x0102 && parsed?.1 == [R(start: 3, count: 2), R(start: 0xffff, count: 1)], "parse: two ranges")
        expect(MouseMoveUDPServer.parseNack(nack, length: nack.count - 1) == nil, "parse: wrong length rejected")
        nack[18] = 0
        expect(MouseMoveUDPServer.parseNack(nack, length: 19) == nil, "parse: zero ranges rejected")

        // Persisted setting: missing = on.
        expect(PersistedVideoSettings(dictionary: [:]).nack, "settings: nack defaults on")
        expect(!PersistedVideoSettings(dictionary: ["nack": false]).nack, "settings: nack false turns it off")

        // Capture->encode latency histogram (host metrics).
        var hist = LatencyHistogram()
        expect(hist.fields("x") == "x_p50=0.0ms x_p95=0.0ms x_max=0.0ms", "latency: empty histogram is zero")
        for i in 1...100 { hist.add(Double(i)) }   // 1..100 ms
        expect(abs(hist.percentile(0.50) - 50) <= 0.15, "latency: p50 of 1..100 ms")
        expect(abs(hist.percentile(0.95) - 95) <= 0.15, "latency: p95 of 1..100 ms")
        expect(hist.maxMS == 100 && hist.samples == 100, "latency: max and count")
        hist.add(5_000); hist.add(-3); hist.add(.nan)
        expect(hist.maxMS == 5_000 && hist.percentile(1.0) == 5_000, "latency: overflow bucket reports max")
        expect(hist.percentile(0.0001) == 0.1, "latency: negative and NaN count as 0")
        hist.reset()
        expect(hist.samples == 0 && hist.maxMS == 0, "latency: reset")
        expect(CaptureClock.elapsedMS(since: 1_000_000, now: 13_500_000) == 12.5, "latency: capture elapsed ms")
        expect(CaptureClock.elapsedMS(since: 0, now: 5) == 0 && CaptureClock.elapsedMS(since: 9, now: 5) == 0, "latency: unknown or future capture is 0")

        loopback(expect)
        return failures == 0 ? 0 : 1
    }

    /// Real sockets on 127.0.0.1: frame -> NACK -> retransmit, and ping -> pong.
    private static func loopback(_ check: (Bool, String) -> Void) {

        guard let viewer = TestUDPSocket(), let mousePort = TestUDPSocket.freePort() else {
            check(false, "loopback: sockets")
            return
        }
        defer { viewer.close() }

        for paced in [false, true] {
            let mode = paced ? "paced" : "unpaced"
            guard let sender = try? UDPFrameSender(bindIP: "127.0.0.1", clientIP: "127.0.0.1", clientPort: viewer.port,
                                                   packetBytes: 1200, pacing: paced ? UDPPacing(mbps: 100, burstBytes: 32 * 1024) : .off,
                                                   retransmit: true, videoBitrateMbps: 20) else {
                check(false, "loopback \(mode): sender")
                continue
            }
            let frame = Data((0..<(1180 * 5)).map { UInt8(($0 * 7) & 0xff) })
            sender.send(frameID: 42, data: frame, keyFrame: false)
            let first = viewer.receiveAll(expect: 5)
            check(first.count == 5, "loopback \(mode): frame arrives as 5 packets")
            let result = sender.retransmit(frameID: 42, ranges: [.init(start: 1, count: 2)])
            let again = viewer.receiveAll(expect: 2)
            let indices = again.map { Int($0[14]) << 8 | Int($0[15]) }
            check(result == .sent(packets: 2) && indices == [1, 2] && again.allSatisfy { $0[5] & 0x04 != 0 },
                  "loopback \(mode): NACK resends packets 1 and 2 with flag 0x04")
            if first.count == 5, again.count == 2 {
                var copy = again[0]
                copy[5] &= ~0x04
                check(copy == first[1], "loopback \(mode): resent packet matches original")
            }
            check(sender.retransmit(frameID: 7, ranges: [.wholeFrame]) == .miss, "loopback \(mode): unknown frame is a miss")
            sender.clearRetransmitCache()
            check(sender.retransmit(frameID: 42, ranges: [.wholeFrame]) == .miss, "loopback \(mode): cleared cache is a miss")
            check(sender.statsLine().contains("nack_rx=3 nack_packets_resent=2"), "loopback \(mode): stats count NACKs")
        }

        // MouseMoveUDPServer: 0x41 reaches the handler, 0x43 is echoed as 0x44.
        let server = MouseMoveUDPServer(bindIP: "127.0.0.1", allowedClientIP: "127.0.0.1", port: mousePort)
        guard (try? server.start()) != nil else {
            check(false, "loopback: mouse UDP server starts")
            return
        }
        defer { server.stop() }
        let got = NackBox()
        server.setNackHandler { id, ranges in got.set(id, ranges) }
        let nack: [UInt8] = [0x4d, 0x52, 0x4d, 0x31, 1, 0x41, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 42, 1, 0, 1, 0, 2]
        viewer.send(nack, toPort: mousePort)
        let ping: [UInt8] = [0x4d, 0x52, 0x4d, 0x31, 1, 0x43, 0, 0, 0, 2, 1, 2, 3, 4, 5, 6, 7, 8]
        viewer.send(ping, toPort: mousePort)
        let pong = viewer.receiveAll(expect: 1)
        var want = ping
        want[5] = 0x44
        check(pong.count == 1 && pong.first.map { [UInt8]($0) } == want, "loopback: ping 0x43 echoed as pong 0x44")
        let deadline = Date().addingTimeInterval(2)
        while Date() < deadline, got.get() == nil { usleep(5_000) }
        check(got.get()?.0 == 42 && got.get()?.1 == [.init(start: 1, count: 2)], "loopback: NACK reaches the handler")
    }
}

private final class NackBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: (UInt64, [UDPFrameSender.NackRange])?
    func set(_ id: UInt64, _ r: [UDPFrameSender.NackRange]) { lock.lock(); value = (id, r); lock.unlock() }
    func get() -> (UInt64, [UDPFrameSender.NackRange])? { lock.lock(); defer { lock.unlock() }; return value }
}

/// A viewer-side UDP socket on 127.0.0.1 with a 200 ms receive timeout.
private final class TestUDPSocket {
    let fd: Int32
    let port: UInt16

    init?() {
        let s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard s >= 0 else { return nil }
        var addr = Self.loopbackAddress(port: 0)
        let rc = withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        var bound = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let named = withUnsafeMutablePointer(to: &bound) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(s, $0, &len) }
        }
        guard rc == 0, named == 0 else { Darwin.close(s); return nil }
        var tv = timeval(tv_sec: 0, tv_usec: 200_000)
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        fd = s
        port = UInt16(bigEndian: bound.sin_port)
    }

    static func freePort() -> UInt16? {
        guard let probe = TestUDPSocket() else { return nil }
        defer { probe.close() }
        return probe.port
    }

    func send(_ bytes: [UInt8], toPort port: UInt16) {
        var addr = Self.loopbackAddress(port: port)
        _ = bytes.withUnsafeBytes { raw in
            withUnsafePointer(to: &addr) { p in
                p.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    sendto(fd, raw.baseAddress, bytes.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
    }

    /// Reads until `expect` datagrams arrived or a 200 ms read times out.
    func receiveAll(expect: Int) -> [Data] {
        var out: [Data] = []
        var buffer = [UInt8](repeating: 0, count: 2048)
        while out.count < expect {
            let n = recv(fd, &buffer, buffer.count, 0)
            if n <= 0 { break }
            out.append(Data(buffer[0..<n]))
        }
        return out
    }

    func close() { Darwin.close(fd) }

    static func loopbackAddress(port: UInt16) -> sockaddr_in {
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        return addr
    }
}
