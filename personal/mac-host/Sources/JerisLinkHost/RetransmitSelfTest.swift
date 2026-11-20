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
        r9StreamBlock(expect)
        r10ResendBlock(expect)
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
            // Review P3: a capture restart numbers frames from 1 again. The
            // send-cadence slope starts over instead of ignoring ids 1..13 as
            // "old" (frame 100 -> 1 left the first 12 frames without samples).
            let T = 1000.0 / 60
            for f in 1...100 { sender.noteFrameCadence(UInt64(1000 + f), nowMs: Double(f) * T) }
            _ = sender.abrWindow()
            sender.captureRestarted()
            for f in 1...13 { sender.noteFrameCadence(UInt64(f), nowMs: 5000 + Double(f) * T) }
            let w = sender.abrWindow().sendSlope
            check(w.valid && w.samples == 12 && abs(w.slopeMs) < 1e-6
                  && sender.retransmit(frameID: 42, ranges: [.wholeFrame]) == .miss,
                  "loopback \(mode): capture restart resets the send cadence and the cache")
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

extension RetransmitSelfTest {
    /// r9: nothing goes to a blocked viewer over UDP either: video frames,
    /// NACK resends, audio, pongs. Real sockets on 127.0.0.1; the gates
    /// the video service wires (PendingJournalHold on a listen.plist and a
    /// journal in a temp folder), a block added from each.
    fileprivate static func r9StreamBlock(_ check: (Bool, String) -> Void) {
        let fm = FileManager.default
        let dir = fm.temporaryDirectory.appendingPathComponent("jl-r9-udp-\(getpid())", isDirectory: true)
        try? fm.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: dir) }
        let plistURL = dir.appendingPathComponent("listen.plist")
        let journalURL = dir.appendingPathComponent("pending-blocks.plist")
        let me = "127.0.0.1"
        func writePlist(_ d: [String: Any]) {
            if let data = try? PropertyListSerialization.data(fromPropertyList: d, format: .xml, options: 0) {
                try? data.write(to: plistURL, options: .atomic)
            }
        }
        let ping: [UInt8] = [0x4d, 0x52, 0x4d, 0x31, 1, 0x43, 0, 0, 0, 2, 1, 2, 3, 4, 5, 6, 7, 8]
        for viaJournal in [true, false] {
            let source = viaJournal ? "the journal" : "listen.plist"
            let name = "r9 udp: a block from \(source) stops video frames, NACK resends, audio and pongs to the viewer from the next frame"
            try? fm.removeItem(at: journalURL)
            writePlist(["mode": "loopback", "clientIP": me])
            guard let viewer = TestUDPSocket(), let mousePort = TestUDPSocket.freePort(),
                  let sender = try? UDPFrameSender(bindIP: me, clientIP: me, clientPort: viewer.port,
                                                   packetBytes: 1200, retransmit: true, videoBitrateMbps: 20) else {
                check(false, name); continue
            }
            defer { viewer.close() }
            let streamHold = PendingJournalHold(url: journalURL, plistURL: plistURL, entry: "udp_stream")
            sender.setStreamGate { streamHold.reason(for: me) == nil }
            let inHold = PendingJournalHold(url: journalURL, plistURL: plistURL)
            let server = MouseMoveUDPServer(bindIP: me, allowedClientIP: me, port: mousePort,
                                            outputAllowed: { inHold.reason(for: me) == nil })
            guard (try? server.start()) != nil else { check(false, name); continue }
            defer { server.stop() }
            let frame = Data((0..<(1180 * 3)).map { UInt8($0 & 0xff) })
            sender.send(frameID: 1, data: frame, keyFrame: true)
            let videoBefore = viewer.receiveAll(expect: 3).count == 3
            viewer.send(ping, toPort: mousePort)
            let pongBefore = viewer.receiveAll(expect: 1).count == 1
            let audioBefore = sender.sendAudio(Data([1, 2, 3, 4]), port: viewer.port) && viewer.receiveAll(expect: 1).count == 1
            if viaJournal {
                _ = PendingBlockFile(url: journalURL).save([BlockedEntry(ip: me, at: Date(), reason: "20 wrong passwords")])
            } else {
                writePlist(["mode": "loopback", "clientIP": me, "blockedIPs": [me]])
            }
            sender.send(frameID: 2, data: frame, keyFrame: true)
            let resend = sender.retransmit(frameID: 1, ranges: [.wholeFrame])
            let audioAfter = sender.sendAudio(Data([1, 2, 3, 4]), port: viewer.port)
            viewer.send(ping, toPort: mousePort)
            let after = viewer.receiveAll(expect: 8)
            check(videoBefore && pongBefore && audioBefore && after.isEmpty && resend == .held && !audioAfter
                  && sender.statsLine().contains("stream_held="), name)
        }
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

extension RetransmitSelfTest {
    /// r10 (blocker 3): a block that lands part-way through resends (or a
    /// paced frame) stops them there. Real UDP sockets on 127.0.0.1, the
    /// video service's gate (PendingJournalHold). The gate lands the block
    /// once the host has written 5 packets of the batch, and notes the
    /// host's packet count at that moment; nothing more may leave after it.
    fileprivate static func r10ResendBlock(_ check: (Bool, String) -> Void) {
        let fm = FileManager.default
        let dir = fm.temporaryDirectory.appendingPathComponent("jl-r10-udp-\(getpid())", isDirectory: true)
        try? fm.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: dir) }
        let plistURL = dir.appendingPathComponent("listen.plist")
        let journalURL = dir.appendingPathComponent("pending-blocks.plist")
        let me = "127.0.0.1"
        func writePlist(_ d: [String: Any]) {
            if let data = try? PropertyListSerialization.data(fromPropertyList: d, format: .xml, options: 0) {
                try? data.write(to: plistURL, options: .atomic)
            }
        }
        enum Kind { case pacedQueue, immediate, pacedFrame }
        let cases: [(Kind, Bool)] = [(.pacedQueue, true), (.pacedQueue, false), (.immediate, true), (.pacedFrame, true)]
        let packets = 20, lead = 10
        for (kind, viaJournal) in cases {
            let source = viaJournal ? "the journal" : "listen.plist"
            let what: String
            switch kind {
            case .pacedQueue: what = "the paced NACK resend queue (20 packets) right after a resend's pacing wait"
            case .immediate: what = "an unpaced NACK resend batch (20 packets)"
            case .pacedFrame: what = "a paced video frame (20 packets)"
            }
            let name = kind == .pacedQueue
                ? "r10 udp: a block from \(source) that lands in \(what), mid-queue, stops it there: that resend and the rest are not sent (host sends 0 packets after the block) and the viewer gets only the resends before it"
                : "r10 udp: a block from \(source) that lands after \(lead) packets of \(what) stops it there: the host sends 0 packets after the block and the viewer gets only those \(lead)"
            try? fm.removeItem(at: journalURL)
            writePlist(["mode": "loopback", "clientIP": me])
            let pacing = kind == .immediate ? UDPPacing.off : UDPPacing(mbps: kind == .pacedQueue ? 1 : 4, burstBytes: kind == .pacedQueue ? 1200 * (packets + lead) : 1200)
            guard let viewer = TestUDPSocket(),
                  let sender = try? UDPFrameSender(bindIP: me, clientIP: me, clientPort: viewer.port, packetBytes: 1200,
                                                   pacing: pacing, retransmit: true, videoBitrateMbps: 20) else {
                check(false, name); continue
            }
            defer { viewer.close() }
            let hold = PendingJournalHold(url: journalURL, plistURL: plistURL, entry: "udp_stream")
            let trip = R10Trip()
            let blockJournal = journalURL, blockPlist = plistURL
            let blockNow: @Sendable () -> Void = {
                if viaJournal {
                    _ = PendingBlockFile(url: blockJournal).save([BlockedEntry(ip: me, at: Date(), reason: "20 wrong passwords")])
                } else if let data = try? PropertyListSerialization.data(
                    fromPropertyList: ["mode": "loopback", "clientIP": me, "blockedIPs": [me]], format: .xml, options: 0) {
                    try? data.write(to: blockPlist, options: .atomic)
                }
            }
            sender.setStreamGate { [weak sender] in
                if let sender, let at = trip.armedAt, !trip.fired, sender.sentPacketCount() >= at {
                    let count = sender.sentPacketCount()
                    blockNow()
                    trip.fire(count)
                }
                return hold.reason(for: me) == nil
            }
            let frame = Data((0..<(1180 * packets)).map { UInt8($0 & 0xff) })
            var result: UDPFrameSender.RetransmitResult?
            var before = true
            var got: [Data] = []
            switch kind {
            case .pacedFrame:
                trip.arm(sender.sentPacketCount() + UInt64(lead))
                sender.send(frameID: 1, data: frame, keyFrame: true)
            case .pacedQueue:
                // The bucket holds the frame plus `lead` packets: the frame
                // leaves in one burst, about `lead` resends follow on what
                // is left, and the next one waits for tokens (1 Mbps, so
                // the gaps here refill little). The block lands right after
                // that first wait, mid-queue, before that resend asks the
                // gate again.
                let base = sender.sentPacketCount()
                sender.setAfterResendPaceWait { [weak sender] in
                    guard let sender, !trip.fired else { return }
                    let count = sender.sentPacketCount()
                    guard count > base + UInt64(packets) else { return }
                    blockNow()
                    trip.fire(count)
                }
                sender.send(frameID: 1, data: frame, keyFrame: true)
                // send() is queued: NACK only once the frame is out.
                let out = Date().addingTimeInterval(1)
                while sender.sentPacketCount() < base + UInt64(packets) && Date() < out { usleep(200) }
                result = sender.retransmit(frameID: 1, ranges: [.wholeFrame])
            case .immediate:
                sender.send(frameID: 1, data: frame, keyFrame: true)
                before = viewer.receiveAll(expect: packets).count == packets
                trip.arm(sender.sentPacketCount() + UInt64(lead))
                result = sender.retransmit(frameID: 1, ranges: [.wholeFrame])
            }
            // Wait for the trip, then long enough for any packet still queued.
            let waitUntil = Date().addingTimeInterval(8)
            while !trip.fired && Date() < waitUntil { Thread.sleep(forTimeInterval: 0.02) }
            Thread.sleep(forTimeInterval: 0.6)
            got = viewer.receiveAll(expect: 2 * packets)
            let hostAfter = trip.firedAt.map { sender.sentPacketCount() - $0 }
            let resent = got.filter { $0.count > 5 && ($0[$0.startIndex + 5] & 0x04) != 0 }.count
            if kind == .pacedQueue {
                // Only the resends count below; the frame must be whole.
                before = got.count - resent == packets
                got = got.filter { $0.count > 5 && ($0[$0.startIndex + 5] & 0x04) != 0 }
            }
            let resultOK: Bool
            switch kind {
            case .pacedQueue: resultOK = result == .sent(packets: packets)
            case .immediate: resultOK = result == .held
            case .pacedFrame: resultOK = true
            }
            print("r10 udp info: case=\(kind) source=\(viaJournal ? "journal" : "listen.plist") fired=\(trip.fired) host_packets_after_block=\(hostAfter.map(String.init) ?? "-") viewer_packets=\(got.count) resent_flag=\(resent) result=\(result.map { "\($0)" } ?? "-") before=\(before) stats=\(sender.statsLine())")
            let flagged = kind == .pacedFrame ? resent == 0 : resent == got.count
            let stats = sender.statsLine()
            let nackWaits = stats.split(separator: " ").first { $0.hasPrefix("nack_pace_waits=") }
                .flatMap { Int($0.dropFirst("nack_pace_waits=".count)) } ?? -1
            // Paced queue: the resends that left before the block, 1..19
            // (a fresh sender: its count starts at 0, the frame is 20).
            let expected = kind == .pacedQueue ? trip.firedAt.map { Int($0) - packets } ?? -1 : lead
            let waited = kind != .pacedQueue || (nackWaits >= 1 && expected >= 1 && expected < packets)
            check(before && resultOK && trip.fired && hostAfter == 0 && got.count == expected && flagged && waited
                  && stats.contains("stream_held="), name)
        }
    }
}

/// r10 self-test: the point at which a gate lands its block.
private final class R10Trip: @unchecked Sendable {
    private let lock = NSLock()
    private var at: UInt64?
    private var firedCount: UInt64?
    func arm(_ count: UInt64) { lock.lock(); at = count; lock.unlock() }
    var armedAt: UInt64? { lock.lock(); defer { lock.unlock() }; return at }
    var fired: Bool { lock.lock(); defer { lock.unlock() }; return firedCount != nil }
    var firedAt: UInt64? { lock.lock(); defer { lock.unlock() }; return firedCount }
    func fire(_ count: UInt64) { lock.lock(); if firedCount == nil { firedCount = count }; lock.unlock() }
}
