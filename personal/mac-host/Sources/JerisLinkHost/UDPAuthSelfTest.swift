import Darwin
import Foundation

/// `JerisLinkHost --self-test` part for the UDP tags and the session link
/// (PR-C): the tagger against ConnAuth.udpTag, every drop case, the bad_tag
/// log throttle, the session link wire and broker, the mouse UDP server and
/// the frame sender end to end on loopback, and the uncounted zero-MAC
/// probe. `--udp-tag-bench` measures what the tags cost at 4K60.
enum UDPAuthSelfTest {
    typealias Expect = (Bool, String) -> Void

    static func run() -> Int32 {
        var failures = 0
        func expect(_ ok: Bool, _ name: String) {
            print("\(ok ? "PASS" : "FAIL") udp-auth: \(name)")
            if !ok { failures += 1 }
        }
        tagger(expect)
        badTagLog(expect)
        sessionState(expect)
        wire(expect)
        broker(expect)
        replayWindow(expect)
        mouseServer(expect)
        frameSender(expect)
        r3MouseServer(expect)
        r3AudioSession(expect)
        probe(expect)
        return failures == 0 ? 0 : 1
    }

    static func key(_ seed: UInt8) -> [UInt8] { (0..<ConnAuth.keyBytes).map { UInt8(truncatingIfNeeded: Int($0) &* 31 &+ Int(seed)) } }

    // MARK: Tagger and drop cases

    private static func tagger(_ expect: Expect) {
        let k = key(1), old = key(2)
        let packet: [UInt8] = Array("MRM1".utf8) + [1, 0x43, 0, 0, 0, 7] + [UInt8](repeating: 0x5a, count: 8)
        for h2v in [false, true] {
            let t = UDPTagger(sessionKey: k, hostToViewer: h2v)
            expect(t.tag(packet) == ConnAuth.udpTag(sessionKey: k, hostToViewer: h2v, packet: packet),
                   "tagger matches ConnAuth.udpTag (\(h2v ? "h2v" : "v2h"))")
        }
        let big = (0..<1200).map { UInt8(truncatingIfNeeded: $0) }
        expect(UDPTagger(sessionKey: k, hostToViewer: true).tag(big) == ConnAuth.udpTag(sessionKey: k, hostToViewer: true, packet: big),
               "tagger matches ConnAuth.udpTag on a 1200-byte datagram")

        let viewer = UDPTagger(sessionKey: k, hostToViewer: false)   // what a viewer sends
        let host = UDPTagger(sessionKey: k, hostToViewer: false)     // what the host checks
        let sealed = viewer.seal(packet)
        func ok(_ t: UDPTagger, _ b: [UInt8]) -> Bool { b.withUnsafeBytes { t.verify($0.baseAddress!, b.count) } }
        expect(sealed.count == packet.count + UDPTag.bytes && sealed[4] == 1 | UDPTag.flag
               && Array(sealed.suffix(8)) == ConnAuth.udpTag(sessionKey: k, hostToViewer: false, packet: Array(sealed.prefix(packet.count))),
               "seal sets the flag on byte 4 and appends the tag of the flagged bytes")
        var viaPointer: [UInt8] = []
        packet.withUnsafeBytes { raw in viewer.withSealed(raw) { viaPointer = Array($0) } }
        expect(viaPointer == sealed, "withSealed (send path) gives the same bytes as seal")
        expect(ok(host, sealed), "a sealed datagram verifies")
        expect(!ok(host, packet), "drop: no tag")
        var flagOnly = packet; flagOnly[4] |= UDPTag.flag
        expect(!ok(host, flagOnly + [UInt8](repeating: 0, count: 8)), "drop: flag with a zero tag")
        var badTag = sealed; badTag[badTag.count - 1] ^= 1
        expect(!ok(host, badTag), "drop: wrong tag")
        var changed = sealed; changed[12] ^= 0x80
        expect(!ok(host, changed), "drop: payload changed")
        var noFlag = sealed; noFlag[4] &= ~UDPTag.flag
        expect(!ok(host, noFlag), "drop: flag cleared (tag covers byte 4)")
        expect(!ok(host, UDPTagger(sessionKey: old, hostToViewer: false).seal(packet)), "drop: an old session's key")
        let reflected = UDPTagger(sessionKey: k, hostToViewer: true).seal(packet)
        expect(!ok(host, reflected), "drop: reflected direction (h2v tag sent back to the host)")
        expect(!ok(host, Array(sealed.prefix(12))), "drop: too short to carry a tag")
        expect(!ok(host, Array(sealed.dropLast())), "drop: truncated by one byte")
    }

    // MARK: bad_tag log throttle

    private final class Box: @unchecked Sendable { var t: TimeInterval = 100; var lines: [String] = [] }

    private static func badTagLog(_ expect: Expect) {
        let b = Box()
        let log = BadTagLog(entry: "mrm1", now: { b.t }, write: { b.lines.append($0) })
        for _ in 0..<500 { log.drop(peer: "100.64.0.9", reason: "bad_tag") }
        expect(b.lines.count == 1 && b.lines[0].contains("n=1 ") && b.lines[0].contains("total=1"),
               "bad_tag: a flood logs one line at once")
        b.t += 9.9
        log.drop(peer: "100.64.0.9", reason: "no_tag")
        expect(b.lines.count == 1, "bad_tag: nothing more within 10 s")
        b.t += 0.2
        log.drop(peer: "100.64.0.10", reason: "no_tag")
        expect(b.lines.count == 2 && b.lines[1] == "udp.bad_tag entry=mrm1 peer=100.64.0.10 reason=no_tag n=501 total=502",
               "bad_tag: the next line after 10 s counts every drop in between")
        expect(log.total == 502, "bad_tag: total counts every drop")
    }

    // MARK: Session state

    private final class Seen: @unchecked Sendable {
        let lock = NSLock(); var list: [UDPPeerSession?] = []
        func add(_ s: UDPPeerSession?) { lock.lock(); list.append(s); lock.unlock() }
        var count: Int { lock.lock(); defer { lock.unlock() }; return list.count }
    }

    private static func sessionState(_ expect: Expect) {
        let pw = UDPSessionState(requireTags: true)
        let seen = Seen()
        pw.onChange { seen.add($0) }
        expect(!pw.set(UDPPeerSession(generation: 1, peerIP: "100.64.0.7", sessionKey: nil)) && pw.snapshot == nil,
               "state: password mode refuses an untagged session")
        let s = UDPPeerSession(generation: 2, peerIP: "100.64.0.7", sessionKey: key(3))
        expect(pw.set(s) && pw.snapshot?.send?.hostToViewer == true && pw.snapshot?.receive?.hostToViewer == false,
               "state: a tagged session gets an h2v sender and a v2h receiver")
        pw.set(s)
        expect(seen.count == 1, "state: the same session again is not a change")
        pw.set(nil)
        expect(pw.snapshot == nil && seen.count == 2, "state: no session")
        expect(!pw.set(UDPPeerSession(generation: 3, peerIP: "not-an-ip", sessionKey: key(3))), "state: a bad peer is refused")
        let open = UDPSessionState(requireTags: false)
        expect(open.set(UDPPeerSession(generation: 1, peerIP: "100.64.0.7", sessionKey: nil)) && open.snapshot?.send == nil,
               "state: transition mode takes an untagged session (no tags)")
    }

    // MARK: Wire

    private static func wire(_ expect: Expect) {
        func roundTrip(_ s: UDPPeerSession?, gen: UInt64) -> SessionLinkWire.Frame? {
            let f = SessionLinkWire.encode(s, generation: gen)
            guard f.count >= 7, Array(f[0..<4]) == SessionLinkWire.magic,
                  Int(f[5]) << 8 | Int(f[6]) == f.count - 7, f.count - 7 <= SessionLinkWire.maxBody else { return nil }
            return SessionLinkWire.decode(type: f[4], body: Array(f[7...]))
        }
        let tagged = UDPPeerSession(generation: 0x0102030405060708, peerIP: "100.100.200.255", sessionKey: key(4))
        expect(roundTrip(tagged, gen: tagged.generation) == .init(generation: tagged.generation, session: tagged), "wire: tagged session round trip (longest IP)")
        let plain = UDPPeerSession(generation: 9, peerIP: "1.2.3.4", sessionKey: nil)
        expect(roundTrip(plain, gen: 9) == .init(generation: 9, session: plain), "wire: untagged session round trip")
        expect(roundTrip(nil, gen: 10) == .init(generation: 10, session: nil), "wire: no session keeps its generation")
        let f = SessionLinkWire.encode(tagged, generation: tagged.generation)
        let body = Array(f[7...])
        expect(SessionLinkWire.decode(type: 1, body: Array(body.dropLast())) == nil, "wire: short key is malformed")
        expect(SessionLinkWire.decode(type: 1, body: body + [0]) == nil, "wire: trailing byte is malformed")
        expect(SessionLinkWire.decode(type: 7, body: body) == nil, "wire: unknown type is malformed")
        var badIP = body; badIP[9] = UInt8(ascii: "x")
        expect(SessionLinkWire.decode(type: 1, body: badIP) == nil, "wire: a non-IPv4 peer is malformed")
        expect(SessionLinkWire.decode(type: 0, body: Array(body.prefix(9))) == nil, "wire: none with a body is malformed")
        // r2 (item 1): stale frames are refused, "none" included.
        let g7 = SessionLinkWire.Frame(generation: 7, session: tagged)
        let none6 = SessionLinkWire.Frame(generation: 6, session: nil)
        expect(SessionLinkClient.accept(g7, after: nil) && SessionLinkClient.accept(g7, after: 7),
               "wire: the first frame and a repeat of the same generation are taken")
        expect(!SessionLinkClient.accept(none6, after: 7), "wire: an older none frame is refused")
        expect(!SessionLinkClient.accept(.init(generation: 6, session: plain), after: 7), "wire: an older session frame is refused")
        expect(SessionLinkClient.accept(.init(generation: 8, session: nil), after: 7), "wire: a newer none frame is taken")
    }

    // MARK: Broker

    private final class Closed: @unchecked Sendable {
        let lock = NSLock(); var tokens: [String] = []
        func add(_ s: String) { lock.lock(); tokens.append(s); lock.unlock() }
        var all: [String] { lock.lock(); defer { lock.unlock() }; return tokens }
    }

    private static func broker(_ expect: Expect) {
        let closed = Closed()
        let b = SessionBroker(passwordMode: true, log: { _ in })
        let a = "100.64.0.1", c = "100.64.0.2"
        let clip = b.begin(peerIP: a, channel: .clipboard, sessionKey: nil, close: { closed.add("a-clip") })
        expect(b.current.0 == nil, "broker: a clipboard login alone is no UDP session")
        let ctlA = b.begin(peerIP: a, channel: .control, sessionKey: key(5), close: { closed.add("a-ctl") })
        let (s1, g1) = b.current
        expect(s1?.peerIP == a && s1?.sessionKey == key(5) && closed.all.isEmpty,
               "broker: control AUTH is the session; same viewer's clipboard stays")
        _ = b.begin(peerIP: a, channel: .control, sessionKey: key(6), close: { closed.add("a-ctl2") })
        let (s2, g2) = b.current
        expect(s2?.sessionKey == key(6) && g2 != g1 && closed.all == ["a-ctl"] && b.replaced == 1,
               "broker: a new AUTH from the same viewer replaces the old key and closes the old control")
        b.end(ctlA)
        expect(b.current.1 == g2, "broker: ending the replaced connection changes nothing")
        let ctlC = b.begin(peerIP: c, channel: .control, sessionKey: key(7), close: { closed.add("c-ctl") })
        expect(b.current.0?.peerIP == c && Set(closed.all) == ["a-ctl", "a-clip", "a-ctl2"],
               "broker: another viewer's AUTH takes over and closes every connection of the old one")
        b.end(clip)
        b.end(ctlC)
        expect(b.current.0 == nil && b.activePeerIP == nil, "broker: the session ends with its control connection")

        let t = SessionBroker(passwordMode: false, log: { _ in })
        let x = t.begin(peerIP: a, channel: nil, sessionKey: nil, close: { closed.add("x") })
        let gx = t.current.1
        let y = t.begin(peerIP: a, channel: nil, sessionKey: nil, close: { closed.add("y") })
        expect(t.current.0?.peerIP == a && t.current.0?.tagged == false && t.current.1 == gx,
               "broker (transition): another connection of the same viewer is the same session")
        let z = t.begin(peerIP: c, channel: nil, sessionKey: nil, close: { closed.add("z") })
        expect(t.current.0?.peerIP == c && !closed.all.contains("x"), "broker (transition): newest viewer, nothing closed")
        t.end(z)
        expect(t.current.0?.peerIP == a, "broker (transition): back to the viewer still connected")
        t.end(x); t.end(y)
        expect(t.current.0 == nil, "broker (transition): no connection, no session")

        // r2 (item 1): concurrent begin/end from many threads: the listeners
        // see every generation once, strictly in order.
        final class Gens: @unchecked Sendable {
            let lock = NSLock(); var list: [UInt64] = []
            func add(_ g: UInt64) { lock.lock(); list.append(g); lock.unlock() }
            var all: [UInt64] { lock.lock(); defer { lock.unlock() }; return list }
        }
        let gens = Gens()
        let o = SessionBroker(passwordMode: true, log: { _ in })
        o.onChange { _, g in gens.add(g); usleep(50) }
        DispatchQueue.concurrentPerform(iterations: 8) { i in
            for n in 0..<50 {
                let t = o.begin(peerIP: "100.64.0.\(i + 1)", channel: .control, sessionKey: key(UInt8(n % 200)), close: {})
                o.end(t)
            }
        }
        let seen = gens.all
        expect(!seen.isEmpty && zip(seen, seen.dropFirst()).allSatisfy { $0 < $1 } && seen.last == o.current.1,
               "broker: concurrent changes reach the listeners in generation order (\(seen.count) changes)")
    }

    // MARK: Loopback UDP helpers

    static func udpSocket(bind port: UInt16 = 0) -> (fd: Int32, port: UInt16)? {
        let s = Darwin.socket(AF_INET, SOCK_DGRAM, 0)
        guard s >= 0 else { return nil }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        var tv = timeval(tv_sec: 0, tv_usec: 300_000)
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        let rc = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard rc == 0 else { Darwin.close(s); return nil }
        var got = sockaddr_in(); var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &got) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(s, $0, &len) } }
        return (s, UInt16(bigEndian: got.sin_port))
    }

    static func sendUDP(_ fd: Int32, _ bytes: [UInt8], to port: UInt16) {
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        _ = bytes.withUnsafeBytes { raw in
            withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.sendto(fd, raw.baseAddress, raw.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        }
    }

    static func receiveUDP(_ fd: Int32) -> [UInt8]? {
        var buf = [UInt8](repeating: 0, count: 2048)
        let n = buf.withUnsafeMutableBytes { Darwin.recv(fd, $0.baseAddress, $0.count, 0) }
        return n > 0 ? Array(buf.prefix(n)) : nil
    }

    private static func freeUDPPort() -> UInt16? {
        guard let s = udpSocket() else { return nil }
        Darwin.close(s.fd)
        return s.port
    }

    // MARK: Mouse UDP server on loopback

    // r2 (Pepper's PR-C review, item 7): the 64-packet anti-replay window.
    private static func replayWindow(_ expect: Expect) {
        var w = SeqReplayWindow()
        expect(w.check(100) == .newest, "window: first seq taken")
        expect(w.check(100) == .duplicate, "window: same seq again is a duplicate")
        expect(w.check(105) == .newest && w.check(101) == .late, "window: a reordered unseen seq is late (taken)")
        w.mark(101)
        expect(w.check(101) == .duplicate, "window: a late seq once marked is a duplicate")
        expect(w.check(105 - 63) == .late && w.check(105 - 64) == .tooOld, "window: 63 behind is inside, 64 behind is too old")
        expect(w.check(105 + 64) == .newest && w.check(106) == .late && w.check(105) == .tooOld,
               "window: a jump of 64 leaves only the new newest seen")
        expect(w.check(105 + 74) == .newest && w.check(105 + 64) == .duplicate && w.check(105 + 65) == .late,
               "window: a jump of 10 keeps what was seen, shifted")
        var wrap = SeqReplayWindow()
        _ = wrap.check(UInt32.max - 1)
        expect(wrap.check(2) == .newest && wrap.check(UInt32.max) == .late && wrap.check(UInt32.max - 1) == .duplicate,
               "window: order and bitmap survive the UInt32 wrap")
        var dense = SeqReplayWindow()
        var seen = 0
        for seq in (1...200).reversed().map(UInt32.init) {
            switch dense.check(seq) {
            case .newest: seen += 1
            case .late: dense.mark(seq); seen += 1
            default: break
            }
        }
        expect(seen == 64, "window: 200 datagrams in reverse order: the newest and the 63 behind it taken, \(seen)")
    }

    private static func mouseServer(_ expect: Expect) {
        let k = key(8)
        func ping(_ seq: UInt32) -> [UInt8] {
            Array("MRM1".utf8) + [1, 0x43, UInt8(seq >> 24), UInt8(seq >> 16 & 0xff), UInt8(seq >> 8 & 0xff), UInt8(seq & 0xff)]
                + [UInt8](repeating: 0x11, count: 8)
        }
        guard let port = freeUDPPort(), let viewer = udpSocket() else { expect(false, "mouse: sockets"); return }
        defer { Darwin.close(viewer.fd) }
        let state = UDPSessionState(requireTags: true)
        let server = MouseMoveUDPServer(bindIP: "127.0.0.1", allowedClientIP: nil, port: port,
                                        relayPort: 1, inputAllowed: { false }, udpSession: state)
        guard (try? server.start()) != nil else { expect(false, "mouse: server starts"); return }
        defer { server.stop() }
        let v2h = UDPTagger(sessionKey: k, hostToViewer: false)
        let h2v = UDPTagger(sessionKey: k, hostToViewer: true)

        sendUDP(viewer.fd, v2h.seal(ping(1)), to: port)
        expect(receiveUDP(viewer.fd) == nil, "mouse: no session, a tagged ping gets nothing")
        state.set(UDPPeerSession(generation: 1, peerIP: "127.0.0.1", sessionKey: k))
        sendUDP(viewer.fd, ping(2), to: port)
        expect(receiveUDP(viewer.fd) == nil, "mouse: untagged ping in password mode gets nothing")
        var bad = v2h.seal(ping(3)); bad[bad.count - 2] ^= 4
        sendUDP(viewer.fd, bad, to: port)
        expect(receiveUDP(viewer.fd) == nil, "mouse: wrong tag gets nothing")
        sendUDP(viewer.fd, UDPTagger(sessionKey: key(9), hostToViewer: false).seal(ping(4)), to: port)
        expect(receiveUDP(viewer.fd) == nil, "mouse: an old session's tag gets nothing")
        sendUDP(viewer.fd, h2v.seal(ping(5)), to: port)
        expect(receiveUDP(viewer.fd) == nil, "mouse: a reflected (h2v) datagram gets nothing")

        let good = v2h.seal(ping(6))
        sendUDP(viewer.fd, good, to: port)
        let pong = receiveUDP(viewer.fd)
        let pongOK = pong.map { p in p.withUnsafeBytes { h2v.verify($0.baseAddress!, p.count) } } ?? false
        expect(pongOK && pong?[5] == 0x44 && pong.map { Array($0[6..<18]) } == Array(ping(6)[6..<18]),
               "mouse: a good tagged ping gets a pong sealed h2v")
        let pongReflectsAsV2H = pong.map { p in p.withUnsafeBytes { v2h.verify($0.baseAddress!, p.count) } } ?? true
        expect(!pongReflectsAsV2H, "mouse: the pong does not verify as v2h (cannot be reflected)")
        sendUDP(viewer.fd, good, to: port)
        expect(receiveUDP(viewer.fd) == nil, "mouse: a replayed datagram gets nothing (sequence)")
        let stats = server.statsLine()
        expect(stats.contains("mouse_udp_bad_tag=4") && stats.contains("mouse_udp_no_session=1"),
               "mouse: drops counted (\(stats.split(separator: " ").filter { $0.contains("bad_tag") || $0.contains("no_session") }.joined(separator: " ")))")

        // r2 item 7: a late datagram never seen is answered; seen again, or
        // behind the 64-packet window, it is not.
        sendUDP(viewer.fd, v2h.seal(ping(12)), to: port)
        expect(receiveUDP(viewer.fd)?[5] == 0x44, "mouse window: newest seq 12 answered")
        sendUDP(viewer.fd, v2h.seal(ping(9)), to: port)
        expect(receiveUDP(viewer.fd)?[5] == 0x44, "mouse window: late unseen seq 9 answered (not dropped as stale)")
        sendUDP(viewer.fd, v2h.seal(ping(9)), to: port)
        expect(receiveUDP(viewer.fd) == nil, "mouse window: seq 9 again gets nothing (replay)")
        sendUDP(viewer.fd, v2h.seal(ping(90)), to: port)
        _ = receiveUDP(viewer.fd)
        sendUDP(viewer.fd, v2h.seal(ping(11)), to: port)
        expect(receiveUDP(viewer.fd) == nil, "mouse window: seq 11, 79 behind the newest, gets nothing")
        let wstats = server.statsLine()
        expect(wstats.contains("mouse_udp_late_ok=1") && wstats.contains("mouse_udp_replay=2"),
               "mouse window: counted (\(wstats.split(separator: " ").filter { $0.contains("late_ok") || $0.contains("replay") || $0.contains("stale") }.joined(separator: " ")))")

        state.set(UDPPeerSession(generation: 2, peerIP: "127.0.0.1", sessionKey: key(10)))
        sendUDP(viewer.fd, v2h.seal(ping(7)), to: port)
        expect(receiveUDP(viewer.fd) == nil, "mouse: after a new AUTH the old key gets nothing")

        guard let port2 = freeUDPPort() else { return }
        let open = UDPSessionState(requireTags: false)
        let legacy = MouseMoveUDPServer(bindIP: "127.0.0.1", allowedClientIP: nil, port: port2,
                                        relayPort: 1, inputAllowed: { false }, udpSession: open)
        guard (try? legacy.start()) != nil else { expect(false, "mouse: transition server starts"); return }
        defer { legacy.stop() }
        open.set(UDPPeerSession(generation: 1, peerIP: "127.0.0.1", sessionKey: nil))
        sendUDP(viewer.fd, ping(1), to: port2)
        let p = receiveUDP(viewer.fd)
        expect(p?.count == 18 && p?[4] == 1 && p?[5] == 0x44, "mouse (transition): an untagged 0.3 ping gets an untagged pong")
        open.set(UDPPeerSession(generation: 2, peerIP: "127.0.0.2", sessionKey: nil))
        sendUDP(viewer.fd, ping(2), to: port2)
        expect(receiveUDP(viewer.fd) == nil, "mouse (transition): only the session peer is answered")
    }

    // MARK: Frame sender on loopback

    private static func frameSender(_ expect: Expect) {
        guard let rx = udpSocket() else { expect(false, "sender: socket"); return }
        defer { Darwin.close(rx.fd) }
        guard let sender = try? UDPFrameSender(bindIP: "127.0.0.1", clientIP: "0.0.0.0", clientPort: rx.port, packetBytes: 1200) else {
            expect(false, "sender: starts"); return
        }
        let state = UDPSessionState(requireTags: true)
        sender.setSession(state)
        let frame = Data((0..<3000).map { UInt8(truncatingIfNeeded: $0) })
        sender.send(frameID: 1, data: frame, keyFrame: true)
        expect(receiveUDP(rx.fd) == nil && sender.statsLine().contains("session_drops=3"),
               "sender: no session, no video leaves (drops counted)")
        let k = key(11)
        state.set(UDPPeerSession(generation: 1, peerIP: "127.0.0.1", sessionKey: k))
        sender.send(frameID: 2, data: frame, keyFrame: true)
        let h2v = UDPTagger(sessionKey: k, hostToViewer: true)
        var got: [[UInt8]] = []
        while let p = receiveUDP(rx.fd) { got.append(p) }
        expect(got.count == 3 && got.allSatisfy { p in p[4] & UDPTag.flag != 0 && p.withUnsafeBytes { h2v.verify($0.baseAddress!, p.count) } }
               && got.allSatisfy { $0.count <= 1200 + UDPTag.bytes },
               "sender: tagged session, every MR02 packet sealed h2v (\(got.count) packets)")
        let audio = Data(Array("MRA1".utf8) + [1, 0, 0, 1] + [UInt8](repeating: 7, count: 40))
        _ = sender.sendAudio(audio, port: rx.port, generation: 1)
        let a = receiveUDP(rx.fd)
        expect(a.map { p in p.count == audio.count + 8 && p.withUnsafeBytes { h2v.verify($0.baseAddress!, p.count) } } ?? false,
               "sender: MRA1 audio sealed h2v")
        state.set(nil)
        _ = sender.sendAudio(audio, port: rx.port, generation: 1)
        expect(receiveUDP(rx.fd) == nil, "sender: session gone, no audio leaves")
    }

    // MARK: r3 (Pepper's PR-C r2 review, items 2, 3 and 5)

    /// Item 3: a replayed, malformed or too-old datagram moves nothing: not
    /// the reply port, not presence. Item 2: a read-only viewer (pings and
    /// 0x45 only, no 0x24) is enough for presence and an audio request.
    /// Item 5: the request carries the session it came in.
    private static func r3MouseServer(_ expect: Expect) {
        let k = key(20)
        func dgram(_ type: UInt8, _ seq: UInt32, _ body: [UInt8]) -> [UInt8] {
            Array("MRM1".utf8) + [1, type, UInt8(seq >> 24), UInt8(seq >> 16 & 0xff), UInt8(seq >> 8 & 0xff), UInt8(seq & 0xff)] + body
        }
        func ping(_ seq: UInt32) -> [UInt8] { dgram(0x43, seq, [UInt8](repeating: 0x22, count: 8)) }
        func audioReq(_ seq: UInt32, port: UInt16) -> [UInt8] { dgram(0x45, seq, [0x03, UInt8(port >> 8), UInt8(port & 0xff)]) }
        guard let port = freeUDPPort(), let a = udpSocket(), let b = udpSocket() else { expect(false, "r3 mouse: sockets"); return }
        defer { Darwin.close(a.fd); Darwin.close(b.fd) }
        let state = UDPSessionState(requireTags: true)
        let presence = ViewerPresence()
        let server = MouseMoveUDPServer(bindIP: "127.0.0.1", allowedClientIP: nil, port: port, presence: presence,
                                        relayPort: 1, inputAllowed: { false }, udpSession: state)
        let requests = LockedBox<[(Bool, UInt16, UInt64?)]>([])
        server.setAudioRequestHandler { enable, p, _, gen in requests.mutate { $0.append((enable, p, gen)) } }
        guard (try? server.start()) != nil else { expect(false, "r3 mouse: server starts"); return }
        defer { server.stop() }
        state.set(UDPPeerSession(generation: 1, peerIP: "127.0.0.1", sessionKey: k))
        let v2h = UDPTagger(sessionKey: k, hostToViewer: false)

        // Read-only viewer: a ping and an audio request, never a move.
        let first = v2h.seal(ping(1))
        sendUDP(a.fd, first, to: port)
        let pong = receiveUDP(a.fd)
        sendUDP(a.fd, v2h.seal(audioReq(2, port: 40001)), to: port)
        Thread.sleep(forTimeInterval: 0.2)
        let r1 = requests.value
        expect(pong?[5] == 0x44 && presence.isActive() && presence.datagramsHeard == 2 && server.replyPortForTest == a.port
               && r1.count == 1 && r1[0].0 && r1[0].1 == 40001 && r1[0].2 == 1 && server.forwarded == 0,
               "r3 read-only: ping + 0x45 alone make presence active and an audio request for gen 1, no move sent")

        // Item 3: replay of seen datagrams from another port.
        sendUDP(b.fd, first, to: port)
        sendUDP(b.fd, v2h.seal(audioReq(2, port: 40002)), to: port)
        Thread.sleep(forTimeInterval: 0.2)
        expect(receiveUDP(b.fd) == nil && server.replyPortForTest == a.port && presence.datagramsHeard == 2 && requests.value.count == 1,
               "r3 replay: seen seqs from another port change neither the reply port nor presence, no audio request")
        // A malformed one (valid tag, wrong length) from that port.
        sendUDP(b.fd, v2h.seal(dgram(0x43, 30, [1, 2])), to: port)
        sendUDP(b.fd, v2h.seal(dgram(0x45, 31, [0x01, 0, 0])), to: port)
        Thread.sleep(forTimeInterval: 0.2)
        expect(receiveUDP(b.fd) == nil && server.replyPortForTest == a.port && presence.datagramsHeard == 2,
               "r3 format: malformed 0x43 / 0x45 change neither the reply port nor presence")
        // Malformed seq 30/31 did not move the window: seq 3 still counts.
        sendUDP(b.fd, v2h.seal(ping(3)), to: port)
        let moved = receiveUDP(b.fd)
        expect(moved?[5] == 0x44 && server.replyPortForTest == b.port && presence.datagramsHeard == 3,
               "r3 port move: a fresh seq from the new port moves the reply port (NAT rebinding)")
        // Too old behind the window from the old port: nothing moves back.
        sendUDP(a.fd, v2h.seal(ping(200)), to: port)
        _ = receiveUDP(a.fd)
        sendUDP(b.fd, v2h.seal(ping(100)), to: port)
        Thread.sleep(forTimeInterval: 0.2)
        expect(receiveUDP(b.fd) == nil && server.replyPortForTest == a.port && presence.datagramsHeard == 4,
               "r3 too old: seq 100 behind 200 from the other port gets nothing and moves nothing")

        // Item 5: a new session; its requests carry gen 2.
        let k2 = key(21)
        state.set(UDPPeerSession(generation: 2, peerIP: "127.0.0.1", sessionKey: k2))
        sendUDP(b.fd, UDPTagger(sessionKey: k2, hostToViewer: false).seal(audioReq(1, port: 40003)), to: port)
        Thread.sleep(forTimeInterval: 0.2)
        let last = requests.value.last
        expect(requests.value.count == 2 && last?.1 == 40003 && last?.2 == 2 && server.replyPortForTest == b.port,
               "r3 session: the new viewer's request carries gen 2")
    }

    /// Item 5: audio goes out only while the session its request came in is
    /// the current one.
    private static func r3AudioSession(_ expect: Expect) {
        guard let rx = udpSocket() else { expect(false, "r3 audio: socket"); return }
        defer { Darwin.close(rx.fd) }
        guard let sender = try? UDPFrameSender(bindIP: "127.0.0.1", clientIP: "0.0.0.0", clientPort: rx.port, packetBytes: 1200) else {
            expect(false, "r3 audio: sender starts"); return
        }
        let state = UDPSessionState(requireTags: true)
        sender.setSession(state)
        let k1 = key(22), k2 = key(23)
        let audio = Data(Array("MRA1".utf8) + [1, 0, 0, 1] + [UInt8](repeating: 9, count: 40))
        state.set(UDPPeerSession(generation: 1, peerIP: "127.0.0.1", sessionKey: k1))
        let ok1 = sender.sendAudio(audio, port: rx.port, generation: 1)
        let p1 = receiveUDP(rx.fd)
        let h2v1 = UDPTagger(sessionKey: k1, hostToViewer: true)
        expect(ok1 && (p1.map { p in p.withUnsafeBytes { h2v1.verify($0.baseAddress!, p.count) } } ?? false),
               "r3 audio: gen 1 request, gen 1 session: audio leaves sealed with its key")
        state.set(UDPPeerSession(generation: 2, peerIP: "127.0.0.1", sessionKey: k2))
        let stale = sender.sendAudio(audio, port: rx.port, generation: 1)
        let none = sender.sendAudio(audio, port: rx.port)
        expect(!stale && !none && receiveUDP(rx.fd) == nil && sender.statsLine().contains("audio_stale_drops=2"),
               "r3 audio: after a new viewer, the old request's audio is dropped (not sent with the new IP/key to the old port)")
        let ok2 = sender.sendAudio(audio, port: rx.port, generation: 2)
        let p2 = receiveUDP(rx.fd)
        let h2v2 = UDPTagger(sessionKey: k2, hostToViewer: true)
        expect(ok2 && (p2.map { p in p.withUnsafeBytes { h2v2.verify($0.baseAddress!, p.count) } } ?? false),
               "r3 audio: the new viewer's own request (gen 2) gets audio")
    }

    // MARK: Zero-MAC probe

    private static func probe(_ expect: Expect) {
        let me = ListenConfig.loopbackIP
        guard let secret = ConnSecret.make(password: "Probe-\(UUID().uuidString.prefix(8))!", iterations: 1000),
              let port = ControlServiceSelfTest.freeLoopbackPort() else { expect(false, "probe: setup"); return }
        let guardian = AuthGuard(whitelist: [me], blocklist: MemoryBlocklist())
        let gate = AuthGate(policy: .password(whitelist: [me]), guardian: guardian, secret: secret, timeout: 2)
        let s = ControlServer(bindIP: me, allowedClientIP: nil, port: port, inject: false,
                              settingsClientIP: { me }, acceptProxy: false, inputHelper: nil,
                              clipboard: FakeClipboard(text: nil), authGate: gate)
        guard (try? s.start()) != nil else { expect(false, "probe: listener starts"); return }
        defer { s.stop() }
        func answer(mac: [UInt8]) -> ConnAuth.Result? {
            guard let c = MRC1Client(port: port), let ch = c.receive(timeout: 2), ch.type == ConnAuth.MsgType.challenge else { return nil }
            _ = c.send(type: ConnAuth.MsgType.response,
                       payload: ConnAuth.Response(clientNonce: ConnAuth.random(ConnAuth.nonceBytes), mac: mac).payload)
            guard let r = c.receive(timeout: 3), r.type == ConnAuth.MsgType.result else { return nil }
            return ConnAuth.Result.decode(r.payload)
        }
        let zero = [UInt8](repeating: 0, count: 32)
        let results = (0..<6).map { _ in answer(mac: zero) }
        expect(results.allSatisfy { $0 == .fail(triesLeft: 5) } && s.probesUncounted == 6,
               "probe: six zero-MAC probes all answered FAIL with 5 tries left (not counted)")
        let wrong = answer(mac: (0..<32).map { UInt8($0 + 1) })
        expect(wrong == .fail(triesLeft: 4), "probe: a wrong MAC after them is the first counted failure")
    }

    // MARK: Benchmark (--udp-tag-bench)

    /// What the tags cost on this Mac: HMAC per 1200-byte MR02 packet, and
    /// sendto to loopback with and without sealing, at the packet rate of
    /// a 4K60 stream at `mbps`.
    static func bench(mbps: [Int]) -> Int32 {
        let k = key(12)
        let t = UDPTagger(sessionKey: k, hostToViewer: true)
        let packet = [UInt8]((0..<1200).map { UInt8(truncatingIfNeeded: $0 &* 7) })
        var out = [UInt8](repeating: 0, count: 8)
        let n = 400_000
        func time(_ body: () -> Void) -> Double {
            let s = DispatchTime.now().uptimeNanoseconds
            body()
            return Double(DispatchTime.now().uptimeNanoseconds - s)
        }
        var sink: UInt8 = 0
        _ = time { for _ in 0..<20_000 { packet.withUnsafeBytes { raw in out.withUnsafeMutableBytes { t.tag(raw.baseAddress!, raw.count, into: $0.baseAddress!) } }; sink ^= out[0] } }
        let tagNs = time { for _ in 0..<n { packet.withUnsafeBytes { raw in out.withUnsafeMutableBytes { t.tag(raw.baseAddress!, raw.count, into: $0.baseAddress!) } }; sink ^= out[0] } } / Double(n)
        let verifyRx = UDPTagger(sessionKey: k, hostToViewer: true)
        let sealed = t.seal(packet)
        var okCount = 0
        let verifyNs = time { for _ in 0..<n { if sealed.withUnsafeBytes({ verifyRx.verify($0.baseAddress!, sealed.count) }) { okCount += 1 } } } / Double(n)

        guard let rx = udpSocket(), let tx = udpSocket() else { return 1 }
        var big: Int32 = 8 << 20
        setsockopt(rx.fd, SOL_SOCKET, SO_RCVBUF, &big, socklen_t(MemoryLayout<Int32>.size))
        var dest = sockaddr_in()
        dest.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        dest.sin_family = sa_family_t(AF_INET)
        dest.sin_port = rx.port.bigEndian
        dest.sin_addr.s_addr = inet_addr("127.0.0.1")
        let drain = Thread { var b = [UInt8](repeating: 0, count: 2048); while true { if b.withUnsafeMutableBytes({ Darwin.recv(rx.fd, $0.baseAddress, $0.count, 0) }) < 0 && errno != EAGAIN { break } } }
        drain.start()
        let m = 200_000
        func sendLoop(sealing: Bool) -> Double {
            time {
                packet.withUnsafeBytes { raw in
                    withUnsafePointer(to: &dest) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                        let len = socklen_t(MemoryLayout<sockaddr_in>.size)
                        for _ in 0..<m {
                            if sealing { t.withSealed(raw) { s in _ = Darwin.sendto(tx.fd, s.baseAddress, s.count, 0, sa, len) } }
                            else { _ = Darwin.sendto(tx.fd, raw.baseAddress, raw.count, 0, sa, len) }
                        }
                    } }
                }
            } / Double(m)
        }
        _ = sendLoop(sealing: false)
        let plainNs = sendLoop(sealing: false)
        let sealedNs = sendLoop(sealing: true)
        let plain2 = sendLoop(sealing: false)
        let sealed2 = sendLoop(sealing: true)
        let plainBest = min(plainNs, plain2), sealedBest = min(sealedNs, sealed2)

        print(String(format: "udp_tag_bench hmac_tag_1200B_ns=%.0f verify_1208B_ns=%.0f verified=%d/%d", tagNs, verifyNs, okCount, n))
        print(String(format: "udp_tag_bench sendto_loopback_ns plain=%.0f sealed=%.0f extra=%.0f (best of 2 runs of %d)", plainBest, sealedBest, sealedBest - plainBest, m))
        for r in mbps {
            let pps = Double(r) * 1_000_000 / 8 / 1180  // 1180 B of payload per 1200-byte MR02 packet (20-byte header)
            let cpu = pps * tagNs / 1e9 * 100
            let perFrameUs = pps / 60 * tagNs / 1000
            print(String(format: "udp_tag_bench 4K60 %d Mbps: %.0f packets/s, %.0f packets/frame, tag cost %.2f%% of one core, %.1f us per frame (frame budget 16667 us), +%.2f%% bytes",
                         r, pps, pps / 60, cpu, perFrameUs, 8.0 / 1200 * 100))
        }
        if sink == 0xff { print("") }
        return okCount == n ? 0 : 1
    }
}

/// r3 self-test: a value shared with a server callback thread.
private final class LockedBox<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: T
    init(_ value: T) { stored = value }
    var value: T { lock.lock(); defer { lock.unlock() }; return stored }
    func mutate(_ change: (inout T) -> Void) { lock.lock(); change(&stored); lock.unlock() }
}
