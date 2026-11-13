import Foundation
import Darwin

/// `JerisLinkHost --self-test` part for `--service control`, end to end.
///
/// Starts the same listeners as `ControlService` (direct + loopback relay) on
/// free loopback ports, with a fake input helper that behaves like the real
/// one: it serves one MRI1 connection at a time. Then it sends a key and a
/// mouse move through the direct listener (as the viewer does on 38400) and
/// through the relay listener (as the video service does on 38411), and checks
/// that all four arrive at the helper. Nothing is injected into the real Mac.
enum ControlServiceSelfTest {
    static func run() -> Int32 {
        var failures = 0
        func expect(_ ok: Bool, _ name: String) {
            print("\(ok ? "PASS" : "FAIL") \(name)")
            if !ok { failures += 1 }
        }

        guard let helper = FakeInputHelper.start() else {
            expect(false, "control e2e: fake input helper listens")
            return 1
        }
        defer { helper.stop() }

        // Root cause of the first P1 install: the helper serves one
        // connection at a time, so a second client never gets an answer.
        let first = InputHelperClient(port: helper.port)
        let second = InputHelperClient(port: helper.port)
        expect(first.ping(), "control e2e: first helper connection answers ping")
        expect(!second.ping(), "control e2e: helper ignores a second concurrent connection (needs one shared client)")
        first.closeConnection()
        second.closeConnection()
        helper.waitIdle()

        guard let directPort = freeLoopbackPort(), let relayPort = freeLoopbackPort(), directPort != relayPort else {
            expect(false, "control e2e: free loopback ports")
            return 1
        }

        // Start on a background thread with a deadline, so a start-up that
        // blocks (as the first P1 build did) fails the test instead of hanging CI.
        let started = DispatchSemaphore(value: 0)
        let result = StartResult()
        Thread.detachNewThread {
            do {
                result.servers = try ControlService.startServers(bindIP: ListenConfig.loopbackIP, clientIP: ListenConfig.loopbackIP,
                                                          port: directPort, relayPort: relayPort, inject: true,
                                                          helper: InputHelperClient(port: helper.port))
            } catch {
                result.error = error
            }
            started.signal()
        }
        let startedInTime = started.wait(timeout: .now() + 10) == .success
        let servers = result.servers
        let startError = result.error
        expect(startedInTime && startError == nil && servers.count == 2,
               "control e2e: direct :\(directPort) and relay :\(relayPort) listeners start within 10 s")
        guard startedInTime, startError == nil, servers.count == 2 else { return Int32(failures) }
        defer { servers.forEach { $0.stop() } }

        // Direct path (viewer -> bindIP:38400): key A and a normalised move.
        let direct = MRC1Client(port: directPort)
        expect(direct != nil, "control e2e: viewer connects to direct listener")
        _ = direct?.send(type: 0x10, payload: [1, 0, 65])            // KEY down, semantic 'A' -> macCG 0
        _ = direct?.send(type: 0x24, payload: [0x0d, 0x05, 0x11, 0x5c]) // MOUSE_MOVE_ABS_NORM 3333,4444

        // Relay path (video service -> 127.0.0.1:38411): the real relay
        // client's mouse move, plus a key on a second relay connection.
        let relayMouse = LocalControlMouseClient(port: relayPort)
        expect(relayMouse.sendMouseMoveNormalized(nx: 1111, ny: 2222), "control e2e: relay client sends mouse move")
        let relayKey = MRC1Client(port: relayPort)
        expect(relayKey != nil, "control e2e: second client connects to relay listener")
        _ = relayKey?.send(type: 0x10, payload: [1, 0, 66])          // KEY down, semantic 'B' -> macCG 11

        let want: [(String, FakeInputHelper.Event)] = [
            ("direct key A (macCG 0)", .init(type: 0x10, payload: [1, 0, 0])),
            ("direct mouse 3333,4444", .init(type: 0x24, payload: [0x0d, 0x05, 0x11, 0x5c])),
            ("relay mouse 1111,2222", .init(type: 0x24, payload: [0x04, 0x57, 0x08, 0xae])),
            ("relay key B (macCG 11)", .init(type: 0x10, payload: [1, 0, 11])),
        ]
        let deadline = Date().addingTimeInterval(5)
        while Date() < deadline, !want.allSatisfy({ helper.received($0.1) }) {
            usleep(20_000)
        }
        for (name, event) in want {
            expect(helper.received(event), "control e2e: helper received \(name)")
        }
        expect(helper.maxConcurrentConnections == 1, "control e2e: one helper connection for both listeners")

        // F3 session lifecycle: one SESSION_START before a viewer connection's
        // first key or mouse message, one SESSION_END when it closes. Nothing
        // per event; nothing for relay, clipboard or ping-only connections.
        let start = InputHelperClient.sessionStartType
        let end = InputHelperClient.sessionEndType
        expect(helper.count(type: start) == 1, "control e2e: one SESSION_START for the viewer, none for the relay clients")
        if let s = helper.firstIndex(type: start),
           let k = helper.firstIndex(of: .init(type: 0x10, payload: [1, 0, 0])) {
            expect(s < k, "control e2e: SESSION_START reaches the helper before the viewer's first event")
        } else {
            expect(false, "control e2e: SESSION_START reaches the helper before the viewer's first event")
        }
        let marker = FakeInputHelper.Event(type: 0x24, payload: [0x00, 0x07, 0x00, 0x09])
        for _ in 0..<50 { _ = direct?.send(type: 0x24, payload: marker.payload) }
        let markerDeadline = Date().addingTimeInterval(5)
        while Date() < markerDeadline, !helper.received(marker) { usleep(20_000) }
        expect(helper.received(marker) && helper.count(type: start) == 1 && helper.count(type: end) == 0,
               "control e2e: no lifecycle message per event (50 events)")

        let clipboard = MRC1Client(port: directPort)
        _ = clipboard?.send(type: 0x30, payload: [])                 // CLIPBOARD_HELLO
        let pingOnly = MRC1Client(port: directPort)
        _ = pingOnly?.send(type: 0x01, payload: [1, 2, 3, 4])        // PING
        usleep(300_000)
        clipboard?.close()
        pingOnly?.close()
        relayKey?.close()
        relayMouse.closeConnection()
        usleep(500_000)
        expect(clipboard != nil && pingOnly != nil && helper.count(type: start) == 1 && helper.count(type: end) == 0,
               "control e2e: clipboard, ping-only and relay connections send no SESSION_START/END")

        direct?.close()
        let endDeadline = Date().addingTimeInterval(5)
        while Date() < endDeadline, helper.count(type: end) < 1 { usleep(20_000) }
        usleep(200_000)
        expect(helper.count(type: end) == 1 && helper.count(type: start) == 1,
               "control e2e: viewer disconnect sends exactly one SESSION_END")
        expect(helper.maxConcurrentConnections == 1, "control e2e: still one helper connection (no reconnect per session)")
        let ev = helper.snapshot()
        let startIDs = ev.filter { $0.type == start }.map(\.payload)
        let endIDs = ev.filter { $0.type == end }.map(\.payload)
        expect(startIDs.count == 1 && startIDs[0].count == 4 && startIDs == endIDs,
               "control e2e: SESSION_START and SESSION_END carry the same 4-byte session id")

        failures += interleavedReconnect(expect)
        failures += helperRecovers(expect)
        return failures == 0 ? 0 : 1
    }

    private static func wait(until cond: () -> Bool, seconds: Double = 5) {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline, !cond() { usleep(20_000) }
    }

    /// Round 4 (a): A START, MRI1 drop, B START + Shift + drag, A END. After
    /// the reconnect the client re-announces A before B's START, and A's END
    /// carries A's id, so the helper (id set) keeps B's state. Once A has
    /// ended, the next reconnect re-announces only B. Returns 0: failures are
    /// counted by `expect`.
    private static func interleavedReconnect(_ expect: (Bool, String) -> Void) -> Int {
        guard let fake = FakeInputHelper.start() else {
            expect(false, "reconnect: fake input helper listens"); return 0
        }
        defer { fake.stop() }
        let start = InputHelperClient.sessionStartType
        let end = InputHelperClient.sessionEndType
        let idA = InputHelperClient.sessionIDBytes(101)
        let idB = InputHelperClient.sessionIDBytes(102)
        let client = InputHelperClient(port: fake.port)
        expect(client.sendSessionStart(id: 101), "reconnect: A SESSION_START delivered")
        wait { fake.snapshot().count == 1 }
        fake.dropCurrentConnection()
        fake.waitIdle()
        usleep(100_000)
        expect(client.sendSessionStart(id: 102), "reconnect: B SESSION_START delivered after the MRI1 drop")
        _ = client.sendKey(cgCode: 56, down: true)
        _ = client.sendMouseButton(button: 0, down: true)
        expect(client.sendSessionEnd(id: 101), "reconnect: A SESSION_END delivered")
        wait { fake.snapshot().count >= 6 }
        let want: [FakeInputHelper.Event] = [
            .init(type: start, payload: idA),                 // before the drop
            .init(type: start, payload: idA),                 // re-announced on reconnect
            .init(type: start, payload: idB),
            .init(type: 0x10, payload: [1, 0, 56]),
            .init(type: 0x21, payload: [0, 1]),
            .init(type: end, payload: idA),
        ]
        let got = fake.snapshot()
        expect(got == want, "reconnect: helper sees A, re-announced A, B, B's Shift and drag, then A's END (got \(got.map { "\($0.type):\($0.payload)" }))")
        expect(fake.connections == 2, "reconnect: exactly one reconnect after the drop (got \(fake.connections))")

        fake.dropCurrentConnection()
        fake.waitIdle()
        usleep(100_000)
        _ = client.sendKey(cgCode: 56, down: false)
        wait { fake.snapshot().count >= 8 }
        let tail = Array(fake.snapshot().dropFirst(6))
        expect(tail == [.init(type: start, payload: idB), .init(type: 0x10, payload: [0, 0, 56])],
               "reconnect: after A ended, a reconnect re-announces only B, before the next event")
        _ = client.sendSessionEnd(id: 102)
        client.closeConnection()
        return 0
    }

    /// Round 4 (b): the helper is not running at the viewer's first input and
    /// comes up later. START is retried on the next input message, reaches
    /// the helper once before that event, and END follows at close.
    private static func helperRecovers(_ expect: (Bool, String) -> Void) -> Int {
        guard let helperPort = freeLoopbackPort(), let directPort = freeLoopbackPort(),
              let relayPort = freeLoopbackPort(), Set([helperPort, directPort, relayPort]).count == 3 else {
            expect(false, "recovery: free loopback ports"); return 0
        }
        let started = DispatchSemaphore(value: 0)
        let result = StartResult()
        Thread.detachNewThread {
            do {
                result.servers = try ControlService.startServers(bindIP: ListenConfig.loopbackIP, clientIP: ListenConfig.loopbackIP,
                                                                 port: directPort, relayPort: relayPort, inject: true,
                                                                 helper: InputHelperClient(port: helperPort))
            } catch {
                result.error = error
            }
            started.signal()
        }
        guard started.wait(timeout: .now() + 10) == .success, result.error == nil, result.servers.count == 2 else {
            expect(false, "recovery: listeners start with the helper down"); return 0
        }
        let servers = result.servers
        defer { servers.forEach { $0.stop() } }

        let viewer = MRC1Client(port: directPort)
        expect(viewer != nil, "recovery: viewer connects while the helper is down")
        _ = viewer?.send(type: 0x10, payload: [1, 0, 65])            // first input: helper down
        usleep(300_000)
        guard let fake = FakeInputHelper.start(port: helperPort) else {
            expect(false, "recovery: helper comes up on its port"); return 0
        }
        defer { fake.stop() }
        _ = viewer?.send(type: 0x10, payload: [0, 0, 65])            // next input: START retried
        let marker = FakeInputHelper.Event(type: 0x24, payload: [0x00, 0x05, 0x00, 0x06])
        for _ in 0..<10 { _ = viewer?.send(type: 0x24, payload: marker.payload) }
        wait { fake.received(marker) }
        viewer?.close()
        wait { fake.count(type: InputHelperClient.sessionEndType) >= 1 }
        usleep(200_000)
        let ev = fake.snapshot()
        let starts = ev.filter { $0.type == InputHelperClient.sessionStartType }
        let ends = ev.filter { $0.type == InputHelperClient.sessionEndType }
        expect(ev.first?.type == InputHelperClient.sessionStartType && starts.count == 1,
               "recovery: START retried once the helper is up, first on the wire, sent once (got \(starts.count))")
        expect(ev.contains(.init(type: 0x10, payload: [0, 0, 0])) && fake.received(marker),
               "recovery: events after the helper came up are delivered")
        expect(ends.count == 1 && ends.map(\.payload) == starts.map(\.payload),
               "recovery: one SESSION_END with the started id at close")
        return 0
    }

    private static func freeLoopbackPort() -> UInt16? {
        let s = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard s >= 0 else { return nil }
        defer { Darwin.close(s) }
        var addr = loopbackAddress(port: 0)
        let rc = withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard rc == 0 else { return nil }
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let got = withUnsafeMutablePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(s, $0, &len) }
        }
        guard got == 0 else { return nil }
        return UInt16(bigEndian: addr.sin_port)
    }

    fileprivate static func loopbackAddress(port: UInt16) -> sockaddr_in {
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        _ = "127.0.0.1".withCString { inet_pton(AF_INET, $0, &addr.sin_addr) }
        return addr
    }
}

/// A viewer-side MRC1 connection for the self-test.
private final class MRC1Client {
    private var fd: Int32

    init?(port: UInt16) {
        let s = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard s >= 0 else { return nil }
        var noSigPipe: Int32 = 1
        setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))
        var addr = ControlServiceSelfTest.loopbackAddress(port: port)
        let rc = withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard rc == 0 else { Darwin.close(s); return nil }
        fd = s
    }

    func send(type: UInt8, payload: [UInt8]) -> Bool {
        let n = UInt16(payload.count)
        let bytes: [UInt8] = [0x4d, 0x52, 0x43, 0x31, 1, type, UInt8(n >> 8), UInt8(n & 0xff)] + payload
        let sent = bytes.withUnsafeBytes { Darwin.send(fd, $0.baseAddress!, bytes.count, 0) }
        return sent == bytes.count
    }

    func close() {
        if fd >= 0 { Darwin.close(fd); fd = -1 }
    }

    deinit { close() }
}

/// Stand-in for JerisLink Input Helper: MRI1 on a free loopback port, one
/// connection at a time (accept, serve until EOF, accept the next), exactly
/// like the real helper's run loop. Records what it receives; posts nothing.
private final class FakeInputHelper: @unchecked Sendable {
    struct Event: Equatable {
        let type: UInt8
        let payload: [UInt8]
    }

    let port: UInt16
    private let listenFD: Int32
    private let lock = NSLock()
    private var events: [Event] = []
    private var active = 0
    private var accepted = 0
    private var current: Int32 = -1
    private(set) var maxConcurrentConnections = 0
    private var stopping = false

    private init(fd: Int32, port: UInt16) {
        listenFD = fd
        self.port = port
    }

    static func start(port: UInt16 = 0) -> FakeInputHelper? {
        let s = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard s >= 0 else { return nil }
        var yes: Int32 = 1
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
        var addr = ControlServiceSelfTest.loopbackAddress(port: port)
        let rc = withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard rc == 0, Darwin.listen(s, 4) == 0 else { Darwin.close(s); return nil }
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(s, $0, &len) }
        }
        let helper = FakeInputHelper(fd: s, port: UInt16(bigEndian: addr.sin_port))
        Thread.detachNewThread { helper.acceptLoop() }
        return helper
    }

    func stop() {
        lock.lock(); stopping = true; lock.unlock()
        Darwin.shutdown(listenFD, SHUT_RDWR)
        Darwin.close(listenFD)
    }

    func received(_ event: Event) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return events.contains(event)
    }

    func count(type: UInt8) -> Int {
        lock.lock(); defer { lock.unlock() }
        return events.filter { $0.type == type }.count
    }

    func firstIndex(of event: Event) -> Int? {
        lock.lock(); defer { lock.unlock() }
        return events.firstIndex(of: event)
    }

    func firstIndex(type: UInt8) -> Int? {
        lock.lock(); defer { lock.unlock() }
        return events.firstIndex { $0.type == type }
    }

    func snapshot() -> [Event] {
        lock.lock(); defer { lock.unlock() }
        return events
    }

    /// Connections accepted so far.
    var connections: Int {
        lock.lock(); defer { lock.unlock() }
        return accepted
    }

    /// Close the connection being served, as a helper restart would.
    func dropCurrentConnection() {
        lock.lock(); let c = current; lock.unlock()
        if c >= 0 { Darwin.shutdown(c, SHUT_RDWR) }
    }

    /// Wait until no client is being served (after the root-cause probe).
    func waitIdle() {
        for _ in 0..<250 {
            lock.lock(); let busy = active > 0; lock.unlock()
            if !busy { return }
            usleep(20_000)
        }
    }

    private func acceptLoop() {
        while true {
            let c = Darwin.accept(listenFD, nil, nil)
            if c < 0 {
                lock.lock(); let done = stopping; lock.unlock()
                if done { return }
                continue
            }
            lock.lock()
            active += 1
            accepted += 1
            current = c
            maxConcurrentConnections = max(maxConcurrentConnections, active)
            lock.unlock()
            serve(c)
            lock.lock(); current = -1; lock.unlock()
            Darwin.close(c)
            lock.lock(); active -= 1; lock.unlock()
        }
    }

    private func serve(_ fd: Int32) {
        while let header = recvExact(fd, 8) {
            guard header[0] == 0x4d, header[1] == 0x52, header[2] == 0x49, header[3] == 0x31, header[4] == 1 else { return }
            let len = Int(UInt16(header[6]) << 8 | UInt16(header[7]))
            guard len <= 4096, let payload = recvExact(fd, len) else { return }
            if header[5] == 0x01 { // PING -> PONG
                let reply: [UInt8] = [0x4d, 0x52, 0x49, 0x31, 1, 0x02, header[6], header[7]] + payload
                _ = reply.withUnsafeBytes { Darwin.send(fd, $0.baseAddress!, reply.count, 0) }
                continue
            }
            lock.lock(); events.append(Event(type: header[5], payload: payload)); lock.unlock()
        }
    }

    private func recvExact(_ fd: Int32, _ count: Int) -> [UInt8]? {
        if count == 0 { return [] }
        var out = [UInt8](repeating: 0, count: count)
        var off = 0
        while off < count {
            let n = out.withUnsafeMutableBytes { Darwin.recv(fd, $0.baseAddress!.advanced(by: off), count - off, 0) }
            if n <= 0 { return nil }
            off += n
        }
        return out
    }
}

private final class StartResult: @unchecked Sendable {
    var servers: [ControlServer] = []
    var error: Error?
}
