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
        failures += eofMonitor(expect)
        failures += recoveryWindow(expect)
        failures += clipboardPollReadsOnlyChangeCount(expect)
        failures += capsUsesInputSourceCache(expect)
        failures += mainThreadHopCounter(expect)
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
        wait { !client.isConnected }
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
        wait { !client.isConnected }
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

    /// Round 5: helper EOF is found by the socket monitor, not by a check per
    /// event. 50 events do not wake the monitor; killing the helper does, and
    /// the next event reconnects, re-announces the live session and arrives.
    private static func eofMonitor(_ expect: (Bool, String) -> Void) -> Int {
        guard let port = freeLoopbackPort(), let fake = FakeInputHelper.start(port: port) else {
            expect(false, "eof monitor: fake input helper listens"); return 0
        }
        let start = InputHelperClient.sessionStartType
        let id = InputHelperClient.sessionIDBytes(201)
        let client = InputHelperClient(port: port)
        _ = client.sendSessionStart(id: 201)
        _ = client.sendKey(cgCode: 0, down: true)
        wait { fake.snapshot().count == 2 }
        let wakeupsBefore = client.eofMonitorWakeups
        for _ in 0..<50 { _ = client.sendMouseMoveNormalized(nx: 7, ny: 9) }
        wait { fake.snapshot().count == 52 }
        usleep(100_000)
        expect(fake.snapshot().count == 52 && client.eofMonitorWakeups == wakeupsBefore,
               "eof monitor: 50 events delivered, monitor not woken by events (wakeups \(wakeupsBefore) -> \(client.eofMonitorWakeups))")

        fake.dropCurrentConnection()     // helper dies
        fake.waitIdle()
        fake.stop()
        wait { !client.isConnected }
        expect(!client.isConnected, "eof monitor: helper EOF detected without sending anything")
        guard let restarted = FakeInputHelper.start(port: port) else {
            expect(false, "eof monitor: helper restarts on its port"); return 0
        }
        defer { restarted.stop() }
        _ = client.sendKey(cgCode: 0, down: false)
        wait { restarted.snapshot().count >= 2 }
        let got = restarted.snapshot()
        expect(got == [.init(type: start, payload: id), .init(type: 0x10, payload: [0, 0, 0])],
               "eof monitor: first event after the helper restart re-sends START and is delivered (got \(got.map { "\($0.type):\($0.payload)" }))")
        _ = client.sendSessionEnd(id: 201)
        client.closeConnection()
        return 0
    }

    /// Round 5: the helper comes up between a failed SESSION_START and the
    /// send of that input message. The message must be dropped (no input
    /// outside a session the helper knows), the next one starts the session.
    private static func recoveryWindow(_ expect: (Bool, String) -> Void) -> Int {
        guard let helperPort = freeLoopbackPort(), let directPort = freeLoopbackPort(),
              let relayPort = freeLoopbackPort(), Set([helperPort, directPort, relayPort]).count == 3 else {
            expect(false, "window: free loopback ports"); return 0
        }
        let box = FakeBox()
        let client = InputHelperClient(port: helperPort)
        client.afterFailedSessionStart = {
            if box.fake == nil { box.fake = FakeInputHelper.start(port: helperPort) }
        }
        let started = DispatchSemaphore(value: 0)
        let result = StartResult()
        Thread.detachNewThread {
            do {
                result.servers = try ControlService.startServers(bindIP: ListenConfig.loopbackIP, clientIP: ListenConfig.loopbackIP,
                                                                 port: directPort, relayPort: relayPort, inject: true,
                                                                 helper: client)
            } catch {
                result.error = error
            }
            started.signal()
        }
        guard started.wait(timeout: .now() + 10) == .success, result.error == nil, result.servers.count == 2 else {
            expect(false, "window: listeners start with the helper down"); return 0
        }
        let servers = result.servers
        defer { servers.forEach { $0.stop() }; box.fake?.stop() }

        let viewer = MRC1Client(port: directPort)
        _ = viewer?.send(type: 0x10, payload: [1, 0, 65])            // START fails, helper comes up
        wait { box.fake != nil }
        usleep(300_000)
        guard let fake = box.fake else {
            expect(false, "window: helper came up after the failed START"); return 0
        }
        expect(fake.snapshot().isEmpty, "window: input whose START failed is not delivered (got \(fake.snapshot().map { "\($0.type):\($0.payload)" }))")
        _ = viewer?.send(type: 0x10, payload: [0, 0, 65])            // next input: START, then key
        wait { fake.snapshot().count >= 2 }
        viewer?.close()
        wait { fake.count(type: InputHelperClient.sessionEndType) >= 1 }
        usleep(200_000)
        let ev = fake.snapshot()
        let ok = ev.count == 3 && ev[0].type == InputHelperClient.sessionStartType
            && ev[1] == .init(type: 0x10, payload: [0, 0, 0])
            && ev[2].type == InputHelperClient.sessionEndType && ev[2].payload == ev[0].payload
        expect(ok, "window: helper sees START, then the key, then END with the same id (got \(ev.map { "\($0.type):\($0.payload)" }))")
        client.closeConnection()
        return 0
    }

    // MARK: PR-E: main-thread hops

    /// Run the main run loop briefly while waiting: the self-test runs on the
    /// main thread, and distributed notifications and main-queue work are
    /// delivered there.
    private static func spinMain(until cond: () -> Bool, seconds: Double = 5) {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline, !cond() {
            _ = CFRunLoopRunInMode(CFRunLoopMode.defaultMode, 0.02, false)
        }
    }

    private static func startServer(inject: Bool, helperPort: UInt16?, clipboard: ClipboardBackend,
                                    inputSources: InputSourceCache) -> (ControlServer, UInt16)? {
        guard let port = freeLoopbackPort() else { return nil }
        let server = ControlServer(bindIP: ListenConfig.loopbackIP, allowedClientIP: ListenConfig.loopbackIP,
                                   port: port, inject: inject,
                                   settingsClientIP: { ListenConfig.loopbackIP }, acceptProxy: false,
                                   inputHelper: helperPort.map { InputHelperClient(port: $0) },
                                   clipboard: clipboard, inputSources: inputSources)
        do { try server.start() } catch { return nil }
        return (server, port)
    }

    /// Clipboard poll: every 100 ms only the change count is read; contents
    /// are read only when it moved. Both directions behave as before: a local
    /// copy is sent to the viewer, a viewer copy is applied and not echoed.
    private static func clipboardPollReadsOnlyChangeCount(_ expect: (Bool, String) -> Void) -> Int {
        let board = FakeClipboard(text: "before-session")
        let cache = InputSourceCache(backend: FakeInputSource(id: "com.apple.keylayout.US"),
                                     notification: "io.jerislink.selftest.clipboard.\(getpid())")
        guard let (server, port) = startServer(inject: false, helperPort: nil, clipboard: board, inputSources: cache),
              let viewer = MRC1Client(port: port) else {
            expect(false, "clipboard poll: server and viewer start")
            return 0
        }
        defer { viewer.close(); server.stop() }
        _ = viewer.send(type: 0x30, payload: [])                     // CLIPBOARD_HELLO
        wait(until: { board.counts.changeCountReads >= 2 })
        let startReads = board.counts.textReads
        let polls0 = board.counts.changeCountReads
        usleep(1_000_000)
        let idle = board.counts
        let idlePolls = idle.changeCountReads - polls0
        print("clipboard poll: idle 1.0 s -> \(idlePolls) change-count polls, \(idle.textReads - startReads) content reads")
        expect(idlePolls >= 5 && idle.textReads == startReads,
               "clipboard poll: idle polls read only the change count (\(idlePolls) polls, \(idle.textReads - startReads) content reads)")

        board.localCopy("local-1")
        let tx1 = viewer.receive(timeout: 2)
        expect(tx1?.type == 0x31 && tx1.map { String(decoding: $0.payload, as: UTF8.self) } == "local-1",
               "clipboard poll: local copy is sent to the viewer")
        expect(board.counts.textReads == startReads + 1, "clipboard poll: one content read for one local change")

        _ = viewer.send(type: 0x31, payload: Array("remote-1".utf8))
        wait(until: { board.writes.contains("remote-1") })
        expect(board.writes == ["remote-1"], "clipboard poll: viewer copy is applied to the pasteboard")
        let echo = viewer.receive(timeout: 0.6)
        expect(echo == nil, "clipboard poll: applied viewer copy is not echoed back")
        let afterRX = board.counts.textReads
        usleep(500_000)
        expect(board.counts.textReads == afterRX, "clipboard poll: no content reads after the viewer copy while idle")

        _ = viewer.send(type: 0x31, payload: Array("remote-1".utf8))  // same text again: no rewrite
        usleep(300_000)
        expect(board.writes == ["remote-1"], "clipboard poll: unchanged viewer copy is not written again")

        board.localCopy("local-2")
        let tx2 = viewer.receive(timeout: 2)
        expect(tx2.map { String(decoding: $0.payload, as: UTF8.self) } == "local-2",
               "clipboard poll: a later local copy is still sent")
        return 0
    }

    /// Caps Lock alpha mode: the per-key input-source check reads the cache;
    /// the cache follows the change notification. TIS (and the main thread)
    /// is asked once per Caps press, never per key.
    private static func capsUsesInputSourceCache(_ expect: (Bool, String) -> Void) -> Int {
        guard let helper = FakeInputHelper.start() else {
            expect(false, "caps cache: fake input helper listens")
            return 0
        }
        defer { helper.stop() }
        let us = "com.apple.keylayout.US"
        let cangjie = "com.apple.inputmethod.TCIM.Cangjie"
        let source = FakeInputSource(id: us)
        let note = "io.jerislink.selftest.inputsource.\(getpid())"
        let cache = InputSourceCache(backend: source, notification: note)
        guard let (server, port) = startServer(inject: true, helperPort: helper.port,
                                               clipboard: FakeClipboard(text: nil), inputSources: cache),
              let viewer = MRC1Client(port: port) else {
            expect(false, "caps cache: server and viewer start")
            return 0
        }
        defer { viewer.close(); server.stop() }
        spinMain(until: { cache.refreshes >= 1 })
        expect(cache.current == us, "caps cache: first value read on the main thread at start")

        func key(_ semantic: UInt8, _ down: Bool) { _ = viewer.send(type: 0x10, payload: [down ? 1 : 0, 0, semantic]) }
        let shiftDown = FakeInputHelper.Event(type: 0x10, payload: [1, 0, 56])
        let readsBefore = source.counts.current

        key(20, true); key(20, false)                                 // Caps Lock: alpha mode on
        for _ in 0..<10 { key(65, true); key(65, false) }             // 10 x 'A'
        let aUp = FakeInputHelper.Event(type: 0x10, payload: [0, 0, 0])
        wait(until: { helper.snapshot().filter { $0 == aUp }.count >= 10 })
        let wrapped = helper.snapshot().filter { $0 == shiftDown }.count
        expect(wrapped == 20, "caps cache: alpha mode wraps each 'A' down/up in synthetic Shift (\(wrapped)/20)")
        let perKeyReads = source.counts.current - readsBefore
        expect(perKeyReads == 1, "caps cache: one TIS read for the Caps press, none for 20 key events (got \(perKeyReads))")

        source.set(cangjie)                                           // user switches input source on the Mac
        let refreshed = cache.refreshes
        CFNotificationCenterPostNotification(CFNotificationCenterGetDistributedCenter(),
                                             CFNotificationName(note as CFString), nil, nil, true)
        spinMain(until: { cache.refreshes > refreshed && cache.current == cangjie })
        expect(cache.current == cangjie, "caps cache: input-source notification updates the cache")

        key(66, true); key(66, false)                                 // 'B' after the switch
        let bUp = FakeInputHelper.Event(type: 0x10, payload: [0, 0, 11])
        wait(until: { helper.received(bUp) })
        usleep(100_000)
        expect(helper.received(bUp) && helper.snapshot().filter { $0 == shiftDown }.count == 20,
               "caps cache: after the switch no synthetic Shift reaches the input method")

        source.set(us)                                                // back to U.S.: alpha mode stays off
        let refreshed2 = cache.refreshes
        CFNotificationCenterPostNotification(CFNotificationCenterGetDistributedCenter(),
                                             CFNotificationName(note as CFString), nil, nil, true)
        spinMain(until: { cache.refreshes > refreshed2 })
        key(67, true); key(67, false)                                 // 'C'
        let cUp = FakeInputHelper.Event(type: 0x10, payload: [0, 0, 8])
        wait(until: { helper.received(cUp) })
        usleep(100_000)
        expect(helper.received(cUp) && helper.snapshot().filter { $0 == shiftDown }.count == 20,
               "caps cache: alpha mode was reset by the switch, as before")
        expect(source.counts.current - readsBefore == 1 && source.counts.selects == 0,
               "caps cache: still one TIS read in total, no input-source selects")
        return 0
    }

    /// The hop counter behind `main_hops=`: SystemClipboard.changeCount() from
    /// a socket thread does not hop; a content read does (read-only, the
    /// test never writes the real pasteboard).
    private static func mainThreadHopCounter(_ expect: (Bool, String) -> Void) -> Int {
        let before = MainThreadHops.total
        let done = DispatchSemaphore(value: 0)
        let box = HopBox()
        Thread.detachNewThread {
            for _ in 0..<100 { _ = SystemClipboard.shared.changeCount() }
            box.afterCounts = MainThreadHops.total
            _ = SystemClipboard.shared.readText()
            box.afterRead = MainThreadHops.total
            done.signal()
        }
        spinMain(until: { done.wait(timeout: .now()) == .success }, seconds: 5)
        expect(box.afterCounts == before, "main hops: 100 change-count reads off the main thread make 0 hops")
        expect(box.afterRead == before + 1, "main hops: one content read off the main thread makes 1 hop")
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

    /// Next MRC1 packet from the host, or nil after `timeout` seconds.
    func receive(timeout: Double) -> (type: UInt8, payload: [UInt8])? {
        guard let header = recvExact(8, timeout: timeout), header[0] == 0x4d, header[3] == 0x31 else { return nil }
        let len = Int(UInt16(header[6]) << 8 | UInt16(header[7]))
        guard let payload = recvExact(len, timeout: 2) else { return nil }
        return (header[5], payload)
    }

    private func recvExact(_ count: Int, timeout: Double) -> [UInt8]? {
        if count == 0 { return [] }
        var out = [UInt8](repeating: 0, count: count)
        var off = 0
        let deadline = Date().addingTimeInterval(timeout)
        while off < count {
            let left = Int32(max(0, deadline.timeIntervalSinceNow) * 1000)
            var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            guard Darwin.poll(&pfd, 1, left) > 0 else { return nil }
            let n = out.withUnsafeMutableBytes { Darwin.recv(fd, $0.baseAddress!.advanced(by: off), count - off, 0) }
            if n <= 0 { return nil }
            off += n
        }
        return out
    }

    deinit { close() }
}

/// Pasteboard stand-in: counts change-count and content reads.
private final class FakeClipboard: ClipboardBackend, @unchecked Sendable {
    struct Counts { var changeCountReads = 0; var textReads = 0 }
    private let lock = NSLock()
    private var count = 1
    private var text: String?
    private var c = Counts()
    private var written: [String] = []

    init(text: String?) { self.text = text }

    var counts: Counts { lock.lock(); defer { lock.unlock() }; return c }
    var writes: [String] { lock.lock(); defer { lock.unlock() }; return written }

    /// A copy made on the Mac itself.
    func localCopy(_ value: String) {
        lock.lock(); count += 1; text = value; lock.unlock()
    }

    func changeCount() -> Int {
        lock.lock(); defer { lock.unlock() }
        c.changeCountReads += 1
        return count
    }

    func readText() -> String? {
        lock.lock(); defer { lock.unlock() }
        c.textReads += 1
        return text
    }

    func writeText(_ value: String) -> Int? {
        lock.lock(); defer { lock.unlock() }
        written.append(value)
        count += 1
        text = value
        return count
    }
}

/// Text Input Sources stand-in: counts reads and selects; never touches TIS.
private final class FakeInputSource: InputSourceBackend, @unchecked Sendable {
    struct Counts { var current = 0; var selects = 0 }
    private let lock = NSLock()
    private var id: String?
    private var c = Counts()

    init(id: String?) { self.id = id }

    var counts: Counts { lock.lock(); defer { lock.unlock() }; return c }
    func set(_ value: String?) { lock.lock(); id = value; lock.unlock() }

    func currentID() -> String? {
        lock.lock(); defer { lock.unlock() }
        c.current += 1
        return id
    }

    /// The cache's notification refresh: not a per-key read, not counted.
    func currentIDOnMain() -> String? {
        lock.lock(); defer { lock.unlock() }
        return id
    }

    func select(id value: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        c.selects += 1
        id = value
        return true
    }
}

private final class HopBox: @unchecked Sendable {
    var afterCounts: UInt64 = 0
    var afterRead: UInt64 = 0
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

private final class FakeBox: @unchecked Sendable {
    var fake: FakeInputHelper?
}

private final class StartResult: @unchecked Sendable {
    var servers: [ControlServer] = []
    var error: Error?
}
