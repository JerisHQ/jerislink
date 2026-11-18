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

        // #58: FORCE_QUIT_OPEN and CLIPBOARD_HELLO are for the configured
        // viewer only. The relay (127.0.0.1:38411, also where an old
        // `tailscale serve` forward lands) cannot prove who is behind it, so
        // it refuses both; the direct listener still serves them.
        let forceQuit = FakeInputHelper.Event(type: InputHelperClient.forceQuitOpenType, payload: [])
        let relayQuit = MRC1Client(port: relayPort)
        _ = relayQuit?.send(type: 0x60, payload: [])
        _ = relayQuit?.send(type: 0x01, payload: [7, 7, 7, 7])     // PING: the relay has read the 0x60
        _ = relayQuit?.receive(timeout: 2)
        usleep(300_000)
        expect(relayQuit != nil && helper.count(type: InputHelperClient.forceQuitOpenType) == 0,
               "control e2e: relay FORCE_QUIT_OPEN never reaches the helper")
        _ = direct?.send(type: 0x60, payload: [])
        let quitDeadline = Date().addingTimeInterval(5)
        while Date() < quitDeadline, !helper.received(forceQuit) { usleep(20_000) }
        expect(helper.count(type: InputHelperClient.forceQuitOpenType) == 1,
               "control e2e: direct FORCE_QUIT_OPEN reaches the helper once")
        relayQuit?.close()
        func clipboardPong(_ port: UInt16) -> Bool {
            guard let c = MRC1Client(port: port) else { return false }
            defer { c.close() }
            _ = c.send(type: 0x30, payload: [])
            _ = c.send(type: 0x01, payload: [5, 6, 7, 8])
            let until = Date().addingTimeInterval(2)
            while Date() < until {
                guard let m = c.receive(timeout: max(0.05, until.timeIntervalSinceNow)) else { return false }
                if m.type == 0x02 && m.payload == [5, 6, 7, 8] { return true }
            }
            return false
        }
        expect(!clipboardPong(relayPort), "control e2e: relay CLIPBOARD_HELLO is refused (connection closed)")
        expect(clipboardPong(directPort), "control e2e: direct CLIPBOARD_HELLO still opens a clipboard session")

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
        failures += fileUploadEndToEnd(expect)
        failures += fileSendEndToEnd(expect)
        failures += fileAnnounceEndToEnd(expect)
        failures += filePushEndToEnd(expect)
        pushBrokerRouting(expect)
        failures += capsUsesInputSourceCache(expect)
        failures += mainThreadHopCounter(expect)
        failures += fileSessions(expect)
        failures += finderPasteRefused(expect)
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
                                    inputSources: InputSourceCache,
                                    fileStagingRoot: URL? = nil,
                                    fileSendFolder: FileSendFolder = .shared,
                                    frontmostApp: @escaping () -> String? = { nil }) -> (ControlServer, UInt16)? {
        guard let port = freeLoopbackPort() else { return nil }
        let server = ControlServer(bindIP: ListenConfig.loopbackIP, allowedClientIP: ListenConfig.loopbackIP,
                                   port: port, inject: inject,
                                   settingsClientIP: { ListenConfig.loopbackIP }, acceptProxy: false,
                                   inputHelper: helperPort.map { InputHelperClient(port: $0) },
                                   allowFileSessions: fileStagingRoot != nil,
                                   fileStagingRoot: fileStagingRoot ?? FileUploadReceiver.defaultRoot,
                                   fileSendFolder: fileSendFolder,
                                   clipboard: clipboard, inputSources: inputSources,
                                   frontmostApp: frontmostApp)
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

    /// F1 file sessions on the real listeners: the direct listener answers
    /// FILE_HELLO, echoes PING and refuses requests; malformed input, a late
    /// HELLO and the loopback relay get no answer. No file session is an
    /// input session.
    private static func fileSessions(_ expect: (Bool, String) -> Void) -> Int {
        guard let fake = FakeInputHelper.start() else { expect(false, "file e2e: fake input helper listens"); return 0 }
        defer { fake.stop() }
        guard let directPort = freeLoopbackPort(), let relayPort = freeLoopbackPort(), directPort != relayPort else {
            expect(false, "file e2e: free loopback ports"); return 0
        }
        let started = DispatchSemaphore(value: 0)
        let result = StartResult()
        Thread.detachNewThread {
            do {
                result.servers = try ControlService.startServers(bindIP: ListenConfig.loopbackIP, clientIP: ListenConfig.loopbackIP,
                                                                 port: directPort, relayPort: relayPort, inject: true,
                                                                 helper: InputHelperClient(port: fake.port))
            } catch {
                result.error = error
            }
            started.signal()
        }
        guard started.wait(timeout: .now() + 10) == .success, result.error == nil, result.servers.count == 2 else {
            expect(false, "file e2e: listeners start"); return 0
        }
        let servers = result.servers
        defer { servers.forEach { $0.stop() } }

        guard let file = MRC1Client(port: directPort) else { expect(false, "file e2e: viewer connects"); return 0 }
        _ = file.send(type: 0x50, payload: [1, 0, 0])                // FILE_HELLO proto 1, caps 0
        if let ack = file.receive(timeout: 3), ack.type == 0x51,
           case let .helloAck(proto, caps, maxChunk, maxTotal)? = FileProto.decode(type: ack.type, payload: ack.payload) {
            expect(proto == 1 && caps == FileProto.Caps.host && maxChunk == 32 * 1024 && maxTotal == 20 * 1024 * 1024 * 1024,
                   "file e2e: direct listener answers HELLO_ACK proto=1 caps=upload+reveal+announce chunk=32K total=20G")
        } else {
            expect(false, "file e2e: direct listener answers HELLO_ACK proto=1 caps=upload+reveal+announce chunk=32K total=20G")
        }
        _ = file.send(type: 0x5B, payload: [9, 8, 7, 6])
        let pong = file.receive(timeout: 3)
        expect(pong?.type == 0x5B && pong?.payload == [9, 8, 7, 6], "file e2e: PING echoed with its token")
        _ = file.send(type: 0x52, payload: FileProto.Message.offer(transfer: 42, purpose: FileProto.Purpose.push,
                                                                    entries: 1, total: 10).encode()!)
        let rej = file.receive(timeout: 3)
        expect(rej?.type == 0x54 && rej?.payload == [0, 0, 0, 42, FileProto.Status.denied], "file e2e: OFFER push refused with REJECT denied (F5)")
        // REVEAL is covered by fileSendEndToEnd with a temp folder: here it
        // would open the real ~/Downloads/JerisLink in Finder.
        _ = file.send(type: 0x10, payload: [1, 0, 65])               // a KEY inside a file session
        expect(file.receive(timeout: 3) == nil, "file e2e: non-file message closes the file session")
        file.close()

        let badHello = MRC1Client(port: directPort)
        _ = badHello?.send(type: 0x50, payload: [1, 0])              // 2 bytes: malformed
        expect(badHello != nil && badHello?.receive(timeout: 2) == nil, "file e2e: malformed HELLO gets no ACK and is closed")
        badHello?.close()

        let late = MRC1Client(port: directPort)
        _ = late?.send(type: 0x01, payload: [1, 2, 3, 4])            // PING first, then HELLO
        _ = late?.send(type: 0x50, payload: [1, 0, 0])
        let latePong = late?.receive(timeout: 2)
        expect(latePong?.type == 0x02 && late?.receive(timeout: 2) == nil, "file e2e: HELLO after another message is refused")
        late?.close()

        let relay = MRC1Client(port: relayPort)
        _ = relay?.send(type: 0x50, payload: [1, 0, 0])
        expect(relay != nil && relay?.receive(timeout: 2) == nil, "file e2e: loopback relay refuses FILE_HELLO")
        relay?.close()

        usleep(300_000)
        expect(fake.count(type: InputHelperClient.sessionStartType) == 0 && fake.snapshot().isEmpty,
               "file e2e: file sessions start no input session and inject nothing")
        let stats = servers[0].statsLine()
        expect(stats.contains("file_sessions=1 file_refused=2"), "file e2e: direct stats count 1 session, 2 refused (\(stats))")
        expect(servers[1].statsLine().contains("file_sessions=0 file_refused=1"), "file e2e: relay stats count 1 refused")
        return 0
    }

    /// r3: Cmd+V from the viewer while an upload runs and Finder is frontmost
    /// never reaches the helper (Finder would save the text clipboard as a
    /// .textClipping); the viewer's notice session gets NOTICE paste_busy.
    /// Another frontmost app, no upload running, or no viewer that shows
    /// NOTICE: Cmd+V passes as before.
    private static func finderPasteRefused(_ expect: (Bool, String) -> Void) -> Int {
        guard let helper = FakeInputHelper.start() else { expect(false, "finder paste: fake input helper listens"); return 0 }
        defer { helper.stop() }
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("jl-finder-paste-\(getpid())", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let front = FrontBox(FinderPasteGate.finderBundleID)
        let cache = InputSourceCache(backend: FakeInputSource(id: "com.apple.keylayout.US"),
                                     notification: "io.jerislink.selftest.finderpaste.\(getpid())")
        guard let (server, port) = startServer(inject: true, helperPort: helper.port, clipboard: FakeClipboard(text: nil),
                                               inputSources: cache, fileStagingRoot: root, frontmostApp: { front.get() }),
              let keys = MRC1Client(port: port), let upload = MRC1Client(port: port), let notice = MRC1Client(port: port) else {
            expect(false, "finder paste: server and sessions start")
            return 0
        }
        defer { keys.close(); upload.close(); notice.close(); server.stop() }
        typealias M = FileProto.Message
        func decoded(_ c: MRC1Client, _ timeout: Double) -> M? {
            c.receive(timeout: timeout).flatMap { FileProto.decode(type: $0.type, payload: $0.payload) }
        }
        func send(_ c: MRC1Client, _ m: M) { _ = c.send(type: m.type, payload: m.encode()!) }
        func key(_ semantic: UInt8, _ down: Bool) { _ = keys.send(type: 0x10, payload: [down ? 1 : 0, 0, semantic]) }
        func cmdV() { key(3, true); key(86, true); key(86, true); key(86, false); key(3, false) }
        let vDown = FakeInputHelper.Event(type: 0x10, payload: [1, 0, 9])
        let vUp = FakeInputHelper.Event(type: 0x10, payload: [0, 0, 9])
        var marker: UInt8 = 65
        /// Type a letter after the keys under test, so "nothing arrived" is
        /// checked once the helper has seen everything sent before it.
        @discardableResult func flush() -> Bool {
            let up = FakeInputHelper.Event(type: 0x10, payload: [0, 0, UInt8(Self.letterCode(marker))])
            let before = helper.snapshot().filter { $0 == up }.count
            key(marker, true); key(marker, false)
            wait(until: { helper.snapshot().filter { $0 == up }.count > before })
            marker += 1
            return helper.snapshot().filter { $0 == up }.count > before
        }
        func vCount() -> Int { helper.snapshot().filter { $0 == vDown || $0 == vUp }.count }
        /// What the helper and the server saw, printed only with a failure.
        func diag() -> String {
            let types = helper.snapshot().map { String($0.type, radix: 16) }.joined(separator: ",")
            return " [helper connections=\(helper.connections) max_concurrent=\(helper.maxConcurrentConnections)"
                + " events=\(types) \(server.statsLine())]"
        }
        func vMessage(_ want: Int, _ what: String) -> String {
            let got = vCount()
            return "finder paste: \(what) (\(got) V events)" + (got == want ? "" : diag())
        }

        send(notice, .hello(proto: 1, caps: FileProto.Caps.notice))
        expect(notice.receive(timeout: 3)?.type == 0x51, "finder paste: notice session HELLO_ACK")
        send(upload, .hello(proto: 1, caps: 0))
        expect(upload.receive(timeout: 3)?.type == 0x51, "finder paste: upload session HELLO_ACK")

        // The helper gets keys from this viewer before anything is tested:
        // the first key opens the input session (SESSION_START).
        let warm = flush()
        expect(warm, "finder paste: helper receives keys from the viewer" + (warm ? "" : diag()))

        // No upload yet: Cmd+V in Finder passes (a normal file paste).
        cmdV(); flush()
        expect(vCount() == 3, vMessage(3, "idle Cmd+V in Finder reaches the Mac (V down, repeat, up)"))

        // A Send to is running.
        let body = [UInt8](repeating: 7, count: 70_000)
        send(upload, .offer(transfer: 11, purpose: FileProto.Purpose.send, entries: 1, total: UInt64(body.count)))
        send(upload, FileUploadSelfTest.entry(11, 0, "big.bin", size: body.count))
        expect(decoded(upload, 3) == .reply(transfer: 11, status: FileProto.Status.ok), "finder paste: send offer accepted")
        send(upload, FileUploadSelfTest.chunks(11, 0, body)[0])

        cmdV(); flush()
        expect(vCount() == 3, vMessage(3, "Cmd+V in Finder mid-transfer never reaches the Mac"))
        let cmdPassed = helper.received(.init(type: 0x10, payload: [1, 0, 55])) && helper.received(.init(type: 0x10, payload: [0, 0, 55]))
        expect(cmdPassed, "finder paste: Command down and up still pass" + (cmdPassed ? "" : diag()))
        expect(decoded(notice, 2) == .notice(code: FileProto.Notice.pasteBusy), "finder paste: viewer gets NOTICE paste_busy")
        expect(notice.receive(timeout: 0.4) == nil, "finder paste: one NOTICE for one refused Cmd+V")
        expect(server.statsLine().contains("finder_paste_refused=1"), "finder paste: stats count the refusal")

        // Another app frontmost: text paste works mid-transfer.
        front.set("com.apple.TextEdit")
        cmdV(); flush()
        expect(vCount() == 6, vMessage(6, "Cmd+V in another app mid-transfer passes"))
        expect(notice.receive(timeout: 0.4) == nil, "finder paste: no NOTICE for another app")

        // No viewer that shows NOTICE: never eaten silently.
        front.set(FinderPasteGate.finderBundleID)
        notice.close()
        usleep(300_000)
        cmdV(); flush()
        expect(vCount() == 9, vMessage(9, "without a notice session Cmd+V passes"))

        // Upload finished (cancelled): Cmd+V in Finder passes again.
        send(upload, .cancel(transfer: 11, reason: FileProto.Status.cancelled))
        guard let again = MRC1Client(port: port) else { expect(false, "finder paste: second notice session"); return 0 }
        defer { again.close() }
        send(again, .hello(proto: 1, caps: FileProto.Caps.notice))
        expect(again.receive(timeout: 3)?.type == 0x51, "finder paste: second notice session HELLO_ACK")
        _ = upload.receive(timeout: 1)                                // RESULT cancelled, if any
        cmdV(); flush()
        expect(vCount() == 12, vMessage(12, "after the transfer Cmd+V in Finder passes"))
        expect(again.receive(timeout: 0.4) == nil, "finder paste: no NOTICE once idle")
        return 0
    }

    /// CGKeyCode the host injects for semantic A-Z (macKeyCode), for flush markers.
    private static func letterCode(_ semantic: UInt8) -> Int {
        let codes: [UInt8: Int] = [65: 0, 66: 11, 67: 8, 68: 2, 69: 14, 70: 3, 71: 5, 72: 4]
        return codes[semantic] ?? 0
    }

    /// F2 over a real socket: a paste upload lands in staging, the pasteboard
    /// gets the file URLs, the clipboard text session does not echo that
    /// change, and a dropped session removes its partial upload.
    private static func fileUploadEndToEnd(_ expect: (Bool, String) -> Void) -> Int {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("jl-upload-e2e-\(getpid())", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let board = FakeClipboard(text: "before-upload")
        let cache = InputSourceCache(backend: FakeInputSource(id: "com.apple.keylayout.US"),
                                     notification: "io.jerislink.selftest.upload.\(getpid())")
        guard let (server, port) = startServer(inject: false, helperPort: nil, clipboard: board, inputSources: cache,
                                               fileStagingRoot: root),
              let text = MRC1Client(port: port), let file = MRC1Client(port: port) else {
            expect(false, "upload e2e: server and sessions start")
            return 0
        }
        defer { text.close(); file.close(); server.stop() }
        _ = text.send(type: 0x30, payload: [])                       // CLIPBOARD_HELLO
        wait(until: { board.counts.changeCountReads >= 2 })
        _ = file.send(type: 0x50, payload: [1, 0, 0])
        expect(file.receive(timeout: 3)?.type == 0x51, "upload e2e: HELLO_ACK")

        typealias M = FileProto.Message
        let body = (0..<100_000).map { UInt8(($0 * 7) & 0xff) }
        var msgs: [M] = [.offer(transfer: 9, purpose: FileProto.Purpose.paste, entries: 1, total: UInt64(body.count)),
                         FileUploadSelfTest.entry(9, 0, "report.bin", size: body.count)]
        msgs += FileUploadSelfTest.chunks(9, 0, body)
        msgs.append(.fileEnd(transfer: 9, index: 0, sha256: FileUploadSelfTest.sha(body)))
        for m in msgs { _ = file.send(type: m.type, payload: m.encode()!) }
        var got: [M] = []
        while let p = file.receive(timeout: 5), let m = FileProto.decode(type: p.type, payload: p.payload) {
            got.append(m)
            if case .result = m { break }
        }
        expect(got.first == .reply(transfer: 9, status: FileProto.Status.ok), "upload e2e: REPLY ok")
        expect(got.last == .result(transfer: 9, status: FileProto.Status.ok, filesOK: 1), "upload e2e: RESULT ok files=1")
        let url = board.fileURLs.first
        expect(board.fileURLs.count == 1 && url.flatMap { try? Data(contentsOf: $0) }.map(Array.init) == body,
               "upload e2e: pasteboard file URL points at the staged bytes")
        expect(text.receive(timeout: 0.8) == nil, "upload e2e: clipboard session does not echo the file-URL change")
        expect(server.statsLine().contains("file_uploads=0"), "upload e2e: session stats fold in at session end")

        // A second upload dropped halfway removes its partial file.
        let half: [M] = [.offer(transfer: 10, purpose: FileProto.Purpose.paste, entries: 1, total: UInt64(body.count)),
                         FileUploadSelfTest.entry(10, 0, "half.bin", size: body.count)] + Array(FileUploadSelfTest.chunks(10, 0, body).prefix(1))
        for m in half { _ = file.send(type: m.type, payload: m.encode()!) }
        expect(file.receive(timeout: 3).flatMap { FileProto.decode(type: $0.type, payload: $0.payload) }
               == .reply(transfer: 10, status: FileProto.Status.ok), "upload e2e: second offer accepted")
        wait(until: { FileUploadSelfTest.jlparts(root) == 1 })
        file.close()
        wait(until: { FileUploadSelfTest.jlparts(root) == 0 && FileUploadSelfTest.transferDirs(root).count == 1 })
        expect(FileUploadSelfTest.jlparts(root) == 0 && FileUploadSelfTest.transferDirs(root).count == 1,
               "upload e2e: drop removes the partial upload, the finished paste stays for Finder")
        wait(until: { server.statsLine().contains("file_uploads=1 file_upload_failed=1") })
        expect(server.statsLine().contains("file_uploads=1 file_upload_failed=1 file_rx_bytes=\(body.count + 32768)"),
               "upload e2e: stats file_uploads=1 failed=1 rx bytes (\(server.statsLine()))")
        return 0
    }

    /// F4 over a real socket: a drop (purpose=send) lands in the send folder,
    /// a second drop of the same name becomes "name 2.ext", the folder opens
    /// after each, REVEAL opens it again with no reply, and staging is gone.
    private static func fileSendEndToEnd(_ expect: (Bool, String) -> Void) -> Int {
        let fm = FileManager.default
        let base = fm.temporaryDirectory.appendingPathComponent("jl-send-e2e-\(getpid())", isDirectory: true)
        defer { try? fm.removeItem(at: base) }
        try? fm.createDirectory(at: base.appendingPathComponent("Downloads"), withIntermediateDirectories: true)
        let opened = OpenedFolders()
        let folder = FileSendFolder(primary: base.appendingPathComponent("Downloads/JerisLink", isDirectory: true),
                                    fallback: base.appendingPathComponent("JerisLink Received", isDirectory: true),
                                    openFolder: { opened.add($0) })
        let staging = base.appendingPathComponent("staging", isDirectory: true)
        let board = FakeClipboard(text: "before-send")
        let cache = InputSourceCache(backend: FakeInputSource(id: "com.apple.keylayout.US"),
                                     notification: "io.jerislink.selftest.send.\(getpid())")
        guard let (server, port) = startServer(inject: false, helperPort: nil, clipboard: board, inputSources: cache,
                                               fileStagingRoot: staging, fileSendFolder: folder),
              let file = MRC1Client(port: port) else {
            expect(false, "send e2e: server and session start")
            return 0
        }
        defer { file.close(); server.stop() }
        _ = file.send(type: 0x50, payload: [1, 0, 0])
        expect(file.receive(timeout: 3)?.type == 0x51, "send e2e: HELLO_ACK")

        typealias M = FileProto.Message
        let body = (0..<70_000).map { UInt8(($0 * 13) & 0xff) }
        func drop(_ t: UInt32) -> [M] {
            var msgs: [M] = [.offer(transfer: t, purpose: FileProto.Purpose.send, entries: 1, total: UInt64(body.count)),
                             FileUploadSelfTest.entry(t, 0, "photo.jpg", size: body.count)]
            msgs += FileUploadSelfTest.chunks(t, 0, body)
            msgs.append(.fileEnd(transfer: t, index: 0, sha256: FileUploadSelfTest.sha(body)))
            for m in msgs { _ = file.send(type: m.type, payload: m.encode()!) }
            var got: [M] = []
            while let p = file.receive(timeout: 5), let m = FileProto.decode(type: p.type, payload: p.payload) {
                got.append(m)
                if case .result = m { break }
            }
            return got
        }
        let first = drop(21)
        expect(first.first == .reply(transfer: 21, status: FileProto.Status.ok) &&
               first.last == .result(transfer: 21, status: FileProto.Status.ok, filesOK: 1), "send e2e: first drop REPLY ok, RESULT ok")
        let second = drop(22)
        expect(second.last == .result(transfer: 22, status: FileProto.Status.ok, filesOK: 1), "send e2e: second drop RESULT ok")
        let dest = folder.primary
        let names = ((try? fm.contentsOfDirectory(atPath: dest.path)) ?? []).sorted()
        expect(names == ["photo 2.jpg", "photo.jpg"], "send e2e: same name twice gives photo.jpg and photo 2.jpg (\(names))")
        expect((try? Data(contentsOf: dest.appendingPathComponent("photo 2.jpg"))).map(Array.init) == body,
               "send e2e: bytes match")
        expect(board.fileURLs.isEmpty, "send e2e: a drop leaves the pasteboard alone")
        expect(FileUploadSelfTest.transferDirs(staging).isEmpty, "send e2e: no staging left after a send")
        wait(until: { opened.count == 2 })
        expect(opened.all == [dest, dest], "send e2e: the folder opens after each drop (\(opened.count))")
        _ = file.send(type: 0x5C, payload: [0, 0, 0, 21])            // REVEAL
        wait(until: { opened.count == 3 })
        expect(opened.count == 3 && opened.all.last == dest, "send e2e: REVEAL opens the folder again")
        _ = file.send(type: 0x5B, payload: [1, 2, 3, 4])
        let pong = file.receive(timeout: 3)
        expect(pong?.type == 0x5B, "send e2e: REVEAL gets no reply; the next answer is the PING echo")
        return 0
    }

    /// F3 over a real socket: a Finder copy is announced only on a session
    /// that asked for announces, the text session does not send the
    /// filename text while it is open, REQUEST pulls the bytes, and a text
    /// copy made mid-paste waits until the paste is quiet, then cancels the
    /// announce and syncs.
    private static func fileAnnounceEndToEnd(_ expect: (Bool, String) -> Void) -> Int {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("jl-announce-e2e-\(getpid())", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let src = root.appendingPathComponent("src/report.bin")
        try? FileManager.default.createDirectory(at: src.deletingLastPathComponent(), withIntermediateDirectories: true)
        let body = FileAnnounceSelfTest.body(90_000)
        FileManager.default.createFile(atPath: src.path, contents: Data(body))
        let board = FakeClipboard(text: "before-announce")
        let cache = InputSourceCache(backend: FakeInputSource(id: "com.apple.keylayout.US"),
                                     notification: "io.jerislink.selftest.announce.\(getpid())")
        guard let (server, port) = startServer(inject: false, helperPort: nil, clipboard: board, inputSources: cache,
                                               fileStagingRoot: root.appendingPathComponent("staging")),
              let text = MRC1Client(port: port), let upload = MRC1Client(port: port), let pull = MRC1Client(port: port) else {
            expect(false, "announce e2e: server and sessions start")
            return 0
        }
        defer { text.close(); upload.close(); pull.close(); server.stop() }
        typealias M = FileProto.Message
        func next(_ c: MRC1Client, _ timeout: Double = 3) -> M? {
            c.receive(timeout: timeout).flatMap { FileProto.decode(type: $0.type, payload: $0.payload) }
        }
        _ = text.send(type: 0x30, payload: [])
        _ = upload.send(type: 0x50, payload: [1, 0, 0])                                   // caps 0: uploads only
        _ = pull.send(type: 0x50, payload: [1, 0, UInt8(FileProto.Caps.announce)])
        expect(next(upload) == .helloAck(proto: 1, caps: FileProto.Caps.host, maxChunk: FileProto.maxChunk, maxTotal: FileProto.maxTotalBytes),
               "announce e2e: HELLO_ACK advertises upload|announce")
        _ = next(pull)
        wait(until: { board.counts.changeCountReads >= 6 })

        board.localCopyFiles([src])
        guard case let .offer(t, purpose, entries, total)? = next(pull) else {
            expect(false, "announce e2e: Finder copy is announced")
            return 0
        }
        expect(purpose == FileProto.Purpose.announce && entries == 1 && total == UInt64(body.count), "announce e2e: OFFER purpose=announce")
        var st = stat()
        let mtime: Int64 = lstat(src.path, &st) == 0 ? Int64(st.st_mtimespec.tv_sec) : -1
        expect(next(pull) == .entry(transfer: t, index: 0, kind: FileProto.EntryKind.file, size: UInt64(body.count),
                                    mtime: mtime, path: Array("report.bin".utf8)),
               "announce e2e: ENTRY with the name, size and mtime")
        expect(upload.receive(timeout: 0.5) == nil, "announce e2e: a session without the announce cap gets nothing")
        expect(text.receive(timeout: 0.5) == nil, "announce e2e: text session does not send the filename text")

        // Explorer pulls in parts. A Mac copy between two parts (F3 r3,
        // Morris's Cmd+C mid-paste) must not cut the paste off: no CANCEL,
        // the next part is served, and the Windows clipboard is not touched.
        let half = body.count / 2
        _ = pull.send(type: FileProto.MsgType.request, payload: M.request(transfer: t, index: 0, offset: 0, length: UInt32(half)).encode()!)
        var got: [UInt8] = []
        var end: M?
        while got.count < half, let m = next(pull) {
            if case let .data(_, _, off, b) = m, off == UInt64(got.count) { got += b }
        }
        expect(got.count == half, "announce e2e: the first part arrives")
        board.localCopy("plain text")
        expect(pull.receive(timeout: 1) == nil, "announce e2e: a Mac copy mid-paste sends no CANCEL")
        expect(text.receive(timeout: 0.5) == nil, "announce e2e: and does not replace the Windows clipboard mid-paste")
        _ = pull.send(type: FileProto.MsgType.request,
                      payload: M.request(transfer: t, index: 0, offset: UInt64(half), length: UInt32(body.count - half)).encode()!)
        while let m = next(pull) {
            if case let .data(_, _, off, b) = m, off == UInt64(got.count) { got += b }
            if case .fileEnd = m { end = m; break }
            if case .reply = m { break }
        }
        expect(got == body && end == .fileEnd(transfer: t, index: 0, sha256: FileUploadSelfTest.sha(body)),
               "announce e2e: the rest is served after the Mac copy, bytes and FILE_END match")

        // Once the paste is quiet the waiting copy goes through.
        expect(next(pull, ControlServer.pullHoldSeconds + 3) == .cancel(transfer: t, reason: FileProto.Status.cancelled),
               "announce e2e: after the paste, the text copy cancels the announce")
        expect(text.receive(timeout: ControlServer.pullHoldSeconds + 3)?.payload == Array("plain text".utf8),
               "announce e2e: and the text then syncs")
        pull.close()
        wait(until: { server.statsLine().contains("file_announces=1 file_pulls=1 file_tx_bytes=\(body.count)") })
        expect(server.statsLine().contains("file_announces=1 file_pulls=1 file_tx_bytes=\(body.count)"),
               "announce e2e: stats (\(server.statsLine()))")
        return 0
    }

    /// r5: pushes go to the newest push-capable session that is still
    /// heard from. A second viewer window on the same PC can leave the
    /// first one's pull session open but silent; the broker skips it.
    private static func pushBrokerRouting(_ expect: (Bool, String) -> Void) {
        final class Clock: @unchecked Sendable { var t: Double = 1000 }
        let clock = Clock()
        let broker = PushBroker(now: { clock.t })
        let push = FileProto.Caps.pushService
        func job() -> PushJob { PushJob(files: []) }
        /// Offers a job; returns the session that took it, or the answer.
        func route() -> (UInt64?, SendWire.Reply?) {
            let j = job()
            if let r = broker.offer(j) { return (nil, r) }
            for id in UInt64(1)...20 {
                if let got = broker.take(session: id) { broker.finished(got); return (id, nil) }
            }
            return (nil, nil)
        }

        expect(route().1 == .notConnected, "push route: no session is not_connected")
        let a = broker.register(peerCaps: push)
        let up = broker.register(peerCaps: 0)
        expect(route().0 == a, "push route: a fresh push session takes the push")
        clock.t += PushBroker.liveSeconds - 1
        expect(route().0 == a, "push route: a session quiet for less than the live window still takes it")
        clock.t += 2
        expect(route().1 == .notConnected, "push route: a push session quiet past the live window is not_connected")
        broker.heard(up)
        expect(route().1 == .notConnected, "push route: a live caps-0 session does not make a quiet push session live")
        broker.heard(a)
        expect(route().0 == a, "push route: a PING makes the session live again")

        // A second viewer's pull session opens later, then goes quiet; the
        // older one keeps pinging and gets the push.
        let b = broker.register(peerCaps: push)
        expect(route().0 == b, "push route: the newest live push session wins")
        clock.t += 20; broker.heard(a)
        clock.t += 20; broker.heard(a)
        expect(route().0 == a, "push route: a newer but quiet session is skipped for an older live one")
        broker.heard(b)
        expect(route().0 == b, "push route: once heard again the newer session wins again")
        broker.unregister(b)
        broker.unregister(a)
        expect(route().1 == .oldViewer, "push route: only a caps-0 session left is old_viewer")
        broker.unregister(up)
        expect(broker.sessionCount == 0 && broker.isIdle, "push route: the broker is empty and idle")
    }

    /// F5b over real sockets: the send socket hands open files to the
    /// newest file session, which pushes them (OFFER purpose=push) and
    /// serves the viewer's REQUESTs. No session, an old viewer, a second
    /// push, an untrusted peer, a bad name and a folder each get their answer.
    private static func filePushEndToEnd(_ expect: (Bool, String) -> Void) -> Int {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("jl-push-e2e-\(getpid())", isDirectory: true)
        let sockDir = "/tmp/jlps-\(getpid())"
        defer { try? FileManager.default.removeItem(at: root); try? FileManager.default.removeItem(atPath: sockDir) }
        try? FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let body = FileAnnounceSelfTest.body(70_000, seed: 5)
        let bigPath = root.appendingPathComponent("a.bin").path
        let emptyPath = root.appendingPathComponent("empty.txt").path
        FileManager.default.createFile(atPath: bigPath, contents: Data(body))
        FileManager.default.createFile(atPath: emptyPath, contents: Data())

        let broker = PushBroker()
        let socket = SendSocketServer(path: sockDir + "/send.sock", broker: broker, peerCheck: { _ in true })
        let refusing = SendSocketServer(path: sockDir + "/refuse.sock", broker: broker, peerCheck: { _ in false })
        do { try socket.start(); try refusing.start() } catch {
            expect(false, "push e2e: send sockets start (\(error.localizedDescription))")
            return 0
        }
        defer { socket.stop(); refusing.stop() }
        var st = stat()
        expect(lstat(sockDir, &st) == 0 && (st.st_mode & 0o777) == 0o700, "push e2e: socket folder is 0700")
        expect(lstat(socket.path, &st) == 0 && (st.st_mode & 0o777) == 0o600 && (st.st_mode & S_IFMT) == S_IFSOCK,
               "push e2e: socket is 0600")

        let sockPath = socket.path
        func submit(_ paths: [String], names: [String]? = nil, path: String? = nil) -> String? {
            pushSubmit(paths, names: names, path: path ?? sockPath)
        }
        final class Box: @unchecked Sendable { var reply: String?; let done = DispatchSemaphore(value: 0) }
        func submitAsync(_ paths: [String]) -> Box {
            let box = Box()
            Thread.detachNewThread { box.reply = pushSubmit(paths, names: nil, path: sockPath); box.done.signal() }
            return box
        }

        expect(submit([bigPath], path: refusing.path) == nil, "push e2e: an untrusted peer is closed with no reply")
        expect(refusing.refusedPeers == 1, "push e2e: the refusal is counted")
        expect(submit([bigPath]) == "not_connected", "push e2e: no viewer session answers not_connected")

        let board = FakeClipboard(text: "before-push")
        let cache = InputSourceCache(backend: FakeInputSource(id: "com.apple.keylayout.US"),
                                     notification: "io.jerislink.selftest.push.\(getpid())")
        guard let port = freeLoopbackPort() else { expect(false, "push e2e: free port"); return 0 }
        let server = ControlServer(bindIP: ListenConfig.loopbackIP, allowedClientIP: ListenConfig.loopbackIP,
                                   port: port, inject: false,
                                   settingsClientIP: { ListenConfig.loopbackIP }, acceptProxy: false,
                                   inputHelper: nil, allowFileSessions: true,
                                   fileStagingRoot: root.appendingPathComponent("staging"),
                                   clipboard: board, inputSources: cache, pushBroker: broker,
                                   frontmostApp: { nil })
        do { try server.start() } catch { expect(false, "push e2e: server starts"); return 0 }
        defer { server.stop() }
        typealias M = FileProto.Message
        func next(_ c: MRC1Client, _ timeout: Double = 3) -> M? {
            c.receive(timeout: timeout).flatMap { FileProto.decode(type: $0.type, payload: $0.payload) }
        }

        guard let old = MRC1Client(port: port) else { expect(false, "push e2e: old viewer connects"); return 0 }
        _ = old.send(type: 0x50, payload: [1, 0, UInt8(FileProto.Caps.upload)])
        expect(next(old) == .helloAck(proto: 1, caps: FileProto.Caps.host, maxChunk: FileProto.maxChunk, maxTotal: FileProto.maxTotalBytes),
               "push e2e: HELLO_ACK advertises the push service")
        wait(until: { broker.sessionCount == 1 })
        expect(submit([bigPath]) == "old_viewer", "push e2e: a viewer without the push cap answers old_viewer")
        // r4: keep this caps-0 session open. The viewer opens a caps-0
        // upload session and a push-capable pull session in either order;
        // `old` connects before the pull session, `upload` after it.
        defer { old.close() }

        guard let pull = MRC1Client(port: port) else { expect(false, "push e2e: viewer connects"); return 0 }
        defer { pull.close() }
        _ = pull.send(type: 0x50, payload: [1, 0, UInt8(FileProto.Caps.pushService)])
        _ = next(pull)
        wait(until: { broker.sessionCount == 2 })
        guard let upload = MRC1Client(port: port) else { expect(false, "push e2e: upload session connects"); return 0 }
        defer { upload.close() }
        _ = upload.send(type: 0x50, payload: [1, 0, 0])
        _ = next(upload)
        wait(until: { broker.sessionCount == 3 })
        expect(submit([emptyPath], names: ["a/b"]) == "bad_name", "push e2e: a name with a slash is refused")
        expect(submit([emptyPath], names: [".."]) == "bad_name", "push e2e: a dot name is refused")
        expect(submit([root.path], names: ["folder"]) == "bad_name", "push e2e: a folder descriptor is refused")
        expect(pull.receive(timeout: 0.3) == nil, "push e2e: refused batches send nothing to the viewer")

        // A push: OFFER + ENTRYs, REPLY ok, then the files by REQUEST.
        let first = submitAsync([bigPath, emptyPath])
        guard case let .offer(t, purpose, entries, total)? = next(pull) else {
            expect(false, "push e2e: OFFER arrives")
            return 0
        }
        expect(purpose == FileProto.Purpose.push && entries == 2 && total == UInt64(body.count) && t & 0x8000_0001 == 0x8000_0000,
               "push e2e: OFFER purpose=push, 2 entries, even id with the top bit")
        _ = lstat(bigPath, &st)
        expect(next(pull) == .entry(transfer: t, index: 0, kind: FileProto.EntryKind.file, size: UInt64(body.count),
                                    mtime: Int64(st.st_mtimespec.tv_sec), path: Array("a.bin".utf8)),
               "push e2e: ENTRY 0 with name, size and mtime")
        guard case let .entry(_, 1, _, 0, _, name1)? = next(pull) else { expect(false, "push e2e: ENTRY 1"); return 0 }
        expect(name1 == Array("empty.txt".utf8), "push e2e: ENTRY 1 is the empty file")
        expect(submit([bigPath]) == "busy", "push e2e: a second push while one runs answers busy")
        _ = pull.send(type: FileProto.MsgType.reply, payload: M.reply(transfer: t, status: FileProto.Status.ok).encode()!)
        expect(first.done.wait(timeout: .now() + 5) == .success && first.reply == "ok", "push e2e: the helper hears ok after REPLY ok")

        var got: [UInt8] = []
        var end: M?
        for off in stride(from: 0, to: body.count, by: 40_000) {
            let len = min(40_000, body.count - off)
            _ = pull.send(type: FileProto.MsgType.request,
                          payload: M.request(transfer: t, index: 0, offset: UInt64(off), length: UInt32(len)).encode()!)
        }
        while let m = next(pull) {
            if case let .data(_, 0, o, b) = m, o == UInt64(got.count) { got += b }
            if case .fileEnd = m { end = m; break }
            if case .reply = m { break }
        }
        expect(got == body && end == .fileEnd(transfer: t, index: 0, sha256: FileUploadSelfTest.sha(body)),
               "push e2e: file 0 bytes and FILE_END match")
        _ = pull.send(type: FileProto.MsgType.request, payload: M.request(transfer: t, index: 1, offset: 0, length: 0).encode()!)
        expect(next(pull) == .fileEnd(transfer: t, index: 1, sha256: FileUploadSelfTest.sha([])),
               "push e2e: the empty file gets FILE_END at once")
        _ = pull.send(type: FileProto.MsgType.result, payload: M.result(transfer: t, status: FileProto.Status.ok, filesOK: 2).encode()!)
        wait(until: { broker.isIdle })
        expect(broker.isIdle, "push e2e: RESULT ends the push")

        // A refusal from the viewer reaches the helper; an out-of-order
        // REQUEST is refused.
        let second = submitAsync([bigPath])
        guard case let .offer(t2, _, _, _)? = next(pull) else { expect(false, "push e2e: second OFFER"); return 0 }
        _ = next(pull)
        _ = pull.send(type: FileProto.MsgType.reply, payload: M.reply(transfer: t2, status: FileProto.Status.noSpace).encode()!)
        expect(second.done.wait(timeout: .now() + 5) == .success && second.reply == "no_space",
               "push e2e: a viewer refusal reaches the helper (no_space)")
        let third = submitAsync([bigPath])
        guard case let .offer(t3, _, _, _)? = next(pull) else { expect(false, "push e2e: third OFFER"); return 0 }
        _ = next(pull)
        _ = pull.send(type: FileProto.MsgType.reply, payload: M.reply(transfer: t3, status: FileProto.Status.ok).encode()!)
        _ = third.done.wait(timeout: .now() + 5)
        _ = pull.send(type: FileProto.MsgType.request, payload: M.request(transfer: t3, index: 0, offset: 100, length: 10).encode()!)
        expect(next(pull) == .reply(transfer: t3, status: FileProto.Status.failed), "push e2e: an out-of-order REQUEST is refused")
        wait(until: { broker.isIdle })
        expect(broker.isIdle, "push e2e: and the push ends")

        // The session closing mid-push lets go of the files.
        let fourth = submitAsync([bigPath])
        guard case .offer? = next(pull) else { expect(false, "push e2e: fourth OFFER"); return 0 }
        pull.close()
        expect(fourth.done.wait(timeout: .now() + 5) == .success && fourth.reply == "not_connected",
               "push e2e: a session closing before REPLY answers not_connected")
        wait(until: { broker.isIdle })
        expect(broker.isIdle, "push e2e: the broker is idle after the session closed")
        wait(until: { broker.sessionCount == 2 })
        expect(submit([bigPath]) == "old_viewer", "push e2e: with only caps-0 sessions left the push answers old_viewer")
        wait(until: { server.statsLine().contains("file_pushes=4") })
        expect(server.statsLine().contains("file_pushes=4"), "push e2e: stats (\(server.statsLine()))")

        // The real peer check never trusts this test process.
        var pair: [Int32] = [-1, -1]
        if socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 {
            expect(!SendSocketServer.isTrustedHelper(pair[0]), "push e2e: the signature check refuses a process that is not the helper")
            Darwin.close(pair[0]); Darwin.close(pair[1])
        }
        expect(SendSocketServer.requirement.contains("identifier \"org.jeris.jerislink.send\"")
               && SendSocketServer.requirement.contains("leaf[subject.OU] = \"DD6947X9AG\""),
               "push e2e: the requirement names the helper and the team")
        return 0
    }

    /// Opens the paths like the helper and submits them; closes its copies.
    private static func pushSubmit(_ paths: [String], names: [String]?, path: String) -> String? {
        let fds = paths.map { open($0, O_RDONLY | O_CLOEXEC) }
        defer { fds.forEach { if $0 >= 0 { Darwin.close($0) } } }
        let leafs = names ?? paths.map { ($0 as NSString).lastPathComponent }
        return SendWire.submit(zip(leafs, fds).map { (name: Array($0.0.utf8), fd: $0.1) }, path: path, timeout: 15)
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
        lock.lock(); count += 1; text = value; copied = nil; lock.unlock()
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

    private var urls: [URL] = []
    private var fileMark: Int?
    var fileURLs: [URL] { lock.lock(); defer { lock.unlock() }; return urls }

    /// Like NSPasteboard: file URLs also read back as a string.
    func writeFileURLs(_ value: [URL]) -> Int? {
        lock.lock(); defer { lock.unlock() }
        urls = value
        count += 1
        text = value.first?.path
        fileMark = count
        return count
    }

    func ownFileWriteChangeCount() -> Int? {
        lock.lock(); defer { lock.unlock() }
        return fileMark
    }

    private var copied: [URL]?

    /// A Finder copy on the Mac itself: file URLs plus the filename text.
    func localCopyFiles(_ value: [URL]) {
        lock.lock(); count += 1; copied = value; text = value.first?.lastPathComponent; lock.unlock()
    }

    func readFileURLs() -> [URL]? {
        lock.lock(); defer { lock.unlock() }
        return copied
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
    /// Signalled when the accept loop has closed the listening socket.
    private let loopDone = DispatchSemaphore(value: 0)

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

    /// Only the accept loop closes the listening socket, after its last
    /// accept(). Closing it here while the loop could still call accept()
    /// let the next FakeInputHelper reuse the descriptor number, and the
    /// stopped helper's loop then took that helper's connections (events
    /// recorded on the wrong helper, depending on timing). stop() ends the
    /// served connection, wakes a blocked accept() and waits for the loop,
    /// so the port is free again when it returns.
    func stop() {
        lock.lock(); stopping = true; let c = current; lock.unlock()
        if c >= 0 { Darwin.shutdown(c, SHUT_RDWR) }
        let wake = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        if wake >= 0 {
            var addr = ControlServiceSelfTest.loopbackAddress(port: port)
            _ = withUnsafePointer(to: &addr) { p in
                p.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(wake, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
            }
            Darwin.close(wake)
        }
        _ = loopDone.wait(timeout: .now() + 3)
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
        defer {
            Darwin.close(listenFD)
            loopDone.signal()
        }
        while true {
            lock.lock(); let stopped = stopping; lock.unlock()
            if stopped { return }
            let c = Darwin.accept(listenFD, nil, nil)
            if c < 0 { continue }
            lock.lock()
            if stopping {                    // stop()'s wake-up connection
                lock.unlock()
                Darwin.close(c)
                return
            }
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

/// The frontmost app the finder-paste self-test pretends to have.
private final class FrontBox: @unchecked Sendable {
    private let lock = NSLock()
    private var id: String?
    init(_ id: String?) { self.id = id }
    func set(_ value: String?) { lock.lock(); id = value; lock.unlock() }
    func get() -> String? { lock.lock(); defer { lock.unlock() }; return id }
}
