import Foundation
import Darwin

/// `JerisLinkHost --self-test` part for the v0.4.0 connection password
/// (PR-A): crypto against known answers and auth_vectors.json, password
/// rules, the lockout ladder, the host-wide wait, the blacklist in
/// listen.plist, migration, and the AUTH handshake end to end on loopback.
/// Nothing touches the real listen.plist; the Keychain only with
/// JERISLINK_SELFTEST_KEYCHAIN=1, under a throwaway service name.
enum AuthSelfTest {
    static func run() -> Int32 {
        var failures = 0
        func expect(_ ok: Bool, _ name: String) {
            print("\(ok ? "PASS" : "FAIL") auth: \(name)")
            if !ok { failures += 1 }
        }
        crypto(expect)
        rules(expect)
        ladder(expect)
        blocklist(expect)
        policy(expect)
        migration(expect)
        keychain(expect)
        endToEnd(expect)
        return failures == 0 ? 0 : 1
    }

    typealias Expect = (Bool, String) -> Void

    // MARK: Crypto

    private static func crypto(_ expect: Expect) {
        let u = { (s: String) in Array(s.utf8) }
        // RFC 4231 test case 2; PBKDF2-HMAC-SHA256 published answers.
        expect(ConnAuth.hex(ConnAuth.hmac(u("Jefe"), [u("what do ya want for nothing?")]))
               == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", "HMAC-SHA256 RFC 4231 case 2")
        expect(ConnAuth.deriveKey(password: "password", salt: u("salt"), iterations: 1).map(ConnAuth.hex)
               == "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b", "PBKDF2-SHA256 c=1")
        expect(ConnAuth.deriveKey(password: "password", salt: u("salt"), iterations: 2).map(ConnAuth.hex)
               == "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43", "PBKDF2-SHA256 c=2")
        expect(ConnAuth.normalizedPassword("Cafe\u{301}") == Array("Caf\u{e9}".utf8), "password is NFC before PBKDF2")

        guard let path = ProcessInfo.processInfo.environment["JERISLINK_AUTH_VECTORS"] else {
            print("SKIP auth: auth_vectors.json (JERISLINK_AUTH_VECTORS not set)")
            return
        }
        guard let data = FileManager.default.contents(atPath: path),
              let doc = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let vectors = doc["vectors"] as? [[String: Any]], !vectors.isEmpty else {
            expect(false, "auth_vectors.json readable at \(path)")
            return
        }
        for v in vectors {
            let name = v["name"] as? String ?? "?"
            func b(_ k: String) -> [UInt8] { (v[k] as? String).flatMap(ConnAuth.unhex) ?? [] }
            guard let password = v["password"] as? String, let iter = v["iterations"] as? Int,
                  let chanName = v["channel"] as? String,
                  let channel = [ConnAuth.Channel.control, .clipboard, .file, .ping].first(where: { $0.name == chanName }) else {
                expect(false, "vector \(name) fields")
                continue
            }
            let key = ConnAuth.deriveKey(password: password, salt: b("salt"), iterations: UInt32(iter)) ?? []
            let hn = b("host_nonce"), cn = b("client_nonce"), hid = b("host_id"), sid = b("session_id")
            expect(ConnAuth.normalizedPassword(password) == b("password_nfc_utf8"), "vector \(name): NFC bytes")
            expect(key == b("key"), "vector \(name): K")
            let macC = ConnAuth.macClient(key: key, hostNonce: hn, clientNonce: cn, channel: channel, hostID: hid)
            expect(macC == b("mac_c"), "vector \(name): mac_c")
            expect(ConnAuth.macHost(key: key, hostNonce: hn, clientNonce: cn, channel: channel) == b("mac_h"), "vector \(name): mac_h")
            expect(ConnAuth.matchChannel(mac: macC, key: key, hostNonce: hn, clientNonce: cn, hostID: hid) == channel,
                   "vector \(name): host finds channel \(chanName)")
            let ks = ConnAuth.sessionKey(key: key, hostNonce: hn, clientNonce: cn, sessionID: sid)
            expect(ks == b("session_key"), "vector \(name): session key")
            expect(ConnAuth.udpTag(sessionKey: ks, hostToViewer: false, packet: b("udp_v2h_packet")) == b("udp_v2h_tag")
                   && ConnAuth.udpTag(sessionKey: ks, hostToViewer: true, packet: b("udp_h2v_packet")) == b("udp_h2v_tag"),
                   "vector \(name): UDP tags")
            let challenge = ConnAuth.Challenge(hostNonce: hn, salt: b("salt"), iterations: UInt32(iter), kdfID: 1, hostID: hid)
            expect(challenge.payload == b("challenge_payload") && ConnAuth.Challenge.decode(b("challenge_payload")) == challenge,
                   "vector \(name): CHALLENGE payload")
            expect(ConnAuth.Response(clientNonce: cn, mac: macC).payload == b("response_payload"), "vector \(name): RESPONSE payload")
            let ok = ConnAuth.Result.ok(macH: b("mac_h"), sessionID: sid)
            expect(ok.payload == b("result_ok_payload") && ConnAuth.Result.decode(ok.payload) == ok, "vector \(name): RESULT ok payload")
        }
    }

    // MARK: Password rules

    private static func rules(_ expect: Expect) {
        expect(ConnAuth.passwordProblems("Abcdefgh!1").isEmpty, "rules: 10 chars, upper, lower, symbol accepted")
        expect(ConnAuth.passwordProblems("Abcdefg!1") == [.tooShort], "rules: 9 chars refused")
        expect(ConnAuth.passwordProblems("abcdefgh!1") == [.noUpper], "rules: no uppercase refused")
        expect(ConnAuth.passwordProblems("ABCDEFGH!1") == [.noLower], "rules: no lowercase refused")
        expect(ConnAuth.passwordProblems("Abcdefgh 12") == [.noSymbol], "rules: space and digits are not symbols")
        expect(ConnSecret.make(password: "short") == nil, "rules: no secret for a refused password")
    }

    // MARK: Lockout ladder and host-wide wait (fake clock)

    private final class Clock: @unchecked Sendable { var t: TimeInterval = 1000 }

    private static func ladder(_ expect: Expect) {
        let clock = Clock()
        let store = MemoryBlocklist()
        let g = AuthGuard(whitelist: [], blocklist: store, now: { clock.t })
        let ip = "100.64.0.7"
        func fail(_ n: Int) -> AuthGuard.FailureOutcome? {
            var last: AuthGuard.FailureOutcome?
            for _ in 0..<n { last = g.recordFailure(ip).outcome; clock.t += 61 }  // stay under the host-wide rate
            return last
        }
        expect(fail(4) == .retry(triesLeft: 1), "ladder: 4th failure leaves 1 try")
        expect(fail(1) == .locked(retrySeconds: 300, stage: 1), "ladder: 5 failures lock 5 min")
        expect(g.admit(ip) == .locked(retrySeconds: 300 - 61, stage: 1), "ladder: locked IP gets no challenge")
        clock.t += 300
        expect(g.admit(ip) == .challenge, "ladder: challenge again after the wait")
        expect(fail(5) == .locked(retrySeconds: 600, stage: 2), "ladder: 10 failures lock 10 min")
        clock.t += 600
        expect(fail(5) == .locked(retrySeconds: 900, stage: 3), "ladder: 15 failures lock 15 min")
        clock.t += 900
        expect(fail(5) == .blacklisted, "ladder: 20 failures blacklist")
        expect(g.admit(ip) == .blocked && store.load().map(\.ip) == [ip], "ladder: blacklisted IP is stored")

        let other = "100.64.0.8"
        _ = g.recordFailure(other); _ = g.recordFailure(other)
        g.recordSuccess(other)
        expect(g.failures(other) == 0, "ladder: success clears the count")

        let wl = AuthGuard(whitelist: ["100.64.0.9"], blocklist: MemoryBlocklist([BlockedEntry(ip: "100.64.0.9", at: Date(), reason: "t")]))
        expect(wl.admit("100.64.0.9") == .blocked, "blacklist wins over the whitelist")
        expect(wl.admit("100.64.0.10") == .notAllowed, "whitelist refuses others before any challenge")

        let gc = Clock()
        let host = AuthGuard(whitelist: [], blocklist: MemoryBlocklist(), now: { gc.t })
        var triggered = false
        for i in 0..<20 {
            let r = host.recordFailure("100.64.1.\(i)")   // 20 IPs, one failure each
            triggered = triggered || r.globalTriggered
            gc.t += 2
        }
        host.recordSuccess("100.64.1.0")
        expect(triggered && host.admit("100.64.2.1") == .globalLocked(retrySeconds: 300 - 2),
               "host-wide: 20 failures in a minute stop every IP for 5 min, success does not clear it")
        gc.t += 300
        expect(host.admit("100.64.2.1") == .challenge, "host-wide: open again after 5 min")

        let slow = Clock()
        let spread = AuthGuard(whitelist: [], blocklist: MemoryBlocklist(), now: { slow.t })
        var spreadTriggered = false
        for i in 0..<20 { spreadTriggered = spreadTriggered || spread.recordFailure("100.64.3.\(i)").globalTriggered; slow.t += 4 }
        expect(!spreadTriggered, "host-wide: 20 failures over 80 s do not trigger")
    }

    // MARK: Blacklist in listen.plist

    private static func tempDir() -> URL {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("jl-auth-selftest-\(UUID().uuidString)")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    private static func writePlist(_ dict: [String: Any], _ url: URL) {
        if let d = try? PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0) { try? d.write(to: url) }
    }

    private static func readPlist(_ url: URL) -> [String: Any]? {
        guard let d = try? Data(contentsOf: url) else { return nil }
        return (try? PropertyListSerialization.propertyList(from: d, options: [], format: nil)) as? [String: Any]
    }

    private static func blocklist(_ expect: Expect) {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("listen.plist")
        writePlist(["bindIP": "100.64.0.1", "clientIP": "100.64.0.2", "allowedIPs": ["100.64.0.2"]], url)
        let clock = Clock()
        let g = AuthGuard(whitelist: [], blocklist: ListenPlistBlocklist(url: url), now: { clock.t })
        for _ in 0..<20 { _ = g.recordFailure("100.64.0.7"); clock.t += 61 }
        let reloaded = AuthGuard(whitelist: [], blocklist: ListenPlistBlocklist(url: url))
        let saved = readPlist(url)
        expect(reloaded.admit("100.64.0.7") == .blocked, "blacklist survives a restart (listen.plist)")
        expect(saved?["bindIP"] as? String == "100.64.0.1" && saved?["clientIP"] as? String == "100.64.0.2",
               "blacklist write keeps the other listen.plist keys")
        expect(reloaded.blockedEntries.first?.reason == "20 wrong passwords", "blacklist entry has its reason")
        expect(reloaded.release("100.64.0.7") && AuthGuard(whitelist: [], blocklist: ListenPlistBlocklist(url: url)).admit("100.64.0.7") == .challenge,
               "release removes the IP and is saved")
        let missing = dir.appendingPathComponent("absent.plist")
        expect(!ListenPlistBlocklist(url: missing).save([BlockedEntry(ip: "100.64.0.7", at: Date(), reason: "t")])
               && !FileManager.default.fileExists(atPath: missing.path), "no listen.plist: the blacklist never creates one")
    }

    // MARK: Policy and migration

    private static func policy(_ expect: Expect) {
        expect(AuthPolicy.resolve(plist: ["clientIP": "100.64.0.2"], clientIP: "100.64.0.2", secretLoaded: false)
               == .transition(whitelist: ["100.64.0.2"]), "policy: no password = transition on clientIP")
        expect(AuthPolicy.resolve(plist: ["allowedIPs": ["100.64.0.3"], "passwordSet": true], clientIP: "100.64.0.2", secretLoaded: true)
               == .password(whitelist: ["100.64.0.3"]), "policy: password with allowedIPs")
        expect(AuthPolicy.resolve(plist: ["passwordSet": true], clientIP: "100.64.0.2", secretLoaded: false)
               == .refused(reason: "password_unreadable"), "policy: passwordSet without Keychain item refuses")
        expect(AuthPolicy.resolve(plist: ["allowedIPs": [String]()], clientIP: nil, secretLoaded: false)
               == .refused(reason: "no_password_no_ip"), "policy: no password and no IP refuses")
    }

    private static func migration(_ expect: Expect) {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("listen.plist")
        writePlist(["bindIP": "100.64.0.1", "clientIP": "100.64.0.2"], url)
        let original = try? Data(contentsOf: url)
        let first = ListenMigration.migrate(url: url)
        let after = readPlist(url)
        let backup = URL(fileURLWithPath: url.path + ".pre-0.4")
        expect(first?.hasPrefix("config.migrated allowed_ips=1") == true, "migration: logs config.migrated")
        expect(after?["allowedIPs"] as? [String] == ["100.64.0.2"] && after?["passwordSet"] as? Bool == false
               && after?["clientIP"] as? String == "100.64.0.2", "migration: allowedIPs=[clientIP], passwordSet=false, clientIP kept")
        expect((try? Data(contentsOf: backup)) == original, "migration: listen.plist.pre-0.4 is the old file")
        expect(ListenMigration.migrate(url: url) == nil, "migration: runs once")
    }

    // MARK: Keychain (opt-in)

    private static func keychain(_ expect: Expect) {
        guard ProcessInfo.processInfo.environment["JERISLINK_SELFTEST_KEYCHAIN"] == "1" else {
            print("SKIP auth: Keychain round trip (JERISLINK_SELFTEST_KEYCHAIN not 1)")
            return
        }
        let store = KeychainSecretStore(service: "org.jeris.jerislink.connpw.selftest.\(UUID().uuidString)")
        defer { store.delete() }
        guard let secret = ConnSecret.make(password: "Selftest-Only-\(UUID().uuidString.prefix(6))", iterations: 1000) else {
            expect(false, "keychain: secret made")
            return
        }
        expect(store.save(secret) && store.load() == secret, "keychain: K, salt, iterations, host id round trip")
        expect(store.delete() && store.load() == nil, "keychain: item deleted")
    }

    // MARK: End to end on loopback

    private static func endToEnd(_ expect: Expect) {
        let password = "Loopback-\(UUID().uuidString.prefix(8))!"
        guard let secret = ConnSecret.make(password: password, iterations: 1000) else {
            expect(false, "e2e: secret made")
            return
        }
        let me = ListenConfig.loopbackIP

        func server(_ policy: AuthPolicy, secret: ConnSecret?, blocked: [String] = [], timeout: TimeInterval = 2) -> (ControlServer, UInt16)? {
            guard let port = ControlServiceSelfTest.freeLoopbackPort() else { return nil }
            let whitelist: [String]
            switch policy {
            case .password(let w), .transition(let w): whitelist = w
            case .refused: whitelist = []
            }
            let store = MemoryBlocklist(blocked.map { BlockedEntry(ip: $0, at: Date(), reason: "t") })
            let gate = AuthGate(policy: policy, guardian: AuthGuard(whitelist: whitelist, blocklist: store),
                                secret: secret, timeout: timeout)
            let s = ControlServer(bindIP: me, allowedClientIP: nil, port: port, inject: false,
                                  settingsClientIP: { me }, acceptProxy: false, inputHelper: nil,
                                  clipboard: FakeClipboard(text: nil), authGate: gate)
            guard (try? s.start()) != nil else { return nil }
            return (s, port)
        }

        /// Connects, reads the CHALLENGE and answers it for `channel`.
        func login(_ port: UInt16, password: String, channel: ConnAuth.Channel, replay: [UInt8]? = nil)
            -> (client: MRC1Client?, result: ConnAuth.Result?, response: [UInt8]?, macOK: Bool) {
            guard let c = MRC1Client(port: port), let ch = c.receive(timeout: 2) else { return (nil, nil, nil, false) }
            guard ch.type == ConnAuth.MsgType.challenge, let challenge = ConnAuth.Challenge.decode(ch.payload),
                  let key = ConnAuth.deriveKey(password: password, salt: challenge.salt, iterations: challenge.iterations) else {
                return (c, ch.type == ConnAuth.MsgType.result ? ConnAuth.Result.decode(ch.payload) : nil, nil, false)
            }
            let cn = ConnAuth.random(ConnAuth.nonceBytes)
            let mac = ConnAuth.macClient(key: key, hostNonce: challenge.hostNonce, clientNonce: cn, channel: channel, hostID: challenge.hostID)
            let response = replay ?? ConnAuth.Response(clientNonce: cn, mac: mac).payload
            _ = c.send(type: ConnAuth.MsgType.response, payload: response)
            guard let r = c.receive(timeout: 3), r.type == ConnAuth.MsgType.result else { return (c, nil, response, false) }
            let result = ConnAuth.Result.decode(r.payload)
            var macOK = false
            if case .ok(let macH, _) = result {
                macOK = ConnAuth.constantTimeEqual(macH, ConnAuth.macHost(key: key, hostNonce: challenge.hostNonce, clientNonce: cn, channel: channel))
            }
            return (c, result, response, macOK)
        }
        func pong(_ c: MRC1Client?) -> Bool {
            guard let c, c.send(type: 0x01, payload: [9, 8, 7, 6]), let r = c.receive(timeout: 2) else { return false }
            return r.type == 0x02 && r.payload == [9, 8, 7, 6]
        }

        // Password mode.
        guard case let (pw, port)? = server(.password(whitelist: [me]), secret: secret, timeout: 0.5) else {
            expect(false, "e2e: password listener starts")
            return
        }
        defer { pw.stop() }
        let good = login(port, password: password, channel: .control)
        if case .ok = good.result { expect(good.macOK, "e2e: right password gets ok with a valid mac_h") }
        else { expect(false, "e2e: right password gets ok with a valid mac_h") }
        expect(pong(good.client), "e2e: authenticated control channel answers PING")
        let replay = login(port, password: password, channel: .control, replay: good.response)
        expect(replay.result == .fail(triesLeft: 4), "e2e: replayed RESPONSE is refused (new host nonce)")

        let cross = login(port, password: password, channel: .control)
        _ = cross.client?.send(type: 0x30, payload: [0, 1])
        expect(!pong(cross.client), "e2e: CLIPBOARD_HELLO on a control login closes the connection")
        let pingChan = login(port, password: password, channel: .ping)
        expect(pong(pingChan.client), "e2e: ping channel answers PING")
        _ = pingChan.client?.send(type: 0x10, payload: [1, 0, 0])
        expect(!pong(pingChan.client), "e2e: KEY on a ping login closes the connection")

        for (type, what) in [(UInt8(0x10), "KEY"), (0x60, "FORCE_QUIT"), (0x30, "CLIPBOARD_HELLO"), (0x50, "FILE_HELLO"), (0x01, "PING")] {
            guard case let (s, p)? = server(.password(whitelist: [me]), secret: secret) else { expect(false, "e2e: listener"); continue }
            let c = MRC1Client(port: p)
            let ch = c?.receive(timeout: 2)
            _ = c?.send(type: type, payload: type == 0x01 ? [1, 2, 3, 4] : [0, 0, 0])
            let r = c?.receive(timeout: 2)
            expect(ch?.type == ConnAuth.MsgType.challenge && r?.type == ConnAuth.MsgType.result
                   && r.flatMap({ ConnAuth.Result.decode($0.payload) }) == .authRequired && c?.receive(timeout: 1) == nil,
                   "e2e: \(what) before AUTH gets AUTH_REQUIRED and is closed")
            s.stop()
        }

        if case let (s, p)? = server(.password(whitelist: [me]), secret: secret, timeout: 0.3) {
            let c = MRC1Client(port: p)
            _ = c?.receive(timeout: 2)
            let r = c?.receive(timeout: 2)
            expect(r.flatMap({ ConnAuth.Result.decode($0.payload) }) == .fail(triesLeft: 4), "e2e: no RESPONSE within the timeout counts a failure")
            s.stop()
        }

        if case let (s, p)? = server(.password(whitelist: [me]), secret: secret) {
            var last: ConnAuth.Result?
            for _ in 0..<5 { last = login(p, password: "Wrong-Password!", channel: .control).result }
            expect(last == .locked(retrySeconds: 300), "e2e: 5th wrong password answers LOCKED 300 s")
            let next = login(p, password: password, channel: .control)
            if case .locked = next.result { expect(next.response == nil, "e2e: locked IP gets LOCKED without a challenge") }
            else { expect(false, "e2e: locked IP gets LOCKED without a challenge") }
            expect(s.authFailures == 5, "e2e: auth_failures counts 5")
            s.stop()
        }

        if case let (s, p)? = server(.password(whitelist: [me]), secret: secret, blocked: [me]) {
            expect(login(p, password: password, channel: .control).result == .blocked, "e2e: blacklisted IP gets BLOCKED, even with the right password")
            s.stop()
        }
        if case let (s, p)? = server(.password(whitelist: ["100.64.0.9"]), secret: secret) {
            let c = MRC1Client(port: p)
            expect(c?.receive(timeout: 1) == nil && s.rejectedClients == 1, "e2e: password mode, IP not on the whitelist: closed, no challenge")
            s.stop()
        }

        // Transition mode (no password set).
        if case let (s, p)? = server(.transition(whitelist: [me]), secret: nil) {
            let c = MRC1Client(port: p)
            expect(pong(c), "e2e: transition, 0.3.x viewer (PING first) connects as before")
            let probe = MRC1Client(port: p)
            _ = probe?.send(type: ConnAuth.MsgType.response, payload: [UInt8](repeating: 0, count: 64))
            let r = probe?.receive(timeout: 2)
            expect(r.flatMap({ ConnAuth.Result.decode($0.payload) }) == .openIPOnly && pong(probe),
                   "e2e: transition, v0.4 probe gets OPEN_IP_ONLY and the connection goes on")
            s.stop()
        }
        if case let (s, p)? = server(.transition(whitelist: ["100.64.0.9"]), secret: nil) {
            expect(!pong(MRC1Client(port: p)) && s.rejectedClients == 1, "e2e: transition, IP not on the whitelist is closed")
            s.stop()
        }
        if case let (s, p)? = server(.transition(whitelist: [me]), secret: nil, blocked: [me]) {
            let c = MRC1Client(port: p)
            let r = c?.receive(timeout: 2)
            expect(r.flatMap({ ConnAuth.Result.decode($0.payload) }) == .blocked, "e2e: transition, blacklisted IP gets BLOCKED")
            s.stop()
        }
    }
}
