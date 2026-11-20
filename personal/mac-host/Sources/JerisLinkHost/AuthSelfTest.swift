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
        settleAtomic(expect)
        saveFailures(expect)
        blocklist(expect)
        policy(expect)
        migration(expect)
        keychain(expect)
        endToEnd(expect)
        concurrentEndToEnd(expect)
        failClosed(expect)
        configWatch(expect)
        legacyRuntime(expect)
        serviceLevel(expect)
        blocklistMerge(expect)
        r4RelayInput(expect)
        r4Waiting(expect)
        r4Pending(expect)
        r4Writers(expect)
        r5Sessions(expect)
        r5Lock(expect)
        r5Journal(expect)
        r6RelayLockdown(expect)
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
        expect(fail(5) == .blacklisted(persisted: true), "ladder: 20 failures blacklist")
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
        expect(reloaded.release("100.64.0.7") == .released && AuthGuard(whitelist: [], blocklist: ListenPlistBlocklist(url: url)).admit("100.64.0.7") == .challenge,
               "release removes the IP and is saved")
        let missing = dir.appendingPathComponent("absent.plist")
        expect(ListenPlistBlocklist(url: missing).update(adding: [BlockedEntry(ip: "100.64.0.7", at: Date(), reason: "t")], removing: []) == nil
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
        // Deploy/README.md: change clientIP only. Migrated allowedIPs follows it.
        let migrated: [String: Any] = ["clientIP": "100.64.0.6", "allowedIPs": ["100.64.0.16"],
                                       "allowedIPsSource": "clientIP", "passwordSet": false]
        expect(AuthPolicy.resolve(plist: migrated, clientIP: "100.64.0.6", secretLoaded: false)
               == .transition(whitelist: ["100.64.0.6"]), "policy: transition, changing only clientIP moves the whitelist")
        expect(AuthPolicy.resolve(plist: ["clientIP": "100.64.0.6", "allowedIPs": ["100.64.0.16"], "passwordSet": false],
                                  clientIP: "100.64.0.6", secretLoaded: false)
               == .transition(whitelist: ["100.64.0.16"]), "policy: hand-edited allowedIPs (no source key) wins")
        expect(AuthPolicy.resolve(plist: ["allowedIPs": ["100.64.0.3", "nonsense"], "passwordSet": true], clientIP: "100.64.0.2", secretLoaded: true)
               == .refused(reason: "invalid_allowed_ips"), "policy: password mode refuses an invalid allowedIPs entry")
        expect(AuthPolicy.resolve(plist: ["allowedIPs": ["nonsense"], "passwordSet": true], clientIP: "100.64.0.2", secretLoaded: true)
               == .refused(reason: "invalid_allowed_ips"), "policy: password mode, only invalid entries: refused, not any")
        expect(AuthPolicy.resolve(plist: ["allowedIPs": "100.64.0.3", "passwordSet": true], clientIP: "100.64.0.2", secretLoaded: true)
               == .refused(reason: "invalid_allowed_ips"), "policy: password mode refuses allowedIPs that is not a list")
        expect(AuthPolicy.resolve(plist: ["allowedIPs": [String](), "passwordSet": true], clientIP: "100.64.0.2", secretLoaded: true)
               == .password(whitelist: []), "policy: password mode, explicit empty allowedIPs = any (design)")
        expect(AuthPolicy.resolve(plist: ["allowedIPs": ["nonsense"]], clientIP: nil, secretLoaded: false)
               == .refused(reason: "no_password_no_ip"), "policy: transition never widens on invalid entries")
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
        expect(after?["allowedIPsSource"] as? String == "clientIP", "migration: marks allowedIPs as following clientIP")
        expect(ListenMigration.migrate(url: url) == nil, "migration: runs once")

        // A plist migrated by the first PR-A build (no source key).
        writePlist(["bindIP": "100.64.0.1", "clientIP": "100.64.0.2", "allowedIPs": ["100.64.0.2"], "passwordSet": false], url)
        expect(ListenMigration.migrate(url: url) == "config.migrated allowed_ips_source=clientIP"
               && readPlist(url)?["allowedIPsSource"] as? String == "clientIP", "migration: earlier v0.4 plist gets the source key")
        writePlist(["bindIP": "100.64.0.1", "clientIP": "100.64.0.2", "allowedIPs": ["100.64.0.9"], "passwordSet": false], url)
        expect(ListenMigration.migrate(url: url) == nil && readPlist(url)?["allowedIPsSource"] == nil,
               "migration: a hand-edited allowedIPs is left alone")
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
        if let next = ConnSecret.make(password: "Selftest-Next-\(UUID().uuidString.prefix(6))", hostID: secret.hostID, iterations: 1000) {
            expect(store.save(next) && store.load() == next, "keychain: a password change updates the item in place")
        }
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

    // MARK: r2: settle is atomic with the limits

    /// Thread-safe result collector for concurrentPerform.
    private final class Box<T>: @unchecked Sendable {
        private let lock = NSLock()
        private var items: [T] = []
        func add(_ item: T) { lock.lock(); items.append(item); lock.unlock() }
        var all: [T] { lock.lock(); defer { lock.unlock() }; return items }
    }

    private static func settleAtomic(_ expect: Expect) {
        // 30 challenges out at once, all answered wrong at once: only the
        // first 5 count, the 5th locks, the other 25 are refused uncounted.
        let ip = "100.64.0.7"
        let g = AuthGuard(whitelist: [], blocklist: MemoryBlocklist())
        let admitted = (0..<30).map { _ in g.admit(ip) }
        expect(admitted.allSatisfy { $0 == .challenge }, "settle: 30 challenges issued before any answer")
        let results = Box<AuthGuard.Settlement>()
        DispatchQueue.concurrentPerform(iterations: 30) { _ in results.add(g.settle(ip) { false }) }
        let failed = results.all.filter { if case .failed = $0 { return true }; return false }
        let refusedLocked = results.all.filter { if case .refused(.locked) = $0 { return true }; return false }
        expect(failed.count == 5 && refusedLocked.count == 25 && g.failures(ip) == 5,
               "settle: concurrent wrong answers count 5, the other 25 get LOCKED uncounted")
        var macChecked = false
        let late = g.settle(ip) { macChecked = true; return true }
        var lateLocked = false
        if case .refused(.locked) = late { lateLocked = true }
        expect(lateLocked && !macChecked, "settle: right answer to a pre-lock challenge gets LOCKED, MAC not even checked")

        // Blacklisted while a challenge was out: BLOCKED, never OK.
        let clock = Clock()
        let bg = AuthGuard(whitelist: [], blocklist: MemoryBlocklist(), now: { clock.t })
        for _ in 0..<3 {
            for _ in 0..<5 { _ = bg.settle(ip) { false }; clock.t += 61 }
            clock.t += 900
        }
        for _ in 0..<4 { _ = bg.settle(ip) { false }; clock.t += 61 }
        expect(bg.admit(ip) == .challenge, "settle: 19 failures, a challenge goes out")
        _ = bg.settle(ip) { false }   // the 20th, from another connection
        expect(bg.settle(ip) { true } == .refused(.blocked), "settle: right answer after the blacklist gets BLOCKED")

        // Host-wide: 40 IPs answer wrong at once: 20 count, 20 refused;
        // a challenge out before the wait gets LOCKED.
        let hg = AuthGuard(whitelist: [], blocklist: MemoryBlocklist())
        expect(hg.admit("100.64.9.9") == .challenge, "settle: victim challenge out before the host-wide wait")
        let host = Box<AuthGuard.Settlement>()
        DispatchQueue.concurrentPerform(iterations: 40) { i in host.add(hg.settle("100.64.8.\(i)") { false }) }
        let counted = host.all.filter { if case .failed = $0 { return true }; return false }.count
        let triggered = host.all.filter { if case .failed(let f) = $0 { return f.globalTriggered }; return false }.count
        expect(counted == 20 && triggered == 1, "settle: concurrent host-wide limit counts exactly 20, triggers once")
        if case .refused(.globalLocked) = hg.settle("100.64.9.9", check: { true }) {
            expect(true, "settle: right answer during the host-wide wait gets LOCKED")
        } else { expect(false, "settle: right answer during the host-wide wait gets LOCKED") }
    }

    private static func saveFailures(_ expect: Expect) {
        let ip = "100.64.0.7"
        func blacklist(_ store: MemoryBlocklist) -> (AuthGuard, AuthGuard.FailureOutcome?) {
            let clock = Clock()
            let g = AuthGuard(whitelist: [], blocklist: store, now: { clock.t }, pause: { _ in })
            var last: AuthGuard.FailureOutcome?
            for i in 1...20 {
                last = g.recordFailure(ip).outcome
                clock.t += i % 5 == 0 ? 961 : 61
            }
            return (g, last)
        }
        let flaky = MemoryBlocklist()
        flaky.failNextSaves = 2
        let (_, retried) = blacklist(flaky)
        expect(retried == .blacklisted(persisted: true) && flaky.saveCalls == 3 && flaky.entries.map(\.ip) == [ip],
               "blacklist write: 2 failures then success, persisted")
        let broken = MemoryBlocklist()
        broken.failNextSaves = 99
        let (g, lost) = blacklist(broken)
        expect(lost == .blacklisted(persisted: false) && broken.saveCalls == AuthGuard.saveAttempts && g.admit(ip) == .blocked
               && !g.persistedIPs.contains(ip), "blacklist write: all attempts fail, reported unpersisted, still blocked in memory")

        let store = MemoryBlocklist([BlockedEntry(ip: ip, at: Date(), reason: "t")])
        let rg = AuthGuard(whitelist: [], blocklist: store, pause: { _ in })
        store.failNextSaves = 99
        expect(rg.release(ip) == .saveFailed && rg.admit(ip) == .blocked && store.entries.count == 1,
               "release: write fails, IP stays blocked (memory and file agree)")
        store.failNextSaves = 0
        expect(rg.release(ip) == .released && rg.admit(ip) == .challenge && store.entries.isEmpty,
               "release: written, IP open")
        expect(rg.release(ip) == .notBlocked, "release: IP not blocked")
    }

    // MARK: r2: concurrent AUTH over sockets

    private static func concurrentEndToEnd(_ expect: Expect) {
        let password = "Concurrent-\(UUID().uuidString.prefix(8))!"
        guard let secret = ConnSecret.make(password: password, iterations: 1000),
              let port = ControlServiceSelfTest.freeLoopbackPort() else {
            expect(false, "e2e concurrent: setup")
            return
        }
        let me = ListenConfig.loopbackIP
        let gate = AuthGate(policy: .password(whitelist: [me]),
                            guardian: AuthGuard(whitelist: [me], blocklist: MemoryBlocklist()),
                            secret: secret, timeout: 5)
        let s = ControlServer(bindIP: me, allowedClientIP: nil, port: port, inject: false,
                              settingsClientIP: { me }, acceptProxy: false, inputHelper: nil,
                              clipboard: FakeClipboard(text: nil), authGate: gate)
        guard (try? s.start()) != nil else { expect(false, "e2e concurrent: listener starts"); return }
        defer { s.stop() }

        // 13 connections, all challenged before anyone answers.
        var pending: [(MRC1Client, ConnAuth.Challenge)] = []
        for _ in 0..<13 {
            guard let c = MRC1Client(port: port), let ch = c.receive(timeout: 2), ch.type == ConnAuth.MsgType.challenge,
                  let challenge = ConnAuth.Challenge.decode(ch.payload) else { continue }
            pending.append((c, challenge))
        }
        guard pending.count == 13,
              let key = ConnAuth.deriveKey(password: password, salt: pending[0].1.salt, iterations: pending[0].1.iterations) else {
            expect(false, "e2e concurrent: 13 challenges issued")
            return
        }
        let wrongKey = ConnAuth.deriveKey(password: "Wrong-Password!", salt: pending[0].1.salt, iterations: pending[0].1.iterations) ?? []
        func respond(_ c: MRC1Client, _ challenge: ConnAuth.Challenge, key: [UInt8]) -> ConnAuth.Result? {
            let cn = ConnAuth.random(ConnAuth.nonceBytes)
            let mac = ConnAuth.macClient(key: key, hostNonce: challenge.hostNonce, clientNonce: cn, channel: .control, hostID: challenge.hostID)
            _ = c.send(type: ConnAuth.MsgType.response, payload: ConnAuth.Response(clientNonce: cn, mac: mac).payload)
            guard let r = c.receive(timeout: 3), r.type == ConnAuth.MsgType.result else { return nil }
            return ConnAuth.Result.decode(r.payload)
        }
        let wrong = Array(pending.prefix(12))
        let results = Box<ConnAuth.Result?>()
        DispatchQueue.concurrentPerform(iterations: wrong.count) { i in results.add(respond(wrong[i].0, wrong[i].1, key: wrongKey)) }
        let fails = results.all.filter { if case .fail? = $0 { return true }; return false }.count
        let locked = results.all.filter { if case .locked? = $0 { return true }; return false }.count
        expect(fails == 4 && locked == 8 && s.authFailures == 5,
               "e2e concurrent: 12 wrong answers at once: 4 FAIL + 8 LOCKED, auth_failures 5 (got \(fails)/\(locked)/\(s.authFailures))")
        let late = respond(pending[12].0, pending[12].1, key: key)
        if case .locked? = late { expect(s.authFailures == 5, "e2e concurrent: right password on a pre-lock challenge gets LOCKED, uncounted") }
        else { expect(false, "e2e concurrent: right password on a pre-lock challenge gets LOCKED, uncounted") }

        // Closing before answering is not a failure.
        guard let p2 = ControlServiceSelfTest.freeLoopbackPort() else { return }
        let g2 = AuthGuard(whitelist: [me], blocklist: MemoryBlocklist())
        let s2 = ControlServer(bindIP: me, allowedClientIP: nil, port: p2, inject: false,
                               settingsClientIP: { me }, acceptProxy: false, inputHelper: nil,
                               clipboard: FakeClipboard(text: nil),
                               authGate: AuthGate(policy: .password(whitelist: [me]), guardian: g2, secret: secret, timeout: 2))
        guard (try? s2.start()) != nil else { expect(false, "e2e: listener 2 starts"); return }
        defer { s2.stop() }
        for _ in 0..<6 {
            let c = MRC1Client(port: p2)
            _ = c?.receive(timeout: 2)
            c?.close()
        }
        Thread.sleep(forTimeInterval: 0.3)
        expect(s2.authFailures == 0 && g2.failures(me) == 0 && g2.admit(me) == .challenge,
               "e2e: 6 disconnects before answering count nothing, no lock")
    }

    // MARK: r2: fail closed without AUTH

    private static func failClosed(_ expect: Expect) {
        let me = ListenConfig.loopbackIP
        guard let secret = ConnSecret.make(password: "FailClosed-\(UUID().uuidString.prefix(8))!", iterations: 1000) else { return }
        func listenerCount(_ policy: AuthPolicy, secret: ConnSecret?) -> Int? {
            guard let p = ControlServiceSelfTest.freeLoopbackPort(), let r = ControlServiceSelfTest.freeLoopbackPort(), p != r else { return nil }
            let gate = AuthGate(policy: policy, guardian: AuthGuard(whitelist: [me], blocklist: MemoryBlocklist()), secret: secret)
            guard let servers = try? ControlService.startServers(bindIP: me, clientIP: me, port: p, relayPort: r, inject: false,
                                                                 helper: InputHelperClient(port: 9), gate: gate) else { return nil }
            defer { servers.forEach { $0.stop() } }
            return servers.count
        }
        expect(listenerCount(.password(whitelist: [me]), secret: secret) == 1, "fail closed: password mode starts no mouse relay listener")
        expect(listenerCount(.transition(whitelist: [me]), secret: nil) == 2, "fail closed: transition mode keeps the relay")

        // MouseMoveUDPServer with input off drops 0x24 but still answers ping.
        guard let up = ControlServiceSelfTest.freeLoopbackPort() else { return }
        let udp = MouseMoveUDPServer(bindIP: me, allowedClientIP: me, port: up, inputAllowed: { false })
        guard (try? udp.start()) != nil else { expect(false, "fail closed: UDP server starts"); return }
        defer { udp.stop() }
        let s = Darwin.socket(AF_INET, SOCK_DGRAM, 0)
        defer { Darwin.close(s) }
        var addr = ControlServiceSelfTest.loopbackAddress(port: up)
        func send(_ bytes: [UInt8]) {
            _ = withUnsafePointer(to: &addr) { p in
                p.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    bytes.withUnsafeBytes { Darwin.sendto(s, $0.baseAddress!, bytes.count, 0, sa, socklen_t(MemoryLayout<sockaddr_in>.size)) }
                }
            }
        }
        send([0x4d, 0x52, 0x4d, 0x31, 1, 0x24, 0, 0, 0, 1, 0x80, 0, 0x80, 0])
        send([0x4d, 0x52, 0x4d, 0x31, 1, 0x43, 0, 0, 0, 2] + [UInt8](repeating: 7, count: 8))
        var tv = timeval(tv_sec: 2, tv_usec: 0)
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var buf = [UInt8](repeating: 0, count: 64)
        let n = buf.withUnsafeMutableBytes { Darwin.recv(s, $0.baseAddress!, 64, 0) }
        expect(udp.inputDropped == 1 && udp.forwarded == 0, "fail closed: password mode drops UDP mouse input")
        expect(n == 18 && buf[5] == 0x44, "fail closed: UDP ping still answered with input off")

        // Legacy entries read passwordSet from listen.plist.
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("listen.plist")
        writePlist(["bindIP": "100.64.0.1", "clientIP": "100.64.0.2", "passwordSet": true], url)
        let on = ListenConfig.passwordState(url: url)
        writePlist(["bindIP": "100.64.0.1", "clientIP": "100.64.0.2", "passwordSet": false], url)
        expect(on == .on && ListenConfig.passwordState(url: url) == .off, "fail closed: legacy entries see passwordSet")
    }

    // MARK: r2: auth config changes restart the service

    private static func configWatch(_ expect: Expect) {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("listen.plist")
        let base: [String: Any] = ["bindIP": "100.64.0.1", "clientIP": "100.64.0.2", "allowedIPs": ["100.64.0.2"],
                                   "allowedIPsSource": "clientIP", "passwordSet": false]
        writePlist(base, url)
        let guardian = AuthGuard(whitelist: ["100.64.0.2"], blocklist: ListenPlistBlocklist(url: url), pause: { _ in })
        let started = AuthConfigSnapshot.read(plist: ListenConfig.readPlist(url: url), secret: nil)
        let ep = ListenEndpoint(mode: .tailnet, bindIP: "100.64.0.1", clientIP: "100.64.0.2", source: "listen.plist")
        let gate = AuthGate(policy: .transition(whitelist: ["100.64.0.2"]), guardian: guardian, secret: nil)
        let watch = PolicyWatch(started: ep, snapshot: started, gate: gate,
                                read: { (.ready(ep), ListenConfig.readPlist(url: url)) }, loadSecret: { nil })
        func check() -> String? {
            if case .changed(let what) = watch.evaluate() { return what }
            return nil
        }
        expect(check() == nil, "watch: unchanged config, no restart")
        var edited = base; edited["allowedIPs"] = ["100.64.0.2", "100.64.0.3"]; edited["allowedIPsSource"] = nil
        writePlist(edited, url)
        expect(check() == "config.auth_changed keys=allowedIPs,allowedIPsSource", "watch: allowedIPs edit restarts")
        var pw = base; pw["passwordSet"] = true
        writePlist(pw, url)
        expect(check()?.hasPrefix("config.auth_changed keys=passwordSet") == true, "watch: passwordSet change restarts")
        writePlist(base, url)
        for _ in 0..<20 { _ = guardian.recordFailure("100.64.0.7") }
        expect(check() == nil, "watch: the service's own blacklist write does not restart it")
        var outside = readPlist(url) ?? base
        outside["blockedIPs"] = ["100.64.0.8"]
        writePlist(outside, url)
        expect(check() == "config.auth_changed keys=blockedIPs", "watch: blockedIPs edited outside restarts")
        let a = AuthConfigSnapshot.read(plist: ["passwordSet": true], secret: ConnSecret(key: [1], salt: [2], iterations: 1, hostID: [3]))
        let b = AuthConfigSnapshot.read(plist: ["passwordSet": true], secret: ConnSecret(key: [1], salt: [4], iterations: 1, hostID: [3]))
        expect(b.changes(from: a) == "password", "watch: a new password (new salt) restarts")
    }

    // MARK: r3: legacy entries, service-level policy changes, blacklist merge

    private final class SecretSlot: @unchecked Sendable {
        private let lock = NSLock()
        private var stored: ConnSecret?
        var value: ConnSecret? {
            get { lock.lock(); defer { lock.unlock() }; return stored }
            set { lock.lock(); stored = newValue; lock.unlock() }
        }
    }

    private static func pong(_ c: MRC1Client?) -> Bool {
        guard let c, c.send(type: 0x01, payload: [9, 8, 7, 6]), let r = c.receive(timeout: 2) else { return false }
        return r.type == 0x02 && r.payload == [9, 8, 7, 6]
    }

    /// Connects and answers the challenge for the control channel.
    private static func login(_ port: UInt16, password: String) -> (MRC1Client?, ConnAuth.Result?) {
        guard let c = MRC1Client(port: port), let ch = c.receive(timeout: 2),
              ch.type == ConnAuth.MsgType.challenge, let challenge = ConnAuth.Challenge.decode(ch.payload),
              let key = ConnAuth.deriveKey(password: password, salt: challenge.salt, iterations: challenge.iterations) else { return (nil, nil) }
        let cn = ConnAuth.random(ConnAuth.nonceBytes)
        let mac = ConnAuth.macClient(key: key, hostNonce: challenge.hostNonce, clientNonce: cn, channel: .control, hostID: challenge.hostID)
        _ = c.send(type: ConnAuth.MsgType.response, payload: ConnAuth.Response(clientNonce: cn, mac: mac).payload)
        guard let r = c.receive(timeout: 3), r.type == ConnAuth.MsgType.result else { return (c, nil) }
        return (c, ConnAuth.Result.decode(r.payload))
    }

    /// B2: legacy entries fail closed on an unknown password state and close
    /// at runtime when a password is set.
    private static func legacyRuntime(_ expect: Expect) {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("listen.plist")
        expect(ListenConfig.passwordState(url: url) == .off, "b2: no listen.plist is password off (network.conf setups)")
        writePlist(["mode": "loopback", "passwordSet": "yes"], url)
        expect(ListenConfig.passwordState(url: url) == .unknown("password_set_invalid"), "b2: a non-bool passwordSet is unknown, not off")
        try? Data("not a plist".utf8).write(to: url)
        expect(ListenConfig.passwordState(url: url) == .unknown("listen_plist_invalid"), "b2: an unparseable listen.plist is unknown, not off")
        writePlist(["mode": "loopback", "passwordSet": false], url)
        chmod(url.path, 0)
        let unreadable = ListenConfig.passwordState(url: url)
        chmod(url.path, 0o644)
        expect(unreadable == .unknown("listen_plist_unreadable"), "b2: an unreadable listen.plist is unknown, not off")
        expect(AuthPolicy.resolve(plist: ["passwordSet": "yes", "clientIP": "100.64.0.2"], clientIP: "100.64.0.2", secretLoaded: false)
               == .refused(reason: "password_set_invalid"), "b2: the control service refuses a non-bool passwordSet")
        expect(!LegacyAuthWatch(read: { .unknown("listen_plist_unreadable") }).isOpen, "b2: legacy entries start closed on an unknown state")

        writePlist(["mode": "loopback", "passwordSet": false], url)
        let me = ListenConfig.loopbackIP
        let watch = LegacyAuthWatch(read: { ListenConfig.passwordState(url: url) })
        guard let port = ControlServiceSelfTest.freeLoopbackPort() else { return }
        let legacy = ControlServer.legacyListener(bindIP: me, allowedClientIP: me, port: port, inject: false,
                                                  globalClientIP: { me }, clipboard: FakeClipboard(text: nil),
                                                  admit: { watch.check() })
        watch.onClose { _ in legacy.stop() }
        guard (try? legacy.start()) != nil else { expect(false, "b2: legacy listener starts"); return }
        defer { legacy.stop() }
        let old = MRC1Client(port: port)
        expect(pong(old), "b2: legacy listener serves while passwordSet is false")
        writePlist(["mode": "loopback", "passwordSet": true], url)
        // No poll has run: the accept-time check alone must refuse it.
        expect(!pong(MRC1Client(port: port)), "b2: password set at runtime: the next legacy connection is refused at once")
        Thread.sleep(forTimeInterval: 0.2)
        expect(!watch.isOpen && !pong(old), "b2: legacy listener stops and the connection opened before the change is closed")
        writePlist(["mode": "loopback", "passwordSet": false], url)
        expect(!watch.check() && MRC1Client(port: port).map { pong($0) } != true, "b2: clearing the password does not reopen legacy entries")
    }

    /// Should-fix: the control service as it runs (startServers + PolicyWatch
    /// on a temporary listen.plist): password turned on while running, old
    /// connections closed, admission after the restart.
    private static func serviceLevel(_ expect: Expect) {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("listen.plist")
        let me = ListenConfig.loopbackIP
        let password = "Service-\(UUID().uuidString.prefix(8))!"
        guard let secret = ConnSecret.make(password: password, iterations: 1000) else { return }
        let slot = SecretSlot()
        let base: [String: Any] = ["mode": "loopback", "clientIP": me, "allowedIPs": [me],
                                   "allowedIPsSource": "clientIP", "passwordSet": false]
        writePlist(base, url)
        let local = [LocalAddress(interface: "lo0", ip: me)]
        let read: @Sendable () -> (ListenResolution, [String: Any]?) = {
            let plist = ListenConfig.readPlist(url: url)
            return (ListenConfig.resolve(plist: plist, conf: (nil, nil), local: local), plist)
        }
        struct Running { var watch: PolicyWatch; var servers: [ControlServer]; var port: UInt16; var changes: Box<String> }
        /// One service start, as ControlService.run does it.
        func boot() -> Running? {
            let (resolution, plist) = read()
            guard case .ready(let ep) = resolution, let port = ControlServiceSelfTest.freeLoopbackPort() else { return nil }
            let (gate, snapshot) = ControlService.authGate(clientIP: ep.clientIP, plist: plist,
                                                           secret: ControlService.wantsPassword(plist) ? slot.value : nil,
                                                           blocklist: ListenPlistBlocklist(url: url))
            let watch = PolicyWatch(started: ep, snapshot: snapshot, gate: gate, read: read, loadSecret: { slot.value })
            guard let servers = try? ControlService.startServers(bindIP: me, clientIP: me, port: port, relayPort: 0, inject: false,
                                                                 helper: InputHelperClient(port: 9), gate: gate,
                                                                 admit: { watch.admitNew() }) else { return nil }
            let changes = Box<String>()
            watch.setOnChange { what in changes.add(what); servers.forEach { $0.stop() } }
            return Running(watch: watch, servers: servers, port: port, changes: changes)
        }

        guard let a = boot() else { expect(false, "service: starts in transition mode"); return }
        let old = MRC1Client(port: a.port)
        expect(pong(old), "service: transition mode admits a 0.3 viewer without AUTH")
        slot.value = secret
        var pw = base; pw["passwordSet"] = true
        writePlist(pw, url)
        // No periodic check has run: the accept-time check alone applies it.
        expect(!pong(MRC1Client(port: a.port)), "service: password set while running: the next connection is refused at once")
        expect(a.watch.appliedChange?.contains("passwordSet") == true && a.watch.gate?.isRevoked == true && a.changes.all.count == 1,
               "service: one check is enough: old gate revoked, change applied once")
        Thread.sleep(forTimeInterval: 0.2)
        expect(!pong(old), "service: a connection admitted before the change is closed")
        a.servers.forEach { $0.stop() }

        // Restart (launchd): the same listen.plist now means password mode.
        guard let b = boot() else { expect(false, "service: restarts in password mode"); return }
        defer { b.servers.forEach { $0.stop() } }
        expect(b.watch.gate?.requiresPassword == true, "service restart: password policy in force")
        let plain = MRC1Client(port: b.port)
        expect(plain?.receive(timeout: 2)?.type == ConnAuth.MsgType.challenge, "service restart: a viewer without a password gets a challenge, nothing else")
        plain?.close()
        let (wrongClient, wrong) = login(b.port, password: "Wrong-\(UUID().uuidString.prefix(6))!")
        if case .fail? = wrong { expect(!pong(wrongClient), "service restart: wrong password refused") }
        else { expect(false, "service restart: wrong password refused") }
        let (goodClient, good) = login(b.port, password: password)
        if case .ok? = good { expect(pong(goodClient), "service restart: right password admitted") }
        else { expect(false, "service restart: right password admitted") }

        // An open authenticated connection is closed by the periodic check.
        var narrowed = pw; narrowed["allowedIPs"] = ["100.64.0.9"]; narrowed["allowedIPsSource"] = nil
        writePlist(narrowed, url)
        b.watch.tick()
        Thread.sleep(forTimeInterval: 0.2)
        expect(b.watch.appliedChange?.contains("allowedIPs") == true && !pong(goodClient),
               "service: allowedIPs edit closes an authenticated connection on the first periodic check")
    }

    /// B5: automatic writes merge with listen.plist; a block that could not
    /// be written keeps the host shut until it is.
    private static func blocklistMerge(_ expect: Expect) {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("listen.plist")
        writePlist(["mode": "loopback", "blockedIPs": ["100.64.0.5"]], url)
        let g = AuthGuard(whitelist: [], blocklist: ListenPlistBlocklist(url: url), pause: { _ in })
        var outside = readPlist(url) ?? [:]
        outside["blockedIPs"] = ["100.64.0.5", "100.64.0.9"]
        writePlist(outside, url)
        for _ in 0..<20 { _ = g.recordFailure("100.64.0.7") }
        let inFile = { Set(ListenPlistBlocklist(url: url).load().map(\.ip)) }
        expect(inFile() == ["100.64.0.5", "100.64.0.9", "100.64.0.7"],
               "b5: automatic block merges into listen.plist; a manual block written after start is kept")
        expect(g.admit("100.64.0.9") == .blocked && !g.persistedIPs.contains("100.64.0.9"),
               "b5: that manual block applies at once and still counts as an outside edit")
        expect(g.release("100.64.0.7") == .released && inFile() == ["100.64.0.5", "100.64.0.9"],
               "b5: release removes only its own IP")

        let clock = Clock()
        let store = MemoryBlocklist()
        store.failNextSaves = 99
        let lg = AuthGuard(whitelist: [], blocklist: store, now: { clock.t }, pause: { _ in })
        var last: AuthGuard.FailureOutcome?
        for _ in 0..<20 { last = lg.recordFailure("100.64.0.7").outcome; clock.t += 61 }
        clock.t -= 61
        expect(last == .blacklisted(persisted: false) && lg.admit("100.64.0.8") == .globalLocked(retrySeconds: AuthGuard.pendingRetrySeconds),
               "b5: a block that could not be written stops every challenge (fail closed)")
        clock.t += 2
        expect(lg.admit("100.64.0.8") != .challenge && lg.pendingIPs == ["100.64.0.7"], "b5: still shut while writes keep failing")
        store.failNextSaves = 0
        clock.t += 2
        expect(lg.admit("100.64.0.8") == .challenge && store.entries.map(\.ip) == ["100.64.0.7"] && lg.pendingIPs.isEmpty,
               "b5: the retry writes the block, then challenges resume")

        guard let secret = ConnSecret.make(password: "Unwritable-\(UUID().uuidString.prefix(6))!", iterations: 1000) else { return }
        let ro = MemoryBlocklist(); ro.canWrite = false
        let plist: [String: Any] = ["mode": "loopback", "allowedIPs": ["127.0.0.1"], "passwordSet": true]
        expect(ControlService.authGate(clientIP: "127.0.0.1", plist: plist, secret: secret, blocklist: ro).0 == nil,
               "b5: password mode refuses to start while the blacklist cannot be written")
        expect(ControlService.authGate(clientIP: "127.0.0.1", plist: plist, secret: secret, blocklist: MemoryBlocklist()).0?.requiresPassword == true,
               "b5: and starts when it can")
    }

    // MARK: r4: no gap after a policy switch, waiting endpoint, durable blocks

    private final class AddressSlot: @unchecked Sendable {
        private let lock = NSLock()
        private var stored: [LocalAddress]
        init(_ value: [LocalAddress]) { stored = value }
        var value: [LocalAddress] {
            get { lock.lock(); defer { lock.unlock() }; return stored }
            set { lock.lock(); stored = newValue; lock.unlock() }
        }
    }

    private static func settle(_ ok: () -> Bool) -> Bool {
        for _ in 0..<40 { if ok() { return true }; Thread.sleep(forTimeInterval: 0.05) }
        return ok()
    }

    private struct Booted {
        var watch: PolicyWatch
        var servers: [ControlServer]
        var port: UInt16
        var relayPort: UInt16
        var gate: AuthGate
    }

    /// One control-service start as ControlService.run does it, mouse relay
    /// on (never relayPort 0), per-message checks on.
    private static func bootService(read: @escaping @Sendable () -> (ListenResolution, [String: Any]?), url: URL,
                                    gate makeGate: (ListenEndpoint, [String: Any]?) -> (AuthGate?, AuthConfigSnapshot)) -> Booted? {
        let me = ListenConfig.loopbackIP
        let (resolution, plist) = read()
        guard case .ready(let ep) = resolution, let port = ControlServiceSelfTest.freeLoopbackPort(),
              let relayPort = ControlServiceSelfTest.freeLoopbackPort(), relayPort != port else { return nil }
        let (made, snapshot) = makeGate(ep, plist)
        guard let gate = made else { return nil }
        let watch = PolicyWatch(started: ep, snapshot: snapshot, gate: gate, read: read, loadSecret: { nil },
                                stamp: { ListenFileStamp.of(url) })
        guard let servers = try? ControlService.startServers(bindIP: me, clientIP: me, port: port, relayPort: relayPort, inject: false,
                                                             helper: InputHelperClient(port: 9), gate: gate,
                                                             admit: { watch.admitNew() },
                                                             admitMessage: { watch.stillCurrent() }),
              servers.count == 2 else { return nil }
        watch.setOnChange { _ in servers.forEach { $0.stop() } }
        return Booted(watch: watch, servers: servers, port: port, relayPort: relayPort, gate: gate)
    }

    /// B2 r4: a password switch stops the running mouse relay and UDP 0x24
    /// input on their next message, with no poll in between.
    private static func r4RelayInput(_ expect: Expect) {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("listen.plist")
        let me = ListenConfig.loopbackIP
        let base: [String: Any] = ["mode": "loopback", "clientIP": me, "allowedIPs": [me],
                                   "allowedIPsSource": "clientIP", "passwordSet": false]
        writePlist(base, url)
        let local = [LocalAddress(interface: "lo0", ip: me)]
        let read: @Sendable () -> (ListenResolution, [String: Any]?) = {
            let plist = ListenConfig.readPlist(url: url)
            return (ListenConfig.resolve(plist: plist, conf: (nil, nil), local: local), plist)
        }
        guard let svc = bootService(read: read, url: url, gate: { ep, plist in
            ControlService.authGate(clientIP: ep.clientIP, plist: plist, secret: nil, blocklist: ListenPlistBlocklist(url: url))
        }), let udpPort = ControlServiceSelfTest.freeLoopbackPort() else {
            expect(false, "r4 b2: service starts with the mouse relay"); return
        }
        defer { svc.servers.forEach { $0.stop() } }
        let relay = svc.servers[1]
        // The video side: UDP input asks LegacyAuthWatch per datagram and
        // relays to this service.
        let legacy = LegacyAuthWatch(url: url)
        let udp = MouseMoveUDPServer(bindIP: me, allowedClientIP: me, port: udpPort, relayPort: svc.relayPort,
                                     inputAllowed: { legacy.check() })
        legacy.onClose { reason in udp.revokeInput(reason: reason) }
        guard (try? udp.start()) != nil else { expect(false, "r4 b2: UDP input starts"); return }
        defer { udp.stop() }
        let s = Darwin.socket(AF_INET, SOCK_DGRAM, 0)
        defer { Darwin.close(s) }
        var addr = ControlServiceSelfTest.loopbackAddress(port: udpPort)
        func move(_ seq: UInt8) {
            let bytes: [UInt8] = [0x4d, 0x52, 0x4d, 0x31, 1, 0x24, 0, 0, 0, seq, 0x80, 0, 0x80, 0]
            _ = withUnsafePointer(to: &addr) { p in
                p.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    bytes.withUnsafeBytes { Darwin.sendto(s, $0.baseAddress!, bytes.count, 0, sa, socklen_t(MemoryLayout<sockaddr_in>.size)) }
                }
            }
        }
        // A second relay connection, open before the switch.
        let other = LocalControlMouseClient(port: svc.relayPort)
        move(1)
        let viaUDP = settle { udp.forwarded == 1 && relay.mouseEvents == 1 }
        let viaRelay = other.sendMouseMoveNormalized(nx: 1, ny: 1) && settle { relay.mouseEvents == 2 }
        expect(viaUDP && viaRelay, "r4 b2: transition mode: UDP 0x24 and an open relay connection reach the control service")
        var pw = base; pw["passwordSet"] = true
        writePlist(pw, url)
        // No poll runs here: no startPolling, no watch.start, no tick.
        move(2)
        Thread.sleep(forTimeInterval: 0.3)
        expect(udp.forwarded == 1 && udp.inputDropped == 1 && relay.mouseEvents == 2,
               "r4 b2: password set: the very next UDP 0x24 is dropped, nothing reaches the relay")
        _ = other.sendMouseMoveNormalized(nx: 2, ny: 2)
        Thread.sleep(forTimeInterval: 0.3)
        expect(relay.mouseEvents == 2 && svc.watch.appliedChange?.contains("passwordSet") == true && svc.gate.isRevoked,
               "r4 b2: the open relay connection is refused on its next message, old gate revoked")
        let late = LocalControlMouseClient(port: svc.relayPort)
        _ = late.sendMouseMoveNormalized(nx: 3, ny: 3)
        Thread.sleep(forTimeInterval: 0.2)
        expect(relay.mouseEvents == 2 && !legacy.isOpen, "r4 b2: no relay connection gets through afterwards")
    }

    /// B3 r4: while the endpoint waits for its address no new connection is
    /// admitted, and an auth change is still applied.
    private static func r4Waiting(_ expect: Expect) {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("listen.plist")
        let me = ListenConfig.loopbackIP
        let up = [LocalAddress(interface: "utun4", ip: "100.64.0.10")]
        let base: [String: Any] = ["mode": "tailnet", "clientIP": "100.64.0.2", "allowedIPs": ["100.64.0.2"],
                                   "allowedIPsSource": "clientIP", "passwordSet": false]
        writePlist(base, url)
        let addrs = AddressSlot(up)
        let read: @Sendable () -> (ListenResolution, [String: Any]?) = {
            let plist = ListenConfig.readPlist(url: url)
            return (ListenConfig.resolve(plist: plist, conf: (nil, nil), local: addrs.value), plist)
        }
        // The endpoint is the tailnet one; the sockets are on loopback, and
        // the gate admits this process as the viewer.
        let gate: (ListenEndpoint, [String: Any]?) -> (AuthGate?, AuthConfigSnapshot) = { _, plist in
            (AuthGate(policy: .transition(whitelist: [me]), guardian: AuthGuard(whitelist: [me], blocklist: MemoryBlocklist()), secret: nil),
             AuthConfigSnapshot.read(plist: plist, secret: nil))
        }
        guard let a = bootService(read: read, url: url, gate: gate) else { expect(false, "r4 b3: service starts"); return }
        expect(pong(MRC1Client(port: a.port)), "r4 b3: admits while the address is up")
        addrs.value = []
        expect(!pong(MRC1Client(port: a.port)) && a.watch.appliedChange == nil,
               "r4 b3: address down (waiting): a new connection is refused, nothing applied yet")
        var pw = base; pw["passwordSet"] = true
        writePlist(pw, url)
        expect(!pong(MRC1Client(port: a.port)) && a.watch.appliedChange?.contains("passwordSet") == true && a.gate.isRevoked,
               "r4 b3: while waiting, a passwordSet change is still applied at once")
        a.servers.forEach { $0.stop() }

        writePlist(base, url)
        addrs.value = up
        guard let b = bootService(read: read, url: url, gate: gate) else { expect(false, "r4 b3: service restarts"); return }
        defer { b.servers.forEach { $0.stop() } }
        var moved = base; moved["bindIP"] = "100.64.0.11"
        writePlist(moved, url)
        expect(!pong(MRC1Client(port: b.port)) && b.watch.appliedChange?.hasPrefix("endpoint changed, new address not up yet") == true,
               "r4 b3: bindIP moved to an address not up yet: the old address refuses new connections, change applied at once")
    }

    /// B5 r4: a block that never reached listen.plist is enforced after a
    /// restart, and the service does not exit with a block in neither place.
    private static func r4Pending(_ expect: Expect) {
        let dir = tempDir()
        let conf = dir.appendingPathComponent("conf", isDirectory: true)
        try? FileManager.default.createDirectory(at: conf, withIntermediateDirectories: true)
        defer { chmod(conf.path, 0o755); try? FileManager.default.removeItem(at: dir) }
        let url = conf.appendingPathComponent("listen.plist")
        let journalURL = dir.appendingPathComponent("auth-state/pending-blocks.plist")
        let me = ListenConfig.loopbackIP
        writePlist(["mode": "loopback", "clientIP": me, "allowedIPs": [me], "allowedIPsSource": "clientIP", "passwordSet": false], url)
        let local = [LocalAddress(interface: "lo0", ip: me)]
        let read: @Sendable () -> (ListenResolution, [String: Any]?) = {
            let plist = ListenConfig.readPlist(url: url)
            return (ListenConfig.resolve(plist: plist, conf: (nil, nil), local: local), plist)
        }
        let gate: (ListenEndpoint, [String: Any]?) -> (AuthGate?, AuthConfigSnapshot) = { ep, plist in
            ControlService.authGate(clientIP: ep.clientIP, plist: plist, secret: nil, blocklist: ListenPlistBlocklist(url: url),
                                    journal: PendingBlockFile(url: journalURL))
        }
        guard let a = bootService(read: read, url: url, gate: gate) else { expect(false, "r4 b5: service starts"); return }
        expect(pong(MRC1Client(port: a.port)), "r4 b5 service: admits this viewer before any block")
        chmod(conf.path, 0o555)
        for _ in 0..<20 { _ = a.gate.guardian.recordFailure(me) }
        expect(a.gate.guardian.pendingIPs == [me] && a.gate.guardian.isDurable
               && PendingBlockFile(url: journalURL).load()?.map(\.ip) == [me] && ListenPlistBlocklist(url: url).load().isEmpty,
               "r4 b5: listen.plist cannot be written: the block is kept in the pending journal")
        a.servers.forEach { $0.stop() }

        guard let b = bootService(read: read, url: url, gate: gate) else { expect(false, "r4 b5: service restarts"); return }
        expect(!pong(MRC1Client(port: b.port)) && b.gate.guardian.admit(me) == .blocked && b.gate.guardian.pendingIPs == [me],
               "r4 b5 service: after a restart the unsaved block still refuses that viewer")
        b.servers.forEach { $0.stop() }

        chmod(conf.path, 0o755)
        guard let c = bootService(read: read, url: url, gate: gate) else { expect(false, "r4 b5: service restarts again"); return }
        defer { c.servers.forEach { $0.stop() } }
        expect(!pong(MRC1Client(port: c.port)) && ListenPlistBlocklist(url: url).load().map(\.ip) == [me]
               && PendingBlockFile(url: journalURL).load()?.isEmpty == true && c.gate.guardian.pendingIPs.isEmpty,
               "r4 b5 service: once listen.plist is writable the restart moves the block into it and empties the journal")

        let store = MemoryBlocklist(); store.failNextSaves = 999
        let journal = MemoryPendingBlocks(); journal.canWrite = false
        let g = AuthGuard(whitelist: [], blocklist: store, pause: { _ in }, journal: journal)
        for _ in 0..<20 { _ = g.recordFailure("100.64.0.7") }
        let held = AuthGate(policy: .transition(whitelist: ["100.64.0.2"]), guardian: g, secret: nil)
        let ep = ListenEndpoint(mode: .tailnet, bindIP: "100.64.0.10", clientIP: "100.64.0.2", source: "listen.plist")
        let w = PolicyWatch(started: ep, snapshot: AuthConfigSnapshot.read(plist: nil, secret: nil), gate: held,
                            read: { (.ready(ep), nil) }, loadSecret: { nil })
        w.apply("self-test")
        let stillHeld = !w.waitUntilDurable(interval: 0.05, maxWait: 0.3)
        journal.canWrite = true
        expect(stillHeld && held.isRevoked && w.waitUntilDurable(interval: 0.05, maxWait: 2) && journal.entries.map(\.ip) == ["100.64.0.7"],
               "r4 b5: a block in neither listen.plist nor the journal holds the exit (gate revoked) until one is written")
    }

    /// B5 r4: blacklist writes against other writers.
    private static func r4Writers(_ expect: Expect) {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("listen.plist")
        writePlist(["mode": "loopback", "note": "keep"], url)
        let store = ListenPlistBlocklist(url: url)
        var fired = false
        store.beforeReplace = {
            guard !fired else { return }
            fired = true
            var d = readPlist(url) ?? [:]
            d["blockedIPs"] = ["100.64.0.9"]
            d["passwordSet"] = false
            writePlist(d, url)
        }
        let out = store.update(adding: [BlockedEntry(ip: "100.64.0.7", at: Date(), reason: "test")], removing: [])
        store.beforeReplace = nil
        let file = readPlist(url) ?? [:]
        expect(fired && Set(out?.map(\.ip) ?? []) == ["100.64.0.9", "100.64.0.7"]
               && Set(ListenPlistBlocklist.entries(in: file).map(\.ip)) == ["100.64.0.9", "100.64.0.7"]
               && file["passwordSet"] as? Bool == false && file["note"] as? String == "keep",
               "r4 b5: an outside edit between the blacklist read and replace is merged, not overwritten")
        let s1 = ListenPlistBlocklist(url: url), s2 = ListenPlistBlocklist(url: url)
        let group = DispatchGroup()
        for (k, s) in [(1, s1), (2, s2)] {
            DispatchQueue.global().async(group: group) {
                for i in 1...15 { _ = s.update(adding: [BlockedEntry(ip: "100.64.\(k).\(i)", at: Date(), reason: "t")], removing: []) }
            }
        }
        group.wait()
        expect(Set(ListenPlistBlocklist(url: url).load().map(\.ip)).count == 32,
               "r4 b5: two writers (separate stores) never lose each other's blocks")
    }

    // MARK: r5

    private static func loopbackBase(_ me: String) -> [String: Any] {
        ["mode": "loopback", "clientIP": me, "allowedIPs": [me], "allowedIPsSource": "clientIP", "passwordSet": false]
    }

    /// B3 r5: the dedicated file and clipboard sessions leave the message
    /// loop. After a policy change neither answers, sends the Mac clipboard
    /// nor writes the PC's text. No poll or tick runs and the server keeps
    /// running, so only the sessions' own checks can close them.
    private static func r5Sessions(_ expect: Expect) {
        let dir = tempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appendingPathComponent("listen.plist")
        let me = ListenConfig.loopbackIP
        let base = loopbackBase(me)
        writePlist(base, url)
        let local = [LocalAddress(interface: "lo0", ip: me)]
        let read: @Sendable () -> (ListenResolution, [String: Any]?) = {
            let plist = ListenConfig.readPlist(url: url)
            return (ListenConfig.resolve(plist: plist, conf: (nil, nil), local: local), plist)
        }
        let (resolution, plist) = read()
        guard case .ready(let ep) = resolution, let port = ControlServiceSelfTest.freeLoopbackPort() else {
            expect(false, "r5 b3: endpoint resolves"); return
        }
        let (made, snapshot) = ControlService.authGate(clientIP: ep.clientIP, plist: plist, secret: nil,
                                                       blocklist: ListenPlistBlocklist(url: url))
        guard let gate = made else { expect(false, "r5 b3: gate"); return }
        let watch = PolicyWatch(started: ep, snapshot: snapshot, gate: gate, read: read, loadSecret: { nil },
                                stamp: { ListenFileStamp.of(url) })
        let board = FakeClipboard(text: "mac-before")
        let folder = FileSendFolder(primary: dir.appendingPathComponent("send", isDirectory: true),
                                    fallback: dir.appendingPathComponent("received", isDirectory: true),
                                    openFolder: { _ in })
        let server = ControlServer(bindIP: me, allowedClientIP: nil, port: port, inject: false,
                                   settingsClientIP: { me }, acceptProxy: false, allowFileSessions: true,
                                   fileStagingRoot: dir.appendingPathComponent("staging", isDirectory: true),
                                   fileSendFolder: folder, clipboard: board, authGate: gate,
                                   admitConnection: { watch.admitNew() }, admitMessage: { watch.stillCurrent() })
        guard (try? server.start()) != nil, let file = MRC1Client(port: port), let clip = MRC1Client(port: port) else {
            expect(false, "r5 b3: server and sessions start"); return
        }
        defer { file.close(); clip.close(); server.stop() }
        let ping = FileProto.Message.ping(token: [1, 2, 3, 4])
        let pingBytes = ping.encode() ?? []
        _ = file.send(type: 0x50, payload: [1, 0, 0])                 // FILE_HELLO
        let ack = file.receive(timeout: 3)?.type == 0x51
        _ = file.send(type: ping.type, payload: pingBytes)
        let echoed = file.receive(timeout: 2)?.type == ping.type
        _ = clip.send(type: 0x30, payload: [])                        // CLIPBOARD_HELLO
        _ = clip.send(type: 0x31, payload: Array("pc-before".utf8))
        let applied = settle { board.writes == ["pc-before"] }
        expect(ack && echoed && applied,
               "r5 b3: transition mode: the file session answers PING, the clipboard session writes the Mac clipboard")

        var pw = base; pw["passwordSet"] = true
        writePlist(pw, url)
        // No watch.start, no tick; nothing stops the server.
        board.localCopy("mac-after")
        _ = clip.send(type: 0x31, payload: Array("pc-after".utf8))
        _ = file.send(type: ping.type, payload: pingBytes)
        Thread.sleep(forTimeInterval: 0.4)
        let fileAfter = file.receive(timeout: 0.5)
        let clipAfter = clip.receive(timeout: 0.5)
        expect(fileAfter == nil && clipAfter == nil && board.writes == ["pc-before"],
               "r5 b3: after a policy change the file session answers nothing and the clipboard session neither sends the Mac copy nor writes the PC text")
        expect(server.rejectedClients == 2 && watch.appliedChange?.contains("passwordSet") == true && gate.isRevoked,
               "r5 b3: both sessions are closed by their own policy check (reason=policy_changed), old gate revoked")
    }

    /// B5 r5: one lock protocol for listen.plist. A manual edit made the
    /// Deploy/README.md way (lockf on listen.plist.lock) holds the same lock,
    /// so a blacklist write waits for it and both edits stay. Without the
    /// lock nothing is written.
    private static func r5Lock(_ expect: Expect) {
        let fm = FileManager.default
        let dir = tempDir()
        defer { try? fm.removeItem(at: dir) }
        let url = dir.appendingPathComponent("listen.plist")
        let lockPath = url.path + ".lock"
        writePlist(["mode": "loopback", "note": "keep"], url)

        let editor = Process()
        editor.executableURL = URL(fileURLWithPath: "/usr/bin/lockf")
        editor.arguments = ["-k", lockPath, "/bin/sh", "-c",
                            "sleep 0.3; /usr/libexec/PlistBuddy -c 'Add :manual string yes' \"$0\"", url.path]
        var held = false
        if (try? editor.run()) != nil {
            // Wait until lockf holds the lock (a probe that gets it lets go at once).
            for _ in 0..<200 {
                let fd = open(lockPath, O_RDWR | O_CLOEXEC)
                if fd >= 0 {
                    let busy = flock(fd, LOCK_EX | LOCK_NB) != 0 && errno == EWOULDBLOCK
                    if !busy { flock(fd, LOCK_UN) }
                    close(fd)
                    if busy { held = true; break }
                }
                usleep(5_000)
            }
        }
        let store = ListenPlistBlocklist(url: url)
        store.lockWait = 10
        let start = ProcessInfo.processInfo.systemUptime
        let out = store.update(adding: [BlockedEntry(ip: "100.64.0.7", at: Date(), reason: "test")], removing: [])
        let waited = ProcessInfo.processInfo.systemUptime - start
        editor.waitUntilExit()
        let file = readPlist(url) ?? [:]
        expect(held && editor.terminationStatus == 0 && waited >= 0.1 && out?.map(\.ip) == ["100.64.0.7"]
               && file["manual"] as? String == "yes" && file["note"] as? String == "keep"
               && ListenPlistBlocklist.entries(in: file).map(\.ip) == ["100.64.0.7"],
               "r5 b5: a blacklist write waits for a lockf + PlistBuddy edit holding the same lock; both edits are kept")

        // The lock is held elsewhere past the wait: nothing written.
        let before = try? Data(contentsOf: url)
        let holder = open(lockPath, O_RDWR | O_CLOEXEC)
        let gotIt = holder >= 0 && flock(holder, LOCK_EX | LOCK_NB) == 0
        let busy = ListenPlistBlocklist(url: url)
        busy.lockWait = 0.2
        let busyOut = busy.update(adding: [BlockedEntry(ip: "100.64.0.8", at: Date(), reason: "test")], removing: [])
        if holder >= 0 { flock(holder, LOCK_UN); close(holder) }
        expect(gotIt && busyOut == nil && (try? Data(contentsOf: url)) == before,
               "r5 b5: lock busy past the wait: the blacklist write gives up and writes nothing")

        // The lock file cannot be opened (a directory in its place).
        try? fm.removeItem(atPath: lockPath)
        try? fm.createDirectory(atPath: lockPath, withIntermediateDirectories: false)
        let noLock = ListenPlistBlocklist(url: url).update(adding: [BlockedEntry(ip: "100.64.0.8", at: Date(), reason: "test")], removing: [])
        expect(noLock == nil && (try? Data(contentsOf: url)) == before,
               "r5 b5: lock file cannot be opened: the blacklist write writes nothing")

        // The guard: the unsaved block goes to the journal, listen.plist untouched.
        let journal = MemoryPendingBlocks()
        let g = AuthGuard(whitelist: [], blocklist: ListenPlistBlocklist(url: url), pause: { _ in }, journal: journal)
        for _ in 0..<20 { _ = g.recordFailure("100.64.0.9") }
        expect(g.pendingIPs == ["100.64.0.9"] && journal.entries.map(\.ip) == ["100.64.0.9"] && g.isDurable
               && (try? Data(contentsOf: url)) == before,
               "r5 b5: no lock: the block stays pending in the journal, listen.plist untouched")

        // Migration takes the same lock.
        let mdir = dir.appendingPathComponent("m", isDirectory: true)
        try? fm.createDirectory(at: mdir, withIntermediateDirectories: true)
        let murl = mdir.appendingPathComponent("listen.plist")
        writePlist(["mode": "tailnet", "clientIP": "100.64.0.2"], murl)
        try? fm.createDirectory(atPath: murl.path + ".lock", withIntermediateDirectories: false)
        let mBefore = try? Data(contentsOf: murl)
        expect(ListenMigration.migrate(url: murl) == "config.migrate_failed reason=lock"
               && (try? Data(contentsOf: murl)) == mBefore && !fm.fileExists(atPath: murl.path + ".pre-0.4"),
               "r5 b5: migration without the lock writes nothing (no backup, listen.plist unchanged)")
    }

    /// B5 r5: a pending journal that exists but does not read is not an
    /// empty one. Nobody is admitted, the file is kept as it is, and
    /// admission comes back once it reads again.
    private static func r5Journal(_ expect: Expect) {
        let fm = FileManager.default
        let dir = tempDir()
        defer { try? fm.removeItem(at: dir) }
        let url = dir.appendingPathComponent("listen.plist")
        let journalURL = dir.appendingPathComponent("auth-state/pending-blocks.plist")
        let me = ListenConfig.loopbackIP
        writePlist(loopbackBase(me), url)
        try? fm.createDirectory(at: journalURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        let garbage = Data("not a plist".utf8)
        try? garbage.write(to: journalURL)
        let noJournal = PendingBlockFile(url: dir.appendingPathComponent("auth-state/none.plist"))
        expect(PendingBlockFile(url: journalURL).load() == nil && noJournal.load()?.isEmpty == true,
               "r5 b5: journal: a missing file reads as empty, a corrupt one as unreadable")

        let local = [LocalAddress(interface: "lo0", ip: me)]
        let read: @Sendable () -> (ListenResolution, [String: Any]?) = {
            let plist = ListenConfig.readPlist(url: url)
            return (ListenConfig.resolve(plist: plist, conf: (nil, nil), local: local), plist)
        }
        let gate: (ListenEndpoint, [String: Any]?) -> (AuthGate?, AuthConfigSnapshot) = { ep, plist in
            ControlService.authGate(clientIP: ep.clientIP, plist: plist, secret: nil, blocklist: ListenPlistBlocklist(url: url),
                                    journal: PendingBlockFile(url: journalURL))
        }
        guard let a = bootService(read: read, url: url, gate: gate) else { expect(false, "r5 b5: service starts"); return }
        defer { a.servers.forEach { $0.stop() } }
        expect(!pong(MRC1Client(port: a.port)) && a.gate.guardian.lockdownReason() == "pending_journal_unreadable"
               && (try? Data(contentsOf: journalURL)) == garbage,
               "r5 b5 service: corrupt journal at start: even the whitelisted viewer is refused (transition mode), journal kept as is")

        let pwGuard = AuthGuard(whitelist: [me], blocklist: ListenPlistBlocklist(url: url), pause: { _ in },
                                journal: PendingBlockFile(url: journalURL))
        expect(pwGuard.admit(me) == .globalLocked(retrySeconds: AuthGuard.pendingRetrySeconds),
               "r5 b5: corrupt journal at start: password mode issues no challenge")

        chmod(journalURL.path, 0o000)
        let unreadable = PendingBlockFile(url: journalURL).load() == nil
        chmod(journalURL.path, 0o600)
        expect(unreadable || getuid() == 0, "r5 b5: journal: a file that cannot be opened reads as unreadable, not empty")

        let mem = MemoryPendingBlocks(); mem.unreadable = true
        let store = MemoryBlocklist(); store.failNextSaves = 999
        let g = AuthGuard(whitelist: [], blocklist: store, pause: { _ in }, journal: mem)
        for _ in 0..<20 { _ = g.recordFailure("100.64.0.7") }
        expect(mem.entries.isEmpty && !g.isDurable && g.lockdownReason() != nil,
               "r5 b5: while the journal does not read, a new unsaved block does not overwrite it and holds the exit")

        _ = PendingBlockFile(url: journalURL).save([BlockedEntry(ip: "100.64.0.9", at: Date(), reason: "test")])
        let back = settle { pong(MRC1Client(port: a.port)) }
        expect(back && a.gate.guardian.isBlocked("100.64.0.9") && ListenPlistBlocklist(url: url).load().map(\.ip) == ["100.64.0.9"]
               && PendingBlockFile(url: journalURL).load()?.isEmpty == true,
               "r5 b5 service: once the journal reads again its block is carried into listen.plist and the viewer is admitted")
    }

    // MARK: r6

    /// B5 r6: a pending journal that does not read holds the mouse relay and
    /// the UDP input too, at start and when it turns unreadable while
    /// running: new relay connections are refused, an open one is refused
    /// on its next move, and the video side drops UDP 0x24. Real sockets.
    private static func r6RelayLockdown(_ expect: Expect) {
        let fm = FileManager.default
        let dir = tempDir()
        defer { try? fm.removeItem(at: dir) }
        let url = dir.appendingPathComponent("listen.plist")
        let journalURL = dir.appendingPathComponent("auth-state/pending-blocks.plist")
        let me = ListenConfig.loopbackIP
        writePlist(loopbackBase(me), url)
        try? fm.createDirectory(at: journalURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        let garbage = Data("not a plist".utf8)
        try? garbage.write(to: journalURL)
        let local = [LocalAddress(interface: "lo0", ip: me)]
        let read: @Sendable () -> (ListenResolution, [String: Any]?) = {
            let plist = ListenConfig.readPlist(url: url)
            return (ListenConfig.resolve(plist: plist, conf: (nil, nil), local: local), plist)
        }
        guard let svc = bootService(read: read, url: url, gate: { ep, plist in
            ControlService.authGate(clientIP: ep.clientIP, plist: plist, secret: nil, blocklist: ListenPlistBlocklist(url: url),
                                    journal: PendingBlockFile(url: journalURL))
        }), let udpPort = ControlServiceSelfTest.freeLoopbackPort() else {
            expect(false, "r6 b5: service starts with the mouse relay"); return
        }
        defer { svc.servers.forEach { $0.stop() } }
        let relay = svc.servers[1]
        // The video side as JerisLinkHostMain wires it.
        let legacy = LegacyAuthWatch(url: url)
        let hold = PendingJournalHold(url: journalURL)
        let udp = MouseMoveUDPServer(bindIP: me, allowedClientIP: me, port: udpPort, relayPort: svc.relayPort,
                                     inputAllowed: PendingJournalHold.udpInputAllowed(legacy: legacy, hold: hold))
        guard (try? udp.start()) != nil else { expect(false, "r6 b5: UDP input starts"); return }
        defer { udp.stop() }
        let s = Darwin.socket(AF_INET, SOCK_DGRAM, 0)
        defer { Darwin.close(s) }
        var addr = ControlServiceSelfTest.loopbackAddress(port: udpPort)
        var seq: UInt8 = 0
        func move() {
            seq &+= 1
            let bytes: [UInt8] = [0x4d, 0x52, 0x4d, 0x31, 1, 0x24, 0, 0, 0, seq, 0x80, 0, 0x80, 0]
            _ = withUnsafePointer(to: &addr) { p in
                p.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    bytes.withUnsafeBytes { Darwin.sendto(s, $0.baseAddress!, bytes.count, 0, sa, socklen_t(MemoryLayout<sockaddr_in>.size)) }
                }
            }
        }

        let early = LocalControlMouseClient(port: svc.relayPort)
        _ = early.sendMouseMoveNormalized(nx: 1, ny: 1)
        move()
        Thread.sleep(forTimeInterval: 0.3)
        expect(relay.mouseEvents == 0 && udp.forwarded == 0 && udp.inputDropped == 1
               && svc.gate.guardian.lockdownReason() == "pending_journal_unreadable",
               "r6 b5 relay: corrupt journal at start: a new relay connection is refused and UDP 0x24 is dropped")

        try? fm.removeItem(at: journalURL)
        let open = LocalControlMouseClient(port: svc.relayPort)
        let viaRelay = settle { _ = open.sendMouseMoveNormalized(nx: 2, ny: 2); return relay.mouseEvents >= 1 }
        Thread.sleep(forTimeInterval: 0.3) // let the retries still in flight land first
        let before = relay.mouseEvents
        move()
        let viaUDP = settle { udp.forwarded == 1 && relay.mouseEvents == before + 1 }
        if !(viaRelay && viaUDP) {
            print("r6 b5 relay detail: viaRelay=\(viaRelay) viaUDP=\(viaUDP) forwarded=\(udp.forwarded) dropped=\(udp.inputDropped) events=\(relay.mouseEvents) before=\(before)")
        }
        expect(viaRelay && viaUDP && svc.gate.guardian.lockdownReason() == nil,
               "r6 b5 relay: once the journal is removed the relay and UDP input go on")

        try? garbage.write(to: journalURL)
        svc.watch.tick() // the once-a-second policy watch
        let held = relay.mouseEvents
        _ = open.sendMouseMoveNormalized(nx: 3, ny: 3)
        Thread.sleep(forTimeInterval: 0.3)
        expect(relay.mouseEvents == held && svc.gate.guardian.lockdownReason() == "pending_journal_unreadable"
               && svc.watch.appliedChange == nil,
               "r6 b5 relay: journal unreadable while running: the open relay connection's next move is refused, no policy change applied")
        move()
        Thread.sleep(forTimeInterval: 0.3)
        expect(udp.forwarded == 1 && udp.inputDropped == 2 && relay.mouseEvents == held
               && (try? Data(contentsOf: journalURL)) == garbage,
               "r6 b5 udp: journal unreadable while running: the next UDP 0x24 is dropped, journal kept as is")
    }
}
