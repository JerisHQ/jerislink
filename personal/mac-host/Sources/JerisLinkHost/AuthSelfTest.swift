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
        r7RelayBlacklist(expect)
        r8DirectBlacklist(expect)
        r9InFlightBlock(expect)
        r10StalledBlock(expect)
        r10ReplyBlock(expect)
        r10StalledBlock(expect, reopen: true)
        r11SendSliceFailClosed(expect)
        r12NonBlockingFailClosed(expect)
        r12KernelWait(expect)
        prcR12(expect)
        prcR13(expect)
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
        // PR-C r5 (Pepper's r4 review, item 2): the resume id is under mac_c.
        // The same fixed inputs and hex as the viewer's conn_auth_test.
        do {
            let k = [UInt8](repeating: 0x11, count: 32), hn = [UInt8](repeating: 0x22, count: 32)
            let cn = [UInt8](repeating: 0x33, count: 32), hid = [UInt8](repeating: 0x44, count: 16)
            let resume: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8]
            let plain = ConnAuth.macClient(key: k, hostNonce: hn, clientNonce: cn, channel: .control, hostID: hid)
            let signed = ConnAuth.macClient(key: k, hostNonce: hn, clientNonce: cn, channel: .control, hostID: hid, resume: resume)
            expect(ConnAuth.hex(plain) == "f80179160e285469a687e3e15aa31a4b9d4c1839d172211f97629a2194cb93bc",
                   "prc r5 vector: mac_c without a resume id (unchanged)")
            expect(ConnAuth.hex(signed) == "d683830f256aebbd4193876e4db47cce29fc0c36e54da8f81c0510136e1a43d5",
                   "prc r5 vector: mac_c covers the resume id")
            expect(ConnAuth.matchChannel(mac: signed, key: k, hostNonce: hn, clientNonce: cn, hostID: hid, resume: resume) == .control
                   && ConnAuth.matchChannel(mac: signed, key: k, hostNonce: hn, clientNonce: cn, hostID: hid) == nil
                   && ConnAuth.matchChannel(mac: plain, key: k, hostNonce: hn, clientNonce: cn, hostID: hid, resume: resume) == nil,
                   "prc r5 vector: the host matches mac_c only with the id it was signed with")
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

    /// Atomic (r10): a host thread checking the policy mid-write must not
    /// read half a file as mode "invalid", which stops the service.
    private static func writePlist(_ dict: [String: Any], _ url: URL) {
        if let d = try? PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0) { try? d.write(to: url, options: .atomic) }
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

    /// r12: a free loopback port for a session test. None is a FAIL, never
    /// a silent skip.
    private static func loopbackPort(_ expect: Expect, _ what: String) -> UInt16? {
        guard let p = ControlServiceSelfTest.freeLoopbackPort() else {
            expect(false, "\(what): loopback port (not skipped)")
            return nil
        }
        return p
    }

    // MARK: PR-C r12 (Morris's decision after Pepper's r11 review)

    /// PR-C r12: one session epoch. The right password takes over at once
    /// (the epoch moves on); every older connection is void from that moment
    /// and closed in the background; nothing resumes.
    private static func prcR12(_ expect: Expect) {
        let password = "PrcR12-\(UUID().uuidString.prefix(8))!"
        guard let secret = ConnSecret.make(password: password, iterations: 1000) else {
            expect(false, "prc r12: secret made")
            return
        }
        let me = ListenConfig.loopbackIP
        func id(_ v: UInt8) -> [UInt8] { [UInt8](repeating: v, count: 8) }
        func key(_ v: UInt8) -> [UInt8] { [UInt8](repeating: v, count: 32) }

        // Broker: the epoch, the background close, the replaced ids.
        do {
            let b = SessionBroker(passwordMode: true, log: { _ in })
            let closed = R10Names()
            let stuck = DispatchSemaphore(value: 0)
            let tA = b.admit(peerIP: me, channel: .control, sessionKey: key(0xA1), authSession: id(0xA1), resume: nil,
                             close: { closed.add("a-ctl") })
            let fA = b.admit(peerIP: me, channel: .file, sessionKey: nil, authSession: nil, resume: id(0xA1),
                             close: { _ = stuck.wait(timeout: .now() + 3); closed.add("a-file") })
            let liveBefore = [tA, fA].allSatisfy { $0.map(b.live) == true }
            // A's own reconnect: a new login too. Its file connection is void
            // at once, and its close (stuck here) does not hold up the AUTH.
            let started = Date()
            let tA2 = b.admit(peerIP: me, channel: .control, sessionKey: key(0xA2), authSession: id(0xA2), resume: id(0xA1),
                              close: { closed.add("a-ctl2") })
            let tookMs = Int(Date().timeIntervalSince(started) * 1000)
            let voidAtOnce = fA.map(b.live) == false && tA.map(b.live) == false && tA2.map(b.live) == true
            stuck.signal()
            b.flushClosesForTest()
            expect(tA != nil && fA != nil && tA2 != nil && liveBefore && voidAtOnce && tookMs < 500
                       && Set(closed.all) == ["a-ctl", "a-file"] && !b.resumeRefused(id(0xA1))
                       && !b.channelAdmitted(id(0xA1)) && b.channelAdmitted(id(0xA2)),
                   "prc r12 broker: a login (even the same viewer's) moves the epoch on: every older connection is void at once and closed in the background; a stuck close does not hold up the AUTH (took_ms=\(tookMs)); channels need the newest id")
            // Two takeovers in a row.
            let tB = b.admit(peerIP: "100.64.0.9", channel: .control, sessionKey: key(0xB1), authSession: id(0xB1), resume: nil, close: {})
            let tC = b.admit(peerIP: me, channel: .control, sessionKey: key(0xC1), authSession: id(0xC1), resume: nil, close: {})
            b.flushClosesForTest()
            expect(tB != nil && tC != nil && b.resumeRefused(id(0xA2)) && b.resumeRefused(id(0xA1)) && b.resumeRefused(id(0xB1))
                       && !b.resumeRefused(id(0xC1)) && tB.map(b.live) == false && tC.map(b.live) == true
                       && b.current.0?.sessionKey == key(0xC1),
                   "prc r12 broker: two takeovers in a row: both earlier viewers are replaced, the newest is live")
            // C's own login again; its AUTH_OK fails; it retries with its id.
            let tC2 = b.admit(peerIP: me, channel: .control, sessionKey: key(0xC2), authSession: id(0xC2), resume: id(0xC1), close: {})
            if let tC2 { b.abandon(tC2) }
            let afterLost = !b.resumeRefused(id(0xC1)) && !b.channelAdmitted(id(0xC2)) && b.current.0 == nil
            let tC3 = b.admit(peerIP: me, channel: .control, sessionKey: key(0xC3), authSession: id(0xC3), resume: id(0xC1), close: {})
            expect(tC2 != nil && afterLost && tC3 != nil && b.current.0?.sessionKey == key(0xC3) && b.resumeRefused(id(0xB1)),
                   "prc r12 broker: a login whose AUTH_OK failed leaves its own viewer free to log in again (not REPLACED); the viewers it took over from stay replaced")
            for t in [tC3] { if let t { b.end(t) } }
            // A restart: a new broker knows no replaced id.
            let r = SessionBroker(passwordMode: true, log: { _ in })
            expect(!r.resumeRefused(id(0xC1)) && !r.resumeRefused(id(0xB1)) && !r.channelAdmitted(id(0xC3)),
                   "prc r12 broker: after a restart every login is new: no id is refused, no channel goes in before a control login")
            // Transition mode: nothing is voided.
            let t = SessionBroker(passwordMode: false, log: { _ in })
            let x = t.begin(peerIP: me, channel: nil, sessionKey: nil, close: {})
            let y = t.begin(peerIP: me, channel: nil, sessionKey: nil, close: {})
            expect(t.live(x) && t.live(y), "prc r12 broker (transition): connections stay live")
            t.end(x); t.end(y)
        }

        // The connection's handle reads the broker.
        do {
            let b = SessionBroker(passwordMode: true, log: { _ in })
            let tA = b.admit(peerIP: me, channel: .control, sessionKey: key(1), authSession: id(1), resume: nil, close: {})!
            let tClip = b.admit(peerIP: me, channel: .clipboard, sessionKey: nil, authSession: nil, resume: id(1), close: {})!
            let life = KickHandle(-1)
            life.bind { b.live(tClip) }
            let fake = FakeClipboard(text: nil)
            let gated = SessionGatedClipboard(fake, life: life)
            let before = gated.writeText("r12 before")
            _ = b.admit(peerIP: me, channel: .control, sessionKey: key(2), authSession: id(2), resume: nil, close: {})
            let lateText = gated.writeText("r12 late")
            let lateFiles = gated.writeFileURLs([URL(fileURLWithPath: "/tmp/jl-r12-late")])
            let reused = KickHandle(-1)
            expect(before != nil && life.isRevoked && lateText == nil && lateFiles == nil && fake.writes == ["r12 before"]
                       && fake.fileURLs.isEmpty && !reused.isRevoked && reused.whileLive({ 1 }) == 1,
                   "prc r12 handle: once the epoch moved no text or file write of the old connection lands; a new handle is unaffected")
            b.end(tA); b.end(tClip)
        }

        /// Connects, reads the CHALLENGE and answers it for `channel`.
        func login(_ port: UInt16, _ channel: ConnAuth.Channel, resume: [UInt8]? = nil) -> (client: MRC1Client?, result: ConnAuth.Result?) {
            guard let c = startAuth(port, channel, resume: resume) else { return (nil, nil) }
            guard let r = c.receive(timeout: 3), r.type == ConnAuth.MsgType.result else { return (c, nil) }
            return (c, ConnAuth.Result.decode(r.payload))
        }
        /// The RESPONSE is sent; the result is left unread.
        func startAuth(_ port: UInt16, _ channel: ConnAuth.Channel, resume: [UInt8]?) -> MRC1Client? {
            guard let c = MRC1Client(port: port), let ch = c.receive(timeout: 2), ch.type == ConnAuth.MsgType.challenge,
                  let challenge = ConnAuth.Challenge.decode(ch.payload),
                  let k = ConnAuth.deriveKey(password: password, salt: challenge.salt, iterations: challenge.iterations)
            else { return nil }
            let cn = ConnAuth.random(ConnAuth.nonceBytes)
            let mac = ConnAuth.macClient(key: k, hostNonce: challenge.hostNonce, clientNonce: cn, channel: channel,
                                         hostID: challenge.hostID, resume: resume)
            guard c.send(type: ConnAuth.MsgType.response,
                         payload: ConnAuth.Response(clientNonce: cn, mac: mac, resume: resume).payload) else { return nil }
            return c
        }
        func okID(_ r: (client: MRC1Client?, result: ConnAuth.Result?)) -> [UInt8]? {
            if case .ok(_, let sid)? = r.result { return sid }
            return nil
        }
        /// Reads what the host sends until it closes (or `seconds` pass).
        func drain(_ c: MRC1Client?, _ seconds: Double) -> (payloads: [[UInt8]], closed: Bool) {
            guard let c else { return ([], true) }
            var out: [[UInt8]] = []
            let until = Date().addingTimeInterval(seconds)
            while Date() < until && !c.sawEOF {
                if let m = c.receive(timeout: 0.2) { out.append(m.payload) }
            }
            return (out, c.sawEOF || c.hostClosed())
        }
        func server(_ port: UInt16, clipboard: FakeClipboard, root: URL? = nil, folder: FileSendFolder? = nil) -> ControlServer {
            let gate = AuthGate(policy: .password(whitelist: [me]),
                                guardian: AuthGuard(whitelist: [me], blocklist: MemoryBlocklist([])),
                                secret: secret, timeout: 2)
            return ControlServer(bindIP: me, allowedClientIP: nil, port: port, inject: false,
                                 settingsClientIP: { me }, acceptProxy: false, inputHelper: nil,
                                 allowFileSessions: root != nil,
                                 fileStagingRoot: root?.appendingPathComponent("staging", isDirectory: true) ?? FileUploadReceiver.defaultRoot,
                                 fileSendFolder: folder ?? .shared,
                                 clipboard: clipboard, authGate: gate,
                                 sessionBroker: SessionBroker(passwordMode: true, log: { _ in }))
        }

        // End to end: an old file step stuck, an old clipboard text already
        // read, a takeover; then the same viewer's own login again.
        if let p = ControlServiceSelfTest.freeLoopbackPort() {
            let fake = FakeClipboard(text: nil)
            let dir = FileManager.default.temporaryDirectory.appendingPathComponent("jl-prc-r12-\(UUID().uuidString)", isDirectory: true)
            defer { try? FileManager.default.removeItem(at: dir) }
            // The send folder is made with a plain mkdir: its parent must exist.
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            let folder = FileSendFolder(primary: dir.appendingPathComponent("send", isDirectory: true),
                                        fallback: dir.appendingPathComponent("received", isDirectory: true),
                                        openFolder: { _ in })
            let s = server(p, clipboard: fake, root: dir, folder: folder)
            let fileHold = R11Hold(), clipHold = R11Hold()
            s.beforeSessionEffectForTest = { kind in
                if kind == "file" { fileHold.pass() }
                if kind == "clipboard" { clipHold.pass() }
            }
            if (try? s.start()) != nil {
                typealias M = FileProto.Message
                let a = login(p, .control)
                if let idA = okID(a) {
                    // A's file channel: a send drop, stuck in a step.
                    let file = login(p, .file, resume: idA)
                    _ = file.client?.send(type: FileProto.MsgType.hello, payload: [1, 0, 0])
                    let ack = file.client?.receive(timeout: 2)?.type == FileProto.MsgType.helloAck
                    let body = [UInt8](repeating: 0x5C, count: 70_000)
                    func put(_ m: M) { _ = file.client?.send(type: m.type, payload: m.encode() ?? []) }
                    put(.offer(transfer: 31, purpose: FileProto.Purpose.send, entries: 1, total: UInt64(body.count)))
                    put(FileUploadSelfTest.entry(31, 0, "r12.bin", size: body.count))
                    let reply = file.client?.receive(timeout: 3).flatMap { FileProto.decode(type: $0.type, payload: $0.payload) }
                    // Held inside the first data step (it passed its check).
                    fileHold.arm()
                    for m in FileUploadSelfTest.chunks(31, 0, body) { put(m) }
                    let held = fileHold.waitEntered()
                    put(.fileEnd(transfer: 31, index: 0, sha256: FileUploadSelfTest.sha(body)))
                    // A's clipboard channel: a text read, held before its write.
                    let clip = login(p, .clipboard, resume: idA)
                    _ = clip.client?.send(type: 0x30, payload: [])
                    clipHold.arm()
                    _ = clip.client?.send(type: 0x31, payload: Array("r12 stale".utf8))
                    let inClip = clipHold.waitEntered()
                    // B logs in while both are held: its AUTH_OK does not wait.
                    let started = Date()
                    let b = login(p, .control)
                    let okMs = Int(Date().timeIntervalSince(started) * 1000)
                    let idB = okID(b)
                    fileHold.release(); clipHold.release()
                    // What A's file channel still gets: no RESULT, then the close.
                    var results: [M] = []
                    let until = Date().addingTimeInterval(3)
                    while Date() < until, let c = file.client, !c.sawEOF {
                        if let m = c.receive(timeout: 0.2), m.type == FileProto.MsgType.result,
                           let r = FileProto.decode(type: m.type, payload: m.payload) { results.append(r) }
                    }
                    let fileClosed = file.client.map { $0.sawEOF || $0.hostClosed() } ?? true
                    let clipEnd = drain(clip.client, 3)
                    let landed = (try? FileManager.default.contentsOfDirectory(atPath: folder.primary.path)) ?? []
                    let staging = FileUploadSelfTest.transferDirs(dir.appendingPathComponent("staging", isDirectory: true))
                    print("prc r12 takeover info: ack=\(ack) reply=\(String(describing: reply)) held=\(held) in_clip=\(inClip) ok_ms=\(okMs) file_closed=\(fileClosed) clip_closed=\(clipEnd.closed) landed=\(landed) staging=\(staging.count) writes=\(fake.writes)")
                    expect(ack && reply == .reply(transfer: 31, status: FileProto.Status.ok) && held && inClip
                               && idB != nil && okMs < 1500,
                           "prc r12 takeover (e2e): with the old viewer's file step and clipboard write both stuck, the new viewer's AUTH_OK comes at once (\(okMs) ms)")
                    expect(fileClosed && results.isEmpty && landed.isEmpty && staging.isEmpty,
                           "prc r12 takeover (e2e): the old file transfer is dropped, not finished: no RESULT, nothing in the send folder, no staging left")
                    expect(clipEnd.closed && !fake.writes.contains("r12 stale") && Self.pong(b.client),
                           "prc r12 takeover (e2e): the old clipboard text, already read, is not written; the new viewer works")
                    // Old channels naming A's id stay out; A's control is replaced.
                    let aClip = login(p, .clipboard, resume: idA)
                    let aBack = login(p, .control, resume: idA)
                    expect(aClip.result == nil && aBack.result == .replaced,
                           "prc r12 takeover (e2e): a channel naming the old id is closed; the old viewer's control login gets REPLACED")
                    // B's own login again cuts B's own file channel; nothing resumes.
                    if let idB {
                        let bFile = login(p, .file, resume: idB)
                        _ = bFile.client?.send(type: FileProto.MsgType.hello, payload: [1, 0, 0])
                        let bAck = bFile.client?.receive(timeout: 2)?.type == FileProto.MsgType.helloAck
                        let b2 = login(p, .control, resume: idB)
                        let idB2 = okID(b2)
                        let bFileEnd = drain(bFile.client, 3)
                        let oldName = login(p, .clipboard, resume: idB)
                        let newName = login(p, .clipboard, resume: idB2)
                        expect(bAck && idB2 != nil && bFileEnd.closed && oldName.result == nil && okID(newName) != nil
                                   && Self.pong(b2.client),
                               "prc r12 own login (e2e): the same viewer logging in again closes its own file channel (no resume); its channels come back on the new id only")
                        bFile.client?.close(); b2.client?.close(); oldName.client?.close(); newName.client?.close()
                    } else {
                        expect(false, "prc r12 (e2e): B login ok")
                    }
                    file.client?.close(); clip.client?.close(); b.client?.close(); aClip.client?.close(); aBack.client?.close()
                } else {
                    expect(false, "prc r12 (e2e): A login ok")
                }
                a.client?.close()
                s.stop()
            } else {
                expect(false, "prc r12: listener starts")
            }
        } else {
            expect(false, "prc r12 takeover (e2e): loopback port (not skipped)")
        }

        // End to end: AUTH_OK lost, retries; two takeovers in a row.
        if let p = ControlServiceSelfTest.freeLoopbackPort() {
            let s = server(p, clipboard: FakeClipboard(text: nil))
            let hold = R7Hold()
            s.failAuthOKForTest = { ok in ok.channel == .control && hold.take(ok.sessionID) }
            if (try? s.start()) != nil {
                // A first login whose OK is lost, then the retry.
                hold.arm()
                let lost = login(p, .control)
                let retry = login(p, .control)
                let idA = okID(retry)
                // A's own login again (naming idA), OK lost; retry with idA.
                hold.arm()
                let lost2 = login(p, .control, resume: idA)
                let retry2 = login(p, .control, resume: idA)
                let idA2 = okID(retry2)
                print("prc r12 ok lost info: lost=\(String(describing: lost.result)) retry=\(idA != nil) lost2=\(String(describing: lost2.result)) retry2=\(String(describing: retry2.result))")
                expect(lost.result == nil && idA != nil && lost2.result == nil && idA2 != nil && Self.pong(retry2.client)
                           && s.authFailures == 0 && s.resumesRefused == 0,
                       "prc r12 OK lost (e2e): a login whose AUTH_OK never reached the viewer is retried with the password and gets in, never REPLACED and never counted as a failure")
                // Two takeovers in a row: A2 -> B -> C.
                let b = login(p, .control)
                let c = login(p, .control)
                let idB = okID(b), idC = okID(c)
                let aBack = login(p, .control, resume: idA2)
                let bBack = login(p, .control, resume: idB)
                expect(idB != nil && idC != nil && aBack.result == .replaced && bBack.result == .replaced && Self.pong(c.client)
                           && s.authFailures == 0,
                       "prc r12 twice (e2e): after two takeovers in a row both earlier viewers get REPLACED, the newest works")
                for x in [lost.client, retry.client, lost2.client, retry2.client, b.client, c.client, aBack.client, bBack.client] { x?.close() }
                s.stop()
            } else {
                expect(false, "prc r12 OK lost: listener starts")
            }
        } else {
            expect(false, "prc r12 OK lost (e2e): loopback port (not skipped)")
        }

        // End to end: a restarted host (a new server and broker).
        if let p = ControlServiceSelfTest.freeLoopbackPort() {
            let s = server(p, clipboard: FakeClipboard(text: nil))
            if (try? s.start()) != nil {
                let before = ConnAuth.random(8)   // the id the viewer had before the restart
                let first = login(p, .control, resume: before)
                let firstOK = okID(first) != nil && Self.pong(first.client)
                first.client?.close()
                // Once more, with the first AUTH_OK after the restart lost.
                let s2p = ControlServiceSelfTest.freeLoopbackPort()
                var lostThenOK = false
                if let p2 = s2p {
                    let s2 = server(p2, clipboard: FakeClipboard(text: nil))
                    let hold2 = R7Hold()
                    s2.failAuthOKForTest = { ok in ok.channel == .control && hold2.take(ok.sessionID) }
                    if (try? s2.start()) != nil {
                        hold2.arm()
                        let lost = login(p2, .control, resume: before)
                        let again = login(p2, .control, resume: before)
                        lostThenOK = lost.result == nil && okID(again) != nil && Self.pong(again.client) && s2.authFailures == 0
                        lost.client?.close(); again.client?.close()
                        s2.stop()
                    }
                }
                expect(firstOK && s2p != nil && lostThenOK,
                       "prc r12 restart (e2e): after a restart the viewer's login naming its old id gets in; with that first AUTH_OK lost, its retry gets in too (never REPLACED)")
                s.stop()
            } else {
                expect(false, "prc r12 restart: listener starts")
            }
        } else {
            expect(false, "prc r12 restart (e2e): loopback port (not skipped)")
        }

        // PR-C r13 (Pepper's r12 review, item 1): a stall at the final
        // landing point, after FILE_END passed its check (hash, commit);
        // a takeover; then the release. A send stalls right before the
        // send-folder move, a paste inside the pasteboard write (where the
        // main-thread block runs). Nothing may land.
        for purpose in [FileProto.Purpose.send, FileProto.Purpose.paste] {
            let what = purpose == FileProto.Purpose.send ? "send-folder move" : "pasteboard write"
            guard let p = Self.loopbackPort(expect, "prc r13 landing (\(what), e2e)") else { continue }
            let fake = FakeClipboard(text: nil)
            let dir = FileManager.default.temporaryDirectory.appendingPathComponent("jl-prc-r13-\(UUID().uuidString)", isDirectory: true)
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            defer { try? FileManager.default.removeItem(at: dir) }
            let folder = FileSendFolder(primary: dir.appendingPathComponent("send", isDirectory: true),
                                        fallback: dir.appendingPathComponent("received", isDirectory: true),
                                        openFolder: { _ in })
            let s = server(p, clipboard: fake, root: dir, folder: folder)
            let hold = R11Hold()
            s.beforeSessionEffectForTest = { kind in if kind == "land:send" { hold.pass() } }
            fake.landHook = { kind in if kind == "files" { hold.pass() } }
            guard (try? s.start()) != nil else { expect(false, "prc r13 landing (\(what)): listener starts"); continue }
            defer { s.stop() }
            let a = login(p, .control)
            guard let idA = okID(a) else { expect(false, "prc r13 landing (\(what)): A login ok"); a.client?.close(); continue }
            typealias M = FileProto.Message
            let file = login(p, .file, resume: idA)
            _ = file.client?.send(type: FileProto.MsgType.hello, payload: [1, 0, 0])
            let ack = file.client?.receive(timeout: 2)?.type == FileProto.MsgType.helloAck
            let body = [UInt8](repeating: 0x7E, count: 4096)
            func put(_ m: M) { _ = file.client?.send(type: m.type, payload: m.encode() ?? []) }
            put(.offer(transfer: 41, purpose: purpose, entries: 1, total: UInt64(body.count)))
            put(FileUploadSelfTest.entry(41, 0, "r13.bin", size: body.count))
            let reply = file.client?.receive(timeout: 3).flatMap { FileProto.decode(type: $0.type, payload: $0.payload) }
            for m in FileUploadSelfTest.chunks(41, 0, body) { put(m) }
            hold.arm()
            put(.fileEnd(transfer: 41, index: 0, sha256: FileUploadSelfTest.sha(body)))
            let held = hold.waitEntered()
            let b = login(p, .control)
            let idB = okID(b)
            hold.release()
            var results: [M] = []
            let until = Date().addingTimeInterval(3)
            while Date() < until, let c = file.client, !c.sawEOF {
                if let m = c.receive(timeout: 0.2), m.type == FileProto.MsgType.result,
                   let r = FileProto.decode(type: m.type, payload: m.payload) { results.append(r) }
            }
            let fileClosed = file.client.map { $0.sawEOF || $0.hostClosed() } ?? true
            let fm = FileManager.default
            let landed = ((try? fm.contentsOfDirectory(atPath: folder.primary.path)) ?? [])
                + ((try? fm.contentsOfDirectory(atPath: folder.fallback.path)) ?? [])
            let staging = FileUploadSelfTest.transferDirs(dir.appendingPathComponent("staging", isDirectory: true))
            print("prc r13 landing info: purpose=\(purpose) ack=\(ack) reply=\(String(describing: reply)) held=\(held) results=\(results.count) closed=\(fileClosed) landed=\(landed) pasteboard=\(fake.fileURLs.count) staging=\(staging.count)")
            expect(ack && reply == .reply(transfer: 41, status: FileProto.Status.ok) && held && idB != nil && fileClosed
                       && results.isEmpty && landed.isEmpty && fake.fileURLs.isEmpty && staging.isEmpty,
                   "prc r13 landing (e2e): stalled at the \(what) after FILE_END passed its check, a takeover, then the release: nothing lands, no RESULT, no staging left")
            file.client?.close(); a.client?.close(); b.client?.close()
        }

        // r13 item 1, text: the pasteboard write of a clipboard text is
        // already queued (held inside the backend's write, before its own
        // check) when a takeover comes in.
        if let p = Self.loopbackPort(expect, "prc r13 queued clipboard write (e2e)") {
            let fake = FakeClipboard(text: nil)
            let s = server(p, clipboard: fake)
            let hold = R11Hold()
            fake.landHook = { kind in if kind == "text" { hold.pass() } }
            if (try? s.start()) != nil {
                let a = login(p, .control)
                if let idA = okID(a) {
                    let clip = login(p, .clipboard, resume: idA)
                    _ = clip.client?.send(type: 0x30, payload: [])
                    hold.arm()
                    _ = clip.client?.send(type: 0x31, payload: Array("r13 queued".utf8))
                    let held = hold.waitEntered()
                    let b = login(p, .control)
                    let idB = okID(b)
                    hold.release()
                    let end = drain(clip.client, 3)
                    expect(held && idB != nil && end.closed && !fake.writes.contains("r13 queued") && Self.pong(b.client),
                           "prc r13 queued clipboard write (e2e): a text write already queued for the pasteboard when the takeover came in is checked where it lands and dropped; the new viewer works")
                    clip.client?.close(); b.client?.close()
                } else {
                    expect(false, "prc r13 queued clipboard write: A login ok")
                }
                a.client?.close()
                s.stop()
            } else {
                expect(false, "prc r13 queued clipboard write: listener starts")
            }
        }

        // r13 item 2: a PONG held at its socket write while a takeover comes
        // in. The control line's replies ask the epoch right before each
        // write (as the video ACK does); REPLACED goes by its own path.
        if let p = Self.loopbackPort(expect, "prc r13 control replies (e2e)") {
            let s = server(p, clipboard: FakeClipboard(text: nil))
            let hold = R11Hold()
            s.beforeCheckedSend = { type in if type == 0x02 { hold.pass() } }
            if (try? s.start()) != nil {
                let a = login(p, .control)
                if okID(a) != nil, let ac = a.client {
                    hold.arm()
                    _ = ac.send(type: 0x01, payload: [1, 2, 3, 4])
                    let held = hold.waitEntered()
                    let b = login(p, .control)
                    let idB = okID(b)
                    hold.release()
                    var frames: [(type: UInt8, payload: [UInt8])] = []
                    let until = Date().addingTimeInterval(3)
                    while Date() < until && !ac.sawEOF {
                        if let m = ac.receive(timeout: 0.2) { frames.append(m) }
                    }
                    let pong = frames.contains { $0.type == 0x02 }
                    let replaced = frames.contains { $0.type == ConnAuth.MsgType.result && ConnAuth.Result.decode($0.payload) == .replaced }
                    print("prc r13 control replies info: held=\(held) frames=\(frames.map { $0.type }) b_ok=\(idB != nil)")
                    expect(held && idB != nil && !pong && replaced && Self.pong(b.client),
                           "prc r13 control replies (e2e): a PONG held at its socket write while a takeover came in is not sent; the old control line still gets REPLACED (its own path); the new viewer's PONG works")
                    b.client?.close()
                } else {
                    expect(false, "prc r13 control replies: A login ok")
                }
                a.client?.close()
                s.stop()
            } else {
                expect(false, "prc r13 control replies: listener starts")
            }
        }
    }

    // MARK: PR-C r13 (Pepper's r12 review, items 3 and 4)

    private static func prcR13(_ expect: Expect) {
        let me = ListenConfig.loopbackIP
        func id(_ v: UInt8) -> [UInt8] { [UInt8](repeating: v, count: 8) }
        func key(_ v: UInt8) -> [UInt8] { [UInt8](repeating: v, count: 32) }

        // Item 3: a push job waiting for a file session when a takeover
        // voids it is not claimed; it is aborted.
        do {
            let b = SessionBroker(passwordMode: true, log: { _ in })
            _ = b.admit(peerIP: me, channel: .control, sessionKey: key(0x31), authSession: id(0x31), resume: nil, close: {})
            let life = KickHandle(-1)
            let tF = b.admit(peerIP: me, channel: .file, sessionKey: nil, authSession: nil, resume: id(0x31), close: {})
            if let tF { life.bind { b.live(tF) } }
            let pb = PushBroker()
            let sF = pb.register(peerCaps: FileProto.Caps.pushService)
            let job = PushJob(files: [])
            let queued = pb.offer(job) == nil
            _ = b.admit(peerIP: me, channel: .control, sessionKey: key(0x32), authSession: id(0x32), resume: nil, close: {})
            let claimed = pb.take(session: sF, live: { !life.isRevoked })
            let answer = job.wait(seconds: 1)
            expect(tF != nil && queued && claimed == nil && answer == .notConnected && pb.isIdle,
                   "prc r13 push claim: a job offered to a file session that a takeover then voided is not claimed; it is aborted (not_connected)")
            pb.unregister(sF)
        }
        // Item 3: a push the old session already runs: the takeover's kick
        // aborts it, and an accept read before the takeover changes nothing.
        do {
            let b = SessionBroker(passwordMode: true, log: { _ in })
            _ = b.admit(peerIP: me, channel: .control, sessionKey: key(0x41), authSession: id(0x41), resume: nil, close: {})
            let life = KickHandle(-1)
            let tF = b.admit(peerIP: me, channel: .file, sessionKey: nil, authSession: nil, resume: id(0x41),
                             close: { life.kick() })
            if let tF { life.bind { b.live(tF) } }
            let pb = PushBroker()
            let sF = pb.register(peerCaps: FileProto.Caps.pushService)
            life.onKick { pb.abort(session: sF) }
            let job = PushJob(files: [])
            let queued = pb.offer(job) == nil
            let taken = pb.take(session: sF, live: { !life.isRevoked })
            let sender = taken.map { PushSender(job: $0, live: { !life.isRevoked }) }
            _ = sender?.start()
            _ = b.admit(peerIP: me, channel: .control, sessionKey: key(0x42), authSession: id(0x42), resume: nil, close: {})
            b.flushClosesForTest()
            sender?.reply(FileProto.Status.ok)
            let answer = job.wait(seconds: 1)
            let next = pb.offer(PushJob(files: []))
            expect(tF != nil && queued && taken != nil && sender?.accepted == false && sender?.ended == true
                       && answer == .notConnected && job.isAbandoned && next == .notConnected,
                   "prc r13 push accept: a takeover aborts the push the old file session runs (not_connected, abandoned); its viewer's accept read before it is not marked accepted; the voided session gets no new job")
            if let taken { pb.finished(taken) }
            pb.unregister(sF)
        }

        // Item 4: a replaced id stays refused by age, never pushed out by
        // count: 5000 later takeovers (more than r12's old cap of 4096).
        do {
            let clock = R13Clock()
            let b = SessionBroker(passwordMode: true, log: { _ in }, now: { clock.now })
            let idA: [UInt8] = [0xA0, 0, 0, 0, 0, 0, 0, 1]
            _ = b.admit(peerIP: me, channel: .control, sessionKey: key(0xA0), authSession: idA, resume: nil, close: {})
            func other(_ i: Int) -> [UInt8] { [0xB0, 0, 0, 0] + withUnsafeBytes(of: UInt32(i).bigEndian, Array.init) }
            for i in 0..<5000 {
                _ = b.admit(peerIP: "100.64.0.\(i % 200 + 1)", channel: .control, sessionKey: key(0xB0),
                            authSession: other(i), resume: nil, close: {})
                if i == 2500 { clock.advance(SessionBroker.replacedTTL / 2) }
            }
            b.flushClosesForTest()
            let kept = b.replacedIDCount
            let refusedAfterMany = b.resumeRefused(idA)
                && b.admit(peerIP: me, channel: .control, sessionKey: key(0xA1), authSession: id(0xA1), resume: idA, close: {}) == nil
            // Past the window from A's replacement, but not from the later half.
            clock.advance(SessionBroker.replacedTTL / 2 + 1)
            let aGone = !b.resumeRefused(idA)
            let laterKept = b.resumeRefused(other(4000)) && !b.resumeRefused(other(100))
            expect(kept == 5000 && refusedAfterMany && aGone && laterKept,
                   "prc r13 replaced ids: an old viewer's id is still REPLACED after 5000 later takeovers (no count eviction, kept=\(kept)); ids leave only by age (\(Int(SessionBroker.replacedTTL / 3600)) h, monotonic)")
        }
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
        func login(_ port: UInt16, password: String, channel: ConnAuth.Channel, replay: [UInt8]? = nil, resume: [UInt8]? = nil,
                   macResume: [UInt8]?? = .none)
            -> (client: MRC1Client?, result: ConnAuth.Result?, response: [UInt8]?, macOK: Bool) {
            guard let c = MRC1Client(port: port), let ch = c.receive(timeout: 2) else { return (nil, nil, nil, false) }
            guard ch.type == ConnAuth.MsgType.challenge, let challenge = ConnAuth.Challenge.decode(ch.payload),
                  let key = ConnAuth.deriveKey(password: password, salt: challenge.salt, iterations: challenge.iterations) else {
                return (c, ch.type == ConnAuth.MsgType.result ? ConnAuth.Result.decode(ch.payload) : nil, nil, false)
            }
            let cn = ConnAuth.random(ConnAuth.nonceBytes)
            // r5: mac_c covers the resume id. `macResume` signs another one
            // (.some(nil): none), as a forged or stripped id would.
            let signed: [UInt8]? = macResume ?? resume
            let mac = ConnAuth.macClient(key: key, hostNonce: challenge.hostNonce, clientNonce: cn, channel: channel,
                                         hostID: challenge.hostID, resume: signed)
            let response = replay ?? ConnAuth.Response(clientNonce: cn, mac: mac, resume: resume).payload
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

        // r2 (item 2): with a session broker, a newer control AUTH tells the
        // old control connection it was replaced, then closes it.
        if let p = Self.loopbackPort(expect, "replace (e2e)") {
            let gate = AuthGate(policy: .password(whitelist: [me]),
                                guardian: AuthGuard(whitelist: [me], blocklist: MemoryBlocklist([])),
                                secret: secret, timeout: 2)
            let broker = SessionBroker(passwordMode: true, log: { _ in })
            let s = ControlServer(bindIP: me, allowedClientIP: nil, port: p, inject: false,
                                  settingsClientIP: { me }, acceptProxy: false, inputHelper: nil,
                                  clipboard: FakeClipboard(text: nil), authGate: gate, sessionBroker: broker)
            if (try? s.start()) != nil {
                let first = login(p, password: password, channel: .control)
                expect(pong(first.client), "replace: first viewer's control channel works")
                let second = login(p, password: password, channel: .control)
                // r3 (item 1): the old viewer's input still in flight does
                // not turn the close into a reset; it sees the notice, then FIN.
                // r4: the input goes out right after the replacing AUTH,
                // before the viewer reads anything, as from a viewer still
                // moving the mouse. With the old read-side shutdown macOS
                // answered it with an RST and the notice was never written
                // (`auth.replaced_notice sent=0` on the CI runner).
                var inputSent = true
                for i in 0..<20 where first.client?.send(type: 0x10, payload: [1, 0, UInt8(0x41 + i)]) != true {
                    inputSent = false
                }
                let notice = first.client?.receive(timeout: 2)
                expect(notice?.type == ConnAuth.MsgType.result
                       && notice.flatMap({ ConnAuth.Result.decode($0.payload) }) == .replaced
                       && first.client?.receive(timeout: 2) == nil,
                       "replace: the old control connection gets REPLACED (status 6), then closes")
                let fin = inputSent && first.client?.sawEOF == true && first.client?.sawReset == false
                if !fin {
                    print("replace close info: input_sent=\(inputSent) eof=\(first.client?.sawEOF == true) reset=\(first.client?.sawReset == true)")
                }
                expect(fin, "replace: after the notice the old connection ends with FIN, not RST")
                expect(pong(second.client), "replace: the new viewer's control channel works")
                expect(broker.replaced == 1, "replace: one connection replaced")
                // r4 (Pepper's r3 review, item 1): the old viewer missed the
                // notice and reconnects on its own, naming its old session.
                // The host refuses it (REPLACED, not counted) and the new
                // viewer keeps the session.
                if case .ok(_, let oldID)? = first.result, case .ok(_, let newID)? = second.result {
                    let failsBefore = s.authFailures
                    let back = login(p, password: password, channel: .control, resume: oldID)
                    expect(back.result == .replaced && back.client?.receive(timeout: 2) == nil,
                           "r4 resume: a replaced viewer's control reconnect gets REPLACED and is closed")
                    // r9: other channels on a replaced id are closed unread, no REPLACED.
                    let clip = login(p, password: password, channel: .clipboard, resume: oldID)
                    expect(clip.result == nil && clip.client?.receive(timeout: 1) == nil,
                           "r4 resume: its clipboard reconnect is closed (r9: no REPLACED on other channels)")
                    expect(s.authFailures == failsBefore && s.resumesRefused == 1 && broker.replaced == 1 && pong(second.client),
                           "r4 resume: nothing counted, nothing kicked, the new viewer's session works")
                    let own = login(p, password: password, channel: .control, resume: newID)
                    if case .ok? = own.result { expect(pong(own.client), "r4 resume: the current viewer's own reconnect is let in") }
                    else { expect(false, "r4 resume: the current viewer's own reconnect is let in") }
                    let fresh = login(p, password: password, channel: .control)
                    if case .ok? = fresh.result { expect(pong(fresh.client), "r4 resume: a new attempt (no resume id) still takes over") }
                    else { expect(false, "r4 resume: a new attempt (no resume id) still takes over") }
                } else {
                    expect(false, "r4 resume: both logins ok")
                }
                s.stop()
            } else {
                expect(false, "replace: listener starts")
            }
        }

        // PR-C r5 (Pepper's r4 review, items 1 and 2).
        if let p = Self.loopbackPort(expect, "prc r5 (e2e)") {
            let gate = AuthGate(policy: .password(whitelist: [me]),
                                guardian: AuthGuard(whitelist: [me], blocklist: MemoryBlocklist([])),
                                secret: secret, timeout: 2)
            let broker = SessionBroker(passwordMode: true, log: { _ in })
            let s = ControlServer(bindIP: me, allowedClientIP: nil, port: p, inject: false,
                                  settingsClientIP: { me }, acceptProxy: false, inputHelper: nil,
                                  clipboard: FakeClipboard(text: nil), authGate: gate, sessionBroker: broker)
            func sessionGone() -> Bool {
                let until = Date().addingTimeInterval(3)
                while Date() < until {
                    if broker.current.0 == nil { return true }
                    usleep(10_000)
                }
                return false
            }
            if (try? s.start()) != nil {
                // Item 1: A is replaced by B, then B goes offline. A missed the
                // notice and reconnects on its own: still refused.
                let a = login(p, password: password, channel: .control)
                let b = login(p, password: password, channel: .control)
                if case .ok(_, let idA)? = a.result, case .ok(_, let idB)? = b.result {
                    _ = a.client?.receive(timeout: 2)  // the notice A may or may not read
                    b.client?.close()
                    expect(sessionGone(), "prc r5 replaced: the new viewer went offline (no live session)")
                    let failsBefore = s.authFailures
                    let back = login(p, password: password, channel: .control, resume: idA)
                    expect(back.result == .replaced && back.client?.receive(timeout: 2) == nil,
                           "prc r5 replaced: after the new viewer left, the old viewer's control reconnect still gets REPLACED")
                    let clip = login(p, password: password, channel: .clipboard, resume: idA)
                    let file = login(p, password: password, channel: .file, resume: idA)
                    expect(clip.result == nil && file.result == nil,
                           "prc r5 replaced: its clipboard and file reconnects are closed too (r9: without REPLACED)")
                    expect(broker.current.0 == nil && s.authFailures == failsBefore,
                           "prc r5 replaced: no session taken over, nothing counted")
                    // B's own reconnect still works (it is the newest session).
                    let bBack = login(p, password: password, channel: .control, resume: idB)
                    if case .ok? = bBack.result { expect(pong(bBack.client), "prc r5 replaced: the newest viewer's own reconnect is let in") }
                    else { expect(false, "prc r5 replaced: the newest viewer's own reconnect is let in") }
                    bBack.client?.close()
                    _ = sessionGone()
                    // Only a new attempt from the user (no resume id) takes over.
                    let fresh = login(p, password: password, channel: .control)
                    if case .ok? = fresh.result { expect(pong(fresh.client), "prc r5 replaced: a new attempt (no resume id) takes over") }
                    else { expect(false, "prc r5 replaced: a new attempt (no resume id) takes over") }
                    fresh.client?.close()
                    _ = sessionGone()
                } else {
                    expect(false, "prc r5 replaced: both logins ok")
                }

                // Item 2: a normal control reconnect, then the other channels
                // at once (no wait) with the new id: all let in. The OK comes
                // after the broker took the session, so there is no gap.
                let c1 = login(p, password: password, channel: .control)
                if case .ok(_, let id1)? = c1.result {
                    c1.client?.close()
                    var allOK = true
                    var prev = id1
                    for round in 0..<20 {
                        let ctl = login(p, password: password, channel: .control, resume: prev)
                        guard case .ok(_, let id)? = ctl.result else {
                            expect(false, "prc r5 order: control reconnect \(round) ok"); allOK = false; break
                        }
                        let clip = login(p, password: password, channel: .clipboard, resume: id)
                        let file = login(p, password: password, channel: .file, resume: id)
                        let ping = login(p, password: password, channel: .ping, resume: id)
                        var each = true
                        for r in [clip.result, file.result, ping.result] { if case .ok? = r {} else { each = false } }
                        if !each || !pong(ctl.client) {
                            print("prc r5 order round=\(round) clip=\(String(describing: clip.result)) file=\(String(describing: file.result)) ping=\(String(describing: ping.result))")
                            allOK = false
                        }
                        // r12: a channel naming the id before is not let in
                        // (nothing resumes; the viewer's channels log in again).
                        let older = login(p, password: password, channel: .clipboard, resume: prev)
                        if older.result != nil { allOK = false }
                        for c in [clip.client, file.client, ping.client, older.client, ctl.client] { c?.close() }
                        prev = id
                    }
                    expect(allOK, "prc r5 order: after each of 20 control reconnects, clipboard/file/ping AUTH with the new id at once get ok (r12: the id before is closed)")
                    expect(s.resumesRefused == 1, "prc r5 order: no reconnect of the current viewer refused (only the control one above)")
                } else {
                    expect(false, "prc r5 order: first login ok")
                }

                // Item 2: the resume id is under mac_c.
                let d = login(p, password: password, channel: .control)
                if case .ok(_, let idD)? = d.result {
                    let failsBefore = s.authFailures
                    let unsigned = login(p, password: password, channel: .control, resume: idD, macResume: .some(nil))
                    expect(unsigned.result == .fail(triesLeft: 4) && s.authFailures == failsBefore + 1,
                           "prc r5 hmac: a resume id added outside mac_c fails (counted as a wrong proof)")
                    var other = idD
                    other[0] ^= 0x01
                    let changed = login(p, password: password, channel: .control, resume: other, macResume: .some(idD))
                    expect(changed.result == .fail(triesLeft: 3), "prc r5 hmac: a changed resume id fails")
                    let stripped = login(p, password: password, channel: .control, resume: nil, macResume: .some(idD))
                    expect(stripped.result == .fail(triesLeft: 2), "prc r5 hmac: a stripped resume id fails")
                    expect(pong(d.client), "prc r5 hmac: the session holder is untouched")
                    let signed = login(p, password: password, channel: .control, resume: idD)
                    if case .ok? = signed.result { expect(true, "prc r5 hmac: the signed resume id gets ok") }
                    else { expect(false, "prc r5 hmac: the signed resume id gets ok") }
                } else {
                    expect(false, "prc r5 hmac: login ok")
                }
                s.stop()
            } else {
                expect(false, "prc r5: listener starts")
            }
        }
        // Item 1 (broker): the replaced ids.
        do {
            let b = SessionBroker(passwordMode: true, log: { _ in })
            let idA: [UInt8] = [1, 1, 1, 1, 1, 1, 1, 1], idB: [UInt8] = [2, 2, 2, 2, 2, 2, 2, 2]
            let idB2: [UInt8] = [4, 4, 4, 4, 4, 4, 4, 4]
            let tA = b.admit(peerIP: me, channel: .control, sessionKey: [UInt8](repeating: 1, count: 32), authSession: idA,
                             resume: nil, close: {})
            let tB = b.admit(peerIP: me, channel: .control, sessionKey: [UInt8](repeating: 2, count: 32), authSession: idB,
                             resume: nil, close: {})
            if let tB { b.end(tB) }
            if let tA { b.end(tA) }
            expect(b.current.0 == nil && b.resumeRefused(idA) && !b.resumeRefused(idB),
                   "prc r5 broker: with nobody connected, the replaced id is refused and the newest is not")
            let tB2 = b.admit(peerIP: me, channel: .control, sessionKey: [UInt8](repeating: 3, count: 32), authSession: idB2,
                              resume: idB, close: {})
            expect(tB2 != nil && !b.resumeRefused(idB2) && !b.resumeRefused(idB) && b.resumeRefused(idA)
                       && !b.channelAdmitted(idB) && b.channelAdmitted(idB2),
                   "prc r5 broker: the same viewer logging in again is not refused; r12: its channels need the new id")
            if let tB2 { b.end(tB2) }
        }

        // PR-C r9 (Morris's simpler design, replacing the r6-r8 reservation
        // and wait): the right password takes over at once; other channels
        // go in only on a session that took over.
        do {
            let b = SessionBroker(passwordMode: true, log: { _ in })
            func id(_ v: UInt8) -> [UInt8] { [UInt8](repeating: v, count: 8) }
            func key(_ v: UInt8) -> [UInt8] { [UInt8](repeating: v, count: 32) }
            let closedA = R6Count(), closedClipA = R6Count()
            let tA = b.admit(peerIP: me, channel: .control, sessionKey: key(0xA1), authSession: id(0xA1), resume: nil,
                             close: { closedA.hit() })
            let cA = b.admit(peerIP: "100.64.0.9", channel: .clipboard, sessionKey: nil, authSession: nil, resume: id(0xA1),
                             close: { closedClipA.hit() })
            let tB = b.admit(peerIP: me, channel: .control, sessionKey: key(0xB1), authSession: id(0xB1), resume: nil, close: {})
            b.flushClosesForTest()   // r12: closed in the background
            expect(tA != nil && cA != nil && tB != nil && closedA.value == 1 && closedClipA.value == 1
                       && b.current.0?.sessionKey == key(0xB1) && b.resumeRefused(id(0xA1)) && !b.resumeRefused(id(0xB1)),
                   "prc r9 broker: the right password takes over at once: the old viewer is kicked and the UDP session switches")
            let unknown = b.admit(peerIP: me, channel: .clipboard, sessionKey: nil, authSession: nil, resume: id(0xEE), close: {})
            let none = b.admit(peerIP: me, channel: .file, sessionKey: nil, authSession: nil, resume: nil, close: {})
            let old = b.admit(peerIP: me, channel: .ping, sessionKey: nil, authSession: nil, resume: id(0xA1), close: {})
            let cur = b.admit(peerIP: me, channel: .clipboard, sessionKey: nil, authSession: nil, resume: id(0xB1), close: {})
            expect(unknown == nil && none == nil && old == nil && cur != nil
                       && !b.channelAdmitted(id(0xEE)) && !b.channelAdmitted(nil) && !b.channelAdmitted(id(0xA1)) && b.channelAdmitted(id(0xB1)),
                   "prc r9 broker: a clipboard/file/ping channel naming no id, an id that never took over or a replaced one is refused; the current id is let in")
            if let cur { b.end(cur) }
            // The OK of a takeover that already kicked B fails.
            let tC = b.admit(peerIP: me, channel: .control, sessionKey: key(0xC1), authSession: id(0xC1), resume: nil, close: {})
            if let tC { b.abandon(tC) }
            let fresh = SessionBroker(passwordMode: true, log: { _ in })
            let freshClip = fresh.admit(peerIP: me, channel: .clipboard, sessionKey: nil, authSession: nil, resume: id(0x77), close: {})
            expect(tC != nil && b.current.0 == nil && !b.channelAdmitted(id(0xC1)) && !b.resumeRefused(id(0xC1))
                       && b.resumeRefused(id(0xB1)) && b.resumeRefused(id(0xA1)) && freshClip == nil && !fresh.resumeRefused(id(0x77)),
                   "prc r9 broker: a takeover whose AUTH_OK failed leaves nothing half taken over: no session, no channel let in on its id, the viewers it replaced stay replaced (r12: its own viewer is not)")
            // The same viewer's reconnect (chained) whose OK fails keeps the id it had.
            let tD = b.admit(peerIP: me, channel: .control, sessionKey: key(0xD1), authSession: id(0xD1), resume: nil, close: {})
            let tD2 = b.admit(peerIP: me, channel: .control, sessionKey: key(0xD2), authSession: id(0xD2), resume: id(0xD1), close: {})
            if let tD2 { b.abandon(tD2) }
            let tD3 = b.admit(peerIP: me, channel: .control, sessionKey: key(0xD3), authSession: id(0xD3), resume: id(0xD1), close: {})
            expect(tD != nil && tD2 != nil && tD3 != nil && b.current.0?.sessionKey == key(0xD3),
                   "prc r9 broker: a viewer's own reconnect whose AUTH_OK failed can reconnect again with the id it had")
            for t in [tD3] { if let t { b.end(t) } }
            _ = tA; _ = tB
        }

        // PR-C r9 end to end.
        if let p = Self.loopbackPort(expect, "prc r9 (e2e)") {
            let gate = AuthGate(policy: .password(whitelist: [me]),
                                guardian: AuthGuard(whitelist: [me], blocklist: MemoryBlocklist([])),
                                secret: secret, timeout: 2)
            let broker = SessionBroker(passwordMode: true, log: { _ in })
            let fake = FakeClipboard(text: nil)
            let s = ControlServer(bindIP: me, allowedClientIP: nil, port: p, inject: false,
                                  settingsClientIP: { me }, acceptProxy: false, inputHelper: nil,
                                  clipboard: fake, authGate: gate, sessionBroker: broker)
            // The first control OK after `hold.arm()` fails (nothing written).
            let hold = R7Hold()
            s.failAuthOKForTest = { ok in ok.channel == .control && hold.take(ok.sessionID) }
            /// Connects and sends the RESPONSE for `channel`; the result is left unread.
            func startAuth(_ channel: ConnAuth.Channel, resume: [UInt8]?) -> MRC1Client? {
                guard let c = MRC1Client(port: p), let ch = c.receive(timeout: 2),
                      let challenge = ConnAuth.Challenge.decode(ch.payload),
                      let key = ConnAuth.deriveKey(password: password, salt: challenge.salt, iterations: challenge.iterations)
                else { return nil }
                let cn = ConnAuth.random(ConnAuth.nonceBytes)
                let mac = ConnAuth.macClient(key: key, hostNonce: challenge.hostNonce, clientNonce: cn, channel: channel,
                                             hostID: challenge.hostID, resume: resume)
                guard c.send(type: ConnAuth.MsgType.response,
                             payload: ConnAuth.Response(clientNonce: cn, mac: mac, resume: resume).payload) else { return nil }
                return c
            }
            /// AUTH with clipboard data right behind it: closed, no frame back.
            func clipboardShut(_ resume: [UInt8]?, _ text: String) -> Bool {
                guard let c = startAuth(.clipboard, resume: resume) else { return false }
                _ = c.send(type: 0x30, payload: [])
                _ = c.send(type: 0x31, payload: Array(text.utf8))
                defer { c.close() }
                return c.receive(timeout: 2) == nil
            }
            func sessionGone() -> Bool {
                let until = Date().addingTimeInterval(3)
                while Date() < until {
                    if broker.current.0 == nil { return true }
                    usleep(10_000)
                }
                return false
            }
            if (try? s.start()) != nil {
                let a = login(p, password: password, channel: .control)
                let b = login(p, password: password, channel: .control)
                if case .ok(_, let idA)? = a.result, case .ok(_, let idB)? = b.result {
                    let notice = a.client?.receive(timeout: 2)
                    expect(notice.flatMap({ ConnAuth.Result.decode($0.payload) }) == .replaced && a.client?.receive(timeout: 2) == nil
                               && pong(b.client) && broker.replaced == 1,
                           "prc r9 takeover (e2e): the right password takes over at once; the old viewer gets REPLACED and is closed")
                    // Other channels: unadmitted ids are closed at once, unread.
                    let base = fake.counts
                    let refusedBefore = s.resumesRefused
                    let shutOld = clipboardShut(idA, "r9 old")
                    let shutNone = clipboardShut(nil, "r9 none")
                    let shutUnknown = clipboardShut([UInt8](repeating: 0x5A, count: idB.count), "r9 unknown")
                    var fileShut = false
                    if let f = startAuth(.file, resume: idA) {
                        _ = f.send(type: FileProto.MsgType.hello, payload: [1, 0, 0, 0, 0])
                        fileShut = f.receive(timeout: 2) == nil
                        f.close()
                    }
                    let now = fake.counts
                    expect(shutOld && shutNone && shutUnknown && fileShut && fake.writes.isEmpty && s.clipboardReceived == 0
                               && now.changeCountReads == base.changeCountReads && now.textReads == base.textReads
                               && s.fileSessions == 0 && s.resumesRefused == refusedBefore && pong(b.client),
                           "prc r9 channel (e2e): clipboard/file naming a replaced, unknown or no id is closed at once: no REPLACED, no OK, no data read")
                    // The id that took over: let in, and the channels work.
                    let clip = login(p, password: password, channel: .clipboard, resume: idB)
                    let ping = login(p, password: password, channel: .ping, resume: idB)
                    var clipOK = false, pingOK = false
                    if case .ok? = clip.result { clipOK = true }
                    if case .ok? = ping.result { pingOK = pong(ping.client) }
                    _ = clip.client?.send(type: 0x30, payload: [])
                    _ = clip.client?.send(type: 0x31, payload: Array("r9 admitted".utf8))
                    let until = Date().addingTimeInterval(2)
                    while !fake.writes.contains("r9 admitted") && Date() < until { usleep(5_000) }
                    expect(clipOK && pingOK && fake.writes == ["r9 admitted"],
                           "prc r9 channel (e2e): clipboard/ping naming the id that took over get OK and work")
                    clip.client?.close(); ping.client?.close()

                    // C takes over; its OK fails. B was replaced, nothing is left.
                    hold.arm()
                    let c = login(p, password: password, channel: .control)
                    let idC = hold.id
                    let bNotice = b.client?.receive(timeout: 2)
                    let bReplaced = bNotice.flatMap({ ConnAuth.Result.decode($0.payload) }) == .replaced
                    let gone = sessionGone()
                    let shutC = idC.map { clipboardShut($0, "r9 unsent") } ?? false
                    expect(c.result == nil && idC != nil && bReplaced && gone && shutC && fake.writes == ["r9 admitted"],
                           "prc r9 OK lost (e2e): the takeover's AUTH_OK fails after it took over: the old viewer was replaced, no session is left, its id is let in nowhere")
                    // The new viewer (it got no id) reconnects: let in.
                    let cBack = login(p, password: password, channel: .control)
                    var cBackOK = false
                    if case .ok(_, let idC2)? = cBack.result {
                        cBackOK = pong(cBack.client)
                        // Its own reconnect, OK lost again, then once more with the same id.
                        hold.arm()
                        let lost = login(p, password: password, channel: .control, resume: idC2)
                        let again = login(p, password: password, channel: .control, resume: idC2)
                        if case .ok? = again.result, lost.result == nil { cBackOK = cBackOK && pong(again.client) } else { cBackOK = false }
                        again.client?.close()
                    }
                    expect(cBackOK, "prc r9 OK lost (e2e): the new viewer's reconnect gets in (fresh, and again with its own id after another lost OK)")
                    cBack.client?.close()
                    // The replaced viewers stay replaced.
                    let aBack = login(p, password: password, channel: .control, resume: idA)
                    let bBack = login(p, password: password, channel: .control, resume: idB)
                    expect(aBack.result == .replaced && bBack.result == .replaced && aBack.client?.receive(timeout: 2) == nil,
                           "prc r9 replaced (e2e): a replaced viewer's control reconnect gets REPLACED (it does not take the session back)")
                } else {
                    expect(false, "prc r9 (e2e): both logins ok")
                }
                s.stop()
            } else {
                expect(false, "prc r9: listener starts")
            }
        }

        // PR-C r10 end to end (Pepper's r9 review).
        if let p = Self.loopbackPort(expect, "prc r10 (e2e)") {
            let gate = AuthGate(policy: .password(whitelist: [me]),
                                guardian: AuthGuard(whitelist: [me], blocklist: MemoryBlocklist([])),
                                secret: secret, timeout: 2)
            let broker = SessionBroker(passwordMode: true, log: { _ in })
            let fake = FakeClipboard(text: nil)
            // File sessions on (as in the app), so the old viewer's file channel really opens.
            let r10Dir = FileManager.default.temporaryDirectory.appendingPathComponent("jl-prc-r10-\(UUID().uuidString)", isDirectory: true)
            defer { try? FileManager.default.removeItem(at: r10Dir) }
            let r10Folder = FileSendFolder(primary: r10Dir.appendingPathComponent("send", isDirectory: true),
                                           fallback: r10Dir.appendingPathComponent("received", isDirectory: true),
                                           openFolder: { _ in })
            let s = ControlServer(bindIP: me, allowedClientIP: nil, port: p, inject: false,
                                  settingsClientIP: { me }, acceptProxy: false, inputHelper: nil,
                                  allowFileSessions: true,
                                  fileStagingRoot: r10Dir.appendingPathComponent("staging", isDirectory: true),
                                  fileSendFolder: r10Folder,
                                  clipboard: fake, authGate: gate, sessionBroker: broker)
            let stall = R10AuthOKStall()
            s.sendHook = stall.send
            s.authOKSendSeconds = 0.4
            /// Reads what the host sends until it closes (or `seconds` pass).
            func drain(_ c: MRC1Client?, _ seconds: Double) -> (payloads: [[UInt8]], closed: Bool) {
                guard let c else { return ([], true) }
                var out: [[UInt8]] = []
                let until = Date().addingTimeInterval(seconds)
                while Date() < until && !c.sawEOF {
                    if let m = c.receive(timeout: 0.2) { out.append(m.payload) }
                }
                return (out, c.sawEOF || c.hostClosed())
            }
            if (try? s.start()) != nil {
                // Blocker 1: viewer A with clipboard and file open; viewer B from the same IP takes over.
                let a = login(p, password: password, channel: .control)
                if case .ok(_, let idA)? = a.result {
                    let clip = login(p, password: password, channel: .clipboard, resume: idA)
                    let file = login(p, password: password, channel: .file, resume: idA)
                    _ = clip.client?.send(type: 0x30, payload: [])
                    _ = file.client?.send(type: FileProto.MsgType.hello, payload: [1, 0, 0])   // FILE_HELLO is 3 bytes
                    let fileAck = file.client?.receive(timeout: 2)?.type == FileProto.MsgType.helloAck
                    // Both channels work before the takeover (Mac -> viewer and viewer -> Mac).
                    _ = clip.client?.send(type: 0x31, payload: Array("r10 before".utf8))
                    var until = Date().addingTimeInterval(2)
                    while !fake.writes.contains("r10 before") && Date() < until { usleep(5_000) }
                    // Let the clipboard loop poll after the write, so the next copy is a change it sees.
                    let polls = fake.counts.changeCountReads
                    _ = settle { fake.counts.changeCountReads >= polls + 2 }
                    fake.localCopy("r10 mac before")
                    var sawBefore = false
                    until = Date().addingTimeInterval(2)
                    while !sawBefore && Date() < until {
                        if let m = clip.client?.receive(timeout: 0.2), m.type == 0x31, m.payload == Array("r10 mac before".utf8) { sawBefore = true }
                    }
                    let workedBefore = fileAck && fake.writes.contains("r10 before") && sawBefore
                    let b = login(p, password: password, channel: .control)
                    var bOK = false
                    if case .ok? = b.result { bOK = pong(b.client) }
                    // After the takeover: a Mac copy must not reach A, A's clipboard text must not land.
                    fake.localCopy("r10 mac after")
                    _ = clip.client?.send(type: 0x31, payload: Array("r10 stale".utf8))
                    let clipEnd = drain(clip.client, 3)
                    let fileEnd = drain(file.client, 3)
                    let leaked = clipEnd.payloads.contains(Array("r10 mac after".utf8))
                    print("prc r10 same-ip info: worked_before=\(workedBefore) file_ack=\(fileAck) mac_copy_before=\(sawBefore) b_ok=\(bOK) clip_closed=\(clipEnd.closed) clip_frames_after=\(clipEnd.payloads.count) leaked=\(leaked) file_closed=\(fileEnd.closed) file_frames_after=\(fileEnd.payloads.count) writes=\(fake.writes)")
                    expect(workedBefore && bOK && clipEnd.closed && fileEnd.closed && !leaked
                               && !fake.writes.contains("r10 stale") && broker.current.0 != nil && pong(b.client),
                           "prc r10 same-IP takeover (e2e): the old viewer's open clipboard and file channels are cut: both closed, the Mac copy made after it does not reach the old viewer, its clipboard text is not applied")
                    clip.client?.close(); file.client?.close(); b.client?.close()
                } else {
                    expect(false, "prc r10 (e2e): login ok")
                }
                a.client?.close()

                // Item 3: AUTH_OK cannot be written (the window never opens): the host gives up within its limit.
                stall.arm()
                var gotOK = false, gaveUp = false, tookMs = -1
                if let c = MRC1Client(port: p), let ch = c.receive(timeout: 2),
                   let challenge = ConnAuth.Challenge.decode(ch.payload),
                   let k = ConnAuth.deriveKey(password: password, salt: challenge.salt, iterations: challenge.iterations) {
                    let cn = ConnAuth.random(ConnAuth.nonceBytes)
                    let mac = ConnAuth.macClient(key: k, hostNonce: challenge.hostNonce, clientNonce: cn, channel: .control,
                                                 hostID: challenge.hostID, resume: nil)
                    let started = Date()
                    if c.send(type: ConnAuth.MsgType.response, payload: ConnAuth.Response(clientNonce: cn, mac: mac, resume: nil).payload) {
                        // The host closes the connection once it gives up on the OK.
                        while Date().timeIntervalSince(started) < 4 && !gaveUp {
                            if let m = c.receive(timeout: 0.05), m.type == ConnAuth.MsgType.result { gotOK = true }
                            gaveUp = c.sawEOF || c.hostClosed()
                        }
                        tookMs = Int(Date().timeIntervalSince(started) * 1000)
                    }
                    c.close()
                }
                let sessionLeft = broker.current.0 != nil
                stall.disarm()
                let after = login(p, password: password, channel: .control)
                var afterOK = false
                if case .ok? = after.result { afterOK = pong(after.client) }
                print("prc r10 ok deadline info: stalled=\(stall.stalledFD != nil) eagain=\(stall.eagain) got_ok=\(gotOK) gave_up=\(gaveUp) took_ms=\(tookMs) session_left=\(sessionLeft) after_ok=\(afterOK)")
                expect(!gotOK && stall.stalledFD != nil && stall.eagain > 0 && gaveUp && tookMs >= 300 && tookMs < 2500
                           && !sessionLeft && afterOK,
                       "prc r10 AUTH_OK deadline (e2e): an AUTH_OK the viewer's window never takes is given up after its limit (0.4 s, monotonic): the connection closes, no session is left, the next login works")
                after.client?.close()
                s.stop()
            } else {
                expect(false, "prc r10: listener starts")
            }
        }

        for (type, what) in [(UInt8(0x10), "KEY"), (0x60, "FORCE_QUIT"), (0x30, "CLIPBOARD_HELLO"), (0x50, "FILE_HELLO"), (0x01, "PING")] {
            guard case let (s, p)? = server(.password(whitelist: [me]), secret: secret) else { expect(false, "e2e: listener"); continue }
            let c = MRC1Client(port: p)
            let ch = c?.receive(timeout: 2)
            // r3 (item 4): each first message as a real 0.3.x viewer sends it;
            // FORCE_QUIT_OPEN and CLIPBOARD_HELLO carry no payload.
            let legacy: [UInt8] = type == 0x01 ? [1, 2, 3, 4] : (type == 0x60 || type == 0x30) ? [] : [0, 0, 0]
            _ = c?.send(type: type, payload: legacy)
            let r = c?.receive(timeout: 2)
            expect(ch?.type == ConnAuth.MsgType.challenge && r?.type == ConnAuth.MsgType.result
                   && r.flatMap({ ConnAuth.Result.decode($0.payload) }) == .authRequired && c?.receive(timeout: 1) == nil,
                   "e2e: \(what) before AUTH gets AUTH_REQUIRED and is closed")
            s.stop()
        }

        // r2 (item 8): a 0.3.x viewer reconnecting in a loop is not counted
        // and so never locks its address out.
        if case let (s, p)? = server(.password(whitelist: [me]), secret: secret) {
            var answers = 0
            for _ in 0..<12 {
                let c = MRC1Client(port: p)
                _ = c?.receive(timeout: 2)
                _ = c?.send(type: 0x01, payload: [1, 2, 3, 4])
                if c?.receive(timeout: 2).flatMap({ ConnAuth.Result.decode($0.payload) }) == .authRequired { answers += 1 }
            }
            expect(answers == 12 && s.authFailures == 0 && s.oldViewersUncounted == 12,
                   "e2e: 12 old-viewer attempts all get AUTH_REQUIRED, none counted")
            if case .ok = login(p, password: password, channel: .control).result {
                expect(true, "e2e: after them the right password still gets ok (not locked)")
            } else {
                expect(false, "e2e: after them the right password still gets ok (not locked)")
            }
            s.stop()
        }

        // r2 (item 8): refusal log lines are throttled per event and peer.
        final class Lines: @unchecked Sendable { var t: TimeInterval = 50; var out: [String] = [] }
        let l = Lines()
        let throttle = AuthLogThrottle(now: { l.t }, write: { l.out.append($0) })
        for _ in 0..<140 { throttle.log("auth.locked", peer: "100.64.0.5", "auth.locked peer=100.64.0.5") }
        throttle.log("auth.locked", peer: "100.64.0.6", "auth.locked peer=100.64.0.6")
        expect(l.out == ["auth.locked peer=100.64.0.5", "auth.locked peer=100.64.0.6"] && throttle.suppressed == 139,
               "log: 140 refusals in 10 s log one line per peer")
        l.t += 10
        throttle.log("auth.locked", peer: "100.64.0.5", "auth.locked peer=100.64.0.5")
        expect(l.out.last == "auth.locked peer=100.64.0.5 suppressed=139", "log: the next line after 10 s says how many were left out")

        // r3 (item 4): the throttle table stays at 1024 keys even when 3000
        // peers arrive within one window; new peers share one overflow line.
        let flood = Lines()
        let capped = AuthLogThrottle(now: { flood.t }, write: { flood.out.append($0) })
        for i in 0..<3000 { capped.log("auth.no_response", peer: "100.64.\(i / 256).\(i % 256)", "auth.no_response peer=\(i)") }
        let overflowLines = flood.out.filter { $0.hasPrefix("auth.overflow ") }.count
        expect(capped.keyCount <= AuthLogThrottle.maxKeys && flood.out.count == AuthLogThrottle.maxKeys && overflowLines == 1,
               "log: 3000 peers in 10 s keep the table at \(AuthLogThrottle.maxKeys) keys (\(capped.keyCount)) with one overflow line")
        flood.t += 10
        capped.log("auth.no_response", peer: "100.99.0.1", "auth.no_response peer=late")
        expect(capped.keyCount <= AuthLogThrottle.maxKeys && flood.out.last == "auth.no_response peer=late",
               "log: after 10 s expired keys make room again")

        // r3 (item 4): only a real 0.3.x header is exempt. A wrong length
        // for PING, an unknown type or non-MRC1 bytes count a failure.
        if case let (s, p)? = server(.password(whitelist: [me]), secret: secret) {
            var fails: [ConnAuth.Result?] = []
            for raw in [[0x4d, 0x52, 0x43, 0x31, 1, 0x01, 0, 2, 9, 9] as [UInt8],
                        [0x4d, 0x52, 0x43, 0x31, 1, 0x7e, 0, 0],
                        Array("GET / HTTP/1.1\r\n\r\n".utf8)] {
                let c = MRC1Client(port: p)
                _ = c?.receive(timeout: 2)
                _ = c?.sendRaw(raw)
                fails.append(c?.receive(timeout: 2).flatMap { ConnAuth.Result.decode($0.payload) })
                c?.close()
            }
            expect(fails == [.fail(triesLeft: 4), .fail(triesLeft: 3), .fail(triesLeft: 2)]
                   && s.authFailures == 3 && s.oldViewersUncounted == 0,
                   "e2e: malformed headers are counted, not exempt as old viewers (\(fails))")
            s.stop()
        }

        // r3 (item 4): a viewer that closes before answering, in a loop,
        // logs one auth.no_response line per window.
        if case let (s, p)? = server(.password(whitelist: [me]), secret: secret) {
            for _ in 0..<6 {
                let c = MRC1Client(port: p)
                _ = c?.receive(timeout: 2)
                c?.close()
            }
            expect(settle { s.authLog.suppressed >= 5 } && s.authFailures == 0,
                   "e2e: 6 closes before answering log one no_response line (suppressed=\(s.authLog.suppressed))")
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
        var added = readPlist(url) ?? base
        added["blockedIPs"] = ((added["blockedIPs"] as? [Any]) ?? []) + ["100.64.0.9"]
        writePlist(added, url)
        expect(check() == nil && guardian.isBlocked("100.64.0.9"),
               "watch: r8: a block added to listen.plist from outside applies at once and does not restart")
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
        expect(g.admit("100.64.0.9") == .blocked && g.persistedIPs.contains("100.64.0.9"),
               "b5: that manual block applies at once (r8: and counts as persisted, so adding it does not restart the service)")
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
        let hold = PendingJournalHold(url: journalURL, plistURL: url)
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

    // MARK: r7

    /// B5 r7: a block restored from a pending journal that reads holds the
    /// viewer on the mouse relay and the UDP input as it does on the direct
    /// listener (transition mode). After a restart a new relay connection
    /// is refused and 0x24 dropped; a block the journal gains while a relay
    /// connection is open refuses that connection's next move and the next
    /// 0x24 with no policy-watch tick in between. Real sockets, real files.
    private static func r7RelayBlacklist(_ expect: Expect) {
        let fm = FileManager.default
        let dir = tempDir()
        defer { try? fm.removeItem(at: dir) }
        let url = dir.appendingPathComponent("listen.plist")
        let journalURL = dir.appendingPathComponent("auth-state/pending-blocks.plist")
        let me = ListenConfig.loopbackIP
        let local = [LocalAddress(interface: "lo0", ip: me)]
        let read: @Sendable () -> (ListenResolution, [String: Any]?) = {
            let plist = ListenConfig.readPlist(url: url)
            return (ListenConfig.resolve(plist: plist, conf: (nil, nil), local: local), plist)
        }
        func boot() -> Booted? {
            bootService(read: read, url: url, gate: { ep, plist in
                ControlService.authGate(clientIP: ep.clientIP, plist: plist, secret: nil, blocklist: ListenPlistBlocklist(url: url),
                                        journal: PendingBlockFile(url: journalURL))
            })
        }
        // The video side as JerisLinkHostMain wires it.
        var udpPort: UInt16 = 0
        func video(_ svc: Booted) -> MouseMoveUDPServer? {
            guard let port = ControlServiceSelfTest.freeLoopbackPort() else { return nil }
            udpPort = port
            let udp = MouseMoveUDPServer(bindIP: me, allowedClientIP: me, port: port, relayPort: svc.relayPort,
                                         inputAllowed: PendingJournalHold.udpInputAllowed(
                                            legacy: LegacyAuthWatch(url: url),
                                            hold: PendingJournalHold(url: journalURL, plistURL: url), viewerIP: me))
            return (try? udp.start()) != nil ? udp : nil
        }
        let s = Darwin.socket(AF_INET, SOCK_DGRAM, 0)
        defer { Darwin.close(s) }
        var seq: UInt8 = 0
        func move(_ udp: MouseMoveUDPServer) {
            seq &+= 1
            var addr = ControlServiceSelfTest.loopbackAddress(port: udpPort)
            let bytes: [UInt8] = [0x4d, 0x52, 0x4d, 0x31, 1, 0x24, 0, 0, 0, seq, 0x80, 0, 0x80, 0]
            _ = withUnsafePointer(to: &addr) { p in
                p.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    bytes.withUnsafeBytes { Darwin.sendto(s, $0.baseAddress!, bytes.count, 0, sa, socklen_t(MemoryLayout<sockaddr_in>.size)) }
                }
            }
        }
        let block = [BlockedEntry(ip: me, at: Date(), reason: "20 wrong passwords")]
        try? fm.createDirectory(at: journalURL.deletingLastPathComponent(), withIntermediateDirectories: true)

        // 1. Restart with a journal that reads and holds a block for the viewer.
        writePlist(loopbackBase(me), url)
        _ = PendingBlockFile(url: journalURL).save(block)
        if let a = boot(), let udp = video(a) {
            let relay = a.servers[1]
            let fresh = LocalControlMouseClient(port: a.relayPort)
            _ = fresh.sendMouseMoveNormalized(nx: 1, ny: 1)
            move(udp)
            Thread.sleep(forTimeInterval: 0.3)
            expect(relay.mouseEvents == 0 && udp.forwarded == 0 && udp.inputDropped == 1
                   && a.gate.guardian.isBlocked(me) && a.gate.guardian.lockdownReason() == nil
                   && a.gate.guardian.inputRefusal(me) == "blocked",
                   "r7 b5 relay: block restored from a readable journal after a restart: a new relay connection is refused and UDP 0x24 is dropped")
            udp.stop()
            a.servers.forEach { $0.stop() }
        } else {
            expect(false, "r7 b5 relay: block restored from a readable journal after a restart: a new relay connection is refused and UDP 0x24 is dropped")
        }

        // 2. No block: the relay and UDP input work; then the journal gains
        // a block for the viewer (another control-service process saving
        // its pending block on its way out) while the relay is open.
        writePlist(loopbackBase(me), url)
        try? fm.removeItem(at: journalURL)
        guard let b = boot(), let udp = video(b) else {
            expect(false, "r7 b5 relay: without a block the relay and UDP input go on"); return
        }
        defer { udp.stop(); b.servers.forEach { $0.stop() } }
        let relay = b.servers[1]
        let open = LocalControlMouseClient(port: b.relayPort)
        let viaRelay = settle { _ = open.sendMouseMoveNormalized(nx: 2, ny: 2); return relay.mouseEvents >= 1 }
        Thread.sleep(forTimeInterval: 0.3) // let the retries still in flight land first
        let before = relay.mouseEvents
        move(udp)
        let viaUDP = settle { udp.forwarded == 1 && relay.mouseEvents == before + 1 }
        expect(viaRelay && viaUDP && udp.inputDropped == 0,
               "r7 b5 relay: without a block the relay and UDP input go on")

        _ = PendingBlockFile(url: journalURL).save(block)
        let held = relay.mouseEvents
        _ = open.sendMouseMoveNormalized(nx: 3, ny: 3)
        Thread.sleep(forTimeInterval: 0.3)
        expect(relay.mouseEvents == held && b.gate.guardian.isBlocked(me) && b.watch.appliedChange == nil
               && ListenPlistBlocklist(url: url).load().map(\.ip) == [me],
               "r7 b5 relay: block gained from the journal while running: the open relay connection's next move is refused before any policy-watch tick, and the block reaches listen.plist")
        move(udp)
        Thread.sleep(forTimeInterval: 0.3)
        expect(udp.forwarded == 1 && udp.inputDropped == 1 && relay.mouseEvents == held,
               "r7 b5 udp: block gained from the journal while running: the next UDP 0x24 is dropped")
    }

    // MARK: r8

    /// B5 r8: a block that arrives while a direct connection is open (the
    /// pending journal gains it, or listen.plist is edited) closes that
    /// viewer's open direct sessions (control and ping, file, clipboard) on
    /// their next message, with no policy-watch tick and no restart; other
    /// viewers' sessions go on. Real sockets, real files.
    private static func r8DirectBlacklist(_ expect: Expect) {
        let fm = FileManager.default
        let dir = tempDir()
        defer { try? fm.removeItem(at: dir) }
        let url = dir.appendingPathComponent("listen.plist")
        let journalURL = dir.appendingPathComponent("auth-state/pending-blocks.plist")
        try? fm.createDirectory(at: journalURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        let me = ListenConfig.loopbackIP
        let local = [LocalAddress(interface: "lo0", ip: me)]
        let read: @Sendable () -> (ListenResolution, [String: Any]?) = {
            let plist = ListenConfig.readPlist(url: url)
            return (ListenConfig.resolve(plist: plist, conf: (nil, nil), local: local), plist)
        }
        let filePing = FileProto.Message.ping(token: [1, 2, 3, 4])
        func pong(_ c: MRC1Client, timeout: Double = 2) -> Bool {
            _ = c.send(type: 0x01, payload: [9, 8, 7, 6])
            return c.receive(timeout: timeout)?.type == 0x02
        }
        func fileEcho(_ c: MRC1Client, timeout: Double = 2) -> Bool {
            _ = c.send(type: filePing.type, payload: filePing.encode() ?? [])
            return c.receive(timeout: timeout)?.type == filePing.type
        }
        func openFile(_ c: MRC1Client) -> Bool {
            _ = c.send(type: 0x50, payload: [1, 0, 0])
            return c.receive(timeout: 3)?.type == 0x51
        }
        func journalBlock(_ ip: String) {
            _ = PendingBlockFile(url: journalURL).save([BlockedEntry(ip: ip, at: Date(), reason: "20 wrong passwords")])
        }
        func plistBlock(_ ip: String) {
            var d = readPlist(url) ?? [:]
            d["blockedIPs"] = ((d["blockedIPs"] as? [Any]) ?? []) + [ip]
            writePlist(d, url)
        }

        // a. The service as ControlService.run starts it, one viewer.
        let cases: [(String, (String) -> Void)] = [
            ("r8 b5 direct: block gained from the journal while running: the open control connection and file session are closed on their next message, no policy-watch tick, no restart", journalBlock),
            ("r8 b5 direct: block added to listen.plist while running: the open control connection and file session are closed on their next message, no restart", plistBlock),
        ]
        for (name, add) in cases {
            writePlist(loopbackBase(me), url)
            try? fm.removeItem(at: journalURL)
            guard let s = bootService(read: read, url: url, gate: { ep, plist in
                ControlService.authGate(clientIP: ep.clientIP, plist: plist, secret: nil, blocklist: ListenPlistBlocklist(url: url),
                                        journal: PendingBlockFile(url: journalURL))
            }), let ctl = MRC1Client(port: s.port), let file = MRC1Client(port: s.port) else {
                expect(false, name); continue
            }
            let direct = s.servers[0]
            let works = pong(ctl) && openFile(file) && fileEcho(file)
            add(me)
            let ctlAfter = pong(ctl, timeout: 0.5)
            let fileAfter = fileEcho(file, timeout: 0.5)
            expect(works && !ctlAfter && !fileAfter && direct.rejectedClients >= 2 && s.watch.appliedChange == nil
                   && !s.gate.isRevoked && s.gate.guardian.inputRefusal(me) == "blocked"
                   && ListenPlistBlocklist(url: url).load().map(\.ip) == [me],
                   name)
            ctl.close(); file.close()
            s.servers.forEach { $0.stop() }
        }

        // b. Three viewers on one direct listener, handed over by a local
        // PROXY forwarder (tailscale serve): a block for one and then for
        // another closes only theirs.
        let va = "100.64.0.21", vb = "100.64.0.22", vc = "100.64.0.23"
        writePlist(["mode": "loopback", "clientIP": me, "allowedIPs": [va, vb, vc], "passwordSet": false], url)
        try? fm.removeItem(at: journalURL)
        let (resolution, plist) = read()
        guard case .ready(let ep) = resolution, let port = ControlServiceSelfTest.freeLoopbackPort() else {
            expect(false, "r8 b5 direct: per peer: endpoint resolves"); return
        }
        let (made, snapshot) = ControlService.authGate(clientIP: ep.clientIP, plist: plist, secret: nil,
                                                       blocklist: ListenPlistBlocklist(url: url),
                                                       journal: PendingBlockFile(url: journalURL))
        guard let gate = made else { expect(false, "r8 b5 direct: per peer: gate"); return }
        let watch = PolicyWatch(started: ep, snapshot: snapshot, gate: gate, read: read, loadSecret: { nil },
                                stamp: { ListenFileStamp.of(url) })
        let board = FakeClipboard(text: "mac-before")
        let folder = FileSendFolder(primary: dir.appendingPathComponent("send", isDirectory: true),
                                    fallback: dir.appendingPathComponent("received", isDirectory: true),
                                    openFolder: { _ in })
        // The direct listener's wiring in ControlService.startServers, with
        // PROXY on so one loopback socket can stand for each viewer.
        let server = ControlServer(bindIP: me, allowedClientIP: nil, port: port, inject: false,
                                   settingsClientIP: { va }, acceptProxy: true, allowFileSessions: true,
                                   fileStagingRoot: dir.appendingPathComponent("staging", isDirectory: true),
                                   fileSendFolder: folder, clipboard: board, authGate: gate,
                                   admitConnection: { watch.admitNew() }, admitMessage: { watch.stillCurrent() },
                                   admitPeerMessage: ControlService.peerCheck(gate))
        func viewer(_ ip: String) -> MRC1Client? {
            guard let cl = MRC1Client(port: port), cl.sendRaw(Array("PROXY TCP4 \(ip) \(me) 40000 \(port)\r\n".utf8)) else { return nil }
            return cl
        }
        guard (try? server.start()) != nil, let aCtl = viewer(va), let aClip = viewer(va), let bCtl = viewer(vb),
              let bFile = viewer(vb), let cCtl = viewer(vc), let cFile = viewer(vc) else {
            expect(false, "r8 b5 direct: per peer: server and viewers start"); return
        }
        defer { [aCtl, aClip, bCtl, bFile, cCtl, cFile].forEach { $0.close() }; server.stop() }
        _ = aClip.send(type: 0x30, payload: [])                        // CLIPBOARD_HELLO
        _ = aClip.send(type: 0x31, payload: Array("a-before".utf8))
        let before = pong(aCtl) && pong(bCtl) && pong(cCtl) && openFile(bFile) && fileEcho(bFile)
            && openFile(cFile) && fileEcho(cFile) && settle { board.writes == ["a-before"] }
        expect(before, "r8 b5 direct: per peer: three viewers through a PROXY forwarder: control, clipboard and file sessions work")

        journalBlock(va)
        _ = aClip.send(type: 0x31, payload: Array("a-after".utf8))
        let aAfter = pong(aCtl, timeout: 0.5)
        Thread.sleep(forTimeInterval: 0.2)
        expect(!aAfter && board.writes == ["a-before"] && pong(bCtl) && pong(cCtl) && fileEcho(bFile) && fileEcho(cFile)
               && watch.appliedChange == nil && !gate.isRevoked,
               "r8 b5 direct: per peer: a journal block for one viewer closes its control connection and clipboard session on the next message; the other viewers go on")

        plistBlock(vb)
        let bCtlAfter = pong(bCtl, timeout: 0.5)
        let bFileAfter = fileEcho(bFile, timeout: 0.5)
        expect(!bCtlAfter && !bFileAfter && pong(cCtl) && fileEcho(cFile) && watch.appliedChange == nil
               && gate.guardian.isBlocked(vb) && !gate.guardian.isBlocked(vc),
               "r8 b5 direct: per peer: a listen.plist block for a second viewer closes its control connection and file session on the next message; the third viewer goes on, no restart")
    }

    // MARK: r9: a block stops a transfer already in flight

    /// r9 (Pepper): r8 closed a blocked viewer's file session on its next
    /// inbound message, but a REQUEST already taken went on sending up to
    /// 4 MiB. Every outbound frame now asks first: a block that lands
    /// mid-pull stops it before the next frame and closes the socket, and
    /// another viewer's pull of the same file, in flight across the block,
    /// finishes. Real sockets, one viewer per address through a PROXY
    /// forwarder, the direct listener's wiring. The blocked viewer reads
    /// through an 8 KiB receive buffer, so the host is mid-REQUEST when the
    /// block lands; what the kernel already held still drains.
    private static func r9InFlightBlock(_ expect: Expect) {
        typealias M = FileProto.Message
        let fm = FileManager.default
        let me = ListenConfig.loopbackIP
        let vx = "100.64.0.31", vy = "100.64.0.32"
        let body = FileAnnounceSelfTest.body(Int(FileAnnouncer.maxRequest))
        let chunk = Int(FileProto.maxChunk)
        for viaJournal in [true, false] {
            let source = viaJournal ? "the journal" : "listen.plist"
            let name = "r9 in-flight: a block from \(source) lands mid-pull (one 4 MiB REQUEST): the blocked viewer gets no further frame, no FILE_END, and its socket closes; the other viewer's pull in flight finishes with every byte and FILE_END; no restart"
            let dir = tempDir()
            defer { try? fm.removeItem(at: dir) }
            let url = dir.appendingPathComponent("listen.plist")
            let journalURL = dir.appendingPathComponent("auth-state/pending-blocks.plist")
            try? fm.createDirectory(at: journalURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            let src = dir.appendingPathComponent("src/big.bin")
            try? fm.createDirectory(at: src.deletingLastPathComponent(), withIntermediateDirectories: true)
            fm.createFile(atPath: src.path, contents: Data(body))
            let local = [LocalAddress(interface: "lo0", ip: me)]
            let read: @Sendable () -> (ListenResolution, [String: Any]?) = {
                let plist = ListenConfig.readPlist(url: url)
                return (ListenConfig.resolve(plist: plist, conf: (nil, nil), local: local), plist)
            }
            writePlist(["mode": "loopback", "clientIP": me, "allowedIPs": [vx, vy], "passwordSet": false], url)
            let (resolution, plist) = read()
            guard case .ready(let ep) = resolution, let port = ControlServiceSelfTest.freeLoopbackPort() else {
                expect(false, name); continue
            }
            let (made, snapshot) = ControlService.authGate(clientIP: ep.clientIP, plist: plist, secret: nil,
                                                           blocklist: ListenPlistBlocklist(url: url),
                                                           journal: PendingBlockFile(url: journalURL))
            guard let gate = made else { expect(false, name); continue }
            let watch = PolicyWatch(started: ep, snapshot: snapshot, gate: gate, read: read, loadSecret: { nil },
                                    stamp: { ListenFileStamp.of(url) })
            let board = FakeClipboard(text: "before")
            let folder = FileSendFolder(primary: dir.appendingPathComponent("send", isDirectory: true),
                                        fallback: dir.appendingPathComponent("received", isDirectory: true),
                                        openFolder: { _ in })
            let server = ControlServer(bindIP: me, allowedClientIP: nil, port: port, inject: false,
                                       settingsClientIP: { vy }, acceptProxy: true, allowFileSessions: true,
                                       fileStagingRoot: dir.appendingPathComponent("staging", isDirectory: true),
                                       fileSendFolder: folder, clipboard: board, authGate: gate,
                                       admitConnection: { watch.admitNew() }, admitMessage: { watch.stillCurrent() },
                                       admitPeerMessage: ControlService.peerCheck(gate))
            func viewer(_ ip: String, receiveBuffer: Int32? = nil) -> MRC1Client? {
                guard let cl = MRC1Client(port: port, receiveBuffer: receiveBuffer),
                      cl.sendRaw(Array("PROXY TCP4 \(ip) \(me) 40000 \(port)\r\n".utf8)) else { return nil }
                return cl
            }
            guard (try? server.start()) != nil, let x = viewer(vx, receiveBuffer: 8 * 1024), let y = viewer(vy) else {
                server.stop(); expect(false, name); continue
            }
            defer { x.close(); y.close(); server.stop() }
            func next(_ c: MRC1Client, _ timeout: Double = 3) -> M? {
                c.receive(timeout: timeout).flatMap { FileProto.decode(type: $0.type, payload: $0.payload) }
            }
            func announced(_ c: MRC1Client) -> UInt32? {
                guard case let .offer(t, _, _, _)? = next(c), case .entry? = next(c) else { return nil }
                return t
            }
            func request(_ c: MRC1Client, _ t: UInt32) {
                _ = c.send(type: FileProto.MsgType.request,
                           payload: M.request(transfer: t, index: 0, offset: 0, length: UInt32(body.count)).encode()!)
            }
            _ = x.send(type: 0x50, payload: [1, 0, UInt8(FileProto.Caps.announce)])
            _ = y.send(type: 0x50, payload: [1, 0, UInt8(FileProto.Caps.announce)])
            guard case .helloAck? = next(x), case .helloAck? = next(y),
                  settle({ board.counts.changeCountReads >= 6 }) else { expect(false, name); continue }
            board.localCopyFiles([src])
            guard let tx = announced(x), let ty = announced(y) else { expect(false, name); continue }
            request(x, tx)
            request(y, ty)
            // x's pull is under way: two chunks read, the host waits on x.
            var xBytes = 0, xFrames = 0, xEnd = false
            while xBytes < 2 * chunk, let m = next(x) {
                if case let .data(_, _, _, b) = m { xBytes += b.count }
            }
            let started = xBytes >= 2 * chunk
            if viaJournal {
                _ = PendingBlockFile(url: journalURL).save([BlockedEntry(ip: vx, at: Date(), reason: "20 wrong passwords")])
            } else {
                var d = readPlist(url) ?? [:]
                d["blockedIPs"] = ((d["blockedIPs"] as? [Any]) ?? []) + [vx]
                writePlist(d, url)
            }
            let atBlock = xBytes
            Thread.sleep(forTimeInterval: 0.3)
            // Only what the kernel already held drains; then EOF.
            while let m = next(x, 2) {
                xFrames += 1
                if case let .data(_, _, _, b) = m { xBytes += b.count }
                if case .fileEnd = m { xEnd = true }
            }
            var yBody: [UInt8] = []
            var yEnd: M?
            while let m = next(y) {
                if case let .data(_, _, off, b) = m, off == UInt64(yBody.count) { yBody += b }
                if case .fileEnd = m { yEnd = m; break }
                if case .reply = m { break }
            }
            print("r9 in-flight info: source=\(viaJournal ? "journal" : "listen.plist") blocked_viewer bytes_at_block=\(atBlock) bytes_total=\(xBytes) of \(body.count) frames_after_block=\(xFrames) file_end=\(xEnd) eof=\(x.sawEOF) tcp_closed=\(x.hostClosed()); other_viewer bytes=\(yBody.count) file_end=\(yEnd != nil)")
            expect(started && !xEnd && xBytes < body.count && x.sawEOF
                   && yBody == body && yEnd == .fileEnd(transfer: ty, index: 0, sha256: FileUploadSelfTest.sha(body))
                   && server.rejectedClients >= 1 && watch.appliedChange == nil && !gate.isRevoked
                   && gate.guardian.isBlocked(vx) && !gate.guardian.isBlocked(vy),
                   name)
        }
    }
}

extension AuthSelfTest {
    /// r10 rig: the direct listener's wiring (as r9), viewers through a
    /// PROXY header, a listen.plist and a journal in a temp folder.
    fileprivate final class R10Rig: @unchecked Sendable {
        let dir: URL, url: URL, journalURL: URL, src: URL
        let server: ControlServer, gate: AuthGate, watch: PolicyWatch, board: FakeClipboard
        let port: UInt16
        let me = ListenConfig.loopbackIP

        init?(allowed: [String], settingsIP: String, srcBody: [UInt8]? = nil) {
            let fm = FileManager.default
            let me = ListenConfig.loopbackIP
            let dir = AuthSelfTest.tempDir()
            let url = dir.appendingPathComponent("listen.plist")
            let journalURL = dir.appendingPathComponent("auth-state/pending-blocks.plist")
            let src = dir.appendingPathComponent("src/big.bin")
            try? fm.createDirectory(at: journalURL.deletingLastPathComponent(), withIntermediateDirectories: true)
            try? fm.createDirectory(at: src.deletingLastPathComponent(), withIntermediateDirectories: true)
            if let srcBody { fm.createFile(atPath: src.path, contents: Data(srcBody)) }
            let local = [LocalAddress(interface: "lo0", ip: me)]
            let read: @Sendable () -> (ListenResolution, [String: Any]?) = {
                let plist = ListenConfig.readPlist(url: url)
                return (ListenConfig.resolve(plist: plist, conf: (nil, nil), local: local), plist)
            }
            AuthSelfTest.writePlist(["mode": "loopback", "clientIP": me, "allowedIPs": allowed, "passwordSet": false], url)
            let (resolution, plist) = read()
            guard case .ready(let ep) = resolution, let p = ControlServiceSelfTest.freeLoopbackPort() else { return nil }
            let (made, snapshot) = ControlService.authGate(clientIP: ep.clientIP, plist: plist, secret: nil,
                                                           blocklist: ListenPlistBlocklist(url: url),
                                                           journal: PendingBlockFile(url: journalURL))
            guard let g = made else { return nil }
            let w = PolicyWatch(started: ep, snapshot: snapshot, gate: g, read: read, loadSecret: { nil },
                                stamp: { ListenFileStamp.of(url) })
            let board = FakeClipboard(text: "before")
            let folder = FileSendFolder(primary: dir.appendingPathComponent("send", isDirectory: true),
                                        fallback: dir.appendingPathComponent("received", isDirectory: true),
                                        openFolder: { _ in })
            server = ControlServer(bindIP: me, allowedClientIP: nil, port: p, inject: false,
                                   settingsClientIP: { settingsIP }, acceptProxy: true, allowFileSessions: true,
                                   fileStagingRoot: dir.appendingPathComponent("staging", isDirectory: true),
                                   fileSendFolder: folder, clipboard: board, authGate: g,
                                   admitConnection: { w.admitNew() }, admitMessage: { w.stillCurrent() },
                                   admitPeerMessage: ControlService.peerCheck(g))
            self.dir = dir; self.url = url; self.journalURL = journalURL; self.src = src
            self.gate = g; self.watch = w; self.board = board; self.port = p
        }

        func start() -> Bool { (try? server.start()) != nil }

        func viewer(_ ip: String, receiveBuffer: Int32? = nil) -> MRC1Client? {
            guard let cl = MRC1Client(port: port, receiveBuffer: receiveBuffer),
                  cl.sendRaw(Array("PROXY TCP4 \(ip) \(me) 40000 \(port)\r\n".utf8)) else { return nil }
            return cl
        }

        /// Blocks `ip` from the journal or from listen.plist.
        func block(_ ip: String, viaJournal: Bool) {
            if viaJournal {
                _ = PendingBlockFile(url: journalURL).save([BlockedEntry(ip: ip, at: Date(), reason: "20 wrong passwords")])
            } else {
                var d = AuthSelfTest.readPlist(url) ?? [:]
                d["blockedIPs"] = ((d["blockedIPs"] as? [Any]) ?? []) + [ip]
                AuthSelfTest.writePlist(d, url)
            }
        }

        func close() {
            server.stop()
            try? FileManager.default.removeItem(at: dir)
        }
    }

    /// r10 (blocker 1): the blocked viewer has stopped reading, so the host
    /// is waiting for its window inside a 4 MiB REQUEST when the block lands.
    /// The viewer never reads again; its connection is still closed within
    /// 2 s, and the host writes nothing to it after the block (host count).
    /// The other viewer's pull finishes with every byte and FILE_END.
    ///
    /// r11 (`reopen`): the same, but the viewer starts reading again right
    /// after the block, so its window reopens while the host waits. The host
    /// still writes 0 bytes after the block (its own write count; what the
    /// viewer reads is what the kernel already held) and the socket closes.
    fileprivate static func r10StalledBlock(_ expect: Expect, reopen: Bool = false) {
        typealias M = FileProto.Message
        let vx = "100.64.0.41", vy = "100.64.0.42"
        let body = FileAnnounceSelfTest.body(Int(FileAnnouncer.maxRequest))
        for viaJournal in [true, false] {
            let source = viaJournal ? "the journal" : "listen.plist"
            let name = reopen
                ? "r11 reopened window: a block from \(source) lands while the host waits on a viewer that stopped reading mid-pull, and the viewer then reads again so its window reopens: the host writes 0 bytes to it after the block (host write count), its socket closes within 2 s, no FILE_END; the other viewer's pull finishes with every byte and FILE_END"
                : "r10 stalled send: a block from \(source) lands while the host waits on a viewer that stopped reading mid-pull: its socket closes within 2 s without the viewer reading again, the host writes 0 bytes to it after the block, no FILE_END; the other viewer's pull finishes with every byte and FILE_END"
            guard let rig = R10Rig(allowed: [vx, vy], settingsIP: vy, srcBody: body), rig.start(),
                  let x = rig.viewer(vx, receiveBuffer: 8 * 1024), let y = rig.viewer(vy) else {
                expect(false, name); continue
            }
            defer { x.close(); y.close(); rig.close() }
            func next(_ c: MRC1Client, _ timeout: Double = 3) -> M? {
                c.receive(timeout: timeout).flatMap { FileProto.decode(type: $0.type, payload: $0.payload) }
            }
            func announced(_ c: MRC1Client) -> UInt32? {
                guard case let .offer(t, _, _, _)? = next(c), case .entry? = next(c) else { return nil }
                return t
            }
            _ = x.send(type: 0x50, payload: [1, 0, UInt8(FileProto.Caps.announce)])
            _ = y.send(type: 0x50, payload: [1, 0, UInt8(FileProto.Caps.announce)])
            guard case .helloAck? = next(x), case .helloAck? = next(y),
                  settle({ rig.board.counts.changeCountReads >= 6 }) else { expect(false, name); continue }
            rig.board.localCopyFiles([rig.src])
            guard let tx = announced(x), let ty = announced(y) else { expect(false, name); continue }
            for (c, t) in [(x, tx), (y, ty)] {
                _ = c.send(type: FileProto.MsgType.request,
                           payload: M.request(transfer: t, index: 0, offset: 0, length: UInt32(body.count)).encode()!)
            }
            // x reads nothing more: wait until the host's writes to it stop
            // (its window and the host's send buffer are full).
            var last = rig.server.txCount(peer: vx).bytes, still = 0
            let stallDeadline = Date().addingTimeInterval(5)
            while still < 4 && Date() < stallDeadline {
                Thread.sleep(forTimeInterval: 0.1)
                let now = rig.server.txCount(peer: vx).bytes
                if now == last && now > 0 { still += 1 } else { still = 0; last = now }
            }
            let stalled = still >= 4 && last < UInt64(body.count)
            let atBlock = rig.server.txCount(peer: vx)
            let blockedAt = Date()
            rig.block(vx, viaJournal: viaJournal)
            let drain = reopen ? R11Drain(x) : nil
            var closed = false
            while !closed && Date().timeIntervalSince(blockedAt) < 2 {
                Thread.sleep(forTimeInterval: 0.02)
                closed = x.hostClosed()
            }
            let closeMs = Int(Date().timeIntervalSince(blockedAt) * 1000)
            Thread.sleep(forTimeInterval: 0.3)
            let after = rig.server.txCount(peer: vx)
            let drained = drain?.finish()
            let viewerRead = drained?.bytes ?? 0
            let longestSend = rig.server.longestSendCallMillis
            var yBody: [UInt8] = []
            var yEnd: M?
            while let m = next(y) {
                if case let .data(_, _, off, b) = m, off == UInt64(yBody.count) { yBody += b }
                if case .fileEnd = m { yEnd = m; break }
                if case .reply = m { break }
            }
            print("\(reopen ? "r11 reopened" : "r10 stalled") info: source=\(viaJournal ? "journal" : "listen.plist") stalled=\(stalled) host_bytes_at_block=\(atBlock.bytes) host_sends_after_block=\(after.sends - atBlock.sends) host_bytes_after_block=\(after.bytes - atBlock.bytes) closed=\(closed) close_ms=\(closeMs) viewer_read_after_block=\(viewerRead) viewer_saw_close=\(drained?.sawClose ?? false) longest_send_call_ms=\(String(format: "%.3f", longestSend)); other_viewer bytes=\(yBody.count) file_end=\(yEnd != nil)")
            expect(stalled && closed && after.sends == atBlock.sends && after.bytes == atBlock.bytes
                   && yBody == body && yEnd == .fileEnd(transfer: ty, index: 0, sha256: FileUploadSelfTest.sha(body))
                   && rig.server.rejectedClients >= 1 && rig.watch.appliedChange == nil && !rig.gate.isRevoked
                   && rig.gate.guardian.isBlocked(vx) && !rig.gate.guardian.isBlocked(vy)
                   // r12: no send() call waited in the kernel (SO_SNDTIMEO would show 100 ms)
                   && longestSend < 50
                   // r12 (Pepper 2): the window really reopened: the viewer read
                   // bytes after the block, and then saw the socket close.
                   && (!reopen || (viewerRead > 0 && drained?.sawClose == true)),
                   name)
        }
    }

    /// r11: reads whatever the host sends to `client`, on its own thread,
    /// until `finish` or the host closes: the viewer's window reopens.
    fileprivate final class R11Drain: @unchecked Sendable {
        private let lock = NSLock()
        private var stop = false
        private var bytes = 0
        private var closed = false
        private let done = DispatchSemaphore(value: 0)

        init(_ client: MRC1Client) {
            Thread.detachNewThread { [self] in
                while true {
                    lock.lock(); let s = stop; lock.unlock()
                    if s { break }
                    let n = client.readAny(timeout: 0.05)
                    if n < 0 { lock.lock(); closed = true; lock.unlock(); break }
                    lock.lock(); bytes += n; lock.unlock()
                }
                done.signal()
            }
        }

        /// Stops reading. `bytes`: what the viewer read before the host
        /// closed; `sawClose`: the read loop ended on EOF/reset, not `finish`.
        func finish() -> (bytes: Int, sawClose: Bool) {
            lock.lock(); stop = true; lock.unlock()
            done.wait()
            lock.lock(); defer { lock.unlock() }
            return (bytes, closed)
        }
    }

    /// r11: a viewer socket whose send timeout cannot be set is not served
    /// (fail closed): the accept loop closes it before any frame.
    fileprivate static func r11SendSliceFailClosed(_ expect: Expect) {
        let v = "100.64.0.44"
        let name = "r11 send timeout unset: when SO_SNDTIMEO cannot be set on an accepted viewer socket the host closes that connection at once (fail closed): no reply, rejected count +1; on a real socket the setter succeeds"
        guard let rig = R10Rig(allowed: [v], settingsIP: v) else { expect(false, name); return }
        rig.server.sendSliceSetter = { _ in false }
        guard rig.start(), let c = rig.viewer(v) else { rig.close(); expect(false, name); return }
        defer { c.close(); rig.close() }
        _ = c.send(type: 0x01, payload: [])
        var closed = false
        let t0 = Date()
        while !closed && Date().timeIntervalSince(t0) < 1 {
            Thread.sleep(forTimeInterval: 0.02)
            closed = c.hostClosed()
        }
        let reply = c.receive(timeout: 0.3)
        let s = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        defer { Darwin.close(s) }
        let realOK = ControlServer.setSendSlice(s)
        print("r11 send timeout info: closed=\(closed) reply=\(reply != nil) rejected=\(rig.server.rejectedClients) real_setter_ok=\(realOK)")
        expect(closed && reply == nil && rig.server.rejectedClients >= 1 && realOK, name)
    }

    /// r12: a viewer socket that cannot be made O_NONBLOCK is not served
    /// (fail closed), like r11's send timeout; the real setter sets the flag.
    fileprivate static func r12NonBlockingFailClosed(_ expect: Expect) {
        let v = "100.64.0.45"
        let name = "r12 non-blocking unset: when O_NONBLOCK cannot be set on an accepted viewer socket the host closes that connection at once (fail closed): no reply, rejected count +1; on a real socket the setter sets O_NONBLOCK"
        guard let rig = R10Rig(allowed: [v], settingsIP: v) else { expect(false, name); return }
        rig.server.nonBlockingSetter = { _ in false }
        guard rig.start(), let c = rig.viewer(v) else { rig.close(); expect(false, name); return }
        defer { c.close(); rig.close() }
        _ = c.send(type: 0x01, payload: [])
        var closed = false
        let t0 = Date()
        while !closed && Date().timeIntervalSince(t0) < 1 {
            Thread.sleep(forTimeInterval: 0.02)
            closed = c.hostClosed()
        }
        let reply = c.receive(timeout: 0.3)
        let s = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        defer { Darwin.close(s) }
        let realOK = ControlServer.setNonBlocking(s) && fcntl(s, F_GETFL) & O_NONBLOCK != 0
        print("r12 non-blocking info: closed=\(closed) reply=\(reply != nil) rejected=\(rig.server.rejectedClients) real_setter_sets_flag=\(realOK)")
        expect(closed && reply == nil && rig.server.rejectedClients >= 1 && realOK, name)
    }

    /// r12 (Pepper 1): poll said writable (and r11's room estimate showed
    /// room), but the kernel cannot take the write. The hook stands in for
    /// that send(): on a blocking socket it waits, as the kernel would, until
    /// released; on an O_NONBLOCK socket the kernel answers EAGAIN instead,
    /// so the hook does too. The block lands while that write is pending;
    /// 200 ms later the kernel "has room" again (release). The host writes 0
    /// bytes to the viewer after the block and its socket closes.
    fileprivate static func r12KernelWait(_ expect: Expect) {
        typealias M = FileProto.Message
        let vx = "100.64.0.46"
        let body = FileAnnounceSelfTest.body(Int(FileAnnouncer.maxRequest))
        for viaJournal in [true, false] {
            let source = viaJournal ? "the journal" : "listen.plist"
            let name = "r12 kernel wait: poll says writable but the kernel cannot take the write (hook); a block from \(source) lands during that wait; once the kernel has room the host writes 0 bytes to the viewer after the block (host write count), its socket closes within 2 s, no FILE_END; the send never waited in the kernel"
            guard let rig = R10Rig(allowed: [vx], settingsIP: vx, srcBody: body), rig.start(),
                  let x = rig.viewer(vx) else { expect(false, name); continue }
            defer { x.close(); rig.close() }
            let hook = R12KernelHook(peer: vx)
            func next(_ timeout: Double = 3) -> M? {
                x.receive(timeout: timeout).flatMap { FileProto.decode(type: $0.type, payload: $0.payload) }
            }
            _ = x.send(type: 0x50, payload: [1, 0, UInt8(FileProto.Caps.announce)])
            guard case .helloAck? = next(), settle({ rig.board.counts.changeCountReads >= 6 }) else { expect(false, name); continue }
            rig.board.localCopyFiles([rig.src])
            guard case let .offer(tx, _, _, _)? = next(), case .entry? = next() else { expect(false, name); continue }
            rig.server.sendHook = hook.send
            _ = x.send(type: FileProto.MsgType.request,
                       payload: M.request(transfer: tx, index: 0, offset: 0, length: UInt32(body.count)).encode()!)
            let fired = hook.waitFired(seconds: 3)
            let atBlock = rig.server.txCount(peer: vx)
            let blockedAt = Date()
            rig.block(vx, viaJournal: viaJournal)
            Thread.sleep(forTimeInterval: 0.2)
            hook.release()
            var closed = false
            while !closed && Date().timeIntervalSince(blockedAt) < 2 {
                Thread.sleep(forTimeInterval: 0.02)
                closed = x.hostClosed()
            }
            let closeMs = Int(Date().timeIntervalSince(blockedAt) * 1000)
            Thread.sleep(forTimeInterval: 0.3)
            let after = rig.server.txCount(peer: vx)
            var fileEnd = false
            while let m = next(0.3) { if case .fileEnd = m { fileEnd = true; break } }
            let longestSend = rig.server.longestSendCallMillis
            print("r12 kernel wait info: source=\(viaJournal ? "journal" : "listen.plist") fired=\(fired) nonblocking=\(hook.sawNonBlocking) eagain_returned=\(hook.eagainCount) host_bytes_at_block=\(atBlock.bytes) host_sends_after_block=\(after.sends - atBlock.sends) host_bytes_after_block=\(after.bytes - atBlock.bytes) closed=\(closed) close_ms=\(closeMs) file_end=\(fileEnd) longest_send_call_ms=\(String(format: "%.3f", longestSend))")
            expect(fired && after.sends == atBlock.sends && after.bytes == atBlock.bytes && closed && !fileEnd
                   && rig.gate.guardian.isBlocked(vx) && !rig.gate.isRevoked && longestSend < 50,
                   name)
        }
    }

    /// r10 (blocker 2): a block that lands while a request is handled (after
    /// the per-message check, before the reply) stops the reply: VIDEO_CONFIG
    /// ACK, TCP PONG, open_ip_only RESULT, FILE_HELLO_ACK, clipboard PONG.
    /// The hook lands the block right before the reply asks; the viewer gets
    /// no reply, its connection closes, the host writes 0 bytes after it.
    fileprivate static func r10ReplyBlock(_ expect: Expect) {
        let v = "100.64.0.43"
        let ping: [UInt8] = [9, 8, 7, 6]
        // settingsIP: the video config cases name another address, so the host
        // takes the reject path (settings read, never written) and still ACKs.
        struct Case { let label: String; let viaJournal: Bool; let reply: UInt8; let first: [(UInt8, [UInt8])]; var settingsIP = "100.64.0.43" }
        let cases = [
            Case(label: "VIDEO_CONFIG_ACK (block lands while the config is applied)", viaJournal: true, reply: 0x41,
                 first: [(0x40, [1, 0, 0, 0, 0, 0, 0, 0])], settingsIP: "100.64.0.99"),
            Case(label: "VIDEO_CONFIG_ACK (block lands while the config is applied)", viaJournal: false, reply: 0x41,
                 first: [(0x40, [1, 0, 0, 0, 0, 0, 0, 0])], settingsIP: "100.64.0.99"),
            Case(label: "TCP PONG", viaJournal: true, reply: 0x02, first: [(0x01, ping)]),
            Case(label: "open_ip_only RESULT", viaJournal: true, reply: ConnAuth.MsgType.result,
                 first: [(ConnAuth.MsgType.response, [UInt8](repeating: 0, count: 8))]),
            Case(label: "FILE_HELLO_ACK", viaJournal: true, reply: FileProto.MsgType.helloAck,
                 first: [(FileProto.MsgType.hello, [1, 0, UInt8(FileProto.Caps.announce)])]),
            Case(label: "clipboard PONG", viaJournal: true, reply: 0x02, first: [(0x30, []), (0x01, ping)]),
        ]
        for c in cases {
            let name = "r10 reply: a block from \(c.viaJournal ? "the journal" : "listen.plist") that lands between the request check and its \(c.label) stops the reply: the viewer gets none, its connection closes, the host writes 0 bytes after the block"
            guard let rig = R10Rig(allowed: [v], settingsIP: c.settingsIP) else { expect(false, name); continue }
            let fired = R10Flag()
            let server = rig.server
            let reply = c.reply, viaJournal = c.viaJournal
            server.beforeCheckedSend = { [weak rig] type in
                guard type == reply, let rig, fired.setOnce(server.txCount(peer: v).bytes) else { return }
                rig.block(v, viaJournal: viaJournal)
            }
            guard rig.start(), let cl = rig.viewer(v) else { expect(false, name); rig.close(); continue }
            defer { cl.close(); rig.close() }
            for (t, p) in c.first { _ = cl.send(type: t, payload: p) }
            var got: [UInt8] = []
            while let m = cl.receive(timeout: 1) { got.append(m.type) }
            let closed = cl.sawEOF || cl.hostClosed()
            let atBlock = fired.value
            let after = server.txCount(peer: v).bytes
            print("r10 reply info: reply=0x\(String(c.reply, radix: 16)) source=\(c.viaJournal ? "journal" : "listen.plist") fired=\(atBlock != nil) frames_received=\(got.map { String($0, radix: 16) }) host_bytes_after_block=\(after - (atBlock ?? after)) closed=\(closed)")
            expect(atBlock != nil && !got.contains(c.reply) && closed && after == atBlock
                   && rig.gate.guardian.isBlocked(v), name)
        }
    }
}

/// r10 self-test: set once, from any thread.
/// r6 self-test: a thread-safe count.
final class R6Count: @unchecked Sendable {
    private let lock = NSLock()
    private var n = 0
    func hit() { lock.lock(); n += 1; lock.unlock() }
    func reset() { lock.lock(); n = 0; lock.unlock() }
    var value: Int { lock.lock(); defer { lock.unlock() }; return n }
}

/// r7 self-test: picks the first control AUTH_OK after `arm` (its session id).
final class R7Hold: @unchecked Sendable {
    private let lock = NSLock()
    private var armed = false
    private var held: [UInt8]?
    func arm() { lock.lock(); armed = true; held = nil; lock.unlock() }
    func take(_ sessionID: [UInt8]) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard armed else { return false }
        armed = false; held = sessionID
        return true
    }
    var id: [UInt8]? { lock.lock(); defer { lock.unlock() }; return held }
}

/// PR-C r10 self-test: names of closed connections, in order.
final class R10Names: @unchecked Sendable {
    private let lock = NSLock()
    private var names: [String] = []
    func add(_ s: String) { lock.lock(); names.append(s); lock.unlock() }
    var all: [String] { lock.lock(); defer { lock.unlock() }; return names }
}

/// PR-C r10 self-test (item 3): stands in for the kernel's send() so the
/// first AUTH_OK after `arm` never goes out: every write on that socket
/// answers EAGAIN, as a viewer whose window never opens would cause. Other
/// sockets and frames pass through.
final class R10AuthOKStall: @unchecked Sendable {
    private let lock = NSLock()
    private var armed = false
    private var fd: Int32?
    private var count = 0
    func arm() { lock.lock(); armed = true; fd = nil; count = 0; lock.unlock() }
    func disarm() { lock.lock(); armed = false; lock.unlock() }
    var stalledFD: Int32? { lock.lock(); defer { lock.unlock() }; return fd }
    var eagain: Int { lock.lock(); defer { lock.unlock() }; return count }
    func send(_ s: Int32, _ peer: String?, _ p: UnsafeRawPointer, _ len: Int) -> Int {
        lock.lock()
        if armed, fd == nil, len >= 8 {
            let b = p.assumingMemoryBound(to: UInt8.self)
            if b[0] == 0x4d && b[3] == 0x31 && b[5] == ConnAuth.MsgType.result { fd = s }
        }
        let stall = armed && fd == s
        if stall { count += 1 }
        lock.unlock()
        if stall { errno = EAGAIN; return -1 }
        return Darwin.send(s, p, len, 0)
    }
}

final class R10Flag: @unchecked Sendable {
    private let lock = NSLock()
    private var v: UInt64?
    func setOnce(_ x: UInt64) -> Bool {
        lock.lock(); defer { lock.unlock() }
        if v != nil { return false }
        v = x; return true
    }
    var value: UInt64? { lock.lock(); defer { lock.unlock() }; return v }
}

/// r12 self-test: the kernel's send() for one peer, from the moment it is
/// armed until `release`: the write cannot be taken. Blocking socket: wait
/// (the kernel's mbuf wait); O_NONBLOCK socket: EAGAIN. Then the real send.
final class R12KernelHook: @unchecked Sendable {
    private let peer: String
    private let lock = NSLock()
    private var released = false, didFire = false
    private var nonBlocking = false, eagains = 0
    private let firedSem = DispatchSemaphore(value: 0)
    private let releaseSem = DispatchSemaphore(value: 0)

    init(peer: String) { self.peer = peer }

    func send(_ fd: Int32, _ peerIP: String?, _ p: UnsafeRawPointer, _ len: Int) -> Int {
        guard peerIP == peer else { return Darwin.send(fd, p, len, 0) }
        lock.lock()
        if released { lock.unlock(); return Darwin.send(fd, p, len, 0) }
        let first = !didFire
        didFire = true
        let nb = fcntl(fd, F_GETFL) & O_NONBLOCK != 0
        if nb { nonBlocking = true; eagains += 1 }
        lock.unlock()
        if first { firedSem.signal() }
        if nb {
            errno = EAGAIN
            return -1
        }
        releaseSem.wait()
        releaseSem.signal()
        return Darwin.send(fd, p, len, 0)
    }

    func waitFired(seconds: Double) -> Bool { firedSem.wait(timeout: .now() + seconds) == .success }

    func release() {
        lock.lock(); released = true; lock.unlock()
        releaseSem.signal()
    }

    var sawNonBlocking: Bool { lock.lock(); defer { lock.unlock() }; return nonBlocking }
    var eagainCount: Int { lock.lock(); defer { lock.unlock() }; return eagains }
}

/// PR-C r11 self-test: holds the first `pass` after `arm` until `release`
/// (at most 5 s); every other `pass` returns at once.
/// r13: a monotonic clock the self-test moves by hand.
final class R13Clock: @unchecked Sendable {
    private let lock = NSLock()
    private var t: Double = 1000
    var now: Double { lock.lock(); defer { lock.unlock() }; return t }
    func advance(_ d: Double) { lock.lock(); t += d; lock.unlock() }
}

final class R11Hold: @unchecked Sendable {
    private let lock = NSLock()
    private var armed = false
    private let enteredSem = DispatchSemaphore(value: 0)
    private let releaseSem = DispatchSemaphore(value: 0)
    func arm() { lock.lock(); armed = true; lock.unlock() }
    func pass() {
        lock.lock(); let hold = armed; armed = false; lock.unlock()
        guard hold else { return }
        enteredSem.signal()
        _ = releaseSem.wait(timeout: .now() + 5)
    }
    func waitEntered(_ seconds: Double = 3) -> Bool { enteredSem.wait(timeout: .now() + seconds) == .success }
    func release() { releaseSem.signal() }
}
