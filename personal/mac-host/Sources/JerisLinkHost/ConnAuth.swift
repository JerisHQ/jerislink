import CommonCrypto
import Foundation
import Security

/// Connection password (design v0.4.0, PR-A): the maths and the MRC1 wire.
///
/// The password never crosses the network. The host keeps
/// K = PBKDF2-HMAC-SHA256(NFC(password), salt, 600,000) and proves, per TCP
/// connection, that the viewer holds the same K with a fresh nonce:
///
///     host   -> 0x05 AUTH_CHALLENGE  host_nonce salt iter kdf_id host_id
///     viewer -> 0x03 AUTH_RESPONSE   client_nonce mac_c
///     host   -> 0x04 AUTH_RESULT     ok mac_h session_id | fail | locked | ...
///
/// AUTH_CHALLENGE is 0x05, not the 0x02 of the first design draft: MRC1 0x02
/// is already PONG (host -> viewer), and a 0.3.x viewer reads any 0x02 as
/// the answer to its PING.
///
/// mac_c binds the channel the viewer means to use (control, clipboard,
/// file, ping). AUTH_RESPONSE does not name it, so the host checks all four
/// and then holds the connection to the one that matched.
/// `personal/protocol/auth_vectors.json` has vectors for every value here.
enum ConnAuth {
    static let iterations: UInt32 = 600_000
    static let kdfPBKDF2SHA256: UInt8 = 1
    static let saltBytes = 16
    static let nonceBytes = 32
    static let hostIDBytes = 16
    static let keyBytes = 32
    static let sessionIDBytes = 8
    static let tagBytes = 8
    /// The viewer has this long after AUTH_CHALLENGE to answer.
    static let authTimeout: TimeInterval = 5

    enum MsgType {
        static let response: UInt8 = 0x03
        static let result: UInt8 = 0x04
        static let challenge: UInt8 = 0x05
    }

    enum Channel: UInt8, CaseIterable, Sendable {
        case control = 1, clipboard = 2, file = 3, ping = 4

        var name: String {
            switch self {
            case .control: return "control"
            case .clipboard: return "clipboard"
            case .file: return "file"
            case .ping: return "ping"
            }
        }
    }

    // MARK: Maths

    static func normalizedPassword(_ password: String) -> [UInt8] {
        Array(password.precomposedStringWithCanonicalMapping.utf8)
    }

    static func deriveKey(password: String, salt: [UInt8], iterations: UInt32) -> [UInt8]? {
        let pw = normalizedPassword(password)
        guard !pw.isEmpty, iterations > 0 else { return nil }
        var out = [UInt8](repeating: 0, count: keyBytes)
        let rc = pw.withUnsafeBufferPointer { p in
            p.baseAddress!.withMemoryRebound(to: CChar.self, capacity: pw.count) { cp in
                CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), cp, pw.count, salt, salt.count,
                                     CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), iterations, &out, out.count)
            }
        }
        return rc == kCCSuccess ? out : nil
    }

    static func hmac(_ key: [UInt8], _ parts: [[UInt8]]) -> [UInt8] {
        var ctx = CCHmacContext()
        CCHmacInit(&ctx, CCHmacAlgorithm(kCCHmacAlgSHA256), key, key.count)
        for part in parts { CCHmacUpdate(&ctx, part, part.count) }
        var out = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        CCHmacFinal(&ctx, &out)
        return out
    }

    static func macClient(key: [UInt8], hostNonce: [UInt8], clientNonce: [UInt8], channel: Channel, hostID: [UInt8]) -> [UInt8] {
        hmac(key, [Array("jl-c".utf8), hostNonce, clientNonce, [channel.rawValue], hostID])
    }

    static func macHost(key: [UInt8], hostNonce: [UInt8], clientNonce: [UInt8], channel: Channel) -> [UInt8] {
        hmac(key, [Array("jl-h".utf8), hostNonce, clientNonce, [channel.rawValue]])
    }

    /// Per-session UDP key (design §5.1). The tags themselves ship in PR-C;
    /// the derivation is fixed now so the vectors cover it.
    static func sessionKey(key: [UInt8], hostNonce: [UInt8], clientNonce: [UInt8], sessionID: [UInt8]) -> [UInt8] {
        hmac(key, [Array("jl-udp".utf8), hostNonce, clientNonce, sessionID])
    }

    static func udpTag(sessionKey: [UInt8], hostToViewer: Bool, packet: [UInt8]) -> [UInt8] {
        Array(hmac(sessionKey, [Array((hostToViewer ? "h2v" : "v2h").utf8), packet]).prefix(tagBytes))
    }

    static func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<a.count { diff |= a[i] ^ b[i] }
        return diff == 0
    }

    static func random(_ count: Int) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: count)
        let rc = SecRandomCopyBytes(kSecRandomDefault, count, &out)
        precondition(rc == errSecSuccess, "SecRandomCopyBytes failed")
        return out
    }

    /// The channel whose mac_c matches, or nil. Always computes all four.
    static func matchChannel(mac: [UInt8], key: [UInt8], hostNonce: [UInt8], clientNonce: [UInt8], hostID: [UInt8]) -> Channel? {
        var found: Channel?
        for channel in Channel.allCases {
            let want = macClient(key: key, hostNonce: hostNonce, clientNonce: clientNonce, channel: channel, hostID: hostID)
            if constantTimeEqual(want, mac) && found == nil { found = channel }
        }
        return found
    }

    // MARK: Password rules (design §3)

    enum PasswordProblem: String, CaseIterable, Sendable {
        case tooShort = "at least 10 characters"
        case noUpper = "an uppercase letter (A-Z)"
        case noLower = "a lowercase letter (a-z)"
        case noSymbol = "a symbol (not a letter, digit or space)"
    }

    static let minPasswordLength = 10

    static func passwordProblems(_ password: String) -> [PasswordProblem] {
        let text = password.precomposedStringWithCanonicalMapping
        var problems: [PasswordProblem] = []
        if text.count < minPasswordLength { problems.append(.tooShort) }
        let scalars = text.unicodeScalars
        if !scalars.contains(where: { ("A"..."Z").contains($0) }) { problems.append(.noUpper) }
        if !scalars.contains(where: { ("a"..."z").contains($0) }) { problems.append(.noLower) }
        let symbol = scalars.contains { s in
            !("A"..."Z").contains(s) && !("a"..."z").contains(s) && !("0"..."9").contains(s)
                && !CharacterSet.whitespacesAndNewlines.contains(s)
        }
        if !symbol { problems.append(.noSymbol) }
        return problems
    }

    // MARK: Wire

    struct Challenge: Equatable {
        var hostNonce: [UInt8]
        var salt: [UInt8]
        var iterations: UInt32
        var kdfID: UInt8
        var hostID: [UInt8]

        static let size = 32 + 16 + 4 + 1 + 16

        var payload: [UInt8] {
            hostNonce + salt + [UInt8(iterations >> 24), UInt8(iterations >> 16 & 0xff),
                                UInt8(iterations >> 8 & 0xff), UInt8(iterations & 0xff)] + [kdfID] + hostID
        }

        static func decode(_ p: [UInt8]) -> Challenge? {
            guard p.count == size else { return nil }
            let iter = UInt32(p[48]) << 24 | UInt32(p[49]) << 16 | UInt32(p[50]) << 8 | UInt32(p[51])
            return Challenge(hostNonce: Array(p[0..<32]), salt: Array(p[32..<48]), iterations: iter,
                             kdfID: p[52], hostID: Array(p[53..<69]))
        }
    }

    struct Response: Equatable {
        var clientNonce: [UInt8]
        var mac: [UInt8]

        var payload: [UInt8] { clientNonce + mac }

        static func decode(_ p: [UInt8]) -> Response? {
            guard p.count == 64 else { return nil }
            return Response(clientNonce: Array(p[0..<32]), mac: Array(p[32..<64]))
        }
    }

    enum Result: Equatable {
        case ok(macH: [UInt8], sessionID: [UInt8])
        case fail(triesLeft: UInt8)
        case locked(retrySeconds: UInt32)
        case blocked
        case authRequired
        case openIPOnly

        var payload: [UInt8] {
            switch self {
            case .ok(let macH, let sessionID): return [0] + macH + sessionID
            case .fail(let tries): return [1, tries]
            case .locked(let s): return [2, UInt8(s >> 24), UInt8(s >> 16 & 0xff), UInt8(s >> 8 & 0xff), UInt8(s & 0xff)]
            case .blocked: return [3]
            case .authRequired: return [4]
            case .openIPOnly: return [5]
            }
        }

        static func decode(_ p: [UInt8]) -> Result? {
            guard let status = p.first else { return nil }
            switch (status, p.count) {
            case (0, 41): return .ok(macH: Array(p[1..<33]), sessionID: Array(p[33..<41]))
            case (1, 2): return .fail(triesLeft: p[1])
            case (2, 5): return .locked(retrySeconds: UInt32(p[1]) << 24 | UInt32(p[2]) << 16 | UInt32(p[3]) << 8 | UInt32(p[4]))
            case (3, 1): return .blocked
            case (4, 1): return .authRequired
            case (5, 1): return .openIPOnly
            default: return nil
            }
        }
    }

    static func hex(_ bytes: [UInt8]) -> String { bytes.map { String(format: "%02x", $0) }.joined() }

    static func unhex(_ s: String) -> [UInt8]? {
        let chars = Array(s.utf8)
        guard chars.count % 2 == 0 else { return nil }
        var out: [UInt8] = []
        out.reserveCapacity(chars.count / 2)
        var i = 0
        while i < chars.count {
            guard let b = UInt8(String(decoding: chars[i..<i + 2], as: UTF8.self), radix: 16) else { return nil }
            out.append(b)
            i += 2
        }
        return out
    }
}

/// What the host keeps for the password: K, never the password itself.
struct ConnSecret: Equatable {
    var key: [UInt8]
    var salt: [UInt8]
    var iterations: UInt32
    var hostID: [UInt8]

    /// A new salt every time (so a changed password invalidates every
    /// remembered viewer); the host id survives a password change.
    static func make(password: String, hostID: [UInt8]? = nil,
                     iterations: UInt32 = ConnAuth.iterations) -> ConnSecret? {
        guard ConnAuth.passwordProblems(password).isEmpty else { return nil }
        let salt = ConnAuth.random(ConnAuth.saltBytes)
        guard let key = ConnAuth.deriveKey(password: password, salt: salt, iterations: iterations) else { return nil }
        return ConnSecret(key: key, salt: salt, iterations: iterations,
                          hostID: hostID ?? ConnAuth.random(ConnAuth.hostIDBytes))
    }

    var data: Data? {
        let dict: [String: Any] = ["v": 1, "key": Data(key), "salt": Data(salt),
                                   "iter": Int(iterations), "hostID": Data(hostID)]
        return try? PropertyListSerialization.data(fromPropertyList: dict, format: .binary, options: 0)
    }

    init(key: [UInt8], salt: [UInt8], iterations: UInt32, hostID: [UInt8]) {
        self.key = key
        self.salt = salt
        self.iterations = iterations
        self.hostID = hostID
    }

    init?(data: Data) {
        guard let dict = (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) as? [String: Any],
              let key = dict["key"] as? Data, key.count == ConnAuth.keyBytes,
              let salt = dict["salt"] as? Data, salt.count == ConnAuth.saltBytes,
              let iter = dict["iter"] as? Int, iter > 0, iter <= Int(UInt32.max),
              let hostID = dict["hostID"] as? Data, hostID.count == ConnAuth.hostIDBytes else { return nil }
        self.init(key: Array(key), salt: Array(salt), iterations: UInt32(iter), hostID: Array(hostID))
    }
}

protocol ConnSecretStore: AnyObject {
    func load() -> ConnSecret?
    func save(_ secret: ConnSecret) -> Bool
    @discardableResult func delete() -> Bool
}

/// Keychain generic password, service `org.jeris.jerislink.connpw` (design §6).
/// The item is created by the signed host, so the keychain's default access
/// list trusts only that code signature; reading it from the same signed app
/// shows no Allow prompt. A prompt means a signature mismatch: treat as a bug.
final class KeychainSecretStore: ConnSecretStore {
    static let defaultService = "org.jeris.jerislink.connpw"
    let service: String
    let account = "connection-password"

    init(service: String = KeychainSecretStore.defaultService) { self.service = service }

    private var query: [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account]
    }

    func load() -> ConnSecret? {
        var q = query
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let data = out as? Data else { return nil }
        return ConnSecret(data: data)
    }

    func save(_ secret: ConnSecret) -> Bool {
        guard let data = secret.data else { return false }
        delete()
        var q = query
        q[kSecValueData as String] = data
        q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        q[kSecAttrLabel as String] = "JerisLink connection password"
        return SecItemAdd(q as CFDictionary, nil) == errSecSuccess
    }

    @discardableResult func delete() -> Bool {
        let rc = SecItemDelete(query as CFDictionary)
        return rc == errSecSuccess || rc == errSecItemNotFound
    }
}

final class MemorySecretStore: ConnSecretStore, @unchecked Sendable {
    private var secret: ConnSecret?
    init(_ secret: ConnSecret? = nil) { self.secret = secret }
    func load() -> ConnSecret? { secret }
    func save(_ secret: ConnSecret) -> Bool { self.secret = secret; return true }
    @discardableResult func delete() -> Bool { secret = nil; return true }
}
