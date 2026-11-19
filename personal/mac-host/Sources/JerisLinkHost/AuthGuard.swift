import Foundation

/// One blocked viewer address (design §4.3), kept in listen.plist `blockedIPs`.
struct BlockedEntry: Equatable {
    var ip: String
    var at: Date
    var reason: String
}

protocol BlocklistStore: AnyObject {
    func load() -> [BlockedEntry]
    @discardableResult func save(_ entries: [BlockedEntry]) -> Bool
}

/// `blockedIPs` in listen.plist: read-modify-write, other keys untouched.
/// Without a listen.plist (network.conf setups) nothing is written, because a
/// listen.plist holding only `blockedIPs` would not resolve to an endpoint;
/// the block then lasts until the service restarts, and the log says so.
final class ListenPlistBlocklist: BlocklistStore, @unchecked Sendable {
    let url: URL
    private let lock = NSLock()
    init(url: URL) { self.url = url }

    func load() -> [BlockedEntry] {
        lock.lock(); defer { lock.unlock() }
        guard let dict = readDict(), let raw = dict["blockedIPs"] as? [Any] else { return [] }
        return raw.compactMap { item in
            if let ip = item as? String, ListenConfig.isIPv4(ip) {
                return BlockedEntry(ip: ip, at: Date(timeIntervalSince1970: 0), reason: "manual")
            }
            guard let d = item as? [String: Any], let ip = d["ip"] as? String, ListenConfig.isIPv4(ip) else { return nil }
            return BlockedEntry(ip: ip, at: d["at"] as? Date ?? Date(timeIntervalSince1970: 0),
                                reason: d["reason"] as? String ?? "manual")
        }
    }

    @discardableResult func save(_ entries: [BlockedEntry]) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard var dict = readDict() else {
            print("auth.blocklist_not_saved reason=no_listen_plist")
            return false
        }
        dict["blockedIPs"] = entries.map { ["ip": $0.ip, "at": $0.at, "reason": $0.reason] as [String: Any] }
        guard let data = try? PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0),
              (try? data.write(to: url, options: .atomic)) != nil else {
            print("auth.blocklist_not_saved reason=write_failed")
            return false
        }
        return true
    }

    private func readDict() -> [String: Any]? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        return (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) as? [String: Any]
    }
}

final class MemoryBlocklist: BlocklistStore, @unchecked Sendable {
    var entries: [BlockedEntry]
    init(_ entries: [BlockedEntry] = []) { self.entries = entries }
    func load() -> [BlockedEntry] { entries }
    @discardableResult func save(_ entries: [BlockedEntry]) -> Bool { self.entries = entries; return true }
}

/// Wrong-password limits (design §4).
///
/// Per peer IP, across every channel: each 5th failure locks that IP for
/// 5, 10, then 15 minutes, and the 20th puts it on the blacklist. One right
/// password clears that IP's count. All IPs together: 20 failures inside any
/// 60 s window stop every challenge for 5 minutes; a right password does not
/// clear that window. Counts and waits live in memory only; the blacklist is
/// persisted. Locked or blocked connections get no challenge, so they cannot
/// add failures.
final class AuthGuard: @unchecked Sendable {
    static let failuresPerStage = 5
    static let blacklistStage = 4
    static let stageWait: TimeInterval = 300
    static let globalWindow: TimeInterval = 60
    static let globalMaxFailures = 20
    static let globalWait: TimeInterval = 300

    enum Admission: Equatable {
        case challenge
        case blocked
        case notAllowed
        case locked(retrySeconds: UInt32, stage: Int)
        case globalLocked(retrySeconds: UInt32)
    }

    enum FailureOutcome: Equatable {
        case retry(triesLeft: UInt8)
        case locked(retrySeconds: UInt32, stage: Int)
        case blacklisted
    }

    private struct PeerState {
        var failures = 0
        var lockedUntil: TimeInterval = 0
        var stage = 0
    }

    let whitelist: [String]
    private let blocklist: BlocklistStore
    private let now: () -> TimeInterval
    private let wallNow: () -> Date
    private let lock = NSLock()
    private var peers: [String: PeerState] = [:]
    private var blocked: [BlockedEntry]
    private var globalFailures: [TimeInterval] = []
    private var globalLockedUntil: TimeInterval = 0

    init(whitelist: [String], blocklist: BlocklistStore,
         now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
         wallNow: @escaping () -> Date = { Date() }) {
        self.whitelist = whitelist
        self.blocklist = blocklist
        self.now = now
        self.wallNow = wallNow
        self.blocked = blocklist.load()
    }

    /// Blacklist first (it wins over the whitelist), then the whitelist, then
    /// this IP's wait, then the host-wide wait.
    func admit(_ ip: String) -> Admission {
        lock.lock(); defer { lock.unlock() }
        if blocked.contains(where: { $0.ip == ip }) { return .blocked }
        if !whitelist.isEmpty && !whitelist.contains(ip) { return .notAllowed }
        let t = now()
        if let p = peers[ip], p.lockedUntil > t {
            return .locked(retrySeconds: Self.seconds(p.lockedUntil - t), stage: p.stage)
        }
        if globalLockedUntil > t { return .globalLocked(retrySeconds: Self.seconds(globalLockedUntil - t)) }
        return .challenge
    }

    /// Blacklist only (transition mode: no challenge, so no counting).
    func isBlocked(_ ip: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return blocked.contains { $0.ip == ip }
    }

    /// Returns this IP's outcome, its total failures, and whether this
    /// failure started the host-wide wait.
    func recordFailure(_ ip: String) -> (outcome: FailureOutcome, failures: Int, globalTriggered: Bool) {
        lock.lock(); defer { lock.unlock() }
        let t = now()
        globalFailures.append(t)
        globalFailures.removeAll { t - $0 >= Self.globalWindow }
        var globalTriggered = false
        if globalFailures.count >= Self.globalMaxFailures && globalLockedUntil <= t {
            globalLockedUntil = t + Self.globalWait
            globalTriggered = true
        }
        var p = peers[ip] ?? PeerState()
        p.failures += 1
        let failures = p.failures
        guard p.failures % Self.failuresPerStage == 0 else {
            peers[ip] = p
            return (.retry(triesLeft: UInt8(Self.failuresPerStage - p.failures % Self.failuresPerStage)), failures, globalTriggered)
        }
        p.stage = p.failures / Self.failuresPerStage
        if p.stage >= Self.blacklistStage {
            peers[ip] = nil
            if !blocked.contains(where: { $0.ip == ip }) {
                blocked.append(BlockedEntry(ip: ip, at: wallNow(), reason: "\(failures) wrong passwords"))
                blocklist.save(blocked)
            }
            return (.blacklisted, failures, globalTriggered)
        }
        let wait = Self.stageWait * Double(p.stage)
        p.lockedUntil = t + wait
        peers[ip] = p
        return (.locked(retrySeconds: Self.seconds(wait), stage: p.stage), failures, globalTriggered)
    }

    func recordSuccess(_ ip: String) {
        lock.lock(); defer { lock.unlock() }
        peers[ip] = nil
    }

    /// Manual release from the host app: off the blacklist, count cleared.
    @discardableResult func release(_ ip: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard blocked.contains(where: { $0.ip == ip }) else { return false }
        blocked.removeAll { $0.ip == ip }
        peers[ip] = nil
        blocklist.save(blocked)
        print("auth.released peer=\(ip)")
        return true
    }

    func failures(_ ip: String) -> Int {
        lock.lock(); defer { lock.unlock() }
        return peers[ip]?.failures ?? 0
    }

    var blockedEntries: [BlockedEntry] {
        lock.lock(); defer { lock.unlock() }
        return blocked
    }

    private static func seconds(_ interval: TimeInterval) -> UInt32 {
        UInt32(max(1, interval.rounded(.up)))
    }
}

/// How the control listener admits viewers (design §9).
enum AuthPolicy: Equatable {
    /// A password is set: every TCP connection must pass AUTH. Empty
    /// whitelist: any address that reaches the listener.
    case password(whitelist: [String])
    /// No password yet: the 0.3 address check, unchanged, so 0.3.x viewers
    /// keep working. A 0x03 probe is answered with open_ip_only.
    case transition(whitelist: [String])
    /// Neither a password nor an address: do not listen.
    case refused(reason: String)

    var summary: String {
        switch self {
        case .password(let w): return "password whitelist=\(w.isEmpty ? "any" : w.joined(separator: ","))"
        case .transition(let w): return "transition whitelist=\(w.joined(separator: ","))"
        case .refused(let reason): return "refused reason=\(reason)"
        }
    }

    /// - plist: listen.plist (nil for network.conf setups).
    /// - clientIP: the endpoint's viewer, used when the plist has no
    ///   `allowedIPs` (not migrated yet, loopback mode, network.conf).
    /// - secretLoaded: the Keychain item was read. `passwordSet` without a
    ///   readable secret refuses rather than falling back to IP only.
    static func resolve(plist: [String: Any]?, clientIP: String?, secretLoaded: Bool) -> AuthPolicy {
        let whitelist: [String]
        if let listed = plist?["allowedIPs"] as? [String] {
            whitelist = listed.filter { ListenConfig.isIPv4($0) }
        } else if let clientIP, ListenConfig.isIPv4(clientIP) {
            whitelist = [clientIP]
        } else {
            whitelist = []
        }
        if plist?["passwordSet"] as? Bool == true {
            return secretLoaded ? .password(whitelist: whitelist) : .refused(reason: "password_unreadable")
        }
        return whitelist.isEmpty ? .refused(reason: "no_password_no_ip") : .transition(whitelist: whitelist)
    }
}

/// First start of v0.4.0 (design §9): a listen.plist with `clientIP` gets
/// `allowedIPs = [clientIP]` and `passwordSet = false`; the file as it was is
/// kept as `listen.plist.pre-0.4`. `clientIP` itself stays: the UDP video
/// and mouse paths still use it until PR-C.
enum ListenMigration {
    static func migrate(url: URL) -> String? {
        guard let data = try? Data(contentsOf: url),
              var dict = (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) as? [String: Any],
              dict["allowedIPs"] == nil,
              let clientIP = dict["clientIP"] as? String, ListenConfig.isIPv4(clientIP) else { return nil }
        let backup = URL(fileURLWithPath: url.path + ".pre-0.4")
        if !FileManager.default.fileExists(atPath: backup.path) {
            guard (try? data.write(to: backup, options: .atomic)) != nil else { return "config.migrate_failed reason=backup" }
        }
        dict["allowedIPs"] = [clientIP]
        if dict["passwordSet"] == nil { dict["passwordSet"] = false }
        guard let out = try? PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0),
              (try? out.write(to: url, options: .atomic)) != nil else { return "config.migrate_failed reason=write" }
        return "config.migrated allowed_ips=1 backup=\(backup.lastPathComponent)"
    }
}

/// What a viewer-facing ControlServer checks before any message (design §5).
final class AuthGate: @unchecked Sendable {
    let policy: AuthPolicy
    let guardian: AuthGuard
    let secret: ConnSecret?
    let timeout: TimeInterval

    init(policy: AuthPolicy, guardian: AuthGuard, secret: ConnSecret?, timeout: TimeInterval = ConnAuth.authTimeout) {
        self.policy = policy
        self.guardian = guardian
        self.secret = secret
        self.timeout = timeout
    }

    var requiresPassword: Bool {
        if case .password = policy, secret != nil { return true }
        return false
    }

    static func make(policy: AuthPolicy, secret: ConnSecret?, blocklist: BlocklistStore) -> AuthGate {
        let whitelist: [String]
        switch policy {
        case .password(let w), .transition(let w): whitelist = w
        case .refused: whitelist = []
        }
        return AuthGate(policy: policy, guardian: AuthGuard(whitelist: whitelist, blocklist: blocklist), secret: secret)
    }
}
