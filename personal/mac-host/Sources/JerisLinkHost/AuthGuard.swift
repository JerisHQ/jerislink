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
    /// Self-test: this many saves fail before one succeeds.
    var failNextSaves = 0
    private(set) var saveCalls = 0
    init(_ entries: [BlockedEntry] = []) { self.entries = entries }
    func load() -> [BlockedEntry] { entries }
    @discardableResult func save(_ entries: [BlockedEntry]) -> Bool {
        saveCalls += 1
        if failNextSaves > 0 { failNextSaves -= 1; return false }
        self.entries = entries
        return true
    }
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
///
/// A challenge can be outstanding while another connection trips a wait or
/// the blacklist. `settle` therefore checks the limits again and records the
/// outcome under the same lock as the MAC check: an answer to a challenge
/// issued before the wait gets LOCKED/BLOCKED, is not counted and never OK.
final class AuthGuard: @unchecked Sendable {
    static let failuresPerStage = 5
    static let blacklistStage = 4
    static let stageWait: TimeInterval = 300
    static let globalWindow: TimeInterval = 60
    static let globalMaxFailures = 20
    static let globalWait: TimeInterval = 300
    /// Blacklist writes: attempts and the pause before each retry.
    static let saveAttempts = 3
    static let saveRetryPause: TimeInterval = 0.05

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
        /// `persisted`: listen.plist now holds the entry. When false the IP
        /// is still blocked in memory until the service restarts.
        case blacklisted(persisted: Bool)
    }

    struct Failure: Equatable {
        var outcome: FailureOutcome
        var failures: Int
        var globalTriggered: Bool
    }

    /// What one answered challenge came to.
    enum Settlement: Equatable {
        case ok
        case failed(Failure)
        /// A wait or the blacklist started after this challenge was sent:
        /// refused, not counted.
        case refused(Admission)
    }

    enum ReleaseResult: Equatable {
        case released
        case notBlocked
        /// listen.plist could not be written; the IP stays blocked.
        case saveFailed
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
    private let pause: (TimeInterval) -> Void
    private let lock = NSLock()
    private var peers: [String: PeerState] = [:]
    private var blocked: [BlockedEntry]
    /// IPs the store holds as far as this guard knows (loaded or last saved).
    private var persisted: Set<String>
    private var globalFailures: [TimeInterval] = []
    private var globalLockedUntil: TimeInterval = 0

    init(whitelist: [String], blocklist: BlocklistStore,
         now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
         wallNow: @escaping () -> Date = { Date() },
         pause: @escaping (TimeInterval) -> Void = { Thread.sleep(forTimeInterval: $0) }) {
        self.whitelist = whitelist
        self.blocklist = blocklist
        self.now = now
        self.wallNow = wallNow
        self.pause = pause
        let loaded = blocklist.load()
        self.blocked = loaded
        self.persisted = Set(loaded.map(\.ip))
    }

    /// Blacklist first (it wins over the whitelist), then the whitelist, then
    /// this IP's wait, then the host-wide wait.
    func admit(_ ip: String) -> Admission {
        lock.lock(); defer { lock.unlock() }
        return admitLocked(ip)
    }

    /// Blacklist only (transition mode: no challenge, so no counting).
    func isBlocked(_ ip: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return blocked.contains { $0.ip == ip }
    }

    /// Settles one outstanding challenge in a single critical section:
    /// limits checked again, then `check` (the MAC comparison; a timeout or
    /// malformed answer passes `{ false }`), then success or failure
    /// recorded. `check` must not block or call back into this guard.
    func settle(_ ip: String, check: () -> Bool) -> Settlement {
        lock.lock(); defer { lock.unlock() }
        let admission = admitLocked(ip)
        guard admission == .challenge else { return .refused(admission) }
        if check() {
            peers[ip] = nil
            return .ok
        }
        return .failed(recordFailureLocked(ip))
    }

    /// One failure without a fresh limit check (tests and callers that
    /// already hold an admission). Prefer `settle`.
    func recordFailure(_ ip: String) -> Failure {
        lock.lock(); defer { lock.unlock() }
        return recordFailureLocked(ip)
    }

    func recordSuccess(_ ip: String) {
        lock.lock(); defer { lock.unlock() }
        peers[ip] = nil
    }

    /// Manual release from the host app: off the blacklist, count cleared.
    /// Only when listen.plist is written; otherwise the IP stays blocked, so
    /// a restart cannot bring back an entry the app reported as released.
    @discardableResult func release(_ ip: String) -> ReleaseResult {
        lock.lock(); defer { lock.unlock() }
        guard blocked.contains(where: { $0.ip == ip }) else { return .notBlocked }
        let remaining = blocked.filter { $0.ip != ip }
        guard saveLocked(remaining) else {
            print("auth.release_failed peer=\(ip) reason=write_failed attempts=\(Self.saveAttempts)")
            return .saveFailed
        }
        blocked = remaining
        peers[ip] = nil
        print("auth.released peer=\(ip) persisted=listen.plist")
        return .released
    }

    func failures(_ ip: String) -> Int {
        lock.lock(); defer { lock.unlock() }
        return peers[ip]?.failures ?? 0
    }

    var blockedEntries: [BlockedEntry] {
        lock.lock(); defer { lock.unlock() }
        return blocked
    }

    /// What listen.plist should hold if nobody else edited it. The control
    /// service compares it with the file to notice outside edits.
    var persistedIPs: Set<String> {
        lock.lock(); defer { lock.unlock() }
        return persisted
    }

    private func admitLocked(_ ip: String) -> Admission {
        if blocked.contains(where: { $0.ip == ip }) { return .blocked }
        if !whitelist.isEmpty && !whitelist.contains(ip) { return .notAllowed }
        let t = now()
        if let p = peers[ip], p.lockedUntil > t {
            return .locked(retrySeconds: Self.seconds(p.lockedUntil - t), stage: p.stage)
        }
        if globalLockedUntil > t { return .globalLocked(retrySeconds: Self.seconds(globalLockedUntil - t)) }
        return .challenge
    }

    private func recordFailureLocked(_ ip: String) -> Failure {
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
            return Failure(outcome: .retry(triesLeft: UInt8(Self.failuresPerStage - p.failures % Self.failuresPerStage)),
                           failures: failures, globalTriggered: globalTriggered)
        }
        p.stage = p.failures / Self.failuresPerStage
        if p.stage >= Self.blacklistStage {
            peers[ip] = nil
            // Blocked in memory first: a failed write must not reopen the IP.
            if !blocked.contains(where: { $0.ip == ip }) {
                blocked.append(BlockedEntry(ip: ip, at: wallNow(), reason: "\(failures) wrong passwords"))
            }
            let persisted = saveLocked(blocked)
            return Failure(outcome: .blacklisted(persisted: persisted), failures: failures, globalTriggered: globalTriggered)
        }
        let wait = Self.stageWait * Double(p.stage)
        p.lockedUntil = t + wait
        peers[ip] = p
        return Failure(outcome: .locked(retrySeconds: Self.seconds(wait), stage: p.stage),
                       failures: failures, globalTriggered: globalTriggered)
    }

    /// Bounded retry; the whole list is written each time, so an entry whose
    /// earlier write failed is saved by the next successful one.
    private func saveLocked(_ entries: [BlockedEntry]) -> Bool {
        for attempt in 1...Self.saveAttempts {
            if blocklist.save(entries) {
                persisted = Set(entries.map(\.ip))
                return true
            }
            if attempt < Self.saveAttempts { pause(Self.saveRetryPause * Double(attempt)) }
        }
        return false
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
    /// - clientIP: the endpoint's viewer. It is the whitelist when the plist
    ///   has no `allowedIPs` (not migrated yet, loopback, network.conf) and
    ///   while `allowedIPs` is still the copy migration made of it
    ///   (`allowedIPsSource = clientIP`), so changing only `clientIP`, as
    ///   Deploy/README.md says, moves the whitelist as in 0.3.
    /// - secretLoaded: the Keychain item was read. `passwordSet` without a
    ///   readable secret refuses rather than falling back to IP only.
    ///
    /// Password mode refuses an `allowedIPs` with any entry that is not an
    /// IPv4 address: dropping it could leave an empty list, which means any.
    static func resolve(plist: [String: Any]?, clientIP: String?, secretLoaded: Bool) -> AuthPolicy {
        let passwordSet = plist?["passwordSet"] as? Bool == true
        let client = clientIP.flatMap { ListenConfig.isIPv4($0) ? [$0] : nil } ?? []
        let whitelist: [String]
        if let raw = plist?["allowedIPs"], !ListenMigration.followsClientIP(plist) {
            let items = raw as? [Any]
            let valid = (items ?? []).compactMap { ($0 as? String).flatMap { ListenConfig.isIPv4($0) ? $0 : nil } }
            if passwordSet && (items == nil || valid.count != items?.count) {
                return .refused(reason: "invalid_allowed_ips")
            }
            whitelist = valid
        } else {
            whitelist = client
        }
        if passwordSet {
            return secretLoaded ? .password(whitelist: whitelist) : .refused(reason: "password_unreadable")
        }
        return whitelist.isEmpty ? .refused(reason: "no_password_no_ip") : .transition(whitelist: whitelist)
    }
}

/// The listen.plist and Keychain inputs of the auth policy, minus clientIP
/// (an endpoint change already restarts the service). The control service
/// restarts when they change, so the new policy applies and connections
/// admitted under the old one are closed. Never logged as a whole.
struct AuthConfigSnapshot: Equatable, Sendable {
    var passwordSet: Bool
    /// Raw description, so an invalid edit is noticed too.
    var allowedIPs: String
    var allowedIPsSource: String
    /// Salt and host id (not K): a new salt on every password change.
    var secretTag: String

    static func read(plist: [String: Any]?, secret: ConnSecret?) -> AuthConfigSnapshot {
        AuthConfigSnapshot(passwordSet: plist?["passwordSet"] as? Bool == true,
                           allowedIPs: plist?["allowedIPs"].map { String(describing: $0) } ?? "-",
                           allowedIPsSource: plist?[ListenMigration.sourceKey] as? String ?? "-",
                           secretTag: secret.map { ConnAuth.hex($0.salt) + ":" + ConnAuth.hex($0.hostID) } ?? "-")
    }

    /// Which keys differ, for the restart log (names only, no values).
    func changes(from old: AuthConfigSnapshot) -> String {
        var keys: [String] = []
        if passwordSet != old.passwordSet { keys.append("passwordSet") }
        if allowedIPs != old.allowedIPs { keys.append("allowedIPs") }
        if allowedIPsSource != old.allowedIPsSource { keys.append(ListenMigration.sourceKey) }
        if secretTag != old.secretTag { keys.append("password") }
        return keys.joined(separator: ",")
    }
}

/// First start of v0.4.0 (design §9): a listen.plist with `clientIP` gets
/// `allowedIPs = [clientIP]`, `allowedIPsSource = clientIP` and
/// `passwordSet = false`; the file as it was is kept as
/// `listen.plist.pre-0.4`. `clientIP` itself stays: the UDP video and mouse
/// paths still use it until PR-C. While `allowedIPsSource` is `clientIP`
/// the whitelist follows `clientIP`; whoever edits `allowedIPs` by hand or
/// in the host app removes that key.
enum ListenMigration {
    static let sourceKey = "allowedIPsSource"
    static let sourceClientIP = "clientIP"

    static func followsClientIP(_ plist: [String: Any]?) -> Bool {
        plist?[sourceKey] as? String == sourceClientIP
    }

    static func migrate(url: URL) -> String? {
        guard let data = try? Data(contentsOf: url),
              var dict = (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) as? [String: Any],
              let clientIP = dict["clientIP"] as? String, ListenConfig.isIPv4(clientIP) else { return nil }
        let message: String
        if dict["allowedIPs"] == nil {
            let backup = URL(fileURLWithPath: url.path + ".pre-0.4")
            if !FileManager.default.fileExists(atPath: backup.path) {
                guard (try? data.write(to: backup, options: .atomic)) != nil else { return "config.migrate_failed reason=backup" }
            }
            dict["allowedIPs"] = [clientIP]
            dict[sourceKey] = sourceClientIP
            if dict["passwordSet"] == nil { dict["passwordSet"] = false }
            message = "config.migrated allowed_ips=1 source=clientIP backup=\(backup.lastPathComponent)"
        } else if dict[sourceKey] == nil, dict["passwordSet"] as? Bool != true,
                  dict["allowedIPs"] as? [String] == [clientIP] {
            // Migrated by an earlier v0.4 build without the source key.
            dict[sourceKey] = sourceClientIP
            message = "config.migrated allowed_ips_source=clientIP"
        } else {
            return nil
        }
        guard let out = try? PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0),
              (try? out.write(to: url, options: .atomic)) != nil else { return "config.migrate_failed reason=write" }
        return message
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
