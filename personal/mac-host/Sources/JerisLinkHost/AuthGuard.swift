import Foundation

/// One blocked viewer address (design §4.3), kept in listen.plist `blockedIPs`.
struct BlockedEntry: Equatable {
    var ip: String
    var at: Date
    var reason: String
}

protocol BlocklistStore: AnyObject {
    func load() -> [BlockedEntry]
    /// Read-modify-write against what the store holds now: entries in
    /// `adding` that are not there yet are appended, IPs in `removing` are
    /// dropped, and every other entry (a manual block written after this
    /// process loaded the list, say) stays. Returns the list as written, or
    /// nil when it could not be written.
    func update(adding: [BlockedEntry], removing: Set<String>) -> [BlockedEntry]?
    /// Whether `update` can write at all (checked at start in password mode).
    func writable() -> Bool
    /// r8: a cheap stamp of the store (one stat). The guard reads the store
    /// again whenever it moves, so a block added by hand while the service
    /// runs applies on the next check; nil (stat failed) reads it too.
    func probeStamp() -> ListenFileStamp?
}

extension BlocklistStore {
    /// Stores without a file never move.
    func probeStamp() -> ListenFileStamp? { ListenFileStamp(exists: false) }

    static func merged(_ current: [BlockedEntry], adding: [BlockedEntry], removing: Set<String>) -> [BlockedEntry] {
        var out = current.filter { !removing.contains($0.ip) }
        for e in adding where !removing.contains(e.ip) && !out.contains(where: { $0.ip == e.ip }) { out.append(e) }
        return out
    }
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
        return readDict().map(Self.entries(in:)) ?? []
    }

    func probeStamp() -> ListenFileStamp? { ListenFileStamp.of(url) }

    /// The `blockedIPs` of a listen.plist already read (the policy watcher
    /// reads the file once per check).
    static func entries(in dict: [String: Any]) -> [BlockedEntry] {
        guard let raw = dict["blockedIPs"] as? [Any] else { return [] }
        return raw.compactMap { item in
            if let ip = item as? String, ListenConfig.isIPv4(ip) {
                return BlockedEntry(ip: ip, at: Date(timeIntervalSince1970: 0), reason: "manual")
            }
            guard let d = item as? [String: Any], let ip = d["ip"] as? String, ListenConfig.isIPv4(ip) else { return nil }
            return BlockedEntry(ip: ip, at: d["at"] as? Date ?? Date(timeIntervalSince1970: 0),
                                reason: d["reason"] as? String ?? "manual")
        }
    }

    /// Attempts when listen.plist changes between the read and the replace.
    static let replaceAttempts = 5
    /// Self-test: runs after the new file is written, before it replaces
    /// listen.plist (to play an outside edit in that window).
    var beforeReplace: (() -> Void)?
    /// How long a write waits for the listen.plist lock before it gives up
    /// (and writes nothing).
    var lockWait: TimeInterval = 0.5

    /// B5: every supported writer holds the flock on `listen.plist.lock`
    /// from read to replace (ListenConfig.withFileLock; manual edits through
    /// `lockf`, Deploy/README.md), so no read-modify-write interleaves with
    /// another. Without the lock nothing is written (nil: the block stays
    /// pending and goes to the journal). The stamp compare before the
    /// replace stays as a second check against a writer that skipped the
    /// lock; such a writer is not supported.
    func update(adding: [BlockedEntry], removing: Set<String>) -> [BlockedEntry]? {
        lock.lock(); defer { lock.unlock() }
        let result = ListenConfig.withFileLock(url, wait: lockWait) { () -> [BlockedEntry]? in
            for _ in 1...Self.replaceAttempts {
                guard let before = ListenFileStamp.of(url), before.exists, var dict = readDict() else {
                    print("auth.blocklist_not_saved reason=no_listen_plist")
                    return nil
                }
                let out = Self.merged(Self.entries(in: dict), adding: adding, removing: removing)
                dict["blockedIPs"] = out.map { ["ip": $0.ip, "at": $0.at, "reason": $0.reason] as [String: Any] }
                let tmp = url.deletingLastPathComponent()
                    .appendingPathComponent(".\(url.lastPathComponent).\(getpid()).\(UUID().uuidString.prefix(8))")
                guard let data = try? PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0),
                      (try? data.write(to: tmp)) != nil else {
                    print("auth.blocklist_not_saved reason=write_failed")
                    return nil
                }
                beforeReplace?()
                guard ListenFileStamp.of(url) == before else {
                    unlink(tmp.path)
                    print("auth.blocklist_retry reason=changed_during_write")
                    continue
                }
                guard rename(tmp.path, url.path) == 0 else {
                    unlink(tmp.path)
                    print("auth.blocklist_not_saved reason=write_failed")
                    return nil
                }
                return out
            }
            print("auth.blocklist_not_saved reason=busy attempts=\(Self.replaceAttempts)")
            return nil
        }
        guard let result else {
            print("auth.blocklist_not_saved reason=lock")
            return nil
        }
        return result
    }

    /// An atomic write replaces the file, so the folder must be writable too.
    func writable() -> Bool {
        let fm = FileManager.default
        return readDict() != nil && fm.isWritableFile(atPath: url.path)
            && fm.isWritableFile(atPath: url.deletingLastPathComponent().path)
    }

    private func readDict() -> [String: Any]? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        return (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) as? [String: Any]
    }
}

final class MemoryBlocklist: BlocklistStore, @unchecked Sendable {
    var entries: [BlockedEntry]
    /// Self-test: this many writes fail before one succeeds.
    var failNextSaves = 0
    var canWrite = true
    private(set) var saveCalls = 0
    init(_ entries: [BlockedEntry] = []) { self.entries = entries }
    func load() -> [BlockedEntry] { entries }
    func update(adding: [BlockedEntry], removing: Set<String>) -> [BlockedEntry]? {
        saveCalls += 1
        if failNextSaves > 0 { failNextSaves -= 1; return nil }
        entries = Self.merged(entries, adding: adding, removing: removing)
        return entries
    }
    func writable() -> Bool { canWrite }
}

/// B5 r4: blocks that could not be written to listen.plist, kept in a second
/// file so a restart still enforces them. The guard loads it at start (the
/// entries are blocked and still pending, so the host stays shut until they
/// reach listen.plist) and empties it once they do.
protocol PendingBlockStore: AnyObject {
    /// r5: [] when there is no journal; nil when one exists but cannot be
    /// read or parsed (the guard then admits nobody: fail closed).
    func load() -> [BlockedEntry]?
    /// Replaces the journal with `entries` (empty removes it). False when
    /// it could not be written.
    func save(_ entries: [BlockedEntry]) -> Bool
    /// r7: a cheap stamp of the journal (one stat). The guard reads the
    /// journal again whenever it moves; nil (stat failed) reads it too.
    func probeStamp() -> ListenFileStamp?
}

extension PendingBlockStore {
    /// Stores without a file never move (they are read by `probeJournal`).
    func probeStamp() -> ListenFileStamp? { ListenFileStamp(exists: false) }
}

final class PendingBlockFile: PendingBlockStore, @unchecked Sendable {
    let url: URL
    init(url: URL) { self.url = url }

    func load() -> [BlockedEntry]? {
        var st = stat()
        if stat(url.path, &st) != 0 { return errno == ENOENT ? [] : nil }
        guard let data = try? Data(contentsOf: url),
              let dict = (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) as? [String: Any],
              let items = dict["blockedIPs"] as? [Any] else { return nil }
        let entries = ListenPlistBlocklist.entries(in: dict)
        // An entry that does not read is not dropped silently.
        return entries.count == items.count ? entries : nil
    }

    func save(_ entries: [BlockedEntry]) -> Bool {
        if entries.isEmpty {
            return unlink(url.path) == 0 || errno == ENOENT
        }
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        let dict: [String: Any] = ["blockedIPs": entries.map { ["ip": $0.ip, "at": $0.at, "reason": $0.reason] as [String: Any] }]
        guard let data = try? PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0) else { return false }
        return (try? data.write(to: url, options: .atomic)) != nil
    }

    func probeStamp() -> ListenFileStamp? { ListenFileStamp.of(url) }
}

final class MemoryPendingBlocks: PendingBlockStore, @unchecked Sendable {
    var entries: [BlockedEntry] = []
    var canWrite = true
    var unreadable = false
    func load() -> [BlockedEntry]? { unreadable ? nil : entries }
    func save(_ entries: [BlockedEntry]) -> Bool {
        guard canWrite else { return false }
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
        /// is blocked in memory and the host issues no challenge to anyone
        /// until the write succeeds (AuthGuard `pending`).
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
    /// Blocked in memory but not yet in the store (every write attempt
    /// failed). While any is pending, no challenge is issued to anyone, and
    /// the write is retried (`retryPending`): a restart must not be able to
    /// drop a block that was never written, so the host stays shut instead.
    private var pending: [BlockedEntry] = []
    /// B5 r4: the second place pending blocks are written to; `journaled`
    /// is what it holds as far as this guard knows.
    private let journal: PendingBlockStore?
    private var journaled: Set<String> = []
    /// r5 (B5): a journal exists but could not be read at start. Nobody is
    /// admitted (both modes) until it reads again or is removed; the file is
    /// never overwritten meanwhile.
    private var journalUnreadable = false
    /// r7: the journal's stamp when this guard last read it.
    private var journalKnown: ListenFileStamp?
    /// r8: the blocklist store's (listen.plist) stamp when last read.
    private var storeKnown: ListenFileStamp?
    private var lastJournalRetry: TimeInterval = -.infinity
    private var lastPendingRetry: TimeInterval = -.infinity
    static let pendingRetryInterval: TimeInterval = 1
    static let pendingRetrySeconds: UInt32 = 5

    init(whitelist: [String], blocklist: BlocklistStore,
         now: @escaping () -> TimeInterval = { ProcessInfo.processInfo.systemUptime },
         wallNow: @escaping () -> Date = { Date() },
         pause: @escaping (TimeInterval) -> Void = { Thread.sleep(forTimeInterval: $0) },
         journal: PendingBlockStore? = nil) {
        self.whitelist = whitelist
        self.blocklist = blocklist
        self.journal = journal
        self.now = now
        self.wallNow = wallNow
        self.pause = pause
        // r8: taken before the read, as for the journal.
        self.storeKnown = blocklist.probeStamp()
        let loaded = blocklist.load()
        self.persisted = Set(loaded.map(\.ip))
        // B5 r4: a block that never reached listen.plist before the last
        // exit is blocked again and still pending, so the host stays shut
        // (no challenges) until listen.plist holds it.
        // r5: read once; a journal that exists but does not read is not an
        // empty one.
        // Taken before the read: a write after it moves the stamp again.
        let journalStamp = journal?.probeStamp()
        let fromJournal = journal.map { $0.load() } ?? []
        if fromJournal != nil { self.journalKnown = journalStamp }
        let carried = (fromJournal ?? []).filter { e in !loaded.contains { $0.ip == e.ip } }
        self.blocked = loaded + carried
        self.pending = carried
        self.journaled = Set((fromJournal ?? []).map(\.ip))
        if fromJournal == nil {
            journalUnreadable = true
            lastJournalRetry = now()
            print("auth.lockdown reason=pending_journal_unreadable (file kept as is; nobody is admitted until it reads or is removed)")
        } else if !carried.isEmpty {
            print("auth.lockdown_restored peers=\(carried.count) source=pending_journal")
            lock.lock(); retryPendingLocked(force: true); lock.unlock()
        } else if !journaled.isEmpty {
            lock.lock(); _ = writeJournalLocked([]); lock.unlock()
        }
    }

    /// Blacklist first (it wins over the whitelist), then the whitelist, then
    /// this IP's wait, then the host-wide wait.
    func admit(_ ip: String) -> Admission {
        lock.lock(); defer { lock.unlock() }
        return admitLocked(ip)
    }

    /// r5 (B5): why nobody may be admitted at all, whatever the address
    /// (transition mode asks this before the blacklist). Nil when admission
    /// can go on to the per-address checks.
    func lockdownReason() -> String? {
        lock.lock(); defer { lock.unlock() }
        refreshLocked(force: false)
        return journalHoldLocked() ? "pending_journal_unreadable" : nil
    }

    /// r7 (B5): what input from viewer `ip` asks on every message once
    /// its connection is open (r8: every direct connection, control,
    /// clipboard, file and ping alike, by its peer address; r7: the mouse
    /// relay on every connection and message): nil to go on, else why not.
    /// The journal lockdown, then the same blacklist direct admission uses:
    /// listen.plist `blockedIPs` (re-read when it moved, r8) plus the blocks
    /// restored from the pending journal.
    func inputRefusal(_ ip: String) -> String? {
        lock.lock(); defer { lock.unlock() }
        refreshLocked(force: false)
        if journalHoldLocked() { return "pending_journal_unreadable" }
        return blocked.contains(where: { $0.ip == ip }) ? "blocked" : nil
    }

    /// r8: the journal, then listen.plist, each read again only when its
    /// stamp moved (one stat each otherwise).
    private func refreshLocked(force: Bool) {
        refreshStoreLocked()
        refreshJournalLocked(force: force)
    }

    /// r8: a block added to listen.plist from outside while the service
    /// runs (by hand, the host app) applies at once: it joins the blacklist
    /// and counts as persisted, so the policy watch does not restart the
    /// service for it and open sessions of other viewers go on; the
    /// blocked viewer's open sessions stop on their next message
    /// (`inputRefusal`). Only additions are taken here; a block removed
    /// from outside is still a change that restarts the service.
    private func refreshStoreLocked() {
        let stamp = blocklist.probeStamp()
        if let stamp, stamp == storeKnown { return }
        let entries = blocklist.load()
        storeKnown = stamp
        let added = entries.filter { !persisted.contains($0.ip) }
        guard !added.isEmpty else { return }
        persisted.formUnion(added.map(\.ip))
        for e in added where !blocked.contains(where: { $0.ip == e.ip }) { blocked.append(e) }
        print("auth.block_added peers=\(added.count) source=listen.plist found=running")
        fflush(stdout)
    }

    /// r6 (B5): a journal that stops reading while the service runs holds
    /// everything as one found at start does (the UDP input in the video
    /// service reads the same file). The policy watch calls this every
    /// second; the file is kept as it is. r7: every admission and every
    /// relay message also looks (one stat), so this is only the fallback.
    func probeJournal() {
        lock.lock(); defer { lock.unlock() }
        refreshLocked(force: true)
    }

    /// r7 (B5): reads the journal when it moved since this guard last read
    /// it (`force`: always), so the per-second probe leaves no window. One
    /// that does not read holds everything (`journalUnreadable`; the file
    /// is kept as it is). One that reads carries in any block this guard
    /// does not hold yet (one another control-service process journaled on
    /// its way out, say), as at start: blocked at once, pending until
    /// listen.plist holds it.
    private func refreshJournalLocked(force: Bool) {
        guard let journal, !journalUnreadable else { return }
        // Taken before the read: a write after it moves the stamp again.
        let stamp = journal.probeStamp()
        if !force, let stamp, stamp == journalKnown { return }
        guard let entries = journal.load() else {
            journalUnreadable = true
            journalKnown = nil
            lastJournalRetry = now()
            print("auth.lockdown reason=pending_journal_unreadable found=running (file kept as is; nobody is admitted and open connections stop until it reads or is removed)")
            fflush(stdout)
            return
        }
        journalKnown = stamp
        journaled = Set(entries.map(\.ip))
        let carried = entries.filter { e in !persisted.contains(e.ip) && !pending.contains { $0.ip == e.ip } }
        guard !carried.isEmpty else { return }
        for e in carried where !blocked.contains(where: { $0.ip == e.ip }) { blocked.append(e) }
        pending.append(contentsOf: carried)
        print("auth.lockdown_restored peers=\(carried.count) source=pending_journal found=running")
        fflush(stdout)
        retryPendingLocked(force: true)
    }

    /// Blacklist only (transition mode: no challenge, so no counting).
    func isBlocked(_ ip: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        refreshLocked(force: false)
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
        // The journal first: a restart must not bring the block back.
        if journaled.contains(ip) {
            guard writeJournalLocked(pending.filter { $0.ip != ip }) else {
                print("auth.release_failed peer=\(ip) reason=journal_write_failed")
                return .saveFailed
            }
        }
        guard writeLocked(adding: [], removing: [ip]) else {
            print("auth.release_failed peer=\(ip) reason=write_failed attempts=\(Self.saveAttempts)")
            return .saveFailed
        }
        blocked.removeAll { $0.ip == ip }
        pending.removeAll { $0.ip == ip }
        peers[ip] = nil
        print("auth.released peer=\(ip) persisted=listen.plist")
        return .released
    }

    enum ProbeAnswer: Equatable {
        case triesLeft(UInt8)
        case refused(Admission)
    }

    /// PR-C item 5: a zero-MAC transition probe that crossed a CHALLENGE.
    /// The admission is checked again (a wait or block that started since
    /// the challenge still wins), and the answer is the tries left now.
    /// Nothing is recorded: the probe is not a password.
    func probe(_ ip: String) -> ProbeAnswer {
        lock.lock(); defer { lock.unlock() }
        let admission = admitLocked(ip)
        guard admission == .challenge else { return .refused(admission) }
        let failures = peers[ip]?.failures ?? 0
        return .triesLeft(UInt8(Self.failuresPerStage - failures % Self.failuresPerStage))
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
        refreshStoreLocked()
        return persisted
    }

    private func admitLocked(_ ip: String) -> Admission {
        refreshLocked(force: false)
        if blocked.contains(where: { $0.ip == ip }) { return .blocked }
        if !whitelist.isEmpty && !whitelist.contains(ip) { return .notAllowed }
        let t = now()
        if let p = peers[ip], p.lockedUntil > t {
            return .locked(retrySeconds: Self.seconds(p.lockedUntil - t), stage: p.stage)
        }
        if globalLockedUntil > t { return .globalLocked(retrySeconds: Self.seconds(globalLockedUntil - t)) }
        if journalHoldLocked() { return .globalLocked(retrySeconds: Self.pendingRetrySeconds) }
        if !pending.isEmpty {
            retryPendingLocked(force: false)
            if !pending.isEmpty { return .globalLocked(retrySeconds: Self.pendingRetrySeconds) }
        }
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
            let entry = blocked.first { $0.ip == ip }!
            let persisted = writeLocked(adding: [entry], removing: [])
            if !persisted && !pending.contains(where: { $0.ip == ip }) {
                pending.append(entry)
                lastPendingRetry = t
                let journalSaved = writeJournalLocked(pending)
                print("auth.lockdown reason=blocklist_unpersisted peer=\(ip) journal=\(journalSaved ? "saved" : "not_saved") (no challenges until listen.plist is written)")
            }
            return Failure(outcome: .blacklisted(persisted: persisted), failures: failures, globalTriggered: globalTriggered)
        }
        let wait = Self.stageWait * Double(p.stage)
        p.lockedUntil = t + wait
        peers[ip] = p
        return Failure(outcome: .locked(retrySeconds: Self.seconds(wait), stage: p.stage),
                       failures: failures, globalTriggered: globalTriggered)
    }

    /// Bounded retry of one merge write (BlocklistStore.update). On success
    /// the guard also adopts entries someone else wrote meanwhile, so a
    /// manual block applies at once; `persisted` tracks only what this guard
    /// wrote or loaded, so the policy watcher still sees the outside edit.
    private func writeLocked(adding: [BlockedEntry], removing: Set<String>) -> Bool {
        for attempt in 1...Self.saveAttempts {
            if let stored = blocklist.update(adding: adding, removing: removing) {
                persisted.formUnion(adding.map(\.ip))
                persisted.subtract(removing)
                for e in stored where !blocked.contains(where: { $0.ip == e.ip }) && !persisted.contains(e.ip) {
                    blocked.append(e)
                }
                return true
            }
            if attempt < Self.saveAttempts { pause(Self.saveRetryPause * Double(attempt)) }
        }
        return false
    }

    /// Writes blocks that are still only in memory. Called on every
    /// admission (at most once per `pendingRetryInterval`) and by the
    /// control service's policy watcher; `force` skips the interval (the
    /// service calls it before exiting). True when nothing is pending.
    @discardableResult func retryPending(force: Bool = true) -> Bool {
        lock.lock(); defer { lock.unlock() }
        retryPendingLocked(force: force)
        return pending.isEmpty
    }

    var pendingIPs: [String] {
        lock.lock(); defer { lock.unlock() }
        return pending.map(\.ip)
    }

    private func retryPendingLocked(force: Bool) {
        guard !pending.isEmpty else { return }
        let t = now()
        guard force || t - lastPendingRetry >= Self.pendingRetryInterval else { return }
        lastPendingRetry = t
        let waiting = pending
        if blocklist.update(adding: waiting, removing: []) != nil {
            persisted.formUnion(waiting.map(\.ip))
            pending = []
            _ = writeJournalLocked([])
            print("auth.lockdown_cleared persisted=listen.plist peers=\(waiting.count)")
        }
    }

    /// Every pending block is at least in the journal (true when none is
    /// pending). The control service does not exit while this is false.
    var isDurable: Bool {
        lock.lock(); defer { lock.unlock() }
        return pending.allSatisfy { journaled.contains($0.ip) }
    }

    /// Writes the pending blocks to the journal again. True when durable.
    @discardableResult func saveJournal() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if pending.allSatisfy({ journaled.contains($0.ip) }) { return true }
        return writeJournalLocked(pending)
    }

    /// r5 (B5): while the journal does not read, try it again at most once
    /// per `pendingRetryInterval`; true while it still does not. Once it
    /// reads (repaired or removed), its blocks are carried in as at start.
    private func journalHoldLocked() -> Bool {
        guard journalUnreadable else { return false }
        guard let journal else { journalUnreadable = false; return false }
        let t = now()
        guard t - lastJournalRetry >= Self.pendingRetryInterval else { return true }
        lastJournalRetry = t
        // r7: stamp first, so the next refresh does not read it again.
        let stamp = journal.probeStamp()
        guard let entries = journal.load() else { return true }
        journalUnreadable = false
        journalKnown = stamp
        journaled = Set(entries.map(\.ip))
        let carried = entries.filter { e in !persisted.contains(e.ip) && !pending.contains { $0.ip == e.ip } }
        for e in carried where !blocked.contains(where: { $0.ip == e.ip }) { blocked.append(e) }
        pending.append(contentsOf: carried)
        print("auth.lockdown_journal_readable peers=\(carried.count)")
        if journaled != Set(pending.map(\.ip)) { _ = writeJournalLocked(pending) }
        retryPendingLocked(force: true)
        return false
    }

    private func writeJournalLocked(_ entries: [BlockedEntry]) -> Bool {
        guard let journal else { return false }
        guard !journalUnreadable else {
            print("auth.pending_journal_not_saved peers=\(entries.count) reason=journal_unreadable (kept as is)")
            return false
        }
        guard journal.save(entries) else {
            print("auth.pending_journal_not_saved peers=\(entries.count)")
            return false
        }
        journaled = Set(entries.map(\.ip))
        return true
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
        // A passwordSet that is not a bool is not "no password".
        if let plist, case .unknown(let why) = ListenConfig.passwordState(plist: plist) {
            return .refused(reason: why)
        }
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
    /// Raw description: an edit to a non-bool value is a change too.
    var passwordSet: String
    /// Raw description, so an invalid edit is noticed too.
    var allowedIPs: String
    var allowedIPsSource: String
    /// Salt and host id (not K): a new salt on every password change.
    var secretTag: String

    static func read(plist: [String: Any]?, secret: ConnSecret?) -> AuthConfigSnapshot {
        AuthConfigSnapshot(passwordSet: plist?["passwordSet"].map { String(describing: $0) } ?? "-",
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
/// `listen.plist.pre-0.4`. `clientIP` itself stays (0.3 hosts reading the
/// file still need it); since PR-C the UDP paths follow the session, not
/// clientIP, and the host app's 連線設定 removes it with the source key
/// when it saves a whitelist. While `allowedIPsSource` is `clientIP`
/// the whitelist follows `clientIP`; whoever edits `allowedIPs` by hand or
/// in the host app removes that key.
enum ListenMigration {
    static let sourceKey = "allowedIPsSource"
    static let sourceClientIP = "clientIP"

    static func followsClientIP(_ plist: [String: Any]?) -> Bool {
        plist?[sourceKey] as? String == sourceClientIP
    }

    /// Holds the listen.plist flock, so it never interleaves with a
    /// blacklist write from a control service that is still running.
    /// r5 (B5): without the lock nothing is written.
    static func migrate(url: URL) -> String? {
        guard FileManager.default.fileExists(atPath: url.path) else { return nil }
        guard let result = ListenConfig.withFileLock(url, { migrateLocked(url: url) }) else {
            return "config.migrate_failed reason=lock"
        }
        return result
    }

    private static func migrateLocked(url: URL) -> String? {
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

    private let revokeLock = NSLock()
    private var revoked = false

    /// The policy changed (ControlService.PolicyWatch): from now on this gate
    /// admits nobody, before the service stops or restarts.
    func revoke() { revokeLock.lock(); revoked = true; revokeLock.unlock() }
    var isRevoked: Bool { revokeLock.lock(); defer { revokeLock.unlock() }; return revoked }

    static func make(policy: AuthPolicy, secret: ConnSecret?, blocklist: BlocklistStore,
                     journal: PendingBlockStore? = nil) -> AuthGate {
        let whitelist: [String]
        switch policy {
        case .password(let w), .transition(let w): whitelist = w
        case .refused: whitelist = []
        }
        return AuthGate(policy: policy, guardian: AuthGuard(whitelist: whitelist, blocklist: blocklist, journal: journal), secret: secret)
    }
}
