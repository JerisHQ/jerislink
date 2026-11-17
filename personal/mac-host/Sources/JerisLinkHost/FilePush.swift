import Foundation
import Darwin
import CryptoKit

/// Finder "Send to JerisLink" (F5b), the host half. Design r2 section 3c.
///
/// The Service helper hands the agent open files over the send socket
/// (`SendSocketServer`). `PushBroker` gives the batch to the newest file
/// session and waits for the viewer's answer; the session's `PushSender`
/// sends OFFER purpose=push plus one ENTRY per file and serves the viewer's
/// REQUESTs from the descriptors. The viewer ends every push with RESULT;
/// then (or on CANCEL, a refusal, or the session closing) the descriptors
/// are closed. One push at a time on the whole Mac. Logs carry no names.

/// One file the helper opened.
struct PushFile {
    var name: [UInt8]   // NFC leaf name
    var fd: Int32
    var size: UInt64
    var mtime: Int64
}

/// A batch from one helper request. Owns the descriptors until `release`.
final class PushJob: @unchecked Sendable {  // state behind `lock`
    let files: [PushFile]
    let total: UInt64
    private let lock = NSLock()
    private var reply: SendWire.Reply?
    private var released = false
    private var abandoned = false
    private let answered = DispatchSemaphore(value: 0)

    init(files: [PushFile]) {
        self.files = files
        total = files.reduce(0) { $0 + $1.size }
    }

    deinit { release() }

    /// The first answer wins; later ones are ignored.
    func answer(_ r: SendWire.Reply) {
        lock.lock()
        let first = reply == nil
        if first { reply = r }
        lock.unlock()
        if first { answered.signal() }
    }

    /// Waits for the answer; nil after `seconds`.
    func wait(seconds: Double) -> SendWire.Reply? {
        guard answered.wait(timeout: .now() + seconds) == .success else { return nil }
        lock.lock(); defer { lock.unlock() }
        return reply
    }

    /// The helper stopped waiting: the session ends the push.
    func abandon() { lock.lock(); abandoned = true; lock.unlock() }
    var isAbandoned: Bool { lock.lock(); defer { lock.unlock() }; return abandoned }

    func release() {
        lock.lock()
        let first = !released
        released = true
        lock.unlock()
        if first { for f in files { Darwin.close(f.fd) } }
    }
}

/// Hands push jobs from the send socket to a file session.
final class PushBroker: @unchecked Sendable {  // state behind `lock`
    static let shared = PushBroker()

    private let lock = NSLock()
    private var sessions: [(id: UInt64, caps: UInt16, heard: Double)] = []
    private var nextSession: UInt64 = 0
    private var pending: (session: UInt64, job: PushJob)?
    private var running: PushJob?
    private let now: () -> Double

    /// A session heard from within this long is live. The viewer PINGs
    /// every 15 s, so a live one is never quiet for more than about 15 s;
    /// this allows one lost PING and some slack.
    static let liveSeconds: Double = 35

    init(now: @escaping () -> Double = { ProcessInfo.processInfo.systemUptime }) {
        self.now = now
    }

    /// A file session opened. Pushes go to the newest live session whose
    /// viewer said HELLO caps=push_service: one viewer opens a caps-0 upload
    /// session next to its push-capable pull session, in either order.
    func register(peerCaps: UInt16) -> UInt64 {
        lock.lock(); defer { lock.unlock() }
        nextSession += 1
        sessions.append((nextSession, peerCaps, now()))
        return nextSession
    }

    /// The session got a message from its viewer (PING or anything else).
    func heard(_ id: UInt64) {
        lock.lock(); defer { lock.unlock() }
        guard let i = sessions.firstIndex(where: { $0.id == id }) else { return }
        sessions[i].heard = now()
    }

    func unregister(_ id: UInt64) {
        lock.lock()
        sessions.removeAll { $0.id == id }
        let orphan = pending?.session == id ? pending?.job : nil
        if orphan != nil { pending = nil }
        lock.unlock()
        orphan?.answer(.notConnected)
        orphan?.release()
    }

    /// Queues `job` for the newest live push-capable session. Answers at
    /// once when it cannot: no session at all is not_connected, sessions
    /// that all lack push_service are old_viewer, and push-capable sessions
    /// that have all gone quiet are not_connected too. A quiet session's
    /// viewer is gone or stuck (a second viewer window on the same PC left
    /// one behind): offering to it would only time out as failed.
    func offer(_ job: PushJob) -> SendWire.Reply? {
        lock.lock(); defer { lock.unlock() }
        guard !sessions.isEmpty else { return .notConnected }
        let capable = sessions.filter { ($0.caps & FileProto.Caps.pushService) != 0 }
        guard !capable.isEmpty else { return .oldViewer }
        let t = now()
        guard let target = capable.last(where: { t - $0.heard <= PushBroker.liveSeconds }) else {
            print("file.push_route=no_live_session push_sessions=\(capable.count)")
            return .notConnected
        }
        if target.id != capable.last?.id {
            print("file.push_route=skipped_quiet push_sessions=\(capable.count)")
        }
        guard pending == nil, running == nil else { return .busy }
        pending = (target.id, job)
        return nil
    }

    /// Gives `job` to its session and waits up to `seconds` for the
    /// viewer to accept or refuse it.
    func submit(_ job: PushJob, waitSeconds: Double = 10) -> SendWire.Reply {
        if let now = offer(job) {
            job.release()
            return now
        }
        if let r = job.wait(seconds: waitSeconds) { return r }
        // No answer: if no session took it, forget it; else the session
        // sees the abandon and cancels.
        lock.lock()
        let untaken = pending.map { $0.job === job } ?? false
        if untaken { pending = nil }
        lock.unlock()
        job.abandon()
        if untaken { job.release() }
        return .failed
    }

    /// The session's poll: its job, if one waits.
    func take(session id: UInt64) -> PushJob? {
        lock.lock(); defer { lock.unlock() }
        guard let p = pending, p.session == id else { return nil }
        pending = nil
        running = p.job
        return p.job
    }

    /// The session is done with `job` (any ending).
    func finished(_ job: PushJob) {
        lock.lock()
        if running === job { running = nil }
        lock.unlock()
        job.release()
    }

    var sessionCount: Int {
        lock.lock(); defer { lock.unlock() }
        return sessions.count
    }

    var isIdle: Bool {
        lock.lock(); defer { lock.unlock() }
        return pending == nil && running == nil
    }
}

/// Serves one push on its session thread. Not thread-safe.
final class PushSender {
    typealias Message = FileProto.Message

    let transfer: UInt32
    let job: PushJob
    private(set) var accepted = false
    private(set) var ended = false
    private(set) var bytesOut: UInt64 = 0
    private(set) var filesServed: UInt64 = 0
    private var index: UInt32 = .max
    private var next: UInt64 = 0
    private var hasher = SHA256()

    /// Largest REQUEST served in one go; the viewer asks for 1 MiB.
    static let maxRequest: UInt32 = 4 << 20
    nonisolated(unsafe) private static var counter: UInt32 = UInt32.random(in: 1...0x3fff_ffff)  // behind counterLock
    private static let counterLock = NSLock()

    /// Push ids have the top bit set and are even: never an announce id
    /// (below 2^31) or a viewer upload id (odd).
    static func newTransfer() -> UInt32 {
        counterLock.lock(); defer { counterLock.unlock() }
        counter = (counter &+ 1) & 0x3fff_ffff
        if counter == 0 { counter = 1 }
        return 0x8000_0000 | (counter << 1)
    }

    init(job: PushJob, transfer: UInt32 = PushSender.newTransfer()) {
        self.job = job
        self.transfer = transfer
    }

    func start() -> [Message] {
        var out: [Message] = [.offer(transfer: transfer, purpose: FileProto.Purpose.push,
                                     entries: UInt32(job.files.count), total: job.total)]
        for (i, f) in job.files.enumerated() {
            out.append(.entry(transfer: transfer, index: UInt32(i), kind: FileProto.EntryKind.file,
                              size: f.size, mtime: f.mtime, path: f.name))
        }
        print("file.push transfer=\(transfer) files=\(job.files.count) bytes=\(job.total)")
        return out
    }

    /// REPLY from the viewer. Not ok ends the push.
    func reply(_ status: UInt8) {
        if status == FileProto.Status.ok {
            accepted = true
            job.answer(.ok)
            return
        }
        let r: SendWire.Reply
        switch status {
        case FileProto.Status.busy: r = .busy
        case FileProto.Status.tooBig: r = .tooBig
        case FileProto.Status.badPath: r = .badName
        case FileProto.Status.noSpace: r = .noSpace
        default: r = .refused
        }
        end("refused_\(status)", answer: r)
    }

    func result(status: UInt8, filesOK: UInt32) {
        end(status == FileProto.Status.ok ? "ok" : "failed_\(status)", files: filesOK)
    }

    func cancelled() { end("cancelled") }

    /// The helper gave up waiting before the viewer answered.
    func abandon() -> [Message] {
        end("abandoned")
        return [.cancel(transfer: transfer, reason: FileProto.Status.cancelled)]
    }

    /// The session closed under the push.
    func close() { end("session_closed", answer: .notConnected) }

    private func end(_ why: String, answer: SendWire.Reply = .failed, files: UInt32? = nil) {
        guard !ended else { return }
        ended = true
        job.answer(answer)
        print("file.push transfer=\(transfer) result=\(why) files_ok=\(files.map(String.init) ?? "-") served=\(filesServed) bytes=\(bytesOut)")
    }

    /// Answers one REQUEST through `send`. False only when `send` failed.
    /// Reads are sequential per file, one file at a time; offset 0
    /// (re)starts a file. A refused request gets REPLY failed and ends the
    /// push (the viewer then sends RESULT, which finds nothing to do).
    func serve(index i: UInt32, offset: UInt64, length: UInt32, send: (Message) -> Bool) -> Bool {
        func refuse(_ why: String) -> Bool {
            end("refused_request:\(why)")
            return send(.reply(transfer: transfer, status: FileProto.Status.failed))
        }
        guard accepted, !ended else { return refuse("state") }
        guard Int(i) < job.files.count else { return refuse("index") }
        let f = job.files[Int(i)]
        guard offset <= f.size else { return refuse("offset") }
        if offset == 0 {
            index = i
            next = 0
            hasher = SHA256()
        } else {
            guard i == index, offset == next else { return refuse("sequence") }
        }
        let stop = min(f.size, offset + UInt64(min(length, Self.maxRequest)))
        var buf = [UInt8](repeating: 0, count: Int(FileProto.maxChunk))
        while next < stop {
            let want = Int(min(UInt64(FileProto.maxChunk), stop - next))
            let n = buf.withUnsafeMutableBytes { Darwin.pread(f.fd, $0.baseAddress!, want, off_t(next)) }
            if n < 0, errno == EINTR { continue }
            if n <= 0 { return refuse(n == 0 ? "changed" : "read") }
            let chunk = Array(buf[0..<n])
            hasher.update(data: chunk)
            guard send(.data(transfer: transfer, index: i, offset: next, bytes: chunk)) else { return false }
            next += UInt64(n)
            bytesOut += UInt64(n)
        }
        if next == f.size {
            // A file that grew since the helper opened it is not what was offered.
            var extra: UInt8 = 0
            if Darwin.pread(f.fd, &extra, 1, off_t(f.size)) != 0 { return refuse("changed") }
            index = .max
            filesServed += 1
            return send(.fileEnd(transfer: transfer, index: i, sha256: Array(hasher.finalize())))
        }
        return true
    }
}
