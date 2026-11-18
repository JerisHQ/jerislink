import Foundation

/// Whether a viewer is still there, from the MRM1 datagrams it sends to the
/// video process (mouse, keyframe requests, NACKs, receiver reports, pings,
/// audio requests).
///
/// The video service used to capture, encode and send to the configured
/// client from launch until it stopped, whether or not a viewer was running.
/// A viewer that was closed, killed, put to sleep or cut off the network left
/// the host sending 4K video to nobody. Now capture runs only while a viewer
/// is heard: it starts on the first datagram, and stops when nothing has
/// arrived for `idleSeconds`.
///
/// A running viewer repeats a 0x43 ping every second (when the host NACK is
/// on), a 0x45 audio request every second (audio on) and a 0x42 receiver
/// report every 250 ms (ABR on), also while it is minimized, has no input or
/// sits in a Windows modal loop. Once a session (source port) has sent one of
/// these, `idleSeconds` of silence ends it. Until then (the first keep-alive
/// was lost, the viewer vanished after a keyframe request, or a viewer with
/// NACK, ABR and audio all off) the longer `fallbackSeconds` applies: no
/// session is exempt from the timeout.
final class ViewerPresence: @unchecked Sendable {
    static let idleSeconds: Double = 15
    /// Silence limit for a session that has not sent a keep-alive yet.
    static let fallbackSeconds: Double = 60

    private let lock = NSLock()
    private let idleNs: UInt64
    private let fallbackNs: UInt64
    private var lastHeardNs: UInt64 = 0  // 0: nothing heard yet
    private var keepAliveSeen = false
    private var heardCount: UInt64 = 0

    init(idleSeconds: Double = ViewerPresence.idleSeconds,
         fallbackSeconds: Double = ViewerPresence.fallbackSeconds) {
        idleNs = UInt64(idleSeconds * 1_000_000_000)
        fallbackNs = UInt64(max(fallbackSeconds, idleSeconds) * 1_000_000_000)
    }

    static func nowNs() -> UInt64 { DispatchTime.now().uptimeNanoseconds }

    /// MRM1 types the viewer repeats on a timer for as long as it runs.
    static func isKeepAlive(_ type: UInt8) -> Bool {
        type == 0x42 || type == 0x43 || type == 0x45
    }

    /// One valid MRM1 datagram from the allowed client. `newSession`: a new
    /// source port (a viewer started or restarted); it is held to the
    /// fallback limit until it sends a keep-alive of its own.
    func heard(type: UInt8, newSession: Bool, nowNs: UInt64 = ViewerPresence.nowNs()) {
        lock.lock(); defer { lock.unlock() }
        if newSession { keepAliveSeen = false }
        if Self.isKeepAlive(type) { keepAliveSeen = true }
        lastHeardNs = max(nowNs, 1)
        heardCount &+= 1
    }

    /// A viewer was heard within the silence limit of its session.
    func isActive(nowNs: UInt64 = ViewerPresence.nowNs()) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard lastHeardNs != 0 else { return false }
        let limit = keepAliveSeen ? idleNs : fallbackNs
        return nowNs < lastHeardNs || nowNs - lastHeardNs < limit
    }

    /// Seconds since the last datagram (-1: none yet), for the log.
    func silenceSeconds(nowNs: UInt64 = ViewerPresence.nowNs()) -> Double {
        lock.lock(); defer { lock.unlock() }
        guard lastHeardNs != 0, nowNs >= lastHeardNs else { return -1 }
        return Double(nowNs - lastHeardNs) / 1_000_000_000
    }

    var datagramsHeard: UInt64 {
        lock.lock(); defer { lock.unlock() }
        return heardCount
    }

    /// Returns when `isActive()` equals `active`, checking every `poll`, or
    /// false when `deadline` passes first or the task is cancelled. A few
    /// lock reads per second: no capture or encode runs while it waits.
    func wait(active: Bool, deadline: Date? = nil,
              poll: Duration = .milliseconds(250)) async -> Bool {
        while isActive() != active {
            if Task.isCancelled { return false }
            if let deadline, Date() >= deadline { return false }
            try? await Task.sleep(for: poll)
        }
        return true
    }

    /// Calls `onIdle` every time the viewer goes quiet, until the task is
    /// cancelled. The capture loop re-checks `isActive()` after each wake, so
    /// a viewer that comes back before that check keeps capture running; the
    /// watcher then waits for it to go quiet again instead of exiting.
    func watchIdle(poll: Duration = .milliseconds(500), onIdle: @Sendable () -> Void) async {
        while !Task.isCancelled {
            guard await wait(active: false, poll: poll) else { return }
            onIdle()
            guard await wait(active: true, poll: poll) else { return }
        }
    }
}

extension DisplayFollower {
    /// `waitForChange` for the capture loop: also returns nil when the viewer
    /// goes quiet. A watcher task wakes the monitor on every idle transition
    /// for as long as this waits. `beforeIdleSignal` is for the self-test (a
    /// datagram landing between the wake and the capture loop's check).
    static func waitForChangeOrViewerIdle<T>(isolation: isolated (any Actor)? = #isolation,
                                             monitor: DisplayChangeMonitor,
                                             since generation: UInt64,
                                             deadline: Date?,
                                             presence: ViewerPresence?,
                                             idlePoll: Duration = .milliseconds(500),
                                             beforeIdleSignal: (@Sendable () -> Void)? = nil,
                                             settleDelays: [Duration] = DisplayFollower.settleDelays,
                                             sleep: (Duration) async -> Void = { try? await Task.sleep(for: $0) },
                                             query: () async -> T?,
                                             isChange: (T) -> Bool) async -> T? {
        let idleWatch: Task<Void, Never>? = presence.map { p in
            Task {
                await p.watchIdle(poll: idlePoll) {
                    beforeIdleSignal?()
                    monitor.signal()
                }
            }
        }
        defer { idleWatch?.cancel() }
        return await waitForChange(isolation: isolation, monitor: monitor, since: generation,
                                   deadline: deadline, settleDelays: settleDelays, sleep: sleep,
                                   query: query, isChange: isChange,
                                   stop: { presence.map { !$0.isActive() } ?? false })
    }
}

/// `JerisLinkHost --self-test` part for the viewer presence gate. Fixed
/// clock values for the timeout rules; short real timers for the watcher.
enum ViewerPresenceSelfTest {
    private final class Count: @unchecked Sendable {
        private let lock = NSLock()
        private var n = 0
        func bump() -> Int { lock.lock(); defer { lock.unlock() }; n += 1; return n }
        var value: Int { lock.lock(); defer { lock.unlock() }; return n }
    }

    static func run() async -> Int32 {
        var failures = 0
        func expect(_ ok: Bool, _ name: String) {
            print("\(ok ? "PASS" : "FAIL") \(name)")
            if !ok { failures += 1 }
        }
        let s: UInt64 = 1_000_000_000

        do {
            let p = ViewerPresence(idleSeconds: 15)
            expect(!p.isActive(nowNs: 100 * s), "presence.none_heard_inactive")
            expect(p.silenceSeconds(nowNs: 100 * s) == -1, "presence.none_heard_silence")
        }
        do {
            // A viewer that sends one keyframe request and is gone before its
            // first keep-alive: active for the fallback limit, then idle.
            let p = ViewerPresence(idleSeconds: 15, fallbackSeconds: 60)
            p.heard(type: 0x40, newSession: true, nowNs: 100 * s)
            expect(p.isActive(nowNs: 101 * s), "presence.first_datagram_active")
            expect(p.isActive(nowNs: 159 * s), "presence.gone_before_keepalive active at 59s")
            expect(!p.isActive(nowNs: 160 * s), "presence.gone_before_keepalive idle at 60s")
            expect(!p.isActive(nowNs: 10_000 * s), "presence.no_keepalive_not_exempt")
        }
        do {
            // The first keep-alive is lost; later ones arm the 15 s timeout.
            let p = ViewerPresence(idleSeconds: 15, fallbackSeconds: 60)
            p.heard(type: 0x40, newSession: true, nowNs: 100 * s)
            // 0x43 at 101 and 102 lost; mouse at 102 does not arm it.
            p.heard(type: 0x00, newSession: false, nowNs: 102 * s)
            expect(p.isActive(nowNs: 130 * s), "presence.first_keepalive_lost fallback holds")
            for t in 103...120 { p.heard(type: 0x43, newSession: false, nowNs: UInt64(t) * s) }
            expect(p.isActive(nowNs: 134 * s), "presence.first_keepalive_lost active at 14s")
            expect(!p.isActive(nowNs: 135 * s), "presence.first_keepalive_lost idle at 15s")
        }
        do {
            // Pings every second keep it alive; 15 s of silence ends it.
            let p = ViewerPresence(idleSeconds: 15)
            p.heard(type: 0x40, newSession: true, nowNs: 100 * s)
            for t in 101...160 { p.heard(type: 0x43, newSession: false, nowNs: UInt64(t) * s) }
            expect(p.isActive(nowNs: 174 * s), "presence.ping_keeps_alive at 14s")
            expect(!p.isActive(nowNs: 175 * s), "presence.idle_after_15s")
            expect(abs(p.silenceSeconds(nowNs: 175 * s) - 15) < 0.001, "presence.silence_seconds")
            // The same viewer comes back (network restored): active again.
            p.heard(type: 0x43, newSession: false, nowNs: 200 * s)
            expect(p.isActive(nowNs: 200 * s), "presence.resume_on_datagram")
        }
        do {
            // Receiver reports and audio requests count as keep-alives too.
            for type: UInt8 in [0x42, 0x45] {
                let p = ViewerPresence(idleSeconds: 15)
                p.heard(type: type, newSession: true, nowNs: 100 * s)
                expect(!p.isActive(nowNs: 116 * s), "presence.keepalive_0x\(String(type, radix: 16))_arms_timeout")
            }
        }
        do {
            // A new source port after a pinging session: bounded by the
            // fallback until it pings, never exempt.
            let p = ViewerPresence(idleSeconds: 15, fallbackSeconds: 60)
            p.heard(type: 0x43, newSession: true, nowNs: 100 * s)
            p.heard(type: 0x40, newSession: true, nowNs: 101 * s)
            expect(p.isActive(nowNs: 160 * s), "presence.new_session_fallback active at 59s")
            expect(!p.isActive(nowNs: 161 * s), "presence.new_session_fallback idle at 60s")
            p.heard(type: 0x43, newSession: false, nowNs: 200 * s)
            expect(!p.isActive(nowNs: 215 * s), "presence.new_session_keepalive_rearms 15s")
        }
        do {
            // wait(active:) returns at once when already there, and gives up
            // at the deadline.
            let p = ViewerPresence(idleSeconds: 15)
            let start = Date()
            let gotUp = await p.wait(active: true, deadline: Date().addingTimeInterval(0.3), poll: .milliseconds(50))
            expect(!gotUp && Date().timeIntervalSince(start) < 2, "presence.wait_deadline")
            p.heard(type: 0x43, newSession: true)
            let up = await p.wait(active: true, poll: .milliseconds(50))
            expect(up, "presence.wait_active")
        }
        do {
            // Regression (review of #63): the viewer comes back between the
            // watcher's wake and the capture loop's check, twice. The watcher
            // must keep watching, so the third silence still stops capture.
            let p = ViewerPresence(idleSeconds: 0.3, fallbackSeconds: 0.3)
            let monitor = DisplayChangeMonitor()
            let wakes = Count()
            p.heard(type: 0x43, newSession: true)
            let start = Date()
            let result: Int? = await DisplayFollower.waitForChangeOrViewerIdle(
                monitor: monitor, since: monitor.currentGeneration,
                deadline: Date().addingTimeInterval(6), presence: p, idlePoll: .milliseconds(50),
                beforeIdleSignal: { if wakes.bump() <= 2 { p.heard(type: 0x43, newSession: false) } },
                sleep: { _ in }, query: { 1 }, isChange: { _ in false })
            let waited = Date().timeIntervalSince(start)
            expect(result == nil && wakes.value == 3 && waited < 4,
                   "presence.watcher_survives_resume wakes=\(wakes.value) waited=\(String(format: "%.2f", waited))s")
        }
        do {
            // Disconnect -> reconnect -> disconnect, three rounds through the
            // capture loop's wait: every silence ends the wait well before
            // the deadline, every return of the viewer makes it active.
            let p = ViewerPresence(idleSeconds: 0.3, fallbackSeconds: 0.3)
            let monitor = DisplayChangeMonitor()
            var rounds = 0
            for round in 1...3 {
                let feeder = Task {
                    let end = Date().addingTimeInterval(0.6)
                    while Date() < end, !Task.isCancelled {
                        p.heard(type: 0x43, newSession: round == 1)
                        try? await Task.sleep(for: .milliseconds(50))
                    }
                }
                let up = await p.wait(active: true, deadline: Date().addingTimeInterval(2), poll: .milliseconds(20))
                let start = Date()
                let result: Int? = await DisplayFollower.waitForChangeOrViewerIdle(
                    monitor: monitor, since: monitor.currentGeneration,
                    deadline: Date().addingTimeInterval(5), presence: p, idlePoll: .milliseconds(50),
                    sleep: { _ in }, query: { 1 }, isChange: { _ in false })
                let waited = Date().timeIntervalSince(start)
                feeder.cancel()
                let ok = up && result == nil && !p.isActive() && waited >= 0.5 && waited < 2.5
                expect(ok, "presence.disconnect_reconnect round=\(round) waited=\(String(format: "%.2f", waited))s")
                if ok { rounds += 1 }
            }
            expect(rounds == 3, "presence.disconnect_reconnect_rounds=\(rounds)")
        }
        print("viewer presence self-test: \(failures == 0 ? "ok" : "\(failures) failed")")
        return failures == 0 ? 0 : 1
    }
}
