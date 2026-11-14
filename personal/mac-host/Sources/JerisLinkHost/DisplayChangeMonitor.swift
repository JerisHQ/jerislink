import CoreGraphics
import Foundation

/// Display reconfiguration events from CoreGraphics (display added or removed,
/// main display moved, mode or HiDPI change). Replaces the old 500 ms layout
/// poll and the 5 s ScreenCaptureKit re-check: the capture loop sleeps until
/// one of these arrives. The callback runs on the main run loop, which the
/// async `main` keeps running (CFRunLoopRun).
final class DisplayChangeMonitor: @unchecked Sendable {
    private let lock = NSLock()
    private var generation: UInt64 = 0
    private var waiter: CheckedContinuation<Void, Never>?
    private var reconfigurations: UInt64 = 0
    private var registered = false

    /// The monitor of the running process; registered once, never removed.
    static let shared = DisplayChangeMonitor()

    /// Registers the CoreGraphics callback. Idempotent. Returns false when
    /// CoreGraphics refuses it (no window server).
    @discardableResult
    func register() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if registered { return true }
        let info = Unmanaged.passUnretained(self).toOpaque()
        registered = CGDisplayRegisterReconfigurationCallback(displayReconfigured, info) == .success
        return registered
    }

    /// One CoreGraphics reconfiguration report. The "about to change" report
    /// (begin flag only) is skipped: the matching end report follows it.
    func note(flags: CGDisplayChangeSummaryFlags) {
        if flags == .beginConfigurationFlag { return }
        lock.lock()
        reconfigurations &+= 1
        lock.unlock()
        signal()
    }

    /// Wakes the waiter; also used for the `--duration` deadline.
    func signal() {
        lock.lock()
        generation &+= 1
        let w = waiter
        waiter = nil
        lock.unlock()
        w?.resume()
    }

    var currentGeneration: UInt64 {
        lock.lock(); defer { lock.unlock() }
        return generation
    }

    var reconfigurationCount: UInt64 {
        lock.lock(); defer { lock.unlock() }
        return reconfigurations
    }

    /// Returns once the generation is past `seen` (at once if it already is).
    /// One waiter at a time: the capture loop.
    func wait(after seen: UInt64) async {
        await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
            lock.lock()
            if generation != seen {
                lock.unlock()
                c.resume()
                return
            }
            let previous = waiter
            waiter = c
            lock.unlock()
            previous?.resume()
        }
    }
}

private func displayReconfigured(_ display: CGDirectDisplayID, _ flags: CGDisplayChangeSummaryFlags,
                                 _ info: UnsafeMutableRawPointer?) {
    guard let info else { return }
    Unmanaged<DisplayChangeMonitor>.fromOpaque(info).takeUnretainedValue().note(flags: flags)
}

/// What the capture loop does between display events: nothing until the
/// monitor fires (no timer), then a few ScreenCaptureKit look-ups spread over
/// ~4 s, because ScreenCaptureKit can report the new layout a moment after
/// CoreGraphics does (and a display that appears later is only sized right
/// through ScreenCaptureKit, see CaptureTarget).
enum DisplayFollower {
    /// Delays before each look-up after an event: coalesces the burst of
    /// per-display reports, then re-checks while the window server settles.
    static let settleDelays: [Duration] = [.milliseconds(250), .milliseconds(750), .seconds(3)]

    /// Waits for a display change and returns the new target, or nil when the
    /// deadline passes first. `since` is the monitor generation read before
    /// the current target was looked up, so an event that lands while capture
    /// is starting is not lost. `query` is the ScreenCaptureKit look-up and
    /// runs only after an event. A new event during the settle look-ups
    /// restarts them.
    /// Runs in the caller's isolation, so the closures are not sent anywhere.
    static func waitForChange<T>(isolation: isolated (any Actor)? = #isolation,
                                 monitor: DisplayChangeMonitor,
                                 since generation: UInt64,
                                 deadline: Date?,
                                 settleDelays: [Duration] = DisplayFollower.settleDelays,
                                 sleep: (Duration) async -> Void = { try? await Task.sleep(for: $0) },
                                 query: () async -> T?,
                                 isChange: (T) -> Bool) async -> T? {
        var seen = generation
        let deadlineTask: Task<Void, Never>? = deadline.map { deadline in
            Task {
                let remaining = deadline.timeIntervalSinceNow
                if remaining > 0 { try? await Task.sleep(for: .seconds(remaining)) }
                if !Task.isCancelled { monitor.signal() }
            }
        }
        defer { deadlineTask?.cancel() }
        while true {
            if let deadline, Date() >= deadline { return nil }
            await monitor.wait(after: seen)
            if let deadline, Date() >= deadline { return nil }
            seen = monitor.currentGeneration
            var restart = false
            for delay in settleDelays {
                await sleep(delay)
                if let current = await query(), isChange(current) { return current }
                if monitor.currentGeneration != seen { restart = true; break }
            }
            if restart { continue }
        }
    }
}

/// `JerisLinkHost --self-test` part for the display follower. No real
/// display changes: the monitor is fed CoreGraphics flags directly.
enum DisplayFollowerSelfTest {
    final class Counter: @unchecked Sendable {
        private let lock = NSLock()
        private var n = 0
        func bump() { lock.lock(); n += 1; lock.unlock() }
        var value: Int { lock.lock(); defer { lock.unlock() }; return n }
    }

    static func run() async -> Int32 {
        var failures = 0
        func expect(_ ok: Bool, _ name: String) {
            print("\(ok ? "PASS" : "FAIL") \(name)")
            if !ok { failures += 1 }
        }
        let noSleep: (Duration) async -> Void = { _ in }

        // 1. No event: no ScreenCaptureKit look-up at all, however long it waits.
        do {
            let monitor = DisplayChangeMonitor()
            let queries = Counter()
            let start = Date()
            let result: Int? = await DisplayFollower.waitForChange(
                monitor: monitor, since: monitor.currentGeneration,
                deadline: Date().addingTimeInterval(1.2), sleep: noSleep,
                query: { queries.bump(); return 1 }, isChange: { _ in true })
            let waited = Date().timeIntervalSince(start)
            expect(result == nil && queries.value == 0, "display.idle_no_poll queries=\(queries.value)")
            expect(waited >= 1.1 && waited < 2.5, "display.deadline_wakes waited=\(String(format: "%.2f", waited))s")
        }

        // 2. A begin-only report does not wake; the end report does, and the
        //    change is picked up by the first look-up.
        do {
            let monitor = DisplayChangeMonitor()
            let queries = Counter()
            Task {
                try? await Task.sleep(for: .milliseconds(100))
                monitor.note(flags: .beginConfigurationFlag)
                try? await Task.sleep(for: .milliseconds(200))
                monitor.note(flags: [.setModeFlag])
            }
            let start = Date()
            let result: Int? = await DisplayFollower.waitForChange(
                monitor: monitor, since: monitor.currentGeneration,
                deadline: Date().addingTimeInterval(5), sleep: noSleep,
                query: { queries.bump(); return 7 }, isChange: { $0 == 7 })
            let waited = Date().timeIntervalSince(start)
            expect(result == 7 && queries.value == 1, "display.callback_triggers_lookup queries=\(queries.value)")
            expect(waited >= 0.25 && waited < 2, "display.begin_flag_ignored waited=\(String(format: "%.2f", waited))s")
            expect(monitor.reconfigurationCount == 1, "display.reconfiguration_count=\(monitor.reconfigurationCount)")
        }

        // 3. ScreenCaptureKit lags: unchanged on the first two look-ups,
        //    changed on the third (the settle delays cover it).
        do {
            let monitor = DisplayChangeMonitor()
            let queries = Counter()
            var slept: [Duration] = []
            // The event lands before the wait starts (while capture starts).
            let before = monitor.currentGeneration
            monitor.note(flags: [.addFlag])
            let result: Int? = await DisplayFollower.waitForChange(
                monitor: monitor, since: before, deadline: Date().addingTimeInterval(5),
                sleep: { slept.append($0) },
                query: { queries.bump(); return queries.value }, isChange: { $0 >= 3 })
            expect(result == 3 && slept == DisplayFollower.settleDelays,
                   "display.settle_rechecks queries=\(queries.value) sleeps=\(slept.count)")
        }

        // 4. Event but nothing changed for capture (e.g. another display's
        //    arrangement): three look-ups, then back to sleep with no more.
        do {
            let monitor = DisplayChangeMonitor()
            let queries = Counter()
            let before = monitor.currentGeneration
            monitor.note(flags: [.movedFlag])
            let result: Int? = await DisplayFollower.waitForChange(
                monitor: monitor, since: before, deadline: Date().addingTimeInterval(1.0), sleep: noSleep,
                query: { queries.bump(); return 0 }, isChange: { _ in false })
            expect(result == nil && queries.value == DisplayFollower.settleDelays.count,
                   "display.no_change_back_to_sleep queries=\(queries.value)")
        }

        // 5. Real registration with CoreGraphics succeeds (needs a window server).
        expect(DisplayChangeMonitor.shared.register(), "display.cg_callback_registered")

        return failures == 0 ? 0 : 1
    }
}
