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
/// sits in a Windows modal loop. Only a session that sent one of these can
/// time out: a viewer that never repeats anything (host NACK, ABR and audio
/// all off) keeps the stream running once it has been heard, as before.
final class ViewerPresence: @unchecked Sendable {
    static let idleSeconds: Double = 15

    private let lock = NSLock()
    private let idleNs: UInt64
    private var lastHeardNs: UInt64 = 0  // 0: nothing heard yet
    private var keepAliveSeen = false
    private var heardCount: UInt64 = 0

    init(idleSeconds: Double = ViewerPresence.idleSeconds) {
        idleNs = UInt64(idleSeconds * 1_000_000_000)
    }

    static func nowNs() -> UInt64 { DispatchTime.now().uptimeNanoseconds }

    /// MRM1 types the viewer repeats on a timer for as long as it runs.
    static func isKeepAlive(_ type: UInt8) -> Bool {
        type == 0x42 || type == 0x43 || type == 0x45
    }

    /// One valid MRM1 datagram from the allowed client. `newSession`: a new
    /// source port (a viewer started or restarted), which has to show again
    /// that it repeats keep-alives before it can time out.
    func heard(type: UInt8, newSession: Bool, nowNs: UInt64 = ViewerPresence.nowNs()) {
        lock.lock(); defer { lock.unlock() }
        if newSession { keepAliveSeen = false }
        if Self.isKeepAlive(type) { keepAliveSeen = true }
        lastHeardNs = max(nowNs, 1)
        heardCount &+= 1
    }

    /// A viewer was heard and, if it repeats keep-alives, recently.
    func isActive(nowNs: UInt64 = ViewerPresence.nowNs()) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard lastHeardNs != 0 else { return false }
        if !keepAliveSeen { return true }
        return nowNs < lastHeardNs || nowNs - lastHeardNs < idleNs
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
}

/// `JerisLinkHost --self-test` part for the viewer presence gate. Fixed
/// clock values; no sockets.
enum ViewerPresenceSelfTest {
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
            // A viewer that only sends keyframe requests or mouse never
            // times out (old behaviour for viewers without keep-alives).
            let p = ViewerPresence(idleSeconds: 15)
            p.heard(type: 0x40, newSession: true, nowNs: 100 * s)
            expect(p.isActive(nowNs: 101 * s), "presence.first_datagram_active")
            expect(p.isActive(nowNs: 10_000 * s), "presence.no_keepalive_never_idle")
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
            // A new viewer (new source port) after a pinging one has to ping
            // again before it can time out.
            let p = ViewerPresence(idleSeconds: 15)
            p.heard(type: 0x43, newSession: true, nowNs: 100 * s)
            p.heard(type: 0x40, newSession: true, nowNs: 101 * s)
            expect(p.isActive(nowNs: 500 * s), "presence.new_session_rearms")
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
        print("viewer presence self-test: \(failures == 0 ? "ok" : "\(failures) failed")")
        return failures == 0 ? 0 : 1
    }
}
