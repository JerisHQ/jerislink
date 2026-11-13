import Foundation

/// MRM1 0x42 receiver report (viewer -> host every 250 ms). Only sent when the
/// host set video config ACK flag 0x40, so old viewers never send it and old
/// hosts never see it. Layout (29 bytes, trailing bytes ignored):
///   0 "MRM1"  4 version 1  5 type 0x42  6 seq u32 BE
///   10 flags (bit0 slope valid)  11 window_ms u16
///   13 expected u32  17 lost_raw u32  21 lost_after_nack u32
///   25 slope i16 (0.1 ms per 250 ms)  27 rtt_ms u16
struct ReceiverReport: Equatable {
    static let minBytes = 29
    var slopeValid = false
    var windowMs: UInt16 = 0
    var expected: UInt32 = 0
    var lostRaw: UInt32 = 0
    var lostAfterNack: UInt32 = 0
    var slope01Ms: Int16 = 0
    var rttMs: UInt16 = 0

    /// Parses the bytes after the 10-byte MRM1 header check. nil when short or
    /// inconsistent: window_ms 0, or not lost_after_nack <= lost_raw <= expected
    /// (the viewer's counters always satisfy that).
    static func parse(_ b: [UInt8]) -> ReceiverReport? {
        guard b.count >= minBytes else { return nil }
        func u16(_ i: Int) -> UInt16 { UInt16(b[i]) << 8 | UInt16(b[i + 1]) }
        func u32(_ i: Int) -> UInt32 { UInt32(u16(i)) << 16 | UInt32(u16(i + 2)) }
        var r = ReceiverReport()
        r.slopeValid = b[10] & 0x01 != 0
        r.windowMs = u16(11)
        r.expected = u32(13)
        r.lostRaw = u32(17)
        r.lostAfterNack = u32(21)
        r.slope01Ms = Int16(bitPattern: u16(25))
        r.rttMs = u16(27)
        guard r.windowMs > 0, r.lostAfterNack <= r.lostRaw, r.lostRaw <= r.expected else { return nil }
        return r
    }
}

struct AbrInput: Equatable {
    var nowMs: UInt64 = 0
    var expected: UInt32 = 0
    var lostRaw: UInt32 = 0
    var lostAfterNack: UInt32 = 0
    var slopeValid = false
    var slope01Ms = 0
    var overBudgetDelta: UInt64 = 0  // host nack_over_budget since the last report
    var queueMax = 0                 // host send queue max since the last report
}

struct AbrChange: Equatable {
    var fromKbps: Int
    var toKbps: Int
    var reason: String
}

/// ABR v1 (design 2.2, D4 A, D5 A: bitrate only). Pure and deterministic;
/// windows-client/abr.hpp has the same rules in C++ for the simulation and
/// both test files pin the same golden trace.
///   congested: loss after NACK > 2%, raw loss > 5%, slope > +4 ms twice in
///              a row, or send queue >= 3 twice in a row -> x0.80
///   heavy:     loss after NACK > 10%, or NACK over budget twice in a row -> x0.50
///   (at most one step down per 500 ms, never below the floor)
///   clear:     loss after NACK < 0.5%, slope <= 1 ms, no over budget; after
///              3 s clear, +5% of the ceiling per 1 s up to the ceiling.
/// Loss is judged on at least 30 expected packets: smaller reports are summed
/// until they reach 30. Until then loss is unknown: such a report can still
/// step down for delay, queue or NACK budget, but never counts as clear (the
/// clear timer is kept as it is and there is no step up).
struct AbrController {
    let ceilingKbps: Int
    private(set) var currentKbps: Int
    private(set) var downs: UInt64 = 0
    private(set) var ups: UInt64 = 0
    private var slopeStreak = 0
    private var budgetStreak = 0
    private var queueStreak = 0
    private var lastDownMs: UInt64?
    private var lastUpMs: UInt64?
    private var clearSinceMs: UInt64?
    private var accExpected: UInt64 = 0
    private var accRaw: UInt64 = 0
    private var accAfter: UInt64 = 0

    init(ceilingKbps: Int) {
        self.ceilingKbps = max(1, ceilingKbps)
        self.currentKbps = self.ceilingKbps
    }

    var floorKbps: Int { min(6000, ceilingKbps) }

    mutating func reset() {
        currentKbps = ceilingKbps
        slopeStreak = 0; budgetStreak = 0; queueStreak = 0
        lastDownMs = nil; lastUpMs = nil; clearSinceMs = nil
        accExpected = 0; accRaw = 0; accAfter = 0
    }

    mutating func onReport(_ i: AbrInput) -> AbrChange? {
        accExpected &+= UInt64(i.expected)
        accRaw &+= UInt64(i.lostRaw)
        accAfter &+= UInt64(i.lostAfterNack)
        let lossKnown = accExpected >= 30
        let afterBp = lossKnown ? accAfter * 10000 / accExpected : 0
        let rawBp = lossKnown ? accRaw * 10000 / accExpected : 0
        if lossKnown { accExpected = 0; accRaw = 0; accAfter = 0 }
        slopeStreak = (i.slopeValid && i.slope01Ms > 40) ? slopeStreak + 1 : 0
        budgetStreak = i.overBudgetDelta > 0 ? budgetStreak + 1 : 0
        // One IDR alone queues about 3 frames at the pacer (250 packets at
        // 72 Mbps is ~40 ms), so the queue only counts when it stays.
        queueStreak = i.queueMax >= 3 ? queueStreak + 1 : 0

        var reason: String?
        var heavy = false
        if afterBp > 1000 { heavy = true; reason = "heavy_loss" }
        else if budgetStreak >= 2 { heavy = true; reason = "nack_budget" }
        else if afterBp > 200 { reason = "loss" }
        else if rawBp > 500 { reason = "raw_loss" }
        else if slopeStreak >= 2 { reason = "delay" }
        else if queueStreak >= 2 { reason = "send_queue" }

        if let reason {
            clearSinceMs = nil
            if let last = lastDownMs, i.nowMs &- last < 500 { return nil }
            let next = max(floorKbps, heavy ? currentKbps / 2 : currentKbps * 4 / 5)
            guard next < currentKbps else { return nil }
            lastDownMs = i.nowMs
            downs &+= 1
            defer { currentKbps = next }
            return AbrChange(fromKbps: currentKbps, toKbps: next, reason: reason)
        }
        let clear = afterBp < 50 && !(i.slopeValid && i.slope01Ms > 10) && i.overBudgetDelta == 0
        guard clear else { clearSinceMs = nil; return nil }
        guard lossKnown else { return nil }  // loss unknown: not clear, timer kept
        if clearSinceMs == nil { clearSinceMs = i.nowMs }
        guard currentKbps < ceilingKbps, let since = clearSinceMs, i.nowMs &- since >= 3000 else { return nil }
        if let last = lastUpMs, i.nowMs &- last < 1000 { return nil }
        let next = min(ceilingKbps, currentKbps + max(1, ceilingKbps / 20))
        lastUpMs = i.nowMs
        ups &+= 1
        defer { currentKbps = next }
        return AbrChange(fromKbps: currentKbps, toKbps: next, reason: "clear")
    }
}

/// Send-cadence slope: the viewer's ArrivalSlope (windows-client/abr.hpp)
/// run over the times the encoder hands frames to the sender. Same rules:
/// consecutive frame ids, gaps outside [0.25 T, 1.75 T] left out, mean excess
/// scaled to 250 ms, under 6 samples = unknown.
struct ArrivalSlope {
    struct Window: Equatable { var valid = false; var slopeMs = 0.0; var samples = 0 }
    static let reportIntervalMs = 250.0
    let t: Double
    private var have = false
    private var last: UInt64 = 0
    private var at = 0.0
    private var sum = 0.0
    private var n = 0

    init(nominalFrameMs: Double) { t = nominalFrameMs > 0 ? nominalFrameMs : 1000.0 / 60 }

    mutating func onFrame(_ fid: UInt64, nowMs: Double) {
        if have && fid <= last {
            if fid &+ 2 < last && last - fid > 120 { last = fid; at = nowMs }  // restart
            return
        }
        if have && fid == last &+ 1 {
            let gap = nowMs - at
            if gap >= 0.25 * t && gap <= 1.75 * t { sum += gap - t; n += 1 }
        }
        have = true
        last = fid
        at = nowMs
    }

    mutating func take() -> Window {
        var w = Window()
        w.samples = n
        w.valid = n >= 6
        if w.valid { w.slopeMs = sum / Double(n) * (Self.reportIntervalMs / t) }
        sum = 0
        n = 0
        return w
    }
}

/// Same rounding as abrSlopeTo01Ms in abr.hpp.
func abrSlopeTo01Ms(_ ms: Double) -> Int {
    let v = min(max(ms * 10, -32767), 32767)
    return Int(v < 0 ? v - 0.5 : v + 0.5)
}

/// Host delay signal (abr.hpp SlopeFilter, same rules and test vectors).
/// 1. Compensation: the viewer measures gaps against 1000/fps, so a host
///    that encodes slower (~50 fps at a 60 fps setting) reads as delay
///    growing 15 x (gap - T) per 250 ms with no queue at all. The host's own
///    send-cadence slope is subtracted; either side unknown = unknown.
/// 2. Jitter gate: over a relay (DERP) the compensated slope moves ~8 ms from
///    one report to the next, twice the 4 ms delay threshold. Noise is the
///    median |change| between consecutive compensated slopes over the last
///    16 reports; a slope within 2x the noise is reported as unknown (no
///    delay step-down, no blocked step-up). A growing queue changes little
///    report to report and stays visible; with no noise nothing is gated.
struct SlopeFilter {
    struct Estimate: Equatable { var valid = false; var slope01Ms = 0 }
    static let history = 16
    static let minDiffs = 4
    private var diffs: [Int] = []
    private var haveLast = false
    private var last = 0

    static func compensate(viewerValid: Bool, viewer01Ms: Int, host: ArrivalSlope.Window) -> Estimate {
        guard viewerValid, host.valid else { return Estimate() }
        return Estimate(valid: true, slope01Ms: viewer01Ms - abrSlopeTo01Ms(host.slopeMs))
    }

    mutating func onReport(viewerValid: Bool, viewer01Ms: Int, host: ArrivalSlope.Window) -> Estimate {
        var e = Self.compensate(viewerValid: viewerValid, viewer01Ms: viewer01Ms, host: host)
        guard e.valid else { haveLast = false; return e }
        if haveLast {
            diffs.append(abs(e.slope01Ms - last))
            if diffs.count > Self.history { diffs.removeFirst() }
        }
        haveLast = true
        last = e.slope01Ms
        let n = noise01Ms
        if n > 0 && abs(e.slope01Ms) <= 2 * n { e.valid = false }
        return e
    }

    /// Median |change| (0.1 ms), 0 until 4 changes. Same element as nth_element(size / 2).
    var noise01Ms: Int {
        guard diffs.count >= Self.minDiffs else { return 0 }
        return diffs.sorted()[diffs.count / 2]
    }

    mutating func reset() { diffs.removeAll(); haveLast = false; last = 0 }
}

/// Host-side ABR state for one video service run (any thread). Reports come
/// in on the mouse UDP queue; the encoder applies a new bitrate before its
/// next frame, the sender updates the NACK budget and (auto pace) the pace.
final class AbrHost: @unchecked Sendable {
    static let idrCapFrames = 3  // DataRateLimits: one frame at most 3x the average

    let enabled: Bool
    private let lock = NSLock()
    private var controller: AbrController
    private var reports: UInt64 = 0
    private var lastOverBudget: UInt64 = 0
    private let start = DispatchTime.now().uptimeNanoseconds
    private var lastSlope01Ms = 0
    private var lastLossAfterBp: UInt64 = 0
    private var slopeFilter = SlopeFilter()
    private var lastHostSlope01Ms: Int?
    private var lastEffective: SlopeFilter.Estimate?

    init(enabled: Bool, ceilingMbps: Int) {
        self.enabled = enabled
        self.controller = AbrController(ceilingKbps: max(1, ceilingMbps) * 1000)
    }

    var currentKbps: Int { lock.lock(); defer { lock.unlock() }; return controller.currentKbps }

    /// A new viewer session: start again at the ceiling. Returns the change
    /// when the bitrate was below it.
    func reset() -> AbrChange? {
        lock.lock(); defer { lock.unlock() }
        let from = controller.currentKbps
        controller.reset()
        slopeFilter.reset()
        return from == controller.currentKbps ? nil : AbrChange(fromKbps: from, toKbps: controller.currentKbps, reason: "new_session")
    }

    /// One 0x42 report plus the sender's window counters. MouseMoveUDPServer
    /// already drops old or duplicate MRM1 sequence numbers. sendSlope: the
    /// sender's send-cadence window since the last report; nil uses the
    /// viewer slope as is (ABR v1).
    func onReport(_ r: ReceiverReport, overBudgetTotal: UInt64, queueMax: Int,
                  sendSlope: ArrivalSlope.Window? = nil,
                  nowNanos: UInt64 = DispatchTime.now().uptimeNanoseconds) -> AbrChange? {
        lock.lock(); defer { lock.unlock() }
        guard enabled else { return nil }
        reports &+= 1
        var i = AbrInput()
        i.nowMs = (nowNanos &- start) / 1_000_000
        i.expected = r.expected
        i.lostRaw = r.lostRaw
        i.lostAfterNack = r.lostAfterNack
        i.slopeValid = r.slopeValid
        i.slope01Ms = Int(r.slope01Ms)
        if let sendSlope {
            let e = slopeFilter.onReport(viewerValid: r.slopeValid, viewer01Ms: Int(r.slope01Ms), host: sendSlope)
            i.slopeValid = e.valid
            i.slope01Ms = e.slope01Ms
            lastHostSlope01Ms = sendSlope.valid ? abrSlopeTo01Ms(sendSlope.slopeMs) : nil
            lastEffective = e
        }
        i.overBudgetDelta = overBudgetTotal &- lastOverBudget
        lastOverBudget = overBudgetTotal
        i.queueMax = queueMax
        lastSlope01Ms = r.slopeValid ? Int(r.slope01Ms) : 0
        lastLossAfterBp = r.expected >= 30 ? UInt64(r.lostAfterNack) * 10000 / UInt64(r.expected) : 0
        return controller.onReport(i)
    }

    func statsFields() -> String {
        lock.lock(); defer { lock.unlock() }
        guard enabled else { return "abr=off" }
        return "abr=on abr_bitrate=\(controller.currentKbps)kbps abr_down=\(controller.downs) abr_up=\(controller.ups) "
            + "abr_reports=\(reports) abr_slope=\(String(format: "%.1f", Double(lastSlope01Ms) / 10))ms "
            + "abr_loss_after_nack=\(String(format: "%.2f", Double(lastLossAfterBp) / 100))%"
            + slopeFields()
    }

    /// Host slope, effective slope ("na" = unknown or gated) and jitter noise.
    private func slopeFields() -> String {
        guard let e = lastEffective else { return "" }
        func ms(_ v: Int?) -> String { v.map { String(format: "%.1fms", Double($0) / 10) } ?? "na" }
        return " abr_slope_host=\(ms(lastHostSlope01Ms)) abr_slope_eff=\(ms(e.valid ? e.slope01Ms : nil))"
            + " abr_slope_noise=\(ms(slopeFilter.noise01Ms))"
    }
}
