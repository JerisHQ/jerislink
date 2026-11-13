import Foundation

/// `JerisLinkHost --self-test` part for ABR v1: the controller golden trace
/// (identical to kAbrGolden in windows-client/video_receiver_test.cpp), the
/// 0x42 receiver report parser, AbrHost, the NACK budget following the
/// bitrate, and the persisted `abr` setting. Pure checks, no sockets.
enum AbrSelfTest {
    static func run() -> Int32 {
        var failures = 0
        func expect(_ ok: Bool, _ name: String) {
            print("\(ok ? "PASS" : "FAIL") \(name)")
            if !ok { failures += 1 }
        }

        // Golden trace: (nowMs, expected, raw, afterNack, slopeValid, slope01Ms, overBudgetDelta, queueMax[, flat]) -> kbps.
        let golden: [(AbrInput, Int)] = [
            (input(250, 400, 0, 0, true, 0, 0, 0), 18000),
            (input(500, 400, 12, 12, true, 0, 0, 0), 14400),
            (input(750, 400, 12, 12, true, 0, 0, 0), 14400),
            (input(1000, 400, 50, 50, true, 0, 0, 0), 7200),
            (input(1250, 400, 0, 0, true, 0, 0, 3), 7200),
            (input(1500, 400, 0, 0, true, 0, 0, 3), 6000),
            (input(1750, 400, 0, 0, true, 50, 0, 0), 6000),
            (input(2000, 400, 0, 0, true, 50, 0, 0), 6000),
            (input(2250, 400, 0, 0, true, 0, 0, 0), 6000),
            (input(5250, 400, 0, 0, true, 0, 0, 0), 6900),
            (input(5750, 400, 0, 0, true, 0, 0, 0), 6900),
            (input(6250, 400, 0, 0, true, 0, 0, 0), 7800),
            (input(6500, 400, 0, 0, true, 0, 1, 0), 7800),
            (input(6750, 400, 0, 0, true, 0, 1, 0), 6000),
            (input(7000, 400, 24, 0, true, 0, 0, 0), 6000),
            (input(7250, 20, 10, 10, false, 0, 0, 0, flat: true), 6000),
            (input(10250, 400, 0, 0, false, 0, 0, 0, flat: true), 6000),
            (input(10500, 400, 0, 0, false, 0, 0, 0, flat: true), 6000),
            (input(13500, 400, 0, 0, false, 0, 0, 0, flat: true), 6900),
            (input(13750, 400, 0, 0, true, 50, 0, 0), 6900),
            (input(14000, 400, 0, 0, false, 0, 0, 0), 6900),
            (input(17000, 400, 0, 0, false, 0, 0, 0), 6900),
            (input(17250, 400, 0, 0, false, 0, 0, 0, flat: true), 6900),
            (input(20250, 400, 0, 0, false, 0, 0, 0, flat: true), 7800),
        ]
        var c = AbrController(ceilingKbps: 18000)
        expect(c.currentKbps == 18000 && c.floorKbps == 6000, "abr: starts at the ceiling, floor 6 Mbps")
        var row = 0
        var reasons: [String] = []
        for (i, want) in golden {
            row += 1
            let before = c.currentKbps
            let change = c.onReport(i)
            let okChange = change == nil ? before == want
                : (change!.fromKbps == before && change!.toKbps == want && !change!.reason.isEmpty)
            if let change { reasons.append(change.reason) }
            expect(c.currentKbps == want && okChange, "abr golden row \(row): \(want) kbps")
        }
        expect(c.downs == 4 && c.ups == 4, "abr golden: 4 down, 4 up")
        expect(reasons == ["loss", "heavy_loss", "send_queue", "clear", "clear", "nack_budget", "clear", "clear"],
               "abr golden: reasons")
        c.reset()
        expect(c.currentKbps == 18000, "abr: reset returns to the ceiling")
        var low = AbrController(ceilingKbps: 4000)
        expect(low.onReport(input(500, 400, 100, 100, true, 0, 0, 0)) == nil && low.currentKbps == 4000,
               "abr: ceiling below 6 Mbps never steps down")

        // Loss unknown (under 30 expected in total) is never "clear".
        func toFloor(_ c: inout AbrController) {
            _ = c.onReport(input(250, 400, 100, 100, true, 0, 0, 0))
            _ = c.onReport(input(750, 400, 100, 100, true, 0, 0, 0))
        }
        var lowLoss = AbrController(ceilingKbps: 18000)
        toFloor(&lowLoss)
        var held = lowLoss.currentKbps == 6000
        for t in stride(from: UInt64(1000), through: 11000, by: 250) {
            _ = lowLoss.onReport(input(t, 20, 10, 10, false, 0, 0, 0))
            held = held && lowLoss.currentKbps == 6000
        }
        expect(held && lowLoss.ups == 0, "abr: low traffic with 50% loss never steps up")
        var lowHeavy = AbrController(ceilingKbps: 18000)
        let first = lowHeavy.onReport(input(250, 20, 10, 10, false, 0, 0, 0))
        let second = lowHeavy.onReport(input(500, 20, 10, 10, false, 0, 0, 0))
        expect(first == nil && second == AbrChange(fromKbps: 18000, toKbps: 9000, reason: "heavy_loss"),
               "abr: small reports are summed to 30 expected, then judged")
        var idle = AbrController(ceilingKbps: 18000)
        toFloor(&idle)
        var idleHeld = idle.currentKbps == 6000
        for t in stride(from: UInt64(1000), through: 11000, by: 250) {
            _ = idle.onReport(input(t, 0, 0, 0, false, 0, 0, 0))
            idleHeld = idleHeld && idle.currentKbps == 6000
        }
        expect(idleHeld && idle.ups == 0, "abr: zero-sample reports never step up")
        let c1 = idle.onReport(input(12000, 400, 0, 0, true, 0, 0, 0))
        let c2 = idle.onReport(input(13500, 0, 0, 0, false, 0, 0, 0))
        let c3 = idle.onReport(input(15000, 400, 0, 0, true, 0, 0, 0))
        let c4 = idle.onReport(input(16500, 400, 0, 0, true, 0, 0, 0))
        expect(c1 == nil && c2 == nil && c3 == nil && c4?.toKbps == 6900,
               "abr: zero-sample reports keep the clear period without advancing it")

        // Review P1: unknown slope is not clear (testAbrUnknownSlopeNeverClear).
        var held2 = AbrController(ceilingKbps: 18000)
        toFloor(&held2)
        var upAt: UInt64 = 0
        for t in stride(from: UInt64(1000), through: 9000, by: 250) where upAt == 0 {
            let unknown = t > 3000 && t <= 8000
            if held2.onReport(input(t, 400, 0, 0, false, 0, 0, 0, flat: !unknown)) != nil { upAt = t }
        }
        expect(upAt == 9000 && held2.currentKbps == 6900, "abr: unknown slope holds the clear time, flat counts")

        // 0x42 parse: same bytes as testReceiverReportEncoding in C++.
        let bytes: [UInt8] = [0x4d, 0x52, 0x4d, 0x31, 1, 0x42, 0x0A, 0x0B, 0x0C, 0x0D, 0x01, 0x00, 0xFA,
                              0x01, 0x02, 0x03, 0x04, 0, 0, 0, 7, 0, 0, 0, 2, 0xFF, 0x85, 0x00, 61]
        var want = ReceiverReport()
        want.slopeValid = true; want.windowMs = 250; want.expected = 0x01020304
        want.lostRaw = 7; want.lostAfterNack = 2; want.slope01Ms = -123; want.rttMs = 61
        expect(ReceiverReport.parse(bytes) == want, "report: parses the C++ encoding")
        expect(ReceiverReport.parse(bytes + [9, 9]) == want, "report: trailing bytes ignored")
        expect(ReceiverReport.parse(Array(bytes.dropLast())) == nil, "report: short packet rejected")
        func report(_ window: UInt16, _ expected: UInt32, _ raw: UInt32, _ after: UInt32) -> [UInt8] {
            var b: [UInt8] = [0x4d, 0x52, 0x4d, 0x31, 1, 0x42, 0, 0, 0, 1, 0]
            b += [UInt8(window >> 8), UInt8(window & 0xff)]
            for v in [expected, raw, after] { b += [UInt8(v >> 24), UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)] }
            b += [0, 0, 0, 0]
            return b
        }
        expect(ReceiverReport.parse(report(250, 30, 3, 3)) != nil && ReceiverReport.parse(report(250, 30, 30, 0)) != nil
               && ReceiverReport.parse(report(250, 0, 0, 0)) != nil, "report: consistent counts accepted")
        expect(ReceiverReport.parse(report(0, 30, 0, 0)) == nil, "report: window 0 rejected")
        expect(ReceiverReport.parse(report(0, 30, 0, UInt32.max)) == nil
               && ReceiverReport.parse(report(250, 30, 0, UInt32.max)) == nil
               && ReceiverReport.parse(report(250, 30, 2, 3)) == nil, "report: after > raw rejected")
        expect(ReceiverReport.parse(report(250, 30, 31, 0)) == nil, "report: raw > expected rejected")

        // AbrHost: off ignores reports, on counts over-budget as a delta.
        let off = AbrHost(enabled: false, ceilingMbps: 18)
        var r = ReceiverReport()
        r.expected = 400; r.lostAfterNack = 100
        expect(off.onReport(r, overBudgetTotal: 0, queueMax: 0, nowNanos: 1) == nil && off.statsFields() == "abr=off",
               "abr host: off does nothing")
        let host = AbrHost(enabled: true, ceilingMbps: 18)
        let t0 = DispatchTime.now().uptimeNanoseconds
        let down = host.onReport(r, overBudgetTotal: 5, queueMax: 0, nowNanos: t0 + 1_000_000_000)
        expect(down == AbrChange(fromKbps: 18000, toKbps: 9000, reason: "heavy_loss"), "abr host: 25% loss -> x0.5")
        var clean = ReceiverReport()
        clean.expected = 400
        // Total stays 5: delta 0, so no budget streak.
        expect(host.onReport(clean, overBudgetTotal: 5, queueMax: 0, nowNanos: t0 + 1_250_000_000) == nil,
               "abr host: over-budget total is turned into a delta")
        expect(host.statsFields().hasPrefix("abr=on abr_bitrate=9000kbps abr_down=1 abr_up=0 abr_reports=2"),
               "abr host: stats fields")
        expect(host.reset() == AbrChange(fromKbps: 9000, toKbps: 18000, reason: "new_session") && host.reset() == nil,
               "abr host: new session resets to the ceiling once")

        // Send-cadence compensation (testSlopeCompensation in C++): a 51 fps
        // host against 60 fps reads as +44 ms per 250 ms at the viewer; the
        // host's own slope cancels it and a real queue stays.
        let T = 1000.0 / 60, gap = 1000.0 / 51
        var hs = ArrivalSlope(nominalFrameMs: T), vs = ArrivalSlope(nominalFrameMs: T)
        for f in 1...14 { hs.onFrame(UInt64(f), nowMs: Double(f) * gap); vs.onFrame(UInt64(f), nowMs: 30 + Double(f) * gap) }
        let hw = hs.take(), vw = vs.take()
        let e1 = SlopeFilter.compensate(viewerValid: true, viewer01Ms: abrSlopeTo01Ms(vw.slopeMs), host: hw)
        expect(vw.valid && vw.slopeMs > 40 && hw.valid && e1.valid && abs(e1.slope01Ms) <= 1,
               "slope: encode-bound cadence cancelled")
        for f in 1...14 {
            hs.onFrame(UInt64(100 + f), nowMs: 1000 + Double(f) * gap)
            vs.onFrame(UInt64(100 + f), nowMs: 1030 + Double(f) * (gap + 1))
        }
        let e2 = SlopeFilter.compensate(viewerValid: true, viewer01Ms: abrSlopeTo01Ms(vs.take().slopeMs), host: hs.take())
        expect(e2.valid && abs(e2.slope01Ms - 150) <= 1, "slope: queue growth survives compensation")
        var slow = ArrivalSlope(nominalFrameMs: T)
        for f in 1...8 { slow.onFrame(UInt64(f), nowMs: Double(f) * 33.3) }
        expect(!SlopeFilter.compensate(viewerValid: true, viewer01Ms: 400, host: slow.take()).valid,
               "slope: host window unknown -> unknown")

        // Jitter gate (testSlopeFilter in C++, same vectors).
        let flat = ArrivalSlope.Window(valid: true, slopeMs: 0, samples: 14)
        var f = SlopeFilter()
        var firstFour = true, gated = true
        for i in 0..<12 {
            let e = f.onReport(viewerValid: true, viewer01Ms: i % 2 == 1 ? -80 : 80, host: flat)
            if i < 4 { firstFour = firstFour && e.valid } else { gated = gated && !e.valid && e.flat }
        }
        expect(firstFour && gated && f.noise01Ms == 160, "slope gate: +-8 ms relay jitter -> flat")
        var firstValid = -1, lastOk = false
        for i in 0..<16 {
            let e = f.onReport(viewerValid: true, viewer01Ms: 150, host: flat)
            if e.valid && firstValid < 0 { firstValid = i }
            if i == 15 { lastOk = e.valid && e.slope01Ms == 150 }
        }
        expect(lastOk && firstValid >= 0 && firstValid <= 9, "slope gate: steady +15 ms queue growth passes")
        var direct = SlopeFilter(), directOk = true
        for i in 0..<10 {
            let e = direct.onReport(viewerValid: true, viewer01Ms: i < 5 ? 0 : 50, host: flat)
            directOk = directOk && e == SlopeFilter.Estimate(valid: true, slope01Ms: i < 5 ? 0 : 50)
        }
        expect(directOk, "slope gate: no noise, nothing gated")
        var g = SlopeFilter()
        let g1 = g.onReport(viewerValid: true, viewer01Ms: 30, host: flat)
        let g2 = g.onReport(viewerValid: false, viewer01Ms: 0, host: flat)
        let g3 = g.onReport(viewerValid: true, viewer01Ms: 30, host: ArrivalSlope.Window())
        let g4 = g.onReport(viewerValid: true, viewer01Ms: 500, host: flat)
        expect(g1.valid && !g2.valid && !g2.flat && !g3.valid && !g3.flat && g4.valid && g.noise01Ms == 0,
               "slope gate: unknown side -> unknown, no change measured across it")

        // Review P2 counter-example B: 0, 0, +10, +10, +20 ms. Noise 10 ms gates
        // the +20 ms, but 40 ms was added over 5 reports: valid, trend 8 ms.
        var b = SlopeFilter()
        var eb = SlopeFilter.Estimate()
        for v in [0, 0, 100, 100, 200] { eb = b.onReport(viewerValid: true, viewer01Ms: v, host: flat) }
        expect(b.noise01Ms == 100 && b.drift01Ms == 400 && eb == SlopeFilter.Estimate(valid: true, slope01Ms: 80),
               "slope drift: 4 changes, +20 ms at the end is not hidden")
        // Counter-example A: mean +10.1 ms per 250 ms with growing jitter on
        // top. The old gate hid all 80 reports; now the trend steps down.
        var a = SlopeFilter()
        var ac = AbrController(ceilingKbps: 18000)
        var aOk = true, aValid = 0, aDelay = 0, aSum = 0
        for k in 0..<80 {
            let v = 101 + (k % 2 == 1 ? -1 : 1) * (120 + k)
            aSum += v
            let e = a.onReport(viewerValid: true, viewer01Ms: v, host: flat)
            if k >= 16 { aOk = aOk && e.valid && e.slope01Ms > 40 }
            if e.valid { aValid += 1 }
            if ac.onReport(input(UInt64(250 * (k + 1)), 400, 0, 0, e.valid, e.slope01Ms, 0, 0, flat: e.flat))?.reason == "delay" {
                aDelay += 1
            }
        }
        expect(aSum >= 8000 && aOk && aValid >= 64 && aDelay >= 2 && ac.currentKbps < 18000,
               "slope drift: queue growth under rising jitter steps down")

        // Review P1 through AbrHost: host cadence unknown the whole time, the
        // viewer reads +25 ms per 250 ms. No step up from the floor (it was
        // 6 -> 18 Mbps with 14 steps when unknown counted as clear).
        let p1 = AbrHost(enabled: true, ceilingMbps: 18)
        var lossy = ReceiverReport()
        lossy.expected = 400; lossy.lostRaw = 100; lossy.lostAfterNack = 100
        _ = p1.onReport(lossy, overBudgetTotal: 0, queueMax: 0, sendSlope: ArrivalSlope.Window(), nowNanos: t0 + 250_000_000)
        _ = p1.onReport(lossy, overBudgetTotal: 0, queueMax: 0, sendSlope: ArrivalSlope.Window(), nowNanos: t0 + 750_000_000)
        var rising = ReceiverReport()
        rising.expected = 400; rising.slopeValid = true; rising.slope01Ms = 250
        var p1Up = false
        for k in 4...124 {
            p1Up = p1Up || p1.onReport(rising, overBudgetTotal: 0, queueMax: 0, sendSlope: ArrivalSlope.Window(),
                                       nowNanos: t0 + UInt64(k) * 250_000_000) != nil
        }
        expect(p1.currentKbps == 6000 && !p1Up && p1.statsFields().contains("abr_slope_eff=na"),
               "abr host: unknown host slope never steps up (review P1)")

        // Review P3: capture restart resets the jitter history. After +-8 ms
        // jitter the next +8 ms is flat; after captureRestarted it is measured.
        let p3 = AbrHost(enabled: true, ceilingMbps: 18)
        var jr = ReceiverReport()
        jr.expected = 400; jr.slopeValid = true
        for k in 1...12 {
            jr.slope01Ms = k % 2 == 1 ? 80 : -80
            _ = p3.onReport(jr, overBudgetTotal: 0, queueMax: 0, sendSlope: flat, nowNanos: t0 + UInt64(k) * 250_000_000)
        }
        jr.slope01Ms = 80
        _ = p3.onReport(jr, overBudgetTotal: 0, queueMax: 0, sendSlope: flat, nowNanos: t0 + 13 * 250_000_000)
        let beforeRestart = p3.statsFields().contains("abr_slope_eff=flat")
        p3.captureRestarted()
        _ = p3.onReport(jr, overBudgetTotal: 0, queueMax: 0, sendSlope: flat, nowNanos: t0 + 14 * 250_000_000)
        expect(beforeRestart && p3.statsFields().contains("abr_slope_eff=8.0ms abr_slope_noise=0.0ms"),
               "abr host: capture restart clears the jitter history (review P3)")

        // AbrHost with the send slope: the 51 fps cadence bias never steps down.
        let comp = AbrHost(enabled: true, ceilingMbps: 18)
        var biased = ReceiverReport()
        biased.expected = 400; biased.slopeValid = true; biased.slope01Ms = Int16(abrSlopeTo01Ms(vw.slopeMs))
        let hostWindow = ArrivalSlope.Window(valid: true, slopeMs: hw.slopeMs, samples: 14)
        var compDown = false
        for k in 1...8 {
            compDown = compDown || comp.onReport(biased, overBudgetTotal: 0, queueMax: 0, sendSlope: hostWindow,
                                                 nowNanos: t0 + UInt64(k) * 250_000_000) != nil
        }
        let v1 = AbrHost(enabled: true, ceilingMbps: 18)
        var v1Down: AbrChange?
        for k in 1...2 { v1Down = v1.onReport(biased, overBudgetTotal: 0, queueMax: 0, nowNanos: t0 + UInt64(k) * 250_000_000) }
        expect(!compDown && comp.currentKbps == 18000 && v1Down?.reason == "delay",
               "abr host: send slope cancels the cadence bias (v1 steps down on it)")
        expect(comp.statsFields().contains(" abr_slope_host=") && comp.statsFields().contains(" abr_slope_eff=")
               && !v1.statsFields().contains("abr_slope_host"), "abr host: slope stats fields")

        // NACK budget follows the bitrate: 20% of bitrate per 100 ms.
        var budget = RetransmitBudget(videoBitrateMbps: 20)
        budget.setVideoBitrate(kbps: 8000)
        expect(budget.bytesPerWindow == 20_000, "budget: 8 Mbps -> 20,000 bytes per 100 ms")
        budget.setVideoBitrate(kbps: 20000)
        expect(budget.bytesPerWindow == 50_000, "budget: back to 20 Mbps -> 50,000 bytes")

        // Persisted setting: missing = on.
        expect(PersistedVideoSettings(dictionary: [:]).abr, "settings: abr defaults on")
        expect(!PersistedVideoSettings(dictionary: ["abr": false]).abr, "settings: abr false turns it off")

        return failures == 0 ? 0 : 1
    }

    private static func input(_ now: UInt64, _ expected: UInt32, _ raw: UInt32, _ after: UInt32, _ valid: Bool,
                              _ slope: Int, _ budget: UInt64, _ queue: Int, flat: Bool = false) -> AbrInput {
        AbrInput(nowMs: now, expected: expected, lostRaw: raw, lostAfterNack: after, slopeValid: valid,
                 slope01Ms: slope, overBudgetDelta: budget, queueMax: queue, slopeFlat: flat)
    }
}
