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

        // Golden trace: (nowMs, expected, raw, afterNack, slopeValid, slope01Ms, overBudgetDelta, queueMax) -> kbps.
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
            (input(7250, 20, 10, 10, false, 0, 0, 0), 6000),
            (input(10250, 400, 0, 0, false, 0, 0, 0), 6900),
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
        expect(c.downs == 4 && c.ups == 3, "abr golden: 4 down, 3 up")
        expect(reasons == ["loss", "heavy_loss", "send_queue", "clear", "clear", "nack_budget", "clear"],
               "abr golden: reasons")
        c.reset()
        expect(c.currentKbps == 18000, "abr: reset returns to the ceiling")
        var low = AbrController(ceilingKbps: 4000)
        expect(low.onReport(input(500, 400, 100, 100, true, 0, 0, 0)) == nil && low.currentKbps == 4000,
               "abr: ceiling below 6 Mbps never steps down")

        // 0x42 parse: same bytes as testReceiverReportEncoding in C++.
        let bytes: [UInt8] = [0x4d, 0x52, 0x4d, 0x31, 1, 0x42, 0x0A, 0x0B, 0x0C, 0x0D, 0x01, 0x00, 0xFA,
                              0x01, 0x02, 0x03, 0x04, 0, 0, 0, 7, 0, 0, 0, 2, 0xFF, 0x85, 0x00, 61]
        var want = ReceiverReport()
        want.slopeValid = true; want.windowMs = 250; want.expected = 0x01020304
        want.lostRaw = 7; want.lostAfterNack = 2; want.slope01Ms = -123; want.rttMs = 61
        expect(ReceiverReport.parse(bytes) == want, "report: parses the C++ encoding")
        expect(ReceiverReport.parse(bytes + [9, 9]) == want, "report: trailing bytes ignored")
        expect(ReceiverReport.parse(Array(bytes.dropLast())) == nil, "report: short packet rejected")

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
                              _ slope: Int, _ budget: UInt64, _ queue: Int) -> AbrInput {
        AbrInput(nowMs: now, expected: expected, lostRaw: raw, lostAfterNack: after, slopeValid: valid,
                 slope01Ms: slope, overBudgetDelta: budget, queueMax: queue)
    }
}
