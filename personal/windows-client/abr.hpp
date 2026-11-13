// ABR v1, viewer side (no Win32): the MRM1 0x42 receiver report, the
// arrival-delay slope estimator, and a C++ copy of the host AbrController
// (mac-host AbrController.swift is the one that runs; this copy drives the
// loss/congestion simulation and pins the same golden trace).
//
// MRM1 0x42 receiver report, viewer -> host, every 250 ms, only when the host
// set video config ACK flag 0x40 (ABR) and the viewer has --abr on:
//   0  "MRM1"   4  version 1   5  type 0x42   6  seq u32 BE
//   10 flags u8 (bit0: slope valid)
//   11 window_ms u16
//   13 expected u32         originals the host sent (finalized frames, delta)
//   17 lost_raw u32         of those, never arrived as an original (delta)
//   21 lost_after_nack u32  never arrived nor repaired in time (delta)
//   25 slope i16            arrival-delay slope, 0.1 ms per 250 ms
//   27 rtt_ms u16           last ping RTT, 0 = unknown
//   29 bytes total. Hosts ignore trailing bytes.
#pragma once

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace jl {

constexpr uint8_t kAckFlagAbr = 0x40;
constexpr size_t kReceiverReportBytes = 29;
constexpr double kReceiverReportIntervalMs = 250.0;

struct ReceiverReport {
    bool slopeValid = false;
    uint16_t windowMs = 0;
    uint32_t expected = 0, lostRaw = 0, lostAfterNack = 0;
    int16_t slope01Ms = 0;  // 0.1 ms per 250 ms
    uint16_t rttMs = 0;
};

inline std::vector<uint8_t> encodeReceiverReport(uint32_t seq, const ReceiverReport& r) {
    std::vector<uint8_t> p{'M', 'R', 'M', '1', 1, 0x42,
                           uint8_t(seq >> 24), uint8_t(seq >> 16), uint8_t(seq >> 8), uint8_t(seq)};
    auto be16 = [&](uint16_t v) { p.push_back(uint8_t(v >> 8)); p.push_back(uint8_t(v)); };
    auto be32 = [&](uint32_t v) { for (int i = 3; i >= 0; --i) p.push_back(uint8_t(v >> (8 * i))); };
    p.push_back(r.slopeValid ? 0x01 : 0x00);
    be16(r.windowMs);
    be32(r.expected);
    be32(r.lostRaw);
    be32(r.lostAfterNack);
    be16(uint16_t(r.slope01Ms));
    be16(r.rttMs);
    return p;
}

inline int16_t abrSlopeTo01Ms(double ms) {
    const double v = std::clamp(ms * 10.0, -32767.0, 32767.0);
    return int16_t(v < 0 ? v - 0.5 : v + 0.5);
}

// Arrival-delay slope (D4 A: no host timestamp). For each new frame id the
// first original packet's arrival time is taken; for consecutive frame ids
// the gap minus the nominal frame interval T is the change in one-way delay.
// Gaps outside [0.25 T, 1.75 T] are left out: the host only encodes frames
// the screen changed, so a skipped capture (2 T, 3 T ...) is not a queue.
// The window's slope is the mean excess per frame scaled to 250 ms; fewer
// than 6 samples means "unknown" (valid = false).
class ArrivalSlope {
public:
    explicit ArrivalSlope(double nominalFrameMs) : t_(nominalFrameMs > 0 ? nominalFrameMs : 1000.0 / 60) {}

    void onPacket(uint64_t fid, bool retransmit, double nowMs) {
        if (retransmit) return;
        if (have_ && fid <= last_) {
            if (fid + 2 < last_ && last_ - fid > 120) { last_ = fid; at_ = nowMs; }  // host restart
            return;
        }
        if (have_ && fid == last_ + 1) {
            const double gap = nowMs - at_;
            if (gap >= 0.25 * t_ && gap <= 1.75 * t_) { sum_ += gap - t_; ++n_; }
            else ++skipped_;
        }
        have_ = true;
        last_ = fid;
        at_ = nowMs;
    }

    struct Window { bool valid = false; double slopeMs = 0; int samples = 0; };
    Window take() {
        Window w;
        w.samples = n_;
        w.valid = n_ >= 6;
        if (w.valid) w.slopeMs = sum_ / n_ * (kReceiverReportIntervalMs / t_);
        sum_ = 0;
        n_ = 0;
        return w;
    }
    uint64_t skipped() const { return skipped_; }

private:
    double t_;
    bool have_ = false;
    uint64_t last_ = 0;
    double at_ = 0;
    double sum_ = 0;
    int n_ = 0;
    uint64_t skipped_ = 0;
};

// Host controller, design 2.2 (D5 A: bitrate only). Integer kbps; the Swift
// AbrController must give the same output for the same inputs (golden test).
struct AbrInput {
    uint64_t nowMs = 0;
    uint32_t expected = 0, lostRaw = 0, lostAfterNack = 0;
    bool slopeValid = false;
    int slope01Ms = 0;
    uint64_t overBudgetDelta = 0;  // host nack_over_budget since the last report
    int queueMax = 0;              // host send queue max since the last report
};

struct AbrChange { uint32_t fromKbps = 0, toKbps = 0; std::string reason; };

class AbrController {
public:
    explicit AbrController(uint32_t ceilingKbps) : ceiling_(std::max<uint32_t>(1, ceilingKbps)) { reset(); }

    void reset() {
        current_ = ceiling_;
        slopeStreak_ = budgetStreak_ = queueStreak_ = 0;
        haveDown_ = haveUp_ = haveClear_ = false;
    }
    uint32_t current() const { return current_; }
    uint32_t ceiling() const { return ceiling_; }
    uint32_t floor() const { return std::min<uint32_t>(6000, ceiling_); }
    uint64_t downs() const { return downs_; }
    uint64_t ups() const { return ups_; }

    // Returns true and fills `out` when the bitrate changes.
    bool onReport(const AbrInput& in, AbrChange& out) {
        const bool lossKnown = in.expected >= 30;
        const uint64_t afterBp = lossKnown ? uint64_t(in.lostAfterNack) * 10000 / in.expected : 0;
        const uint64_t rawBp = lossKnown ? uint64_t(in.lostRaw) * 10000 / in.expected : 0;
        slopeStreak_ = (in.slopeValid && in.slope01Ms > 40) ? slopeStreak_ + 1 : 0;
        budgetStreak_ = in.overBudgetDelta > 0 ? budgetStreak_ + 1 : 0;
        // One IDR alone queues about 3 frames at the pacer (250 packets at
        // 72 Mbps is ~40 ms), so the queue only counts when it stays.
        queueStreak_ = in.queueMax >= 3 ? queueStreak_ + 1 : 0;

        const char* reason = nullptr;
        bool heavy = false;
        if (afterBp > 1000) { heavy = true; reason = "heavy_loss"; }
        else if (budgetStreak_ >= 2) { heavy = true; reason = "nack_budget"; }
        else if (afterBp > 200) reason = "loss";
        else if (rawBp > 500) reason = "raw_loss";
        else if (slopeStreak_ >= 2) reason = "delay";
        else if (queueStreak_ >= 2) reason = "send_queue";

        if (reason) {
            haveClear_ = false;
            if (haveDown_ && in.nowMs - lastDownMs_ < 500) return false;
            const uint32_t next = std::max(floor(), heavy ? current_ / 2 : current_ * 4 / 5);
            if (next >= current_) return false;
            haveDown_ = true;
            lastDownMs_ = in.nowMs;
            ++downs_;
            out = {current_, next, reason};
            current_ = next;
            return true;
        }
        const bool clear = afterBp < 50 && !(in.slopeValid && in.slope01Ms > 10) && in.overBudgetDelta == 0;
        if (!clear) { haveClear_ = false; return false; }
        if (!haveClear_) { haveClear_ = true; clearSinceMs_ = in.nowMs; }
        if (current_ >= ceiling_ || in.nowMs - clearSinceMs_ < 3000) return false;
        if (haveUp_ && in.nowMs - lastUpMs_ < 1000) return false;
        const uint32_t next = std::min(ceiling_, current_ + std::max<uint32_t>(1, ceiling_ / 20));
        haveUp_ = true;
        lastUpMs_ = in.nowMs;
        ++ups_;
        out = {current_, next, "clear"};
        current_ = next;
        return true;
    }

private:
    uint32_t ceiling_;
    uint32_t current_ = 0;
    int slopeStreak_ = 0, budgetStreak_ = 0, queueStreak_ = 0;
    bool haveDown_ = false, haveUp_ = false, haveClear_ = false;
    uint64_t lastDownMs_ = 0, lastUpMs_ = 0, clearSinceMs_ = 0;
    uint64_t downs_ = 0, ups_ = 0;
};

}  // namespace jl
