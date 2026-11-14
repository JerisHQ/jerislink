// Main-loop accounting for the viewer stats: how much of an input
// message's wait our loop caused, which part of a long loop iteration
// was spent inside a Windows modal loop, and which loop phase took the
// rest. Plain C++ (no Windows headers) so loop_wait_test.cpp checks the
// same code the viewer runs.
#pragma once

#include <algorithm>
#include <array>
#include <cstdint>

namespace jl {

// An input message's age when the loop takes it (GetTickCount - MSG::time)
// splits into two parts:
// - loopMs: time it sat in our queue while the loop was busy. The loop
//   drains the queue to empty on every pump and waits with QS_ALLINPUT, so
//   a message cannot have been in our queue before the loop was last
//   responsive (queue drained, or the wait returned). This is our latency.
// - deliveryMs: the rest. The event was already that old when Windows put
//   it in our queue (raw input thread, another process's low-level hook,
//   a stale or coarse timestamp). Not caused by the loop; reported apart.
struct InputWaitSplit {
    double loopMs = 0.0;
    double deliveryMs = 0.0;
};

inline InputWaitSplit splitInputWait(double ageMs, double sinceResponsiveMs) {
    ageMs = std::max(0.0, ageMs);
    sinceResponsiveMs = std::max(0.0, sinceResponsiveMs);
    InputWaitSplit s;
    s.loopMs = std::min(ageMs, sinceResponsiveMs);
    s.deliveryMs = ageMs - s.loopMs;
    return s;
}

// Time inside Windows modal loops run from our window procedure: caption
// button tracking (WM_NCLBUTTONDOWN), move/size (WM_SYSCOMMAND,
// WM_ENTERSIZEMOVE..WM_EXITSIZEMOVE), menus, our own modal dialogs. The
// system pumps our messages meanwhile, but our receive loop does not run.
// Nested scopes count once (the outermost one). Main thread only.
class ModalClock {
public:
    void enter(double nowMs) {
        if (depth_++ == 0) startMs_ = nowMs;
    }
    // Length of the modal stretch when the outermost scope ends, else 0.
    double exit(double nowMs) {
        if (depth_ == 0) return 0.0;
        if (--depth_ != 0) return 0.0;
        const double d = std::max(0.0, nowMs - startMs_);
        iterMs_ += d;
        windowMs_ += d;
        totalMs_ += d;
        maxMs_ = std::max(maxMs_, d);
        ++events_;
        return d;
    }
    bool active() const { return depth_ > 0; }
    // Modal time since the previous call (one loop iteration).
    double takeIterMs() { const double v = iterMs_; iterMs_ = 0.0; return v; }
    // Modal time since the previous call (one stats window).
    double takeWindowMs() { const double v = windowMs_; windowMs_ = 0.0; return v; }
    double totalMs() const { return totalMs_; }
    double maxMs() const { return maxMs_; }
    uint64_t events() const { return events_; }

private:
    int depth_ = 0;
    double startMs_ = 0.0;
    double iterMs_ = 0.0, windowMs_ = 0.0, totalMs_ = 0.0, maxMs_ = 0.0;
    uint64_t events_ = 0;
};

// Loop stalls count only the loop's own work: an iteration's busy time
// minus the modal time inside it.
struct LoopStallCounter {
    uint64_t stalls16 = 0;
    uint64_t stalls100 = 0;
    double ownMaxMs = 0.0;

    // Returns the iteration's own busy time.
    double note(double busyMs, double modalMs) {
        const double own = std::max(0.0, busyMs - std::max(0.0, modalMs));
        ownMaxMs = std::max(ownMaxMs, own);
        if (own >= 16.0) ++stalls16;
        if (own >= 100.0) ++stalls100;
        return own;
    }
};

// Where one main-loop iteration's time went (logged as loop.slow_iter).
// Phases follow the loop body in order; time not covered by a phase (the
// wait setup, the gaps between marks) is reported as "other". Wall time:
// a modal stretch inside the pump counts in pump; modal_ms is logged apart.
enum class IterPhase : int { Pre, Pump, VideoInfo, NetTx, Stats, Recv, Packet, Count };

inline const char* iterPhaseName(IterPhase p) {
    switch (p) {
    case IterPhase::Pre: return "pre";
    case IterPhase::Pump: return "pump";
    case IterPhase::VideoInfo: return "video_info";
    case IterPhase::NetTx: return "net_tx";
    case IterPhase::Stats: return "stats";
    case IterPhase::Recv: return "recv";
    case IterPhase::Packet: return "packet";
    default: return "other";
    }
}

class IterPhases {
public:
    static constexpr int kCount = static_cast<int>(IterPhase::Count);

    void reset() { ms_.fill(0.0); }
    void add(IterPhase p, double ms) {
        const int i = static_cast<int>(p);
        if (i < 0 || i >= kCount) return;
        ms_[i] += std::max(0.0, ms);
    }
    double get(IterPhase p) const {
        const int i = static_cast<int>(p);
        return i >= 0 && i < kCount ? ms_[i] : 0.0;
    }
    double sum() const {
        double t = 0.0;
        for (double v : ms_) t += v;
        return t;
    }
    // Iteration time outside every phase.
    double other(double busyMs) const { return std::max(0.0, busyMs - sum()); }
    // Name of the largest part, "other" included.
    const char* topName(double busyMs) const {
        int best = 0;
        for (int i = 1; i < kCount; ++i)
            if (ms_[i] > ms_[best]) best = i;
        if (other(busyMs) > ms_[best]) return "other";
        return iterPhaseName(static_cast<IterPhase>(best));
    }

private:
    std::array<double, kCount> ms_{};
};

// Inside the pump phase: PeekMessage calls (they also run the low-level
// keyboard hook and sent cross-thread messages), DispatchMessage calls,
// time in our keyboard hook, and outermost window-procedure calls (posted
// or sent) with the slowest message. Reset once per iteration.
struct PumpDetail {
    double peekMs = 0.0;
    double dispatchMs = 0.0;
    double hookMs = 0.0;
    double wndprocMs = 0.0;
    uint32_t msgs = 0;
    uint32_t hookCalls = 0;
    uint32_t wndprocCalls = 0;
    uint32_t slowMsg = 0;
    double slowMsgMs = 0.0;

    void reset() { *this = PumpDetail{}; }
    void noteHook(double ms) {
        hookMs += std::max(0.0, ms);
        ++hookCalls;
    }
    void noteWndProc(uint32_t msg, double ms) {
        ms = std::max(0.0, ms);
        wndprocMs += ms;
        ++wndprocCalls;
        if (ms > slowMsgMs) {
            slowMsgMs = ms;
            slowMsg = msg;
        }
    }
};

// Rate limit for loop.slow_iter: iterations with at least thresholdMs of
// own time are candidates. Below alwaysMs at most one line per intervalMs;
// the rest are counted (with their max) for the next line and the summary.
class SlowIterLimiter {
public:
    explicit SlowIterLimiter(double thresholdMs = 16.0, double alwaysMs = 100.0,
                             double intervalMs = 1000.0)
        : thresholdMs_(thresholdMs), alwaysMs_(alwaysMs), intervalMs_(intervalMs) {}

    bool shouldLog(double ownMs, double nowMs) {
        if (ownMs < thresholdMs_) return false;
        ++events_;
        if (ownMs < alwaysMs_ && nowMs - lastLogMs_ < intervalMs_) {
            ++pending_;
            ++suppressedTotal_;
            pendingMaxMs_ = std::max(pendingMaxMs_, ownMs);
            return false;
        }
        lastLogMs_ = nowMs;
        ++logged_;
        return true;
    }
    // Suppressed since the previous logged line; call when logging one.
    uint64_t takePending(double& maxMs) {
        const uint64_t n = pending_;
        maxMs = pendingMaxMs_;
        pending_ = 0;
        pendingMaxMs_ = 0.0;
        return n;
    }
    double thresholdMs() const { return thresholdMs_; }
    uint64_t events() const { return events_; }
    uint64_t logged() const { return logged_; }
    uint64_t suppressedTotal() const { return suppressedTotal_; }

private:
    double thresholdMs_, alwaysMs_, intervalMs_;
    double lastLogMs_ = -1e18;
    uint64_t events_ = 0, logged_ = 0, suppressedTotal_ = 0, pending_ = 0;
    double pendingMaxMs_ = 0.0;
};

} // namespace jl
