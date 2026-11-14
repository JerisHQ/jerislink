// Main-loop accounting for the viewer stats: how much of an input
// message's wait our loop caused, and which part of a long loop iteration
// was spent inside a Windows modal loop. Plain C++ (no Windows headers) so
// loop_wait_test.cpp checks the same code the viewer runs.
#pragma once

#include <algorithm>
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

} // namespace jl
