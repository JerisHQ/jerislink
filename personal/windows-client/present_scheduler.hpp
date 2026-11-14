#pragma once
// Latest-frame-wins present scheduling for the hardware (DXGI flip) path.
// No Win32 here, so the rules can be unit tested with a fake swap chain.
//
// Rules:
// - A decoded frame never waits in a queue. It becomes "the newest frame";
//   if the previous newest frame was never shown, that one is dropped and
//   counted in busyDrops.
// - A present that would block (latency object not signalled, or Present()
//   returns DXGI_ERROR_WAS_STILL_DRAWING) leaves the frame pending. The
//   receive loop calls service() again on its next pass; nothing blocks.
// - A repaint (WM_PAINT, resize) draws the newest frame again.
// - While the window is hidden (minimized, zero client area, or Present()
//   reported DXGI_STATUS_OCCLUDED) nothing is rendered or presented. The
//   newest frame stays pending and is shown when the window is visible
//   again; frames replaced meanwhile count as hiddenDrops, not busyDrops.
#include <cstdint>
#include <functional>
#include <utility>

namespace jl {

enum class PresentResult { Ok, Busy };

struct PresentOps {
    // Non-blocking: true when a back buffer may be used now. Returning true
    // consumes the latency slot, so it is asked again only after a present
    // succeeded. Empty function = always ready.
    std::function<bool()> latencyReady;
    // Draw the newest frame into the back buffer.
    std::function<void()> render;
    // Non-blocking present. Busy = would block, try again later.
    // Real errors throw.
    std::function<PresentResult()> present;
    // Milliseconds, any monotonic origin. Used only for the latency wait cap.
    std::function<double()> nowMs;
};

struct PresentCounters {
    uint64_t decoded = 0;          // frames handed to onDecoded()
    uint64_t presented = 0;        // decoded frames that reached the screen
    uint64_t repaints = 0;         // successful re-presents of an already shown frame
    uint64_t busyDrops = 0;        // decoded frames replaced before they were shown
    uint64_t busyRetries = 0;      // service() calls that found the present busy
    uint64_t latencyTimeouts = 0;  // latency gate skipped after kLatencyWaitCapMs
    uint64_t hiddenDrops = 0;      // decoded frames replaced while the window was hidden
};

class LatestFramePresenter {
public:
    // If the latency object stays unsignalled this long (occluded window,
    // driver quirk), present anyway so a frame can never be stuck forever.
    static constexpr double kLatencyWaitCapMs = 50.0;

    explicit LatestFramePresenter(PresentOps ops) : ops_(std::move(ops)) {}

    // A new decoded frame is now the newest one.
    void onDecoded() {
        ++c_.decoded;
        if (pending_ && !pendingIsRepaint_) {
            if (hidden_) ++c_.hiddenDrops;
            else ++c_.busyDrops;
        }
        pending_ = true;
        pendingIsRepaint_ = false;
        rendered_ = false;
        haveFrame_ = true;
        service();
    }

    // Draw the newest frame again (WM_PAINT, resize). Keeps a pending new
    // frame as a new frame.
    void onRepaint() {
        if (!haveFrame_) return;
        if (!pending_) {
            pending_ = true;
            pendingIsRepaint_ = true;
        }
        rendered_ = false;
        service();
    }

    // The back buffer content was lost (ResizeBuffers): render again.
    void onBuffersLost() { rendered_ = false; }

    // The caller waited on the latency object itself and it was signalled.
    void onLatencySignalled() {
        latencyAcquired_ = true;
        waitStartMs_ = -1.0;  // this wait is over; the next one starts fresh
        service();
    }

    // Forget the newest frame (stream reset / shutdown). A pending frame
    // that is dropped here is not a busy drop.
    void clear() {
        pending_ = false;
        pendingIsRepaint_ = false;
        rendered_ = false;
        haveFrame_ = false;
        waitStartMs_ = -1.0;
    }

    // The window is hidden (true) or visible again (false). While hidden,
    // service() does nothing and the newest frame waits.
    void setHidden(bool hidden) {
        if (hidden_ == hidden) return;
        hidden_ = hidden;
        // Do not carry a half-finished latency wait across the gap.
        waitStartMs_ = -1.0;
        // The back buffer may have been resized or discarded meanwhile.
        rendered_ = false;
    }

    // Try to put the pending frame on screen. Never blocks.
    // Returns true while a frame is still pending afterwards.
    bool service() {
        if (!pending_) return false;
        if (hidden_) return true;
        if (!latencyAcquired_) {
            const bool ready = !ops_.latencyReady || ops_.latencyReady();
            if (ready) {
                latencyAcquired_ = true;
                waitStartMs_ = -1.0;
            } else {
                const double now = ops_.nowMs ? ops_.nowMs() : 0.0;
                if (waitStartMs_ < 0) waitStartMs_ = now;
                if (now - waitStartMs_ < kLatencyWaitCapMs) {
                    ++c_.busyRetries;
                    return true;
                }
                ++c_.latencyTimeouts;
                latencyAcquired_ = true;  // retries go straight to Present()
                waitStartMs_ = -1.0;
            }
        }
        if (!rendered_) {
            ops_.render();
            rendered_ = true;
        }
        if (ops_.present() == PresentResult::Busy) {
            ++c_.busyRetries;
            return true;
        }
        if (pendingIsRepaint_) ++c_.repaints;
        else ++c_.presented;
        pending_ = false;
        pendingIsRepaint_ = false;
        rendered_ = false;  // FLIP_DISCARD: back buffer content is undefined now
        latencyAcquired_ = false;
        waitStartMs_ = -1.0;  // every present path starts the next wait clean
        return false;
    }

    bool pending() const { return pending_; }
    bool hidden() const { return hidden_; }
    // True when service() could make progress now (a frame is pending and
    // the window is visible). Callers poll or wait only while this is true.
    bool wantsService() const { return pending_ && !hidden_; }
    // True when the next service() would ask the latency object first, so
    // the caller may wait on that object instead of polling.
    bool waitingForLatency() const { return pending_ && !hidden_ && !latencyAcquired_; }
    const PresentCounters& counters() const { return c_; }

private:
    PresentOps ops_;
    PresentCounters c_;
    bool pending_ = false;
    bool pendingIsRepaint_ = false;
    bool rendered_ = false;
    bool haveFrame_ = false;
    bool hidden_ = false;
    bool latencyAcquired_ = false;
    double waitStartMs_ = -1.0;
};

} // namespace jl
