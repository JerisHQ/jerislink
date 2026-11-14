#pragma once

#include <windows.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "video_decoder_factory.hpp"

class HardwareVideoPipeline {
public:
    using Logger = std::function<void(const std::string&)>;

    // presentMode: "waitable" (default) uses the swap chain frame-latency
    // waitable object with max frame latency 2; "waitable1" uses latency 1
    // (the G2 behaviour); "nowait" skips the object. All use 3 buffers and
    // keep a busy frame pending instead of dropping it.
    HardwareVideoPipeline(HWND hwnd, UINT32 width, UINT32 height, UINT32 fps,
                          JerisVideoCodec codec, Logger logger,
                          const std::string& presentMode = "waitable");
    ~HardwareVideoPipeline();

    HardwareVideoPipeline(const HardwareVideoPipeline&) = delete;
    HardwareVideoPipeline& operator=(const HardwareVideoPipeline&) = delete;

    void submit(uint64_t frameId, const std::vector<uint8_t>& annexB, bool discontinuity);
    void resetForNewStream();
    void finish();
    void abandon() noexcept;

    // Non-blocking. Present the pending newest frame if the swap chain can
    // take it now. Call on every receive-loop pass.
    void servicePresent();
    // Draw the newest frame again (WM_PAINT, resize). Non-blocking.
    void repaint();
    // True while a decoded frame is still waiting to be presented.
    bool presentPending() const;
    // Frame-latency waitable object to wait on, or nullptr when the next
    // servicePresent() does not need it. Do not close it.
    HANDLE presentWaitHandle() const;
    // The caller's wait on presentWaitHandle() succeeded (that consumed it).
    void onPresentWaitSignaled();

    uint64_t decodedFrames() const;
    uint64_t presented() const;
    uint64_t busyDrops() const;
    uint64_t busyRetries() const;
    uint64_t repaints() const;
    uint64_t latencyTimeouts() const;
    // Decoded frames replaced while the window was minimized / occluded.
    uint64_t hiddenDrops() const;
    // Present() calls that returned DXGI_STATUS_OCCLUDED.
    uint64_t occludedPresents() const;
    // Times presenting stopped because the window was hidden.
    uint64_t hiddenPeriods() const;
    // Max frame latency in use (0 = no waitable object).
    UINT maxFrameLatency() const;
    // Present -> vblank samples (ms) since the last call. Same thread as
    // servicePresent().
    void takeDisplayLatencyMs(std::vector<float>& out);
    uint64_t nonDxgiDrops() const;
    uint64_t streamChanges() const;
    uint64_t inputBackpressure() const;
    double avgPresentMs() const;
    double maxPresentMs() const;
    UINT32 activeWidth() const;
    UINT32 activeHeight() const;
    const std::string& adapterName() const;
    const std::string& decoderName() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
