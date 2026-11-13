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
    // waitable object; "nowait" skips it. Both use 3 buffers and keep a busy
    // frame pending instead of dropping it.
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
