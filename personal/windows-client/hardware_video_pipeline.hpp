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

    HardwareVideoPipeline(HWND hwnd, UINT32 width, UINT32 height, UINT32 fps,
                          JerisVideoCodec codec, Logger logger);
    ~HardwareVideoPipeline();

    HardwareVideoPipeline(const HardwareVideoPipeline&) = delete;
    HardwareVideoPipeline& operator=(const HardwareVideoPipeline&) = delete;

    void submit(uint64_t frameId, const std::vector<uint8_t>& annexB, bool discontinuity);
    void resetForNewStream();
    void finish();
    void abandon() noexcept;

    uint64_t decodedFrames() const;
    uint64_t presented() const;
    uint64_t busyDrops() const;
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
