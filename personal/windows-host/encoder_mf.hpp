// JerisLink Windows host, H1: H.264 through the Media Foundation software
// encoder (CLSID_CMSH264EncoderMFT, synchronous). NV12 in, one Annex B
// access unit out per frame, no B-frames, low-latency CBR.
//
// The hardware encoder MFTs are asynchronous and need a D3D device manager;
// they come in a later phase (design D2), not here.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace jlh {

struct EncoderConfig {
    int width = 0, height = 0;  // even
    int fps = 30;
    int bitrateMbps = 25;
    int gopFrames = 30;
};

class MfH264Encoder {
public:
    MfH264Encoder();
    ~MfH264Encoder();
    MfH264Encoder(const MfH264Encoder&) = delete;
    MfH264Encoder& operator=(const MfH264Encoder&) = delete;

    // MFStartup / COM must already be up on this thread (MTA).
    bool open(const EncoderConfig& cfg, std::string& error);
    void close();
    bool isOpen() const;
    const EncoderConfig& config() const { return cfg_; }

    // nv12: width*height*3/2 bytes. Returns false on an encoder error; an
    // empty `out` with true means the encoder held the frame (not expected
    // in low-latency mode). A keyframe output always carries SPS/PPS.
    bool encode(const uint8_t* nv12, int64_t timestamp100ns, bool forceKeyframe, std::vector<uint8_t>& out,
                bool& keyFrame, std::string& error);

private:
    struct Impl;
    Impl* impl_ = nullptr;
    EncoderConfig cfg_;
};

}  // namespace jlh
