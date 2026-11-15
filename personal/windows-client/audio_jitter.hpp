#pragma once
// MRA1 audio packets and the viewer's jitter buffer. Portable (no Windows
// headers) so audio_jitter_test.cpp can drive it with synthetic arrival times.
//
// MRA1 (Mac -> viewer, one UDP datagram per 5 ms of 48 kHz stereo PCM):
//   0..3   "MRA1"
//   4      version = 1
//   5      flags (0x01 = first packet after the host capture (re)started)
//   6..9   sequence, big-endian u32 (wraps)
//   10..17 host capture time of the first frame, microseconds, big-endian u64
//   18..19 frame count, big-endian u16 (240)
//   20...  frames x 2 channels x s16 little-endian, interleaved L R
//
// The buffer is not thread-safe; the player guards it with one mutex shared
// by the network thread (push) and the render thread (pull).

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <vector>

namespace jl::audio {

constexpr int kSampleRate = 48000;
constexpr int kChannels = 2;
constexpr int kFramesPerPacket = 240;  // 5 ms
constexpr size_t kHeaderBytes = 20;
constexpr size_t kMaxFramesPerPacket = 960;  // 20 ms; anything larger is malformed
constexpr uint8_t kFlagRestart = 0x01;

struct Mra1Packet {
    uint8_t flags = 0;
    uint32_t seq = 0;
    uint64_t captureUs = 0;
    uint16_t frames = 0;
    const uint8_t* pcm = nullptr;  // frames * kChannels * 2 bytes, s16 LE
};

inline bool parseMra1(const uint8_t* p, size_t n, Mra1Packet& out) {
    if (n < kHeaderBytes || std::memcmp(p, "MRA1", 4) != 0 || p[4] != 1) return false;
    const uint16_t frames = uint16_t((uint16_t(p[18]) << 8) | p[19]);
    if (frames == 0 || frames > kMaxFramesPerPacket ||
        n != kHeaderBytes + size_t(frames) * kChannels * 2) return false;
    out.flags = p[5];
    out.seq = (uint32_t(p[6]) << 24) | (uint32_t(p[7]) << 16) | (uint32_t(p[8]) << 8) | p[9];
    out.captureUs = 0;
    for (int i = 0; i < 8; ++i) out.captureUs = (out.captureUs << 8) | p[10 + i];
    out.frames = frames;
    out.pcm = p + kHeaderBytes;
    return true;
}

// Test helper: builds one MRA1 datagram.
inline std::vector<uint8_t> makeMra1(uint32_t seq, uint64_t captureUs, uint8_t flags,
                                     const std::vector<int16_t>& interleaved) {
    const uint16_t frames = uint16_t(interleaved.size() / kChannels);
    std::vector<uint8_t> p{'M', 'R', 'A', '1', 1, flags,
                           uint8_t(seq >> 24), uint8_t(seq >> 16), uint8_t(seq >> 8), uint8_t(seq)};
    for (int i = 0; i < 8; ++i) p.push_back(uint8_t(captureUs >> (56 - 8 * i)));
    p.push_back(uint8_t(frames >> 8));
    p.push_back(uint8_t(frames));
    for (int16_t s : interleaved) {
        const uint16_t u = uint16_t(s);
        p.push_back(uint8_t(u));
        p.push_back(uint8_t(u >> 8));
    }
    return p;
}

struct JitterStats {
    uint64_t packetsRx = 0;
    uint64_t lost = 0;           // packets never received when their turn came (played as silence)
    uint64_t late = 0;           // arrived after their turn had passed (dropped)
    uint64_t duplicates = 0;
    uint64_t underruns = 0;      // buffer ran dry while playing
    uint64_t overflowDrops = 0;  // packets dropped because the buffer grew past target + 30 ms
    uint64_t resets = 0;         // host restart flag or a large sequence jump
    uint64_t framesPlayed = 0;
    uint64_t framesSilence = 0;  // prebuffer, underrun and concealment frames
    double targetMs = 0;
    double jitterMs = 0;
    double bufferedMs = 0;
};

class JitterBuffer {
public:
    static constexpr double kMinTargetMs = 10.0;
    static constexpr double kMaxTargetMs = 60.0;
    static constexpr double kInitialTargetMs = 20.0;
    static constexpr double kOverflowSlackMs = 30.0;
    static constexpr double kUnderrunStepMs = 5.0;
    // Steady playback needed before the target may shrink by 1 ms.
    static constexpr int kShrinkAfterFrames = kSampleRate * 5;

    // arrivalUs: viewer monotonic clock at receive time.
    void push(const Mra1Packet& pkt, uint64_t arrivalUs) {
        ++stats_.packetsRx;
        if (!started_ || (pkt.flags & kFlagRestart) != 0) {
            if (started_) ++stats_.resets;
            resetTo(pkt.seq);
        }
        int64_t ext = extend(pkt.seq);
        if (ext - next_ > 2000 || next_ - ext > 2000) {
            // 10 s jump: the host restarted without the flag reaching us.
            ++stats_.resets;
            resetTo(pkt.seq);
            ext = next_;
        }
        updateJitter(pkt.captureUs, arrivalUs);
        if (ext < next_) { ++stats_.late; return; }
        if (packets_.count(ext)) { ++stats_.duplicates; return; }
        std::vector<int16_t> s(size_t(pkt.frames) * kChannels);
        std::memcpy(s.data(), pkt.pcm, s.size() * 2);  // s16 LE on x86/ARM
        bufferedFrames_ += pkt.frames;
        packets_.emplace(ext, std::move(s));
        trimOverflow();
    }

    // Fills `frames` interleaved stereo frames; always writes all of them.
    void pull(int16_t* out, size_t frames) {
        size_t done = 0;
        while (done < frames) {
            if (prebuffering_) {
                if (started_ && bufferedMs() >= targetMs_) {
                    prebuffering_ = false;
                } else {
                    silence(out + done * kChannels, frames - done);
                    return;
                }
            }
            if (cur_.empty() || curPos_ >= cur_.size() / kChannels) {
                if (!loadNext()) {
                    // Buffer ran dry: count it, grow the target, prebuffer again.
                    ++stats_.underruns;
                    targetMs_ = std::min(kMaxTargetMs, targetMs_ + kUnderrunStepMs);
                    steadyFrames_ = 0;
                    prebuffering_ = true;
                    continue;
                }
            }
            const size_t avail = cur_.size() / kChannels - curPos_;
            const size_t n = std::min(avail, frames - done);
            if (curSilent_) {
                std::fill(out + done * kChannels, out + (done + n) * kChannels, int16_t(0));
                stats_.framesSilence += n;
            } else {
                std::memcpy(out + done * kChannels, cur_.data() + curPos_ * kChannels,
                            n * kChannels * sizeof(int16_t));
                stats_.framesPlayed += n;
            }
            curPos_ += n;
            bufferedFrames_ -= std::min<uint64_t>(bufferedFrames_, curSilent_ ? 0 : n);
            done += n;
            adaptAfterPlaying(n);
        }
    }

    JitterStats stats() const {
        JitterStats s = stats_;
        s.targetMs = targetMs_;
        s.jitterMs = jitterUs_ / 1000.0;
        s.bufferedMs = bufferedMs();
        return s;
    }
    bool prebuffering() const { return prebuffering_; }

private:
    void resetTo(uint32_t seq) {
        packets_.clear();
        cur_.clear();
        curPos_ = 0;
        curSilent_ = false;
        bufferedFrames_ = 0;
        base_ = seq;
        next_ = 0;
        started_ = true;
        prebuffering_ = true;
        havePrev_ = false;
    }

    // Sequence relative to base_, unwrapped to 64 bits around next_.
    int64_t extend(uint32_t seq) const {
        const uint32_t expected = uint32_t(base_ + uint32_t(next_));
        return next_ + int64_t(int32_t(seq - expected));
    }

    void updateJitter(uint64_t captureUs, uint64_t arrivalUs) {
        // RFC 3550 interarrival jitter, using the host capture clock.
        if (havePrev_) {
            const double d = (double(arrivalUs) - double(prevArrivalUs_)) -
                             (double(captureUs) - double(prevCaptureUs_));
            // A jump over 500 ms is a pause or a clock reset, not network jitter.
            if (std::fabs(d) < 500000.0) jitterUs_ += (std::fabs(d) - jitterUs_) / 16.0;
            const double desired = std::clamp(4.0 * jitterUs_ / 1000.0 + 5.0, kMinTargetMs, kMaxTargetMs);
            if (desired > targetMs_) targetMs_ = desired;
        }
        havePrev_ = true;
        prevArrivalUs_ = arrivalUs;
        prevCaptureUs_ = captureUs;
    }

    bool loadNext() {
        cur_.clear();
        curPos_ = 0;
        curSilent_ = false;
        if (packets_.empty()) return false;
        auto it = packets_.begin();
        if (it->first == next_) {
            cur_ = std::move(it->second);
            packets_.erase(it);
        } else {
            // Our packet is missing but a later one is here: play 5 ms of
            // silence in its place so timing stays intact.
            ++stats_.lost;
            cur_.assign(size_t(kFramesPerPacket) * kChannels, 0);
            curSilent_ = true;
        }
        ++next_;
        return true;
    }

    void trimOverflow() {
        while (!packets_.empty() && bufferedMs() > targetMs_ + kOverflowSlackMs) {
            // Drop the oldest buffered audio to pull latency back.
            auto it = packets_.begin();
            bufferedFrames_ -= std::min<uint64_t>(bufferedFrames_, it->second.size() / kChannels);
            next_ = it->first + 1;
            packets_.erase(it);
            ++stats_.overflowDrops;
        }
    }

    void adaptAfterPlaying(size_t frames) {
        steadyFrames_ += int(frames);
        if (steadyFrames_ >= kShrinkAfterFrames) {
            steadyFrames_ = 0;
            const double desired = std::clamp(4.0 * jitterUs_ / 1000.0 + 5.0, kMinTargetMs, kMaxTargetMs);
            if (targetMs_ - 1.0 >= desired) targetMs_ -= 1.0;
        }
    }

    void silence(int16_t* out, size_t frames) {
        std::fill(out, out + frames * kChannels, int16_t(0));
        stats_.framesSilence += frames;
    }

    double bufferedMs() const {
        return double(bufferedFrames_) * 1000.0 / kSampleRate;
    }

    std::map<int64_t, std::vector<int16_t>> packets_;
    std::vector<int16_t> cur_;
    size_t curPos_ = 0;
    bool curSilent_ = false;
    uint64_t bufferedFrames_ = 0;  // received frames not yet played (map + current packet)
    uint32_t base_ = 0;
    int64_t next_ = 0;             // next packet index to load
    bool started_ = false;
    bool prebuffering_ = true;
    bool havePrev_ = false;
    uint64_t prevArrivalUs_ = 0;
    uint64_t prevCaptureUs_ = 0;
    double jitterUs_ = 0;
    double targetMs_ = kInitialTargetMs;
    int steadyFrames_ = 0;
    JitterStats stats_;
};

}  // namespace jl::audio
