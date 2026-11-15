#pragma once
// MRA1 audio packets and the viewer's jitter buffer. Portable (no Windows
// headers) so audio_jitter_test.cpp can drive it with synthetic arrival times.
//
// MRA1 (Mac -> viewer, one UDP datagram per packet of 48 kHz stereo):
//   0..3   "MRA1"
//   4      version: 1 = PCM (A1), 2 = Opus (A2)
//   5      flags (0x01 = first packet after the host capture (re)started)
//   6..9   sequence, big-endian u32 (wraps)
//   10..17 host capture time of the first frame, microseconds, big-endian u64
//   18..19 frame count, big-endian u16 (v1: 240 = 5 ms, v2: 480 = 10 ms)
//   20...  v1: frames x 2 channels x s16 little-endian, interleaved L R
//          v2: one Opus packet that decodes to `frame count` frames
//
// The viewer asks for v2 with MRM1 0x45 flag 0x02. An A1 host ignores that
// bit and keeps sending v1, which this buffer still plays; an A1 viewer never
// sets it and an A2 host sends it v1.
//
// Opus is decoded here, in order, on the render thread (loadNext). A missing
// packet is rebuilt from the next packet's in-band FEC when it has any, and
// concealed by Opus PLC otherwise. PCM gaps stay 5 ms of silence as in A1.
//
// Clock drift: the Mac capture clock and the PC output clock differ by a few
// hundred ppm, so without correction the buffer slowly drains (underrun) or
// fills (overflow drop). With drift control on, the buffer depth seen by each
// device pull (before it takes audio, the same measure prebuffering uses) is
// averaged over 1 s and compared with a set point: the target when
// prebuffering ended, raised whenever the target grows (never lowered until
// the next prebuffer, so the jitter margin is not given away). When the
// average is below set point - 3 ms, or the lowest depth minus the packet in
// play is under 3 ms, every decoded packet is stretched by one frame; when the
// average is above set point + 5 ms and even the lowest depth is above the set
// point, shrunk by one (linear interpolation; ~0.2% for 10 ms packets, ~0.4%
// for 5 ms). Either continues until the average is back at the set point.
// The target itself adds (packet length - 5 ms) of slack, so 10 ms Opus
// packets get 5 ms more buffer than 5 ms PCM (see desiredTargetMs).
//
// Output gaps: while the player has no open device (startup, a default
// output switch, a device that went away) nothing pulls, so the buffer would
// fill to target + 30 ms and then drop one packet per arrival as "overflow".
// The player marks those spans with setOutputActive(false): packets beyond
// the target are dropped as idleDrops instead, and setOutputActive(true)
// trims to the newest `target` of audio (the live edge), resets the Opus
// decoder across the discontinuity and prebuffers again, so the new device
// starts at the normal latency instead of with a backlog.
//
// The buffer is not thread-safe; the player guards it with one mutex shared
// by the network thread (push) and the render thread (pull).

#include <opus.h>

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
constexpr int kFramesPerPacket = 240;      // v1 PCM: 5 ms
constexpr int kOpusFramesPerPacket = 480;  // v2 Opus: 10 ms
constexpr size_t kHeaderBytes = 20;
constexpr size_t kMaxFramesPerPacket = 960;  // 20 ms; anything larger is malformed
constexpr size_t kMaxOpusPayload = 1275;     // RFC 6716 limit for one frame
constexpr uint8_t kVersionPcm = 1;
constexpr uint8_t kVersionOpus = 2;
constexpr uint8_t kFlagRestart = 0x01;
// MRM1 0x45 request flags.
constexpr uint8_t kRequestEnable = 0x01;
constexpr uint8_t kRequestOpus = 0x02;

struct Mra1Packet {
    uint8_t version = kVersionPcm;
    uint8_t flags = 0;
    uint32_t seq = 0;
    uint64_t captureUs = 0;
    uint16_t frames = 0;
    const uint8_t* payload = nullptr;  // v1: frames * kChannels * 2 bytes s16 LE; v2: Opus packet
    size_t payloadBytes = 0;
};

inline bool parseMra1(const uint8_t* p, size_t n, Mra1Packet& out) {
    if (n < kHeaderBytes || std::memcmp(p, "MRA1", 4) != 0) return false;
    const uint8_t version = p[4];
    const uint16_t frames = uint16_t((uint16_t(p[18]) << 8) | p[19]);
    if (frames == 0 || frames > kMaxFramesPerPacket) return false;
    if (version == kVersionPcm) {
        if (n != kHeaderBytes + size_t(frames) * kChannels * 2) return false;
    } else if (version == kVersionOpus) {
        // 2.5 / 5 / 10 / 20 ms Opus frames only.
        if (frames != 120 && frames != 240 && frames != 480 && frames != 960) return false;
        if (n <= kHeaderBytes || n > kHeaderBytes + kMaxOpusPayload) return false;
    } else {
        return false;
    }
    out.version = version;
    out.flags = p[5];
    out.seq = (uint32_t(p[6]) << 24) | (uint32_t(p[7]) << 16) | (uint32_t(p[8]) << 8) | p[9];
    out.captureUs = 0;
    for (int i = 0; i < 8; ++i) out.captureUs = (out.captureUs << 8) | p[10 + i];
    out.frames = frames;
    out.payload = p + kHeaderBytes;
    out.payloadBytes = n - kHeaderBytes;
    return true;
}

inline std::vector<uint8_t> makeMra1Header(uint8_t version, uint32_t seq, uint64_t captureUs, uint8_t flags,
                                           uint16_t frames) {
    std::vector<uint8_t> p{'M', 'R', 'A', '1', version, flags,
                           uint8_t(seq >> 24), uint8_t(seq >> 16), uint8_t(seq >> 8), uint8_t(seq)};
    for (int i = 0; i < 8; ++i) p.push_back(uint8_t(captureUs >> (56 - 8 * i)));
    p.push_back(uint8_t(frames >> 8));
    p.push_back(uint8_t(frames));
    return p;
}

// Test helper: builds one MRA1 v1 (PCM) datagram.
inline std::vector<uint8_t> makeMra1(uint32_t seq, uint64_t captureUs, uint8_t flags,
                                     const std::vector<int16_t>& interleaved) {
    auto p = makeMra1Header(kVersionPcm, seq, captureUs, flags, uint16_t(interleaved.size() / kChannels));
    for (int16_t s : interleaved) {
        const uint16_t u = uint16_t(s);
        p.push_back(uint8_t(u));
        p.push_back(uint8_t(u >> 8));
    }
    return p;
}

// Test helper: builds one MRA1 v2 (Opus) datagram.
inline std::vector<uint8_t> makeMra1Opus(uint32_t seq, uint64_t captureUs, uint8_t flags, uint16_t frames,
                                         const uint8_t* opus, size_t bytes) {
    auto p = makeMra1Header(kVersionOpus, seq, captureUs, flags, frames);
    p.insert(p.end(), opus, opus + bytes);
    return p;
}

inline const char* codecName(uint8_t version) {
    return version == kVersionOpus ? "opus" : version == kVersionPcm ? "pcm" : "none";
}

struct JitterStats {
    uint8_t codec = 0;           // version of the stream being played (0 = none yet)
    uint16_t packetFrames = 0;   // frames per packet of that stream
    uint64_t packetsRx = 0;
    uint64_t payloadBytes = 0;   // MRA1 payload bytes received (bitrate)
    uint64_t lost = 0;           // packets never received when their turn came
    uint64_t late = 0;           // arrived after their turn had passed, or of a stale codec (dropped)
    uint64_t duplicates = 0;
    uint64_t underruns = 0;      // buffer ran dry while playing
    uint64_t overflowDrops = 0;  // packets dropped because the buffer grew past target + 30 ms
    uint64_t idleDrops = 0;      // packets dropped past the target while no output device was playing
    uint64_t resets = 0;         // host restart flag, codec change or a large sequence jump
    uint64_t fecRecovered = 0;   // lost Opus packets rebuilt from the next packet's in-band FEC
    uint64_t plcFrames = 0;      // frames concealed by Opus PLC (lost packets without FEC)
    uint64_t decodeErrors = 0;
    uint64_t driftInserted = 0;  // packets stretched by one frame (buffer below target)
    uint64_t driftDropped = 0;   // packets shrunk by one frame (buffer above target)
    uint64_t framesPlayed = 0;
    uint64_t framesSilence = 0;  // prebuffer, underrun and PCM loss frames
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
    // Drift control: 1 s windows; stretch below set point - 3 ms, shrink above set point + 5 ms.
    static constexpr int kDriftWindowFrames = kSampleRate;
    static constexpr double kDriftLowMs = 3.0;
    static constexpr double kDriftHighMs = 5.0;

    JitterBuffer() = default;
    ~JitterBuffer() {
        if (dec_) opus_decoder_destroy(dec_);
    }
    JitterBuffer(const JitterBuffer&) = delete;
    JitterBuffer& operator=(const JitterBuffer&) = delete;

    // A1 behaviour for comparisons: no drift correction.
    void setDriftControl(bool on) {
        driftControl_ = on;
        resetDrift();
    }

    // False while the player has no device pulling (see "Output gaps" at the
    // top). Going active flushes to the live edge and prebuffers again.
    void setOutputActive(bool active) {
        if (active == outputActive_) return;
        outputActive_ = active;
        if (!active || !started_) return;
        // The packet that was playing when the old device went away is stale.
        cur_.clear();
        curPos_ = 0;
        curSilent_ = false;
        trimTo(targetMs_, stats_.idleDrops);
        prebuffering_ = true;
        steadyFrames_ = 0;
        resetDrift();
        if (dec_) opus_decoder_ctl(dec_, OPUS_RESET_STATE);
    }
    bool outputActive() const { return outputActive_; }

    // arrivalUs: viewer monotonic clock at receive time.
    void push(const Mra1Packet& pkt, uint64_t arrivalUs) {
        ++stats_.packetsRx;
        stats_.payloadBytes += pkt.payloadBytes;
        const bool restart = (pkt.flags & kFlagRestart) != 0;
        if (started_ && pkt.version != codec_ && !restart) {
            // A straggler from before a codec switch (the switch itself
            // carries the restart flag).
            ++stats_.late;
            return;
        }
        if (!started_ || restart) {
            if (started_) ++stats_.resets;
            codec_ = pkt.version;
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
        Stored s;
        s.frames = pkt.frames;
        s.data.assign(pkt.payload, pkt.payload + pkt.payloadBytes);
        bufferedFrames_ += pkt.frames;
        packetFrames_ = pkt.frames;
        packets_.emplace(ext, std::move(s));
        trimOverflow();
    }

    // Fills `frames` interleaved stereo frames; always writes all of them.
    void pull(int16_t* out, size_t frames) {
        size_t done = 0;
        const double before = bufferedMs();
        while (done < frames) {
            if (prebuffering_) {
                if (started_ && bufferedMs() >= targetMs_) {
                    prebuffering_ = false;
                    driftSetMs_ = targetMs_;
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
                    resetDrift();
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
            done += n;
            adaptAfterPlaying(n);
        }
        observeDrift(frames, before);
    }

    JitterStats stats() const {
        JitterStats s = stats_;
        s.codec = codec_;
        s.packetFrames = uint16_t(packetFrames_);
        s.targetMs = targetMs_;
        s.jitterMs = jitterUs_ / 1000.0;
        s.bufferedMs = bufferedMs();
        return s;
    }
    bool prebuffering() const { return prebuffering_; }
    int driftMode() const { return driftMode_; }

private:
    struct Stored {
        uint16_t frames = 0;
        std::vector<uint8_t> data;
    };

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
        resetDrift();
        if (dec_) opus_decoder_ctl(dec_, OPUS_RESET_STATE);
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
            const double desired = desiredTargetMs();
            if (desired > targetMs_) targetMs_ = desired;
        }
        havePrev_ = true;
        prevArrivalUs_ = arrivalUs;
        prevCaptureUs_ = captureUs;
    }

    // 4x the RFC 3550 jitter + 5 ms. Packets longer than 5 ms (Opus: 10 ms)
    // add the extra length: a late packet is covered by the next one only
    // after a whole packet time, so 10 ms packets need ~5 ms more slack than
    // A1's 5 ms PCM for the same underrun rate (simulated on the wifi case).
    double desiredTargetMs() const {
        const double pktMs = double(packetFrames_) * 1000.0 / kSampleRate;
        return std::clamp(4.0 * jitterUs_ / 1000.0 + 5.0 + std::max(0.0, pktMs - 5.0), kMinTargetMs, kMaxTargetMs);
    }

    bool ensureDecoder() {
        if (dec_) return true;
        int err = 0;
        dec_ = opus_decoder_create(kSampleRate, kChannels, &err);
        return dec_ != nullptr;
    }

    // Decodes `s` (or conceals when s is null; fec: rebuild the packet before
    // `s` from its in-band FEC) into cur_. False on a decoder error.
    bool decodeOpus(const Stored* s, int frames, bool fec) {
        if (!ensureDecoder()) return false;
        cur_.assign(size_t(frames) * kChannels, 0);
        const int n = opus_decode(dec_, s ? s->data.data() : nullptr, s ? opus_int32(s->data.size()) : 0,
                                  cur_.data(), frames, fec ? 1 : 0);
        if (n <= 0) return false;
        cur_.resize(size_t(n) * kChannels);
        return true;
    }

    bool loadNext() {
        cur_.clear();
        curPos_ = 0;
        curSilent_ = false;
        if (packets_.empty()) return false;
        auto it = packets_.begin();
        if (it->first == next_) {
            bufferedFrames_ -= std::min<uint64_t>(bufferedFrames_, it->second.frames);
            if (codec_ == kVersionOpus) {
                if (!decodeOpus(&it->second, it->second.frames, false)) {
                    ++stats_.decodeErrors;
                    concealSilence(it->second.frames);
                }
            } else {
                cur_.resize(size_t(it->second.frames) * kChannels);
                std::memcpy(cur_.data(), it->second.data.data(), cur_.size() * 2);  // s16 LE on x86/ARM
            }
            packets_.erase(it);
            applyDrift();
        } else {
            // Our packet is missing but a later one is here.
            ++stats_.lost;
            const int frames = it->second.frames;  // the host uses one packet size
            if (codec_ == kVersionOpus) {
                const bool nextIsHere = it->first == next_ + 1;
                if (nextIsHere && decodeOpus(&it->second, frames, true)) {
                    // Without LBRR data in the next packet libopus ran PLC.
                    if (opus_packet_has_lbrr(it->second.data.data(), opus_int32(it->second.data.size())) > 0)
                        ++stats_.fecRecovered;
                    else
                        stats_.plcFrames += cur_.size() / kChannels;
                } else if (decodeOpus(nullptr, frames, false)) {
                    stats_.plcFrames += cur_.size() / kChannels;
                } else {
                    ++stats_.decodeErrors;
                    concealSilence(frames);
                }
            } else {
                // PCM: play silence in its place so timing stays intact.
                concealSilence(frames);
            }
        }
        ++next_;
        return true;
    }

    void concealSilence(int frames) {
        cur_.assign(size_t(frames) * kChannels, 0);
        curSilent_ = true;
    }

    // Stretches or shrinks the packet just loaded by one frame while drift
    // control says so. Linear interpolation, end points kept.
    void applyDrift() {
        if (driftMode_ == 0 || curSilent_) return;
        const size_t f = cur_.size() / kChannels;
        if (f < 8) return;
        const size_t g = driftMode_ > 0 ? f + 1 : f - 1;
        std::vector<int16_t> o(g * kChannels);
        const double step = double(f - 1) / double(g - 1);
        for (size_t j = 0; j < g; ++j) {
            const double x = double(j) * step;
            size_t i = size_t(x);
            double fr = x - double(i);
            if (i >= f - 1) { i = f - 2; fr = 1.0; }
            for (int c = 0; c < kChannels; ++c) {
                const double v = cur_[i * kChannels + c] * (1.0 - fr) + cur_[(i + 1) * kChannels + c] * fr;
                o[j * kChannels + c] = int16_t(std::lround(std::clamp(v, -32768.0, 32767.0)));
            }
        }
        cur_.swap(o);
        if (driftMode_ > 0) ++stats_.driftInserted; else ++stats_.driftDropped;
    }

    // Stretching also starts when the window's lowest margin (depth minus the
    // packet being played) falls under 3 ms, so 10 ms packets keep the same
    // slack against late packets as 5 ms ones.
    // Shrinking starts only when even the window's lowest depth is above the
    // set point: a buffer that still dips (jitter, bursts) keeps its margin.
    // Hysteresis: once on, stretching (shrinking) continues until the
    // average is back at the set point.
    void observeDrift(size_t frames, double beforeMs) {
        if (!driftControl_ || prebuffering_) return;
        driftSumMs_ += beforeMs * double(frames);
        driftMinMs_ = driftFrames_ == 0 ? beforeMs : std::min(driftMinMs_, beforeMs);
        driftFrames_ += int(frames);
        if (driftFrames_ < kDriftWindowFrames) return;
        const double avg = driftSumMs_ / double(driftFrames_);
        driftSumMs_ = 0;
        driftFrames_ = 0;
        driftSetMs_ = std::max(driftSetMs_, targetMs_);
        // The lowest depth before a pull includes the packet being played,
        // so the real margin is that minus one packet.
        const double margin = driftMinMs_ - double(packetFrames_) / (kSampleRate / 1000.0);
        if (avg < driftSetMs_ - kDriftLowMs || margin < kDriftLowMs) driftMode_ = 1;
        else if (avg > driftSetMs_ + kDriftHighMs && driftMinMs_ > driftSetMs_) driftMode_ = -1;
        else if ((driftMode_ > 0 && avg >= driftSetMs_) || (driftMode_ < 0 && avg <= driftSetMs_)) driftMode_ = 0;
    }

    void resetDrift() {
        driftMode_ = 0;
        driftSumMs_ = 0;
        driftFrames_ = 0;
    }

    void trimOverflow() {
        if (outputActive_) trimTo(targetMs_ + kOverflowSlackMs, stats_.overflowDrops);
        else trimTo(targetMs_, stats_.idleDrops);
    }

    // Drops the oldest buffered audio until at most `limitMs` is left.
    void trimTo(double limitMs, uint64_t& counter) {
        while (!packets_.empty() && bufferedMs() > limitMs) {
            auto it = packets_.begin();
            bufferedFrames_ -= std::min<uint64_t>(bufferedFrames_, it->second.frames);
            next_ = it->first + 1;
            packets_.erase(it);
            ++counter;
            // The Opus decoder skips a packet: conceal nothing, it resyncs on
            // the next one (CELT recovers within a frame).
        }
    }

    void adaptAfterPlaying(size_t frames) {
        steadyFrames_ += int(frames);
        if (steadyFrames_ >= kShrinkAfterFrames) {
            steadyFrames_ = 0;
            const double desired = desiredTargetMs();
            if (targetMs_ - 1.0 >= desired) targetMs_ -= 1.0;
        }
    }

    void silence(int16_t* out, size_t frames) {
        std::fill(out, out + frames * kChannels, int16_t(0));
        stats_.framesSilence += frames;
    }

    // Received audio not yet played: queued packets plus the rest of the
    // packet being played.
    double bufferedMs() const {
        const size_t curLeft = cur_.empty() ? 0 : cur_.size() / kChannels - std::min(curPos_, cur_.size() / kChannels);
        return double(bufferedFrames_ + curLeft) * 1000.0 / kSampleRate;
    }

    std::map<int64_t, Stored> packets_;
    std::vector<int16_t> cur_;
    size_t curPos_ = 0;
    bool curSilent_ = false;
    uint64_t bufferedFrames_ = 0;  // frames in packets_ (not yet loaded)
    uint32_t base_ = 0;
    int64_t next_ = 0;             // next packet index to load
    uint8_t codec_ = 0;
    int packetFrames_ = 0;
    bool started_ = false;
    bool prebuffering_ = true;
    bool havePrev_ = false;
    uint64_t prevArrivalUs_ = 0;
    uint64_t prevCaptureUs_ = 0;
    double jitterUs_ = 0;
    double targetMs_ = kInitialTargetMs;
    int steadyFrames_ = 0;
    bool driftControl_ = true;
    bool outputActive_ = true;
    int driftMode_ = 0;
    double driftSumMs_ = 0;
    double driftMinMs_ = 0;
    int driftFrames_ = 0;
    double driftSetMs_ = kInitialTargetMs;  // drift control set point (see the top of the file)
    OpusDecoder* dec_ = nullptr;
    JitterStats stats_;
};

}  // namespace jl::audio
