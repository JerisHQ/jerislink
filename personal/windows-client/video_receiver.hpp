#pragma once
// MR02 video receive logic, kept free of Win32 so it can be unit-tested
// (video_receiver_test.cpp). viewer.cpp feeds it packets and wires the hooks
// to the decoder and to the MRM1 channel.
//
// Modes:
// - legacy / strict: the pre-NACK behaviour, unchanged. Strict drops an
//   assembling frame once it is 2 frames behind the newest frame, or a
//   complete frame after a gap, and then waits for a keyframe (0x40).
// - strict + NACK (host advertised 0x20): holes are requested again with an
//   MRM1 0x41 message and later complete frames are held until the hole is
//   repaired. A hole that is still open after holdMs (40 ms, D1-A) falls back
//   to the strict behaviour.
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <functional>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace jl {

struct NackRange {
    uint16_t start = 0;
    uint16_t count = 0;  // (0, 0xFFFF) = the whole frame
};

struct ReceiverConfig {
    bool strict = true;          // --loss-recovery strict
    bool nack = false;           // only used together with strict
    double holdMs = 40.0;        // D1-A: fixed hold per hole
    double reorderGraceMs = 2.0; // a lower index may still arrive this late
    int reorderDepth = 4;        // ... or this many indices behind the newest
    int maxNackAttempts = 2;
    double minRetryMs = 8.0;     // second NACK after max(1.2 x RTT, this)
    double defaultRttMs = 20.0;  // until a measured RTT is known
    size_t maxHeldFrames = 16;
    size_t maxRangesPerNack = 32;
};

struct ReceiverHooks {
    std::function<void(uint64_t fid, const std::vector<uint8_t>& frame, bool discontinuity, bool keyFrame)> submit;
    std::function<void()> resetForNewStream;
    std::function<void()> requestKeyframe;
    std::function<void(uint64_t fid, const std::vector<NackRange>& ranges)> sendNack;
    std::function<void(const std::string&)> log;
};

struct ReceiverStats {
    // Same meaning as the existing SUMMARY fields.
    uint64_t packets = 0, bad = 0, complete = 0, incompleteDropped = 0, streamRestarts = 0;
    uint64_t strictRecoveryEvents = 0, lateFramesDropped = 0, recoveryWaitPacketDrops = 0;
    // NACK mode.
    uint64_t nackTx = 0;              // 0x41 messages sent
    uint64_t nackPacketsRequested = 0;// indices asked for (whole frame counts as 1)
    uint64_t nackWholeFrames = 0;     // whole-frame requests
    uint64_t lostPacketsRaw = 0;      // distinct packets found missing (first NACK)
    uint64_t framesRepaired = 0;      // frames completed after a NACK
    uint64_t nackDeadlineMiss = 0;    // hole not repaired within holdMs -> keyframe
    uint64_t heldCapMiss = 0;         // too many frames held -> keyframe
    uint64_t retransmitRx = 0;        // packets with flag 0x04
    uint64_t duplicatePackets = 0;
    uint64_t latePacketsIgnored = 0;  // packets of frames already submitted
    uint64_t keyframeJumps = 0;       // complete keyframe ended a hold early
    uint64_t heldFramesMax = 0;
    std::vector<float> repairMs;      // first NACK -> frame complete, capped
};

inline uint16_t receiverBe16(const uint8_t* p) {
    return static_cast<uint16_t>((uint16_t(p[0]) << 8) | uint16_t(p[1]));
}
inline uint64_t receiverBe64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | uint64_t(p[i]);
    return v;
}

// Percentile of a sample (0 when empty); p in [0, 100].
inline double receiverPercentile(std::vector<float> v, double p) {
    if (v.empty()) return 0.0;
    std::sort(v.begin(), v.end());
    size_t i = static_cast<size_t>(p / 100.0 * double(v.size() - 1) + 0.5);
    return v[std::min(i, v.size() - 1)];
}

class VideoReceiver {
public:
    VideoReceiver(ReceiverConfig cfg, ReceiverHooks hooks) : cfg_(cfg), h_(std::move(hooks)) {
        if (!cfg_.strict) cfg_.nack = false;
    }

    bool nackActive() const { return cfg_.nack; }
    const ReceiverStats& stats() const { return st_; }
    void setRttMs(double rtt) { if (rtt > 0) rttMs_ = rtt; }
    double rttMs() const { return rttMs_ > 0 ? rttMs_ : cfg_.defaultRttMs; }
    size_t heldFrames() const { return assembling_.size(); }

    // Same as the old start of the receive loop.
    void start() {
        waiting_ = cfg_.strict;
        forceDisc_ = cfg_.strict;
        if (cfg_.strict) {
            reset();
            log("loss.strict_wait_for_keyframe reason=startup");
            requestKeyframe();
        }
    }

    // One UDP datagram from the allowed host. packetGapMs: time since the
    // previous datagram (0 for the first one), used by restart detection.
    void onPacket(const uint8_t* buf, size_t n, double nowMs, long long packetGapMs) {
        ++st_.packets;
        if (n < 20 || std::memcmp(buf, "MR02", 4) || buf[4] != 1) { ++st_.bad; return; }
        const uint8_t flags = buf[5];
        const uint64_t fid = receiverBe64(buf + 6);
        const uint16_t idx = receiverBe16(buf + 14), cnt = receiverBe16(buf + 16), len = receiverBe16(buf + 18);
        if (!cnt || idx >= cnt || len != static_cast<uint16_t>(n - 20)) { ++st_.bad; return; }

        const bool frameWentBackward = newest_ > 0 && fid + 2 < newest_;
        const bool farBackward = newest_ > fid + 120;
        const bool earlyRestart = frameWentBackward && fid <= 5;
        const bool gapRestart = frameWentBackward && packetGapMs >= 250;
        if (frameWentBackward && (farBackward || earlyRestart || gapRestart)) {
            std::ostringstream restart;
            restart << "stream.restart_detected old_newest=" << newest_
                    << " new_fid=" << fid
                    << " gap_ms=" << packetGapMs
                    << " key=" << ((flags & 0x01) ? 1 : 0);
            log(restart.str());
            assembling_.clear();
            newest_ = fid;
            lastSubmitted_ = 0;
            waiting_ = true;
            forceDisc_ = true;
            reset();
            requestKeyframe();
            ++st_.streamRestarts;
        }

        if (cfg_.nack) onPacketNack(flags, fid, idx, cnt, buf + 20, len, nowMs);
        else onPacketStrict(flags, fid, idx, cnt, buf + 20, len);
    }

    // Timers (NACK retry, hold deadline). Call often: on every packet and on
    // every receive timeout.
    void tick(double nowMs) {
        if (!cfg_.nack) return;
        service(nowMs);
    }

private:
    struct Frame {
        uint16_t count = 0;   // 0 = placeholder, no packet seen yet
        bool key = false;
        std::vector<std::vector<uint8_t>> parts;
        std::vector<uint8_t> nacked;  // per index: NACK attempts
        std::vector<bool> present;
        size_t received = 0;
        int maxIndex = -1;
        double holeMs = -1;        // first time a hole was seen (deadline base)
        double lastPacketMs = 0;
        double lastNackMs = -1;
        double firstNackMs = -1;
        int wholeNacks = 0;        // placeholder only

        void init(uint16_t cnt) {
            count = cnt;
            parts.assign(cnt, {});
            present.assign(cnt, false);
            nacked.assign(cnt, 0);
        }
        bool add(uint16_t index, const uint8_t* data, size_t size, bool k) {
            if (index >= count || present[index]) return false;
            parts[index].assign(data, data + size);
            present[index] = true;
            key = key || k;
            ++received;
            maxIndex = std::max(maxIndex, int(index));
            return true;
        }
        bool complete() const { return count && received == count; }
        std::vector<uint8_t> join() const {
            size_t total = 0;
            for (const auto& p : parts) total += p.size();
            std::vector<uint8_t> out;
            out.reserve(total);
            for (const auto& p : parts) out.insert(out.end(), p.begin(), p.end());
            return out;
        }
    };

    void log(const std::string& s) { if (h_.log) h_.log(s); }
    void reset() { if (h_.resetForNewStream) h_.resetForNewStream(); }
    void requestKeyframe() { if (h_.requestKeyframe) h_.requestKeyframe(); }
    void submit(uint64_t fid, const Frame& f, bool disc) {
        if (h_.submit) h_.submit(fid, f.join(), disc, f.key);
        ++st_.complete;
    }

    // ---- legacy / strict: the pre-NACK loop body, unchanged ----
    void onPacketStrict(uint8_t flags, uint64_t fid, uint16_t idx, uint16_t cnt,
                        const uint8_t* payload, uint16_t len) {
        const bool strict = cfg_.strict;
        newest_ = std::max(newest_, fid);
        if (waiting_ && (flags & 0x01) == 0) {
            ++st_.recoveryWaitPacketDrops;
            requestKeyframe();
            return;
        }
        bool staleLossDetected = false;
        for (auto it = assembling_.begin(); it != assembling_.end();) {
            if (it->first + 2 < newest_) {
                ++st_.incompleteDropped;
                staleLossDetected = true;
                it = assembling_.erase(it);
            } else ++it;
        }
        if (strict && staleLossDetected) {
            ++st_.strictRecoveryEvents;
            waiting_ = true;
            forceDisc_ = true;
            lastSubmitted_ = 0;
            assembling_.clear();
            reset();
            log("loss.strict_wait_for_keyframe reason=stale_incomplete newest=" + std::to_string(newest_));
            requestKeyframe();
            if ((flags & 0x01) == 0) {
                ++st_.recoveryWaitPacketDrops;
                return;
            }
        }
        auto it = assembling_.find(fid);
        if (it == assembling_.end()) {
            it = assembling_.emplace(fid, Frame{}).first;
            it->second.init(cnt);
        }
        if (it->second.count != cnt) { ++st_.bad; assembling_.erase(it); return; }
        it->second.add(idx, payload, len, (flags & 0x01) != 0);
        if (!it->second.complete()) return;

        const bool keyFrame = it->second.key;
        if (strict && lastSubmitted_ && fid <= lastSubmitted_) {
            ++st_.lateFramesDropped;
            log("loss.strict_drop_late fid=" + std::to_string(fid) + " last=" + std::to_string(lastSubmitted_));
            assembling_.erase(it);
            return;
        }
        if (strict && lastSubmitted_ && fid > lastSubmitted_ + 1) {
            ++st_.strictRecoveryEvents;
            waiting_ = true;
            forceDisc_ = true;
            lastSubmitted_ = 0;
            reset();
            log("loss.strict_wait_for_keyframe reason=frame_gap fid=" + std::to_string(fid));
            requestKeyframe();
            if (!keyFrame) {
                assembling_.clear();
                return;
            }
        }
        const bool discontinuity = forceDisc_ || (lastSubmitted_ && fid != lastSubmitted_ + 1);
        submit(fid, it->second, discontinuity);
        lastSubmitted_ = fid;
        if (waiting_) {
            waiting_ = false;
            log("stream.keyframe_reacquired fid=" + std::to_string(fid));
        }
        forceDisc_ = false;
        assembling_.erase(it);
    }

    // ---- strict + NACK ----
    void onPacketNack(uint8_t flags, uint64_t fid, uint16_t idx, uint16_t cnt,
                      const uint8_t* payload, uint16_t len, double now) {
        const bool key = (flags & 0x01) != 0;
        if (flags & 0x04) ++st_.retransmitRx;
        const uint64_t prevNewest = newest_;
        newest_ = std::max(newest_, fid);

        if (waiting_ && !key) {
            ++st_.recoveryWaitPacketDrops;
            requestKeyframe();
            service(now);
            return;
        }
        if (lastSubmitted_ && fid <= lastSubmitted_) {
            ++st_.latePacketsIgnored;
            return;
        }
        // Whole frames skipped between the newest frame and this one.
        if (!waiting_ && fid > prevNewest + 1) {
            const uint64_t from = std::max(prevNewest, lastSubmitted_) + 1;
            if (fid - from > cfg_.maxHeldFrames) {
                enterRecovery("frame_gap fid=" + std::to_string(fid), false);
                ++st_.heldCapMiss;
                if (!key) { ++st_.recoveryWaitPacketDrops; return; }
            } else {
                for (uint64_t f = from; f < fid; ++f) {
                    auto& ph = assembling_[f];
                    if (ph.count == 0 && ph.holeMs < 0) ph.holeMs = now;
                }
            }
        }

        Frame& fr = assembling_[fid];
        if (fr.count == 0) {
            fr.init(cnt);
        } else if (fr.count != cnt) {
            ++st_.bad;
            return;
        }
        if (!fr.add(idx, payload, len, key)) {
            ++st_.duplicatePackets;
            return;
        }
        fr.lastPacketMs = now;
        if (fr.complete() && fr.firstNackMs >= 0) {
            ++st_.framesRepaired;
            if (st_.repairMs.size() < 100000) st_.repairMs.push_back(float(now - fr.firstNackMs));
        }
        st_.heldFramesMax = std::max<uint64_t>(st_.heldFramesMax, assembling_.size());
        drain();
        service(now);
    }

    // Submit what can go out in order.
    void drain() {
        for (;;) {
            if (waiting_) {
                auto it = std::find_if(assembling_.begin(), assembling_.end(),
                                       [](const auto& e) { return e.second.complete() && e.second.key; });
                if (it == assembling_.end()) return;
                const uint64_t fid = it->first;
                submit(fid, it->second, true);
                lastSubmitted_ = fid;
                waiting_ = false;
                forceDisc_ = false;
                log("stream.keyframe_reacquired fid=" + std::to_string(fid));
                assembling_.erase(assembling_.begin(), std::next(it));
                continue;
            }
            auto next = assembling_.find(lastSubmitted_ + 1);
            if (next != assembling_.end() && next->second.complete()) {
                submit(next->first, next->second, forceDisc_);
                forceDisc_ = false;
                lastSubmitted_ = next->first;
                assembling_.erase(assembling_.begin(), std::next(next));
                continue;
            }
            // A complete keyframe past the hole needs no repair.
            auto key = std::find_if(assembling_.begin(), assembling_.end(), [&](const auto& e) {
                return e.first > lastSubmitted_ + 1 && e.second.complete() && e.second.key;
            });
            if (key != assembling_.end()) {
                for (auto it = assembling_.begin(); it != key; ++it)
                    if (!it->second.complete()) ++st_.incompleteDropped;
                ++st_.keyframeJumps;
                submit(key->first, key->second, true);
                forceDisc_ = false;
                lastSubmitted_ = key->first;
                log("loss.nack_keyframe_jump fid=" + std::to_string(key->first));
                assembling_.erase(assembling_.begin(), std::next(key));
                continue;
            }
            return;
        }
    }

    // Deadline-miss fallback: the strict behaviour. Complete or partial
    // keyframes after dropUpTo are kept; they end the wait.
    void enterRecovery(const std::string& reason, bool countMiss, uint64_t dropUpTo = 0) {
        if (countMiss) ++st_.nackDeadlineMiss;
        ++st_.strictRecoveryEvents;
        for (auto it = assembling_.begin(); it != assembling_.end();) {
            if (it->first > dropUpTo && it->second.count && it->second.key) { ++it; continue; }
            if (!it->second.complete()) ++st_.incompleteDropped;
            it = assembling_.erase(it);
        }
        waiting_ = true;
        forceDisc_ = true;
        lastSubmitted_ = 0;
        reset();
        log("loss.strict_wait_for_keyframe reason=" + reason);
        requestKeyframe();
    }

    void service(double now) {
        if (assembling_.size() > cfg_.maxHeldFrames && !waiting_) {
            ++st_.heldCapMiss;
            enterRecovery("nack_held_cap held=" + std::to_string(assembling_.size()), false);
            drain();
            return;
        }
        const double retryMs = std::max(cfg_.minRetryMs, 1.2 * rttMs());
        for (auto it = assembling_.begin(); it != assembling_.end();) {
            const uint64_t fid = it->first;
            Frame& fr = it->second;
            if (fr.complete()) { ++it; continue; }
            const bool laterSeen = newest_ > fid;

            std::vector<NackRange> ranges;
            bool anyHole = false;
            uint64_t freshIndices = 0;
            bool retryDue = fr.lastNackMs < 0 || now - fr.lastNackMs >= retryMs;
            if (fr.count == 0) {
                anyHole = laterSeen;
                if (anyHole && fr.wholeNacks < cfg_.maxNackAttempts && (fr.wholeNacks == 0 || retryDue)) {
                    ranges.push_back({0, 0xFFFF});
                    if (fr.wholeNacks == 0) { ++st_.nackWholeFrames; ++st_.lostPacketsRaw; }
                    ++fr.wholeNacks;
                    freshIndices = 1;
                }
            } else {
                const bool graceOver = now - fr.lastPacketMs >= cfg_.reorderGraceMs;
                const int limit = laterSeen ? int(fr.count) : fr.maxIndex;
                for (int i = 0; i < limit; ++i) {
                    if (fr.present[i]) continue;
                    if (!laterSeen && !graceOver && fr.maxIndex - i < cfg_.reorderDepth) continue;
                    anyHole = true;
                    const bool fresh = fr.nacked[i] == 0;
                    if (!fresh && (fr.nacked[i] >= cfg_.maxNackAttempts || !retryDue)) continue;
                    if (fresh) ++st_.lostPacketsRaw;
                    ++fr.nacked[i];
                    ++freshIndices;
                    if (!ranges.empty() && ranges.back().start + ranges.back().count == i &&
                        ranges.back().count < 0xFFFF) {
                        ++ranges.back().count;
                    } else if (ranges.size() < cfg_.maxRangesPerNack) {
                        ranges.push_back({uint16_t(i), 1});
                    } else {
                        --fr.nacked[i];  // no room: next pass
                        --freshIndices;
                        if (fresh) --st_.lostPacketsRaw;
                    }
                }
            }
            if (anyHole && fr.holeMs < 0) fr.holeMs = now;
            if (fr.holeMs >= 0 && now - fr.holeMs > cfg_.holdMs) {
                enterRecovery("nack_deadline fid=" + std::to_string(fid), true, fid);
                drain();
                return;  // iterators invalid
            }
            if (!ranges.empty()) {
                if (h_.sendNack) h_.sendNack(fid, ranges);
                ++st_.nackTx;
                st_.nackPacketsRequested += freshIndices;
                fr.lastNackMs = now;
                if (fr.firstNackMs < 0) fr.firstNackMs = now;
            }
            ++it;
        }
    }

    ReceiverConfig cfg_;
    ReceiverHooks h_;
    ReceiverStats st_;
    std::map<uint64_t, Frame> assembling_;
    uint64_t newest_ = 0, lastSubmitted_ = 0;
    bool waiting_ = false, forceDisc_ = false;
    double rttMs_ = 0;
};

// MRM1 0x41 NACK message, 19 + 4n bytes.
inline std::vector<uint8_t> encodeNack(uint32_t seq, uint64_t fid, const std::vector<NackRange>& ranges) {
    const size_t n = std::min<size_t>(ranges.size(), 32);
    std::vector<uint8_t> p{'M', 'R', 'M', '1', 1, 0x41,
                           uint8_t(seq >> 24), uint8_t(seq >> 16), uint8_t(seq >> 8), uint8_t(seq)};
    for (int i = 7; i >= 0; --i) p.push_back(uint8_t(fid >> (8 * i)));
    p.push_back(uint8_t(n));
    for (size_t i = 0; i < n; ++i) {
        p.push_back(uint8_t(ranges[i].start >> 8)); p.push_back(uint8_t(ranges[i].start));
        p.push_back(uint8_t(ranges[i].count >> 8)); p.push_back(uint8_t(ranges[i].count));
    }
    return p;
}

}  // namespace jl
