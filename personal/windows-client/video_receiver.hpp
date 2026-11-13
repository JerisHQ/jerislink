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
//   to the strict behaviour. The deadline is checked before a packet is
//   accepted, so a repair that comes too late never counts. At most 2 NACKs
//   per frame, the second RTT-spaced; an index is NACKed only after a 2 ms
//   reorder grace. Retransmits (flag 0x04) never look like a stream restart.
//   While RTT + grace does not fit inside holdMs (e.g. DERP) a repair cannot
//   arrive in time, so NACK pauses and the strict path runs, as with NACK off.
//   Frames already held when NACK pauses keep their deadline: they are
//   settled on the NACK path (no new NACKs) before the strict path takes over.
// - All modes: frames never go backwards within one stream (a submitted
//   watermark survives recovery; only a real restart resets it), and packet
//   loss is counted per (frame id, index), de-duplicated (PacketLossCounter).
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
    double reorderGraceMs = 2.0; // a missing index is only NACKed after this long
    int maxNackAttempts = 2;     // NACK messages per frame
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
    uint64_t lostPacketsRaw = 0;      // distinct holes NACKed (index, or whole frame as 1)
    uint64_t holesRecovered = 0;      // of those, filled while the frame was still held
    uint64_t originalPackets = 0;     // valid packets without flag 0x04 (loss % base)
    uint64_t framesRepaired = 0;      // frames completed after a NACK
    uint64_t nackDeadlineMiss = 0;    // hole not repaired within holdMs -> keyframe
    uint64_t nackPausedRtt = 0;       // times NACK paused because RTT + grace >= holdMs
    uint64_t heldCapMiss = 0;         // too many frames held -> keyframe
    uint64_t retransmitRx = 0;        // packets with flag 0x04
    uint64_t duplicatePackets = 0;
    uint64_t latePacketsIgnored = 0;  // packets of frames already submitted
    uint64_t keyframeJumps = 0;       // complete keyframe ended a hold early
    uint64_t heldFramesMax = 0;
    std::vector<float> repairMs;      // first NACK -> frame complete, capped
    // Packet loss in every mode (off, paused, on), from PacketLossCounter.
    // Counted when a frame is finalized (32 frames behind the newest).
    uint64_t lossExpected = 0;        // packets the host sent as originals
    uint64_t lossRaw = 0;             // of those, never arrived as an original
    uint64_t lossAfterNack = 0;       // never arrived at all, nor repaired in time
    uint64_t lossWholeFrames = 0;     // frames with no packet at all (size estimated)
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

// Loss in percent of the packets the host sent (PacketLossCounter totals):
// raw = never arrived as an original, afterNack = still missing after repair.
struct ReceiverLoss {
    double rawPct = 0, afterNackPct = 0;
};
inline ReceiverLoss receiverLoss(uint64_t expected, uint64_t lostRaw, uint64_t lostAfterNack) {
    ReceiverLoss l;
    if (expected == 0) return l;
    l.rawPct = 100.0 * double(lostRaw) / double(expected);
    l.afterNackPct = 100.0 * double(lostAfterNack) / double(expected);
    return l;
}

// Packet loss by sequence number, independent of the receive mode. MR02 has
// no packet counter, so the sequence is (frame id, index): frame ids are
// consecutive and each packet carries the frame's packet count. Duplicates
// are ignored. A frame is finalized once it is kFinalizeLag frames behind the
// newest one (well past the 40 ms hold); packets that come later count as
// lost. A frame with no packet at all is counted with the mean size of the
// frames seen so far (an estimate, also counted in wholeFrames).
class PacketLossCounter {
public:
    static constexpr uint64_t kFinalizeLag = 32;

    // A packet without flag 0x04.
    void original(uint64_t fid, uint16_t idx, uint16_t cnt) { mark(fid, idx, cnt, true); }
    // A retransmit the receiver accepted while the frame was still wanted.
    void repaired(uint64_t fid, uint16_t idx, uint16_t cnt) { mark(fid, idx, cnt, false); }
    // Stream restart: count what is open, then start over.
    void restart() {
        finalizeUpTo(newest_);
        frames_.clear();
        started_ = false;
        newest_ = finalized_ = 0;
    }
    // End of session: count the frames still inside the lag.
    void flush() { finalizeUpTo(newest_); }

    uint64_t expected = 0, lostRaw = 0, lostAfterNack = 0, wholeFrames = 0;

private:
    struct F {
        uint16_t count = 0;
        uint32_t orig = 0, any = 0;
        std::vector<uint8_t> bits;  // 1 = original, 2 = repaired
    };

    void mark(uint64_t fid, uint16_t idx, uint16_t cnt, bool orig) {
        if (!cnt || idx >= cnt) return;
        if (!started_) {
            if (!orig) return;  // a stray repair cannot start the count
            started_ = true;
            finalized_ = fid ? fid - 1 : 0;
            newest_ = fid;
        }
        if (fid <= finalized_) return;  // too late, already counted as lost
        F& f = frames_[fid];
        if (f.count == 0) { f.count = cnt; f.bits.assign(cnt, 0); }
        if (f.count != cnt) return;
        uint8_t& b = f.bits[idx];
        if (orig) {
            if (!(b & 1)) { if (!b) ++f.any; b |= 1; ++f.orig; }
        } else if (!b) {
            b = 2;
            ++f.any;
        }
        if (fid > newest_) newest_ = fid;
        if (newest_ > kFinalizeLag) finalizeUpTo(newest_ - kFinalizeLag);
    }

    void missingFrames(uint64_t n) {
        if (!n) return;
        const uint64_t est = seenFrames_ ? std::max<uint64_t>(1, (seenPackets_ + seenFrames_ / 2) / seenFrames_) : 1;
        expected += n * est;
        lostRaw += n * est;
        lostAfterNack += n * est;
        wholeFrames += n;
    }

    void finalizeUpTo(uint64_t t) {
        while (!frames_.empty() && frames_.begin()->first <= t) {
            auto it = frames_.begin();
            missingFrames(it->first - finalized_ - 1);
            const F& f = it->second;
            expected += f.count;
            lostRaw += f.count - f.orig;
            lostAfterNack += f.count - f.any;
            seenPackets_ += f.count;
            ++seenFrames_;
            finalized_ = it->first;
            frames_.erase(it);
        }
        if (t > finalized_) {
            missingFrames(t - finalized_);
            finalized_ = t;
        }
    }

    std::map<uint64_t, F> frames_;
    bool started_ = false;
    uint64_t newest_ = 0, finalized_ = 0;
    uint64_t seenPackets_ = 0, seenFrames_ = 0;
};

// Presented frames per second, one sample per >= 1 s of wall time. The
// window holds the samples since clearWindow() (the 5 s stats line); the
// session keeps every sample (capped) for the SUMMARY. A counter that goes
// backwards (presenter swapped) restarts the baseline without a sample.
class PresentedFpsSampler {
public:
    void update(double nowMs, uint64_t presented) {
        if (lastMs_ < 0 || presented < last_ || nowMs < lastMs_) {
            lastMs_ = nowMs;
            last_ = presented;
            return;
        }
        const double dt = nowMs - lastMs_;
        if (dt < 1000.0) return;
        const float fps = static_cast<float>(double(presented - last_) * 1000.0 / dt);
        window_.push_back(fps);
        if (session_.size() < kMaxSamples) session_.push_back(fps);
        lastMs_ = nowMs;
        last_ = presented;
    }
    const std::vector<float>& window() const { return window_; }
    const std::vector<float>& session() const { return session_; }
    void clearWindow() { window_.clear(); }

private:
    static constexpr size_t kMaxSamples = 1u << 20;
    double lastMs_ = -1;
    uint64_t last_ = 0;
    std::vector<float> window_, session_;
};

class VideoReceiver {
public:
    VideoReceiver(ReceiverConfig cfg, ReceiverHooks hooks) : cfg_(cfg), h_(std::move(hooks)) {
        if (!cfg_.strict) cfg_.nack = false;
    }

    bool nackActive() const { return cfg_.nack; }
    const ReceiverStats& stats() const { return st_; }
    void setRttMs(double rtt) { if (rtt > 0) rttMs_ = rtt; }
    double rttMs() const { return rttMs_ > 0 ? rttMs_ : cfg_.defaultRttMs; }
    // A repair needs about one RTT after the reorder grace. When that cannot fit
    // inside holdMs (D1-A, e.g. DERP), holding only delays the keyframe that
    // will come anyway: use the strict path (as with NACK off) until it fits.
    bool nackCanFit() const { return rttMs() + cfg_.reorderGraceMs < cfg_.holdMs; }
    // Logs and counts each switch between NACK and the strict fallback.
    bool nackUsable() {
        const bool fit = nackCanFit();
        if (fit == nackPaused_) {
            nackPaused_ = !fit;
            if (nackPaused_) ++st_.nackPausedRtt;
            // Frames held behind a hole keep their 40 ms deadline after the
            // switch; they are settled on the NACK path (no new NACKs).
            settling_ = nackPaused_ && holdingHole();
            log(std::string(nackPaused_ ? "loss.nack_paused" : "loss.nack_resumed") +
                " rtt_ms=" + std::to_string(int(rttMs())) + " hold_ms=" + std::to_string(int(cfg_.holdMs)));
        }
        return fit;
    }
    size_t heldFrames() const { return assembling_.size(); }
    // End of session: count loss for the frames that are not finalized yet.
    void flushLoss() { loss_.flush(); syncLoss(); }

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

        // A retransmit (flag 0x04) is always a copy of a frame the host already
        // sent in this stream, so an old frame id on one is a late repair (or a
        // duplicate of one), never a host restart. Only fresh packets can
        // signal a restart.
        const bool retransmit = (flags & 0x04) != 0;
        if (!retransmit) ++st_.originalPackets;
        else ++st_.retransmitRx;
        const bool frameWentBackward = !retransmit && newest_ > 0 && fid + 2 < newest_;
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
            submittedMax_ = 0;
            settling_ = false;
            loss_.restart();
            syncLoss();
            carried_.clear();
            waiting_ = true;
            forceDisc_ = true;
            reset();
            requestKeyframe();
            ++st_.streamRestarts;
        }

        if (!retransmit) { loss_.original(fid, idx, cnt); syncLoss(); }
        // A copy of a frame already shown in this stream is never used again,
        // in any mode: recovery must not move the stream backwards.
        if (retransmit && submittedMax_ && fid <= submittedMax_) {
            ++st_.latePacketsIgnored;
            return;
        }

        if (cfg_.nack) {
            const bool usable = nackUsable();
            if (usable || settling_) {
                onPacketNack(flags, fid, idx, cnt, buf + 20, len, nowMs);
                if (!usable) updateSettling();
            } else {
                onPacketStrict(flags, fid, idx, cnt, buf + 20, len);
            }
        } else {
            onPacketStrict(flags, fid, idx, cnt, buf + 20, len);
        }
    }

    // Timers (NACK retry, hold deadline). Call often: on every packet and on
    // every receive timeout.
    void tick(double nowMs) {
        if (!cfg_.nack) return;
        const bool usable = nackUsable();
        if (!usable && !settling_) return;
        service(nowMs);
        if (!usable) updateSettling();
    }

private:
    struct Frame {
        uint16_t count = 0;   // 0 = placeholder, no packet seen yet
        bool key = false;
        std::vector<std::vector<uint8_t>> parts;
        std::vector<uint8_t> requested;   // per index: asked for in a NACK
        std::vector<double> missSinceMs;  // per index: first seen missing, -1 = not yet
        std::vector<bool> present;
        size_t received = 0;
        int maxIndex = -1;
        double holeMs = -1;        // first time a hole was seen (deadline base)
        double lastPacketMs = 0;
        double lastNackMs = -1;
        double firstNackMs = -1;
        int nackAttempts = 0;      // NACK messages sent for this frame (D: max 2)
        bool wholeRequested = false;  // placeholder was asked for as a whole frame
        bool expired = false;      // deadline already missed: no NACK, no repair

        void init(uint16_t cnt) {
            count = cnt;
            parts.assign(cnt, {});
            present.assign(cnt, false);
            requested.assign(cnt, 0);
            missSinceMs.assign(cnt, -1.0);
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
        submittedMax_ = std::max(submittedMax_, fid);
    }
    void syncLoss() {
        st_.lossExpected = loss_.expected;
        st_.lossRaw = loss_.lostRaw;
        st_.lossAfterNack = loss_.lostAfterNack;
        st_.lossWholeFrames = loss_.wholeFrames;
    }
    // A frame is held behind a known hole (NACK state that needs settling).
    bool holdingHole() const {
        for (const auto& e : assembling_)
            if (!e.second.complete() && !e.second.expired && e.second.holeMs >= 0) return true;
        return false;
    }
    // While NACK is paused, held frames are settled on the NACK path until
    // no hole is held any more or recovery took over (then strict waits).
    void updateSettling() {
        if (settling_ && (waiting_ || !holdingHole())) {
            settling_ = false;
            log("loss.nack_settled waiting=" + std::string(waiting_ ? "1" : "0"));
        }
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
        if (it->second.add(idx, payload, len, (flags & 0x01) != 0) && (flags & 0x04)) {
            loss_.repaired(fid, idx, cnt);
            syncLoss();
        }
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
        const bool retransmit = (flags & 0x04) != 0;
        // Deadlines first: a hole that is already past holdMs must fall back
        // to a keyframe even if this very packet would have closed it.
        // After a fallback this packet is handled like any packet that arrives
        // while waiting for a keyframe.
        expireDeadlines(now);
        const uint64_t prevNewest = newest_;
        newest_ = std::max(newest_, fid);

        if (waiting_ && !key) {
            ++st_.recoveryWaitPacketDrops;
            requestKeyframe();
            service(now);
            return;
        }
        if (submittedMax_ && fid <= submittedMax_) {
            ++st_.latePacketsIgnored;
            return;
        }
        // Whole frames skipped between the newest frame and this one.
        if (!waiting_ && fid > prevNewest + 1) {
            const uint64_t from = std::max(prevNewest, lastSubmitted_) + 1;
            if (fid - from > cfg_.maxHeldFrames) {
                enterRecovery("frame_gap fid=" + std::to_string(fid), false, now);
                ++st_.heldCapMiss;
                if (!key) { ++st_.recoveryWaitPacketDrops; return; }
            } else {
                for (uint64_t f = from; f < fid; ++f) {
                    auto& ph = assembling_[f];
                    if (ph.count == 0 && ph.holeMs < 0) ph.holeMs = now;
                }
            }
        }

        if (!carried_.empty()) pruneCarried();
        Frame& fr = assembling_[fid];
        if (fr.count == 0) {
            auto c = carried_.find(fid);
            if (c != carried_.end() && c->second.count == cnt) fr = std::move(c->second);
            else fr.init(cnt);
            if (c != carried_.end()) carried_.erase(c);
        } else if (fr.count != cnt) {
            ++st_.bad;
            return;
        }
        // A frame whose deadline already passed takes no repair (it may still
        // complete from its own original packets, e.g. a long IDR tail).
        if (fr.expired && retransmit) {
            ++st_.latePacketsIgnored;
            return;
        }
        if (!fr.add(idx, payload, len, key)) {
            ++st_.duplicatePackets;
            return;
        }
        if (retransmit) { loss_.repaired(fid, idx, cnt); syncLoss(); }
        if (fr.requested[idx] && !fr.expired) ++st_.holesRecovered;
        fr.lastPacketMs = now;
        if (fr.complete() && !fr.expired) {
            if (fr.wholeRequested) ++st_.holesRecovered;
            if (fr.firstNackMs >= 0) {
                ++st_.framesRepaired;
                if (st_.repairMs.size() < 100000) st_.repairMs.push_back(float(now - fr.firstNackMs));
            }
        }
        st_.heldFramesMax = std::max<uint64_t>(st_.heldFramesMax, assembling_.size());
        drain();
        service(now);
    }

    // Submit what can go out in order.
    void drain() {
        for (;;) {
            if (waiting_) {
                auto it = std::find_if(assembling_.begin(), assembling_.end(), [&](const auto& e) {
                    return e.first > submittedMax_ && e.second.complete() && e.second.key;
                });
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
    void pruneCarried() {
        for (auto it = carried_.begin(); it != carried_.end();) {
            const bool done = submittedMax_ && it->first <= submittedMax_;
            if (done || it->first + 240 < newest_) it = carried_.erase(it); else ++it;
        }
    }

    void enterRecovery(const std::string& reason, bool countMiss, double now, uint64_t dropUpTo = 0) {
        if (countMiss) ++st_.nackDeadlineMiss;
        // A keyframe given up here may be assembled again from its tail (a long
        // IDR is often still on the wire). Keep everything: what was received,
        // what was NACKed, the attempt count and the original deadline, so a
        // rebuild neither asks again past the 2-attempt cap or the deadline nor
        // counts its holes twice. Past its deadline it takes no repair.
        pruneCarried();
        ++st_.strictRecoveryEvents;
        for (auto it = assembling_.begin(); it != assembling_.end();) {
            if (it->first > dropUpTo && it->second.count && it->second.key) { ++it; continue; }
            if (!it->second.complete()) ++st_.incompleteDropped;
            if (it->second.count && it->second.key && !it->second.complete()) {
                Frame kept = std::move(it->second);
                if (kept.holeMs >= 0 && now - kept.holeMs > cfg_.holdMs) kept.expired = true;
                carried_[it->first] = std::move(kept);
            }
            it = assembling_.erase(it);
        }
        waiting_ = true;
        forceDisc_ = true;
        lastSubmitted_ = 0;  // submittedMax_ stays: same stream
        reset();
        log("loss.strict_wait_for_keyframe reason=" + reason);
        requestKeyframe();
    }

    void service(double now) {
        if (assembling_.size() > cfg_.maxHeldFrames && !waiting_) {
            ++st_.heldCapMiss;
            enterRecovery("nack_held_cap held=" + std::to_string(assembling_.size()), false, now);
            drain();
            return;
        }
        if (expireDeadlines(now)) return;
        if (!nackPaused_) sendNacks(now);
    }

    // Marks newly visible holes and enforces holdMs (D1-A) from the moment a
    // hole was first seen. True when it fell back to a keyframe.
    bool expireDeadlines(double now) {
        for (auto& e : assembling_) {
            Frame& fr = e.second;
            if (fr.complete() || fr.expired) continue;
            markHoles(e.first, fr, now);
            if (fr.holeMs >= 0 && now - fr.holeMs > cfg_.holdMs) {
                enterRecovery("nack_deadline fid=" + std::to_string(e.first), true, now, e.first);
                drain();
                return true;
            }
        }
        return false;
    }

    // A placeholder is a hole as soon as it exists (a later frame created it).
    // Inside a frame: lower indices once a higher one arrived; the tail once a
    // later frame arrived.
    void markHoles(uint64_t fid, Frame& fr, double now) {
        if (fr.count == 0) {
            if (fr.holeMs < 0) fr.holeMs = now;
            return;
        }
        const int limit = newest_ > fid ? int(fr.count) : fr.maxIndex;
        for (int i = 0; i < limit; ++i) {
            if (fr.present[i] || fr.missSinceMs[i] >= 0) continue;
            fr.missSinceMs[i] = now;
            if (fr.holeMs < 0) fr.holeMs = now;
        }
    }

    // One NACK message per frame per attempt, at most maxNackAttempts per
    // frame, the next one no sooner than max(minRetryMs, 1.2 x RTT) after the
    // previous one. An index is only asked for after it has been missing for
    // reorderGraceMs. Each message carries every eligible hole of the frame,
    // as merged ranges.
    void sendNacks(double now) {
        const double retryMs = std::max(cfg_.minRetryMs, 1.2 * rttMs());
        for (auto& e : assembling_) {
            const uint64_t fid = e.first;
            Frame& fr = e.second;
            if (fr.complete() || fr.expired) continue;
            if (fr.nackAttempts >= cfg_.maxNackAttempts) continue;
            if (fr.nackAttempts > 0 && now - fr.lastNackMs < retryMs) continue;

            std::vector<NackRange> ranges;
            uint64_t indices = 0;
            if (fr.count == 0) {
                if (fr.holeMs < 0 || now - fr.holeMs < cfg_.reorderGraceMs) continue;
                ranges.push_back({0, 0xFFFF});
                if (!fr.wholeRequested) {
                    fr.wholeRequested = true;
                    ++st_.nackWholeFrames;
                    ++st_.lostPacketsRaw;
                }
                indices = 1;
            } else {
                std::vector<uint16_t> missing;
                for (int i = 0; i < int(fr.count); ++i) {
                    if (fr.present[i] || fr.missSinceMs[i] < 0) continue;
                    if (now - fr.missSinceMs[i] < cfg_.reorderGraceMs) continue;
                    missing.push_back(uint16_t(i));
                }
                if (missing.empty()) continue;
                ranges = mergeRanges(missing, cfg_.maxRangesPerNack);
                for (uint16_t i : missing) {
                    if (!fr.requested[i]) { fr.requested[i] = 1; ++st_.lostPacketsRaw; }
                }
                indices = missing.size();
            }
            if (h_.sendNack) h_.sendNack(fid, ranges);
            ++st_.nackTx;
            st_.nackPacketsRequested += indices;
            ++fr.nackAttempts;
            fr.lastNackMs = now;
            if (fr.firstNackMs < 0) fr.firstNackMs = now;
        }
    }

public:
    // Sorted, distinct indices -> ranges of consecutive indices. Above
    // maxRanges, the ranges with the smallest gap between them are joined
    // (the host then also resends the few packets in the gap).
    static std::vector<NackRange> mergeRanges(const std::vector<uint16_t>& idx, size_t maxRanges) {
        std::vector<NackRange> r;
        for (uint16_t i : idx) {
            if (!r.empty() && uint32_t(r.back().start) + r.back().count == i && r.back().count < 0xFFFE)
                ++r.back().count;
            else
                r.push_back({i, 1});
        }
        while (maxRanges > 0 && r.size() > maxRanges) {
            size_t best = 0;
            uint32_t bestGap = UINT32_MAX;
            for (size_t k = 0; k + 1 < r.size(); ++k) {
                const uint32_t gap = uint32_t(r[k + 1].start) - (uint32_t(r[k].start) + r[k].count);
                if (gap < bestGap) { bestGap = gap; best = k; }
            }
            r[best].count = uint16_t(uint32_t(r[best + 1].start) + r[best + 1].count - r[best].start);
            r.erase(r.begin() + long(best) + 1);
        }
        return r;
    }

private:

    ReceiverConfig cfg_;
    ReceiverHooks h_;
    ReceiverStats st_;
    std::map<uint64_t, Frame> assembling_;
    uint64_t newest_ = 0, lastSubmitted_ = 0;
    uint64_t submittedMax_ = 0;  // highest frame submitted in this stream
    bool waiting_ = false, forceDisc_ = false;
    double rttMs_ = 0;
    bool nackPaused_ = false;
    bool settling_ = false;      // NACK paused, held frames still on their deadline
    PacketLossCounter loss_;
    std::map<uint64_t, Frame> carried_;  // keyframes dropped by a fallback, for a rebuild
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
