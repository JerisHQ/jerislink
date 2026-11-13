// Console unit test for video_receiver.hpp (no Win32).
// 1. Small scripted cases: strict without NACK, single hole, tail loss,
//    whole-frame loss, deadline miss, NACK message layout.
// 2. Loss simulation: a modelled host (encoder, 150 ms keyframe gate, frame
//    cache 250 ms / 4 MiB / 32 frames, 20% retransmit budget, D2-B) talks to
//    the real VideoReceiver over a lossy link. Each scenario runs once with
//    NACK and once without, with the same loss pattern seed, and compares
//    the number of forced IDRs.
// 3. ABR v1: report layout, arrival slope, controller rules, and the same
//    simulation with a bottleneck link (drop-tail queue, capacity that drops
//    for a while) run with ABR off and on.
#include "abr.hpp"
#include "present_scheduler.hpp"
#include "video_receiver.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <deque>
#include <memory>
#include <queue>
#include <random>

using namespace jl;

static int gFailures = 0;
#define CHECK(cond)                                                                  \
    do {                                                                             \
        if (!(cond)) {                                                               \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);              \
            ++gFailures;                                                             \
        }                                                                            \
    } while (0)

static std::vector<uint8_t> packet(uint64_t fid, uint16_t idx, uint16_t cnt, bool key,
                                   bool retransmit = false, uint16_t payload = 8) {
    std::vector<uint8_t> p{'M', 'R', '0', '2', 1};
    uint8_t flags = key ? 0x01 : 0x00;
    if (idx == cnt - 1) flags |= 0x02;
    if (retransmit) flags |= 0x04;
    p.push_back(flags);
    for (int i = 7; i >= 0; --i) p.push_back(uint8_t(fid >> (8 * i)));
    p.push_back(uint8_t(idx >> 8)); p.push_back(uint8_t(idx));
    p.push_back(uint8_t(cnt >> 8)); p.push_back(uint8_t(cnt));
    p.push_back(uint8_t(payload >> 8)); p.push_back(uint8_t(payload));
    for (uint16_t i = 0; i < payload; ++i) p.push_back(uint8_t(fid + idx + i));
    return p;
}

struct Recorder {
    struct Sub { uint64_t fid; bool disc; bool key; };
    std::vector<Sub> subs;
    int keyframeRequests = 0;
    int resets = 0;
    std::vector<std::pair<uint64_t, std::vector<NackRange>>> nacks;
    ReceiverHooks hooks() {
        ReceiverHooks h;
        h.submit = [this](uint64_t fid, const std::vector<uint8_t>&, bool d, bool k) { subs.push_back({fid, d, k}); };
        h.resetForNewStream = [this] { ++resets; };
        h.requestKeyframe = [this] { ++keyframeRequests; };
        h.sendNack = [this](uint64_t fid, const std::vector<NackRange>& r) { nacks.push_back({fid, r}); };
        return h;
    }
};

static void feed(VideoReceiver& r, uint64_t fid, uint16_t cnt, bool key, double now,
                 const std::vector<uint16_t>& skip = {}) {
    for (uint16_t i = 0; i < cnt; ++i) {
        if (std::find(skip.begin(), skip.end(), i) != skip.end()) continue;
        auto p = packet(fid, i, cnt, key);
        r.onPacket(p.data(), p.size(), now, 0);
    }
}

static ReceiverConfig nackConfig() {
    ReceiverConfig c;
    c.strict = true;
    c.nack = true;
    return c;
}

static void testStrictWithoutNack() {
    Recorder rec;
    ReceiverConfig c;  // strict, no NACK
    VideoReceiver r(c, rec.hooks());
    r.start();
    CHECK(rec.keyframeRequests == 1);
    feed(r, 1, 4, true, 0);
    feed(r, 2, 3, false, 16);
    feed(r, 3, 3, false, 33, {1});  // hole
    feed(r, 4, 3, false, 50);       // 4 complete, 3 missing -> frame gap
    CHECK(rec.subs.size() == 2);
    CHECK(r.stats().strictRecoveryEvents >= 1);
    CHECK(rec.keyframeRequests >= 2);
    CHECK(rec.nacks.empty());
}

static void testSingleHoleRepaired() {
    Recorder rec;
    VideoReceiver r(nackConfig(), rec.hooks());
    r.start();
    feed(r, 1, 4, true, 0);
    feed(r, 2, 6, false, 16, {2});  // index 2 lost, indices 3..5 arrived
    r.tick(18.5);  // reorder grace (2 ms) over
    CHECK(rec.nacks.size() == 1);
    if (rec.nacks.empty()) return;
    CHECK(rec.nacks[0].first == 2);
    CHECK(rec.nacks[0].second.size() == 1);
    CHECK(rec.nacks[0].second[0].start == 2 && rec.nacks[0].second[0].count == 1);
    feed(r, 3, 3, false, 33);  // held behind frame 2
    CHECK(rec.subs.size() == 1);
    auto p = packet(2, 2, 6, false, true);
    r.onPacket(p.data(), p.size(), 40, 0);
    CHECK(rec.subs.size() == 3);
    CHECK(rec.subs[1].fid == 2 && !rec.subs[1].disc);
    CHECK(rec.subs[2].fid == 3 && !rec.subs[2].disc);
    CHECK(rec.keyframeRequests == 1);  // only the startup one
    CHECK(r.stats().framesRepaired == 1);
    CHECK(r.stats().retransmitRx == 1);
}

static void testTailLossAndWholeFrame() {
    Recorder rec;
    VideoReceiver r(nackConfig(), rec.hooks());
    r.start();
    feed(r, 1, 2, true, 0);
    feed(r, 2, 5, false, 16, {3, 4});  // tail lost: not visible yet
    r.tick(30);
    CHECK(rec.nacks.empty());
    // frame 3 lost entirely, frame 4 arrives
    feed(r, 4, 2, false, 50);
    CHECK(rec.nacks.empty());  // 2 ms reorder grace first
    r.tick(52.5);
    bool tail = false, whole = false;
    for (auto& n : rec.nacks) {
        if (n.first == 2 && n.second.size() == 1 && n.second[0].start == 3 && n.second[0].count == 2) tail = true;
        if (n.first == 3 && n.second.size() == 1 && n.second[0].start == 0 && n.second[0].count == 0xFFFF) whole = true;
    }
    CHECK(tail);
    CHECK(whole);
    auto a = packet(2, 3, 5, false, true), b = packet(2, 4, 5, false, true);
    r.onPacket(a.data(), a.size(), 60, 0);
    r.onPacket(b.data(), b.size(), 60, 0);
    CHECK(rec.subs.size() == 2);  // 3 still missing, 4 held
    feed(r, 3, 2, false, 62);
    CHECK(rec.subs.size() == 4);
    CHECK(rec.subs.back().fid == 4 && !rec.subs.back().disc);
    CHECK(rec.keyframeRequests == 1);
}

static void testDeadlineMiss() {
    Recorder rec;
    VideoReceiver r(nackConfig(), rec.hooks());
    r.start();
    feed(r, 1, 2, true, 0);
    feed(r, 2, 4, false, 16, {1});
    feed(r, 3, 2, false, 33);
    CHECK(rec.keyframeRequests == 1);
    r.tick(16 + 41);  // hole seen when index 2 arrived (16 ms); 40 ms hold is over
    CHECK(r.stats().nackDeadlineMiss == 1);
    CHECK(rec.keyframeRequests == 2);
    feed(r, 4, 2, false, 80);  // non-key while waiting: dropped
    CHECK(rec.subs.size() == 1);
    feed(r, 5, 3, true, 95);
    CHECK(rec.subs.size() == 2 && rec.subs.back().fid == 5 && rec.subs.back().disc);
}

static void testKeyframeJump() {
    Recorder rec;
    VideoReceiver r(nackConfig(), rec.hooks());
    r.start();
    feed(r, 1, 2, true, 0);
    feed(r, 2, 4, false, 16, {1});
    feed(r, 3, 3, true, 33);  // complete keyframe past the hole
    CHECK(rec.subs.size() == 2 && rec.subs.back().fid == 3 && rec.subs.back().disc);
    CHECK(r.stats().keyframeJumps == 1);
    CHECK(r.stats().nackDeadlineMiss == 0);
}

static void testNackEncoding() {
    std::vector<NackRange> ranges{{2, 1}, {10, 3}};
    auto p = encodeNack(7, 0x0102030405060708ULL, ranges);
    CHECK(p.size() == 19 + 4 * 2);
    CHECK(p[5] == 0x41 && p[9] == 7);
    CHECK(p[10] == 1 && p[17] == 8);
    CHECK(p[18] == 2);
    CHECK(p[19] == 0 && p[20] == 2 && p[21] == 0 && p[22] == 1);
    std::vector<NackRange> many(40, NackRange{1, 1});
    CHECK(encodeNack(1, 1, many).size() == 19 + 4 * 32);
}

// Review item 1: a late duplicate retransmit of an old frame must not look
// like a stream restart (fid <= 5 used to trip earlyRestart).
static void testLateRetransmitIsNotRestart() {
    Recorder rec;
    VideoReceiver r(nackConfig(), rec.hooks());
    r.start();
    feed(r, 1, 3, true, 0);
    for (uint64_t f = 2; f <= 6; ++f) feed(r, f, 2, false, double(f) * 16);
    CHECK(rec.subs.size() == 6);
    auto late = packet(1, 1, 3, true, true);  // duplicate retransmit of frame 1
    r.onPacket(late.data(), late.size(), 100, 0);
    CHECK(r.stats().streamRestarts == 0);
    CHECK(r.stats().latePacketsIgnored == 1);
    CHECK(rec.keyframeRequests == 1);  // startup only
    feed(r, 7, 2, false, 112);
    CHECK(rec.subs.size() == 7 && rec.subs.back().fid == 7 && !rec.subs.back().disc);
    // A fresh fid 1 from a restarted host is still a restart.
    auto fresh = packet(1, 0, 3, true);
    r.onPacket(fresh.data(), fresh.size(), 130, 0);
    CHECK(r.stats().streamRestarts == 1);
}

// Review item 2: reorder grace, ranges merged into one message, at most 2
// NACK messages per frame, RTT-spaced.
static void testNackAttemptsPerFrame() {
    Recorder rec;
    VideoReceiver r(nackConfig(), rec.hooks());
    r.start();
    feed(r, 1, 2, true, 0);
    const std::vector<uint16_t> lost{1, 3, 5, 7, 9, 11, 13, 15};
    feed(r, 2, 20, false, 16, lost);
    CHECK(rec.nacks.empty());  // grace not over
    r.tick(17.5);
    CHECK(rec.nacks.empty());
    r.tick(18.5);
    CHECK(rec.nacks.size() == 1);
    if (!rec.nacks.empty()) CHECK(rec.nacks[0].first == 2 && rec.nacks[0].second.size() == lost.size());
    for (double t = 19; t < 18.5 + 24; t += 1) r.tick(t);  // retry after 1.2 x 20 ms RTT
    CHECK(rec.nacks.size() == 1);
    r.tick(18.5 + 24.1);
    CHECK(rec.nacks.size() == 2);
    for (double t = 43; t < 56; t += 1) r.tick(t);
    CHECK(rec.nacks.size() == 2);  // no third attempt
    CHECK(r.stats().nackTx == 2);
    CHECK(r.stats().lostPacketsRaw == lost.size());

    auto m = VideoReceiver::mergeRanges({1, 2, 3, 7, 8, 20}, 32);
    CHECK(m.size() == 3 && m[0].start == 1 && m[0].count == 3 && m[1].start == 7 && m[1].count == 2);
    auto m2 = VideoReceiver::mergeRanges({1, 2, 3, 7, 8, 20}, 2);
    CHECK(m2.size() == 2 && m2[0].start == 1 && m2[0].count == 8 && m2[1].start == 20 && m2[1].count == 1);
}

// Review item 3: a repair that lands after the 40 ms hold is not accepted.
static void testDeadlineEnforcedBeforeRepair() {
    Recorder rec;
    VideoReceiver r(nackConfig(), rec.hooks());
    r.start();
    feed(r, 1, 2, true, 0);
    feed(r, 2, 4, false, 16, {1});  // hole seen at 16 ms
    r.tick(18.5);                   // NACK sent
    feed(r, 3, 2, false, 33);       // held
    CHECK(rec.subs.size() == 1);
    auto p = packet(2, 1, 4, false, true);
    r.onPacket(p.data(), p.size(), 16 + 42, 0);  // repair 42 ms after the hole, no tick in between
    CHECK(r.stats().nackDeadlineMiss == 1);
    CHECK(r.stats().framesRepaired == 0);
    CHECK(rec.subs.size() == 1);
    CHECK(rec.keyframeRequests >= 2);
    // Exactly at the deadline is still in time.
    Recorder rec2;
    VideoReceiver r2(nackConfig(), rec2.hooks());
    r2.start();
    feed(r2, 1, 2, true, 0);
    feed(r2, 2, 4, false, 16, {1});
    r2.tick(18.5);
    r2.onPacket(p.data(), p.size(), 16 + 40, 0);
    CHECK(r2.stats().nackDeadlineMiss == 0 && r2.stats().framesRepaired == 1 && rec2.subs.size() == 2);
}

static void testHighRttSkipsHold() {
    // RTT 60 ms cannot fit the 40 ms hold: NACK pauses, strict behaviour.
    Recorder rec;
    VideoReceiver r(nackConfig(), rec.hooks());
    r.setRttMs(60);
    r.start();
    feed(r, 1, 2, true, 0);
    const int keyBefore = rec.keyframeRequests;
    feed(r, 2, 4, false, 16, {1});
    r.tick(30);
    CHECK(rec.nacks.empty());
    CHECK(rec.keyframeRequests == keyBefore);
    feed(r, 3, 2, false, 33);  // frame gap -> keyframe at once, like NACK off
    CHECK(rec.nacks.empty() && r.stats().nackTx == 0);
    CHECK(r.stats().nackPausedRtt == 1);
    CHECK(r.stats().strictRecoveryEvents == 1);
    CHECK(rec.keyframeRequests == keyBefore + 1);
    // RTT 30 ms still fits: NACK as usual.
    Recorder rec2;
    VideoReceiver r2(nackConfig(), rec2.hooks());
    r2.setRttMs(30);
    r2.start();
    feed(r2, 1, 2, true, 0);
    feed(r2, 2, 4, false, 16, {1});
    r2.tick(18.5);
    CHECK(rec2.nacks.size() == 1 && r2.stats().nackPausedRtt == 0);
}

static void testPresentedFps() {
    PresentedFpsSampler s;
    s.update(0, 0);                 // baseline
    s.update(500, 30);              // < 1 s: no sample
    CHECK(s.window().empty());
    s.update(1000, 60);             // 60 frames in 1 s
    s.update(2500, 105);            // 45 frames in 1.5 s = 30 fps
    CHECK(s.window().size() == 2);
    CHECK(std::fabs(s.window()[0] - 60.f) < 1e-3f && std::fabs(s.window()[1] - 30.f) < 1e-3f);
    CHECK(receiverPercentile(s.window(), 0) == 30.f && receiverPercentile(s.window(), 100) == 60.f);
    s.clearWindow();
    CHECK(s.window().empty() && s.session().size() == 2);
    s.update(3000, 10);             // counter went back: new baseline, no sample
    s.update(4000, 70);             // 60 fps from the new baseline
    CHECK(s.window().size() == 1 && std::fabs(s.window()[0] - 60.f) < 1e-3f && s.session().size() == 3);
}

static void testRebuiltFrameKeepsQuotaAndDeadline() {
    // Second review item 2. A long IDR with an early hole misses the deadline
    // while its tail is still on the wire. The tail assembles the frame again;
    // the rebuild keeps the original deadline and attempt count, so it sends no
    // more NACKs (it used to send 2 more: 4 in total), takes no late repair,
    // and its hole does not count twice.
    Recorder rec;
    VideoReceiver r(nackConfig(), rec.hooks());
    r.start();
    for (uint16_t i = 0; i < 5; ++i) {
        if (i == 2) continue;
        auto p = packet(1, i, 10, true);
        r.onPacket(p.data(), p.size(), 0, 0);
    }
    r.tick(2.5);
    CHECK(rec.nacks.size() == 1);
    CHECK(r.stats().lostPacketsRaw == 1);
    r.tick(41);
    CHECK(r.stats().nackDeadlineMiss == 1);
    for (uint16_t i = 5; i < 10; ++i) {
        auto p = packet(1, i, 10, true);
        r.onPacket(p.data(), p.size(), 42, 0);
    }
    for (double t = 42.5; t < 120; t += 0.5) r.tick(t);
    CHECK(rec.nacks.size() == 1);  // hard cap: no new attempt, past deadline anyway
    CHECK(r.stats().nackDeadlineMiss == 1);  // the miss is not counted again
    CHECK(r.stats().lostPacketsRaw == 1);
    auto p = packet(1, 2, 10, true, true);
    r.onPacket(p.data(), p.size(), 120, 0);  // repair long after the deadline
    CHECK(r.stats().holesRecovered == 0 && r.stats().framesRepaired == 0);
    CHECK(rec.subs.empty());
    feed(r, 2, 3, true, 130);  // the requested fresh keyframe
    CHECK(rec.subs.size() == 1 && rec.subs[0].fid == 2 && rec.subs[0].disc);

    // Attempts are capped per frame even when the rebuild is still in time:
    // two NACKs, deadline miss, rebuild, and never a third NACK for that frame.
    Recorder rec2;
    VideoReceiver r2(nackConfig(), rec2.hooks());
    r2.start();
    for (uint16_t i = 0; i < 5; ++i)
        if (i != 2) { auto q = packet(1, i, 10, true); r2.onPacket(q.data(), q.size(), 0, 0); }
    for (double t = 0.5; t <= 41; t += 0.5) r2.tick(t);
    CHECK(rec2.nacks.size() == 2);
    for (uint16_t i = 5; i < 10; ++i) { auto q = packet(1, i, 10, true); r2.onPacket(q.data(), q.size(), 41.5, 0); }
    for (double t = 42; t < 200; t += 0.5) r2.tick(t);
    size_t forFrame1 = 0;
    for (auto& n : rec2.nacks) if (n.first == 1) ++forFrame1;
    CHECK(forFrame1 == 2);
    CHECK(r2.stats().nackDeadlineMiss == 1);
}

// Second review item 1: recovery keeps the submitted watermark of the stream.
// Frame 11 was shown; after a deadline fallback an old keyframe-10 copy must
// not be shown again (the stream would go backwards).
static void testRecoveryNeverGoesBackwards() {
    Recorder rec;
    VideoReceiver r(nackConfig(), rec.hooks());
    r.start();
    feed(r, 1, 2, true, 0);
    for (uint64_t f = 2; f <= 9; ++f) feed(r, f, 2, false, double(f));
    feed(r, 10, 4, true, 10);
    feed(r, 11, 2, false, 11);
    CHECK(rec.subs.size() == 11 && rec.subs.back().fid == 11);
    feed(r, 12, 4, false, 12, {1});
    r.tick(12 + 41);
    CHECK(r.stats().nackDeadlineMiss == 1);
    for (uint16_t i = 0; i < 4; ++i) {  // e.g. an over-wide NACK range resent all of frame 10
        auto p = packet(10, i, 4, true, true);
        r.onPacket(p.data(), p.size(), 60, 0);
    }
    CHECK(rec.subs.size() == 11 && rec.subs.back().fid == 11);
    CHECK(r.stats().streamRestarts == 0);
    feed(r, 13, 3, true, 70);
    CHECK(rec.subs.size() == 12 && rec.subs.back().fid == 13 && rec.subs.back().disc);

    // Same on the strict path (NACK paused at RTT 60 ms): a retransmit from an
    // earlier NACK arriving during the wait is not shown either.
    Recorder rec2;
    VideoReceiver r2(nackConfig(), rec2.hooks());
    r2.setRttMs(60);
    r2.start();
    feed(r2, 1, 2, true, 0);
    feed(r2, 2, 2, false, 16);
    feed(r2, 3, 3, false, 33, {1});
    feed(r2, 4, 2, false, 50);  // frame gap -> strict wait
    CHECK(r2.stats().strictRecoveryEvents == 1);
    for (uint16_t i = 0; i < 2; ++i) {
        auto p = packet(1, i, 2, true, true);
        r2.onPacket(p.data(), p.size(), 60, 0);
    }
    CHECK(rec2.subs.size() == 2 && rec2.subs.back().fid == 2);
    // A real host restart still resets the watermark.
    auto fresh = packet(1, 0, 1, true);
    r2.onPacket(fresh.data(), fresh.size(), 400, 300);
    CHECK(r2.stats().streamRestarts == 1);
    CHECK(rec2.subs.size() == 3 && rec2.subs.back().fid == 1);
}

// Second review item 3: frames already held when RTT rises and NACK pauses
// keep the 40 ms deadline, and the miss is counted.
static void testPauseKeepsHeldDeadline() {
    auto setup = [](Recorder& rec, VideoReceiver& r) {
        r.start();
        feed(r, 1, 2, true, 0);
        feed(r, 2, 4, false, 16, {1});  // hole at 16 ms
        r.tick(18.5);                   // NACK sent
        feed(r, 3, 2, false, 33);       // held
        CHECK(rec.nacks.size() == 1 && rec.subs.size() == 1);
        r.setRttMs(60);                 // NACK cannot fit any more
    };
    {   // repair 44 ms after the hole: too late
        Recorder rec;
        VideoReceiver r(nackConfig(), rec.hooks());
        setup(rec, r);
        auto p = packet(2, 1, 4, false, true);
        r.onPacket(p.data(), p.size(), 16 + 44, 0);
        CHECK(r.stats().nackPausedRtt == 1);
        CHECK(r.stats().nackDeadlineMiss == 1);
        CHECK(r.stats().framesRepaired == 0);
        CHECK(rec.subs.size() == 1);
        CHECK(rec.keyframeRequests >= 2);
    }
    {   // no packet at all: the timer alone enforces it
        Recorder rec;
        VideoReceiver r(nackConfig(), rec.hooks());
        setup(rec, r);
        r.tick(40);
        CHECK(r.stats().nackDeadlineMiss == 0);
        r.tick(16 + 41);
        CHECK(r.stats().nackDeadlineMiss == 1);
        CHECK(rec.nacks.size() == 1);  // no new NACK while paused
    }
    {   // repair inside the hold: frames 2 and 3 go out, then strict as usual
        Recorder rec;
        VideoReceiver r(nackConfig(), rec.hooks());
        setup(rec, r);
        auto p = packet(2, 1, 4, false, true);
        r.onPacket(p.data(), p.size(), 16 + 30, 0);
        CHECK(rec.subs.size() == 3 && rec.subs.back().fid == 3 && !rec.subs.back().disc);
        CHECK(r.stats().nackDeadlineMiss == 0 && r.stats().framesRepaired == 1);
        feed(r, 4, 3, false, 50, {1});
        feed(r, 5, 2, false, 66);  // strict: frame gap -> keyframe at once
        CHECK(rec.nacks.size() == 1);
        CHECK(r.stats().strictRecoveryEvents == 1);
    }
}

// Third review item 1: the strict path (NACK paused) keeps the same
// per-stream watermark. Frame 11 is shown, frame 12 misses its deadline
// (recovery clears lastSubmitted_), NACK pauses, then a late original (not a
// retransmit, e.g. a network duplicate) of keyframe 10 arrives complete. It
// must not be shown again, and it is not a restart.
static void testStrictLateOriginalNeverGoesBackwards() {
    Recorder rec;
    VideoReceiver r(nackConfig(), rec.hooks());
    r.start();
    feed(r, 1, 2, true, 0);
    for (uint64_t f = 2; f <= 9; ++f) feed(r, f, 2, false, double(f));
    feed(r, 10, 4, true, 10);
    feed(r, 11, 2, false, 11);
    CHECK(rec.subs.size() == 11 && rec.subs.back().fid == 11);
    feed(r, 12, 4, false, 12, {1});  // hole at 12 ms
    r.tick(14.5);                    // NACK sent
    r.setRttMs(60);
    r.tick(20);                      // NACK paused, frame 12 settling
    r.tick(12 + 41);                 // deadline: recovery, then strict path
    CHECK(r.stats().nackDeadlineMiss == 1);
    CHECK(r.stats().nackPausedRtt == 1);
    feed(r, 10, 4, true, 60);        // late original keyframe 10
    CHECK(rec.subs.size() == 11 && rec.subs.back().fid == 11);
    CHECK(r.stats().streamRestarts == 0);
    CHECK(r.stats().latePacketsIgnored >= 4);
    feed(r, 13, 3, true, 70);        // a fresh keyframe is accepted
    CHECK(rec.subs.size() == 12 && rec.subs.back().fid == 13 && rec.subs.back().disc);
    // A real host restart still resets the watermark on this path.
    auto fresh = packet(1, 0, 1, true);
    r.onPacket(fresh.data(), fresh.size(), 400, 300);
    CHECK(r.stats().streamRestarts == 1);
    CHECK(rec.subs.size() == 13 && rec.subs.back().fid == 1);
}

// Third review item 2: a held keyframe keeps its 40 ms deadline after NACK
// pauses, also while the receiver is waiting for a keyframe (startup and
// recovery). The miss is counted and the late repair is not shown.
static void testPauseDeadlineWhileWaiting() {
    // Startup: first keyframe has a hole at 16 ms.
    auto startup = [](Recorder& rec, VideoReceiver& r) {
        r.start();
        feed(r, 1, 4, true, 16, {1});
        r.tick(18.5);
        CHECK(rec.nacks.size() == 1);
        r.setRttMs(60);
        r.tick(30);  // switch to paused while waiting for the first keyframe
        CHECK(r.stats().nackPausedRtt == 1);
    };
    {   Recorder rec;
        VideoReceiver r(nackConfig(), rec.hooks());
        startup(rec, r);
        auto p = packet(1, 1, 4, true, true);
        r.onPacket(p.data(), p.size(), 61, 0);
        CHECK(rec.subs.empty());
        CHECK(r.stats().nackDeadlineMiss == 1);
        CHECK(r.stats().framesRepaired == 0);
        feed(r, 2, 3, true, 70);  // next keyframe, strict path
        CHECK(rec.subs.size() == 1 && rec.subs.back().fid == 2);
    }
    {   Recorder rec;  // timer only
        VideoReceiver r(nackConfig(), rec.hooks());
        startup(rec, r);
        r.tick(16 + 41);
        CHECK(r.stats().nackDeadlineMiss == 1);
        CHECK(rec.nacks.size() == 1);
    }
    {   Recorder rec;  // repair inside the hold is shown
        VideoReceiver r(nackConfig(), rec.hooks());
        startup(rec, r);
        auto p = packet(1, 1, 4, true, true);
        r.onPacket(p.data(), p.size(), 16 + 30, 0);
        CHECK(rec.subs.size() == 1 && rec.subs.back().fid == 1);
        CHECK(r.stats().nackDeadlineMiss == 0);
    }
    // Recovery: frame 3 misses its deadline, then recovery keyframe 4 has a
    // hole at 80 ms and NACK pauses while it is held.
    auto recovery = [](Recorder& rec, VideoReceiver& r) {
        r.start();
        feed(r, 1, 2, true, 0);
        feed(r, 2, 2, false, 16);
        feed(r, 3, 4, false, 33, {1});
        r.tick(33 + 41);
        CHECK(r.stats().nackDeadlineMiss == 1);
        feed(r, 4, 4, true, 80, {1});
        r.tick(82.5);
        r.setRttMs(60);
        r.tick(90);
        CHECK(r.stats().nackPausedRtt == 1);
        CHECK(rec.subs.size() == 2);
    };
    {   Recorder rec;
        VideoReceiver r(nackConfig(), rec.hooks());
        recovery(rec, r);
        auto p = packet(4, 1, 4, true, true);
        r.onPacket(p.data(), p.size(), 80 + 45, 0);
        CHECK(rec.subs.size() == 2);
        CHECK(r.stats().nackDeadlineMiss == 2);
    }
    {   Recorder rec;
        VideoReceiver r(nackConfig(), rec.hooks());
        recovery(rec, r);
        auto p = packet(4, 1, 4, true, true);
        r.onPacket(p.data(), p.size(), 80 + 30, 0);
        CHECK(rec.subs.size() == 3 && rec.subs.back().fid == 4 && rec.subs.back().disc);
        CHECK(r.stats().nackDeadlineMiss == 1);
    }
}

// Second review item 4: loss is counted by (frame, index), de-duplicated, in
// every mode. 1 of 4 packets lost per frame is 25%, with every other packet
// arriving twice.
static void testPacketLossAllModes() {
    auto run = [](ReceiverConfig c, double rtt) {
        Recorder rec;
        VideoReceiver r(c, rec.hooks());
        if (rtt > 0) r.setRttMs(rtt);
        r.start();
        for (uint64_t f = 1; f <= 100; ++f) {
            for (int dup = 0; dup < 2; ++dup)
                for (uint16_t i = 0; i < 4; ++i) {
                    if (i == 1) continue;
                    auto p = packet(f, i, 4, f % 50 == 1);
                    r.onPacket(p.data(), p.size(), double(f) * 16, 0);
                }
        }
        r.flushLoss();
        return r.stats();
    };
    ReceiverConfig off;  // strict, NACK off
    for (const ReceiverStats& st : {run(off, 0), run(nackConfig(), 60)}) {
        const ReceiverLoss l = receiverLoss(st.lossExpected, st.lossRaw, st.lossAfterNack);
        CHECK(st.lossExpected == 400);
        CHECK(std::fabs(l.rawPct - 25.0) < 1e-9);
        CHECK(std::fabs(l.afterNackPct - 25.0) < 1e-9);
    }
    // NACK on: the repaired packet counts as raw loss but not as loss left.
    Recorder rec;
    VideoReceiver r(nackConfig(), rec.hooks());
    r.start();
    feed(r, 1, 4, true, 0);
    feed(r, 2, 4, false, 16, {1});
    r.tick(18.5);
    auto p = packet(2, 1, 4, false, true);
    r.onPacket(p.data(), p.size(), 25, 0);
    r.onPacket(p.data(), p.size(), 26, 0);  // duplicate repair
    feed(r, 3, 4, false, 33);
    r.flushLoss();
    CHECK(r.stats().lossExpected == 12 && r.stats().lossRaw == 1 && r.stats().lossAfterNack == 0);
    // A frame with no packet at all counts with the mean frame size.
    PacketLossCounter c;
    for (uint64_t f = 1; f <= 40; ++f)
        if (f != 5) for (uint16_t i = 0; i < 4; ++i) c.original(f, i, 4);
    CHECK(c.wholeFrames == 1 && c.expected == 8 * 4 && c.lostRaw == 4);  // finalized up to frame 8
    c.flush();
    CHECK(c.expected == 160 && c.lostRaw == 4 && c.lostAfterNack == 4);
}

static void testLossPercent() {
    auto l = receiverLoss(1000, 10, 2);
    CHECK(std::fabs(l.rawPct - 1.0) < 1e-9 && std::fabs(l.afterNackPct - 0.2) < 1e-9);
    CHECK(receiverLoss(0, 0, 0).rawPct == 0);
}

// ---------------------------------------------------------------- simulation

struct SimConfig {
    const char* name;
    double lossRate;      // independent per-packet loss
    double burstRate;     // chance per packet that a burst starts
    int burstLen;         // packets lost in a burst
    double oneWayMs;
    double seconds;
    uint32_t seed;
    // Bottleneck after the host pacer (0 = none): capacity in Mbps, drop-tail
    // queue of queueMs at that capacity. From congestFrom to congestTo
    // seconds the capacity is congestMbps instead.
    double capMbps = 0;
    double queueMs = 0;
    double congestFrom = 0, congestTo = 0, congestMbps = 0;
    // Encode-bound host: a frame every hostFrameMs +- hostFrameJitterMs
    // (uniform) instead of exactly 1000/60. 0 = 60 fps.
    double hostFrameMs = 0, hostFrameJitterMs = 0;
    // Relay (DERP) jitter: each video packet gets 0..jitterMs extra delay,
    // spikeRate of them a spikeMs stall; delivery stays in order (TCP relay),
    // so a stall holds the packets behind it.
    double jitterMs = 0, spikeRate = 0, spikeMs = 0;
};

// Host model knobs for the ABR runs (design 2.2).
struct AbrSimOptions {
    bool paceFollows = true;   // pace = UDPPacing.autoMbps(ABR bitrate), else fixed 72 Mbps
    int idrCapFrames = 3;      // DataRateLimits: IDR at most N x the average frame (0 = off)
    bool slopeComp = true;     // host SlopeFilter: cadence compensation + jitter gate (false = ABR v1 as merged)
};

struct SimResult {
    uint64_t forcedIdr = 0, periodicIdr = 0, framesShown = 0, corrupt = 0;
    uint64_t nackTx = 0, repaired = 0, deadlineMiss = 0, hostMiss = 0, overBudget = 0;
    uint64_t resent = 0, lostVideoPackets = 0, keyframeReqTx = 0;
    double repairP50 = 0, repairP95 = 0;
    double lossRawPct = 0;
    double lossAfterNackPct = 0;
    // ABR
    uint64_t abrDown = 0, abrUp = 0, abrReports = 0, queueDrops = 0;
    uint32_t minKbps = 0;
    double recoverS = -2;       // congestTo -> bitrate back at the ceiling (-1 never, -2 n/a)
    double settleKbps = 0;      // time-weighted mean bitrate over the second half of the run
    uint64_t delayDown = 0;     // down-steps with reason "delay"
    double delayP95 = 0;        // encode -> frame submitted at the viewer, ms
    std::vector<std::pair<double, uint32_t>> trace;  // (s, kbps) at each change
};

class Sim {
public:
    Sim(SimConfig c, bool nack, bool abr = false, AbrSimOptions o = {})
        : c_(c), nack_(nack), abr_(abr), o_(o), rng_(c.seed), slope_(1000.0 / 60), ctl_(18000),
          hostRng_(c.seed * 7919 + 1), hostSlope_(1000.0 / 60) {}

    SimResult run() {
        ReceiverConfig rc;
        rc.strict = true;
        rc.nack = nack_;
        ReceiverHooks h;
        h.submit = [this](uint64_t fid, const std::vector<uint8_t>&, bool disc, bool key) { onSubmit(fid, disc, key); };
        h.resetForNewStream = [] {};
        h.requestKeyframe = [this] { viewerRequestKeyframe(); };
        h.sendNack = [this](uint64_t fid, const std::vector<NackRange>& r) {
            const auto msg = encodeNack(++seq_, fid, r);
            (void)msg;  // layout covered by testNackEncoding
            sendUp([this, fid, r] { hostNack(fid, r); });
        };
        rx_ = std::make_unique<VideoReceiver>(rc, h);
        rx_->setRttMs(2 * c_.oneWayMs);
        rx_->start();
        r_.minKbps = ctl_.current();
        r_.trace.push_back({0, ctl_.current()});

        if (c_.hostFrameMs > 0) {
            std::uniform_real_distribution<double> j(-c_.hostFrameJitterMs, c_.hostFrameJitterMs);
            uint64_t f = 0;
            for (double t = c_.hostFrameMs; t <= c_.seconds * 1000.0; t += std::max(1.0, c_.hostFrameMs + j(hostRng_))) {
                ++f;
                at(t, [this, f] { hostEncode(f); });
            }
        } else {
            const double frameMs = 1000.0 / 60.0;
            const uint64_t frames = uint64_t(c_.seconds * 60.0);
            for (uint64_t f = 1; f <= frames; ++f) at(f * frameMs, [this, f] { hostEncode(f); });
        }
        for (double t = 0; t < c_.seconds * 1000.0 + 500; t += 2.0) at(t, [this, t] { rx_->tick(t); });
        if (abr_)
            for (double t = kReceiverReportIntervalMs; t < c_.seconds * 1000.0; t += kReceiverReportIntervalMs)
                at(t, [this] { viewerReport(); });
        while (!q_.empty()) {
            Ev e = q_.top();
            q_.pop();
            now_ = e.t;
            e.fn();
        }
        const auto& st = rx_->stats();
        r_.nackTx = st.nackTx;
        r_.repaired = st.framesRepaired;
        r_.deadlineMiss = st.nackDeadlineMiss;
        r_.repairP50 = receiverPercentile(st.repairMs, 50);
        r_.repairP95 = receiverPercentile(st.repairMs, 95);
        rx_->flushLoss();
        const ReceiverLoss loss = receiverLoss(st.lossExpected, st.lossRaw, st.lossAfterNack);
        r_.lossRawPct = loss.rawPct;
        r_.lossAfterNackPct = loss.afterNackPct;
        r_.abrDown = ctl_.downs();
        r_.abrUp = ctl_.ups();
        {   // time-weighted mean bitrate over the second half
            const double from = c_.seconds / 2, to = c_.seconds;
            double sum = 0;
            const auto& tr = r_.trace;
            for (size_t i = 0; i < tr.size(); ++i) {
                const double a = std::max(from, tr[i].first);
                const double b = std::min(to, i + 1 < tr.size() ? tr[i + 1].first : to);
                if (b > a) sum += (b - a) * tr[i].second;
            }
            r_.settleKbps = sum / (to - from);
        }
        if (!delays_.empty()) {
            std::sort(delays_.begin(), delays_.end());
            r_.delayP95 = delays_[std::min(delays_.size() - 1, delays_.size() * 95 / 100)];
        }
        if (abr_ && c_.congestTo > 0) {
            r_.recoverS = -1;
            // First time at or after congestTo that the bitrate is back at the ceiling.
            const auto& tr = r_.trace;
            for (size_t i = 0; i < tr.size(); ++i) {
                const bool atCeiling = tr[i].second == ctl_.ceiling();
                const double until = i + 1 < tr.size() ? tr[i + 1].first : 1e18;
                if (atCeiling && until > c_.congestTo) { r_.recoverS = std::max(0.0, tr[i].first - c_.congestTo); break; }
            }
        }
        return r_;
    }

private:
    struct Ev {
        double t;
        uint64_t order;
        std::function<void()> fn;
        bool operator<(const Ev& o) const { return t != o.t ? t > o.t : order > o.order; }
    };
    struct Cached { uint16_t count; bool key; double sentMs; };

    void at(double t, std::function<void()> fn) { q_.push({t, ++order_, std::move(fn)}); }

    bool linkLoses() {
        if (burstLeft_ > 0) { --burstLeft_; return true; }
        std::uniform_real_distribution<double> u(0, 1);
        if (c_.burstRate > 0 && u(rng_) < c_.burstRate) { burstLeft_ = c_.burstLen - 1; return true; }
        return u(rng_) < c_.lossRate;
    }

    double capacityAt(double ms) const {
        if (c_.congestTo > 0 && ms >= c_.congestFrom * 1000 && ms < c_.congestTo * 1000) return c_.congestMbps;
        return c_.capMbps;
    }

    // host -> viewer video packet, paced at 72 Mbps (0.156 ms per 1400 B),
    // then through the bottleneck (if any): drop-tail when the packet would
    // wait more than queueMs.
    void sendVideo(uint64_t fid, uint16_t idx, uint16_t cnt, bool key, bool retransmit) {
        // UDPPacing.autoMbps: 4x bitrate, 40..400 Mbps (18 Mbps -> 72).
        const double paceMbps = (abr_ && o_.paceFollows) ? std::clamp(ctl_.current() * 4 / 1000.0, 40.0, 400.0) : 72.0;
        const double paceMs = 1400.0 * 8 / (paceMbps * 1e6) * 1000.0;
        linkFreeMs_ = std::max(linkFreeMs_, now_) + paceMs;
        double out = linkFreeMs_;
        const double cap = capacityAt(out);
        if (cap > 0) {
            const double start = std::max(bottleFreeMs_, out);
            if (start - out > c_.queueMs) { ++r_.queueDrops; ++r_.lostVideoPackets; return; }
            bottleFreeMs_ = start + 1400.0 * 8 / (cap * 1e6) * 1000.0;
            out = bottleFreeMs_;
        }
        if (linkLoses()) { ++r_.lostVideoPackets; return; }
        double arrive = out + c_.oneWayMs;
        if (c_.jitterMs > 0 || c_.spikeRate > 0) {
            std::uniform_real_distribution<double> u(0, 1);
            arrive += u(hostRng_) * c_.jitterMs;
            if (u(hostRng_) < c_.spikeRate) arrive += c_.spikeMs;
            arrive = std::max(arrive, relayLastMs_);  // in order
            relayLastMs_ = arrive;
        }
        auto p = packet(fid, idx, cnt, key, retransmit);
        at(arrive, [this, p, arrive, fid, retransmit] {
            const long long gap = haveLast_ ? (long long)(arrive - lastArrive_) : 0;
            haveLast_ = true;
            lastArrive_ = arrive;
            slope_.onPacket(fid, retransmit, arrive);
            rx_->onPacket(p.data(), p.size(), arrive, gap);
        });
    }
    // viewer -> host control message, same loss and delay
    void sendUp(std::function<void()> fn) {
        if (linkLoses()) return;
        at(now_ + c_.oneWayMs, std::move(fn));
    }

    void hostEncode(uint64_t fid) {
        bool key = fid == 1 || fid % 600 == 0;
        if (key && fid != 1) ++r_.periodicIdr;
        if (!key && forceKeyPending_) { key = true; ++r_.forcedIdr; }
        forceKeyPending_ = false;
        // 4K IDR 250 packets / P frame 28 packets at 18 Mbps; both scale with
        // the ABR bitrate (the encoder targets an average, so this is a model).
        hostSlope_.onPacket(fid, false, now_);  // encoder hands the frame to the sender
        const uint32_t kbps = ctl_.current();
        const uint32_t frameBytes = c_.hostFrameMs > 0 ? uint32_t(kbps * 1000.0 / 8 * c_.hostFrameMs / 1000.0)
                                                       : kbps * 1000 / 8 / 60;
        const uint16_t pCnt = uint16_t(std::max<uint32_t>(4, (frameBytes + 1379) / 1380));
        uint16_t cnt = key ? uint16_t(std::max<uint32_t>(60, 250 * kbps / 18000)) : pCnt;
        if (key && abr_ && o_.idrCapFrames > 0) cnt = std::min<uint16_t>(cnt, uint16_t(pCnt * o_.idrCapFrames));
        encodedAt_[fid] = now_;
        cache_[fid] = {cnt, key, now_};
        evict();
        for (uint16_t i = 0; i < cnt; ++i) sendVideo(fid, i, cnt, key, false);
        // Host send queue: frames handed to the pacer whose last packet has not left.
        while (!pacerFrames_.empty() && pacerFrames_.front() <= now_) pacerFrames_.pop_front();
        pacerFrames_.push_back(linkFreeMs_);
        queueMax_ = std::max<int>(queueMax_, int(pacerFrames_.size()));
    }

    void evict() {
        auto bytes = [&] {
            size_t b = 0;
            for (auto& e : cache_) b += size_t(e.second.count) * 1380;
            return b;
        };
        while (!cache_.empty() &&
               (now_ - cache_.begin()->second.sentMs > 250 || cache_.size() > 32 || bytes() > 4 * 1024 * 1024))
            cache_.erase(cache_.begin());
    }

    void hostKeyframeRequest() {  // KeyframeRequestGate(0.15)
        if (lastGateMs_ >= 0 && now_ - lastGateMs_ < 150) return;
        lastGateMs_ = now_;
        forceKeyPending_ = true;
    }

    void hostNack(uint64_t fid, const std::vector<NackRange>& ranges) {
        evict();
        auto it = cache_.find(fid);
        if (it == cache_.end()) { ++r_.hostMiss; hostKeyframeRequest(); return; }  // D2-B
        // 20% of 18 Mbps in any 100 ms (sliding, same as RetransmitBudget)
        const double budgetBytes = ctl_.current() * 1e3 / 8 * 0.2 * 0.1;
        while (!budget_.empty() && now_ - budget_.front().first >= 100) {
            budgetUsed_ -= budget_.front().second;
            budget_.pop_front();
        }
        std::vector<uint16_t> idx;
        for (auto& r : ranges) {
            const uint32_t end = std::min<uint32_t>(uint32_t(r.start) + r.count, it->second.count);
            for (uint32_t i = r.start; i < end; ++i) idx.push_back(uint16_t(i));
        }
        const double need = double(idx.size()) * 1400;
        if (budgetUsed_ + need > budgetBytes) { ++r_.overBudget; ++overBudgetTotal_; return; }
        budgetUsed_ += need;
        budget_.push_back({now_, need});
        for (uint16_t i : idx) { sendVideo(fid, i, it->second.count, it->second.key, true); ++r_.resent; }
    }

    void viewerRequestKeyframe() {  // MouseMoveUdpChannel: 1 per 100 ms
        if (lastKeyReqMs_ >= 0 && now_ - lastKeyReqMs_ < 100) return;
        lastKeyReqMs_ = now_;
        ++r_.keyframeReqTx;
        sendUp([this] { hostKeyframeRequest(); });
    }

    // Viewer, every 250 ms: loss deltas (finalized frames) and the slope.
    void viewerReport() {
        const auto& st = rx_->stats();
        ReceiverReport sent;
        sent.windowMs = uint16_t(kReceiverReportIntervalMs);
        sent.expected = uint32_t(st.lossExpected - prevExp_);
        sent.lostRaw = uint32_t(st.lossRaw - prevRaw_);
        sent.lostAfterNack = uint32_t(st.lossAfterNack - prevAfter_);
        prevExp_ = st.lossExpected; prevRaw_ = st.lossRaw; prevAfter_ = st.lossAfterNack;
        const auto w = slope_.take();
        sent.slopeValid = w.valid;
        sent.slope01Ms = abrSlopeTo01Ms(w.slopeMs);
        sent.rttMs = uint16_t(2 * c_.oneWayMs);
        // Round trip through the wire format: the host decode must accept
        // every report a real viewer sends.
        const auto wire = encodeReceiverReport(++seq_, sent);
        ReceiverReport rep;
        CHECK(wire.size() == kReceiverReportBytes && decodeReceiverReport(wire.data(), wire.size(), rep));
        sendUp([this, rep] { hostReport(rep); });
    }

    void hostReport(const ReceiverReport& rep) {
        ++r_.abrReports;
        AbrInput in;
        in.nowMs = uint64_t(now_);
        in.expected = rep.expected;
        in.lostRaw = rep.lostRaw;
        in.lostAfterNack = rep.lostAfterNack;
        in.slopeValid = rep.slopeValid;
        in.slope01Ms = rep.slope01Ms;
        const auto hostWindow = hostSlope_.take();
        if (o_.slopeComp) {
            const SlopeEstimate e = slopeFilter_.onReport(rep.slopeValid, rep.slope01Ms, hostWindow);
            in.slopeValid = e.valid;
            in.slope01Ms = e.slope01Ms;
            in.slopeFlat = e.flat;
        } else {
            in.slopeFlat = !rep.slopeValid;  // ABR v1 as merged: no slope counted as clear
        }
        in.overBudgetDelta = overBudgetTotal_ - overBudgetSeen_;
        overBudgetSeen_ = overBudgetTotal_;
        while (!pacerFrames_.empty() && pacerFrames_.front() <= now_) pacerFrames_.pop_front();
        in.queueMax = queueMax_;
        queueMax_ = int(pacerFrames_.size());
        AbrChange ch;
        if (ctl_.onReport(in, ch)) {
            r_.trace.push_back({now_ / 1000.0, ch.toKbps});
            r_.minKbps = std::min(r_.minKbps, ch.toKbps);
            if (ch.toKbps < ch.fromKbps && ch.reason == "delay") ++r_.delayDown;
        }
    }

    void onSubmit(uint64_t fid, bool disc, bool key) {
        if (auto it = encodedAt_.find(fid); it != encodedAt_.end()) {
            delays_.push_back(float(now_ - it->second));
            encodedAt_.erase(encodedAt_.begin(), std::next(it));
        }
        // Decoder model: a frame decodes cleanly if it is a keyframe after a
        // discontinuity, or the direct successor of a cleanly decoded frame.
        bool ok;
        if (disc) ok = key;
        else ok = decoderValid_ && fid == lastDecoded_ + 1;
        if (!ok) ++r_.corrupt;
        decoderValid_ = ok;
        lastDecoded_ = fid;
        if (ok) ++r_.framesShown;
    }

    SimConfig c_;
    bool nack_;
    bool abr_;
    AbrSimOptions o_;
    std::mt19937 rng_;
    ArrivalSlope slope_;
    AbrController ctl_;
    std::deque<double> pacerFrames_;
    int queueMax_ = 0;
    double bottleFreeMs_ = 0;
    uint64_t overBudgetTotal_ = 0, overBudgetSeen_ = 0;
    uint64_t prevExp_ = 0, prevRaw_ = 0, prevAfter_ = 0;
    std::map<uint64_t, double> encodedAt_;
    std::vector<float> delays_;
    std::priority_queue<Ev> q_;
    uint64_t order_ = 0;
    double now_ = 0;
    std::unique_ptr<VideoReceiver> rx_;
    SimResult r_;
    uint32_t seq_ = 0;
    int burstLeft_ = 0;
    double linkFreeMs_ = 0;
    bool haveLast_ = false;
    double lastArrive_ = 0;
    std::map<uint64_t, Cached> cache_;
    std::deque<std::pair<double, double>> budget_;
    double budgetUsed_ = 0;
    double lastGateMs_ = -1, lastKeyReqMs_ = -1;
    bool forceKeyPending_ = false;
    bool decoderValid_ = false;
    uint64_t lastDecoded_ = 0;
    std::mt19937 hostRng_;     // host cadence and relay jitter (off the link-loss stream)
    ArrivalSlope hostSlope_;   // host send-cadence slope (compensation)
    SlopeFilter slopeFilter_;
    double relayLastMs_ = 0;
};

static void runSimulation() {
    const SimConfig scenarios[] = {
        {"direct_0.1pct", 0.001, 0, 0, 5, 60, 11},
        {"direct_0.5pct", 0.005, 0, 0, 5, 60, 12},
        {"direct_1pct", 0.01, 0, 0, 5, 60, 13},
        {"direct_burst4", 0.0005, 0.0005, 4, 5, 60, 14},
        {"derp_0.5pct_rtt60", 0.005, 0, 0, 30, 60, 15},
    };
    std::printf("\nloss simulation, 60 s at 60 fps, 28-packet P frames, 250-packet IDR\n");
    std::printf("%-20s %-5s %8s %8s %7s %8s %8s %7s %7s %7s %8s %8s %9s %9s\n", "scenario", "nack", "forced", "shown",
                "corrupt", "nack_tx", "repaired", "dl_miss", "h_miss", "budget", "rep_p50", "rep_p95", "loss_raw", "loss_left");
    for (const auto& s : scenarios) {
        SimResult off = Sim(s, false).run();
        SimResult on = Sim(s, true).run();
        for (int k = 0; k < 2; ++k) {
            const SimResult& r = k ? on : off;
            std::printf("%-20s %-5s %8llu %8llu %7llu %8llu %8llu %7llu %7llu %7llu %7.1fms %7.1fms %8.3f%% %8.3f%%\n", s.name,
                        k ? "on" : "off", (unsigned long long)r.forcedIdr, (unsigned long long)r.framesShown,
                        (unsigned long long)r.corrupt, (unsigned long long)r.nackTx,
                        (unsigned long long)r.repaired, (unsigned long long)r.deadlineMiss,
                        (unsigned long long)r.hostMiss, (unsigned long long)r.overBudget, r.repairP50,
                        r.repairP95, r.lossRawPct, r.lossAfterNackPct);
        }
        CHECK(off.corrupt == 0);
        CHECK(on.corrupt == 0);
        CHECK(off.nackTx == 0);
        if (s.oneWayMs * 2 < 40 && off.forcedIdr >= 5) {
            // Direct path: NACK must remove most forced IDRs.
            CHECK(on.forcedIdr * 2 <= off.forcedIdr);
        }
        CHECK(on.forcedIdr <= off.forcedIdr);
        if (s.oneWayMs * 2 < 40) {
            CHECK(on.framesShown >= off.framesShown);
        } else {
            // RTT above the fixed 40 ms hold (D1-A): NACK cannot repair in time and
            // falls back to IDR as today. The hold costs a few frames; allow 10%.
            CHECK(on.framesShown * 10 >= off.framesShown * 9);
        }
    }
}

// ---------------------------------------------------------------- ABR v1

static void testReceiverReportEncoding() {
    ReceiverReport r;
    r.slopeValid = true;
    r.windowMs = 250;
    r.expected = 0x01020304;
    r.lostRaw = 7;
    r.lostAfterNack = 2;
    r.slope01Ms = -123;
    r.rttMs = 61;
    const auto p = encodeReceiverReport(0x0A0B0C0D, r);
    const std::vector<uint8_t> want{'M', 'R', 'M', '1', 1, 0x42, 0x0A, 0x0B, 0x0C, 0x0D, 0x01, 0x00, 0xFA,
                                    0x01, 0x02, 0x03, 0x04, 0, 0, 0, 7, 0, 0, 0, 2, 0xFF, 0x85, 0x00, 61};
    CHECK(p == want);
    CHECK(p.size() == kReceiverReportBytes);
    CHECK(abrSlopeTo01Ms(1.26) == 13);
    CHECK(abrSlopeTo01Ms(-1.26) == -13);
    CHECK(abrSlopeTo01Ms(1e9) == 32767);
    ReceiverReport d;
    CHECK(decodeReceiverReport(p.data(), p.size(), d) && d.windowMs == 250 && d.expected == 0x01020304 &&
          d.lostRaw == 7 && d.lostAfterNack == 2 && d.slope01Ms == -123 && d.rttMs == 61 && d.slopeValid);
}

// Malformed 0x42 reports are rejected (same cases as the Swift self-test).
static void testReceiverReportRejectsMalformed() {
    auto bytes = [](uint16_t window, uint32_t expected, uint32_t raw, uint32_t after) {
        ReceiverReport r;
        r.windowMs = window;
        r.expected = expected;
        r.lostRaw = raw;
        r.lostAfterNack = after;
        return encodeReceiverReport(1, r);
    };
    ReceiverReport d;
    auto ok = [&](const std::vector<uint8_t>& p) { return decodeReceiverReport(p.data(), p.size(), d); };
    CHECK(ok(bytes(250, 30, 3, 3)));                    // after == raw: fine
    CHECK(ok(bytes(250, 30, 30, 0)));                   // raw == expected, all repaired: fine
    CHECK(ok(bytes(250, 0, 0, 0)));                     // nothing sent this window: fine
    CHECK(!ok(bytes(0, 30, 0, 0)));                     // window 0
    CHECK(!ok(bytes(0, 30, 0, 0xFFFFFFFFu)));           // Pepper's report
    CHECK(!ok(bytes(250, 30, 0, 0xFFFFFFFFu)));         // after > raw
    CHECK(!ok(bytes(250, 30, 2, 3)));                   // after > raw
    CHECK(!ok(bytes(250, 30, 31, 0)));                  // raw > expected
    auto good = bytes(250, 30, 3, 3);
    CHECK(!decodeReceiverReport(good.data(), good.size() - 1, d));  // short
}

// Loss unknown (under 30 expected in total) is never "clear".
static void testAbrLowSampleNeverClear() {
    auto toFloor = [](AbrController& c) {
        AbrChange ch;
        c.onReport({250, 400, 100, 100, true, 0, 0, 0}, ch);  // 25%: x0.5 -> 9000
        c.onReport({750, 400, 100, 100, true, 0, 0, 0}, ch);  // -> 6000
        CHECK(c.current() == 6000);
    };
    // Pepper's case: 20 expected, 10 lost per report (50% loss) for 10 s.
    AbrController a(18000);
    toFloor(a);
    for (uint64_t t = 1000; t <= 11000; t += 250) {
        AbrChange ch;
        a.onReport({t, 20, 10, 10, false, 0, 0, 0}, ch);
        CHECK(a.current() == 6000);
    }
    CHECK(a.ups() == 0);
    // 50% at low rate from the ceiling: two reports make 40 expected -> heavy.
    AbrController h(18000);
    AbrChange ch;
    CHECK(!h.onReport({250, 20, 10, 10, false, 0, 0, 0}, ch) && h.current() == 18000);
    CHECK(h.onReport({500, 20, 10, 10, false, 0, 0, 0}, ch) && h.current() == 9000 && ch.reason == "heavy_loss");
    // Zero-sample reports (nothing sent) for 10 s: no step up.
    AbrController z(18000);
    toFloor(z);
    for (uint64_t t = 1000; t <= 11000; t += 250) {
        AbrChange c2;
        z.onReport({t, 0, 0, 0, false, 0, 0, 0}, c2);
        CHECK(z.current() == 6000);
    }
    CHECK(z.ups() == 0);
    // They keep a clear period without advancing it: clear 12.0, idle 13.5,
    // clear 15.0 is 1.5 s of clear time (not 3 s), clear 16.5 is 3 s -> up.
    CHECK(!z.onReport({12000, 400, 0, 0, true, 0, 0, 0}, ch));
    CHECK(!z.onReport({13500, 0, 0, 0, false, 0, 0, 0}, ch));
    CHECK(!z.onReport({15000, 400, 0, 0, true, 0, 0, 0}, ch) && z.current() == 6000);
    CHECK(z.onReport({16500, 400, 0, 0, true, 0, 0, 0}, ch) && z.current() == 6900);
}

// Review P1 (Pepper, PR #18): an unknown slope is not clear. Host cadence
// unknown the whole time while the viewer reads +25 ms per 250 ms: v1-style
// "unknown = clear" climbed 6 -> 18 Mbps with 14 up-steps. Now no up-step.
static void testAbrUnknownSlopeNeverClear() {
    AbrController c(18000);
    SlopeFilter f;
    AbrChange ch;
    c.onReport({250, 400, 100, 100, true, 0, 0, 0}, ch);
    c.onReport({750, 400, 100, 100, true, 0, 0, 0}, ch);
    CHECK(c.current() == 6000);
    ArrivalSlope::Window none;  // host window unknown (e.g. 30 fps cadence)
    for (uint64_t t = 1000; t <= 31000; t += 250) {
        const SlopeEstimate e = f.onReport(true, 250, none);
        CHECK(!e.valid && !e.flat);
        AbrInput in{t, 400, 0, 0, e.valid, e.slope01Ms, 0, 0};
        in.slopeFlat = e.flat;
        c.onReport(in, ch);
        CHECK(c.current() == 6000);
    }
    CHECK(c.ups() == 0);
    // Unknown in the middle of a clear period holds it: 2 s flat, 5 s
    // unknown, then 1 s flat is 3 s of clear time -> one up-step.
    AbrController h(18000);
    h.onReport({250, 400, 100, 100, true, 0, 0, 0}, ch);
    h.onReport({750, 400, 100, 100, true, 0, 0, 0}, ch);
    bool up = false;
    uint64_t upAt = 0;
    for (uint64_t t = 1000; t <= 9000 && !up; t += 250) {
        const bool unknown = t > 3000 && t <= 8000;
        AbrInput in{t, 400, 0, 0, false, 0, 0, 0};
        in.slopeFlat = !unknown;
        if (h.onReport(in, ch)) { up = true; upAt = t; }
    }
    CHECK(up && upAt == 9000 && h.current() == 6900);
}

// Review P2: the jitter gate must not hide a queue that keeps growing.
static void testSlopeDriftBound() {
    ArrivalSlope::Window host;
    host.valid = true;
    host.samples = 14;
    {   // B: exactly 4 changes, 0,0,+10,+10,+20 ms. Noise 10 ms gates the
        // last +20 ms, but 40 ms was added over 5 reports: valid, trend 8 ms.
        SlopeFilter f;
        const int s[] = {0, 0, 100, 100, 200};
        SlopeEstimate e;
        for (int v : s) e = f.onReport(true, v, host);
        CHECK(f.noise01Ms() == 100 && f.drift01Ms() == 400);
        CHECK(e.valid && !e.flat && e.slope01Ms == 80);
    }
    {   // A: mean delay and jitter rise together. Mean +10.1 ms per 250 ms
        // (808 ms over 20 s), +-(12 + k/10) ms alternating on top: the old gate
        // hid all 80 reports. Now the trend shows and ABR steps down for delay.
        SlopeFilter f;
        AbrController c(18000);
        AbrChange ch;
        int valid = 0, delayDowns = 0, sum = 0;
        for (int k = 0; k < 80; ++k) {
            const int v = 101 + (k % 2 ? -1 : 1) * (120 + k);
            sum += v;
            const SlopeEstimate e = f.onReport(true, v, host);
            if (k >= 16) CHECK(e.valid && e.slope01Ms > 40);
            if (e.valid) ++valid;
            AbrInput in{uint64_t(250 * (k + 1)), 400, 0, 0, e.valid, e.slope01Ms, 0, 0};
            in.slopeFlat = e.flat;
            if (c.onReport(in, ch) && ch.reason == "delay") ++delayDowns;
        }
        CHECK(sum >= 8000);
        CHECK(valid >= 64 && delayDowns >= 2 && c.current() < 18000);
    }
    {   // Pure relay jitter (+-8 ms, no growth) stays flat, and flat is clear:
        // from the floor ABR climbs back.
        SlopeFilter f;
        AbrController c(18000);
        AbrChange ch;
        c.onReport({250, 400, 100, 100, true, 0, 0, 0}, ch);
        c.onReport({750, 400, 100, 100, true, 0, 0, 0}, ch);
        int flat = 0;
        for (int k = 0; k < 40; ++k) {
            const SlopeEstimate e = f.onReport(true, k % 2 ? -80 : 80, host);
            if (e.flat) ++flat;
            AbrInput in{uint64_t(1000 + 250 * k), 400, 0, 0, e.valid, e.slope01Ms, 0, 0};
            in.slopeFlat = e.flat;
            c.onReport(in, ch);
        }
        CHECK(flat == 36 && c.ups() >= 3);
    }
}

// Review P3: a capture restart numbers frames from 1 again. Without a reset
// the old id 100 makes ids 1..13 "old" (restart rule needs a 120-frame drop)
// and the first window has no samples; after reset() it measures 12 gaps.
static void testCaptureRestartCadence() {
    const double T = 1000.0 / 60;
    ArrivalSlope a(T), b(T);
    for (int f = 1; f <= 100; ++f) { a.onPacket(f, false, f * T); b.onPacket(f, false, f * T); }
    a.take();
    b.take();
    a.reset();
    for (int f = 1; f <= 13; ++f) { a.onPacket(f, false, 5000 + f * T); b.onPacket(f, false, 5000 + f * T); }
    const auto wa = a.take(), wb = b.take();
    CHECK(wa.valid && wa.samples == 12 && std::fabs(wa.slopeMs) < 1e-6);
    CHECK(!wb.valid && wb.samples == 0);
}

static void testArrivalSlope() {
    const double T = 1000.0 / 60;
    {   // steady arrivals: slope 0
        ArrivalSlope a(T);
        for (int f = 1; f <= 16; ++f) a.onPacket(f, false, 100 + f * T);
        const auto w = a.take();
        CHECK(w.valid && w.samples == 15 && std::fabs(w.slopeMs) < 1e-6);
    }
    {   // each frame 1 ms later than the last: +1 ms per frame = 15 ms per 250 ms
        ArrivalSlope a(T);
        for (int f = 1; f <= 16; ++f) a.onPacket(f, false, 100 + f * (T + 1));
        const auto w = a.take();
        CHECK(w.valid && std::fabs(w.slopeMs - 15.0) < 1e-6);
    }
    {   // later packets of the same frame, retransmits and skipped captures do not count
        ArrivalSlope a(T);
        double t = 100;
        for (int f = 1; f <= 10; ++f) {
            t += (f == 5) ? 2 * T : T;          // frame 5: capture skipped one interval
            a.onPacket(f, false, t);
            a.onPacket(f, false, t + 3);        // second packet of the frame
            a.onPacket(f - 1, true, t + 4);     // late retransmit of the previous frame
        }
        const auto w = a.take();
        CHECK(w.valid && w.samples == 8 && std::fabs(w.slopeMs) < 1e-6);
        CHECK(a.skipped() == 1);
    }
    {   // too few samples: unknown; the window resets after take()
        ArrivalSlope a(T);
        for (int f = 1; f <= 5; ++f) a.onPacket(f, false, f * T * 3);
        CHECK(!a.take().valid);
        CHECK(a.take().samples == 0);
    }
}

// Host send-cadence compensation: an encode-bound host (51 fps against the
// 60 fps setting) reads as +44 ms per 250 ms at the viewer with no queue at
// all; the host's own estimate cancels it, real queue growth stays.
// SlopeFilter jitter gate. Same vectors in AbrSelfTest.swift.
static void testSlopeFilter() {
    ArrivalSlope::Window host;
    host.valid = true;
    host.slopeMs = 0;
    host.samples = 14;
    SlopeFilter f;
    // Relay jitter: +-8 ms alternating. The first 4 reports pass (no noise
    // estimate yet), then noise = 160 and +-80 is gated to unknown.
    for (int i = 0; i < 4; ++i) {
        const SlopeEstimate e = f.onReport(true, i % 2 ? -80 : 80, host);
        CHECK(e.valid);
    }
    for (int i = 4; i < 12; ++i) {
        const SlopeEstimate e = f.onReport(true, i % 2 ? -80 : 80, host);
        CHECK(!e.valid && e.flat);
    }
    CHECK(f.noise01Ms() == 160);
    // A queue growing +15 ms per 250 ms barely changes report to report:
    // once most of the last 16 changes are small it is reported again.
    int firstValid = -1;
    for (int i = 0; i < 16; ++i) {
        const SlopeEstimate e = f.onReport(true, 150, host);
        if (e.valid && firstValid < 0) firstValid = i;
        if (i == 15) CHECK(e.valid && e.slope01Ms == 150);
    }
    CHECK(firstValid >= 0 && firstValid <= 9);
    // Direct path: no change, no noise, every slope passes, including 0.
    SlopeFilter d;
    for (int i = 0; i < 10; ++i) {
        const SlopeEstimate e = d.onReport(true, i < 5 ? 0 : 50, host);
        CHECK(e.valid && e.slope01Ms == (i < 5 ? 0 : 50));
    }
    // Unknown viewer or host window: unknown, and no change is measured across it.
    SlopeFilter g;
    CHECK(g.onReport(true, 30, host).valid);
    const SlopeEstimate gv = g.onReport(false, 0, host);
    CHECK(!gv.valid && !gv.flat);
    ArrivalSlope::Window none;
    const SlopeEstimate gh = g.onReport(true, 30, none);
    CHECK(!gh.valid && !gh.flat);
    CHECK(g.onReport(true, 500, host).valid);
    CHECK(g.noise01Ms() == 0);
}

static void testSlopeCompensation() {
    const double T = 1000.0 / 60, gap = 1000.0 / 51;
    ArrivalSlope host(T), viewer(T);
    for (int f = 1; f <= 14; ++f) {
        host.onPacket(f, false, f * gap);
        viewer.onPacket(f, false, 30 + f * gap);  // fixed one-way delay
    }
    const auto hw = host.take(), vw = viewer.take();
    CHECK(vw.valid && vw.slopeMs > 40 && hw.valid);
    const SlopeEstimate e = compensateSlope(true, abrSlopeTo01Ms(vw.slopeMs), hw);
    CHECK(e.valid && std::abs(e.slope01Ms) <= 1);
    // Queue growing 1 ms per frame on top: +15 ms per 250 ms remains.
    for (int f = 1; f <= 14; ++f) {
        host.onPacket(100 + f, false, 1000 + f * gap);
        viewer.onPacket(100 + f, false, 1030 + f * (gap + 1));
    }
    const auto hw2 = host.take(), vw2 = viewer.take();
    const SlopeEstimate e2 = compensateSlope(true, abrSlopeTo01Ms(vw2.slopeMs), hw2);
    CHECK(e2.valid && std::abs(e2.slope01Ms - 150) <= 1);
    // Host window unknown (30 fps: gaps out of range) -> slope unknown.
    ArrivalSlope slow(T);
    for (int f = 1; f <= 8; ++f) slow.onPacket(f, false, f * 33.3);
    CHECK(!compensateSlope(true, 400, slow.take()).valid);
    // Viewer slope unknown stays unknown.
    CHECK(!compensateSlope(false, 400, hw).valid);
}

// Golden trace, ceiling 18000 kbps. AbrSelfTest.swift runs the same inputs
// and must produce the same bitrates.
struct AbrGolden { AbrInput in; uint32_t kbps; };
static const AbrGolden kAbrGolden[] = {
    {{250, 400, 0, 0, true, 0, 0, 0}, 18000},        // clean, at ceiling
    {{500, 400, 12, 12, true, 0, 0, 0}, 14400},      // 3% after NACK: x0.8
    {{750, 400, 12, 12, true, 0, 0, 0}, 14400},      // within 500 ms: hold
    {{1000, 400, 50, 50, true, 0, 0, 0}, 7200},      // 12.5%: heavy x0.5
    {{1250, 400, 0, 0, true, 0, 0, 3}, 7200},        // send queue 3, within 500 ms
    {{1500, 400, 0, 0, true, 0, 0, 3}, 6000},        // x0.8 -> 5760, floor 6000
    {{1750, 400, 0, 0, true, 50, 0, 0}, 6000},       // slope +5 ms once: hold
    {{2000, 400, 0, 0, true, 50, 0, 0}, 6000},       // twice: delay, already at floor
    {{2250, 400, 0, 0, true, 0, 0, 0}, 6000},        // clear starts
    {{5250, 400, 0, 0, true, 0, 0, 0}, 6900},        // clear 3 s: +5% of ceiling
    {{5750, 400, 0, 0, true, 0, 0, 0}, 6900},        // within 1 s of the last step
    {{6250, 400, 0, 0, true, 0, 0, 0}, 7800},
    {{6500, 400, 0, 0, true, 0, 1, 0}, 7800},        // NACK over budget once: hold
    {{6750, 400, 0, 0, true, 0, 1, 0}, 6000},        // twice: heavy x0.5 -> floor
    {{7000, 400, 24, 0, true, 0, 0, 0}, 6000},       // raw 6%, within 500 ms
    {{7250, 20, 10, 10, false, 0, 0, 0, true}, 6000},   // under 30 expected: loss unknown, held over
    {{10250, 400, 0, 0, false, 0, 0, 0, true}, 6000},   // 10 of 420 (2.4%): loss, already at floor
    {{10500, 400, 0, 0, false, 0, 0, 0, true}, 6000},   // slope flat (gated): clear starts
    {{13500, 400, 0, 0, false, 0, 0, 0, true}, 6900},   // clear 3 s: +5% of ceiling
    {{13750, 400, 0, 0, true, 50, 0, 0}, 6900},         // slope +5 ms: not clear
    {{14000, 400, 0, 0, false, 0, 0, 0}, 6900},         // slope unknown: clear does not start
    {{17000, 400, 0, 0, false, 0, 0, 0}, 6900},         // still unknown 3 s later: no step up
    {{17250, 400, 0, 0, false, 0, 0, 0, true}, 6900},   // flat: clear starts
    {{20250, 400, 0, 0, false, 0, 0, 0, true}, 7800},   // clear 3 s
};

static void testAbrControllerGolden() {
    AbrController c(18000);
    CHECK(c.current() == 18000 && c.floor() == 6000);
    for (const auto& g : kAbrGolden) {
        AbrChange ch;
        const uint32_t before = c.current();
        const bool changed = c.onReport(g.in, ch);
        CHECK(c.current() == g.kbps);
        CHECK(changed == (before != g.kbps));
        if (changed) CHECK(ch.fromKbps == before && ch.toKbps == g.kbps && !ch.reason.empty());
    }
    CHECK(c.downs() == 4 && c.ups() == 4);
    c.reset();
    CHECK(c.current() == 18000);
    AbrController low(4000);  // ceiling below 6 Mbps: floor = ceiling, never changes
    AbrChange ch;
    CHECK(!low.onReport({500, 400, 100, 100, true, 0, 0, 0}, ch) && low.current() == 4000);
}

static void printAbrRow(const char* name, const char* abr, const SimResult& r) {
    std::printf("%-27s %-4s %7llu %7llu %7llu %6llu %6llu %7u %8.0f %8.1fms %8llu %s\n", name, abr,
                (unsigned long long)r.forcedIdr, (unsigned long long)r.framesShown, (unsigned long long)r.corrupt,
                (unsigned long long)r.abrDown, (unsigned long long)r.delayDown, r.minKbps, r.settleKbps, r.delayP95,
                (unsigned long long)r.queueDrops,
                r.recoverS == -1 ? "never" : r.recoverS < 0 ? "-" : (std::to_string(r.recoverS).substr(0, 4) + "s").c_str());
}

static void printTrace(const char* name, const SimResult& r) {
    std::printf("  %s bitrate trace (s:kbps):", name);
    size_t n = 0;
    for (auto& [t, k] : r.trace) {
        if (n++ % 10 == 0) std::printf("\n   ");
        std::printf(" %.2f:%u", t, k);
    }
    std::printf("\n");
}

static void runAbrSimulation() {
    SimConfig loss[] = {
        {"direct_0.1pct", 0.001, 0, 0, 5, 60, 11},
        {"direct_1pct", 0.01, 0, 0, 5, 60, 13},
        {"direct_burst4", 0.0005, 0.0005, 4, 5, 60, 14},
        {"derp_0.5pct_rtt60", 0.005, 0, 0, 30, 60, 15},
    };
    SimConfig congest[] = {
        // 100 Mbps link with a 50 ms drop-tail queue; 10..30 s it drops to 10 Mbps.
        {"congest_10mbps_q50", 0.0005, 0, 0, 5, 60, 21, 100, 50, 10, 30, 10},
        // Same with a deep (200 ms) router queue.
        {"congest_10mbps_q200", 0.0005, 0, 0, 5, 60, 24, 100, 200, 10, 30, 10},
        // Same over a relay: RTT 60 ms, 8 Mbps for 20 s.
        {"congest_8mbps_rtt60", 0.0005, 0, 0, 30, 60, 22, 100, 80, 10, 30, 8},
        // Short dip: 12 Mbps for 5 s.
        {"dip_12mbps_5s", 0.0005, 0, 0, 5, 40, 23, 100, 50, 10, 15, 12},
    };
    std::printf("\nABR simulation (NACK on in both), 60 fps, 18 Mbps ceiling, 6 Mbps floor\n");
    std::printf("%-27s %-4s %7s %7s %7s %6s %6s %7s %8s %10s %8s %s\n", "scenario", "abr", "forced", "shown", "corrupt",
                "down", "d_delay", "min_kbps", "settle", "delay_p95", "q_drops", "recover");
    for (const auto& s : loss) {
        SimResult off = Sim(s, true, false).run();
        SimResult on = Sim(s, true, true).run();
        printAbrRow(s.name, "off", off);
        printAbrRow(s.name, "on", on);
        CHECK(on.corrupt == 0);
        CHECK(on.abrReports > 200);
        // Random loss that NACK repairs is not congestion: the bitrate stays up.
        if (s.oneWayMs * 2 < 40) CHECK(on.abrDown == 0 && on.minKbps == 18000);
        CHECK(on.forcedIdr <= off.forcedIdr + 2);
    }
    for (const auto& s : congest) {
        SimResult off = Sim(s, true, false).run();
        SimResult on = Sim(s, true, true).run();
        printAbrRow(s.name, "off", off);
        printAbrRow(s.name, "on", on);
        printTrace(s.name, on);
        CHECK(off.corrupt == 0);
        CHECK(on.corrupt == 0);
        CHECK(on.abrDown >= 1);
        CHECK(on.minKbps < 18000);
        // ABR must cut forced IDRs and show more frames while the link is short.
        CHECK(on.forcedIdr * 2 <= off.forcedIdr);
        CHECK(on.framesShown > off.framesShown);
        // And climb back to the ceiling once the link is clear again.
        CHECK(on.recoverS >= 0 && on.recoverS <= 25);
    }

    // DERP relay with an encode-bound host (Mac hand test, 2026-11-13: the
    // host made 30..52 fps against the 60 fps setting and ABR v1 sat at the
    // floor on "delay"). RTT 60 ms, 0..8 ms relay jitter per packet, 0.05% of
    // packets a 40 ms stall, delivered in order; 0.02% packet loss (the hand
    // test logs show 0 to 0.1% left after NACK). "off" = fixed 18 Mbps,
    // "v1" = ABR as merged, "on" = with the host SlopeFilter.
    //            name                  loss  b  bl ow  s   seed cap q  cf ct cm  frame jit  rj  spike  spMs
    SimConfig derp[] = {
        {"derp_jitter_60fps",          0.0002, 0, 0, 30, 60, 31, 0, 0, 0, 0, 0, 0,    0,   8, 0.0005, 40},
        {"derp_jitter_51fps",          0.0002, 0, 0, 30, 60, 32, 0, 0, 0, 0, 0, 19.6, 3,   8, 0.0005, 40},
        {"derp_jitter_45fps_mixed",    0.0002, 0, 0, 30, 60, 33, 0, 0, 0, 0, 0, 22,   9,   8, 0.0005, 40},
        {"derp_jitter_31fps",          0.0002, 0, 0, 30, 60, 34, 0, 0, 0, 0, 0, 32,   4,   8, 0.0005, 40},
        // Same 51 fps host, real congestion on top: 8 Mbps for 20 s.
        {"derp_jitter_51fps_congest8", 0.0002, 0, 0, 30, 60, 35, 100, 80, 10, 30, 8, 19.6, 3, 8, 0.0005, 40},
    };
    std::printf("\nABR over DERP with an encode-bound host (off = fixed ceiling, v1 = merged ABR, on = host SlopeFilter)\n");
    for (const auto& s : derp) {
        AbrSimOptions v1o;
        v1o.slopeComp = false;
        SimResult off = Sim(s, true, false).run();
        SimResult v1 = Sim(s, true, true, v1o).run();
        SimResult on = Sim(s, true, true).run();
        printAbrRow(s.name, "off", off);
        printAbrRow(s.name, "v1", v1);
        printAbrRow(s.name, "on", on);
        printTrace(s.name, on);
        CHECK(on.corrupt == 0);
        CHECK(on.abrReports > 200);
        if (s.congestTo > 0) {
            // Real congestion still steps down and recovers.
            CHECK(on.abrDown >= 1 && on.minKbps < 18000);
            CHECK(on.recoverS >= 0 && on.recoverS <= 25);
        } else {
            // No congestion: no delay down-steps, settles well above the floor.
            CHECK(on.delayDown == 0);
            CHECK(on.settleKbps >= 12000);
            CHECK(on.settleKbps >= v1.settleKbps);
        }
        // No IDR storm from ABR: at RTT 60 the NACK hold (40 ms) cannot
        // repair a lost packet, so the forced-IDR count follows bitrate
        // (packets per frame); v1 has fewer only because it sits at 6 Mbps.
        // ABR must not add IDRs on top of the fixed-ceiling run.
        CHECK(on.forcedIdr <= off.forcedIdr + 2);
    }
}

// ---- Present scheduling (present_scheduler.hpp) ----------------------------
// A fake swap chain stands in for DXGI: Present() can be told to return
// "busy" (DXGI_ERROR_WAS_STILL_DRAWING) and the latency object can be held
// unsignalled. The screen records which decoded frame each present showed.

struct FakeSwapChain {
    int newest = 0;            // frame id the decoder produced last
    int backBuffer = 0;        // frame id drawn into the back buffer
    std::vector<int> screen;   // frame ids in present order
    int busyLeft = 0;          // the next N Present() calls return Busy
    bool latencySignalled = true;
    int latencyAsks = 0;
    int renders = 0;
    double now = 0.0;

    PresentOps ops() {
        PresentOps o;
        o.latencyReady = [this] { ++latencyAsks; return latencySignalled; };
        o.render = [this] { ++renders; backBuffer = newest; };
        o.present = [this] {
            if (busyLeft > 0) { --busyLeft; return PresentResult::Busy; }
            screen.push_back(backBuffer);
            return PresentResult::Ok;
        };
        o.nowMs = [this] { return now; };
        return o;
    }
};

static void testPresentStillDrawingKeepsFrame() {
    // Old viewer: WAS_STILL_DRAWING dropped the frame for good. Here the
    // same frame must reach the screen on the next loop pass.
    FakeSwapChain sc;
    LatestFramePresenter p(sc.ops());
    sc.newest = 1;
    sc.busyLeft = 1;
    p.onDecoded();
    CHECK(sc.screen.empty());
    CHECK(p.pending());
    CHECK(p.service() == false);       // next loop pass
    CHECK(sc.screen.size() == 1 && sc.screen.back() == 1);
    CHECK(sc.renders == 1);            // drawn once, presented on retry
    CHECK(p.counters().presented == 1);
    CHECK(p.counters().busyDrops == 0);
    CHECK(p.counters().busyRetries == 1);
    CHECK(!p.pending());
    CHECK(p.service() == false);       // nothing pending: no extra present
    CHECK(sc.screen.size() == 1);
}

static void testPresentLatestFrameWins() {
    // Frames 1..3 arrive while the swap chain stays busy: only 3 is shown,
    // 1 and 2 count as busy drops, nothing queues up.
    FakeSwapChain sc;
    LatestFramePresenter p(sc.ops());
    sc.busyLeft = 1000;
    for (int f = 1; f <= 3; ++f) { sc.newest = f; p.onDecoded(); }
    CHECK(sc.screen.empty());
    CHECK(p.counters().busyDrops == 2);
    sc.busyLeft = 0;
    p.service();
    CHECK(sc.screen.size() == 1 && sc.screen.back() == 3);
    CHECK(p.counters().decoded == 3);
    CHECK(p.counters().presented == 1);
    CHECK(p.counters().presented + p.counters().busyDrops == p.counters().decoded);
}

static void testPresentLatencyGate() {
    FakeSwapChain sc;
    LatestFramePresenter p(sc.ops());
    sc.latencySignalled = false;
    sc.newest = 1;
    p.onDecoded();
    CHECK(sc.renders == 0);            // no draw into a buffer still in use
    CHECK(sc.screen.empty());
    CHECK(p.waitingForLatency());
    sc.now = 10.0;
    p.service();
    CHECK(sc.screen.empty());
    // The loop waited on the latency object and it fired.
    p.onLatencySignalled();
    CHECK(sc.screen.size() == 1 && sc.screen.back() == 1);
    // A busy Present() after the slot was taken must not ask for the slot again.
    sc.latencySignalled = true;
    sc.newest = 2;
    sc.busyLeft = 2;
    const int asksBefore = sc.latencyAsks;
    p.onDecoded();
    p.service();
    CHECK(sc.latencyAsks == asksBefore + 1);
    CHECK(sc.screen.size() == 1);
    p.service();
    CHECK(sc.screen.size() == 2 && sc.screen.back() == 2);
    CHECK(sc.latencyAsks == asksBefore + 1);
}

static void testPresentLatencyCap() {
    // An object that never fires (occluded window, driver quirk) must not
    // freeze the picture: after the cap the frame is presented anyway.
    FakeSwapChain sc;
    LatestFramePresenter p(sc.ops());
    sc.latencySignalled = false;
    sc.newest = 7;
    p.onDecoded();
    sc.now = LatestFramePresenter::kLatencyWaitCapMs - 1;
    p.service();
    CHECK(sc.screen.empty());
    sc.now = LatestFramePresenter::kLatencyWaitCapMs + 1;
    p.service();
    CHECK(sc.screen.size() == 1 && sc.screen.back() == 7);
    CHECK(p.counters().latencyTimeouts == 1);
}

static void testPresentLatencyMultiCycle() {
    // The loop waits on the latency object itself (MsgWaitForMultipleObjects)
    // and calls onLatencySignalled() when it fires. Each new frame must start
    // its own wait: a start time left over from the previous frame would make
    // the next wait look older than the cap and skip the gate at once.
    FakeSwapChain sc;
    LatestFramePresenter p(sc.ops());
    sc.latencySignalled = false;
    // Idle gaps longer than the cap (IME popup, cursor blink), then 60 fps.
    double t = 0.0;
    for (int f = 1; f <= 13; ++f) {
        t += (f <= 4) ? 100.0 : 1000.0 / 60.0;
        sc.now = t;
        sc.newest = f;
        p.onDecoded();
        CHECK(sc.screen.size() == static_cast<size_t>(f - 1));   // not presented by a timeout
        CHECK(p.waitingForLatency());
        sc.now = t + 4.0;
        p.service();
        CHECK(sc.screen.size() == static_cast<size_t>(f - 1));
        p.onLatencySignalled();
        CHECK(sc.screen.size() == static_cast<size_t>(f) && sc.screen.back() == f);
    }
    CHECK(p.counters().latencyTimeouts == 0);
    CHECK(p.counters().presented == 13);
    // The cap still works after many cycles: a wait that never fires times
    // out once, measured from this frame's own start.
    t += 100.0;
    sc.now = t;
    sc.newest = 14;
    p.onDecoded();
    sc.now = t + LatestFramePresenter::kLatencyWaitCapMs - 1;
    p.service();
    CHECK(sc.screen.size() == 13);
    sc.now = t + LatestFramePresenter::kLatencyWaitCapMs + 1;
    p.service();
    CHECK(sc.screen.size() == 14 && sc.screen.back() == 14);
    CHECK(p.counters().latencyTimeouts == 1);
    // A wait cut short by clear() (stream reset) must not leak into the next one.
    t += 100.0;
    sc.now = t;
    sc.newest = 15;
    p.onDecoded();
    CHECK(p.waitingForLatency());
    p.clear();
    sc.now = t + 200.0;
    sc.newest = 16;
    p.onDecoded();
    CHECK(sc.screen.size() == 14);
    CHECK(p.counters().latencyTimeouts == 1);
    p.onLatencySignalled();
    CHECK(sc.screen.back() == 16);
}

static void testPresentRepaint() {
    FakeSwapChain sc;
    LatestFramePresenter p(sc.ops());
    p.onRepaint();                     // nothing decoded yet: nothing to draw
    CHECK(sc.renders == 0 && sc.screen.empty());
    sc.newest = 1;
    p.onDecoded();
    CHECK(sc.screen.size() == 1);
    p.onRepaint();                     // WM_PAINT draws the last frame again
    CHECK(sc.screen.size() == 2 && sc.screen.back() == 1);
    CHECK(sc.renders == 2);
    CHECK(p.counters().presented == 1);
    CHECK(p.counters().repaints == 1);
    // A pending repaint replaced by a new frame is not a busy drop.
    sc.busyLeft = 1;
    p.onRepaint();
    sc.newest = 2;
    p.onDecoded();
    CHECK(p.counters().busyDrops == 0);
    CHECK(sc.screen.back() == 2);
    CHECK(p.counters().presented == 2);
    // Resize lost the back buffer while a frame was pending: draw it again.
    sc.busyLeft = 1;
    sc.newest = 3;
    p.onDecoded();
    p.onBuffersLost();
    const int r = sc.renders;
    p.service();
    CHECK(sc.renders == r + 1);
    CHECK(sc.screen.back() == 3);
}

// Loop-level model of the reported laptop case: decoded frames arrive at ~57 fps, the
// receive loop runs every 1 ms, and a presented buffer stays in use until the
// second vsync after it (DWM composition), so a present in that window is
// "still drawing". Old policy drops on busy; the new one retries next pass.
struct PresentLoopResult {
    uint64_t decoded = 0, presented = 0, busyDrops = 0;
    int lastShown = 0;
    double idleFrameShownMs = -1.0;    // when the lone frame after idle reached the screen
};

static PresentLoopResult runPresentLoop(bool newPolicy, double fps, int frames, bool idleFrame) {
    const double vsync = 1000.0 / 60.0;
    double busyUntil = -1.0;
    double now = 0.0;
    int newest = 0, back = 0;
    PresentLoopResult res;
    PresentOps ops;
    ops.render = [&] { back = newest; };
    ops.present = [&] {
        if (now < busyUntil) return PresentResult::Busy;
        busyUntil = (std::floor(now / vsync) + 2.0) * vsync;
        res.lastShown = back;
        if (back == frames + 1 && res.idleFrameShownMs < 0) res.idleFrameShownMs = now;
        return PresentResult::Ok;
    };
    ops.nowMs = [&] { return now; };
    LatestFramePresenter p(ops);
    uint64_t oldPresented = 0, oldDrops = 0;
    int next = 1;
    const double idleAt = frames * (1000.0 / fps) + 500.0;
    for (int ms = 0; ms < static_cast<int>(idleAt) + 200; ++ms) {
        now = ms;
        const bool lone = idleFrame && next == frames + 1 && now >= idleAt;
        if ((next <= frames && now >= (next - 1) * (1000.0 / fps)) || lone) {
            newest = next++;
            if (lone) busyUntil = now + 5.0;   // the frame lands while the last flip is still in use
            if (newPolicy) {
                p.onDecoded();
            } else {
                back = newest;
                if (ops.present() == PresentResult::Busy) ++oldDrops; else ++oldPresented;
            }
            ++res.decoded;
        } else if (newPolicy) {
            p.service();
        }
    }
    if (newPolicy) {
        res.presented = p.counters().presented;
        res.busyDrops = p.counters().busyDrops;
    } else {
        res.presented = oldPresented;
        res.busyDrops = oldDrops;
    }
    return res;
}

static void testPresentLoopOldVsNew() {
    const PresentLoopResult oldR = runPresentLoop(false, 57.0, 570, true);
    const PresentLoopResult newR = runPresentLoop(true, 57.0, 570, true);
    std::printf("present loop 57 fps: old presented=%llu busy_drops=%llu | new presented=%llu busy_drops=%llu\n",
                static_cast<unsigned long long>(oldR.presented), static_cast<unsigned long long>(oldR.busyDrops),
                static_cast<unsigned long long>(newR.presented), static_cast<unsigned long long>(newR.busyDrops));
    CHECK(oldR.decoded == newR.decoded);
    CHECK(oldR.presented + oldR.busyDrops == oldR.decoded);
    CHECK(newR.presented + newR.busyDrops == newR.decoded);
    // Old policy: the lone frame after idle (IME popup) hit a busy present
    // and never reached the screen.
    CHECK(oldR.idleFrameShownMs < 0);
    CHECK(oldR.lastShown != 571);
    // New policy: it is shown once the buffer frees, within two vsyncs.
    CHECK(newR.lastShown == 571);
    CHECK(newR.idleFrameShownMs >= 0);
    // The display can show at most 30 frames/s in this model (a buffer is
    // held for two vsyncs); the new loop must use every slot it gets.
    CHECK(newR.presented > oldR.presented);
    CHECK(newR.presented * 100 >= newR.decoded * 45);
}

int main() {
    testStrictWithoutNack();
    testSingleHoleRepaired();
    testTailLossAndWholeFrame();
    testDeadlineMiss();
    testKeyframeJump();
    testNackEncoding();
    testLateRetransmitIsNotRestart();
    testNackAttemptsPerFrame();
    testDeadlineEnforcedBeforeRepair();
    testLossPercent();
    testHighRttSkipsHold();
    testRebuiltFrameKeepsQuotaAndDeadline();
    testRecoveryNeverGoesBackwards();
    testPauseKeepsHeldDeadline();
    testStrictLateOriginalNeverGoesBackwards();
    testPauseDeadlineWhileWaiting();
    testPacketLossAllModes();
    testPresentedFps();
    testReceiverReportEncoding();
    testArrivalSlope();
    testSlopeCompensation();
    testSlopeFilter();
    testAbrControllerGolden();
    testReceiverReportRejectsMalformed();
    testAbrLowSampleNeverClear();
    testAbrUnknownSlopeNeverClear();
    testSlopeDriftBound();
    testCaptureRestartCadence();
    testPresentStillDrawingKeepsFrame();
    testPresentLatestFrameWins();
    testPresentLatencyGate();
    testPresentLatencyCap();
    testPresentLatencyMultiCycle();
    testPresentRepaint();
    testPresentLoopOldVsNew();
    runSimulation();
    runAbrSimulation();
    if (gFailures) {
        std::printf("\n%d check(s) failed\n", gFailures);
        return 1;
    }
    std::printf("\nall video receiver tests passed\n");
    return 0;
}
