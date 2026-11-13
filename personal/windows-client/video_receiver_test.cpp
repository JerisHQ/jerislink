// Console unit test for video_receiver.hpp (no Win32).
// 1. Small scripted cases: strict without NACK, single hole, tail loss,
//    whole-frame loss, deadline miss, NACK message layout.
// 2. Loss simulation: a modelled host (encoder, 150 ms keyframe gate, frame
//    cache 250 ms / 4 MiB / 32 frames, 20% retransmit budget, D2-B) talks to
//    the real VideoReceiver over a lossy link. Each scenario runs once with
//    NACK and once without, with the same loss pattern seed, and compares
//    the number of forced IDRs.
#include "video_receiver.hpp"

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
};

struct SimResult {
    uint64_t forcedIdr = 0, periodicIdr = 0, framesShown = 0, corrupt = 0;
    uint64_t nackTx = 0, repaired = 0, deadlineMiss = 0, hostMiss = 0, overBudget = 0;
    uint64_t resent = 0, lostVideoPackets = 0, keyframeReqTx = 0;
    double repairP50 = 0, repairP95 = 0;
    double lossRawPct = 0;
    double lossAfterNackPct = 0;
};

class Sim {
public:
    Sim(SimConfig c, bool nack) : c_(c), nack_(nack), rng_(c.seed) {}

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

        const double frameMs = 1000.0 / 60.0;
        const uint64_t frames = uint64_t(c_.seconds * 60.0);
        for (uint64_t f = 1; f <= frames; ++f) at(f * frameMs, [this, f] { hostEncode(f); });
        for (double t = 0; t < c_.seconds * 1000.0 + 500; t += 2.0) at(t, [this, t] { rx_->tick(t); });
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

    // host -> viewer video packet, paced at 72 Mbps (0.156 ms per 1400 B)
    void sendVideo(uint64_t fid, uint16_t idx, uint16_t cnt, bool key, bool retransmit) {
        const double paceMs = 1400.0 * 8 / 72e6 * 1000.0;
        linkFreeMs_ = std::max(linkFreeMs_, now_) + paceMs;
        if (linkLoses()) { ++r_.lostVideoPackets; return; }
        const double arrive = linkFreeMs_ + c_.oneWayMs;
        auto p = packet(fid, idx, cnt, key, retransmit);
        at(arrive, [this, p, arrive] {
            const long long gap = haveLast_ ? (long long)(arrive - lastArrive_) : 0;
            haveLast_ = true;
            lastArrive_ = arrive;
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
        const uint16_t cnt = key ? 250 : 28;  // 4K IDR / 18 Mbps P frame
        cache_[fid] = {cnt, key, now_};
        evict();
        for (uint16_t i = 0; i < cnt; ++i) sendVideo(fid, i, cnt, key, false);
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
        const double budgetBytes = 18e6 / 8 * 0.2 * 0.1;
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
        if (budgetUsed_ + need > budgetBytes) { ++r_.overBudget; return; }
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

    void onSubmit(uint64_t fid, bool disc, bool key) {
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
    std::mt19937 rng_;
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
    runSimulation();
    if (gFailures) {
        std::printf("\n%d check(s) failed\n", gFailures);
        return 1;
    }
    std::printf("\nall video receiver tests passed\n");
    return 0;
}
