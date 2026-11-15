// Console unit test for audio_jitter.hpp (no Win32).
// 1. MRA1 parse: layout, malformed packets.
// 2. Jitter buffer scripted cases: prebuffer to 20 ms, in-order playback,
//    reorder, loss concealment, late and duplicate drops, underrun growth,
//    overflow trim, restart flag, sequence wrap, target shrink.
// 3. Simulation: 60 s of 5 ms packets over a link with random delay and
//    loss, pulled in 10 ms device periods, at several jitter levels.
#include "audio_jitter.hpp"

#include <cstdio>
#include <random>
#include <vector>

using namespace jl::audio;

static int gFailures = 0;
#define CHECK(cond)                                                                  \
    do {                                                                             \
        if (!(cond)) {                                                               \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);              \
            ++gFailures;                                                             \
        }                                                                            \
    } while (0)

// Capture time follows the sequence from gSeqBase, like a real host stream.
static uint32_t gSeqBase = 0;

// One 5 ms packet whose every sample equals `value` (so playback order is visible).
static std::vector<uint8_t> pkt(uint32_t seq, int16_t value, uint8_t flags = 0) {
    std::vector<int16_t> s(size_t(kFramesPerPacket) * kChannels, value);
    return makeMra1(seq, uint64_t(uint32_t(seq - gSeqBase)) * 5000, flags, s);
}

static void push(JitterBuffer& jb, const std::vector<uint8_t>& p, uint64_t arrivalUs) {
    Mra1Packet m;
    if (!parseMra1(p.data(), p.size(), m)) { CHECK(false); return; }
    jb.push(m, arrivalUs);
}

// Pulls one 5 ms block and returns its first sample (all samples of a packet are equal).
static int16_t pull5(JitterBuffer& jb) {
    std::vector<int16_t> out(size_t(kFramesPerPacket) * kChannels, 12345);
    jb.pull(out.data(), kFramesPerPacket);
    for (int16_t v : out) if (v != out[0]) { CHECK(false); break; }
    return out[0];
}

static void testParse() {
    std::vector<int16_t> s{1, -2, 3, -4};
    auto p = makeMra1(0xfffffffe, 0x0102030405060708ull, kFlagRestart, s);
    CHECK(p.size() == kHeaderBytes + 8);
    Mra1Packet m;
    CHECK(parseMra1(p.data(), p.size(), m));
    CHECK(m.seq == 0xfffffffe && m.captureUs == 0x0102030405060708ull);
    CHECK(m.flags == kFlagRestart && m.frames == 2);
    CHECK(m.pcm[0] == 1 && m.pcm[1] == 0 && m.pcm[2] == 0xfe && m.pcm[3] == 0xff);
    auto full = pkt(7, 100);
    CHECK(full.size() == 980);  // the host's 5 ms packet
    CHECK(parseMra1(full.data(), full.size(), m) && m.frames == 240);
    // Malformed: short, wrong magic, wrong version, length mismatch, zero frames.
    CHECK(!parseMra1(p.data(), 19, m));
    auto bad = p; bad[3] = '2'; CHECK(!parseMra1(bad.data(), bad.size(), m));
    bad = p; bad[4] = 2; CHECK(!parseMra1(bad.data(), bad.size(), m));
    CHECK(!parseMra1(p.data(), p.size() - 1, m));
    bad = makeMra1(1, 0, 0, {}); CHECK(!parseMra1(bad.data(), bad.size(), m));
}

static void testPrebufferAndOrder() {
    JitterBuffer jb;
    CHECK(pull5(jb) == 0);  // nothing yet: silence
    push(jb, pkt(10, 1), 0);
    push(jb, pkt(11, 2), 5000);
    push(jb, pkt(12, 3), 10000);
    CHECK(pull5(jb) == 0);  // 15 ms buffered < 20 ms target: still prebuffering
    push(jb, pkt(13, 4), 15000);
    CHECK(pull5(jb) == 1);
    CHECK(pull5(jb) == 2);
    CHECK(pull5(jb) == 3);
    CHECK(pull5(jb) == 4);
    auto st = jb.stats();
    CHECK(st.packetsRx == 4 && st.lost == 0 && st.underruns == 0);
    CHECK(st.targetMs >= 20.0 - 1e-9);
}

static void testReorderLossLateDuplicate() {
    JitterBuffer jb;
    push(jb, pkt(0, 1), 0);
    push(jb, pkt(2, 3), 10000);  // 1 is reordered
    push(jb, pkt(1, 2), 10500);
    push(jb, pkt(1, 2), 10600);  // duplicate
    push(jb, pkt(4, 5), 20000);  // 3 is lost
    push(jb, pkt(5, 6), 25000);
    CHECK(pull5(jb) == 1);
    CHECK(pull5(jb) == 2);
    CHECK(pull5(jb) == 3);
    CHECK(pull5(jb) == 0);  // seq 3 missing: 5 ms of silence
    push(jb, pkt(3, 4), 30000);  // too late now
    CHECK(pull5(jb) == 5);
    CHECK(pull5(jb) == 6);
    auto st = jb.stats();
    CHECK(st.lost == 1 && st.late == 1 && st.duplicates == 1);
}

static void testUnderrunGrowsTarget() {
    JitterBuffer jb;
    for (uint32_t i = 0; i < 4; ++i) push(jb, pkt(i, int16_t(i + 1)), i * 5000);
    for (int i = 0; i < 4; ++i) CHECK(pull5(jb) == i + 1);
    const double before = jb.stats().targetMs;
    CHECK(pull5(jb) == 0);  // dry
    auto st = jb.stats();
    CHECK(st.underruns == 1);
    CHECK(st.targetMs >= before + JitterBuffer::kUnderrunStepMs - 1e-9);
    CHECK(jb.prebuffering());
    // Many underruns never push the target past 60 ms.
    for (int i = 0; i < 40; ++i) {
        push(jb, pkt(uint32_t(4 + i), 9), 0);
        for (int k = 0; k < 30; ++k) pull5(jb);
    }
    CHECK(jb.stats().targetMs <= JitterBuffer::kMaxTargetMs + 1e-9);
}

static void testOverflowTrim() {
    JitterBuffer jb;
    // A burst of 100 ms arrives at once (e.g. after a Wi-Fi stall).
    for (uint32_t i = 0; i < 20; ++i) push(jb, pkt(i, int16_t(i + 1)), 0);
    auto st = jb.stats();
    CHECK(st.overflowDrops > 0);
    CHECK(st.bufferedMs <= st.targetMs + JitterBuffer::kOverflowSlackMs + 1e-9);
    // Playback resumes with the newest audio, still in order.
    int16_t prev = pull5(jb);
    CHECK(prev > 1);
    for (int i = 0; i < 5; ++i) {
        const int16_t v = pull5(jb);
        CHECK(v == prev + 1);
        prev = v;
    }
}

static void testRestartAndWrap() {
    JitterBuffer jb;
    // Wrap: 0xfffffffe, 0xffffffff, 0, 1.
    const uint32_t s0 = 0xfffffffeu;
    gSeqBase = s0;
    for (uint32_t i = 0; i < 4; ++i) push(jb, pkt(s0 + i, int16_t(i + 1)), i * 5000);
    for (int i = 0; i < 4; ++i) CHECK(pull5(jb) == i + 1);
    CHECK(jb.stats().lost == 0 && jb.stats().late == 0);
    // Host restart: new sequence base with the restart flag.
    push(jb, pkt(500000, 7, kFlagRestart), 100000);
    for (uint32_t i = 1; i < 4; ++i) push(jb, pkt(500000 + i, int16_t(7 + i)), 100000 + i * 5000);
    CHECK(jb.stats().resets == 1);
    CHECK(pull5(jb) == 7);
    CHECK(pull5(jb) == 8);
    // A huge jump without the flag also resets instead of waiting forever.
    for (uint32_t i = 0; i < 4; ++i) push(jb, pkt(9000000 + i, int16_t(20 + i)), 200000 + i * 5000);
    CHECK(jb.stats().resets == 2);
    CHECK(pull5(jb) == 20);
    gSeqBase = 0;
}

static void testShrinkWhenSteady() {
    JitterBuffer jb;
    // Bad start: underruns raise the target.
    for (uint32_t i = 0; i < 4; ++i) push(jb, pkt(i, 1), i * 5000);
    for (int i = 0; i < 6; ++i) pull5(jb);
    const double raised = jb.stats().targetMs;
    CHECK(raised > JitterBuffer::kInitialTargetMs);
    // Then 60 s of perfectly paced packets: target comes back down.
    uint32_t seq = 4;
    uint64_t t = 1'000'000;
    for (int i = 0; i < 12000; ++i) {
        push(jb, pkt(seq++, 1), t);
        t += 5000;
        pull5(jb);
    }
    auto st = jb.stats();
    CHECK(st.targetMs < raised);
    CHECK(st.targetMs >= JitterBuffer::kMinTargetMs - 1e-9);
}

struct SimResult {
    JitterStats st;
    double avgBufferedMs;
};

// 5 ms packets sent on time; each gets base delay + exponential jitter,
// some are lost. The device pulls 10 ms every 10 ms.
static SimResult simulate(double jitterMeanMs, double lossRate, unsigned seed) {
    std::mt19937 rng(seed);
    std::exponential_distribution<double> jit(jitterMeanMs > 0 ? 1.0 / jitterMeanMs : 1e9);
    std::uniform_real_distribution<double> u(0, 1);
    struct Arrival { uint64_t at; uint32_t seq; };
    std::vector<Arrival> arrivals;
    const int packets = 12000;  // 60 s
    for (int i = 0; i < packets; ++i) {
        if (u(rng) < lossRate) continue;
        const double delay = 3.0 + (jitterMeanMs > 0 ? jit(rng) : 0.0);
        arrivals.push_back({uint64_t((i * 5.0 + delay) * 1000.0), uint32_t(i)});
    }
    std::sort(arrivals.begin(), arrivals.end(), [](const Arrival& a, const Arrival& b) { return a.at < b.at; });
    JitterBuffer jb;
    size_t ai = 0;
    std::vector<int16_t> out(480 * kChannels);
    double bufSum = 0;
    int pulls = 0;
    for (uint64_t now = 0; now < uint64_t(packets) * 5000 + 200000; now += 10000) {
        while (ai < arrivals.size() && arrivals[ai].at <= now) {
            auto p = pkt(arrivals[ai].seq, 1);
            push(jb, p, arrivals[ai].at);
            ++ai;
        }
        jb.pull(out.data(), 480);
        bufSum += jb.stats().bufferedMs;
        ++pulls;
    }
    return {jb.stats(), bufSum / pulls};
}

static void testSimulation() {
    std::printf("%-22s %8s %6s %6s %9s %9s %9s %9s\n", "scenario", "rx", "lost", "late",
                "underrun", "overflow", "target_ms", "avg_buf_ms");
    struct Case { const char* name; double jitterMs; double loss; };
    const Case cases[] = {
        {"lan (0.3 ms jitter)", 0.3, 0.0},
        {"wifi (2 ms jitter)", 2.0, 0.002},
        {"tailnet (5 ms)", 5.0, 0.005},
        {"bad link (12 ms)", 12.0, 0.02},
    };
    for (const auto& c : cases) {
        const auto r = simulate(c.jitterMs, c.loss, 42);
        std::printf("%-22s %8llu %6llu %6llu %9llu %9llu %9.1f %9.1f\n", c.name,
                    (unsigned long long)r.st.packetsRx, (unsigned long long)r.st.lost,
                    (unsigned long long)r.st.late, (unsigned long long)r.st.underruns,
                    (unsigned long long)r.st.overflowDrops, r.st.targetMs, r.avgBufferedMs);
        CHECK(r.st.targetMs >= JitterBuffer::kMinTargetMs - 1e-9);
        CHECK(r.st.targetMs <= JitterBuffer::kMaxTargetMs + 1e-9);
        if (c.jitterMs <= 2.0) {
            // A clean link plays almost continuously near the 20 ms target.
            CHECK(r.st.underruns <= 3);
            CHECK(r.avgBufferedMs < 35.0);
        }
    }
}

int main() {
    testParse();
    testPrebufferAndOrder();
    testReorderLossLateDuplicate();
    testUnderrunGrowsTarget();
    testOverflowTrim();
    testRestartAndWrap();
    testShrinkWhenSteady();
    testSimulation();
    if (gFailures) {
        std::printf("audio jitter test: %d FAILURES\n", gFailures);
        return 1;
    }
    std::printf("audio jitter test: all passed\n");
    return 0;
}
