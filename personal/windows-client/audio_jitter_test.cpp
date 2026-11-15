// Console unit test for audio_jitter.hpp (no Win32).
// 1. MRA1 parse: layout, malformed packets.
// 2. Jitter buffer scripted cases: prebuffer to 20 ms, in-order playback,
//    reorder, loss concealment, late and duplicate drops, underrun growth,
//    overflow trim, restart flag, sequence wrap, target shrink.
// 3. Opus (MRA1 v2): encode/decode round trip, PLC and in-band FEC under
//    loss, codec switch.
// 4. Drift control: a slow or fast host clock keeps the depth steady.
// 5. Simulation: A1 (5 ms PCM, no drift control) vs A2 (10 ms Opus, drift
//    control) over links with jitter, loss, 20 ms capture bursts and clock
//    drift, pulled in 10 ms device periods.
#include "audio_jitter.hpp"

#include <algorithm>
#include <cmath>
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
    CHECK(m.version == kVersionPcm && m.payloadBytes == 8);
    CHECK(m.payload[0] == 1 && m.payload[1] == 0 && m.payload[2] == 0xfe && m.payload[3] == 0xff);
    auto full = pkt(7, 100);
    CHECK(full.size() == 980);  // the host's 5 ms packet
    CHECK(parseMra1(full.data(), full.size(), m) && m.frames == 240);
    // Malformed: short, wrong magic, wrong version, length mismatch, zero frames.
    CHECK(!parseMra1(p.data(), 19, m));
    auto bad = p; bad[3] = '2'; CHECK(!parseMra1(bad.data(), bad.size(), m));
    bad = p; bad[4] = 3; CHECK(!parseMra1(bad.data(), bad.size(), m));
    // v2 (Opus): any payload of 1..1275 bytes, 2.5/5/10/20 ms frame counts.
    const uint8_t op[3] = {0xfc, 0xff, 0xfe};
    auto o = makeMra1Opus(9, 1234, 0, 480, op, sizeof(op));
    CHECK(parseMra1(o.data(), o.size(), m));
    CHECK(m.version == kVersionOpus && m.frames == 480 && m.payloadBytes == 3 && m.payload[0] == 0xfc);
    CHECK(m.seq == 9 && m.captureUs == 1234);
    CHECK(!parseMra1(o.data(), kHeaderBytes, m));               // empty payload
    bad = makeMra1Opus(9, 0, 0, 500, op, sizeof(op));           // not an Opus frame size
    CHECK(!parseMra1(bad.data(), bad.size(), m));
    std::vector<uint8_t> big(kMaxOpusPayload + 1, 0);
    bad = makeMra1Opus(9, 0, 0, 480, big.data(), big.size());   // over the RFC 6716 limit
    CHECK(!parseMra1(bad.data(), bad.size(), m));
    bad = makeMra1Opus(9, 0, 0, 480, big.data(), kMaxOpusPayload);
    CHECK(parseMra1(bad.data(), bad.size(), m));
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

// ---------------------------------------------------------------- Opus

constexpr double kPi = 3.14159265358979323846;

// Music-like test signal: two tones with a slow tremolo (stereo, different per channel).
static std::vector<int16_t> musicSignal(int frames) {
    std::vector<int16_t> s(size_t(frames) * kChannels);
    for (int i = 0; i < frames; ++i) {
        const double t = double(i) / kSampleRate;
        const double env = 0.75 + 0.25 * std::sin(2 * kPi * 0.5 * t);
        s[size_t(i) * 2] = int16_t(env * (7000 * std::sin(2 * kPi * 440 * t) + 4000 * std::sin(2 * kPi * 1000 * t)));
        s[size_t(i) * 2 + 1] = int16_t(env * (7000 * std::sin(2 * kPi * 660 * t) + 4000 * std::sin(2 * kPi * 1500 * t)));
    }
    return s;
}

// Speech-like test signal: gliding 120..220 Hz harmonics, 4 Hz syllables, some noise.
static std::vector<int16_t> voiceSignal(int frames) {
    std::mt19937 rng(7);
    std::normal_distribution<double> noise(0, 300);
    std::vector<int16_t> s(size_t(frames) * kChannels);
    double phase = 0;
    for (int i = 0; i < frames; ++i) {
        const double t = double(i) / kSampleRate;
        const double f0 = 170 + 50 * std::sin(2 * kPi * 0.7 * t);
        phase += 2 * kPi * f0 / kSampleRate;
        const double syl = std::max(0.0, std::sin(2 * kPi * 4 * t));
        double v = 0;
        for (int h = 1; h <= 12; ++h) v += std::sin(h * phase) / h;
        const int16_t x = int16_t(std::clamp(syl * 6000 * v + noise(rng), -32768.0, 32767.0));
        s[size_t(i) * 2] = x;
        s[size_t(i) * 2 + 1] = x;
    }
    return s;
}

// Same settings as the host (COpusShim): 48 kHz stereo, OPUS_APPLICATION_AUDIO,
// complexity 10, constrained VBR, in-band FEC flag.
static std::vector<std::vector<uint8_t>> opusEncode(const std::vector<int16_t>& pcm, int bitrate, int lossPerc,
                                                    int* lookahead = nullptr) {
    int err = 0;
    OpusEncoder* enc = opus_encoder_create(kSampleRate, kChannels, OPUS_APPLICATION_AUDIO, &err);
    CHECK(enc != nullptr && err == OPUS_OK);
    if (!enc) return {};
    CHECK(opus_encoder_ctl(enc, OPUS_SET_BITRATE(bitrate)) == OPUS_OK);
    CHECK(opus_encoder_ctl(enc, OPUS_SET_COMPLEXITY(10)) == OPUS_OK);
    CHECK(opus_encoder_ctl(enc, OPUS_SET_INBAND_FEC(1)) == OPUS_OK);
    CHECK(opus_encoder_ctl(enc, OPUS_SET_PACKET_LOSS_PERC(lossPerc)) == OPUS_OK);
    if (lookahead) opus_encoder_ctl(enc, OPUS_GET_LOOKAHEAD(lookahead));
    std::vector<std::vector<uint8_t>> out;
    std::vector<uint8_t> buf(kMaxOpusPayload);
    for (size_t off = 0; off + size_t(kOpusFramesPerPacket) * kChannels <= pcm.size();
         off += size_t(kOpusFramesPerPacket) * kChannels) {
        const int n = opus_encode(enc, pcm.data() + off, kOpusFramesPerPacket, buf.data(), opus_int32(buf.size()));
        CHECK(n > 0);
        out.emplace_back(buf.begin(), buf.begin() + std::max(n, 0));
    }
    opus_encoder_destroy(enc);
    return out;
}

// SNR (dB) of out against in delayed by `delay` frames, over in[from..to).
static double snrDb(const std::vector<int16_t>& in, const std::vector<int16_t>& out, size_t delay, size_t from,
                    size_t to) {
    double sig = 0, err = 0;
    for (size_t i = from; i < to && (i + delay) * kChannels + 1 < out.size(); ++i) {
        for (int c = 0; c < kChannels; ++c) {
            const double a = in[i * kChannels + c], b = out[(i + delay) * kChannels + c];
            sig += a * a;
            err += (a - b) * (a - b);
        }
    }
    return 10 * std::log10(sig / std::max(err, 1.0));
}

static std::vector<uint8_t> opusPkt(uint32_t seq, const std::vector<uint8_t>& op, uint8_t flags = 0) {
    return makeMra1Opus(seq, uint64_t(seq) * 10000, flags, kOpusFramesPerPacket, op.data(), op.size());
}

// Pushes packets[i] (skipping drop(i)) and pulls 10 ms per packet, in order;
// returns everything played.
template <typename Drop>
static std::vector<int16_t> playOpus(JitterBuffer& jb, const std::vector<std::vector<uint8_t>>& packets, Drop drop) {
    std::vector<int16_t> out;
    std::vector<int16_t> block(size_t(kOpusFramesPerPacket) * kChannels);
    for (size_t i = 0; i < packets.size(); ++i) {
        if (!drop(i)) push(jb, opusPkt(uint32_t(i), packets[i]), uint64_t(i) * 10000);
        if (i >= 3) {  // let it prebuffer 30 ms first
            jb.pull(block.data(), kOpusFramesPerPacket);
            out.insert(out.end(), block.begin(), block.end());
        }
    }
    return out;
}

static void testOpusRoundTrip() {
    const int frames = kSampleRate * 2;  // 2 s
    const auto in = musicSignal(frames);
    int lookahead = 0;
    const auto packets = opusEncode(in, 128000, 0, &lookahead);
    CHECK(packets.size() == size_t(frames / kOpusFramesPerPacket));
    CHECK(lookahead > 0 && lookahead <= kSampleRate * 7 / 1000);  // <= 7 ms extra latency
    size_t bytes = 0;
    for (const auto& p : packets) {
        bytes += p.size();
        CHECK(p.size() >= 1 && p.size() <= kMaxOpusPayload);
    }
    const double kbps = double(bytes) * 8.0 / (double(frames) / kSampleRate) / 1000.0;
    CHECK(kbps > 100 && kbps < 140);

    // Straight decode.
    int err = 0;
    OpusDecoder* dec = opus_decoder_create(kSampleRate, kChannels, &err);
    CHECK(dec != nullptr);
    std::vector<int16_t> out;
    std::vector<int16_t> block(size_t(kOpusFramesPerPacket) * kChannels);
    for (const auto& p : packets) {
        const int n = opus_decode(dec, p.data(), opus_int32(p.size()), block.data(), kOpusFramesPerPacket, 0);
        CHECK(n == kOpusFramesPerPacket);
        out.insert(out.end(), block.begin(), block.end());
    }
    opus_decoder_destroy(dec);
    const double snr = snrDb(in, out, size_t(lookahead), size_t(frames / 2), size_t(frames) - 2000);

    // Through the jitter buffer: same audio after the prebuffer silence.
    JitterBuffer jb;
    const auto played = playOpus(jb, packets, [](size_t) { return false; });
    const auto st = jb.stats();
    CHECK(st.codec == kVersionOpus && st.packetFrames == kOpusFramesPerPacket);
    CHECK(st.lost == 0 && st.underruns == 0 && st.decodeErrors == 0 && st.plcFrames == 0);
    CHECK(st.payloadBytes == bytes);
    const size_t lead = size_t(st.framesSilence);  // prebuffer only
    const double snrJb = snrDb(in, played, size_t(lookahead) + lead, size_t(frames / 2), size_t(frames) - 4000);
    std::printf("opus round trip: %.1f kbps, lookahead %.2f ms, snr %.1f dB direct, %.1f dB via jitter buffer\n",
                kbps, lookahead * 1000.0 / kSampleRate, snr, snrJb);
    CHECK(snr > 20.0);
    CHECK(snrJb > 20.0);
}

static double energy(const std::vector<int16_t>& s, size_t fromFrame, size_t frames) {
    double e = 0;
    for (size_t i = fromFrame * kChannels; i < (fromFrame + frames) * kChannels && i < s.size(); ++i)
        e += double(s[i]) * s[i];
    return e / double(frames * kChannels);
}

static void testOpusPlc() {
    // Music at 128 kbps with no expected loss is pure CELT: no in-band FEC,
    // so every lost packet is concealed by PLC.
    const auto in = musicSignal(kSampleRate * 2);
    const auto packets = opusEncode(in, 128000, 0);
    int lbrr = 0;
    for (const auto& p : packets) lbrr += opus_packet_has_lbrr(p.data(), opus_int32(p.size())) > 0;
    JitterBuffer jb;
    const auto played = playOpus(jb, packets, [](size_t i) { return i % 10 == 5; });
    const auto st = jb.stats();
    std::printf("opus plc: %zu packets, %d with fec data, lost %llu, plc_frames %llu, fec_recovered %llu\n",
                packets.size(), lbrr, (unsigned long long)st.lost, (unsigned long long)st.plcFrames,
                (unsigned long long)st.fecRecovered);
    CHECK(lbrr == 0);
    CHECK(st.lost == packets.size() / 10);
    CHECK(st.fecRecovered == 0);
    CHECK(st.plcFrames == st.lost * kOpusFramesPerPacket);
    CHECK(st.decodeErrors == 0 && st.underruns == 0);
    // Concealed slots are not silent (PLC continues the tones).
    const size_t lead = size_t(st.framesSilence);
    const double lostSlot = energy(played, lead + 15 * kOpusFramesPerPacket, kOpusFramesPerPacket);
    const double normal = energy(played, lead + 13 * kOpusFramesPerPacket, kOpusFramesPerPacket);
    CHECK(lostSlot > normal * 0.05);
}

static void testOpusFec() {
    // Speech with the encoder told to expect 10% loss runs SILK/hybrid and
    // carries in-band FEC (LBRR) for the previous packet: a lost packet
    // followed by one with LBRR is rebuilt instead of concealed.
    const auto in = voiceSignal(kSampleRate * 4);
    const auto packets = opusEncode(in, 128000, 10);
    int lbrr = 0;
    for (const auto& p : packets) lbrr += opus_packet_has_lbrr(p.data(), opus_int32(p.size())) > 0;
    const auto drop = [](size_t i) { return i % 10 == 5; };
    int expectFec = 0;
    for (size_t i = 0; i + 1 < packets.size(); ++i)
        if (drop(i) && opus_packet_has_lbrr(packets[i + 1].data(), opus_int32(packets[i + 1].size())) > 0)
            ++expectFec;
    JitterBuffer jb;
    playOpus(jb, packets, drop);
    const auto st = jb.stats();
    std::printf("opus fec (speech, loss_perc 10): %zu packets, %d with fec data, lost %llu, fec_recovered %llu, "
                "plc_frames %llu\n", packets.size(), lbrr, (unsigned long long)st.lost,
                (unsigned long long)st.fecRecovered, (unsigned long long)st.plcFrames);
    CHECK(lbrr > 0);
    CHECK(expectFec > 0);
    CHECK(st.fecRecovered == uint64_t(expectFec));
    CHECK(st.plcFrames == (st.lost - st.fecRecovered) * kOpusFramesPerPacket);
    CHECK(st.decodeErrors == 0);
}

static void testCodecSwitch() {
    // An A1 host (PCM) restarts as A2 (Opus): the restart flag switches codec.
    JitterBuffer jb;
    for (uint32_t i = 0; i < 6; ++i) push(jb, pkt(i, 5), i * 5000);
    CHECK(pull5(jb) == 5);
    CHECK(jb.stats().codec == kVersionPcm);
    const auto packets = opusEncode(musicSignal(kSampleRate / 2), 128000, 0);
    std::vector<int16_t> block(size_t(kOpusFramesPerPacket) * kChannels);
    for (uint32_t i = 0; i < packets.size(); ++i) {
        push(jb, opusPkt(100 + i, packets[i], i == 0 ? kFlagRestart : 0), 100000 + i * 10000);
        if (i == 0) {
            CHECK(jb.stats().codec == kVersionOpus && jb.stats().resets == 1);
            push(jb, pkt(6, 5), 100500);  // PCM straggler after the switch: dropped
            CHECK(jb.stats().late == 1);
        }
        if (i >= 3) jb.pull(block.data(), kOpusFramesPerPacket);
    }
    const auto st = jb.stats();
    CHECK(st.decodeErrors == 0 && st.lost == 0 && st.overflowDrops == 0);
    CHECK(st.framesPlayed >= uint64_t(packets.size() - 3) * kOpusFramesPerPacket);
}

// ---------------------------------------------------------------- drift

static void testDriftControl() {
    // Perfectly paced 10 ms Opus packets from a host whose clock runs 1000 ppm
    // slow: without control the depth falls ~1 ms/s; with control it holds.
    const auto& packets = opusEncode(musicSignal(kSampleRate), 128000, 0);
    for (int on = 0; on < 2; ++on) {
        JitterBuffer jb;
        jb.setDriftControl(on == 1);
        std::vector<int16_t> block(480 * kChannels);
        uint64_t nextPull = 0;
        const int n = 6000;  // 60 s
        double lastDepth = 0;
        for (int i = 0; i < n; ++i) {
            const uint64_t at = uint64_t((i + 1) * 10000 * 1.001);
            while (nextPull <= at) {
                jb.pull(block.data(), 480);
                nextPull += 10000;
            }
            push(jb, opusPkt(uint32_t(i), packets[size_t(i) % packets.size()]), at);
            lastDepth = jb.stats().bufferedMs;
        }
        const auto st = jb.stats();
        std::printf("drift 1000 ppm, control %s: underruns %llu, inserted %llu, depth at 60 s %.1f ms\n",
                    on ? "on " : "off", (unsigned long long)st.underruns, (unsigned long long)st.driftInserted,
                    lastDepth);
        if (on) {
            CHECK(st.underruns == 0);
            CHECK(st.driftInserted > 0);
            CHECK(st.driftDropped == 0);
        } else {
            CHECK(st.underruns >= 1);
            CHECK(st.driftInserted == 0);
        }
    }
}

// ---------------------------------------------------------------- simulation

// A1: 5 ms PCM packets, no drift control. A2: 10 ms Opus packets, drift control.
struct Sim {
    const char* name;
    double jitterMs;   // mean of the exponential network jitter
    double loss;
    double driftPpm;   // > 0: the host clock is slow against the viewer's device (buffer drains)
    double burstMs;    // the host sends its packets in bursts of this period (ScreenCaptureKit: 20 ms)
};

struct SimResult {
    JitterStats st;
    double avgBufferedMs;
};

static const std::vector<std::vector<uint8_t>>& opusPool() {
    static const auto pool = opusEncode(musicSignal(kSampleRate * 5), 128000, 0);
    return pool;
}

static SimResult simulate(const Sim& c, bool a2, double seconds, unsigned seed) {
    std::mt19937 rng(seed);
    std::exponential_distribution<double> jit(c.jitterMs > 0 ? 1.0 / c.jitterMs : 1e9);
    std::uniform_real_distribution<double> u(0, 1);
    const int frames = a2 ? kOpusFramesPerPacket : kFramesPerPacket;
    const double pktMs = frames * 1000.0 / kSampleRate;
    const int packets = int(seconds * 1000.0 / pktMs);
    struct Arrival { uint64_t at; uint32_t seq; };
    std::vector<Arrival> arrivals;
    arrivals.reserve(size_t(packets));
    for (int i = 0; i < packets; ++i) {
        if (u(rng) < c.loss) continue;
        const double captured = (i + 1) * pktMs;  // host clock, end of the packet
        const double sent = c.burstMs > 0 ? std::ceil(captured / c.burstMs - 1e-9) * c.burstMs : captured;
        const double at = sent * (1.0 + c.driftPpm * 1e-6) + 3.0 + (c.jitterMs > 0 ? jit(rng) : 0.0);
        arrivals.push_back({uint64_t(at * 1000.0), uint32_t(i)});
    }
    std::stable_sort(arrivals.begin(), arrivals.end(), [](const Arrival& a, const Arrival& b) { return a.at < b.at; });
    JitterBuffer jb;
    jb.setDriftControl(a2);
    const auto& pool = opusPool();
    const std::vector<int16_t> pcm(size_t(kFramesPerPacket) * kChannels, 1000);
    size_t ai = 0;
    std::vector<int16_t> out(480 * kChannels);
    double bufSum = 0;
    int pulls = 0;
    const uint64_t end = uint64_t(seconds * 1e6);
    for (uint64_t now = 0; now < end; now += 10000) {
        while (ai < arrivals.size() && arrivals[ai].at <= now) {
            const uint32_t seq = arrivals[ai].seq;
            const uint64_t capUs = uint64_t(seq * pktMs * 1000.0);
            const auto& op = pool[seq % pool.size()];
            const auto p = a2 ? makeMra1Opus(seq, capUs, 0, uint16_t(frames), op.data(), op.size())
                              : makeMra1(seq, capUs, 0, pcm);
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
    const double seconds = 1200;  // 20 min, like the A1 hand test
    std::printf("\nsimulation: %.0f s each, 10 ms device pulls; A1 = 5 ms PCM, no drift control; "
                "A2 = 10 ms Opus + drift control\n", seconds);
    std::printf("%-30s %3s %7s %5s %5s %8s %8s %5s %7s %7s %7s %6s %7s\n", "scenario", "ver", "rx", "lost",
                "late", "underrun", "overflow", "fec", "plc_ms", "drift+", "drift-", "target", "avg_buf");
    const Sim cases[] = {
        {"lan (0.3 ms jitter)", 0.3, 0.0, 0, 0},
        {"wifi (2 ms, 0.2% loss)", 2.0, 0.002, 0, 0},
        {"tailnet (5 ms, 0.5% loss)", 5.0, 0.005, 0, 0},
        {"bad link (12 ms, 2% loss)", 12.0, 0.02, 0, 0},
        {"20 ms bursts, +300 ppm", 0.3, 0.0, 300, 20},
        {"20 ms bursts, -300 ppm", 0.3, 0.0, -300, 20},
        {"tailnet + bursts + 500 ppm", 5.0, 0.005, 500, 20},
    };
    for (const auto& c : cases) {
        SimResult r[2];
        for (int v = 0; v < 2; ++v) {
            r[v] = simulate(c, v == 1, seconds, 42);
            const auto& st = r[v].st;
            std::printf("%-30s %3s %7llu %5llu %5llu %8llu %8llu %5llu %7llu %7llu %7llu %6.1f %7.1f\n", c.name,
                        v ? "A2" : "A1", (unsigned long long)st.packetsRx, (unsigned long long)st.lost,
                        (unsigned long long)st.late, (unsigned long long)st.underruns,
                        (unsigned long long)st.overflowDrops, (unsigned long long)st.fecRecovered,
                        (unsigned long long)(st.plcFrames / 48), (unsigned long long)st.driftInserted,
                        (unsigned long long)st.driftDropped, st.targetMs, r[v].avgBufferedMs);
            CHECK(st.targetMs >= JitterBuffer::kMinTargetMs - 1e-9);
            CHECK(st.targetMs <= JitterBuffer::kMaxTargetMs + 1e-9);
            CHECK(st.decodeErrors == 0);
        }
        const auto& a1 = r[0].st;
        const auto& a2 = r[1].st;
        // A2 never does worse than A1.
        CHECK(a2.underruns <= a1.underruns + 1);
        CHECK(a2.overflowDrops <= a1.overflowDrops);
        if (c.jitterMs <= 2.0 && c.driftPpm == 0) {
            // A clean link plays almost continuously near the 20 ms target.
            CHECK(a2.underruns <= 3);
            CHECK(r[1].avgBufferedMs < 35.0);
        }
        if (c.driftPpm != 0 && c.jitterMs <= 2.0) {
            // Clock drift alone: A1 underruns (slow host) or drops (fast host);
            // A2 corrects it.
            CHECK(a1.underruns + a1.overflowDrops >= 5);
            CHECK(a2.underruns <= 2 && a2.overflowDrops == 0);
            CHECK(a2.driftInserted + a2.driftDropped > 0);
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
    testOpusRoundTrip();
    testOpusPlc();
    testOpusFec();
    testCodecSwitch();
    testDriftControl();
    testSimulation();
    if (gFailures) {
        std::printf("audio jitter test: %d FAILURES\n", gFailures);
        return 1;
    }
    std::printf("audio jitter test: all passed\n");
    return 0;
}
