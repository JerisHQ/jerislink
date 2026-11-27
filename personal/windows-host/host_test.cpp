// JerisLink Windows host, H1 tests.
//
// Wire formats against the viewer's own parsers (video_receiver.hpp,
// h264_nal_summary.hpp), colour conversion values, and on Windows a
// loopback: synthetic frames -> the real MF software encoder -> MR02 ->
// jl::VideoReceiver -> an IDR access unit with SPS of the right size.

#include "color_convert.hpp"
#include "host_protocol.hpp"

#include "../windows-client/h264_nal_summary.hpp"
#include "../windows-client/video_receiver.hpp"

#ifdef _WIN32
#include "encoder_mf.hpp"
#include <windows.h>
#include <mfapi.h>
#include <objbase.h>
#endif

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

static int gFailures = 0;
#define CHECK(cond)                                                        \
    do {                                                                   \
        if (!(cond)) {                                                     \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);    \
            ++gFailures;                                                   \
        }                                                                  \
    } while (0)

struct Collected {
    std::vector<std::vector<uint8_t>> frames;
    std::vector<uint64_t> ids;
    std::vector<bool> keys;
    int keyframeRequests = 0;
};

static jl::VideoReceiver makeReceiver(Collected& c) {
    jl::ReceiverHooks h;
    h.submit = [&c](uint64_t fid, const std::vector<uint8_t>& f, bool, bool key) {
        c.ids.push_back(fid);
        c.frames.push_back(f);
        c.keys.push_back(key);
    };
    h.resetForNewStream = [] {};
    h.requestKeyframe = [&c] { ++c.keyframeRequests; };
    h.sendNack = [](uint64_t, const std::vector<jl::NackRange>&) {};
    h.log = [](const std::string&) {};
    return jl::VideoReceiver(jl::ReceiverConfig{}, h);
}

static void testPacketizeRoundTrip() {
    std::vector<uint8_t> au(5000);
    for (size_t i = 0; i < au.size(); ++i) au[i] = uint8_t(i * 7 + 3);
    const auto packets = jlh::packetizeMr02(42, au.data(), au.size(), true, 1200);
    CHECK(packets.size() == 5);  // 1180-byte payloads
    for (size_t i = 0; i < packets.size(); ++i) {
        CHECK(packets[i].size() <= 1200);
        CHECK((packets[i][5] & 0x01) == 0x01);
        CHECK(((packets[i][5] & 0x02) != 0) == (i + 1 == packets.size()));
    }
    // The viewer's receiver puts it back together, in order or not.
    Collected c;
    auto rx = makeReceiver(c);
    rx.start();
    for (size_t i = packets.size(); i-- > 0;) rx.onPacket(packets[i].data(), packets[i].size(), 1.0, 0);
    CHECK(rx.stats().bad == 0);
    CHECK(c.frames.size() == 1);
    if (!c.frames.empty()) {
        CHECK(c.frames[0] == au);
        CHECK(c.ids[0] == 42);
        CHECK(c.keys[0]);
    }
    CHECK(jlh::packetizeMr02(1, au.data(), 0, false).empty());
    const auto one = jlh::packetizeMr02(7, au.data(), 10, false);
    CHECK(one.size() == 1 && one[0].size() == 30 && one[0][5] == 0x02);
}

static void testPacer() {
    jlh::Pacer p(25);  // 4 x 25 = 100 Mbit/s = 12.5 bytes/us
    CHECK(p.mbps() > 99.9 && p.mbps() < 100.1);
    int64_t t = 1000;
    size_t sent = 0;
    while (p.waitUs(t, 1200) == 0) { p.spend(t, 1200); sent += 1200; }
    CHECK(sent >= 32 * 1024 - 1200 && sent <= 32 * 1024);  // the burst
    const int64_t w = p.waitUs(t, 1200);
    CHECK(w > 0 && w <= 100);
    jlh::Pacer lo(4), hi(200);
    CHECK(lo.mbps() > 39.9 && lo.mbps() < 40.1);    // floor 40
    CHECK(hi.mbps() > 399.9 && hi.mbps() < 400.1);  // cap 400
}

static void testControlFrames() {
    const auto f = jlh::mrc1Frame(0x02, std::vector<uint8_t>{1, 2, 3, 4});
    CHECK(f.size() == 12 && f[0] == 'M' && f[3] == '1' && f[4] == 1 && f[5] == 0x02 && f[6] == 0 && f[7] == 4);
    auto h = jlh::parseMrc1Header(f.data());
    CHECK(h && h->type == 0x02 && h->length == 4);
    uint8_t bad[8] = {'M', 'R', 'C', '2', 1, 1, 0, 0};
    CHECK(!jlh::parseMrc1Header(bad));

    // The transition probe: 0x03, 64 bytes, zero MAC.
    std::vector<uint8_t> probe(64, 0);
    for (int i = 0; i < 32; ++i) probe[size_t(i)] = uint8_t(i + 1);
    CHECK(jlh::isTransitionProbe(jlh::Mrc1Header{0x03, 64}, probe.data()));
    probe[63] = 1;  // a real MAC: H1 has no password to check it with
    CHECK(!jlh::isTransitionProbe(jlh::Mrc1Header{0x03, 64}, probe.data()));
    CHECK(!jlh::isTransitionProbe(jlh::Mrc1Header{0x03, 72}, probe.data()));
    // Its answer is what conn_auth.hpp decodes as OpenIpOnly.
    const uint8_t open = jlh::kAuthOpenIpOnly;
    const auto r = jlh::mrc1Frame(jlh::kMsgAuthResult, &open, 1);
    CHECK(r.size() == 9 && r[5] == 0x04 && r[7] == 1 && r[8] == 5);
}

static void testVideoConfig() {
    // auto codec, viewer h264+hevc, default bitrate
    const uint8_t autoReq[6] = {1, 0, 0x03, 0, 0, 0};
    auto d = jlh::decideVideoConfig(autoReq, 6, 25, 1920, 1080);
    CHECK(d.accepted && d.ack.size() == 10);
    CHECK(d.ack[0] == 1 && d.ack[1] == 0 && d.ack[2] == 1);  // status ok, h264
    CHECK(d.ack[3] == 0x08);                                 // size only: no HEVC/NACK/ABR/audio
    CHECK(d.ack[4] == 0 && d.ack[5] == 25 && !d.bitrateChanged);
    CHECK(d.ack[6] == (1920 >> 8) && d.ack[7] == (1920 & 0xff) && d.ack[8] == (1080 >> 8) && d.ack[9] == (1080 & 0xff));
    // HEVC asked: H.264 with the fallback flag
    const uint8_t hevc[6] = {1, 2, 0x03, 0, 0, 40};
    d = jlh::decideVideoConfig(hevc, 6, 25, 0, 0);
    CHECK(d.accepted && d.ack[2] == 1 && (d.ack[3] & 0x04) && (d.ack[3] & 0x01) && !(d.ack[3] & 0x08));
    CHECK(d.bitrateMbps == 40 && d.bitrateChanged && d.ack[5] == 40);
    // refusals: no h264 decoder, bad codec, bitrate out of range, wrong shape
    const uint8_t noH264[6] = {1, 0, 0x02, 0, 0, 0};
    const uint8_t badCodec[6] = {1, 3, 0x01, 0, 0, 0};
    const uint8_t badRate[6] = {1, 1, 0x01, 0, 0, 101};
    const uint8_t badVer[6] = {2, 1, 0x01, 0, 0, 0};
    for (const uint8_t* p : {noH264, badCodec, badRate, badVer}) {
        d = jlh::decideVideoConfig(p, 6, 25, 1920, 1080);
        CHECK(!d.accepted && d.ack.size() == 10 && d.ack[1] == 1 && d.bitrateMbps == 25);
    }
    d = jlh::decideVideoConfig(autoReq, 5, 25, 1920, 1080);
    CHECK(!d.accepted);
}

static void testMrm1() {
    const uint8_t kf[10] = {'M', 'R', 'M', '1', 1, 0x40, 0, 0, 1, 2};
    auto m = jlh::parseMrm1(kf, 10);
    CHECK(m && m->type == 0x40 && m->seq == 0x102);
    CHECK(!jlh::parseMrm1(kf, 9));
    uint8_t ping[18] = {'M', 'R', 'M', '1', 1, 0x43, 0, 0, 0, 9, 1, 2, 3, 4, 5, 6, 7, 8};
    m = jlh::parseMrm1(ping, 18);
    CHECK(m && m->type == 0x43);
    CHECK(!jlh::parseMrm1(ping, 17));
    const auto pong = jlh::mrm1Pong(ping, 18);
    CHECK(pong.size() == 18 && pong[5] == 0x44);
    for (int i = 0; i < 18; ++i)
        if (i != 5) CHECK(pong[size_t(i)] == ping[i]);
}

static void testAnnexB() {
    const std::vector<uint8_t> header{0, 0, 0, 1, 0x67, 0x42, 0, 0, 0, 1, 0x68, 0xce};
    std::vector<uint8_t> idr{0, 0, 0, 1, 0x65, 0x88, 0x84};
    jlh::ensureParameterSets(idr, header);
    const auto t = jlh::annexBNalTypes(idr.data(), idr.size());
    CHECK(t.size() == 3 && t[0] == 7 && t[1] == 8 && t[2] == 5);
    std::vector<uint8_t> p{0, 0, 1, 0x41, 0x9a};
    jlh::ensureParameterSets(p, header);
    CHECK(p.size() == 5);  // not a keyframe: unchanged
    jlh::ensureParameterSets(idr, header);
    CHECK(jlh::annexBNalTypes(idr.data(), idr.size()).size() == 3);  // already has SPS
}

static void testColor() {
    int w = 0, h = 0;
    jlh::fitEven(3840, 2160, 1920, 1080, w, h);
    CHECK(w == 1920 && h == 1080);
    jlh::fitEven(1366, 768, 1920, 1080, w, h);
    CHECK(w == 1366 && h == 768);
    jlh::fitEven(1025, 767, 1920, 1080, w, h);
    CHECK(w == 1024 && h == 766);
    jlh::fitEven(2560, 1600, 1920, 1080, w, h);
    CHECK(w == 1728 && h == 1080);

    // 2x2 of one colour: BT.709 limited-range values.
    auto one = [](uint8_t r, uint8_t g, uint8_t b, int& y, int& cb, int& cr) {
        std::vector<uint8_t> src(16);
        for (int i = 0; i < 4; ++i) { src[size_t(i) * 4] = b; src[size_t(i) * 4 + 1] = g; src[size_t(i) * 4 + 2] = r; src[size_t(i) * 4 + 3] = 255; }
        uint8_t dst[6];
        jlh::bgraToNv12(src.data(), 2, 2, 8, dst, 2, 2);
        y = dst[0]; cb = dst[4]; cr = dst[5];
        return dst[0] == dst[1] && dst[1] == dst[2] && dst[2] == dst[3];
    };
    int y, cb, cr;
    CHECK(one(255, 255, 255, y, cb, cr) && y == 235 && cb == 128 && cr == 128);
    CHECK(one(0, 0, 0, y, cb, cr) && y == 16 && cb == 128 && cr == 128);
    CHECK(one(255, 0, 0, y, cb, cr) && y == 63 && cb == 102 && cr == 240);
    CHECK(one(0, 255, 0, y, cb, cr) && y == 173 && cb == 42 && cr == 26);
    CHECK(one(0, 0, 255, y, cb, cr) && y == 32 && cb == 240 && cr == 118);

    // Downscale picks pixels from the whole source.
    std::vector<uint8_t> src(size_t(8) * 4 * 4, 0);
    for (int x = 4; x < 8; ++x)
        for (int yy = 0; yy < 4; ++yy) for (int k = 0; k < 3; ++k) src[size_t(yy) * 32 + size_t(x) * 4 + size_t(k)] = 255;
    uint8_t dst[6];
    jlh::bgraToNv12(src.data(), 8, 4, 32, dst, 2, 2);
    CHECK(dst[0] == 16 && dst[1] == 235 && dst[2] == 16 && dst[3] == 235);
}

#ifdef _WIN32
// The real encoder, the real packetizer and the viewer's receiver.
static void testEncoderLoopback() {
    const int w = 640, h = 360, fps = 30;
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    MFStartup(MF_VERSION, MFSTARTUP_LITE);
    jlh::MfH264Encoder enc;
    std::string err;
    if (!enc.open(jlh::EncoderConfig{w, h, fps, 8, fps}, err)) {
        std::printf("FAIL encoder.open %s\n", err.c_str());
        ++gFailures;
        MFShutdown();
        return;
    }
    Collected c;
    auto rx = makeReceiver(c);
    rx.start();
    std::vector<uint8_t> bgra(size_t(w) * h * 4), nv12(size_t(w) * h * 3 / 2), au;
    int keys = 0;
    for (int i = 0; i < 12; ++i) {
        for (int y = 0; y < h; ++y)
            for (int x = 0; x < w; ++x) {
                uint8_t* p = &bgra[(size_t(y) * w + x) * 4];
                p[0] = uint8_t(x + i * 8); p[1] = uint8_t(y * 2); p[2] = uint8_t((x ^ y) + i); p[3] = 255;
            }
        jlh::bgraToNv12(bgra.data(), w, h, size_t(w) * 4, nv12.data(), w, h);
        bool key = false;
        if (!enc.encode(nv12.data(), int64_t(i) * 10'000'000 / fps, i == 0 || i == 8, au, key, err)) {
            std::printf("FAIL encoder.encode frame=%d %s\n", i, err.c_str());
            ++gFailures;
            break;
        }
        if (au.empty()) continue;
        if (key) ++keys;
        for (const auto& p : jlh::packetizeMr02(uint64_t(100 + i), au.data(), au.size(), key))
            rx.onPacket(p.data(), p.size(), double(i), 0);
    }
    enc.close();
    MFShutdown();
    CHECK(keys >= 2);  // the first frame and the forced one
    CHECK(c.frames.size() == 12);
    CHECK(rx.stats().bad == 0);
    if (!c.frames.empty()) {
        const auto s = jl::h264::summarizeAnnexB(c.frames[0].data(), c.frames[0].size());
        CHECK(c.keys[0] && s.idr());
        CHECK(s.spsWidth == w && s.spsHeight == h);
        std::printf("loopback first=%zu bytes idr=%d sps=%dx%d frames=%zu keys=%d\n", c.frames[0].size(),
                    int(s.idr()), s.spsWidth, s.spsHeight, c.frames.size(), keys);
    }
    for (size_t i = 1; i < c.frames.size(); ++i) {
        const auto s = jl::h264::summarizeAnnexB(c.frames[i].data(), c.frames[i].size());
        CHECK(s.idr() == c.keys[i]);
        for (int t : s.nalTypes) CHECK(t == 1 || t == 5 || t == 6 || t == 7 || t == 8 || t == 9);
        if (s.idr()) CHECK(s.spsWidth == w);  // every keyframe carries its SPS
    }
}
#endif

int main() {
    testPacketizeRoundTrip();
    testPacer();
    testControlFrames();
    testVideoConfig();
    testMrm1();
    testAnnexB();
    testColor();
#ifdef _WIN32
    testEncoderLoopback();
#endif
    if (gFailures) {
        std::printf("JerisLinkHostTest: %d failure(s)\n", gFailures);
        return 1;
    }
    std::printf("JerisLinkHostTest: all passed\n");
    return 0;
}
