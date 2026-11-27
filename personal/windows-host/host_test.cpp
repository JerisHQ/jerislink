// JerisLink Windows host, H1 and H2 tests.
//
// Wire formats against the viewer's own parsers (video_receiver.hpp,
// h264_nal_summary.hpp, host_info.hpp) and key codes (keymap.hpp), colour
// conversion values, and on Windows a loopback: synthetic frames -> the
// real MF software encoder -> MR02 -> jl::VideoReceiver -> an IDR access
// unit with SPS of the right size. Nothing here injects input.

#include "color_convert.hpp"
#include "host_protocol.hpp"

#include "../windows-client/h264_nal_summary.hpp"
#include "../windows-client/host_info.hpp"
#include "../windows-client/keymap.hpp"
#include "../windows-client/video_receiver.hpp"

#ifdef _WIN32
#include "encoder_mf.hpp"
#include <windows.h>
#include <mfapi.h>
#include <objbase.h>
#endif

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
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

    // PING is answered only at the viewer's 4-byte size.
    CHECK(jlh::isValidPing(jlh::Mrc1Header{0x01, 4}));
    CHECK(!jlh::isValidPing(jlh::Mrc1Header{0x01, 0}));
    CHECK(!jlh::isValidPing(jlh::Mrc1Header{0x01, 5}));
    CHECK(!jlh::isValidPing(jlh::Mrc1Header{0x01, 0xFFFF}));
    CHECK(!jlh::isValidPing(jlh::Mrc1Header{0x02, 4}));
}

static void testConnectionSlots() {
    jlh::ConnectionSlots slots(8);
    int taken = 0;
    for (int i = 0; i < 20; ++i) taken += slots.tryAcquire() ? 1 : 0;
    CHECK(taken == 8 && slots.inUse() == 8);
    slots.release();
    CHECK(slots.inUse() == 7);
    CHECK(slots.tryAcquire());
    CHECK(!slots.tryAcquire());
    for (int i = 0; i < 8; ++i) slots.release();
    CHECK(slots.inUse() == 0);
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
    // Types the host does not handle never reach host state, whatever their size.
    for (uint8_t type : {uint8_t(0x41), uint8_t(0x42), uint8_t(0x44), uint8_t(0x45), uint8_t(0x99)}) {
        uint8_t other[32] = {'M', 'R', 'M', '1', 1, type, 0, 0, 0, 1};
        for (size_t n : {size_t(10), size_t(18), size_t(32)}) CHECK(!jlh::parseMrm1(other, n));
    }
    uint8_t kfLong[11] = {'M', 'R', 'M', '1', 1, 0x40, 0, 0, 1, 2, 0};
    CHECK(!jlh::parseMrm1(kfLong, 11));
    // H2: 0x24 pointer, exactly 14 bytes (seq, then nx, ny big-endian).
    const uint8_t ptr[14] = {'M', 'R', 'M', '1', 1, 0x24, 0x80, 0, 0, 5, 0x12, 0x34, 0xFF, 0xFF};
    m = jlh::parseMrm1(ptr, 14);
    CHECK(m && m->type == 0x24 && m->seq == 0x80000005u && m->nx == 0x1234 && m->ny == 0xFFFF);
    for (size_t n : {size_t(10), size_t(13), size_t(18)}) {
        uint8_t other[18] = {'M', 'R', 'M', '1', 1, 0x24, 0, 0, 0, 1};
        CHECK(!jlh::parseMrm1(other, n));
    }
    const auto pong = jlh::mrm1Pong(ping, 18);
    CHECK(pong.size() == 18 && pong[5] == 0x44);
    for (int i = 0; i < 18; ++i)
        if (i != 5) CHECK(pong[size_t(i)] == ping[i]);
}

// ------------------------------------------------------------------ H2

static jlh::Mrc1Header hdr(uint8_t type, uint16_t len) { return jlh::Mrc1Header{type, len}; }

static void testHostInfo() {
    // What the host sends, read by the viewer's own decoder.
    const auto p = jlh::hostInfoPayload(jlh::kPlatformWindows, 0x0F, 2, "0.4.1-h2dev");
    CHECK(p.size() == 8 + 11);
    auto info = jl::hostinfo::decode(p.data(), p.size());
    CHECK(info && info->format == 1 && info->windows() && info->caps == 0x0F && info->monitors == 2 &&
          info->version == "0.4.1-h2dev");
    CHECK(jlh::kHostCapKeyboard == jl::hostinfo::kCapKeyboard && jlh::kHostCapPointer == jl::hostinfo::kCapPointer &&
          jlh::kHostCapCursorShape == jl::hostinfo::kCapCursorShape &&
          jlh::kHostCapTaskManager == jl::hostinfo::kCapTaskManager &&
          jlh::kHostCapPointerSync == jl::hostinfo::kCapPointerSync);
    CHECK(jlh::kMsgHostInfo == jl::hostinfo::kType);
    // The frame the host puts behind the ACK is one the viewer recognises.
    auto frame = jlh::mrc1Frame(jlh::kMsgHostInfo, p);
    CHECK(jl::hostinfo::isFramePrefix(frame.data(), frame.size()));
    CHECK(jl::hostinfo::completeFrameBytes(frame.data(), frame.size()) == frame.size());
    for (size_t n = 1; n < frame.size(); ++n) {
        CHECK(jl::hostinfo::isFramePrefix(frame.data(), n));
        CHECK(jl::hostinfo::completeFrameBytes(frame.data(), n) == 0);
    }
    auto twice = frame;
    twice.insert(twice.end(), frame.begin(), frame.end());
    CHECK(jl::hostinfo::completeFrameBytes(twice.data(), twice.size()) == frame.size());
    // The "replaced" notice (MRC1 0x04) and an ACK are not HOST_INFO.
    const uint8_t notice[9] = {'M', 'R', 'C', '1', 1, 0x04, 0, 1, 6};
    CHECK(!jl::hostinfo::isFramePrefix(notice, 9));
    auto ack = jlh::mrc1Frame(0x41, {1, 0, 1, 0x48, 0, 25});
    CHECK(!jl::hostinfo::isFramePrefix(ack.data(), ack.size()));
    // Version: capped at 64, non-printable bytes made '?'.
    const auto longV = jlh::hostInfoPayload(jlh::kPlatformWindows, 0, 1, std::string(100, 'v') + "\x01");
    CHECK(longV.size() == 8 + 64 && longV[7] == 64);
    const auto odd = jlh::hostInfoPayload(jlh::kPlatformWindows, 0, 1, std::string("a\x01\x7f"));
    info = jl::hostinfo::decode(odd.data(), odd.size());
    CHECK(info && info->version == "a??");
    // Malformed: short, format 0, a version longer than the payload.
    CHECK(!jl::hostinfo::decode(p.data(), 7));
    auto bad = p;
    bad[0] = 0;
    CHECK(!jl::hostinfo::decode(bad.data(), bad.size()));
    bad = p;
    bad[7] = 12;
    CHECK(!jl::hostinfo::decode(bad.data(), bad.size()));
    // A later format with more fields: the known ones still read.
    auto later = p;
    later[0] = 2;
    later.push_back(0xAA);
    info = jl::hostinfo::decode(later.data(), later.size());
    CHECK(info && info->format == 2 && info->windows() && info->version == "0.4.1-h2dev");
    // Header length outside 8..512: not HOST_INFO, left alone.
    const uint8_t tiny[8] = {'M', 'R', 'C', '1', 1, 0x06, 0, 7};
    const uint8_t huge[8] = {'M', 'R', 'C', '1', 1, 0x06, 0x02, 0x01};
    CHECK(!jl::hostinfo::isFramePrefix(tiny, 8) && !jl::hostinfo::isFramePrefix(huge, 8));
}

// Pepper's H2 review, item 1: HOST_INFO goes only to a viewer that asks for
// it in VIDEO_CONFIG (caps 0x08). An older viewer reads exactly the ACK and
// nothing is left unread on its socket.
static void testHostInfoOnlyWhenAsked() {
    const auto hi = jlh::hostInfoPayload(jlh::kPlatformWindows, 0x2F, 1, "0.4.1-h2dev");
    // 0.4.x viewer: h264 + audio, no 0x08.
    const uint8_t oldViewer[6] = {1, 0, 0x05, 0, 0, 0};
    auto d = jlh::decideVideoConfig(oldViewer, 6, 25, 1920, 1080);
    CHECK(d.accepted && !d.hostInfo && d.ack.size() == 10);
    auto reply = jlh::videoConfigReply(d, hi);
    CHECK(reply.size() == 8 + 10);
    CHECK(reply[5] == jlh::kMsgVideoConfigAck && reply[6] == 0 && reply[7] == 10);
    // H2 viewer: 0x08 set. ACK of 11 bytes, [10] = 0x01, then HOST_INFO.
    const uint8_t newViewer[6] = {1, 0, 0x0D, 0, 0, 0};
    d = jlh::decideVideoConfig(newViewer, 6, 25, 1920, 1080);
    CHECK(d.accepted && d.hostInfo && d.ack.size() == 11 && d.ack[10] == jlh::kAckExtHostInfo);
    CHECK(d.ack[1] == 0 && d.ack[2] == 1 && d.ack[3] == 0x08);  // the first ten as before
    reply = jlh::videoConfigReply(d, hi);
    CHECK(reply.size() == 8 + 11 + 8 + hi.size());
    CHECK(reply[5] == jlh::kMsgVideoConfigAck && reply[7] == 11 && reply[8 + 10] == 0x01);
    const uint8_t* f = reply.data() + 8 + 11;
    const size_t fn = reply.size() - (8 + 11);
    CHECK(jl::hostinfo::isFramePrefix(f, fn) && jl::hostinfo::completeFrameBytes(f, fn) == fn);
    const auto info = jl::hostinfo::decode(f + 8, fn - 8);
    CHECK(info && info->windows() && info->caps == 0x2F && info->version == "0.4.1-h2dev");
    // A refusal answers the same way: the viewer asked, so HOST_INFO follows.
    const uint8_t refused[6] = {1, 3, 0x09, 0, 0, 0};
    d = jlh::decideVideoConfig(refused, 6, 25, 1920, 1080);
    CHECK(!d.accepted && d.hostInfo && d.ack.size() == 11);
    // A malformed request never gets HOST_INFO.
    d = jlh::decideVideoConfig(newViewer, 5, 25, 1920, 1080);
    CHECK(!d.accepted && !d.hostInfo && d.ack.size() == 10);
}

static void testDecodeInput() {
    const uint8_t key[3] = {1, 0, 'A'};
    auto e = jlh::decodeInput(hdr(0x10, 3), key);
    CHECK(e && e->kind == jlh::InputEvent::Kind::Key && e->down && e->semantic == 'A');
    CHECK(!jlh::decodeInput(hdr(0x10, 2), key) && !jlh::decodeInput(hdr(0x10, 4), key));
    const uint8_t rel[4] = {0xFF, 0xFE, 0x00, 0x03};
    e = jlh::decodeInput(hdr(0x20, 4), rel);
    CHECK(e && e->kind == jlh::InputEvent::Kind::MoveRel && e->x == -2 && e->y == 3);
    e = jlh::decodeInput(hdr(0x22, 4), rel);
    CHECK(e && e->kind == jlh::InputEvent::Kind::Scroll && e->x == -2 && e->y == 3);
    const uint8_t abs[4] = {0xFF, 0xFF, 0x80, 0x00};
    e = jlh::decodeInput(hdr(0x23, 4), abs);
    CHECK(e && e->kind == jlh::InputEvent::Kind::MoveAbsPixels && e->x == 65535 && e->y == 32768);
    e = jlh::decodeInput(hdr(0x24, 4), abs);
    CHECK(e && e->kind == jlh::InputEvent::Kind::MoveNorm && e->x == 65535 && e->y == 32768);
    for (uint8_t t : {uint8_t(0x20), uint8_t(0x22), uint8_t(0x23), uint8_t(0x24)})
        CHECK(!jlh::decodeInput(hdr(t, 3), abs) && !jlh::decodeInput(hdr(t, 5), abs));
    const uint8_t btn[3] = {1, 1, 2};
    e = jlh::decodeInput(hdr(0x21, 2), btn);
    CHECK(e && e->kind == jlh::InputEvent::Kind::Button && e->button == 1 && e->down);
    e = jlh::decodeInput(hdr(0x25, 3), btn);
    CHECK(e && e->kind == jlh::InputEvent::Kind::Button && e->button == 1 && e->down);
    CHECK(!jlh::decodeInput(hdr(0x21, 3), btn) && !jlh::decodeInput(hdr(0x25, 2), btn));
    const uint8_t btn3[2] = {3, 1};
    CHECK(!jlh::decodeInput(hdr(0x21, 2), btn3));
    e = jlh::decodeInput(hdr(0x60, 0), key);
    CHECK(e && e->kind == jlh::InputEvent::Kind::TaskManager);
    CHECK(!jlh::decodeInput(hdr(0x60, 1), key));
    // POINTER_SYNC: [nx BE16, ny BE16, seq BE32, port BE16], 10 bytes and
    // no other size (8f8a33b's 8-byte form is not taken).
    const uint8_t sync[11] = {0x12, 0x34, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x05, 0xC3, 0x51, 0};
    e = jlh::decodeInput(hdr(0x27, 10), sync);
    CHECK(e && e->kind == jlh::InputEvent::Kind::PointerSync && e->x == 0x1234 && e->y == 65535 &&
          e->seq == 0x80000005u && e->port == 50001);
    CHECK(jlh::kPointerSyncBytes == 10 && jlh::kPointerSyncBytes == jl::hostinfo::kPointerSyncBytes);
    CHECK(!jlh::decodeInput(hdr(0x27, 8), sync) && !jlh::decodeInput(hdr(0x27, 9), sync) &&
          !jlh::decodeInput(hdr(0x27, 11), sync));
    // Not input: the host's other frames and unknown types. 0x28 (r5's
    // VIEWER_ID, dropped in r6) is one of them.
    for (uint8_t t : {uint8_t(0x01), uint8_t(0x30), uint8_t(0x40), uint8_t(0x26), uint8_t(0x28), uint8_t(0x61)})
        CHECK(!jlh::decodeInput(hdr(t, 3), key));
}

static void testKeysAgainstViewer() {
    namespace km = jl::keymap;
    // Every key the viewer forwards (pass-through to a Windows host sends
    // the Mac preset's codes) is one this host presses; non-modifiers are
    // the same VK, modifiers the left-hand key.
    int forwarded = 0;
    for (uint32_t key = 0; key < 256; ++key) {
        const uint16_t sem = km::semanticKey(key, km::Preset::Mac);
        if (!sem) continue;
        ++forwarded;
        const uint16_t v = jlh::semanticToVk(sem);
        CHECK(v != 0);
        if (sem > 4) CHECK(v == key);
    }
    CHECK(forwarded > 90);
    CHECK(jlh::semanticToVk(km::kCtrl) == jlh::vk::LControl && jlh::semanticToVk(km::kAlt) == jlh::vk::LMenu &&
          jlh::semanticToVk(km::kWin) == jlh::vk::LWin && jlh::semanticToVk(km::kShift) == jlh::vk::LShift);
    // Nothing the viewer never sends is pressed.
    for (uint32_t s = 5; s < 0x10000; ++s) {
        if (!jlh::semanticToVk(uint16_t(s))) continue;
        CHECK(s < 256 && km::semanticKey(s, km::Preset::Mac) == s);
    }
    CHECK(jlh::semanticToVk(0) == 0);
    CHECK(jlh::isExtendedVk(jlh::vk::Left) && jlh::isExtendedVk(jlh::vk::Delete) && jlh::isExtendedVk(jlh::vk::LWin) &&
          jlh::isExtendedVk(jlh::vk::Divide));
    CHECK(!jlh::isExtendedVk('A') && !jlh::isExtendedVk(jlh::vk::LControl) && !jlh::isExtendedVk(jlh::vk::Return) &&
          !jlh::isExtendedVk(jlh::vk::Numpad0));
}

template <class T>
static bool same(const std::vector<T>& v, std::initializer_list<T> want) {
    return v == std::vector<T>(want);
}

static void testHeldInput() {
    using Up = jlh::HeldInput::Up;
    const jlh::HeldInput::Owner A = 1, B = 2, C = 3;
    std::vector<uint16_t> ups;
    std::vector<uint8_t> buttonUps;
    auto upKey = [&](uint16_t v) { ups.push_back(v); return true; };
    auto upButton = [&](uint8_t b) { buttonUps.push_back(b); return true; };
    auto noKey = [](uint16_t) { CHECK(false); return true; };
    auto noButton = [](uint8_t) { CHECK(false); return true; };

    // One connection: what it pressed goes up when it closes, newest key first.
    jlh::HeldInput h;
    CHECK(!h.anyHeld());
    h.pressKey(jlh::vk::LControl, A);
    h.pressKey('C', A);
    h.pressKey('C', A);  // auto-repeat: still one
    h.pressButton(0, A);
    h.pressButton(3, A);  // not a button: ignored
    CHECK(h.anyHeld() && h.keyOwnedBy('C', A) && h.buttonOwnedBy(0, A));
    size_t n = h.releaseOwned(A, upKey, upButton);
    CHECK(n == 3 && same(ups, {uint16_t('C'), jlh::vk::LControl}) && same(buttonUps, {uint8_t(0)}));
    CHECK(!h.anyHeld());
    // Its own ups: sent, and nothing left for the close.
    ups.clear();
    buttonUps.clear();
    h.pressKey('A', A);
    CHECK(h.releaseKey('A', A, upKey) == Up::Sent);
    h.pressButton(1, A);
    CHECK(h.releaseButton(1, A, upButton) == Up::Sent);
    CHECK(!h.anyHeld() && same(ups, {uint16_t('A')}) && same(buttonUps, {uint8_t(1)}));
    CHECK(h.releaseOwned(A, noKey, noButton) == 0);
    // An up for a key nobody holds here goes to Windows as it is.
    ups.clear();
    CHECK(h.releaseKey('Z', B, upKey) == Up::Sent && same(ups, {uint16_t('Z')}) && !h.anyHeld());

    // Pepper's H2 review of a784cd7, item 2. The viewer reconnected: old
    // connection A held Shift when it was lost, new connection B presses
    // the left button, and only then is A seen closed. A's Shift goes up;
    // B's button stays.
    jlh::HeldInput r;
    ups.clear();
    buttonUps.clear();
    r.pressKey(jlh::vk::LShift, A);
    r.pressButton(0, B);
    n = r.releaseOwned(A, upKey, upButton);
    CHECK(n == 1 && same(ups, {jlh::vk::LShift}) && buttonUps.empty());
    CHECK(r.buttonHeld(0) && r.buttonOwnedBy(0, B) && !r.keyHeld(jlh::vk::LShift));
    n = r.releaseOwned(B, upKey, upButton);
    CHECK(n == 1 && same(buttonUps, {uint8_t(0)}) && !r.anyHeld());

    // Pepper's review of 8f8a33b, item 2: an up frame follows the same
    // rule. Old connection A pressed the left button and W, the viewer
    // moved to B and pressed them again there; A's late ups arrive after
    // that. They end A's claims only. Nothing goes up on Windows: B still
    // holds both.
    jlh::HeldInput u;
    ups.clear();
    buttonUps.clear();
    u.pressButton(0, A);
    u.pressKey('W', A);
    u.pressButton(0, B);
    u.pressKey('W', B);
    CHECK(u.releaseButton(0, A, noButton) == Up::Held && u.releaseKey('W', A, noKey) == Up::Held);
    CHECK(u.buttonOwnedBy(0, B) && !u.buttonOwnedBy(0, A) && u.keyOwnedBy('W', B) && !u.keyOwnedBy('W', A));
    // ... and A's late close does not release them either.
    CHECK(u.releaseOwned(A, noKey, noButton) == 0 && u.buttonHeld(0) && u.keyHeld('W'));
    // B's own ups do.
    CHECK(u.releaseButton(0, B, upButton) == Up::Sent && u.releaseKey('W', B, upKey) == Up::Sent);
    CHECK(same(buttonUps, {uint8_t(0)}) && same(ups, {uint16_t('W')}) && !u.anyHeld());
    // The other holder outlives the up whatever the order they pressed in:
    // C pressed first, then B; B's up leaves C's claim.
    buttonUps.clear();
    u.pressButton(2, C);
    u.pressButton(2, B);
    CHECK(u.releaseButton(2, B, noButton) == Up::Held && u.buttonOwnedBy(2, C));
    CHECK(u.releaseButton(2, C, upButton) == Up::Sent && same(buttonUps, {uint8_t(2)}) && !u.anyHeld());

    // Pepper's review of f97ad11, item 1. A and B both hold Shift and the
    // left button; B, the newer connection, closes. A is still open and
    // still holds them: Windows gets no up. A's own up, or its close, lets
    // go.
    jlh::HeldInput p;
    ups.clear();
    buttonUps.clear();
    p.pressKey(jlh::vk::LShift, A);
    p.pressButton(0, A);
    p.pressKey(jlh::vk::LShift, B);
    p.pressButton(0, B);
    CHECK(p.releaseOwned(B, noKey, noButton) == 0);
    CHECK(p.keyOwnedBy(jlh::vk::LShift, A) && p.buttonOwnedBy(0, A) && !p.keyOwnedBy(jlh::vk::LShift, B) &&
          !p.buttonOwnedBy(0, B));
    CHECK(p.releaseButton(0, A, upButton) == Up::Sent && same(buttonUps, {uint8_t(0)}));
    CHECK(p.releaseOwned(A, upKey, upButton) == 1 && same(ups, {jlh::vk::LShift}) && !p.anyHeld());

    // A close lets go of its own claims only, older or newer than the
    // others: a connection still open keeps what it holds.
    jlh::HeldInput c;
    ups.clear();
    buttonUps.clear();
    c.pressKey('W', B);
    c.pressKey('W', C);
    c.pressKey('Q', A);
    n = c.releaseOwned(B, noKey, noButton);  // B closes: C still holds W
    CHECK(n == 0 && c.keyOwnedBy('W', C) && !c.keyOwnedBy('W', B) && c.keyOwnedBy('Q', A));
    const jlh::HeldInput::Owner D = 4;
    c.pressKey('W', D);
    n = c.releaseOwned(D, noKey, noButton);  // D, the newest, closes: C still holds W
    CHECK(n == 0 && c.keyOwnedBy('W', C) && !c.keyOwnedBy('W', D));
    n = c.releaseOwned(A, upKey, upButton);
    CHECK(n == 1 && same(ups, {uint16_t('Q')}) && c.keyOwnedBy('W', C));
    n = c.releaseOwned(C, upKey, upButton);
    CHECK(n == 1 && same(ups, {uint16_t('Q'), uint16_t('W')}) && !c.anyHeld());

    // Pepper's reviews of 04622f0 and c397898, item 1: two live
    // connections (two viewers, or one viewer's old and new connection;
    // the host does not know which) both hold Shift and the left button.
    // B lets go normally: A still holds them and Windows gets no up. A
    // lets go: one up each. Whichever connection is newer.
    for (const bool bNewer : {true, false}) {
        const jlh::HeldInput::Owner a = bNewer ? A : B, b = bNewer ? B : A;
        jlh::HeldInput two;
        ups.clear();
        buttonUps.clear();
        two.pressKey(jlh::vk::LShift, a);
        two.pressButton(0, a);
        two.pressKey(jlh::vk::LShift, b);
        two.pressButton(0, b);
        CHECK(two.releaseKey(jlh::vk::LShift, b, noKey) == Up::Held);
        CHECK(two.releaseButton(0, b, noButton) == Up::Held);
        CHECK(two.keyOwnedBy(jlh::vk::LShift, a) && two.buttonOwnedBy(0, a));
        CHECK(!two.keyOwnedBy(jlh::vk::LShift, b) && !two.buttonOwnedBy(0, b));
        CHECK(ups.empty() && buttonUps.empty());
        // b's up again (a repeat, or an owed up): still nothing.
        CHECK(two.releaseKey(jlh::vk::LShift, b, noKey) == Up::Held && two.keyOwnedBy(jlh::vk::LShift, a));
        CHECK(two.releaseKey(jlh::vk::LShift, a, upKey) == Up::Sent);
        CHECK(two.releaseButton(0, a, upButton) == Up::Sent);
        CHECK(same(ups, {jlh::vk::LShift}) && same(buttonUps, {uint8_t(0)}) && !two.anyHeld());
        // Their closes find nothing left.
        CHECK(two.releaseOwned(b, noKey, noButton) == 0 && two.releaseOwned(a, noKey, noButton) == 0);
    }

    // r6 (Pepper's review of c397898, item 1): one viewer, several old
    // connections still open here. The viewer held Shift and the left
    // button on A, lost A, pressed them again on B, lost B, again on C,
    // lost C; the host has seen none of those closes. On its new connection
    // E it sends the ups it owes (takeOwedLocked): they look the same as a
    // plain up and end E's own claim only, which E does not have. A, B and
    // C keep theirs and Windows gets nothing. Then E presses and lets go
    // of Shift itself: its own claim only. Each old connection's close
    // ends its own claims; the last one sends one up each.
    {
        const jlh::HeldInput::Owner E = 5;
        jlh::HeldInput m;
        ups.clear();
        buttonUps.clear();
        for (const jlh::HeldInput::Owner o : {A, B, C}) {
            m.pressKey(jlh::vk::LShift, o);
            m.pressButton(0, o);
        }
        CHECK(m.releaseKey(jlh::vk::LShift, E, noKey) == Up::Held);
        CHECK(m.releaseButton(0, E, noButton) == Up::Held);
        for (const jlh::HeldInput::Owner o : {A, B, C})
            CHECK(m.keyOwnedBy(jlh::vk::LShift, o) && m.buttonOwnedBy(0, o));
        m.pressKey(jlh::vk::LShift, E);
        m.pressButton(0, E);
        CHECK(m.releaseKey(jlh::vk::LShift, E, noKey) == Up::Held);
        CHECK(m.releaseButton(0, E, noButton) == Up::Held);
        CHECK(!m.keyOwnedBy(jlh::vk::LShift, E) && !m.buttonOwnedBy(0, E));
        for (const jlh::HeldInput::Owner o : {A, B, C})
            CHECK(m.keyOwnedBy(jlh::vk::LShift, o) && m.buttonOwnedBy(0, o));
        CHECK(ups.empty() && buttonUps.empty());
        // A late up of one old connection (B) ends B's claims only.
        CHECK(m.releaseKey(jlh::vk::LShift, B, noKey) == Up::Held && m.releaseButton(0, B, noButton) == Up::Held);
        CHECK(!m.keyOwnedBy(jlh::vk::LShift, B) && !m.buttonOwnedBy(0, B));
        CHECK(m.keyOwnedBy(jlh::vk::LShift, A) && m.keyOwnedBy(jlh::vk::LShift, C) && m.buttonOwnedBy(0, A) &&
              m.buttonOwnedBy(0, C));
        // The closes, oldest first; E's close has nothing to let go of.
        CHECK(m.releaseOwned(E, noKey, noButton) == 0);
        CHECK(m.releaseOwned(B, noKey, noButton) == 0);
        CHECK(m.releaseOwned(A, noKey, noButton) == 0);
        CHECK(m.keyOwnedBy(jlh::vk::LShift, C) && m.buttonOwnedBy(0, C) && ups.empty() && buttonUps.empty());
        CHECK(m.releaseOwned(C, upKey, upButton) == 2);
        CHECK(same(ups, {jlh::vk::LShift}) && same(buttonUps, {uint8_t(0)}) && !m.anyHeld());
        // An owed up that comes after every old close finds nobody holding
        // the key: it goes to Windows as it is, as any such up does.
        CHECK(m.releaseKey(jlh::vk::LShift, E, upKey) == Up::Sent && same(ups, {jlh::vk::LShift, jlh::vk::LShift}));
    }
    // The same, closes newest first, and the middle button on its own: the
    // order of the closes does not matter, only the last one sends the up.
    {
        jlh::HeldInput m;
        buttonUps.clear();
        for (const jlh::HeldInput::Owner o : {A, B, C}) m.pressButton(2, o);
        CHECK(m.releaseButton(2, D, noButton) == Up::Held);
        CHECK(m.releaseOwned(C, noKey, noButton) == 0 && m.releaseOwned(B, noKey, noButton) == 0);
        CHECK(m.buttonOwnedBy(2, A) && buttonUps.empty());
        CHECK(m.releaseOwned(A, noKey, upButton) == 1 && same(buttonUps, {uint8_t(2)}) && !m.anyHeld());
    }

    // An up Windows did not take: the entry stays, and the next release
    // (any connection's close or up) tries it again.
    jlh::HeldInput f;
    ups.clear();
    buttonUps.clear();
    f.pressKey('X', A);
    f.pressButton(1, A);
    n = f.releaseOwned(A, [](uint16_t) { return false; }, [](uint8_t) { return false; });
    CHECK(n == 0 && f.keyHeld('X') && f.buttonHeld(1) && !f.keyOwnedBy('X', A) && !f.buttonOwnedBy(1, A));
    n = f.releaseOwned(B, upKey, upButton);
    CHECK(n == 2 && same(ups, {uint16_t('X')}) && same(buttonUps, {uint8_t(1)}) && !f.anyHeld());
    f.pressKey('Y', A);
    CHECK(f.releaseKey('Y', A, [](uint16_t) { return false; }) == Up::Failed);
    CHECK(f.keyHeld('Y') && !f.keyOwnedBy('Y', A));
    ups.clear();
    CHECK(f.releaseKey('Y', A, upKey) == Up::Sent && same(ups, {uint16_t('Y')}) && !f.anyHeld());
}

// Pepper's H2 review, item 3: Task Manager (MRC1 0x60) releases held keys
// only. A button stays down on Windows, so its record stays too; a key whose
// up Windows did not take stays recorded for a later release.
static void testTaskManagerRelease() {
    const jlh::HeldInput::Owner A = 1;
    jlh::HeldInput t;
    t.pressKey(jlh::vk::LMenu, A);
    t.pressKey('Q', A);
    t.pressButton(0, A);
    std::vector<uint16_t> tried;
    size_t n = t.releaseKeys([&](uint16_t v) {
        tried.push_back(v);
        return v != 'Q';  // Windows refuses Q's up
    });
    CHECK(n == 1 && same(tried, {uint16_t('Q'), jlh::vk::LMenu}));
    CHECK(t.keyHeld('Q') && !t.keyHeld(jlh::vk::LMenu));
    CHECK(t.buttonHeld(0) && t.buttonOwnedBy(0, A));
    // A closes later: the button goes up then, and Q is tried again.
    std::vector<uint16_t> ups;
    std::vector<uint8_t> buttonUps;
    n = t.releaseOwned(
        A, [&](uint16_t v) { ups.push_back(v); return true; },
        [&](uint8_t b) { buttonUps.push_back(b); return true; });
    CHECK(n == 2 && same(ups, {uint16_t('Q')}) && same(buttonUps, {uint8_t(0)}) && !t.anyHeld());
    // Nothing held: nothing sent.
    CHECK(t.releaseKeys([](uint16_t) { CHECK(false); return true; }) == 0);
}

static void testPointerMapping() {
    // Primary 1920x1080 at 0,0; a second monitor at -1280,-200.
    const jlh::DesktopRect primary{0, 0, 1920, 1080};
    int px = -1, py = -1;
    jlh::normToDesktop(0, 0, primary, px, py);
    CHECK(px == 0 && py == 0);
    jlh::normToDesktop(65535, 65535, primary, px, py);
    CHECK(px == 1919 && py == 1079);
    jlh::normToDesktop(32768, 32768, primary, px, py);
    CHECK(px == 960 && py == 540);
    jlh::normToDesktop(-5, 70000, primary, px, py);
    CHECK(px == 0 && py == 1079);
    const jlh::DesktopRect left{-1280, -200, 1280, 1024};
    jlh::normToDesktop(0, 0, left, px, py);
    CHECK(px == -1280 && py == -200);
    jlh::normToDesktop(65535, 65535, left, px, py);
    CHECK(px == -1 && py == 823);
    // Virtual desktop -1280,-200 .. 1920,1080 (3200 x 1280): every pixel a
    // SendInput absolute value lands on is the pixel asked for.
    const int vx = -1280, vw = 3200, vy = -200, vh = 1280;
    for (int x = vx; x < vx + vw; ++x) {
        const int a = jlh::toAbsolute(x, vx, vw);
        CHECK(a >= 0 && a <= 65535);
        CHECK(vx + int((int64_t(a) * vw) / 65536) == x);
    }
    for (int y = vy; y < vy + vh; ++y) {
        const int a = jlh::toAbsolute(y, vy, vh);
        CHECK(vy + int((int64_t(a) * vh) / 65536) == y);
    }
    CHECK(jlh::toAbsolute(-5000, vx, vw) == 0);
    CHECK(jlh::toAbsolute(5000, vx, vw) == jlh::toAbsolute(vx + vw - 1, vx, vw));
    CHECK(jlh::toAbsolute(10, 0, 0) == 0);
}

static void testMrm1SessionAndCursor() {
    jlh::Mrm1Session s;
    CHECK(s.note(0x64400010, 50000, 0));   // first datagram: a session
    CHECK(!s.note(0x64400010, 50000, 0));  // same port: same session
    CHECK(s.takePointer(10));
    CHECK(!s.takePointer(10) && !s.takePointer(9));  // repeat or late: dropped
    CHECK(s.takePointer(11));
    CHECK(s.takePointer(0x7FFFFFFFu + 11));  // newer: just under half the range ahead
    CHECK(s.takePointer(5));                 // wrapped round: newer again
    CHECK(s.note(0x64400010, 50001, 0));     // viewer restarted: new session
    CHECK(s.takePointer(1));                 // its own order, from the start
    CHECK(s.note(0x64400011, 50001, 0));     // another address: new session
    // The cursor packet the viewer reads (viewer.cpp: 11 bytes, seq, shape).
    const auto c = jlh::mrm1Cursor(0x01020304u, jlh::CursorShape::Wait);
    CHECK(c.size() == 11 && c[0] == 'M' && c[3] == '1' && c[4] == 1 && c[5] == 0x31);
    CHECK(c[6] == 1 && c[7] == 2 && c[8] == 3 && c[9] == 4 && c[10] == 12);
    CHECK(uint8_t(jlh::CursorShape::IBeam) == 1 && uint8_t(jlh::CursorShape::PointingHand) == 2 &&
          uint8_t(jlh::CursorShape::NotAllowed) == 10 && uint8_t(jlh::CursorShape::Move) == 14);
    // POINTER_SYNC marks a seq of the current session as taken; it never
    // moves the mark back.
    const uint32_t ip = 0x0A000002;
    jlh::Mrm1Session p;
    CHECK(p.note(ip, 50000, 0));
    p.syncPointer(ip, 50000, 7, 0);  // before any move
    CHECK(!p.takePointer(7) && !p.takePointer(6) && p.takePointer(8));
    p.syncPointer(ip, 50000, 5, 0);  // older than what was taken: no change
    CHECK(!p.takePointer(8) && p.takePointer(9));
    p.syncPointer(ip, 50000, 0xFFFFFFF0u, 0);  // half the range behind 9: older, no change
    CHECK(p.takePointer(10));
    p.syncPointer(ip, 50000, 0x7FFFFFF0u, 0);  // ahead
    CHECK(!p.takePointer(0x7FFFFFEFu) && p.takePointer(0x7FFFFFF1u));
    p.syncPointer(ip, 0, 0x7FFFFFFFu, 0);  // port 0: position only, no mark
    CHECK(p.takePointer(0x7FFFFFF2u));

    // Pepper's review of 8f8a33b, item 5a: the sync is for a viewer socket
    // the host has not heard from yet. Its seq is that socket's (each new
    // socket starts at 1), not the current session's: kept for that
    // socket, and in force when its first datagram arrives.
    jlh::Mrm1Session q;
    CHECK(q.note(ip, 50000, 0) && q.takePointer(5000));
    q.syncPointer(ip, 50001, 2, 0);  // the new socket's move 2 came before the click
    CHECK(q.takePointer(5001));      // the current session is not touched
    CHECK(q.note(ip, 50001, 0));     // the new socket's first datagram, late
    CHECK(!q.takePointer(1) && !q.takePointer(2) && q.takePointer(3));
    // No session at all yet: the same.
    jlh::Mrm1Session r;
    r.syncPointer(ip, 50002, 3, 0);
    CHECK(r.note(ip, 50002, 0) && !r.takePointer(1) && !r.takePointer(3) && r.takePointer(4));
    // A mark only goes to its own socket: not to another port or address.
    jlh::Mrm1Session t;
    t.syncPointer(ip, 50003, 9, 0);
    t.syncPointer(ip, 50003, 4, 0);  // older: the mark stays at 9
    CHECK(t.note(ip, 50004, 0) && t.takePointer(1));
    CHECK(t.note(ip + 1, 50003, 0) && t.takePointer(1));
    CHECK(t.note(ip, 50003, 0) && !t.takePointer(9) && t.takePointer(10));
    CHECK(t.note(ip, 50004, 0) && !t.takePointer(1) && t.takePointer(2));  // 50004 kept its own order
    // Syncs for two sockets that have not sent yet: each keeps its own mark.
    jlh::Mrm1Session u;
    u.syncPointer(ip, 50005, 9, 0);
    u.syncPointer(ip, 50006, 2, 0);
    CHECK(u.note(ip, 50005, 0) && !u.takePointer(9) && u.takePointer(10));
    CHECK(u.note(ip, 50006, 0) && !u.takePointer(2) && u.takePointer(3));

    // Pepper's review of f97ad11, item 3. B (the new socket) got its mark;
    // a late datagram from A (the old socket) makes A current for a
    // moment; when B comes back, its mark is still there, so B's move from
    // before the click stays dropped. A keeps its own order too.
    jlh::Mrm1Session v;
    CHECK(v.note(ip, 50000, 0) && v.takePointer(5000));
    v.syncPointer(ip, 50001, 3, 10);
    CHECK(v.note(ip, 50001, 20) && !v.takePointer(1));     // B, from before the click
    CHECK(v.note(ip, 50000, 30) && v.takePointer(5001));   // A, late
    CHECK(v.note(ip, 50001, 40) && !v.takePointer(2) && !v.takePointer(3) && v.takePointer(4));
    CHECK(v.note(ip, 50000, 50) && !v.takePointer(5001) && !v.takePointer(4999));

    // A socket not heard from (no datagram, no sync) for more than kIdleMs
    // starts over: the viewer sends a keep-alive every second, so that is a
    // new viewer socket that got the same port.
    const int64_t idle = jlh::Mrm1Session::kIdleMs;
    jlh::Mrm1Session w;
    CHECK(w.note(ip, 50000, 0) && w.takePointer(100));
    CHECK(!w.note(ip, 50000, idle) && !w.takePointer(1));        // kIdleMs exactly: same order
    CHECK(!w.note(ip, 50000, 2 * idle + 1) && w.takePointer(1));  // more: starts over
    w.syncPointer(ip, 50000, 50, 3 * idle);                       // a sync counts as heard from
    CHECK(!w.note(ip, 50000, 4 * idle) && !w.takePointer(50) && w.takePointer(51));
    // An idle socket that is not the current one starts over as well.
    CHECK(w.note(ip, 50001, 4 * idle) && w.takePointer(7));
    CHECK(w.note(ip, 50000, 5 * idle + 1) && w.takePointer(1));

    // At most kMaxSockets are kept. The one heard from least recently makes
    // room, never the current one, even when it is the oldest.
    const size_t cap = jlh::Mrm1Session::kMaxSockets;
    jlh::Mrm1Session e;
    CHECK(e.note(ip, 40000, 0) && e.takePointer(7));
    for (size_t i = 1; i <= cap; ++i) e.syncPointer(ip, uint16_t(40000 + i), 5, int64_t(i));
    CHECK(e.socketsKept() == cap);
    CHECK(!e.note(ip, 40000, 100) && !e.takePointer(7) && e.takePointer(8));  // the current one stayed
    CHECK(e.note(ip, uint16_t(40000 + cap), 101) && !e.takePointer(5) && e.takePointer(6));
    CHECK(e.note(ip, 40001, 102) && e.takePointer(1));  // made room first: starts over
    CHECK(e.socketsKept() == cap);
}

// Pepper's H2 review, item 5. The host's pointer and buttons as the real
// steps drive them: UDP moves through Mrm1Session::takePointer, control
// frames (parsed from the viewer's wire bytes) through stepInput, with
// POINTER_SYNC applied as in host_main.cpp's applyPointerSync.
namespace {
struct Press {
    uint8_t button;
    bool down;
    int x, y;
};
constexpr uint32_t kViewerIp = 0x0A000002;
constexpr uint16_t kViewerPort = 50000;
struct FakeDesk {
    jlh::Mrm1Session order;
    int x = -1, y = -1;
    std::vector<Press> presses;
    std::optional<jlh::InputEvent> pending;
    // One MRM1 0x24 from the viewer's UDP socket at port, as mrm1Listener
    // takes it.
    void udp(uint32_t seq, int nx, int ny, uint16_t port = kViewerPort) {
        order.note(kViewerIp, port, 0);
        if (order.takePointer(seq)) {
            x = nx;
            y = ny;
        }
    }
    // One TCP write from the viewer: any number of MRC1 frames.
    void tcp(const std::vector<uint8_t>& bytes) {
        size_t off = 0;
        while (off + jlh::kMrc1HeaderBytes <= bytes.size()) {
            const auto h = jlh::parseMrc1Header(bytes.data() + off);
            CHECK(h.has_value());
            if (!h) return;
            const auto e = jlh::decodeInput(*h, bytes.data() + off + jlh::kMrc1HeaderBytes);
            CHECK(e.has_value());
            off += jlh::kMrc1HeaderBytes + h->length;
            if (!e) continue;
            jlh::stepInput(
                pending, *e,
                [&](const jlh::InputEvent& s, const jlh::InputEvent* b) {
                    order.syncPointer(kViewerIp, s.port, s.seq, 0);
                    x = s.x;
                    y = s.y;
                    if (b) presses.push_back({b->button, b->down, x, y});
                    return true;
                },
                [&](const jlh::InputEvent& ev) {
                    if (ev.kind == jlh::InputEvent::Kind::Button) presses.push_back({ev.button, ev.down, x, y});
                    if (ev.kind == jlh::InputEvent::Kind::MoveNorm) {
                        x = ev.x;
                        y = ev.y;
                    }
                    return true;
                });
        }
        CHECK(off == bytes.size());
    }
};
// What the viewer writes for a click with POINTER_SYNC: 0x27 then 0x25.
std::vector<uint8_t> syncedButton(int nx, int ny, uint32_t seq, uint8_t b, bool down,
                                  uint16_t port = kViewerPort) {
    auto out = jlh::mrc1Frame(jlh::kMsgPointerSync,
                              {uint8_t(nx >> 8), uint8_t(nx), uint8_t(ny >> 8), uint8_t(ny), uint8_t(seq >> 24),
                               uint8_t(seq >> 16), uint8_t(seq >> 8), uint8_t(seq), uint8_t(port >> 8),
                               uint8_t(port)});
    const auto btn = jlh::mrc1Frame(jlh::kMsgMouseButtonExt, {b, uint8_t(down ? 1 : 0), 1});
    out.insert(out.end(), btn.begin(), btn.end());
    return out;
}
bool pressedAt(const Press& p, uint8_t b, bool down, int x, int y) {
    return p.button == b && p.down == down && p.x == x && p.y == y;
}
}  // namespace

static void testPointerSyncOrdering() {
    // The move to the click point (seq 2) is late: it arrives after the
    // click, together with an older move (seq 1). Down and up land at the
    // click point, and the late moves are dropped.
    {
        FakeDesk d;
        d.udp(0, 100, 100);
        d.tcp(syncedButton(500, 600, 2, 0, true));
        d.udp(1, 300, 300);
        d.udp(2, 500, 600);
        d.tcp(syncedButton(500, 600, 2, 0, false));
        CHECK(d.presses.size() == 2 && pressedAt(d.presses[0], 0, true, 500, 600) &&
              pressedAt(d.presses[1], 0, false, 500, 600));
        CHECK(d.x == 500 && d.y == 600);
    }
    // The move to the click point is lost: the click still lands there.
    {
        FakeDesk d;
        d.udp(0, 100, 100);
        d.tcp(syncedButton(700, 800, 1, 1, true));
        d.tcp(syncedButton(700, 800, 1, 1, false));
        CHECK(d.presses.size() == 2 && pressedAt(d.presses[0], 1, true, 700, 800) &&
              pressedAt(d.presses[1], 1, false, 700, 800));
    }
    // A drag: down at the start, moves on the way, up at the end even when
    // the last move comes late; a move from before the up that arrives
    // after it does not move the pointer off the drop point.
    {
        FakeDesk d;
        d.tcp(syncedButton(1000, 1000, 5, 0, true));
        d.udp(6, 1500, 1200);
        d.tcp(syncedButton(2000, 1500, 7, 0, false));
        d.udp(7, 2000, 1500);
        d.udp(6, 1500, 1200);
        CHECK(d.presses.size() == 2 && pressedAt(d.presses[0], 0, true, 1000, 1000) &&
              pressedAt(d.presses[1], 0, false, 2000, 1500));
        CHECK(d.x == 2000 && d.y == 1500);
        d.udp(8, 2100, 1600);  // a move after the drop is taken
        CHECK(d.x == 2100 && d.y == 1600);
    }
    // Without POINTER_SYNC (a viewer that does not send it), the same late
    // move puts the press at the old point: what Pepper found.
    {
        FakeDesk d;
        d.udp(0, 100, 100);
        d.tcp(jlh::mrc1Frame(jlh::kMsgMouseButtonExt, {0, 1, 1}));
        d.udp(1, 500, 600);
        CHECK(d.presses.size() == 1 && pressedAt(d.presses[0], 0, true, 100, 100));
    }
    // A sync followed by something other than a button is applied alone
    // first, and a sync after a sync applies the first alone.
    {
        FakeDesk d;
        auto two = syncedButton(10, 20, 3, 0, true);
        two.resize(jlh::kMrc1HeaderBytes + jlh::kPointerSyncBytes);  // the sync only
        const auto key = jlh::mrc1Frame(jlh::kMsgKey, {1, 0, 'A'});
        two.insert(two.end(), key.begin(), key.end());
        d.tcp(two);
        CHECK(d.x == 10 && d.y == 20 && d.presses.empty() && !d.pending);
        d.udp(3, 99, 99);  // covered by that sync
        CHECK(d.x == 10);
        auto s1 = syncedButton(30, 40, 4, 0, true);
        s1.resize(jlh::kMrc1HeaderBytes + jlh::kPointerSyncBytes);
        d.tcp(s1);
        CHECK(d.pending && d.x == 10);
        d.tcp(syncedButton(50, 60, 5, 0, true));
        CHECK(d.presses.size() == 1 && pressedAt(d.presses[0], 0, true, 50, 60));
    }
    // Pepper's review of 8f8a33b, item 5a. The viewer reconnected and
    // opened a new UDP socket (port 50001, seq from 1). The click on the
    // control connection overtakes that socket's first datagram, the move
    // to the click point. The late move is dropped, not taken as the start
    // of a new session, and the press stays where the viewer clicked.
    {
        FakeDesk d;
        d.udp(4999, 100, 100);
        d.udp(5000, 200, 200);  // the old socket's session, far ahead in seq
        d.tcp(syncedButton(500, 600, 1, 0, true, 50001));
        d.udp(1, 300, 300, 50001);  // late, from before the click
        CHECK(d.presses.size() == 1 && pressedAt(d.presses[0], 0, true, 500, 600));
        CHECK(d.x == 500 && d.y == 600);
        d.udp(2, 700, 800, 50001);  // the drag goes on
        CHECK(d.x == 700 && d.y == 800);
        d.tcp(syncedButton(700, 800, 2, 0, false, 50001));
        CHECK(d.presses.size() == 2 && pressedAt(d.presses[1], 0, false, 700, 800));
    }
    // Pepper's review of f97ad11, item 3. As above, and then a late
    // datagram from the old socket arrives after the click. It is newer in
    // the old socket's own order, so it moves the pointer (no button goes
    // down there), and the new socket's move from before the click, seq 2,
    // arriving after it, is still dropped.
    {
        FakeDesk d;
        d.udp(4999, 100, 100);
        d.udp(5000, 200, 200);                             // A, the old socket
        d.tcp(syncedButton(500, 600, 3, 0, true, 50001));  // B's mark: seq 3
        d.udp(1, 300, 300, 50001);                         // B, from before the click
        CHECK(d.x == 500 && d.y == 600);
        d.udp(5001, 250, 250);  // A, late
        CHECK(d.x == 250 && d.y == 250);
        d.udp(2, 400, 400, 50001);  // B, from before the click: dropped
        CHECK(d.x == 250 && d.y == 250);
        d.udp(4, 700, 800, 50001);  // B, after the click
        CHECK(d.x == 700 && d.y == 800);
        d.tcp(syncedButton(700, 800, 4, 0, false, 50001));
        CHECK(d.presses.size() == 2 && pressedAt(d.presses[0], 0, true, 500, 600) &&
              pressedAt(d.presses[1], 0, false, 700, 800));
    }
    // Port 0 (no MRM1 socket known): the click lands at the sync point; no
    // seq is marked.
    {
        FakeDesk d;
        d.udp(1, 100, 100);
        d.tcp(syncedButton(500, 600, 9, 0, true, 0));
        CHECK(d.presses.size() == 1 && pressedAt(d.presses[0], 0, true, 500, 600));
        d.udp(2, 300, 300);
        CHECK(d.x == 300);
    }
}

// r8 (Pepper's review of 6175b5e): one input owner (InputClaims).
// OwnerHost drives InputClaims as host_main.cpp does: an input frame is
// decoded and handed to InputClaims::frame, which admits it (taking over
// when it makes a new owner) and runs the injection, done as
// InputInjector does it, on the HeldInput it passes. Windows is a log and
// can be made to refuse ups. No connection closes unless a test closes it:
// a socket that still answers keep-alive never closes by itself.
namespace {
struct OwnerHost {
    using Owner = jlh::HeldInput::Owner;
    jlh::InputClaims claims;
    // What Windows got, in order: "Kd162" key down, "Ku162", "Bd0", "Bu0",
    // "M" a move from a POINTER_SYNC; an up Windows refused ends in "!".
    std::vector<std::string> win;
    std::vector<uint16_t> keysDown;
    std::vector<uint8_t> buttonsDown;
    bool refuseUps = false;                               // SendInput takes no up
    size_t udpMoves = 0;                                  // MRM1 0x24 moves: the pointer only
    std::vector<std::optional<jlh::InputEvent>> pending;  // serveControl's pendingSync, per connection
    jlh::InputClaims::Frame last;  // the last write, over its input frames: all admitted, any takeover, sums
    size_t replacedTotal = 0;                             // takeovers from an owner still open
    size_t dropped = 0;                                   // input frames dropped: not the owner

    Owner open() { return claims.open(); }
    bool sendKey(uint16_t v, bool down) {
        if (!down && refuseUps) {
            win.push_back("Ku" + std::to_string(v) + "!");
            return false;
        }
        win.push_back(std::string(down ? "Kd" : "Ku") + std::to_string(v));
        const auto it = std::find(keysDown.begin(), keysDown.end(), v);
        if (down && it == keysDown.end()) keysDown.push_back(v);
        if (!down && it != keysDown.end()) keysDown.erase(it);
        return true;
    }
    bool sendButton(uint8_t b, bool down) {
        if (!down && refuseUps) {
            win.push_back("Bu" + std::to_string(b) + "!");
            return false;
        }
        win.push_back(std::string(down ? "Bd" : "Bu") + std::to_string(b));
        const auto it = std::find(buttonsDown.begin(), buttonsDown.end(), b);
        if (down && it == buttonsDown.end()) buttonsDown.push_back(b);
        if (!down && it != buttonsDown.end()) buttonsDown.erase(it);
        return true;
    }
    bool keyDown(uint16_t v) const { return std::find(keysDown.begin(), keysDown.end(), v) != keysDown.end(); }
    bool buttonDown(uint8_t b) const {
        return std::find(buttonsDown.begin(), buttonsDown.end(), b) != buttonsDown.end();
    }
    bool got(std::initializer_list<const char*> want) const {
        if (win.size() != want.size()) return false;
        size_t i = 0;
        for (const char* w : want)
            if (win[i++] != w) return false;
        return true;
    }
    // InputInjector::key / button: a down goes to Windows and is claimed; an
    // up goes through HeldInput.
    bool apply(const jlh::InputEvent& e, Owner o, jlh::HeldInput& held) {
        auto upKey = [this](uint16_t v) { return sendKey(v, false); };
        auto upButton = [this](uint8_t b) { return sendButton(b, false); };
        if (e.kind == jlh::InputEvent::Kind::Key) {
            const uint16_t v = jlh::semanticToVk(e.semantic);
            if (!v) return false;
            if (!e.down) return held.releaseKey(v, o, upKey) != jlh::HeldInput::Up::Failed;
            sendKey(v, true);
            held.pressKey(v, o);
            return true;
        }
        if (e.kind == jlh::InputEvent::Kind::Button) {
            if (!e.down) return held.releaseButton(e.button, o, upButton) != jlh::HeldInput::Up::Failed;
            sendButton(e.button, true);
            held.pressButton(e.button, o);
            return true;
        }
        win.push_back("M");
        return true;
    }
    // One TCP write the host reads on connection o: any number of MRC1
    // frames, taken as serveControl takes them.
    void tcp(Owner o, const std::vector<uint8_t>& bytes) {
        last = jlh::InputClaims::Frame{};
        bool any = false, all = true;
        size_t off = 0;
        while (off + jlh::kMrc1HeaderBytes <= bytes.size()) {
            const auto h = jlh::parseMrc1Header(bytes.data() + off);
            CHECK(h.has_value());
            if (!h) return;
            const uint8_t* p = bytes.data() + off + jlh::kMrc1HeaderBytes;
            off += jlh::kMrc1HeaderBytes + h->length;
            const auto e = jlh::decodeInput(*h, p);
            if (!e) continue;  // ping, VIDEO_CONFIG, clipboard: no part in input
            if (pending.size() <= o) pending.resize(o + 1);
            const auto f = claims.frame(
                o,
                [&](jlh::HeldInput& held) {
                    return jlh::stepInput(
                        pending[o], *e,
                        [&](const jlh::InputEvent&, const jlh::InputEvent* b) {
                            win.push_back("M");
                            return b ? apply(*b, o, held) : true;
                        },
                        [&](const jlh::InputEvent& ev) { return apply(ev, o, held); });
                },
                [this](uint16_t v) { return sendKey(v, false); }, [this](uint8_t b) { return sendButton(b, false); });
            any = true;
            all = all && f.admitted;
            last.tookOver = last.tookOver || f.tookOver;
            last.replaced += f.replaced;
            last.released += f.released;
            last.injected = f.injected;
            replacedTotal += f.replaced;
            if (!f.admitted) ++dropped;
        }
        last.admitted = any && all;
        CHECK(off == bytes.size());
    }
    // A valid MRM1 0x24 move from the viewer (mrm1Listener): it moves the
    // pointer; InputClaims never sees it.
    void pointer() { ++udpMoves; }
    size_t close(Owner o) {
        return claims.close(o, [this](uint16_t v) { return sendKey(v, false); },
                            [this](uint8_t b) { return sendButton(b, false); });
    }
    // One round of inputRetryLoop (every 250 ms).
    size_t retry() {
        return claims.retry([this](uint16_t v) { return sendKey(v, false); },
                            [this](uint8_t b) { return sendButton(b, false); });
    }
};
// Wire semantics (keymap.hpp): 1 Control, 2 Alt, 4 Shift; letters are their own code.
std::vector<uint8_t> keyFrame(uint16_t semantic, bool down) {
    return jlh::mrc1Frame(jlh::kMsgKey, {uint8_t(down ? 1 : 0), uint8_t(semantic >> 8), uint8_t(semantic)});
}
std::vector<uint8_t> pingFrame() { return jlh::mrc1Frame(jlh::kMsgPing, std::vector<uint8_t>(jlh::kPingPayloadBytes, 7)); }
std::vector<uint8_t> clipboardHelloFrame() { return jlh::mrc1Frame(jlh::kMsgClipboardHello, std::vector<uint8_t>{}); }
}  // namespace

// Pepper's review of 6175b5e, item 1, and Morris's PR-C rule (the newer
// connection wins): a newer connection's first input takes over from the
// owner at once, whatever the owner is doing. That the owner is still
// connected, still dragging over MRM1, or only just stopped does not keep
// it: being replaced is the expected outcome, and it reconnects to type
// again.
static void testOwnerTakeover() {
    using jlh::vk::LControl;
    using jlh::vk::LShift;
    {
        // A reconnect while the old connection A is still open on the host,
        // sends nothing and still answers keep-alive. A holds Ctrl and the
        // left button (a Ctrl+drag) when its network goes.
        OwnerHost h;
        const auto A = h.open();
        h.tcp(A, keyFrame(1, true));
        h.tcp(A, syncedButton(1000, 1000, 1, 0, true));
        CHECK(h.keyDown(LControl) && h.buttonDown(0) && h.claims.owner() == A);
        // The viewer is on a new connection B. B opening, and a frame on it
        // that is not input, change nothing.
        const auto B = h.open();
        h.tcp(B, pingFrame());
        CHECK(h.keyDown(LControl) && h.buttonDown(0) && h.claims.owner() == A);
        // B's first action, C: Ctrl and the button go up first, so Windows
        // gets a plain C.
        h.win.clear();
        h.tcp(B, keyFrame('C', true));
        CHECK(h.last.admitted && h.last.tookOver && h.last.replaced == 1 && h.last.released == 2);
        CHECK(h.got({"Ku162", "Bu0", "Kd67"}));
        CHECK(h.claims.owner() == B && !h.claims.held().ownsAny(A) && h.claims.held().keyOwnedBy('C', B));
        // A's late frames are dropped: a Ctrl repeat claims nothing, and its
        // button up ends nothing.
        h.win.clear();
        h.tcp(A, keyFrame(1, true));
        h.tcp(A, syncedButton(1200, 1200, 2, 0, false));
        CHECK(h.dropped == 3 && h.win.empty() && !h.keyDown(LControl) && !h.claims.held().ownsAny(A));
        // A's close, whenever it comes, has nothing left to release; B's own
        // up ends B's C.
        CHECK(h.close(A) == 0 && h.win.empty() && h.claims.owner() == B);
        h.tcp(B, keyFrame('C', false));
        CHECK(h.got({"Ku67"}) && !h.claims.anyHeld() && h.retry() == 0);
    }
    {
        // The first action is a click elsewhere (POINTER_SYNC, then the
        // button): A's Ctrl and right button go up before the pointer moves.
        OwnerHost h;
        const auto A = h.open();
        h.tcp(A, keyFrame(1, true));
        h.tcp(A, syncedButton(1000, 1000, 1, 1, true));
        const auto B = h.open();
        h.win.clear();
        h.tcp(B, syncedButton(2000, 2000, 1, 0, true));
        CHECK(h.got({"Ku162", "Bu1", "M", "Bd0"}));
        CHECK(!h.keyDown(LControl) && !h.buttonDown(1) && h.buttonDown(0) && h.claims.owner() == B);
    }
    {
        // The viewer sends the up it owes for Ctrl first on the new
        // connection: the takeover has already sent Ctrl's up, and the owed
        // up goes to Windows as it is (nobody holds Ctrl); then V is plain.
        OwnerHost h;
        const auto A = h.open();
        h.tcp(A, keyFrame(1, true));
        const auto B = h.open();
        h.win.clear();
        auto both = keyFrame(1, false);
        const auto v = keyFrame('V', true);
        both.insert(both.end(), v.begin(), v.end());
        h.tcp(B, both);
        CHECK(h.got({"Ku162", "Ku162", "Kd86"}) && !h.keyDown(LControl));
    }
    {
        // A is dragging: its button went down on its TCP connection and the
        // moves come over MRM1, so A sends no new TCP frame, before or after
        // B opens. B's first input still takes over: A's button goes up, then
        // B's key goes in.
        OwnerHost h;
        const auto A = h.open();
        h.tcp(A, syncedButton(1000, 1000, 1, 0, true));
        CHECK(h.last.tookOver && h.last.replaced == 0 && h.claims.owner() == A);
        for (int i = 0; i < 50; ++i) h.pointer();
        const auto B = h.open();
        for (int i = 0; i < 50; ++i) h.pointer();
        CHECK(h.buttonDown(0) && h.claims.held().buttonOwnedBy(0, A));
        h.win.clear();
        h.tcp(B, keyFrame('C', true));
        CHECK(h.last.admitted && h.last.tookOver && h.last.replaced == 1 && h.last.released == 1);
        CHECK(h.got({"Bu0", "Kd67"}) && h.claims.owner() == B && !h.claims.held().ownsAny(A));
        // A lets go and presses again: dropped. A has to reconnect.
        h.win.clear();
        h.tcp(A, syncedButton(1200, 1200, 60, 0, false));
        h.tcp(A, syncedButton(1300, 1300, 61, 0, true));
        CHECK(h.dropped == 4 && h.win.empty() && !h.buttonDown(0) && h.keyDown('C'));
    }
    {
        // A has only just stopped: it typed after B opened, its last frame a
        // moment before B's first. r7 kept such a connection; now B's first
        // input replaces it.
        OwnerHost h;
        const auto A = h.open();
        h.tcp(A, keyFrame(4, true));
        const auto B = h.open();
        h.tcp(A, keyFrame(4, true));  // a repeat after B opened
        h.tcp(A, keyFrame('K', true));
        h.tcp(A, keyFrame('K', false));
        h.win.clear();
        h.tcp(B, keyFrame('L', true));
        CHECK(h.last.replaced == 1 && h.last.released == 1 && h.got({"Ku160", "Kd76"}));
        CHECK(h.claims.owner() == B && !h.keyDown(LShift));
        // A's own Shift up, late: dropped; Windows had Shift's up already.
        h.win.clear();
        h.tcp(A, keyFrame(4, false));
        CHECK(h.win.empty() && h.dropped == 1);
    }
    {
        // An older connection never takes input, before or after the newest
        // owner closes; a newer one does, with nothing to replace. Clipboard
        // and ping connections are never the owner and never replaced.
        OwnerHost h;
        const auto C = h.open();
        h.tcp(C, clipboardHelloFrame());
        const auto P = h.open();
        h.tcp(P, pingFrame());
        const auto O = h.open();  // a control connection that has not sent input yet
        const auto D = h.open();
        h.tcp(D, keyFrame('Q', true));
        CHECK(h.last.tookOver && h.last.replaced == 0 && h.claims.owner() == D);
        h.win.clear();
        h.tcp(O, keyFrame('Z', true));
        CHECK(!h.last.admitted && !h.last.tookOver && h.win.empty() && h.claims.owner() == D && h.keyDown('Q'));
        h.tcp(C, clipboardHelloFrame());
        h.tcp(P, pingFrame());
        CHECK(h.claims.owner() == D && h.dropped == 1);
        CHECK(h.close(D) == 1 && h.got({"Ku81"}) && h.claims.owner() == 0);
        h.win.clear();
        h.tcp(O, keyFrame('Z', true));
        CHECK(!h.last.admitted && h.win.empty() && h.claims.owner() == 0 && h.dropped == 2);
        const auto E = h.open();
        h.tcp(E, keyFrame('E', true));
        CHECK(h.last.tookOver && h.last.replaced == 0 && h.got({"Kd69"}) && h.claims.owner() == E);
    }
    {
        // Each newer connection's first input replaces the one before: never
        // two owners.
        OwnerHost h;
        const auto A1 = h.open();
        const auto A2 = h.open();
        h.tcp(A1, keyFrame(4, true));
        h.tcp(A2, keyFrame(2, true));
        CHECK(h.last.replaced == 1 && h.got({"Kd160", "Ku160", "Kd164"}));
        const auto B = h.open();
        h.win.clear();
        h.tcp(B, keyFrame('Z', true));
        CHECK(h.last.replaced == 1 && h.got({"Ku164", "Kd90"}) && h.replacedTotal == 2);
        CHECK(h.claims.owner() == B && !h.claims.held().ownsAny(A1) && !h.claims.held().ownsAny(A2));
    }
}

// Pepper's review of 6175b5e, item 2: nothing is let go for being still. A
// button and a key held with no move, repeat or frame for 60 s stay down;
// with two connections dragging at once there is one owner, and nothing the
// other one sends cuts the owner's drag.
static void testHoldStill() {
    using jlh::vk::LShift;
    {
        OwnerHost h;
        const auto A = h.open();
        h.tcp(A, syncedButton(1000, 1000, 1, 0, true));
        h.tcp(A, keyFrame(4, true));
        h.win.clear();
        size_t released = 0;
        for (int i = 0; i < 240; ++i) released += h.retry();  // 60 s of 250 ms rounds
        CHECK(released == 0 && h.win.empty() && h.buttonDown(0) && h.keyDown(LShift));
        CHECK(h.claims.held().buttonOwnedBy(0, A) && h.claims.held().keyOwnedBy(LShift, A));
        // Its own ups let go.
        h.tcp(A, syncedButton(1000, 1000, 2, 0, false));
        h.tcp(A, keyFrame(4, false));
        CHECK(h.got({"M", "Bu0", "Ku160"}) && !h.claims.anyHeld());
    }
    {
        // A started dragging first, then B (a second viewer on the same
        // address, or the same viewer's new connection). B's press makes B
        // the owner: A's button goes up just before B's goes down. Both keep
        // moving over MRM1 for 30 s; A then lets go and presses again on its
        // connection: dropped, so B's drag is not cut. B lets go itself.
        OwnerHost h;
        const auto A = h.open();
        const auto B = h.open();
        h.tcp(A, syncedButton(1000, 1000, 1, 0, true));
        h.pointer();
        h.win.clear();
        h.tcp(B, syncedButton(3000, 3000, 1, 0, true));
        CHECK(h.last.tookOver && h.last.replaced == 1 && h.got({"Bu0", "M", "Bd0"}));
        CHECK(h.claims.held().buttonOwnedBy(0, B) && !h.claims.held().ownsAny(A));
        h.win.clear();
        for (int i = 0; i < 120; ++i) {
            h.pointer();
            h.pointer();
            h.retry();
        }
        h.tcp(A, syncedButton(1500, 1500, 90, 0, false));
        h.tcp(A, syncedButton(1600, 1600, 91, 0, true));
        CHECK(h.win.empty() && h.buttonDown(0) && h.claims.held().buttonOwnedBy(0, B) && h.dropped == 4);
        h.tcp(B, syncedButton(3500, 3500, 95, 0, false));
        CHECK(h.got({"M", "Bu0"}) && !h.claims.anyHeld());
    }
    {
        // The other order: B, the newer, drags first; A's press comes later.
        // A opened before the owner, so its press is dropped and B's drag
        // goes on.
        OwnerHost h;
        const auto A = h.open();
        const auto B = h.open();
        h.tcp(B, syncedButton(3000, 3000, 1, 0, true));
        h.win.clear();
        h.tcp(A, syncedButton(1000, 1000, 1, 2, true));
        h.tcp(A, syncedButton(1000, 1000, 2, 0, false));
        CHECK(h.win.empty() && h.dropped == 4 && h.claims.owner() == B && h.buttonDown(0) && !h.buttonDown(2));
        CHECK(h.claims.held().buttonOwnedBy(0, B));
    }
}

// Pepper's review of 6175b5e, item 3: admission, takeover and injection are
// one step (InputClaims::frame). A's frame is admitted while A is the owner
// and is still going in (a slow SendInput) when B's first frame comes on
// another thread. B's takeover waits for A's frame, so it releases what
// A's frame pressed, and nothing of A's is left. In 6175b5e admission and
// injection were apart: B's takeover ran in between, found nothing to
// release, and A's press stayed recorded for a replaced connection.
static void testAdmitInjectOrder() {
    for (int round = 0; round < 2; ++round) {  // a button, then a key
        jlh::InputClaims claims;
        std::mutex winMutex;
        std::vector<std::string> win;
        auto log = [&](const std::string& s) {
            std::lock_guard<std::mutex> g(winMutex);
            win.push_back(s);
        };
        auto upKey = [&](uint16_t v) {
            log("Ku" + std::to_string(v));
            return true;
        };
        auto upButton = [&](uint8_t b) {
            log("Bu" + std::to_string(b));
            return true;
        };
        const auto A = claims.open();
        const auto B = claims.open();
        CHECK(claims.frame(A, [](jlh::HeldInput&) { return true; }, upKey, upButton).tookOver);  // A owns input
        std::atomic<bool> aInside{false}, bCalling{false}, bDone{false};
        bool bDoneDuringA = true;
        jlh::InputClaims::Frame fa, fb;
        std::thread ta([&] {
            fa = claims.frame(
                A,
                [&](jlh::HeldInput& held) {
                    aInside = true;
                    while (!bCalling) std::this_thread::yield();
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));  // B has every chance to run
                    bDoneDuringA = bDone.load();
                    if (round == 0) {
                        log("Bd0");
                        held.pressButton(0, A);
                    } else {
                        log("Kd162");
                        held.pressKey(jlh::vk::LControl, A);
                    }
                    return true;
                },
                upKey, upButton);
        });
        while (!aInside) std::this_thread::yield();
        std::thread tb([&] {
            bCalling = true;
            fb = claims.frame(
                B,
                [&](jlh::HeldInput& held) {
                    log("Kd67");
                    held.pressKey('C', B);
                    return true;
                },
                upKey, upButton);
            bDone = true;
        });
        ta.join();
        tb.join();
        CHECK(fa.admitted && !fa.tookOver && !bDoneDuringA);
        CHECK(fb.admitted && fb.tookOver && fb.replaced == 1 && fb.released == 1);
        const char* down = round == 0 ? "Bd0" : "Kd162";
        const char* up = round == 0 ? "Bu0" : "Ku162";
        CHECK(win.size() == 3 && win[0] == down && win[1] == up && win[2] == "Kd67");
        const auto held = claims.held();
        CHECK(!held.ownsAny(A) && !held.buttonHeld(0) && !held.keyHeld(jlh::vk::LControl) &&
              held.keyOwnedBy('C', B));
        // A's next frame: dropped before inject.
        bool called = false;
        const auto late = claims.frame(
            A,
            [&](jlh::HeldInput&) {
                called = true;
                return true;
            },
            upKey, upButton);
        CHECK(!late.admitted && !called && claims.owner() == B);
    }
}

// Pepper's review of 6175b5e, item 4: an up Windows did not take stays
// recorded with no owner, and each retry round (every 250 ms) sends it again
// until Windows takes it, however it was let go: a close, a takeover, the
// owner's own up. What a connection holds is left alone.
static void testRetryFailedUp() {
    using jlh::vk::LControl;
    {
        // A closes holding the left button; Windows refuses the up, and
        // again on the next round; the round after, it takes it.
        OwnerHost h;
        const auto A = h.open();
        h.tcp(A, syncedButton(1000, 1000, 1, 0, true));
        h.refuseUps = true;
        h.win.clear();
        CHECK(h.close(A) == 0 && h.got({"Bu0!"}) && h.buttonDown(0));
        CHECK(h.claims.held().buttonHeld(0) && !h.claims.held().buttonOwnedBy(0, A));
        CHECK(h.retry() == 0 && h.got({"Bu0!", "Bu0!"}) && h.buttonDown(0));
        h.refuseUps = false;
        h.win.clear();
        CHECK(h.retry() == 1 && h.got({"Bu0"}) && !h.buttonDown(0) && !h.claims.anyHeld());
        CHECK(h.retry() == 0 && h.got({"Bu0"}));  // nothing left to send
    }
    {
        // A takeover whose ups Windows refuses: B's key still goes in; the
        // next round sends A's Ctrl and right button up and leaves B's key.
        OwnerHost h;
        const auto A = h.open();
        h.tcp(A, keyFrame(1, true));
        h.tcp(A, syncedButton(1000, 1000, 1, 1, true));
        const auto B = h.open();
        h.refuseUps = true;
        h.win.clear();
        h.tcp(B, keyFrame('C', true));
        CHECK(h.last.tookOver && h.last.replaced == 1 && h.last.released == 0);
        CHECK(h.got({"Ku162!", "Bu1!", "Kd67"}) && h.keyDown(LControl) && h.buttonDown(1));
        h.refuseUps = false;
        h.win.clear();
        CHECK(h.retry() == 2 && h.got({"Ku162", "Bu1"}) && !h.keyDown(LControl) && !h.buttonDown(1));
        CHECK(h.keyDown('C') && h.claims.held().keyOwnedBy('C', B));
    }
    {
        // The owner's own up, refused: the next round sends it.
        OwnerHost h;
        const auto A = h.open();
        h.tcp(A, keyFrame('X', true));
        h.refuseUps = true;
        h.tcp(A, keyFrame('X', false));
        CHECK(h.keyDown('X') && h.claims.held().keyHeld('X') && !h.claims.held().keyOwnedBy('X', A));
        h.refuseUps = false;
        h.win.clear();
        CHECK(h.retry() == 1 && h.got({"Ku88"}) && !h.claims.anyHeld());
        // The same key pressed again before the round: it is the owner's
        // again, and the round leaves it down.
        h.refuseUps = true;
        h.tcp(A, keyFrame('Y', true));
        h.tcp(A, keyFrame('Y', false));
        h.refuseUps = false;
        h.tcp(A, keyFrame('Y', true));
        h.win.clear();
        CHECK(h.retry() == 0 && h.win.empty() && h.keyDown('Y') && h.claims.held().keyOwnedBy('Y', A));
    }
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
    testConnectionSlots();
    testVideoConfig();
    testMrm1();
    testHostInfo();
    testDecodeInput();
    testKeysAgainstViewer();
    testHostInfoOnlyWhenAsked();
    testHeldInput();
    testTaskManagerRelease();
    testPointerMapping();
    testMrm1SessionAndCursor();
    testPointerSyncOrdering();
    testOwnerTakeover();
    testHoldStill();
    testAdmitInjectOrder();
    testRetryFailedUp();
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
