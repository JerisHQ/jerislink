// JerisLink Windows host: wire formats shared with the viewer.
//
// Platform-free so the unit tests run the same code the host sends with.
// Matches the macOS host: MR02 video packets (UDPFrameSender.makePacket),
// MRC1 control frames (ControlServer), the 0x41 VIDEO_CONFIG ACK
// (VideoSettingsAck), the MRC1 input frames (ControlServer.isLegacyFirstHeader
// lengths) and the MRM1 pointer, cursor and ping packets (MouseMoveUDPServer).
// H2 adds MRC1 0x06 HOST_INFO (design D10), which only this host sends.
#pragma once

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace jlh {

// ---------------------------------------------------------------- MR02 video

constexpr size_t kMr02HeaderBytes = 20;
constexpr size_t kDefaultPacketBytes = 1200;  // the macOS host's default
constexpr uint8_t kMr02Key = 0x01, kMr02Last = 0x02;

// Splits one Annex B access unit into MR02 datagrams. packetBytes is the
// whole datagram (header included), as on the macOS host.
inline std::vector<std::vector<uint8_t>> packetizeMr02(uint64_t frameId, const uint8_t* data, size_t n, bool keyFrame,
                                                     size_t packetBytes = kDefaultPacketBytes) {
    std::vector<std::vector<uint8_t>> out;
    if (packetBytes <= kMr02HeaderBytes || n == 0) return out;
    const size_t cap = packetBytes - kMr02HeaderBytes;
    const size_t count = (n + cap - 1) / cap;
    if (count > 0xFFFF) return out;  // larger than the format can carry
    out.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        const size_t off = i * cap;
        const size_t len = std::min(cap, n - off);
        std::vector<uint8_t> p(kMr02HeaderBytes + len);
        p[0] = 'M'; p[1] = 'R'; p[2] = '0'; p[3] = '2';
        p[4] = 1;
        p[5] = uint8_t((keyFrame ? kMr02Key : 0) | (i + 1 == count ? kMr02Last : 0));
        for (int b = 0; b < 8; ++b) p[6 + b] = uint8_t(frameId >> (56 - 8 * b));
        p[14] = uint8_t(i >> 8); p[15] = uint8_t(i);
        p[16] = uint8_t(count >> 8); p[17] = uint8_t(count);
        p[18] = uint8_t(len >> 8); p[19] = uint8_t(len);
        std::memcpy(p.data() + kMr02HeaderBytes, data + off, len);
        out.push_back(std::move(p));
    }
    return out;
}

// Token bucket in front of the video socket (the macOS host's UDPPacing):
// rate = min(400, max(40, 4 x bitrate)) Mbit/s, 32 KB burst.
class Pacer {
public:
    explicit Pacer(int bitrateMbps) { setBitrate(bitrateMbps); }
    void setBitrate(int bitrateMbps) {
        const double mbps = std::min(400.0, std::max(40.0, 4.0 * bitrateMbps));
        bytesPerUs_ = mbps * 1e6 / 8.0 / 1e6;
    }
    double mbps() const { return bytesPerUs_ * 8.0; }
    // Microseconds to wait before `bytes` may leave at time nowUs; the
    // caller sleeps that long, then calls spend().
    int64_t waitUs(int64_t nowUs, size_t bytes) {
        refill(nowUs);
        if (tokens_ >= double(bytes)) return 0;
        return int64_t((double(bytes) - tokens_) / bytesPerUs_) + 1;
    }
    void spend(int64_t nowUs, size_t bytes) {
        refill(nowUs);
        tokens_ -= double(bytes);
    }

private:
    void refill(int64_t nowUs) {
        if (lastUs_ < 0) { lastUs_ = nowUs; tokens_ = kBurst; return; }
        if (nowUs > lastUs_) tokens_ = std::min(kBurst, tokens_ + double(nowUs - lastUs_) * bytesPerUs_);
        lastUs_ = nowUs;
    }
    static constexpr double kBurst = 32.0 * 1024.0;
    double bytesPerUs_ = 5.0;
    double tokens_ = 0;
    int64_t lastUs_ = -1;
};

// -------------------------------------------------------------- MRC1 control

constexpr size_t kMrc1HeaderBytes = 8;
constexpr uint8_t kMsgPing = 0x01, kMsgPong = 0x02;
constexpr size_t kPingPayloadBytes = 4;     // ControlChannel::ping(); the Mac host ignores other sizes
constexpr uint8_t kMsgAuthResponse = 0x03, kMsgAuthResult = 0x04;
constexpr uint8_t kMsgClipboardHello = 0x30;
constexpr uint8_t kMsgVideoConfig = 0x40, kMsgVideoConfigAck = 0x41;
constexpr uint8_t kMsgFileHello = 0x50;
constexpr uint8_t kMsgHostInfo = 0x06;      // H2, host -> viewer (windows-client/host_info.hpp)
constexpr size_t kAuthProbeBytes = 64;      // client nonce (32) + MAC (32)
constexpr uint8_t kAuthOpenIpOnly = 5;      // conn_auth.hpp Result::Status

inline std::vector<uint8_t> mrc1Frame(uint8_t type, const uint8_t* payload, size_t n) {
    std::vector<uint8_t> b{'M', 'R', 'C', '1', 1, type, uint8_t(n >> 8), uint8_t(n)};
    if (n) b.insert(b.end(), payload, payload + n);
    return b;
}
inline std::vector<uint8_t> mrc1Frame(uint8_t type, const std::vector<uint8_t>& p) {
    return mrc1Frame(type, p.data(), p.size());
}

struct Mrc1Header {
    uint8_t type = 0;
    uint16_t length = 0;
};
inline std::optional<Mrc1Header> parseMrc1Header(const uint8_t* h) {
    if (h[0] != 'M' || h[1] != 'R' || h[2] != 'C' || h[3] != '1' || h[4] != 1) return std::nullopt;
    return Mrc1Header{h[5], uint16_t((uint16_t(h[6]) << 8) | h[7])};
}

// A PING the host answers: the 4-byte payload real viewers send.
inline bool isValidPing(const Mrc1Header& h) { return h.type == kMsgPing && h.length == kPingPayloadBytes; }

// Control connection slots. The listener takes one before it starts a
// worker, so sockets still in the handshake count against the cap too; the
// worker gives it back on every exit path.
class ConnectionSlots {
public:
    explicit ConnectionSlots(int max) : max_(max) {}
    bool tryAcquire() {
        int n = used_.load();
        while (n < max_)
            if (used_.compare_exchange_weak(n, n + 1)) return true;
        return false;
    }
    void release() { --used_; }
    int inUse() const { return used_.load(); }

private:
    const int max_;
    std::atomic<int> used_{0};
};

// The transition probe a viewer sends to a host that sent no challenge:
// random nonce, all-zero MAC (conn_auth.hpp, design §9). H1 runs without a
// password only, so the probe is the only AUTH it accepts.
inline bool isTransitionProbe(const Mrc1Header& h, const uint8_t* payload) {
    if (h.type != kMsgAuthResponse || h.length != kAuthProbeBytes) return false;
    for (size_t i = 32; i < kAuthProbeBytes; ++i)
        if (payload[i] != 0) return false;
    return true;
}

// VIDEO_CONFIG_SET v1: [1, codec (0 auto, 1 h264, 2 hevc), caps, 0, bitrate BE16].
// H1 encodes H.264 only. Same refusals as VideoSettingsController.apply.
//
// H2 (Pepper's H2 review, item 1): caps 0x08 says "this viewer reads
// HOST_INFO"; the macOS host ignores caps bits it does not know. Only then
// does this host send HOST_INFO, right behind the ACK, and say so in the
// ACK: one payload byte after the usual ten, kAckExtHostInfo, so the viewer
// reads it at once instead of guessing whether more is coming. A viewer of
// 0.4.x or older never sets 0x08: it gets exactly the ACK it reads, and
// nothing stays unread on its socket (its pollHostNotice must see the host
// close the connection, or a read-only view never reconnects).
constexpr uint8_t kViewerCapHostInfo = 0x08;
constexpr uint8_t kAckExtHostInfo = 0x01;  // ACK payload [10]: one MRC1 0x06 HOST_INFO follows
struct VideoConfigDecision {
    std::vector<uint8_t> ack;  // the 0x41 payload: 10 bytes, 11 when HOST_INFO follows
    bool accepted = false;
    bool hostInfo = false;     // the viewer asked for HOST_INFO (caps 0x08)
    int bitrateMbps = 25;
    bool bitrateChanged = false;
};
inline VideoConfigDecision decideVideoConfig(const uint8_t* p, size_t n, int currentBitrateMbps, int width,
                                             int height) {
    VideoConfigDecision d;
    const bool shapeOk = n == 6 && p[0] == 1;
    const uint8_t codec = shapeOk ? p[1] : 0;
    const uint8_t caps = shapeOk ? p[2] : 0;
    const int bitrate = shapeOk ? int((uint16_t(p[4]) << 8) | p[5]) : 0;
    d.hostInfo = (caps & kViewerCapHostInfo) != 0;
    auto ack = [&](uint8_t status, uint8_t flags, int bitrate, int w, int h) {
        d.ack = {1, status, 1, flags, uint8_t(bitrate >> 8), uint8_t(bitrate), uint8_t(w >> 8), uint8_t(w),
                 uint8_t(h >> 8), uint8_t(h)};
        if (d.hostInfo) d.ack.push_back(kAckExtHostInfo);
    };
    d.bitrateMbps = currentBitrateMbps;
    if (!shapeOk || !(caps & 0x01) || codec > 2 || (bitrate != 0 && (bitrate < 4 || bitrate > 100))) {
        ack(1, 0, 25, 0, 0);
        return d;
    }
    const int selected = bitrate == 0 ? 25 : bitrate;
    uint8_t flags = 0;
    d.bitrateChanged = selected != currentBitrateMbps;
    if (d.bitrateChanged) flags |= 0x01;           // stream restarted
    if (codec == 2) flags |= 0x04;                 // asked for HEVC, got H.264
    const bool sized = width > 0 && height > 0 && width <= 0xFFFF && height <= 0xFFFF;
    if (sized) flags |= 0x08;
    ack(0, flags, selected, sized ? width : 0, sized ? height : 0);
    d.accepted = true;
    d.bitrateMbps = selected;
    return d;
}

// What goes on the socket for one VIDEO_CONFIG: the ACK frame, then the
// HOST_INFO frame when the viewer asked for it, in one send.
inline std::vector<uint8_t> videoConfigReply(const VideoConfigDecision& d, const std::vector<uint8_t>& hostInfo) {
    auto out = mrc1Frame(kMsgVideoConfigAck, d.ack);
    if (d.hostInfo) {
        const auto hi = mrc1Frame(kMsgHostInfo, hostInfo);
        out.insert(out.end(), hi.begin(), hi.end());
    }
    return out;
}

// ------------------------------------------------------------- HOST_INFO (H2)

// MRC1 0x06 HOST_INFO, host -> viewer, design D10. The macOS host never
// sends it; a viewer that gets none treats the host as a Mac. Payload:
//   [0] format (1)   [1] platform (1 macOS, 2 Windows)
//   [2..5] capability bits, BE   [6] monitors   [7] version length n
//   [8..8+n) version, ASCII
// Later formats append fields; the viewer reads the ones it knows.
// Sent behind each 0x41 ACK whose VIDEO_CONFIG asked for it (caps 0x08,
// decideVideoConfig), in the same send; never to a viewer that did not ask.
constexpr uint8_t kHostInfoFormat = 1;
constexpr uint8_t kPlatformMac = 1, kPlatformWindows = 2;
constexpr uint32_t kHostCapKeyboard = 0x01;     // MRC1 0x10 is injected
constexpr uint32_t kHostCapPointer = 0x02;      // MRC1 0x20-0x25 and MRM1 0x24 are injected
constexpr uint32_t kHostCapCursorShape = 0x04;  // MRM1 0x31 cursor state is sent
constexpr uint32_t kHostCapTaskManager = 0x08;  // MRC1 0x60 opens Task Manager (Ctrl+Shift+Esc)
// 0x10 is kept for the secure desktop (UAC, lock screen; design D1, not in H2).
constexpr uint32_t kHostCapPointerSync = 0x20;  // MRC1 0x27 POINTER_SYNC is taken (decodeInput)
constexpr size_t kHostInfoMaxVersion = 64;

inline std::vector<uint8_t> hostInfoPayload(uint8_t platform, uint32_t caps, uint8_t monitors,
                                            const std::string& version) {
    std::string v;
    for (char c : version) {
        if (v.size() == kHostInfoMaxVersion) break;
        v.push_back(c >= 0x20 && c < 0x7F ? c : '?');
    }
    std::vector<uint8_t> p{kHostInfoFormat, platform, uint8_t(caps >> 24), uint8_t(caps >> 16), uint8_t(caps >> 8),
                           uint8_t(caps), monitors, uint8_t(v.size())};
    p.insert(p.end(), v.begin(), v.end());
    return p;
}

// ------------------------------------------------------------ MRC1 input (H2)

constexpr uint8_t kMsgKey = 0x10;
constexpr uint8_t kMsgMouseMoveRel = 0x20, kMsgMouseButton = 0x21, kMsgMouseScroll = 0x22;
constexpr uint8_t kMsgMouseMoveAbs = 0x23, kMsgMouseMoveNorm = 0x24, kMsgMouseButtonExt = 0x25;
constexpr uint8_t kMsgForceQuitOpen = 0x60;
// H2 (Pepper's H2 review, item 5), only from a viewer this host's HOST_INFO
// told (kHostCapPointerSync): [nx BE16, ny BE16, MRM1 seq BE32, MRM1 port
// BE16], sent right in front of a button frame in the same write. The
// pointer moves by UDP and the button by TCP, so the button can overtake
// the move it belongs to. The button is pressed or released at (nx, ny),
// and MRM1 pointer moves up to seq (the newest the viewer had sent by then)
// from the viewer's UDP source port are stale from then on, so a late one
// cannot move the pointer away from the press. The port names the MRM1
// session the seq belongs to (Pepper's review of 8f8a33b, item 5a): the
// viewer's seq starts over on every new UDP socket, and the sync can arrive
// before that socket's first datagram (Mrm1Session::syncPointer). Port 0:
// position only, no seq mark.
constexpr uint8_t kMsgPointerSync = 0x27;
constexpr uint16_t kPointerSyncBytes = 10;

// One input frame, decoded. Integers on the wire are big-endian.
struct InputEvent {
    enum class Kind { Key, MoveRel, Button, Scroll, MoveAbsPixels, MoveNorm, TaskManager, PointerSync };
    Kind kind = Kind::Key;
    bool down = false;
    uint16_t semantic = 0;  // Key
    uint8_t button = 0;     // Button: 0 left, 1 right, 2 middle
    int x = 0, y = 0;       // MoveRel / Scroll: signed deltas; MoveAbsPixels: pixels; MoveNorm, PointerSync: 0..65535
    uint32_t seq = 0;       // PointerSync: the MRM1 seq it covers
    uint16_t port = 0;      // PointerSync: the viewer's MRM1 UDP source port that seq belongs to
};

// One decoded input frame on a control connection. A POINTER_SYNC is held
// in `pending` until the next input frame: a button is then applied with it
// as one step (sync(s, &button): the host does both under its pointer
// lock), anything else after it on its own (sync(s, nullptr), then
// apply(e)). Returns what the step returned.
template <class Sync, class Apply>
bool stepInput(std::optional<InputEvent>& pending, const InputEvent& e, Sync&& sync, Apply&& apply) {
    if (e.kind == InputEvent::Kind::PointerSync) {
        if (pending) sync(*pending, nullptr);  // two in a row: the first alone
        pending = e;
        return true;
    }
    if (pending) {
        const InputEvent s = *pending;
        pending.reset();
        if (e.kind == InputEvent::Kind::Button) return sync(s, &e);
        sync(s, nullptr);
    }
    return apply(e);
}

// The frame lengths the macOS host accepts (ControlServer.isLegacyFirstHeader),
// exactly. Anything else is not input and is dropped whole.
inline std::optional<InputEvent> decodeInput(const Mrc1Header& h, const uint8_t* p) {
    auto s16 = [p](int at) { return int(int16_t(uint16_t((uint16_t(p[at]) << 8) | p[at + 1]))); };
    auto u16 = [p](int at) { return int((uint16_t(p[at]) << 8) | p[at + 1]); };
    InputEvent e;
    switch (h.type) {
    case kMsgKey:
        if (h.length != 3) return std::nullopt;
        e.kind = InputEvent::Kind::Key;
        e.down = p[0] != 0;
        e.semantic = uint16_t(u16(1));
        return e;
    case kMsgMouseMoveRel:
    case kMsgMouseScroll:
    case kMsgMouseMoveAbs:
    case kMsgMouseMoveNorm:
        if (h.length != 4) return std::nullopt;
        e.kind = h.type == kMsgMouseMoveRel  ? InputEvent::Kind::MoveRel
                 : h.type == kMsgMouseScroll ? InputEvent::Kind::Scroll
                 : h.type == kMsgMouseMoveAbs ? InputEvent::Kind::MoveAbsPixels
                                              : InputEvent::Kind::MoveNorm;
        if (h.type == kMsgMouseMoveRel || h.type == kMsgMouseScroll) {
            e.x = s16(0);
            e.y = s16(2);
        } else {
            e.x = u16(0);
            e.y = u16(2);
        }
        return e;
    case kMsgMouseButton:
    case kMsgMouseButtonExt:
        if (h.length != (h.type == kMsgMouseButton ? 2 : 3)) return std::nullopt;
        if (p[0] > 2) return std::nullopt;  // 0 left, 1 right, 2 middle; the click count is Windows' own
        e.kind = InputEvent::Kind::Button;
        e.button = p[0];
        e.down = p[1] != 0;
        return e;
    case kMsgForceQuitOpen:
        if (h.length != 0) return std::nullopt;
        e.kind = InputEvent::Kind::TaskManager;
        return e;
    case kMsgPointerSync:
        if (h.length != kPointerSyncBytes) return std::nullopt;
        e.kind = InputEvent::Kind::PointerSync;
        e.x = u16(0);
        e.y = u16(2);
        e.seq = (uint32_t(p[4]) << 24) | (uint32_t(p[5]) << 16) | (uint32_t(p[6]) << 8) | p[7];
        e.port = uint16_t(u16(8));
        return e;
    default:
        return std::nullopt;
    }
}

// Windows virtual-key codes used here (no <windows.h>); input_win.cpp
// static_asserts them against the real VK_* values.
namespace vk {
constexpr uint16_t Back = 0x08, Tab = 0x09, Return = 0x0D, Capital = 0x14, Escape = 0x1B, Space = 0x20;
constexpr uint16_t Prior = 0x21, Next = 0x22, End = 0x23, Home = 0x24;
constexpr uint16_t Left = 0x25, Up = 0x26, Right = 0x27, Down = 0x28, Insert = 0x2D, Delete = 0x2E;
constexpr uint16_t LWin = 0x5B, RWin = 0x5C, Numpad0 = 0x60, Numpad9 = 0x69;
constexpr uint16_t Multiply = 0x6A, Add = 0x6B, Subtract = 0x6D, Decimal = 0x6E, Divide = 0x6F;
constexpr uint16_t F1 = 0x70, F12 = 0x7B;
constexpr uint16_t LShift = 0xA0, LControl = 0xA2, RControl = 0xA3, LMenu = 0xA4, RMenu = 0xA5;
constexpr uint16_t Oem1 = 0xBA, OemPlus = 0xBB, OemComma = 0xBC, OemMinus = 0xBD, OemPeriod = 0xBE;
constexpr uint16_t Oem2 = 0xBF, Oem3 = 0xC0, Oem4 = 0xDB, Oem5 = 0xDC, Oem6 = 0xDD, Oem7 = 0xDE;
}  // namespace vk

// Wire semantic (windows-client/keymap.hpp) -> the Windows VK to press.
// 1 Control, 2 Option/Alt, 3 Command/Win, 4 Shift press the left-hand key;
// every other forwarded key is its own VK. 0 = not a key this host presses
// (the frame is dropped and counted).
inline uint16_t semanticToVk(uint16_t semantic) {
    switch (semantic) {
    case 1: return vk::LControl;
    case 2: return vk::LMenu;
    case 3: return vk::LWin;
    case 4: return vk::LShift;
    case vk::Capital:
    case vk::Back: case vk::Tab: case vk::Return: case vk::Escape: case vk::Space:
    case vk::Prior: case vk::Next: case vk::End: case vk::Home:
    case vk::Left: case vk::Up: case vk::Right: case vk::Down: case vk::Insert: case vk::Delete:
    case vk::Multiply: case vk::Add: case vk::Subtract: case vk::Decimal: case vk::Divide:
    case vk::Oem1: case vk::OemPlus: case vk::OemComma: case vk::OemMinus: case vk::OemPeriod:
    case vk::Oem2: case vk::Oem3: case vk::Oem4: case vk::Oem5: case vk::Oem6: case vk::Oem7:
        return semantic;
    default:
        if ((semantic >= 'A' && semantic <= 'Z') || (semantic >= '0' && semantic <= '9') ||
            (semantic >= vk::Numpad0 && semantic <= vk::Numpad9) || (semantic >= vk::F1 && semantic <= vk::F12))
            return semantic;
        return 0;
    }
}

// Keys whose scan code carries the E0 prefix (KEYEVENTF_EXTENDEDKEY).
inline bool isExtendedVk(uint16_t v) {
    switch (v) {
    case vk::Prior: case vk::Next: case vk::End: case vk::Home:
    case vk::Left: case vk::Up: case vk::Right: case vk::Down: case vk::Insert: case vk::Delete:
    case vk::LWin: case vk::RWin: case vk::Divide: case vk::RControl: case vk::RMenu:
        return true;
    default:
        return false;
    }
}

// Keys and buttons this host has pressed and not released, and which
// control connections hold them, so a viewer that goes away (connection
// closed, viewer crashed) leaves nothing held.
//
// More than one control connection can be open at a time: a reconnect
// opens the new one before the old one is seen closed, and two viewers can
// be connected at once. Each connection is an owner here, numbered in the
// order the connections opened (InputClaims::open).
//
// Who lets go of what (Pepper's H2 reviews: item 2 of a784cd7 and of
// 8f8a33b, item 1 of f97ad11, the one item of 04622f0, item 1 of c397898):
// - A claim belongs to the connection whose down made it, and only that
//   connection ends it: with an up frame for that key or button
//   (releaseKey, releaseButton), or by closing (releaseOwned). Another
//   connection's up or close never ends it, older or newer, the same
//   viewer or another.
// - The viewer sends every up on the connection it has now. After a
//   reconnect, the ups it owes for presses made on the old connection go
//   first on the new one (the viewer's control_channel.hpp,
//   takeOwedLocked), and look the same as a plain up. The host does not
//   tell them apart: such an up ends the new connection's own claim, if it
//   has one, and nothing else. The old connection's claims end when the
//   new connection's first input makes it the input owner, or when the old
//   one closes, whichever comes first (InputClaims, r8). Only the input
//   owner presses, so one connection at most holds claims.
// Windows gets the up only when no connection holds it any more.
//
// Every up goes to Windows only through upKey(vk) / upButton(b), which
// return true when Windows took it. One that Windows did not take keeps its
// entry, with no owner left, and the next release or retryUnowned (every
// 250 ms, InputClaims::retry) tries it again: nothing is forgotten while it
// may still be down. An up for a key nobody holds
// here goes to Windows as it is (as on the macOS host).
class HeldInput {
public:
    using Owner = uint64_t;
    enum class Up {
        Sent,    // Windows took the up
        Held,    // another connection still holds it: no up sent
        Failed,  // Windows did not take the up
    };
    // A down Windows took, from connection o.
    void pressKey(uint16_t v, Owner o) { press(keys_, v, o); }
    void pressButton(uint8_t b, Owner o) { if (b < 3) press(buttons_, b, o); }
    // An up frame from connection o (the rule above).
    template <class UpKey>
    Up releaseKey(uint16_t v, Owner o, UpKey&& upKey) { return release(keys_, v, o, upKey); }
    template <class UpButton>
    Up releaseButton(uint8_t b, Owner o, UpButton&& upButton) {
        return release(buttons_, b, o, [&](uint16_t c) { return upButton(uint8_t(c)); });
    }
    bool anyHeld() const { return !keys_.empty() || !buttons_.empty(); }
    bool keyHeld(uint16_t v) const { return find(keys_, v) != nullptr; }
    bool buttonHeld(uint8_t b) const { return find(buttons_, b) != nullptr; }
    bool keyOwnedBy(uint16_t v, Owner o) const { return owns(find(keys_, v), o); }
    bool buttonOwnedBy(uint8_t b, Owner o) const { return owns(find(buttons_, b), o); }
    bool ownsAny(Owner o) const {
        for (const auto& e : keys_)
            if (owns(&e, o)) return true;
        for (const auto& e : buttons_)
            if (owns(&e, o)) return true;
        return false;
    }
    // r9: an up Windows did not take is still owed (an entry no connection
    // holds any more, which retryUnowned tries again).
    bool anyUnowned() const {
        for (const auto& e : keys_)
            if (e.owners.empty()) return true;
        for (const auto& e : buttons_)
            if (e.owners.empty()) return true;
        return false;
    }
    // r9: key v's up, sent outside any claim (the Task Manager chord), was
    // not taken by Windows: recorded with no owner, so retryUnowned sends it
    // again and no new input goes in until it does (InputClaims).
    void oweKey(uint16_t v) {
        if (!find(keys_, v)) keys_.push_back(Entry{v, {}});
    }

    // Connection o went away: it lets go of its own claims only (the rule
    // above). Keys (newest press first), then buttons, that no connection
    // holds any more are released, and so is anything an earlier up could
    // not release. Returns how many ups Windows took.
    template <class UpKey, class UpButton>
    size_t releaseOwned(Owner o, UpKey&& upKey, UpButton&& upButton) {
        for (auto& e : keys_) dropOwner(e, o);
        for (auto& e : buttons_) dropOwner(e, o);
        return retryUnowned(upKey, upButton);
    }
    // Ups Windows did not take before (entries with no owner left), keys
    // newest first, then buttons: tried again. What a connection still
    // holds is left alone. Returns how many ups Windows took.
    template <class UpKey, class UpButton>
    size_t retryUnowned(UpKey&& upKey, UpButton&& upButton) {
        return releaseUnowned(keys_, upKey) +
               releaseUnowned(buttons_, [&](uint16_t b) { return upButton(uint8_t(b)); });
    }
    // Item 3 (Task Manager): every held key is released, whoever pressed
    // it, so the chord goes in clean. Buttons are left exactly as they are,
    // on Windows and here. Returns how many ups Windows took.
    template <class UpKey>
    size_t releaseKeys(UpKey&& upKey) {
        for (auto& e : keys_) e.owners.clear();
        return releaseUnowned(keys_, upKey);
    }

private:
    struct Entry {
        uint16_t code = 0;
        std::vector<Owner> owners;
    };
    static const Entry* find(const std::vector<Entry>& v, uint16_t code) {
        for (const auto& e : v)
            if (e.code == code) return &e;
        return nullptr;
    }
    static bool owns(const Entry* e, Owner o) {
        return e && std::find(e->owners.begin(), e->owners.end(), o) != e->owners.end();
    }
    // An up or a close from o: o's own claim ends, no other.
    static void dropOwner(Entry& e, Owner o) {
        e.owners.erase(std::remove(e.owners.begin(), e.owners.end(), o), e.owners.end());
    }
    static void press(std::vector<Entry>& v, uint16_t code, Owner o) {
        auto it = std::find_if(v.begin(), v.end(), [&](const Entry& e) { return e.code == code; });
        if (it == v.end()) v.push_back(Entry{code, {o}});
        else if (!owns(&*it, o)) it->owners.push_back(o);
    }
    template <class UpFn>
    Up release(std::vector<Entry>& v, uint16_t code, Owner o, UpFn&& up) {
        auto it = std::find_if(v.begin(), v.end(), [&](const Entry& e) { return e.code == code; });
        if (it != v.end()) {
            dropOwner(*it, o);
            if (!it->owners.empty()) return Up::Held;
        }
        if (!up(code)) return Up::Failed;  // an entry stays, with no owner, for the next release
        if (it != v.end()) v.erase(it);
        return Up::Sent;
    }
    // Newest first; an entry stays when Windows did not take its up.
    template <class UpFn>
    static size_t releaseUnowned(std::vector<Entry>& v, UpFn&& up) {
        size_t n = 0;
        for (size_t i = v.size(); i-- > 0;) {
            if (!v[i].owners.empty()) continue;
            if (up(v[i].code)) {
                v.erase(v.begin() + std::ptrdiff_t(i));
                ++n;
            }
        }
        return n;
    }
    std::vector<Entry> keys_;     // in press order
    std::vector<Entry> buttons_;  // 0 left, 1 right, 2 middle; in press order
};

// MRC1 0x60, the viewer's Force Quit button: on Windows, Ctrl+Shift+Esc
// (InputInjector::taskManager; sendKey(vk, down) is SendInput). Held keys
// are released first so the chord is clean. Buttons stay as they are
// (Pepper's H2 review, item 3): no up goes to Windows for them, so their
// records stay too, and a later up or close releases them. A key whose up
// Windows did not take stays recorded as well (InputClaims::retry tries it
// again).
// r9 (Pepper's review of 0d74abe, item 3): with an up still owed the chord
// does not go at all (it would be a different chord). It goes down in
// order and stops at the first down Windows does not take, so no part of
// it goes in on its own (Ctrl+Esc without Shift); the keys that went down
// come up, and an up Windows does not take is recorded (oweKey) and tried
// again like any other. Returns true when the whole chord went in.
template <class SendKey>
bool taskManagerChord(HeldInput& held, SendKey&& sendKey) {
    held.releaseKeys([&](uint16_t v) { return sendKey(v, false); });
    if (held.anyUnowned()) return false;
    const uint16_t chord[] = {vk::LControl, vk::LShift, vk::Escape};
    size_t down = 0;
    while (down < 3 && sendKey(chord[down], true)) ++down;
    bool ok = down == 3;
    for (size_t i = down; i-- > 0;) {
        if (!sendKey(chord[i], false)) {
            held.oweKey(chord[i]);
            ok = false;
        }
    }
    return ok;
}

// r9 (Pepper's review of 0d74abe, item 1): a viewer that pings on its
// control connection (once a second, from its UI thread: the viewer's
// control_channel.hpp, kLivenessPingMs) and then sends none for more than
// this loses input ownership, and what it holds is let go. Five missed
// pings: a lost segment's TCP retransmission or a short UI stall (a modal
// resize, a GPU hitch) does not end a press, and a UI frozen for longer
// could not let go of anything anyway. From the moment the viewer's UI
// hangs to the ups on Windows: at most 5 s + one check (host_main.cpp,
// kUpRetryMs, 250 ms) + the last ping's one-way time; at least about 4 s
// (the last ping went out up to a second before the hang). A dead network
// is still TCP's (about 13 s).
constexpr int64_t kLivenessTimeoutMs = 5'000;

// r8 (Pepper's review of 6175b5e, items 1 to 4; Morris's PR-C takeover
// rule of 2026-11-22, the newer connection wins): one input owner. Keys,
// buttons and moves go in from one control connection at a time, the
// input owner, and only the owner holds anything. The rules use only what
// the host itself sees, with no new message on the wire:
//
// - A connection becomes the input owner with its first input frame, when
//   it opened after every connection that was the owner before it. The
//   owner until then is replaced at once: its claims end (their ups go to
//   Windows first, before the new owner's frame goes in), and every input
//   frame it sends later is dropped. Nothing about the old owner is
//   checked: the newer connection wins even while the old one is still
//   connected and dragging over MRM1, typing, or just stopped (one
//   viewer's old connection the host has not seen close, or a second
//   viewer on the same address). A replaced viewer that wants to type
//   again reconnects.
// - An input frame from any other connection opened before the newest
//   owner is dropped too: an old connection never takes input back.
// - A connection that never sends input (clipboard, ping) is never the
//   owner and never replaced.
// - Nothing is let go for being still: a key or button stays down for as
//   long as the owner holds it, still or not (r9: an owner that pings
//   keeps pinging while it holds still).
// - The owner's claims end with its own ups, its close, or a newer owner
//   (r9: or its pings stopping, below). TCP closes a dead owner about 13 s
//   after the last thing the host got from it (host_main.cpp,
//   serveControl; a connection whose keep-alive or retransmission limit
//   cannot be set is closed before it can send).
// - An up Windows did not take stays recorded with no owner, and retry(),
//   every 250 ms, sends it again until Windows takes it.
//
// r9 (Pepper's review of 0d74abe, items 1 to 3; no new message on the
// wire either):
// - A hung viewer app (item 1). TCP cannot tell it from a live one: the
//   viewer's OS still answers keep-alive. A viewer that knows this host is
//   Windows sends the existing MRC1 ping (0x01) on its control connection
//   from its UI thread, once a second (kLivenessTimeoutMs, above, says
//   why those numbers), so a hung app stops sending them. Only a ping
//   after the connection's first frame counts (every viewer, old or new,
//   sends one ping as the first frame at startup). The first such ping
//   arms the connection (ping()). An armed owner that goes timeoutMs
//   without a ping loses ownership (expire(), every 250 ms): its claims
//   end (their ups go to Windows), it is silenced, so its frames are
//   dropped and the host closes it at the next one, and a newer connection
//   becomes the owner with its first input as before. A connection with
//   no such ping (an older viewer, or a viewer of the macOS host) is never
//   armed and keeps the r8 rules.
// - MRM1 moves come from the owner only (item 2). A UDP move goes in only
//   from the owner's own MRM1 socket: its address and the port its newest
//   POINTER_SYNC (0x27) named (udpMove()). Until the owner names one, and
//   from a takeover, close or expire on, no UDP move goes in, so a
//   replaced viewer's late datagram never moves the pointer. With no owner
//   no UDP move goes in either (r14: again, below).
// - An up before anything new (item 3). While an up Windows did not take
//   is owed (an entry with no owner), only key and button ups go in, since
//   they can only let go. Every other frame (a down, a move, a wheel, a
//   POINTER_SYNC, Task Manager) and every UDP move is dropped, not kept
//   for later: Windows refuses input while something blocks it (the secure
//   desktop, a UAC prompt, a window of higher integrity), for as long as
//   that lasts, and a down replayed late would land wherever the user is
//   by then. So a new owner's C never goes in while the old owner's Ctrl
//   may still be down: never Ctrl+C.
//
// r10 to r13 (Pepper's reviews of f919167, 5880264, 9f803c6 and 35d72ff;
// no new message on the wire, 0x27 stays the only addition). What stays:
// - An owner silenced for going quiet is closed at once (host_main.cpp:
//   the connection's reader stops when it is silenced), and its slot comes
//   back (r10, item 1).
// - The cursor shape goes to the socket the host takes moves from (bound_,
//   cursorPeer()) and nowhere else, so a datagram from any other socket
//   cannot take the shape from the owner (r10, item 3).
// - A viewer opts into liveness by pinging (r11, item 1). Only a
//   connection's first liveness ping arms it (a valid ping that is not its
//   first frame, heard()). Only a viewer that pings a Windows host sends
//   one: 0.4.x sends a single ping per connection, as its first frame, and
//   is never armed. This viewer sends it before any input on every
//   connection (control_channel.hpp: as it adopts the start-up connection,
//   and twice before a reconnect's first input), so the timer runs from
//   before the first input. H2 development builds go in pairs: a host and
//   a viewer of the same build. An earlier H2 development viewer with this
//   host, or the other way round, is not supported (one with the early
//   8-byte 0x27, 8f8a33b, and one with the 10-byte 0x27 drop each other's
//   POINTER_SYNC as malformed).
// - A connection's first frame FILE_HELLO is a file panel's: refused
//   (heard()).
// - A 0.4.x viewer run with --mouse-move-transport tcp sends its moves as
//   MRC1 0x24 on its control connection (r12); they go in like any other
//   input frame of the owner.
// What went: r10 to r13 also let an owner that never sent a POINTER_SYNC
// (a 0.4.x viewer), and a viewer hovering with no owner, move the pointer
// by UDP from a socket the host took to be theirs, judged by its address,
// by the connections open from that address when the host first heard the
// socket, and (r13) by handovers on the address.
//
// r14 (Pepper's review of 524e4d1; still no new message on the wire): an
// MRM1 datagram carries nothing that ties its socket to a control
// connection. A 0.4.x viewer whose control connection failed (it never got
// a session, or it closed) keeps sending MRM1 from its socket, and another
// viewer that connects from the same address cannot be told apart from
// it: the host could take the first viewer's late datagram as the new
// one's, so the pointer moves and the cursor shape goes to the wrong
// viewer. No rule over addresses, timing or connection counts rules that
// out, so the host takes UDP moves only from a socket an owner named in
// its own POINTER_SYNC (r9's rule):
// - An owner that has sent no POINTER_SYNC (0.4.x) takes no UDP move
//   (Udp::LegacyOff), and with no owner none goes in (Udp::NotOwner).
//   Nothing is bound for them, so no cursor shape is sent.
// - A 0.4.x viewer with this host runs with --mouse-move-transport tcp
//   (README): its moves go by TCP (r12), and it gets no cursor shape.
//   Without the flag its moves do nothing and its clicks go in where the
//   host's pointer is.
// - An r9+ viewer, which names its socket, is not affected.
//
// Admission (with the takeover it may make) and the injection of the frame
// are one step under this object's lock (frame()), and so are close(),
// retry(), expire() and udpMove(): a frame admitted for the old owner is
// in, claim and all, before a takeover can start, so the takeover's
// release covers it, and a frame that comes after the takeover is dropped.
// Lock order: this lock, then host_main.cpp's pointer lock, then
// InputInjector's.
class InputClaims {
public:
    using Owner = HeldInput::Owner;

    // A connection the host accepted. Owners are numbered from 1 in the
    // order the connections opened (host_main.cpp opens one at accept).
    Owner open() {
        std::lock_guard<std::mutex> g(m_);
        const Owner o = next_++;
        framed_[o] = false;
        return o;
    }

    struct Heard {
        bool refuse = false;    // a FILE_HELLO first: no file transfer here; close the connection
        bool liveness = false;  // a liveness ping: valid, and not o's first frame
        bool armed = false;     // its first one: o is armed from now on
        bool silenced = false;  // o lost ownership for going quiet: close it, no pong
    };
    // r11 (Pepper's review of 5880264, item 1): every MRC1 frame
    // serveControl reads on o, in order, before it handles it, at nowMs.
    // The class comment says what o's first frame and its pings make it.
    Heard heard(Owner o, const Mrc1Header& h, int64_t nowMs) {
        std::lock_guard<std::mutex> g(m_);
        Heard r;
        const auto it = framed_.find(o);
        if (it == framed_.end()) return r;
        if (!it->second) {
            // A first-frame ping (every viewer's start-up ping) arms nothing.
            it->second = true;
            r.refuse = h.type == kMsgFileHello;
            return r;
        }
        if (!isValidPing(h)) return r;
        r.liveness = true;
        r.armed = !lastPing_.count(o) && !silenced_.count(o);
        r.silenced = pingLocked(o, nowMs);
        return r;
    }

    struct Frame {
        bool admitted = false;  // false: o is not the owner and cannot become it; nothing went in
        bool tookOver = false;  // o became the owner with this frame
        size_t replaced = 0;    // 1 when it took over from an owner still open
        size_t released = 0;    // ups Windows took then
        bool blocked = false;   // r9: o is the owner, but an up is still owed: dropped (only ups go in)
        bool silenced = false;  // r9: o lost ownership for going quiet (expire()): close it
        bool injected = false;  // what inject returned
    };
    // One input frame e from o, whose peer address is ip. When o is the
    // owner, or becomes it now, and the frame may go in, inject(HeldInput&)
    // puts it in, still under the lock; otherwise inject is not called.
    template <class Inject, class UpKey, class UpButton>
    Frame frame(Owner o, uint32_t ip, const InputEvent& e, Inject&& inject, UpKey&& upKey, UpButton&& upButton) {
        std::lock_guard<std::mutex> g(m_);
        Frame r;
        if (silenced_.count(o)) {
            r.silenced = true;
            return r;
        }
        if (o != owner_) {
            if (o <= newest_) return r;  // replaced, or older than the newest owner
            if (owner_) {
                r.replaced = 1;
                r.released = held_.releaseOwned(owner_, upKey, upButton);
            }
            owner_ = newest_ = o;
            newOwnershipLocked();
            r.tookOver = true;
        }
        r.admitted = true;
        // r9: the owner's MRM1 socket, from its own POINTER_SYNC (port 0:
        // that position went by TCP; nothing to name). r14: an owner that
        // never sent one takes no UDP move.
        if (e.kind == InputEvent::Kind::PointerSync) {
            ownerSynced_ = true;
            if (e.port) bindLocked(Endpoint{true, ip, e.port});
        }
        if (held_.anyUnowned() && !isUp(e)) {
            r.blocked = true;
            return r;
        }
        r.injected = inject(held_);
        return r;
    }
    // Connection o closed: its claims end (HeldInput::releaseOwned, which
    // also tries again any up Windows did not take). Returns how many ups
    // Windows took.
    template <class UpKey, class UpButton>
    size_t close(Owner o, UpKey&& upKey, UpButton&& upButton) {
        std::lock_guard<std::mutex> g(m_);
        if (owner_ == o) {
            owner_ = 0;
            newOwnershipLocked();
        }
        lastPing_.erase(o);
        silenced_.erase(o);
        framed_.erase(o);
        return held_.releaseOwned(o, upKey, upButton);
    }
    // Ups Windows did not take, tried again (HeldInput::retryUnowned).
    // Returns how many Windows took.
    template <class UpKey, class UpButton>
    size_t retry(UpKey&& upKey, UpButton&& upButton) {
        std::lock_guard<std::mutex> g(m_);
        return held_.retryUnowned(upKey, upButton);
    }

    // r9: a liveness ping from o at nowMs (one that was not o's first
    // frame; r11: heard() tells). Returns true when o was silenced: the host
    // closes it.
    bool ping(Owner o, int64_t nowMs) {
        std::lock_guard<std::mutex> g(m_);
        return pingLocked(o, nowMs);
    }
    // r11: o has sent a liveness ping (it is armed). r10's arm() at the
    // VIDEO_CONFIG is gone (the class comment says why).
    bool armed(Owner o) const {
        std::lock_guard<std::mutex> g(m_);
        return lastPing_.count(o) != 0;
    }
    // r10: o lost ownership for going quiet; its reader closes it.
    bool silenced(Owner o) const {
        std::lock_guard<std::mutex> g(m_);
        return silenced_.count(o) != 0;
    }
    struct Expired {
        Owner owner = 0;       // the owner that went quiet; 0: none did
        int64_t silentMs = 0;  // since its last ping
        size_t released = 0;   // ups Windows took
    };
    // r9: the owner, if armed (it has pinged) and quiet for more than
    // timeoutMs at nowMs, loses ownership: its claims end, it is silenced,
    // and no connection is the owner until a newer one sends input
    // (newest_ stays, so no older connection takes input back).
    template <class UpKey, class UpButton>
    Expired expire(int64_t nowMs, int64_t timeoutMs, UpKey&& upKey, UpButton&& upButton) {
        std::lock_guard<std::mutex> g(m_);
        Expired x;
        if (!owner_) return x;
        const auto it = lastPing_.find(owner_);
        if (it == lastPing_.end() || nowMs - it->second <= timeoutMs) return x;
        x.owner = owner_;
        x.silentMs = nowMs - it->second;
        silenced_.insert(owner_);
        x.released = held_.releaseOwned(owner_, upKey, upButton);
        owner_ = 0;
        newOwnershipLocked();
        return x;
    }

    // r9: what became of an MRM1 pointer move from (ip, port).
    enum class Udp {
        Moved,      // move() went in
        Stale,      // move() returned false (an older seq)
        NotOwner,   // no owner, or not the socket the owner named: dropped
        UpPending,  // an up is still owed: dropped
        LegacyOff,  // r14: the owner named no socket (0.4.x without --mouse-move-transport tcp): dropped
    };
    // r9: an MRM1 pointer move from (ip, port). move() (the host takes its
    // pointer lock in it) runs only for the socket the owner named in its
    // own POINTER_SYNC (r14: no other; the class comment says why) and only
    // while no up is owed, under this lock.
    template <class Move>
    Udp udpMove(uint32_t ip, uint16_t port, Move&& move) {
        std::lock_guard<std::mutex> g(m_);
        if (!owner_) return Udp::NotOwner;
        if (!ownerSynced_) return Udp::LegacyOff;
        if (!bound_.is(ip, port)) return Udp::NotOwner;
        if (held_.anyUnowned()) return Udp::UpPending;
        return move() ? Udp::Moved : Udp::Stale;
    }
    // r10 (Pepper's review of f919167, item 3): where the cursor shape goes,
    // the socket the host takes moves from now (none: nowhere). gen moves
    // on whenever that changes, so the shape goes out at once to a new one.
    struct CursorPeer {
        bool named = false;
        uint32_t ip = 0;
        uint16_t port = 0;
        uint64_t gen = 0;
    };
    CursorPeer cursorPeer() const {
        std::lock_guard<std::mutex> g(m_);
        return CursorPeer{bound_.named, bound_.ip, bound_.port, boundGen_};
    }

    // The input owner; 0 when there is none.
    Owner owner() const {
        std::lock_guard<std::mutex> g(m_);
        return owner_;
    }
    bool anyHeld() const {
        std::lock_guard<std::mutex> g(m_);
        return held_.anyHeld();
    }
    // A copy of what is held now, for logs and tests.
    HeldInput held() const {
        std::lock_guard<std::mutex> g(m_);
        return held_;
    }

private:
    static bool isUp(const InputEvent& e) {
        return (e.kind == InputEvent::Kind::Key || e.kind == InputEvent::Kind::Button) && !e.down;
    }
    struct Endpoint {
        bool named = false;
        uint32_t ip = 0;
        uint16_t port = 0;
        bool is(uint32_t i, uint16_t p) const { return named && ip == i && port == p; }
    };
    void bindLocked(const Endpoint& e) {
        if (e.named == bound_.named && e.ip == bound_.ip && e.port == bound_.port) return;
        bound_ = e;
        ++boundGen_;
    }
    // Ownership changed (a takeover, the owner's close, expiry): no socket
    // is bound until the new owner names one.
    void newOwnershipLocked() {
        ownerSynced_ = false;
        bindLocked(Endpoint{});
    }
    bool pingLocked(Owner o, int64_t nowMs) {
        if (silenced_.count(o)) return true;
        lastPing_[o] = nowMs;
        return false;
    }

    mutable std::mutex m_;
    Owner next_ = 1;
    Owner owner_ = 0;   // the input owner, 0 none
    Owner newest_ = 0;  // the newest connection that has been the owner
    bool ownerSynced_ = false;  // r10: the owner sent a POINTER_SYNC (a viewer of r9 or later)
    // r9: the owner's MRM1 socket, once its POINTER_SYNC named it; the
    // cursor shape goes there (r10).
    Endpoint bound_;
    uint64_t boundGen_ = 0;
    std::map<Owner, bool> framed_;       // r11: open connections, and whether their first frame came
    std::map<Owner, int64_t> lastPing_;  // r9: armed connections, and their last liveness ping
    std::set<Owner> silenced_;           // r9: owners that went quiet and are not closed yet
    HeldInput held_;
};

// The captured monitor in virtual-desktop pixels.
struct DesktopRect {
    int left = 0, top = 0, width = 0, height = 0;
};

// Viewer pointer position (MRC1 / MRM1 0x24: 0 = first pixel, 65535 = last
// pixel of the picture it shows) -> a pixel on the captured monitor.
inline void normToDesktop(int nx, int ny, const DesktopRect& r, int& px, int& py) {
    nx = std::clamp(nx, 0, 65535);
    ny = std::clamp(ny, 0, 65535);
    px = r.left + int((int64_t(nx) * std::max(0, r.width - 1) + 32767) / 65535);
    py = r.top + int((int64_t(ny) * std::max(0, r.height - 1) + 32767) / 65535);
}

// A virtual-desktop pixel -> SendInput MOUSEEVENTF_ABSOLUTE|VIRTUALDESK
// units. Windows lands on floor(a * size / 65536), so the smallest a with
// that floor equal to the pixel hits it exactly.
inline int toAbsolute(int pixel, int origin, int size) {
    if (size <= 0) return 0;
    const int64_t off = std::clamp<int64_t>(int64_t(pixel) - origin, 0, size - 1);
    return int(std::min<int64_t>(65535, (off * 65536 + size - 1) / size));
}

// ---------------------------------------------------------------- MRM1 UDP

constexpr uint8_t kMrm1Pointer = 0x24, kMrm1Cursor = 0x31;
constexpr uint8_t kMrm1KeyframeRequest = 0x40, kMrm1Ping = 0x43, kMrm1Pong = 0x44;

struct Mrm1Packet {
    uint8_t type = 0;
    uint32_t seq = 0;
    uint16_t nx = 0, ny = 0;  // 0x24 only
};
// Only the types this host handles, each at its exact length: 0x24 pointer
// (14), 0x40 keyframe request (10), 0x43 ping (18). Anything else (NACK,
// receiver report, audio, junk) is dropped before it can touch host state.
inline std::optional<Mrm1Packet> parseMrm1(const uint8_t* p, size_t n) {
    if (n < 10 || p[0] != 'M' || p[1] != 'R' || p[2] != 'M' || p[3] != '1' || p[4] != 1) return std::nullopt;
    Mrm1Packet m;
    m.type = p[5];
    m.seq = (uint32_t(p[6]) << 24) | (uint32_t(p[7]) << 16) | (uint32_t(p[8]) << 8) | p[9];
    if (m.type == kMrm1KeyframeRequest) return n == 10 ? std::optional<Mrm1Packet>(m) : std::nullopt;
    if (m.type == kMrm1Ping) return n == 18 ? std::optional<Mrm1Packet>(m) : std::nullopt;
    if (m.type == kMrm1Pointer) {
        if (n != 14) return std::nullopt;
        m.nx = uint16_t((uint16_t(p[10]) << 8) | p[11]);
        m.ny = uint16_t((uint16_t(p[12]) << 8) | p[13]);
        return m;
    }
    return std::nullopt;
}

// MRM1 sessions, as on the macOS host: a viewer port not seen before starts
// a new session (pointer order and cursor state start over). Within one, a
// pointer move is taken only when its seq is newer than the newest taken,
// so a late datagram never moves the pointer back. H2 (Pepper's H2 review,
// item 5): a POINTER_SYNC on the control connection counts as taking its
// seq (syncPointer), so a move the viewer sent before a click and that
// arrives after it is dropped too. The host calls all of these under one
// lock.
//
// A seq belongs to one viewer UDP socket (ip, port), and each new socket
// starts its seq over (Pepper's review of 8f8a33b, item 5a). A sync for a
// socket the host has not heard from yet (the click overtook that socket's
// first datagram) marks that socket, so its first datagram and any other
// move up to seq is dropped too.
//
// Each socket keeps its own order (Pepper's review of f97ad11, item 3).
// The current socket (where the cursor shape goes) is the one the newest
// datagram came from, so a late datagram from an older socket A makes A
// current again, and then the next datagram from the newer socket B makes
// B current. Neither switch touches either socket's order: B's mark and
// newest seq are still there when B comes back, so a move B sent before
// the click stays dropped. A socket not heard from (no datagram, no sync)
// for kIdleMs starts over: the viewer sends a keep-alive every second
// while it runs, so that is a new socket that got the same port.
class Mrm1Session {
public:
    static constexpr int64_t kIdleMs = 10'000;
    // At most this many sockets are kept; the one heard from least recently
    // (never the current one) makes room.
    static constexpr size_t kMaxSockets = 8;

    // A datagram from (ip, port) at nowMs (the host's clock). True when it
    // is not from the current socket: a new socket, or one heard before.
    bool note(uint32_t ip, uint16_t port, int64_t nowMs) {
        touch(ip, port, nowMs);
        const bool same = have_ && ip == ip_ && port == port_;
        have_ = true;
        ip_ = ip;
        port_ = port;
        return !same;
    }
    // A pointer move from the current socket (the one note() was given).
    bool takePointer(uint32_t seq) {
        Socket* s = have_ ? find(ip_, port_) : nullptr;
        if (!s) return false;
        if (s->havePointer && int32_t(seq - s->pointerSeq) <= 0) return false;
        s->havePointer = true;
        s->pointerSeq = seq;
        return true;
    }
    // Moves up to seq from (ip, port) are stale from now on (never moves a
    // mark back). Port 0 marks nothing.
    void syncPointer(uint32_t ip, uint16_t port, uint32_t seq, int64_t nowMs) {
        if (port == 0) return;
        Socket& s = touch(ip, port, nowMs);
        if (s.havePointer && int32_t(seq - s.pointerSeq) <= 0) return;
        s.havePointer = true;
        s.pointerSeq = seq;
    }
    size_t socketsKept() const { return sockets_.size(); }

private:
    struct Socket {
        uint32_t ip = 0;
        uint16_t port = 0;
        int64_t lastMs = 0;
        bool havePointer = false;
        uint32_t pointerSeq = 0;
    };
    Socket* find(uint32_t ip, uint16_t port) {
        for (auto& s : sockets_)
            if (s.ip == ip && s.port == port) return &s;
        return nullptr;
    }
    Socket& touch(uint32_t ip, uint16_t port, int64_t nowMs) {
        if (Socket* s = find(ip, port)) {
            if (nowMs - s->lastMs > kIdleMs) *s = Socket{ip, port};
            s->lastMs = nowMs;
            return *s;
        }
        if (sockets_.size() >= kMaxSockets) {
            auto victim = sockets_.end();
            for (auto it = sockets_.begin(); it != sockets_.end(); ++it) {
                if (have_ && it->ip == ip_ && it->port == port_) continue;
                if (victim == sockets_.end() || it->lastMs < victim->lastMs) victim = it;
            }
            sockets_.erase(victim);
        }
        sockets_.push_back(Socket{ip, port, nowMs});
        return sockets_.back();
    }
    bool have_ = false;  // a current socket
    uint32_t ip_ = 0;
    uint16_t port_ = 0;
    std::vector<Socket> sockets_;
};

// Cursor shape codes the viewer maps to a local cursor (viewer.cpp
// cursorForRemoteShape); 0-11 as the macOS host, 12-14 added for Windows
// (an older viewer shows the arrow for them).
enum class CursorShape : uint8_t {
    Arrow = 0, IBeam = 1, PointingHand = 2, ResizeLeftRight = 3, ResizeUpDown = 4, ResizeNwse = 5,
    ResizeNesw = 6, Crosshair = 7, OpenHand = 8, ClosedHand = 9, NotAllowed = 10, VerticalIBeam = 11,
    Wait = 12, AppStarting = 13, Move = 14,
};

// MRM1 0x31 cursor state, host -> viewer: header + shape, 11 bytes.
inline std::vector<uint8_t> mrm1Cursor(uint32_t seq, CursorShape shape) {
    return {'M', 'R', 'M', '1', 1, kMrm1Cursor, uint8_t(seq >> 24), uint8_t(seq >> 16), uint8_t(seq >> 8),
            uint8_t(seq), uint8_t(shape)};
}
// The same 18 bytes back with the type set to 0x44.
inline std::vector<uint8_t> mrm1Pong(const uint8_t* ping, size_t n) {
    std::vector<uint8_t> r(ping, ping + n);
    r[5] = kMrm1Pong;
    return r;
}

// ------------------------------------------------------------ Annex B helpers

// NAL unit types in an Annex B buffer, in order.
inline std::vector<int> annexBNalTypes(const uint8_t* p, size_t n) {
    std::vector<int> t;
    for (size_t i = 0; i + 3 < n; ++i) {
        if (p[i] == 0 && p[i + 1] == 0 && (p[i + 2] == 1 || (p[i + 2] == 0 && i + 3 < n && p[i + 3] == 1))) {
            const size_t start = i + (p[i + 2] == 1 ? 3 : 4);
            if (start < n) t.push_back(p[start] & 0x1F);
            i = start;
        }
    }
    return t;
}

// A keyframe from the encoder must carry SPS and PPS in band: the viewer
// starts decoding from it. Prepends `header` (Annex B SPS+PPS) when the
// unit has an IDR but no SPS.
inline void ensureParameterSets(std::vector<uint8_t>& au, const std::vector<uint8_t>& header) {
    const auto types = annexBNalTypes(au.data(), au.size());
    const bool idr = std::find(types.begin(), types.end(), 5) != types.end();
    const bool sps = std::find(types.begin(), types.end(), 7) != types.end();
    if (idr && !sps && !header.empty()) au.insert(au.begin(), header.begin(), header.end());
}

}  // namespace jlh
