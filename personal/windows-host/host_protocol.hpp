// JerisLink Windows host, H1: wire formats shared with the viewer.
//
// Platform-free so the unit tests run the same code the host sends with.
// Matches the macOS host: MR02 video packets (UDPFrameSender.makePacket),
// MRC1 control frames (ControlServer), the 0x41 VIDEO_CONFIG ACK
// (VideoSettingsAck) and the MRM1 0x43/0x44 ping echo (MouseMoveUDPServer).
#pragma once

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
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
struct VideoConfigDecision {
    std::vector<uint8_t> ack;  // the 10-byte 0x41 payload
    bool accepted = false;
    int bitrateMbps = 25;
    bool bitrateChanged = false;
};
inline VideoConfigDecision decideVideoConfig(const uint8_t* p, size_t n, int currentBitrateMbps, int width,
                                             int height) {
    VideoConfigDecision d;
    auto ack = [&](uint8_t status, uint8_t flags, int bitrate, int w, int h) {
        d.ack = {1, status, 1, flags, uint8_t(bitrate >> 8), uint8_t(bitrate), uint8_t(w >> 8), uint8_t(w),
                 uint8_t(h >> 8), uint8_t(h)};
    };
    d.bitrateMbps = currentBitrateMbps;
    const bool shapeOk = n == 6 && p[0] == 1;
    const uint8_t codec = shapeOk ? p[1] : 0;
    const uint8_t caps = shapeOk ? p[2] : 0;
    const int bitrate = shapeOk ? int((uint16_t(p[4]) << 8) | p[5]) : 0;
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

// ---------------------------------------------------------------- MRM1 UDP

constexpr uint8_t kMrm1KeyframeRequest = 0x40, kMrm1Ping = 0x43, kMrm1Pong = 0x44;

struct Mrm1Packet {
    uint8_t type = 0;
    uint32_t seq = 0;
};
// Only the two types H1 handles, each at its exact length. Anything else
// (pointer, NACK, receiver report, audio, junk) is dropped before it can
// touch host state.
inline std::optional<Mrm1Packet> parseMrm1(const uint8_t* p, size_t n) {
    if (n < 10 || p[0] != 'M' || p[1] != 'R' || p[2] != 'M' || p[3] != '1' || p[4] != 1) return std::nullopt;
    Mrm1Packet m;
    m.type = p[5];
    m.seq = (uint32_t(p[6]) << 24) | (uint32_t(p[7]) << 16) | (uint32_t(p[8]) << 8) | p[9];
    if (m.type == kMrm1KeyframeRequest) return n == 10 ? std::optional<Mrm1Packet>(m) : std::nullopt;
    if (m.type == kMrm1Ping) return n == 18 ? std::optional<Mrm1Packet>(m) : std::nullopt;
    return std::nullopt;
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
