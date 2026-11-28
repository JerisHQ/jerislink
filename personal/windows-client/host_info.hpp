#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

// MRC1 0x06 HOST_INFO (design D10, Windows host H2): what kind of host this
// is. Pure, so the host's unit test decodes what the host encodes
// (windows-host/host_protocol.hpp hostInfoPayload).
//
// A Windows host sends it right behind a 0x41 VIDEO_CONFIG ACK, only when
// the VIDEO_CONFIG said this viewer reads it (caps kViewerCapHostInfo), and
// says so in the ACK (an 11th byte, kAckExtHostInfo): the viewer reads it
// there and then (control_channel.hpp exchangeVideoConfig). The macOS host
// never sends it: no HOST_INFO means a Mac, and everything stays as it was.
//   [0] format (1 so far)   [1] platform (1 macOS, 2 Windows)
//   [2..5] capability bits, big-endian   [6] monitors   [7] version length n
//   [8..8+n) version, ASCII
// Later formats append fields; this reads the ones it knows.
namespace jl::hostinfo {

inline constexpr uint8_t kType = 0x06;
inline constexpr size_t kHeaderBytes = 8;   // MRC1 header
inline constexpr size_t kMinPayload = 8;
inline constexpr size_t kMaxPayload = 512;  // larger is not HOST_INFO: left alone
inline constexpr size_t kMaxFrameBytes = kHeaderBytes + kMaxPayload;

inline constexpr uint8_t kPlatformMac = 1, kPlatformWindows = 2;
inline constexpr uint32_t kCapKeyboard = 0x01, kCapPointer = 0x02, kCapCursorShape = 0x04, kCapTaskManager = 0x08;
// The host takes MRC1 0x27 POINTER_SYNC in front of a button frame:
// [nx BE16, ny BE16, MRM1 seq BE32, MRM1 UDP source port BE16].
inline constexpr uint32_t kCapPointerSync = 0x20;
inline constexpr uint16_t kPointerSyncBytes = 10;
// VIDEO_CONFIG caps bit: "this viewer reads HOST_INFO". ACK payload [10]
// bit kAckExtHostInfo: one HOST_INFO frame follows the ACK.
inline constexpr uint8_t kViewerCapHostInfo = 0x08;
inline constexpr uint8_t kAckExtHostInfo = 0x01;

struct Info {
    uint8_t format = 0;
    uint8_t platform = 0;
    uint32_t caps = 0;
    uint8_t monitors = 0;
    std::string version;  // printable ASCII; anything else became '?'
    bool windows() const { return platform == kPlatformWindows; }
};

inline std::optional<Info> decode(const uint8_t* p, size_t n) {
    if (n < kMinPayload || n > kMaxPayload || p[0] < 1) return std::nullopt;
    const size_t vlen = p[7];
    if (kMinPayload + vlen > n) return std::nullopt;
    Info i;
    i.format = p[0];
    i.platform = p[1];
    i.caps = (uint32_t(p[2]) << 24) | (uint32_t(p[3]) << 16) | (uint32_t(p[4]) << 8) | p[5];
    i.monitors = p[6];
    for (size_t k = 0; k < vlen; ++k) {
        const uint8_t c = p[kMinPayload + k];
        i.version.push_back(c >= 0x20 && c < 0x7F ? char(c) : '?');
    }
    return i;
}

// Buttons carry POINTER_SYNC only to a Windows host that said it takes it.
inline bool pointerSyncFor(const std::optional<Info>& i) {
    return i && i->windows() && (i->caps & kCapPointerSync) != 0;
}

// H2 r9 (Pepper's review of 0d74abe, item 1): a Windows host gets the
// liveness pings (control_channel.hpp livenessTick): the existing MRC1 ping,
// no cap bit. One that does not time out only answers them. A macOS host
// gets none, so its control connection carries what it did before.
inline bool livenessFor(const std::optional<Info>& i) { return i && i->windows(); }

// The first n bytes waiting on the socket could be a HOST_INFO frame: the
// header so far matches MRC1 v1 type 0x06 and, once the length is there, it
// is one HOST_INFO can have.
inline bool isFramePrefix(const uint8_t* b, size_t n) {
    static const uint8_t want[6] = {'M', 'R', 'C', '1', 1, kType};
    if (n == 0) return false;
    for (size_t i = 0; i < n && i < 6; ++i)
        if (b[i] != want[i]) return false;
    if (n < kHeaderBytes) return true;
    const size_t len = (size_t(b[6]) << 8) | b[7];
    return len >= kMinPayload && len <= kMaxPayload;
}

// Bytes of the whole frame when all of it is in b[0..n); 0 otherwise.
inline size_t completeFrameBytes(const uint8_t* b, size_t n) {
    if (n < kHeaderBytes || !isFramePrefix(b, n)) return 0;
    const size_t total = kHeaderBytes + ((size_t(b[6]) << 8) | b[7]);
    return n >= total ? total : 0;
}

}  // namespace jl::hostinfo
