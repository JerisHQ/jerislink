#pragma once

// File transfer wire (MRC1 types 0x50-0x5C), design r2 section 4. The Mac
// side is FileProtocol.swift; both must encode the same bytes.
//
// The viewer opens a dedicated TCP connection to the control port and sends
// FILE_HELLO first; that connection then carries only these types. Integers
// are big-endian. Decoding is strict: a payload whose length does not match
// its type is rejected, and the session closes.
//
// F1 ships every type so later PRs add behaviour, never wire. No Win32 here,
// so the codec builds in a plain console test.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace jl::file {

inline constexpr uint8_t kVersion = 1;

namespace type {
inline constexpr uint8_t kHello = 0x50;
inline constexpr uint8_t kHelloAck = 0x51;
inline constexpr uint8_t kOffer = 0x52;
inline constexpr uint8_t kEntry = 0x53;
inline constexpr uint8_t kReply = 0x54;     // ACCEPT (status ok) / REJECT
inline constexpr uint8_t kData = 0x55;
inline constexpr uint8_t kFileEnd = 0x56;
inline constexpr uint8_t kResult = 0x57;
inline constexpr uint8_t kCancel = 0x58;
inline constexpr uint8_t kRequest = 0x59;
inline constexpr uint8_t kProgress = 0x5A;
inline constexpr uint8_t kPing = 0x5B;
inline constexpr uint8_t kReveal = 0x5C;
}  // namespace type

namespace purpose {
inline constexpr uint8_t kPaste = 1;     // Win->Mac paste, Mac->Win paste pull
inline constexpr uint8_t kSend = 2;      // Windows Send to, drop on the viewer
inline constexpr uint8_t kAnnounce = 3;  // Finder Cmd+C manifest, no data
inline constexpr uint8_t kPush = 4;      // Finder "Send to JerisLink"
inline constexpr bool known(uint8_t p) { return p >= 1 && p <= 4; }
}  // namespace purpose

// Capability bits in HELLO / HELLO_ACK. A side advertises only what it
// already implements; bits 8-15 are reserved and must be ignored.
namespace caps {
inline constexpr uint16_t kUpload = 1u << 0;       // F2: host receives paste/send uploads
inline constexpr uint16_t kPushService = 1u << 1;  // F5b: Finder Send to JerisLink
inline constexpr uint16_t kReveal = 1u << 2;       // F4: 0x5C opens the received folder
inline constexpr uint16_t kAnnounce = 1u << 3;     // F3: Cmd+C manifests, serves REQUEST
inline constexpr uint16_t kViewer = 0;             // what this viewer build implements (F1: none)
}  // namespace caps

namespace status {
inline constexpr uint8_t kOk = 0;
inline constexpr uint8_t kTooBig = 1;
inline constexpr uint8_t kNoSpace = 2;
inline constexpr uint8_t kBusy = 3;
inline constexpr uint8_t kDenied = 4;
inline constexpr uint8_t kBadPath = 5;
inline constexpr uint8_t kFailed = 6;
inline constexpr uint8_t kCancelled = 7;
// F3 r2: macOS privacy settings (TCC Files & Folders) blocked the host's read,
// or a prompt asking for it is still open on the Mac. Additive.
inline constexpr uint8_t kMacPermission = 8;
}  // namespace status

namespace kind {
inline constexpr uint8_t kFile = 0;
inline constexpr uint8_t kDir = 1;
}  // namespace kind

inline constexpr uint16_t kMaxChunk = 32 * 1024;
inline constexpr uint64_t kMaxTotalBytes = 20ull * 1024 * 1024 * 1024;
inline constexpr uint32_t kMaxEntries = 10000;
inline constexpr size_t kMaxPathBytes = 1024;
inline constexpr size_t kMaxPayload = 16 + kMaxChunk;  // DATA header + one chunk

struct Hello { uint8_t proto; uint16_t caps; bool operator==(const Hello&) const = default; };
struct HelloAck { uint8_t proto; uint16_t caps; uint16_t maxChunk; uint64_t maxTotal; bool operator==(const HelloAck&) const = default; };
struct Offer { uint32_t transfer; uint8_t purpose; uint32_t entries; uint64_t total; bool operator==(const Offer&) const = default; };
struct Entry { uint32_t transfer; uint32_t index; uint8_t kind; uint64_t size; int64_t mtime; std::vector<uint8_t> path; bool operator==(const Entry&) const = default; };
struct Reply { uint32_t transfer; uint8_t status; bool operator==(const Reply&) const = default; };
struct Data { uint32_t transfer; uint32_t index; uint64_t offset; std::vector<uint8_t> bytes; bool operator==(const Data&) const = default; };
struct FileEnd { uint32_t transfer; uint32_t index; std::vector<uint8_t> sha256; bool operator==(const FileEnd&) const = default; };
struct Result { uint32_t transfer; uint8_t status; uint32_t filesOk; bool operator==(const Result&) const = default; };
struct Cancel { uint32_t transfer; uint8_t reason; bool operator==(const Cancel&) const = default; };
struct Request { uint32_t transfer; uint32_t index; uint64_t offset; uint32_t length; bool operator==(const Request&) const = default; };
struct Progress { uint32_t transfer; uint64_t committed; bool operator==(const Progress&) const = default; };
struct Ping { std::vector<uint8_t> token; bool operator==(const Ping&) const = default; };
struct Reveal { uint32_t transfer; bool operator==(const Reveal&) const = default; };

using Message = std::variant<Hello, HelloAck, Offer, Entry, Reply, Data, FileEnd, Result, Cancel, Request, Progress, Ping, Reveal>;

// Wire type of a message: 0x50 + variant index (the order above is the wire order).
inline uint8_t typeOf(const Message& m) { return static_cast<uint8_t>(type::kHello + m.index()); }

namespace detail {
struct Writer {
    std::vector<uint8_t> out;
    void u8(uint8_t v) { out.push_back(v); }
    void u16(uint16_t v) { out.push_back(uint8_t(v >> 8)); out.push_back(uint8_t(v)); }
    void u32(uint32_t v) { for (int s = 24; s >= 0; s -= 8) out.push_back(uint8_t(v >> s)); }
    void u64(uint64_t v) { for (int s = 56; s >= 0; s -= 8) out.push_back(uint8_t(v >> s)); }
    void bytes(const std::vector<uint8_t>& b) { out.insert(out.end(), b.begin(), b.end()); }
};
// Callers check the payload length first; reads never run past it.
struct Reader {
    const std::vector<uint8_t>& p;
    size_t i = 0;
    uint8_t u8() { return p[i++]; }
    uint16_t u16() { uint16_t v = u8(); return uint16_t((v << 8) | u8()); }
    uint32_t u32() { uint32_t v = 0; for (int k = 0; k < 4; ++k) v = (v << 8) | u8(); return v; }
    uint64_t u64() { uint64_t v = 0; for (int k = 0; k < 8; ++k) v = (v << 8) | u8(); return v; }
    std::vector<uint8_t> rest() { std::vector<uint8_t> r(p.begin() + static_cast<std::ptrdiff_t>(i), p.end()); i = p.size(); return r; }
};
}  // namespace detail

// Payload bytes, or nullopt when a field is over its limit.
inline std::optional<std::vector<uint8_t>> encode(const Message& m) {
    detail::Writer w;
    bool ok = true;
    std::visit([&](const auto& v) {
        using T = std::decay_t<decltype(v)>;
        if constexpr (std::is_same_v<T, Hello>) { w.u8(v.proto); w.u16(v.caps); }
        else if constexpr (std::is_same_v<T, HelloAck>) { w.u8(v.proto); w.u16(v.caps); w.u16(v.maxChunk); w.u64(v.maxTotal); }
        else if constexpr (std::is_same_v<T, Offer>) { w.u32(v.transfer); w.u8(v.purpose); w.u32(v.entries); w.u64(v.total); }
        else if constexpr (std::is_same_v<T, Entry>) {
            if (v.path.empty() || v.path.size() > kMaxPathBytes) { ok = false; return; }
            w.u32(v.transfer); w.u32(v.index); w.u8(v.kind); w.u64(v.size); w.u64(static_cast<uint64_t>(v.mtime)); w.bytes(v.path);
        }
        else if constexpr (std::is_same_v<T, Reply>) { w.u32(v.transfer); w.u8(v.status); }
        else if constexpr (std::is_same_v<T, Data>) {
            if (v.bytes.size() > kMaxChunk) { ok = false; return; }
            w.u32(v.transfer); w.u32(v.index); w.u64(v.offset); w.bytes(v.bytes);
        }
        else if constexpr (std::is_same_v<T, FileEnd>) {
            if (v.sha256.size() != 32) { ok = false; return; }
            w.u32(v.transfer); w.u32(v.index); w.bytes(v.sha256);
        }
        else if constexpr (std::is_same_v<T, Result>) { w.u32(v.transfer); w.u8(v.status); w.u32(v.filesOk); }
        else if constexpr (std::is_same_v<T, Cancel>) { w.u32(v.transfer); w.u8(v.reason); }
        else if constexpr (std::is_same_v<T, Request>) { w.u32(v.transfer); w.u32(v.index); w.u64(v.offset); w.u32(v.length); }
        else if constexpr (std::is_same_v<T, Progress>) { w.u32(v.transfer); w.u64(v.committed); }
        else if constexpr (std::is_same_v<T, Ping>) {
            if (v.token.size() != 4) { ok = false; return; }
            w.bytes(v.token);
        }
        else if constexpr (std::is_same_v<T, Reveal>) { w.u32(v.transfer); }
    }, m);
    if (!ok) return std::nullopt;
    return std::move(w.out);
}

// Strict decode: exact lengths for fixed-size messages, bounded variable
// parts, known purpose and kind values. nullopt for anything else.
inline std::optional<Message> decode(uint8_t t, const std::vector<uint8_t>& p) {
    detail::Reader r{p};
    const size_t n = p.size();
    switch (t) {
    case type::kHello: {
        if (n != 3) return std::nullopt;
        Hello h; h.proto = r.u8(); h.caps = r.u16(); return h;
    }
    case type::kHelloAck: {
        if (n != 13) return std::nullopt;
        HelloAck a; a.proto = r.u8(); a.caps = r.u16(); a.maxChunk = r.u16(); a.maxTotal = r.u64(); return a;
    }
    case type::kOffer: {
        if (n != 17) return std::nullopt;
        Offer o; o.transfer = r.u32(); o.purpose = r.u8(); o.entries = r.u32(); o.total = r.u64();
        if (!purpose::known(o.purpose)) return std::nullopt;
        return o;
    }
    case type::kEntry: {
        if (n <= 25 || n - 25 > kMaxPathBytes) return std::nullopt;
        Entry e; e.transfer = r.u32(); e.index = r.u32(); e.kind = r.u8(); e.size = r.u64();
        e.mtime = static_cast<int64_t>(r.u64()); e.path = r.rest();
        if (e.kind != kind::kFile && e.kind != kind::kDir) return std::nullopt;
        return e;
    }
    case type::kReply: {
        if (n != 5) return std::nullopt;
        Reply x; x.transfer = r.u32(); x.status = r.u8(); return x;
    }
    case type::kData: {
        if (n < 16 || n - 16 > kMaxChunk) return std::nullopt;
        Data d; d.transfer = r.u32(); d.index = r.u32(); d.offset = r.u64(); d.bytes = r.rest(); return d;
    }
    case type::kFileEnd: {
        if (n != 40) return std::nullopt;
        FileEnd f; f.transfer = r.u32(); f.index = r.u32(); f.sha256 = r.rest(); return f;
    }
    case type::kResult: {
        if (n != 9) return std::nullopt;
        Result x; x.transfer = r.u32(); x.status = r.u8(); x.filesOk = r.u32(); return x;
    }
    case type::kCancel: {
        if (n != 5) return std::nullopt;
        Cancel c; c.transfer = r.u32(); c.reason = r.u8(); return c;
    }
    case type::kRequest: {
        if (n != 20) return std::nullopt;
        Request q; q.transfer = r.u32(); q.index = r.u32(); q.offset = r.u64(); q.length = r.u32(); return q;
    }
    case type::kProgress: {
        if (n != 12) return std::nullopt;
        Progress g; g.transfer = r.u32(); g.committed = r.u64(); return g;
    }
    case type::kPing: {
        if (n != 4) return std::nullopt;
        return Ping{p};
    }
    case type::kReveal: {
        if (n != 4) return std::nullopt;
        Reveal v; v.transfer = r.u32(); return v;
    }
    default:
        return std::nullopt;
    }
}

}  // namespace jl::file
