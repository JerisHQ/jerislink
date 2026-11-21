#pragma once
// UDP tags, viewer side (design v0.4.0 §5.1, PR-C).
//
// With a connection password, every UDP datagram in both directions (MRM1
// input and feedback, MR02 video, MRA1 audio, pongs, cursor shapes) ends
// with an 8-byte tag:
//
//     K_s = HMAC-SHA256(K, "jl-udp" | host_nonce | client_nonce | session_id)
//     tag = HMAC-SHA256(K_s, "v2h" or "h2v" | datagram without the tag)[0..8]
//
// K_s comes from the control channel's AUTH (conn_auth.hpp publishes it
// here), so a reconnect makes every old tag useless, and the direction
// string stops a datagram from being reflected back to its sender. A tagged
// datagram sets bit 0x80 of byte 4 (the version byte of MRM1, MR02 and
// MRA1); the tag covers that byte too. Receivers check the tag, then clear
// the bit and drop the tag, so the parsers see a 0.3 datagram.
//
// States (Session):
//   Open     no password (transition host, or no AUTH at all): untagged
//            only, as in 0.3. A tagged datagram is dropped.
//   Pending  the host wants a password but the control channel has not
//            authenticated yet: everything received is dropped; sends go
//            untagged and the host drops them.
//   Keyed    tags on every send; only datagrams with a good h2v tag are
//            taken.

#include <winsock2.h>
#include <windows.h>
#include <bcrypt.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

#ifdef _MSC_VER
#pragma comment(lib, "bcrypt.lib")
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

namespace jl::udptag {

constexpr size_t kTagBytes = 8;
constexpr size_t kKeyBytes = 32;
constexpr size_t kVersionByte = 4;
constexpr uint8_t kFlag = 0x80;
using SessionKey = std::array<uint8_t, kKeyBytes>;

// HMAC-SHA256 with K_s for one direction. CNG reusable hash: no allocation
// per datagram. One mutex per tagger; the viewer has one sealer (v2h) and
// one verifier (h2v) per session.
class Tagger {
public:
    Tagger(const SessionKey& key, bool hostToViewer) : dir_{hostToViewer ? "h2v" : "v2h"} {
        if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg_, BCRYPT_SHA256_ALGORITHM, nullptr,
                                                    BCRYPT_ALG_HANDLE_HMAC_FLAG | BCRYPT_HASH_REUSABLE_FLAG))) {
            alg_ = nullptr;
            return;
        }
        if (!NT_SUCCESS(BCryptCreateHash(alg_, &h_, nullptr, 0, const_cast<PUCHAR>(key.data()), ULONG(key.size()),
                                         BCRYPT_HASH_REUSABLE_FLAG))) {
            h_ = nullptr;
        }
    }
    ~Tagger() {
        if (h_) BCryptDestroyHash(h_);
        if (alg_) BCryptCloseAlgorithmProvider(alg_, 0);
    }
    Tagger(const Tagger&) = delete;
    Tagger& operator=(const Tagger&) = delete;

    bool ok() const { return h_ != nullptr; }

    // The tag of n bytes at p. False (and `out` zero) when CNG failed.
    bool tag(const uint8_t* p, size_t n, uint8_t out[kTagBytes]) const {
        std::memset(out, 0, kTagBytes);
        if (!h_) return false;
        uint8_t mac[32];
        std::lock_guard<std::mutex> g(m_);
        if (!NT_SUCCESS(BCryptHashData(h_, reinterpret_cast<PUCHAR>(const_cast<char*>(dir_)), 3, 0))) return false;
        if (n && !NT_SUCCESS(BCryptHashData(h_, const_cast<PUCHAR>(p), ULONG(n), 0))) return false;
        if (!NT_SUCCESS(BCryptFinishHash(h_, mac, sizeof(mac), 0))) return false;
        std::memcpy(out, mac, kTagBytes);
        SecureZeroMemory(mac, sizeof(mac));
        return true;
    }

    // Copies n bytes to `out` (room for n + kTagBytes), sets the flag and
    // appends the tag. Returns the sealed length, 0 on failure.
    size_t seal(const uint8_t* p, size_t n, uint8_t* out) const {
        if (n <= kVersionByte) return 0;
        std::memcpy(out, p, n);
        out[kVersionByte] |= kFlag;
        return tag(out, n, out + n) ? n + kTagBytes : 0;
    }

    // n bytes carrying the flag and a good tag (constant-time compare).
    bool verify(const uint8_t* p, size_t n) const {
        if (n <= kTagBytes + kVersionByte || !(p[kVersionByte] & kFlag)) return false;
        const size_t body = n - kTagBytes;
        uint8_t want[kTagBytes];
        if (!tag(p, body, want)) return false;
        uint8_t diff = 0;
        for (size_t i = 0; i < kTagBytes; ++i) diff |= uint8_t(want[i] ^ p[body + i]);
        return diff == 0;
    }

private:
    const char* dir_;
    BCRYPT_ALG_HANDLE alg_ = nullptr;
    BCRYPT_HASH_HANDLE h_ = nullptr;
    mutable std::mutex m_;
};

enum class Mode : uint8_t { Open = 0, Pending = 1, Keyed = 2 };

// One published state: the mode and, when keyed, both taggers.
struct Session {
    Mode mode = Mode::Open;
    uint64_t generation = 0;
    std::shared_ptr<const Tagger> sealer;    // v2h
    std::shared_ptr<const Tagger> verifier;  // h2v
};

namespace detail {
inline std::mutex& m() { static std::mutex x; return x; }
inline std::shared_ptr<const Session>& slot() {
    static std::shared_ptr<const Session> s = std::make_shared<Session>();
    return s;
}
inline std::atomic<uint64_t>& gen() { static std::atomic<uint64_t> g{1}; return g; }
// The slot changes before the generation moves on, so a reader that sees
// the new generation always reads the new slot.
inline void store(std::shared_ptr<Session> s) {
    std::lock_guard<std::mutex> g(m());
    s->generation = gen().load() + 1;
    const uint64_t next = s->generation;
    slot() = std::move(s);
    gen().store(next, std::memory_order_release);
}
}  // namespace detail

// The generation moves on with every publish: users cache `current()` and
// look again only when it changed (one atomic load per datagram).
inline uint64_t generation() { return detail::gen().load(std::memory_order_acquire); }
inline std::shared_ptr<const Session> current() {
    std::lock_guard<std::mutex> g(detail::m());
    return detail::slot();
}

inline void publishOpen() { detail::store(std::make_shared<Session>()); }
inline void publishPending() {
    auto s = std::make_shared<Session>();
    s->mode = Mode::Pending;
    detail::store(std::move(s));
}
// False when CNG could not set up the taggers: the state is then Pending
// (nothing taken, nothing tagged), never Open.
inline bool publishKey(const SessionKey& k) {
    auto s = std::make_shared<Session>();
    auto sealer = std::make_shared<Tagger>(k, false);
    auto verifier = std::make_shared<Tagger>(k, true);
    if (!sealer->ok() || !verifier->ok()) {
        s->mode = Mode::Pending;
        detail::store(std::move(s));
        return false;
    }
    s->mode = Mode::Keyed;
    s->sealer = std::move(sealer);
    s->verifier = std::move(verifier);
    detail::store(std::move(s));
    return true;
}

enum class Verdict : uint8_t { Ok, NoTag, BadTag, Pending, TaggedInOpen, Short };

inline const char* verdictName(Verdict v) {
    switch (v) {
    case Verdict::Ok: return "ok";
    case Verdict::NoTag: return "no_tag";
    case Verdict::BadTag: return "bad_tag";
    case Verdict::Pending: return "no_session";
    case Verdict::TaggedInOpen: return "tagged_open";
    case Verdict::Short: return "short";
    }
    return "?";
}

// Per-socket view of the published session: one atomic load per datagram,
// the shared state is copied again only after a publish.
class View {
public:
    const Session& get() {
        const uint64_t g = generation();
        if (!s_ || g != seen_) {
            s_ = current();
            seen_ = g;
        }
        return *s_;
    }

    // Receive side. On Ok, n is shortened by the tag and byte 4 loses the
    // flag, so the 0.3 parser takes the datagram as it is.
    Verdict open(uint8_t* p, int& n) {
        const Session& s = get();
        if (n <= int(kVersionByte)) return Verdict::Short;
        const bool flagged = (p[kVersionByte] & kFlag) != 0;
        switch (s.mode) {
        case Mode::Open:
            return flagged ? Verdict::TaggedInOpen : Verdict::Ok;
        case Mode::Pending:
            return Verdict::Pending;
        case Mode::Keyed:
            if (!flagged) return Verdict::NoTag;
            if (!s.verifier->verify(p, size_t(n))) return Verdict::BadTag;
            n -= int(kTagBytes);
            p[kVersionByte] &= uint8_t(~kFlag);
            return Verdict::Ok;
        }
        return Verdict::BadTag;
    }

    // Send side: calls send(bytes, len) with the datagram, sealed when
    // keyed. Returns what send returned, or -1 if sealing failed (nothing sent).
    template <class SendFn>
    int send(const uint8_t* p, size_t n, SendFn&& sendFn) {
        const Session& s = get();
        if (s.mode != Mode::Keyed) return sendFn(p, int(n));
        uint8_t buf[1600];
        if (n + kTagBytes > sizeof(buf)) return -1;
        const size_t sealed = s.sealer->seal(p, n, buf);
        if (!sealed) return -1;
        const int r = sendFn(buf, int(sealed));
        // Callers compare against the length they passed in.
        return r == int(sealed) ? int(n) : r;
    }

private:
    std::shared_ptr<const Session> s_;
    uint64_t seen_ = 0;
};

// At most one log line per 10 s for dropped datagrams, with counts.
class DropLog {
public:
    using Clock = std::chrono::steady_clock;
    void note(const char* entry, Verdict v, const std::function<void(const std::string&)>& log) {
        ++total_;
        ++sinceLine_;
        const auto now = Clock::now();
        if (logged_ && now - last_ < std::chrono::seconds(10)) return;
        logged_ = true;
        last_ = now;
        if (log) {
            log(std::string("udp.bad_tag entry=") + entry + " reason=" + verdictName(v) + " n=" +
                std::to_string(sinceLine_) + " total=" + std::to_string(total_));
        }
        sinceLine_ = 0;
    }
    uint64_t total() const { return total_; }

private:
    uint64_t total_ = 0;
    uint64_t sinceLine_ = 0;
    bool logged_ = false;
    Clock::time_point last_{};
};

}  // namespace jl::udptag
