// JerisLink Windows host, H3: the connection password (design v0.4.0 §3-§5).
//
// The host side of what the macOS host does since v0.4.0 (PR-C), ported
// rule for rule, so a viewer cannot tell the two hosts apart:
//
//   - AUTH: 0x05 CHALLENGE, 0x03 RESPONSE, 0x04 RESULT, the same MACs as
//     windows-client/conn_auth.hpp and personal/protocol/auth_vectors.json.
//   - AuthGuard (AuthGuard.swift): per address, each 5th wrong password
//     locks it for 5, 10, 15 minutes and the 20th blacklists it; 20 wrong
//     passwords from anyone inside 60 s stop every challenge for 5 minutes.
//     The blacklist is persisted (the registry, host_config_win.hpp); a
//     block that could not be written goes to a pending journal and keeps
//     the host shut until it is written.
//   - SessionBroker (SessionLink.swift): one viewer at a time. A manual
//     control AUTH with the right password takes over: the epoch moves on,
//     every older connection is void at once and closed in the background,
//     and its viewer is told REPLACED. A reconnect the viewer makes on its
//     own (the "jl-auto1" trailer) never takes over while a control
//     connection is open. Clipboard, file and ping channels get in only on
//     the newest control session.
//   - UDP: only the session's viewer is heard, every datagram carries an
//     8-byte tag under K_s (udp_tag.hpp), and MRM1 has a 64-packet
//     anti-replay window (SeqReplayWindow).
//
// Portable: no Windows headers. The HMAC, the random source, the clock and
// the stores are passed in, so host_test runs all of it on Linux too.

#pragma once

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace jlh::auth {

// ------------------------------------------------------------------- wire

constexpr uint8_t kMsgResponse = 0x03, kMsgResult = 0x04, kMsgChallenge = 0x05;
constexpr size_t kNonceBytes = 32, kSaltBytes = 16, kHostIdBytes = 16, kKeyBytes = 32, kMacBytes = 32;
constexpr size_t kSessionIdBytes = 8, kTagBytes = 8;
constexpr size_t kChallengeBytes = kNonceBytes + kSaltBytes + 4 + 1 + kHostIdBytes;  // 69
constexpr size_t kResponseBytes = kNonceBytes + kMacBytes;                          // 64
constexpr size_t kResumeResponseBytes = kResponseBytes + kSessionIdBytes;           // 72
constexpr uint32_t kIterations = 600000;
constexpr uint8_t kKdfPbkdf2Sha256 = 1;
// What a viewer puts in the 8 bytes after the MAC of a control AUTH it
// makes on its own (ConnAuth.Response.autoMarker, conn_auth.hpp).
constexpr uint8_t kAutoMarker[kSessionIdBytes] = {'j', 'l', '-', 'a', 'u', 't', 'o', '1'};

// Timing, as the macOS host (ConnAuth.authTimeout, ControlServer,
// KickHandle).
constexpr int kAuthTimeoutMs = 5000;    // CHALLENGE sent -> whole RESPONSE read
constexpr int kHandshakeSendMs = 5000;  // one handshake frame (RESULT) going out
constexpr int kSendSliceMs = 100;       // a send re-checks revocation this often
constexpr int kNoticeLingerMs = 1000;   // after REPLACED + FIN, read and drop this long

enum class Status : uint8_t { Ok = 0, Fail = 1, Locked = 2, Blocked = 3, AuthRequired = 4, OpenIpOnly = 5, Replaced = 6 };
enum class Channel : uint8_t { Control = 1, Clipboard = 2, File = 3, Ping = 4 };
constexpr Channel kChannels[] = {Channel::Control, Channel::Clipboard, Channel::File, Channel::Ping};

inline const char* channelName(Channel c) {
    switch (c) {
    case Channel::Control: return "control";
    case Channel::Clipboard: return "clipboard";
    case Channel::File: return "file";
    case Channel::Ping: return "ping";
    }
    return "?";
}

using Bytes = std::vector<uint8_t>;
using Nonce = std::array<uint8_t, kNonceBytes>;
using Mac = std::array<uint8_t, kMacBytes>;
using Key = std::array<uint8_t, kKeyBytes>;
using Salt = std::array<uint8_t, kSaltBytes>;
using HostId = std::array<uint8_t, kHostIdBytes>;
using SessionId = std::array<uint8_t, kSessionIdBytes>;

inline std::string hex(const uint8_t* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        s.push_back(d[p[i] >> 4]);
        s.push_back(d[p[i] & 15]);
    }
    return s;
}
template <size_t N>
std::string hex(const std::array<uint8_t, N>& a) { return hex(a.data(), N); }

// Clears secrets. A volatile write the optimizer keeps.
inline void wipe(void* p, size_t n) {
    volatile uint8_t* v = static_cast<volatile uint8_t*>(p);
    while (n--) *v++ = 0;
}

inline Bytes challengePayload(const Nonce& hostNonce, const Salt& salt, uint32_t iterations, const HostId& hostId) {
    Bytes p(hostNonce.begin(), hostNonce.end());
    p.insert(p.end(), salt.begin(), salt.end());
    p.push_back(uint8_t(iterations >> 24));
    p.push_back(uint8_t(iterations >> 16));
    p.push_back(uint8_t(iterations >> 8));
    p.push_back(uint8_t(iterations));
    p.push_back(kKdfPbkdf2Sha256);
    p.insert(p.end(), hostId.begin(), hostId.end());
    return p;
}
inline Bytes resultOk(const Mac& macH, const SessionId& sid) {
    Bytes p{uint8_t(Status::Ok)};
    p.insert(p.end(), macH.begin(), macH.end());
    p.insert(p.end(), sid.begin(), sid.end());
    return p;
}
inline Bytes resultFail(uint8_t triesLeft) { return {uint8_t(Status::Fail), triesLeft}; }
inline Bytes resultLocked(uint32_t s) {
    return {uint8_t(Status::Locked), uint8_t(s >> 24), uint8_t(s >> 16), uint8_t(s >> 8), uint8_t(s)};
}
inline Bytes resultStatus(Status s) { return {uint8_t(s)}; }

struct Response {
    Nonce clientNonce{};
    Mac mac{};
    bool hasResume = false;
    SessionId resume{};

    bool zeroMac() const {
        uint8_t any = 0;
        for (uint8_t b : mac) any |= b;
        return any == 0;
    }
};

inline std::optional<Response> decodeResponse(const uint8_t* p, size_t n) {
    if (n != kResponseBytes && n != kResumeResponseBytes) return std::nullopt;
    Response r;
    std::memcpy(r.clientNonce.data(), p, kNonceBytes);
    std::memcpy(r.mac.data(), p + kNonceBytes, kMacBytes);
    if (n == kResumeResponseBytes) {
        r.hasResume = true;
        std::memcpy(r.resume.data(), p + kResponseBytes, kSessionIdBytes);
    }
    return r;
}

// ----------------------------------------------------------------- crypto

// One HMAC-SHA256 over the concatenated parts. The host passes CNG
// (conn_auth.hpp); host_test passes a portable one checked against the
// vectors. False: the primitive failed (no MAC matches then).
struct Part {
    const uint8_t* p;
    size_t n;
};
using HmacFn = bool (*)(const uint8_t* key, size_t keyLen, const Part* parts, size_t nParts, Mac& out);

inline bool constantTimeEqual(const uint8_t* a, const uint8_t* b, size_t n) {
    uint8_t d = 0;
    for (size_t i = 0; i < n; ++i) d |= uint8_t(a[i] ^ b[i]);
    return d == 0;
}

// mac_c = HMAC(K, "jl-c" | hn | cn | ch | host_id [| resume8])
inline bool macClient(HmacFn hmac, const Key& k, const Nonce& hn, const Nonce& cn, Channel ch, const HostId& hostId,
                      const SessionId* resume, Mac& out) {
    const uint8_t c = uint8_t(ch);
    const Part parts[] = {{reinterpret_cast<const uint8_t*>("jl-c"), 4}, {hn.data(), hn.size()},
                          {cn.data(), cn.size()},                       {&c, 1},
                          {hostId.data(), hostId.size()},               {resume ? resume->data() : nullptr, resume ? kSessionIdBytes : 0}};
    return hmac(k.data(), k.size(), parts, resume ? 6 : 5, out);
}
// mac_h = HMAC(K, "jl-h" | hn | cn | ch)
inline bool macHost(HmacFn hmac, const Key& k, const Nonce& hn, const Nonce& cn, Channel ch, Mac& out) {
    const uint8_t c = uint8_t(ch);
    const Part parts[] = {{reinterpret_cast<const uint8_t*>("jl-h"), 4}, {hn.data(), hn.size()}, {cn.data(), cn.size()}, {&c, 1}};
    return hmac(k.data(), k.size(), parts, 4, out);
}
// K_s = HMAC(K, "jl-udp" | hn | cn | session_id)
inline bool sessionKey(HmacFn hmac, const Key& k, const Nonce& hn, const Nonce& cn, const SessionId& sid, Key& out) {
    const Part parts[] = {{reinterpret_cast<const uint8_t*>("jl-udp"), 6}, {hn.data(), hn.size()},
                          {cn.data(), cn.size()}, {sid.data(), sid.size()}};
    Mac m{};
    if (!hmac(k.data(), k.size(), parts, 4, m)) return false;
    std::memcpy(out.data(), m.data(), kKeyBytes);
    wipe(m.data(), m.size());
    return true;
}
// tag = HMAC(K_s, "v2h" or "h2v" | datagram)[0..8]
inline bool udpTag(HmacFn hmac, const Key& ks, bool hostToViewer, const uint8_t* p, size_t n, uint8_t out[kTagBytes]) {
    const Part parts[] = {{reinterpret_cast<const uint8_t*>(hostToViewer ? "h2v" : "v2h"), 3}, {p, n}};
    Mac m{};
    if (!hmac(ks.data(), ks.size(), parts, 2, m)) return false;
    std::memcpy(out, m.data(), kTagBytes);
    return true;
}

// The channel whose mac_c matches (ConnAuth.matchChannel): all four are
// computed and compared in constant time, the first match kept, so the
// time taken does not say which channel (or whether any) matched.
inline std::optional<Channel> matchChannel(HmacFn hmac, const Key& k, const Nonce& hn, const Response& r,
                                           const HostId& hostId) {
    std::optional<Channel> found;
    for (Channel ch : kChannels) {
        Mac want{};
        const bool ok = macClient(hmac, k, hn, r.clientNonce, ch, hostId, r.hasResume ? &r.resume : nullptr, want);
        const bool eq = constantTimeEqual(want.data(), r.mac.data(), kMacBytes);
        if (ok && eq && !found) found = ch;
    }
    return found;
}

// --------------------------------------------------- what a channel may send

// r3 (Pepper's PR-C r2 review, item 4): the first header a real 0.3.x
// viewer sends, with that message's exact payload length. Only these skip
// the failure count when a password is required (ControlServer).
inline bool isLegacyFirstHeader(uint8_t type, size_t length) {
    switch (type) {
    case 0x01: return length == 4;                                  // PING
    case 0x10: return length == 3;                                  // KEY
    case 0x20: case 0x22: case 0x23: case 0x24: return length == 4; // mouse move / scroll
    case 0x21: return length == 2;                                  // MOUSE_BUTTON
    case 0x25: return length == 3;                                  // MOUSE_BUTTON_EXT
    case 0x30: return length == 0;                                  // CLIPBOARD_HELLO
    case 0x40: return length == 6;                                  // VIDEO_CONFIG_SET v1
    case 0x50: return length == 3;                                  // FILE_HELLO
    case 0x60: return length == 0;                                  // FORCE_QUIT_OPEN
    default: return false;
    }
}

// The connection stays on the channel it authenticated for: a MAC for the
// ping channel cannot open a file session, and so on.
inline bool channelAllows(Channel c, uint8_t type, bool first) {
    switch (c) {
    case Channel::Ping: return type == 0x01;
    case Channel::Clipboard: return !first || type == 0x30;
    case Channel::File: return !first || type == 0x50;
    case Channel::Control: return type != 0x30 && type != 0x50;
    }
    return false;
}

// ---------------------------------------------------------------- addresses

// A dotted IPv4 address in its one canonical spelling (no leading zeros,
// no spaces), as stored in the lists. Host order value.
inline std::optional<uint32_t> parseIpv4(const std::string& s) {
    uint32_t v = 0;
    int parts = 0;
    size_t i = 0;
    while (parts < 4) {
        if (i >= s.size() || s[i] < '0' || s[i] > '9') return std::nullopt;
        const size_t start = i;
        uint32_t x = 0;
        while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
            x = x * 10 + uint32_t(s[i] - '0');
            if (x > 255 || i - start >= 3) return std::nullopt;
            ++i;
        }
        if (i - start > 1 && s[start] == '0') return std::nullopt;
        v = (v << 8) | x;
        ++parts;
        if (parts < 4) {
            if (i >= s.size() || s[i] != '.') return std::nullopt;
            ++i;
        }
    }
    if (i != s.size()) return std::nullopt;
    return v;
}
inline bool isIpv4(const std::string& s) { return parseIpv4(s).has_value(); }
// Tailscale's CGNAT range, 100.64.0.0/10 (the address the host binds to
// when none is set).
inline bool isTailnetIpv4(const std::string& s) {
    const auto v = parseIpv4(s);
    return v && (*v & 0xFFC00000u) == 0x64400000u;
}
inline std::string ipv4String(uint32_t v) {
    return std::to_string(v >> 24) + "." + std::to_string((v >> 16) & 255) + "." + std::to_string((v >> 8) & 255) +
           "." + std::to_string(v & 255);
}

// A list typed in the settings window: addresses separated by new lines,
// commas, spaces or tabs. Duplicates are kept once, in the order typed;
// anything that is not an IPv4 address is reported, never dropped quietly.
struct IpList {
    std::vector<std::string> ips;
    std::vector<std::string> bad;
};
inline IpList parseIpList(const std::string& text) {
    IpList out;
    std::string cur;
    auto flush = [&] {
        if (cur.empty()) return;
        if (!isIpv4(cur)) out.bad.push_back(cur);
        else if (std::find(out.ips.begin(), out.ips.end(), cur) == out.ips.end()) out.ips.push_back(cur);
        cur.clear();
    };
    for (char ch : text) {
        if (ch == '\n' || ch == '\r' || ch == ',' || ch == ' ' || ch == '\t' || ch == ';') flush();
        else cur.push_back(ch);
    }
    flush();
    return out;
}

// ----------------------------------------------------------- password rules

// Design §3, as ConnAuth.passwordProblems: at least 10 characters, an
// uppercase and a lowercase ASCII letter, and a symbol (anything that is
// not an ASCII letter, a digit or white space). Takes the NFC code points
// (the caller normalizes). Windows counts code points where the Mac counts
// grapheme clusters: a password of combining marks may pass here with
// fewer than 10 visible characters (a known difference, never weaker for
// ASCII passwords).
enum class PasswordProblem { TooShort, NoUpper, NoLower, NoSymbol };
constexpr size_t kMinPasswordLength = 10;

inline const char* passwordProblemText(PasswordProblem p) {
    switch (p) {
    case PasswordProblem::TooShort: return "at least 10 characters";
    case PasswordProblem::NoUpper: return "an uppercase letter (A-Z)";
    case PasswordProblem::NoLower: return "a lowercase letter (a-z)";
    case PasswordProblem::NoSymbol: return "a symbol (not a letter, digit or space)";
    }
    return "?";
}

inline bool isUnicodeSpace(char32_t c) {
    // CharacterSet.whitespacesAndNewlines: Unicode White_Space.
    switch (c) {
    case 0x09: case 0x0A: case 0x0B: case 0x0C: case 0x0D: case 0x20: case 0x85: case 0xA0: case 0x1680:
    case 0x2028: case 0x2029: case 0x202F: case 0x205F: case 0x3000:
        return true;
    default:
        return c >= 0x2000 && c <= 0x200A;
    }
}

inline std::vector<PasswordProblem> passwordProblems(const std::u32string& nfc) {
    std::vector<PasswordProblem> out;
    if (nfc.size() < kMinPasswordLength) out.push_back(PasswordProblem::TooShort);
    bool upper = false, lower = false, symbol = false;
    for (char32_t c : nfc) {
        const bool u = c >= U'A' && c <= U'Z', l = c >= U'a' && c <= U'z', d = c >= U'0' && c <= U'9';
        upper |= u;
        lower |= l;
        symbol |= !u && !l && !d && !isUnicodeSpace(c);
    }
    if (!upper) out.push_back(PasswordProblem::NoUpper);
    if (!lower) out.push_back(PasswordProblem::NoLower);
    if (!symbol) out.push_back(PasswordProblem::NoSymbol);
    return out;
}

// ------------------------------------------------------------- the stores

// One blocked viewer address (design §4.3). `at`: Unix seconds.
struct BlockedEntry {
    std::string ip;
    int64_t at = 0;
    std::string reason;
    bool operator==(const BlockedEntry&) const = default;
};

// A cheap stamp of a store (the registry key's last write and its serial
// on Windows). The guard reads the store again whenever it moves; nullopt
// (could not be taken) reads it too.
struct StoreStamp {
    bool exists = false;
    uint64_t a = 0, b = 0;
    bool operator==(const StoreStamp&) const = default;
};

inline std::vector<BlockedEntry> mergedBlocklist(const std::vector<BlockedEntry>& current,
                                                 const std::vector<BlockedEntry>& adding,
                                                 const std::set<std::string>& removing) {
    std::vector<BlockedEntry> out;
    for (const auto& e : current)
        if (!removing.count(e.ip)) out.push_back(e);
    for (const auto& e : adding) {
        if (removing.count(e.ip)) continue;
        if (std::none_of(out.begin(), out.end(), [&](const BlockedEntry& x) { return x.ip == e.ip; })) out.push_back(e);
    }
    return out;
}

// The persisted blacklist (listen.plist blockedIPs on the Mac; the
// registry value blockedIPs here).
class BlocklistStore {
public:
    virtual ~BlocklistStore() = default;
    // nullopt: it could not be read (the guard keeps what it has).
    virtual std::optional<std::vector<BlockedEntry>> load() = 0;
    // Read-modify-write against what the store holds now (mergedBlocklist).
    // Returns the list as written, or nullopt when it could not be written.
    virtual std::optional<std::vector<BlockedEntry>> update(const std::vector<BlockedEntry>& adding,
                                                            const std::set<std::string>& removing) = 0;
    virtual std::optional<StoreStamp> probeStamp() { return StoreStamp{}; }
};

// Blocks that could not be written to the blacklist (B5 r4), kept apart
// so a restart still enforces them.
class PendingBlockStore {
public:
    virtual ~PendingBlockStore() = default;
    // {} when there is no journal; nullopt when one exists but cannot be
    // read (the guard then admits nobody: fail closed).
    virtual std::optional<std::vector<BlockedEntry>> load() = 0;
    // Replaces the journal with `entries` (empty removes it).
    virtual bool save(const std::vector<BlockedEntry>& entries) = 0;
    virtual std::optional<StoreStamp> probeStamp() { return StoreStamp{}; }
};

class MemoryBlocklist : public BlocklistStore {
public:
    std::vector<BlockedEntry> entries;
    int failNextSaves = 0;
    int saveCalls = 0;
    bool unreadable = false;
    StoreStamp stamp{};  // tests move it to play an outside edit

    std::optional<std::vector<BlockedEntry>> load() override {
        if (unreadable) return std::nullopt;
        return entries;
    }
    std::optional<std::vector<BlockedEntry>> update(const std::vector<BlockedEntry>& adding,
                                                    const std::set<std::string>& removing) override {
        ++saveCalls;
        if (failNextSaves > 0) {
            --failNextSaves;
            return std::nullopt;
        }
        entries = mergedBlocklist(entries, adding, removing);
        ++stamp.b;
        return entries;
    }
    std::optional<StoreStamp> probeStamp() override { return stamp; }
};

class MemoryPendingBlocks : public PendingBlockStore {
public:
    std::vector<BlockedEntry> entries;
    bool canWrite = true;
    bool unreadable = false;
    StoreStamp stamp{};

    std::optional<std::vector<BlockedEntry>> load() override {
        if (unreadable) return std::nullopt;
        return entries;
    }
    bool save(const std::vector<BlockedEntry>& e) override {
        if (!canWrite) return false;
        entries = e;
        ++stamp.b;
        return true;
    }
    std::optional<StoreStamp> probeStamp() override { return stamp; }
};

// --------------------------------------------------------------- AuthGuard

// Wrong-password limits (design §4), AuthGuard.swift rule for rule.
//
// Per peer IP, across every channel: each 5th failure locks that IP for
// 5, 10, then 15 minutes, and the 20th puts it on the blacklist. One right
// password clears that IP's count. All IPs together: 20 failures inside any
// 60 s window stop every challenge for 5 minutes; a right password does not
// clear that window. Counts and waits live in memory only; the blacklist is
// persisted. Locked or blocked connections get no challenge, so they cannot
// add failures.
//
// A challenge can be outstanding while another connection trips a wait or
// the blacklist. `settle` therefore checks the limits again and records the
// outcome under the same lock as the MAC check: an answer to a challenge
// issued before the wait gets LOCKED/BLOCKED, is not counted and never OK.
//
// Windows additions (the Mac restarts its control service instead):
// `setWhitelist` (the settings window changed it while the host runs), and
// a block removed from the registry by the settings window is released in
// place ("auth.block_removed"). `takeNewlyBlocked` hands every address that
// joined the blacklist to the host, which closes its open connections.
class AuthGuard {
public:
    static constexpr int kFailuresPerStage = 5;
    static constexpr int kBlacklistStage = 4;
    static constexpr double kStageWait = 300;
    static constexpr double kGlobalWindow = 60;
    static constexpr int kGlobalMaxFailures = 20;
    static constexpr double kGlobalWait = 300;
    static constexpr int kSaveAttempts = 3;
    static constexpr double kSaveRetryPause = 0.05;
    static constexpr double kPendingRetryInterval = 1;
    static constexpr uint32_t kPendingRetrySeconds = 5;

    struct Admission {
        enum Kind { Challenge, Blocked, NotAllowed, Locked, GlobalLocked } kind = Challenge;
        uint32_t retrySeconds = 0;
        int stage = 0;
        bool operator==(const Admission&) const = default;
    };
    struct FailureOutcome {
        enum Kind { Retry, Locked, Blacklisted } kind = Retry;
        uint8_t triesLeft = 0;
        uint32_t retrySeconds = 0;
        int stage = 0;
        bool persisted = false;  // Blacklisted: the store holds the entry
        bool operator==(const FailureOutcome&) const = default;
    };
    struct Failure {
        FailureOutcome outcome;
        int failures = 0;
        bool globalTriggered = false;
        bool operator==(const Failure&) const = default;
    };
    struct Settlement {
        enum Kind { Ok, Failed, Refused } kind = Ok;
        Failure failure;
        Admission admission;
    };
    enum class ReleaseResult { Released, NotBlocked, SaveFailed };
    struct ProbeAnswer {
        bool refused = false;
        uint8_t triesLeft = 0;
        Admission admission;
    };

    struct Hooks {
        std::function<double()> now;        // monotonic seconds
        std::function<int64_t()> wallNow;   // Unix seconds
        std::function<void(double)> pause;  // between blacklist write attempts
        std::function<void(const std::string&)> log;
        std::string storeName = "registry";
    };

    static Hooks defaultHooks(std::function<void(const std::string&)> log) {
        Hooks h;
        h.now = [] {
            return std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count();
        };
        h.wallNow = [] { return int64_t(std::time(nullptr)); };
        h.pause = [](double s) { std::this_thread::sleep_for(std::chrono::duration<double>(s)); };
        h.log = std::move(log);
        return h;
    }

    AuthGuard(std::vector<std::string> whitelist, BlocklistStore& blocklist, PendingBlockStore* journal, Hooks hooks)
        : whitelist_(std::move(whitelist)), blocklist_(blocklist), journal_(journal), h_(std::move(hooks)) {
        std::lock_guard<std::mutex> g(m_);
        // r8: taken before the read, as for the journal.
        storeKnown_ = blocklist_.probeStamp();
        const auto loaded = blocklist_.load().value_or(std::vector<BlockedEntry>{});
        for (const auto& e : loaded) persisted_.insert(e.ip);
        // B5 r4: a block that never reached the store before the last exit
        // is blocked again and still pending, so the host stays shut (no
        // challenges) until the store holds it. r5: a journal that exists
        // but does not read is not an empty one.
        const auto journalStamp = journal_ ? journal_->probeStamp() : std::optional<StoreStamp>{};
        const std::optional<std::vector<BlockedEntry>> fromJournal =
            journal_ ? journal_->load() : std::optional<std::vector<BlockedEntry>>(std::vector<BlockedEntry>{});
        if (fromJournal) journalKnown_ = journalStamp;
        std::vector<BlockedEntry> carried;
        if (fromJournal)
            for (const auto& e : *fromJournal)
                if (!containsIp(loaded, e.ip)) carried.push_back(e);
        blocked_ = loaded;
        blocked_.insert(blocked_.end(), carried.begin(), carried.end());
        for (const auto& e : carried) noteBlocked(e.ip);
        pending_ = carried;
        if (fromJournal)
            for (const auto& e : *fromJournal) journaled_.insert(e.ip);
        if (!fromJournal) {
            journalUnreadable_ = true;
            lastJournalRetry_ = h_.now();
            log("auth.lockdown reason=pending_journal_unreadable (file kept as is; nobody is admitted until it reads or is removed)");
        } else if (!carried.empty()) {
            log("auth.lockdown_restored peers=" + std::to_string(carried.size()) + " source=pending_journal");
            retryPendingLocked(true);
        } else if (!journaled_.empty()) {
            writeJournalLocked({});
        }
    }

    // Blacklist first (it wins over the whitelist), then the whitelist,
    // then this IP's wait, then the host-wide wait.
    Admission admit(const std::string& ip) {
        std::lock_guard<std::mutex> g(m_);
        return admitLocked(ip);
    }

    // r5 (B5): why nobody may be admitted at all, whatever the address.
    std::optional<std::string> lockdownReason() {
        std::lock_guard<std::mutex> g(m_);
        refreshLocked(false);
        if (journalHoldLocked()) return std::string("pending_journal_unreadable");
        return std::nullopt;
    }

    // r7/r8: asked with an open connection's peer address on every message:
    // nullopt to go on, else why not (the journal lockdown, then the
    // blacklist).
    std::optional<std::string> inputRefusal(const std::string& ip) {
        std::lock_guard<std::mutex> g(m_);
        refreshLocked(false);
        if (journalHoldLocked()) return std::string("pending_journal_unreadable");
        if (containsIp(blocked_, ip)) return std::string("blocked");
        return std::nullopt;
    }

    // The policy watch's fallback, once a second: both stores read again.
    void probeJournal() {
        std::lock_guard<std::mutex> g(m_);
        refreshLocked(true);
    }

    bool isBlocked(const std::string& ip) {
        std::lock_guard<std::mutex> g(m_);
        refreshLocked(false);
        return containsIp(blocked_, ip);
    }

    // Settles one outstanding challenge in a single critical section:
    // limits checked again, then `check` (the MAC comparison; a timeout or
    // malformed answer passes a check that returns false), then success
    // or failure recorded. `check` must not block or call back in here.
    template <class Check>
    Settlement settle(const std::string& ip, Check&& check) {
        std::lock_guard<std::mutex> g(m_);
        Settlement s;
        const Admission a = admitLocked(ip);
        if (a.kind != Admission::Challenge) {
            s.kind = Settlement::Refused;
            s.admission = a;
            return s;
        }
        if (check()) {
            peers_.erase(ip);
            s.kind = Settlement::Ok;
            return s;
        }
        s.kind = Settlement::Failed;
        s.failure = recordFailureLocked(ip);
        return s;
    }

    Failure recordFailure(const std::string& ip) {
        std::lock_guard<std::mutex> g(m_);
        return recordFailureLocked(ip);
    }
    void recordSuccess(const std::string& ip) {
        std::lock_guard<std::mutex> g(m_);
        peers_.erase(ip);
    }

    // Manual release: off the blacklist, count cleared, only when the store
    // is written (a restart cannot bring back an entry reported released).
    ReleaseResult release(const std::string& ip) {
        std::lock_guard<std::mutex> g(m_);
        if (!containsIp(blocked_, ip)) return ReleaseResult::NotBlocked;
        if (journaled_.count(ip)) {
            std::vector<BlockedEntry> rest;
            for (const auto& e : pending_)
                if (e.ip != ip) rest.push_back(e);
            if (!writeJournalLocked(rest)) {
                log("auth.release_failed peer=" + ip + " reason=journal_write_failed");
                return ReleaseResult::SaveFailed;
            }
        }
        if (!writeLocked({}, {ip})) {
            log("auth.release_failed peer=" + ip + " reason=write_failed attempts=" + std::to_string(kSaveAttempts));
            return ReleaseResult::SaveFailed;
        }
        eraseIp(blocked_, ip);
        eraseIp(pending_, ip);
        peers_.erase(ip);
        log("auth.released peer=" + ip + " persisted=" + h_.storeName);
        return ReleaseResult::Released;
    }

    // PR-C item 5: a zero-MAC transition probe that crossed a CHALLENGE.
    // The admission is checked again, and the answer is the tries left
    // now. Nothing is recorded.
    ProbeAnswer probe(const std::string& ip) {
        std::lock_guard<std::mutex> g(m_);
        ProbeAnswer p;
        const Admission a = admitLocked(ip);
        if (a.kind != Admission::Challenge) {
            p.refused = true;
            p.admission = a;
            return p;
        }
        const auto it = peers_.find(ip);
        const int f = it == peers_.end() ? 0 : it->second.failures;
        p.triesLeft = uint8_t(kFailuresPerStage - f % kFailuresPerStage);
        return p;
    }

    int failures(const std::string& ip) {
        std::lock_guard<std::mutex> g(m_);
        const auto it = peers_.find(ip);
        return it == peers_.end() ? 0 : it->second.failures;
    }
    std::vector<BlockedEntry> blockedEntries() {
        std::lock_guard<std::mutex> g(m_);
        return blocked_;
    }
    std::set<std::string> persistedIPs() {
        std::lock_guard<std::mutex> g(m_);
        refreshStoreLocked();
        return persisted_;
    }
    bool retryPending(bool force = true) {
        std::lock_guard<std::mutex> g(m_);
        retryPendingLocked(force);
        return pending_.empty();
    }
    std::vector<std::string> pendingIPs() {
        std::lock_guard<std::mutex> g(m_);
        std::vector<std::string> out;
        for (const auto& e : pending_) out.push_back(e.ip);
        return out;
    }
    // Every pending block is at least in the journal (true when none is).
    bool isDurable() {
        std::lock_guard<std::mutex> g(m_);
        return std::all_of(pending_.begin(), pending_.end(), [&](const BlockedEntry& e) { return journaled_.count(e.ip) > 0; });
    }
    bool saveJournal() {
        std::lock_guard<std::mutex> g(m_);
        if (std::all_of(pending_.begin(), pending_.end(), [&](const BlockedEntry& e) { return journaled_.count(e.ip) > 0; }))
            return true;
        return writeJournalLocked(pending_);
    }

    void setWhitelist(std::vector<std::string> w) {
        std::lock_guard<std::mutex> g(m_);
        whitelist_ = std::move(w);
    }
    std::vector<std::string> whitelist() {
        std::lock_guard<std::mutex> g(m_);
        return whitelist_;
    }

    // Addresses that joined the blacklist since the last call (a 20th
    // failure, the settings window, the journal): the host closes their
    // open connections at once.
    std::vector<std::string> takeNewlyBlocked() {
        std::lock_guard<std::mutex> g(m_);
        std::vector<std::string> out;
        out.swap(newlyBlocked_);
        return out;
    }

private:
    struct PeerState {
        int failures = 0;
        double lockedUntil = 0;
        int stage = 0;
    };

    static bool containsIp(const std::vector<BlockedEntry>& v, const std::string& ip) {
        return std::any_of(v.begin(), v.end(), [&](const BlockedEntry& e) { return e.ip == ip; });
    }
    static void eraseIp(std::vector<BlockedEntry>& v, const std::string& ip) {
        v.erase(std::remove_if(v.begin(), v.end(), [&](const BlockedEntry& e) { return e.ip == ip; }), v.end());
    }
    static uint32_t seconds(double interval) { return uint32_t(std::max(1.0, std::ceil(interval))); }

    void log(const std::string& line) {
        if (h_.log) h_.log(line);
    }
    void noteBlocked(const std::string& ip) {
        if (std::find(newlyBlocked_.begin(), newlyBlocked_.end(), ip) == newlyBlocked_.end()) newlyBlocked_.push_back(ip);
    }
    void addBlocked(const BlockedEntry& e) {
        if (containsIp(blocked_, e.ip)) return;
        blocked_.push_back(e);
        noteBlocked(e.ip);
    }

    void refreshLocked(bool force) {
        refreshStoreLocked();
        refreshJournalLocked(force);
    }

    // r8: a block added to the store from outside while the host runs (the
    // settings window) applies at once and counts as persisted. Windows: a
    // block removed from outside (released in the settings window) is
    // released here too, with its count; one still pending stays.
    void refreshStoreLocked() {
        const auto stamp = blocklist_.probeStamp();
        if (stamp && storeKnown_ && *stamp == *storeKnown_) return;
        const auto entries = blocklist_.load();
        if (!entries) {
            if (!storeUnreadableLogged_) {
                storeUnreadableLogged_ = true;
                log("auth.blocklist_unreadable source=" + h_.storeName + " (kept the blacklist as it was)");
            }
            return;
        }
        storeUnreadableLogged_ = false;
        storeKnown_ = stamp;
        std::vector<BlockedEntry> added;
        for (const auto& e : *entries)
            if (!persisted_.count(e.ip)) added.push_back(e);
        std::vector<std::string> removed;
        for (const auto& ip : persisted_)
            if (!containsIp(*entries, ip) && !containsIp(pending_, ip)) removed.push_back(ip);
        if (!added.empty()) {
            for (const auto& e : added) {
                persisted_.insert(e.ip);
                addBlocked(e);
            }
            log("auth.block_added peers=" + std::to_string(added.size()) + " source=" + h_.storeName + " found=running");
        }
        if (!removed.empty()) {
            for (const auto& ip : removed) {
                persisted_.erase(ip);
                eraseIp(blocked_, ip);
                peers_.erase(ip);
            }
            log("auth.block_removed peers=" + std::to_string(removed.size()) + " source=" + h_.storeName + " found=running");
        }
    }

    // r7 (B5): reads the journal when it moved since this guard last read
    // it (`force`: always). One that does not read holds everything; one
    // that reads carries in any block this guard does not hold yet.
    void refreshJournalLocked(bool force) {
        if (!journal_ || journalUnreadable_) return;
        const auto stamp = journal_->probeStamp();
        if (!force && stamp && journalKnown_ && *stamp == *journalKnown_) return;
        const auto entries = journal_->load();
        if (!entries) {
            journalUnreadable_ = true;
            journalKnown_.reset();
            lastJournalRetry_ = h_.now();
            log("auth.lockdown reason=pending_journal_unreadable found=running (file kept as is; nobody is admitted and open connections stop until it reads or is removed)");
            return;
        }
        journalKnown_ = stamp;
        journaled_.clear();
        for (const auto& e : *entries) journaled_.insert(e.ip);
        std::vector<BlockedEntry> carried;
        for (const auto& e : *entries)
            if (!persisted_.count(e.ip) && !containsIp(pending_, e.ip)) carried.push_back(e);
        if (carried.empty()) return;
        for (const auto& e : carried) addBlocked(e);
        pending_.insert(pending_.end(), carried.begin(), carried.end());
        log("auth.lockdown_restored peers=" + std::to_string(carried.size()) + " source=pending_journal found=running");
        retryPendingLocked(true);
    }

    Admission admitLocked(const std::string& ip) {
        refreshLocked(false);
        Admission a;
        if (containsIp(blocked_, ip)) {
            a.kind = Admission::Blocked;
            return a;
        }
        if (!whitelist_.empty() && std::find(whitelist_.begin(), whitelist_.end(), ip) == whitelist_.end()) {
            a.kind = Admission::NotAllowed;
            return a;
        }
        const double t = h_.now();
        const auto it = peers_.find(ip);
        if (it != peers_.end() && it->second.lockedUntil > t) {
            a.kind = Admission::Locked;
            a.retrySeconds = seconds(it->second.lockedUntil - t);
            a.stage = it->second.stage;
            return a;
        }
        if (globalLockedUntil_ > t) {
            a.kind = Admission::GlobalLocked;
            a.retrySeconds = seconds(globalLockedUntil_ - t);
            return a;
        }
        if (journalHoldLocked()) {
            a.kind = Admission::GlobalLocked;
            a.retrySeconds = kPendingRetrySeconds;
            return a;
        }
        if (!pending_.empty()) {
            retryPendingLocked(false);
            if (!pending_.empty()) {
                a.kind = Admission::GlobalLocked;
                a.retrySeconds = kPendingRetrySeconds;
                return a;
            }
        }
        return a;
    }

    Failure recordFailureLocked(const std::string& ip) {
        const double t = h_.now();
        globalFailures_.push_back(t);
        globalFailures_.erase(std::remove_if(globalFailures_.begin(), globalFailures_.end(),
                                             [&](double x) { return t - x >= kGlobalWindow; }),
                              globalFailures_.end());
        bool globalTriggered = false;
        if (int(globalFailures_.size()) >= kGlobalMaxFailures && globalLockedUntil_ <= t) {
            globalLockedUntil_ = t + kGlobalWait;
            globalTriggered = true;
        }
        PeerState p = peers_.count(ip) ? peers_[ip] : PeerState{};
        p.failures += 1;
        const int failures = p.failures;
        Failure f;
        f.failures = failures;
        f.globalTriggered = globalTriggered;
        if (p.failures % kFailuresPerStage != 0) {
            peers_[ip] = p;
            f.outcome.kind = FailureOutcome::Retry;
            f.outcome.triesLeft = uint8_t(kFailuresPerStage - p.failures % kFailuresPerStage);
            return f;
        }
        p.stage = p.failures / kFailuresPerStage;
        if (p.stage >= kBlacklistStage) {
            peers_.erase(ip);
            // Blocked in memory first: a failed write must not reopen the IP.
            addBlocked(BlockedEntry{ip, h_.wallNow(), std::to_string(failures) + " wrong passwords"});
            BlockedEntry entry;
            for (const auto& e : blocked_)
                if (e.ip == ip) entry = e;
            const bool persisted = writeLocked({entry}, {});
            if (!persisted && !containsIp(pending_, ip)) {
                pending_.push_back(entry);
                lastPendingRetry_ = t;
                const bool journalSaved = writeJournalLocked(pending_);
                log("auth.lockdown reason=blocklist_unpersisted peer=" + ip + " journal=" +
                    (journalSaved ? "saved" : "not_saved") + " (no challenges until the " + h_.storeName +
                    " is written)");
            }
            f.outcome.kind = FailureOutcome::Blacklisted;
            f.outcome.persisted = persisted;
            return f;
        }
        const double wait = kStageWait * double(p.stage);
        p.lockedUntil = t + wait;
        peers_[ip] = p;
        f.outcome.kind = FailureOutcome::Locked;
        f.outcome.retrySeconds = seconds(wait);
        f.outcome.stage = p.stage;
        return f;
    }

    // Bounded retry of one merge write. On success the guard also adopts
    // entries someone else wrote meanwhile, so a manual block applies at
    // once.
    bool writeLocked(const std::vector<BlockedEntry>& adding, const std::set<std::string>& removing) {
        for (int attempt = 1; attempt <= kSaveAttempts; ++attempt) {
            if (const auto stored = blocklist_.update(adding, removing)) {
                for (const auto& e : adding) persisted_.insert(e.ip);
                for (const auto& ip : removing) persisted_.erase(ip);
                for (const auto& e : *stored)
                    if (!containsIp(blocked_, e.ip) && !persisted_.count(e.ip)) addBlocked(e);
                return true;
            }
            if (attempt < kSaveAttempts && h_.pause) h_.pause(kSaveRetryPause * double(attempt));
        }
        return false;
    }

    void retryPendingLocked(bool force) {
        if (pending_.empty()) return;
        const double t = h_.now();
        if (!force && t - lastPendingRetry_ < kPendingRetryInterval) return;
        lastPendingRetry_ = t;
        const auto waiting = pending_;
        if (blocklist_.update(waiting, {})) {
            for (const auto& e : waiting) persisted_.insert(e.ip);
            pending_.clear();
            writeJournalLocked({});
            log("auth.lockdown_cleared persisted=" + h_.storeName + " peers=" + std::to_string(waiting.size()));
        }
    }

    // r5 (B5): while the journal does not read, try it again at most once
    // per kPendingRetryInterval; true while it still does not.
    bool journalHoldLocked() {
        if (!journalUnreadable_) return false;
        if (!journal_) {
            journalUnreadable_ = false;
            return false;
        }
        const double t = h_.now();
        if (t - lastJournalRetry_ < kPendingRetryInterval) return true;
        lastJournalRetry_ = t;
        const auto stamp = journal_->probeStamp();
        const auto entries = journal_->load();
        if (!entries) return true;
        journalUnreadable_ = false;
        journalKnown_ = stamp;
        journaled_.clear();
        for (const auto& e : *entries) journaled_.insert(e.ip);
        std::vector<BlockedEntry> carried;
        for (const auto& e : *entries)
            if (!persisted_.count(e.ip) && !containsIp(pending_, e.ip)) carried.push_back(e);
        for (const auto& e : carried) addBlocked(e);
        pending_.insert(pending_.end(), carried.begin(), carried.end());
        log("auth.lockdown_journal_readable peers=" + std::to_string(carried.size()));
        std::set<std::string> pendingSet;
        for (const auto& e : pending_) pendingSet.insert(e.ip);
        if (journaled_ != pendingSet) writeJournalLocked(pending_);
        retryPendingLocked(true);
        return false;
    }

    bool writeJournalLocked(const std::vector<BlockedEntry>& entries) {
        if (!journal_) return false;
        if (journalUnreadable_) {
            log("auth.pending_journal_not_saved peers=" + std::to_string(entries.size()) +
                " reason=journal_unreadable (kept as is)");
            return false;
        }
        if (!journal_->save(entries)) {
            log("auth.pending_journal_not_saved peers=" + std::to_string(entries.size()));
            return false;
        }
        journaled_.clear();
        for (const auto& e : entries) journaled_.insert(e.ip);
        return true;
    }

    std::mutex m_;
    std::vector<std::string> whitelist_;
    BlocklistStore& blocklist_;
    PendingBlockStore* journal_;
    Hooks h_;
    std::map<std::string, PeerState> peers_;
    std::vector<BlockedEntry> blocked_;
    std::set<std::string> persisted_;
    std::vector<double> globalFailures_;
    double globalLockedUntil_ = 0;
    std::vector<BlockedEntry> pending_;
    std::set<std::string> journaled_;
    bool journalUnreadable_ = false;
    std::optional<StoreStamp> journalKnown_;
    std::optional<StoreStamp> storeKnown_;
    bool storeUnreadableLogged_ = false;
    double lastJournalRetry_ = -1e300;
    double lastPendingRetry_ = -1e300;
    std::vector<std::string> newlyBlocked_;
};

// ----------------------------------------------------------- SessionBroker

// The UDP tags of one session: seal host -> viewer, verify viewer -> host.
// The host builds them with CNG (udp_tag.hpp's Tagger), host_test with the
// portable HMAC.
class UdpTags {
public:
    virtual ~UdpTags() = default;
    // Copies n bytes to out (room for n + kTagBytes), sets bit 0x80 of byte
    // 4 and appends the h2v tag. The sealed length, 0 on failure.
    virtual size_t seal(const uint8_t* p, size_t n, uint8_t* out) const = 0;
    // n bytes with the flag and a good v2h tag (constant-time compare).
    virtual bool verify(const uint8_t* p, size_t n) const = 0;
};
using UdpTagsFactory = std::function<std::shared_ptr<const UdpTags>(const Key& sessionKey)>;

constexpr size_t kUdpVersionByte = 4;
constexpr uint8_t kUdpTagFlag = 0x80;

// Why the host closed an admitted connection from outside its own thread.
enum class CloseReason : uint8_t {
    Replaced,  // a newer control AUTH took the session: control gets REPLACED
    Policy,    // the password or the whitelist changed: closed, no notice
    Blocked,   // its address joined the blacklist: closed, no notice
    Lockdown,  // the pending journal stopped reading: closed, no notice
};
inline const char* closeReasonName(CloseReason r) {
    switch (r) {
    case CloseReason::Replaced: return "replaced";
    case CloseReason::Policy: return "policy_changed";
    case CloseReason::Blocked: return "blocked";
    case CloseReason::Lockdown: return "lockdown";
    }
    return "?";
}

// The viewer the UDP paths serve now.
struct UdpSession {
    uint64_t generation = 0;
    std::string peerIp;
    std::shared_ptr<const UdpTags> tags;  // nullptr: the taggers could not be made; nothing is sent or taken
};

// SessionLink.swift's SessionBroker, password mode.
class SessionBroker {
public:
    using CloseFn = std::function<void(CloseReason)>;
    using LogFn = std::function<void(const std::string&)>;

    SessionBroker(UdpTagsFactory tags, LogFn log) : tags_(std::move(tags)), log_(std::move(log)) {}
    ~SessionBroker() {
        {
            std::lock_guard<std::mutex> g(qm_);
            qStop_ = true;
        }
        qcv_.notify_all();
        if (worker_.joinable()) worker_.join();
    }
    SessionBroker(const SessionBroker&) = delete;
    SessionBroker& operator=(const SessionBroker&) = delete;

    // Run after every void (a takeover, voidAll, kickPeer), before the call
    // that voided returns, so before a takeover's AUTH_OK goes out. The
    // host retires a voided input owner here (InputClaims::retire): an
    // injection that passed its check before the void finishes first, and
    // none starts after (the Mac r11 whileLive rule). Set once at start-up,
    // before anything is admitted; it may call live() but nothing that
    // voids or admits.
    void onVoid(std::function<void()> f) { onVoid_ = std::move(f); }

    // r14: a control AUTH flagged "auto" is refused while any control
    // connection is open, whoever holds it: it never takes over.
    bool autoRefused(bool isAuto) {
        if (!isAuto) return false;
        std::lock_guard<std::mutex> g(m_);
        return controlOpenLocked();
    }

    enum class Refusal { None, Resume, Policy };
    struct Admitted {
        Refusal refused = Refusal::None;
        uint64_t token = 0;
    };

    // Takes one authenticated connection. A control AUTH takes over here,
    // before its AUTH_OK goes out, unless it is auto and a control
    // connection is open; another channel only when it names the newest
    // control session. `policy`: the policy generation the AUTH ran under;
    // a change since (voidAll) refuses it. Refused: nothing changed and
    // nothing closed.
    Admitted admit(const std::string& peerIp, Channel channel, const std::optional<Key>& sessionKeyV,
                   const std::optional<SessionId>& authSession, const std::optional<SessionId>& resume, bool isAuto,
                   uint64_t policy, CloseFn close) {
        std::vector<Entry> voided;
        Admitted out;
        std::lock_guard<std::mutex> order(orderM_);
        std::shared_ptr<const UdpSession> change;
        {
            std::unique_lock<std::mutex> g(m_);
            if (policy != policy_) {
                out.refused = Refusal::Policy;
                return out;
            }
            const bool refused = channel == Channel::Control ? (isAuto && controlOpenLocked())
                                                             : (!resume || !currentId_ || *resume != *currentId_);
            if (refused) {
                ++resumeRefused_;
                out.refused = Refusal::Resume;
                return out;
            }
            Entry e;
            e.token = ++nextToken_;
            e.peerIp = peerIp;
            e.channel = channel;
            if (channel == Channel::Control) e.sessionKey = sessionKeyV;
            e.authSession = authSession;
            e.epoch = epoch_;
            e.close = std::move(close);
            if (channel == Channel::Control) {
                // §5.2: one viewer at a time; the newest AUTH wins. r12: one
                // step under the lock: the epoch moves on and everything
                // admitted before is void, whoever it came from.
                ++epoch_;
                e.epoch = epoch_;
                if (authSession) currentId_ = authSession;
                voided.swap(entries_);
                for (const auto& v : voided) why_[v.token] = CloseReason::Replaced;
            }
            out.token = e.token;
            entries_.push_back(std::move(e));
            replaced_ += voided.size();
            change = recomputeLocked();
        }
        publish(change);
        if (!voided.empty()) {
            if (onVoid_) onVoid_();
            const std::string newPeer = peerIp;
            enqueueCloses(std::move(voided), CloseReason::Replaced, [this, newPeer](const Entry& old) {
                log("auth.replaced old_peer=" + old.peerIp + " chan=" + channelName(old.channel) + " new_peer=" + newPeer +
                    "; old connection closed");
            });
        }
        return out;
    }

    // r12: the connection is still in the epoch it was admitted in.
    bool live(uint64_t token) {
        std::lock_guard<std::mutex> g(m_);
        for (const auto& e : entries_)
            if (e.token == token) return e.epoch == epoch_;
        return false;
    }

    // r9: the AUTH_OK of an admitted control AUTH did not go out: its
    // connection ends and its id stops counting.
    void abandon(uint64_t token) {
        std::lock_guard<std::mutex> order(orderM_);
        std::shared_ptr<const UdpSession> change;
        {
            std::lock_guard<std::mutex> g(m_);
            for (const auto& e : entries_)
                if (e.token == token && e.authSession && currentId_ && *e.authSession == *currentId_) currentId_.reset();
            eraseToken(token);
            why_.erase(token);
            change = recomputeLocked();
        }
        publish(change);
    }

    void end(uint64_t token) {
        std::lock_guard<std::mutex> order(orderM_);
        std::shared_ptr<const UdpSession> change;
        {
            std::lock_guard<std::mutex> g(m_);
            eraseToken(token);
            why_.erase(token);
            change = recomputeLocked();
        }
        publish(change);
    }

    // Windows: the password or the whitelist changed (Policy), or the
    // pending journal stopped reading (Lockdown). Every connection is void
    // and closed with no notice, the session id stops counting, and an AUTH
    // that ran under the old policy is refused at admit. The Mac restarts
    // its control service for the same changes.
    void voidAll(CloseReason why, bool policyChanged) {
        std::vector<Entry> voided;
        std::lock_guard<std::mutex> order(orderM_);
        std::shared_ptr<const UdpSession> change;
        {
            std::lock_guard<std::mutex> g(m_);
            if (policyChanged) ++policy_;
            ++epoch_;
            currentId_.reset();
            voided.swap(entries_);
            for (const auto& v : voided) why_[v.token] = why;
            change = recomputeLocked();
        }
        publish(change);
        if (!voided.empty() && onVoid_) onVoid_();
        if (!voided.empty())
            enqueueCloses(std::move(voided), why, [this, why](const Entry& old) {
                log(std::string("auth.closed peer=") + old.peerIp + " chan=" + channelName(old.channel) +
                    " reason=" + closeReasonName(why) + "; connection closed");
            });
    }

    // Windows: `ip` joined the blacklist. Its connections leave the broker
    // (void at once) and are closed with no notice; its viewer learns
    // BLOCKED when it reconnects. Other viewers go on.
    size_t kickPeer(const std::string& ip, CloseReason why) {
        std::vector<Entry> voided;
        std::lock_guard<std::mutex> order(orderM_);
        std::shared_ptr<const UdpSession> change;
        {
            std::lock_guard<std::mutex> g(m_);
            std::vector<Entry> keep;
            for (auto& e : entries_) {
                if (e.peerIp == ip) {
                    if (e.authSession && currentId_ && *e.authSession == *currentId_) currentId_.reset();
                    why_[e.token] = why;
                    voided.push_back(std::move(e));
                } else {
                    keep.push_back(std::move(e));
                }
            }
            entries_.swap(keep);
            change = recomputeLocked();
        }
        publish(change);
        const size_t n = voided.size();
        if (n && onVoid_) onVoid_();
        if (n)
            enqueueCloses(std::move(voided), why, [this, why](const Entry& old) {
                log(std::string("auth.closed peer=") + old.peerIp + " chan=" + channelName(old.channel) +
                    " reason=" + closeReasonName(why) + "; connection closed");
            });
        return n;
    }

    // Why a connection admitted as `token` was voided (nullopt: it was
    // not, or it ended). Kept until its end(): the handler asks it once its
    // loop stopped, to tell a takeover (REPLACED notice) from the rest
    // (closed with no notice).
    std::optional<CloseReason> voidReason(uint64_t token) {
        std::lock_guard<std::mutex> g(m_);
        const auto it = why_.find(token);
        if (it == why_.end()) return std::nullopt;
        return it->second;
    }

    uint64_t policyGeneration() {
        std::lock_guard<std::mutex> g(m_);
        return policy_;
    }

    // The session and its generation (one atomic load when unchanged:
    // readers cache by generation()).
    uint64_t generation() const { return generation_.load(std::memory_order_acquire); }
    std::shared_ptr<const UdpSession> current() {
        std::lock_guard<std::mutex> g(m_);
        return announced_;
    }

    uint64_t replaced() {
        std::lock_guard<std::mutex> g(m_);
        return replaced_;
    }
    uint64_t resumesRefused() {
        std::lock_guard<std::mutex> g(m_);
        return resumeRefused_;
    }
    size_t openConnections() {
        std::lock_guard<std::mutex> g(m_);
        return entries_.size();
    }
    bool controlOpen() {
        std::lock_guard<std::mutex> g(m_);
        return controlOpenLocked();
    }

    // Returns once the closes queued so far have run (tests).
    void flushClosesForTest() {
        std::unique_lock<std::mutex> g(qm_);
        qcv_.wait(g, [&] { return queue_.empty() && !busy_; });
    }

private:
    struct Entry {
        uint64_t token = 0;
        std::string peerIp;
        Channel channel = Channel::Control;
        std::optional<Key> sessionKey;
        std::optional<SessionId> authSession;
        uint64_t epoch = 0;
        CloseFn close;
    };

    void log(const std::string& s) {
        if (log_) log_(s);
    }
    bool controlOpenLocked() const {
        return std::any_of(entries_.begin(), entries_.end(), [](const Entry& e) { return e.channel == Channel::Control; });
    }
    void eraseToken(uint64_t token) {
        entries_.erase(std::remove_if(entries_.begin(), entries_.end(), [&](const Entry& e) { return e.token == token; }),
                       entries_.end());
    }

    // The announced session: the newest control entry with a key. A new
    // generation whenever the peer or the key changes. Caller holds m_.
    std::shared_ptr<const UdpSession> recomputeLocked() {
        const Entry* src = nullptr;
        for (const auto& e : entries_)
            if (e.channel == Channel::Control && e.sessionKey) src = &e;
        const bool same = (!src && !announcedKey_) ||
                          (src && announcedKey_ && src->peerIp == announcedIp_ && *src->sessionKey == *announcedKey_);
        if (same) return nullptr;
        auto s = std::make_shared<UdpSession>();
        s->generation = generation_.load() + 1;
        if (src) {
            s->peerIp = src->peerIp;
            s->tags = tags_ ? tags_(*src->sessionKey) : nullptr;
            announcedIp_ = src->peerIp;
            announcedKey_ = src->sessionKey;
        } else {
            announcedIp_.clear();
            announcedKey_.reset();
        }
        announced_ = src ? std::shared_ptr<const UdpSession>(s) : nullptr;
        generation_.store(s->generation, std::memory_order_release);
        return s;
    }

    void publish(const std::shared_ptr<const UdpSession>& s) {
        if (!s) return;
        if (s->peerIp.empty())
            log("session.link gen=" + std::to_string(s->generation) + " none");
        else
            log("session.link gen=" + std::to_string(s->generation) + " peer=" + s->peerIp + " udp=" +
                (s->tags ? "tagged" : "untagged_dropped"));
    }

    void enqueueCloses(std::vector<Entry> voided, CloseReason why, std::function<void(const Entry&)> note) {
        std::lock_guard<std::mutex> g(qm_);
        for (auto& e : voided) queue_.push_back(Job{std::move(e), why, note});
        if (!worker_.joinable()) worker_ = std::thread([this] { runCloses(); });
        qcv_.notify_all();
    }

    struct Job {
        Entry e;
        CloseReason why;
        std::function<void(const Entry&)> note;
    };
    void runCloses() {
        std::unique_lock<std::mutex> g(qm_);
        for (;;) {
            qcv_.wait(g, [&] { return qStop_ || !queue_.empty(); });
            if (queue_.empty()) return;
            Job j = std::move(queue_.front());
            queue_.pop_front();
            busy_ = true;
            g.unlock();
            if (j.note) j.note(j.e);
            if (j.e.close) j.e.close(j.why);
            g.lock();
            busy_ = false;
            qcv_.notify_all();
        }
    }

    UdpTagsFactory tags_;
    LogFn log_;
    std::mutex orderM_;  // taken before m_: changes reach the log in order
    std::function<void()> onVoid_;  // run under orderM_, never under m_
    std::mutex m_;
    std::vector<Entry> entries_;
    uint64_t nextToken_ = 0;
    uint64_t epoch_ = 0;
    uint64_t policy_ = 0;
    std::optional<SessionId> currentId_;
    std::shared_ptr<const UdpSession> announced_;
    std::string announcedIp_;
    std::optional<Key> announcedKey_;
    std::unordered_map<uint64_t, CloseReason> why_;  // voided tokens, until their end()
    std::atomic<uint64_t> generation_{0};
    uint64_t replaced_ = 0, resumeRefused_ = 0;

    std::mutex qm_;
    std::condition_variable qcv_;
    std::deque<Job> queue_;
    bool busy_ = false;
    bool qStop_ = false;
    std::thread worker_;
};

// ------------------------------------------------------------- UDP checks

// MRM1's 64-packet anti-replay window (MouseMoveUDPServer.swift).
class SeqReplayWindow {
public:
    static constexpr uint32_t kSize = 64;
    enum class Verdict { Newest, Late, Duplicate, TooOld };

    Verdict check(uint32_t seq) {
        if (!have_) {
            have_ = true;
            highest_ = seq;
            bits_ = 1;
            return Verdict::Newest;
        }
        if (int32_t(seq - highest_) > 0) {
            const uint32_t shift = seq - highest_;
            bits_ = shift >= kSize ? 1 : (bits_ << shift) | 1;
            highest_ = seq;
            return Verdict::Newest;
        }
        const uint32_t back = highest_ - seq;
        if (back >= kSize) return Verdict::TooOld;
        return (bits_ & (uint64_t(1) << back)) ? Verdict::Duplicate : Verdict::Late;
    }
    void mark(uint32_t seq) {
        if (!have_) return;
        const uint32_t back = highest_ - seq;
        if (back < kSize) bits_ |= uint64_t(1) << back;
    }

private:
    bool have_ = false;
    uint32_t highest_ = 0;
    uint64_t bits_ = 0;
};

// Repeated refusals (a viewer reconnecting in a loop) log once per 10 s
// per event and peer; at most 1024 keys (ConnAuth.swift AuthLogThrottle).
class AuthLogThrottle {
public:
    static constexpr double kWindow = 10;
    static constexpr size_t kMaxKeys = 1024;

    AuthLogThrottle(std::function<double()> now, std::function<void(const std::string&)> write)
        : now_(std::move(now)), write_(std::move(write)) {}

    void log(const std::string& event, const std::string& peer, const std::string& line) {
        std::string key = event + " " + peer;
        static const std::string kOverflow = "auth.overflow *";
        std::unique_lock<std::mutex> g(m_);
        const double t = now_();
        if (!last_.count(key) && last_.size() >= kMaxKeys - 1) {
            for (auto it = last_.begin(); it != last_.end();) {
                if (t - it->second.at < kWindow) ++it;
                else it = last_.erase(it);
            }
            if (last_.size() >= kMaxKeys - 1) key = kOverflow;
        }
        auto it = last_.find(key);
        if (it != last_.end() && t - it->second.at < kWindow) {
            it->second.skipped += 1;
            ++suppressed_;
            return;
        }
        const uint64_t skipped = it == last_.end() ? 0 : it->second.skipped;
        last_[key] = Slot{t, 0};
        g.unlock();
        std::string out = key == kOverflow ? "auth.overflow keys=" + std::to_string(kMaxKeys) + " first=" + line : line;
        if (skipped) out += " suppressed=" + std::to_string(skipped);
        if (write_) write_(out);
    }
    size_t keyCount() {
        std::lock_guard<std::mutex> g(m_);
        return last_.size();
    }
    uint64_t suppressed() {
        std::lock_guard<std::mutex> g(m_);
        return suppressed_;
    }

private:
    struct Slot {
        double at;
        uint64_t skipped;
    };
    std::mutex m_;
    std::unordered_map<std::string, Slot> last_;
    std::function<double()> now_;
    std::function<void(const std::string&)> write_;
    uint64_t suppressed_ = 0;
};

// Dropped datagrams with a bad tag: one line per 10 s at most, with
// counts. Never answers the sender (UDPAuth.swift BadTagLog).
class BadTagLog {
public:
    BadTagLog(std::string entry, std::function<double()> now, std::function<void(const std::string&)> write,
              double interval = 10)
        : entry_(std::move(entry)), now_(std::move(now)), write_(std::move(write)), interval_(interval) {}

    void drop(const std::string& peer, const char* reason) {
        std::unique_lock<std::mutex> g(m_);
        ++total_;
        ++pending_;
        lastPeer_ = peer;
        lastReason_ = reason;
        const double t = now_();
        if (t - lastLog_ < interval_) return;
        lastLog_ = t;
        const std::string line = "udp.bad_tag entry=" + entry_ + " peer=" + lastPeer_ + " reason=" + lastReason_ +
                                 " n=" + std::to_string(pending_) + " total=" + std::to_string(total_);
        pending_ = 0;
        g.unlock();
        if (write_) write_(line);
    }
    uint64_t total() {
        std::lock_guard<std::mutex> g(m_);
        return total_;
    }

private:
    std::string entry_;
    std::function<double()> now_;
    std::function<void(const std::string&)> write_;
    double interval_;
    std::mutex m_;
    uint64_t total_ = 0, pending_ = 0;
    std::string lastPeer_ = "-", lastReason_ = "-";
    double lastLog_ = -1e300;
};

// Why a received datagram's tag did not check (BadTagLog reasons).
inline const char* badTagReason(const uint8_t* p, size_t n) {
    if (n <= kTagBytes + kUdpVersionByte) return "short";
    if (!(p[kUdpVersionByte] & kUdpTagFlag)) return "no_tag";
    return "bad_tag";
}

// ------------------------------------------------------- auth failure log

// r2/r3/r4 (Pepper's PR-C review, item 6): the last counted failures and
// each failure's time for 24 hours, for the settings window (design §10).
// No password material: time, address, reason and the failure count.
struct FailureRecord {
    int64_t at = 0;
    std::string ip;
    std::string reason;
    int failures = 0;
    bool operator==(const FailureRecord&) const = default;
};

class FailureLogStore {
public:
    virtual ~FailureLogStore() = default;
    virtual std::vector<FailureRecord> loadRecords() = 0;
    virtual std::vector<int64_t> loadTimes() = 0;
    virtual void save(const std::vector<FailureRecord>& records, const std::vector<int64_t>& times) = 0;
};

constexpr size_t kFailureRecordLimit = 20;
constexpr int64_t kFailureWindowSeconds = 24 * 3600;
constexpr size_t kFailureMaxTimes = 5000;

// The kept times after one more failure at `at`: sorted, none older than
// 24 hours before the newest, at most `cap` (the newest).
inline std::vector<int64_t> prunedFailureTimes(std::vector<int64_t> all, int64_t at, size_t cap = kFailureMaxTimes) {
    all.insert(std::upper_bound(all.begin(), all.end(), at), at);
    const int64_t newest = all.back();
    all.erase(std::remove_if(all.begin(), all.end(), [&](int64_t x) { return x <= newest - kFailureWindowSeconds; }),
              all.end());
    if (all.size() > cap) all.erase(all.begin(), all.begin() + std::ptrdiff_t(all.size() - cap));
    return all;
}

struct FailureSummary {
    size_t last24h = 0;
    std::string lastIp;  // empty: none
    int64_t lastAt = 0;
    bool capped = false;  // more were kept than fit: the count is a lower bound
};

inline FailureSummary summarizeFailures(const std::vector<FailureRecord>& records, std::vector<int64_t> times,
                                        int64_t now) {
    std::sort(times.begin(), times.end());
    FailureSummary s;
    for (int64_t t : times)
        if (t > now - kFailureWindowSeconds && t <= now) ++s.last24h;
    s.capped = times.size() >= kFailureMaxTimes && !times.empty() && times.front() > now - kFailureWindowSeconds;
    if (!records.empty()) {
        s.lastIp = records.back().ip;
        s.lastAt = records.back().at;
    }
    return s;
}

// Written on its own thread, so a failed try never waits for the store.
class AuthFailureLog {
public:
    explicit AuthFailureLog(FailureLogStore& store) : store_(store) {}
    ~AuthFailureLog() {
        {
            std::lock_guard<std::mutex> g(m_);
            stop_ = true;
        }
        cv_.notify_all();
        if (worker_.joinable()) worker_.join();
    }
    AuthFailureLog(const AuthFailureLog&) = delete;
    AuthFailureLog& operator=(const AuthFailureLog&) = delete;

    void record(const std::string& ip, const std::string& reason, int failures, int64_t at) {
        std::lock_guard<std::mutex> g(m_);
        q_.push_back(FailureRecord{at, ip, reason.substr(0, 40), failures});
        if (!worker_.joinable()) worker_ = std::thread([this] { run(); });
        cv_.notify_all();
    }
    void flush() {
        std::unique_lock<std::mutex> g(m_);
        cv_.wait(g, [&] { return q_.empty() && !busy_; });
    }

private:
    void run() {
        std::unique_lock<std::mutex> g(m_);
        for (;;) {
            cv_.wait(g, [&] { return stop_ || !q_.empty(); });
            if (q_.empty()) return;
            const FailureRecord r = q_.front();
            q_.pop_front();
            busy_ = true;
            g.unlock();
            auto all = store_.loadRecords();
            all.push_back(r);
            if (all.size() > kFailureRecordLimit)
                all.erase(all.begin(), all.begin() + std::ptrdiff_t(all.size() - kFailureRecordLimit));
            store_.save(all, prunedFailureTimes(store_.loadTimes(), r.at));
            g.lock();
            busy_ = false;
            cv_.notify_all();
        }
    }

    FailureLogStore& store_;
    std::mutex m_;
    std::condition_variable cv_;
    std::deque<FailureRecord> q_;
    bool busy_ = false, stop_ = false;
    std::thread worker_;
};

}  // namespace jlh::auth
