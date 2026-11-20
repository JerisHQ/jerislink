#pragma once
// Connection password, viewer side (design v0.4.0, PR-B).
//
// Every TCP connection to the Mac host proves, before its first real
// message, that this PC holds K = PBKDF2-HMAC-SHA256(NFC(password), salt,
// 600,000) for the channel it is about to use:
//
//     host   -> 0x05 AUTH_CHALLENGE  host_nonce(32) salt(16) iter(u32) kdf(1) host_id(16)
//     viewer -> 0x03 AUTH_RESPONSE   client_nonce(32) mac_c(32)
//     host   -> 0x04 AUTH_RESULT     ok mac_h(32) session_id(8) | fail tries | locked s | ...
//
// The viewer checks mac_h too (mutual check). The password never leaves the
// PC and is never written down: only K, sealed with DPAPI (CurrentUser), and
// only when "Remember password" is ticked. K is derived once per host and
// cached, so reconnects never run PBKDF2 again.
//
// Hosts that do not send 0x05:
//   - transition host (v0.4.0, no password yet): after a short wait the
//     viewer sends a 0x03 probe; the host answers open_ip_only and the
//     connection carries on as in 0.3.
//   - 0.3.x host: answers nothing; 2 s after connect the viewer gives up
//     with "host too old". No password is sent and there is no fallback to
//     an unauthenticated session.
//
// Once a connection ends with an answer the user must act on (wrong
// password, lockout, blocked, mutual check failed, old host, password
// needed), `Client` halts: no channel connects again until the launch
// screen starts a new attempt, so background reconnects cannot spend the
// lockout budget. personal/protocol/auth_vectors.json has vectors for the
// maths here; conn_auth_test.cpp checks them.

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <initializer_list>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#ifdef _MSC_VER
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "normaliz.lib")
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

namespace jl::auth {

constexpr uint32_t kIterations = 600000;
constexpr uint32_t kMinIterations = 100000;
constexpr uint32_t kMaxIterations = 10000000;
constexpr uint8_t kKdfPbkdf2Sha256 = 1;
constexpr size_t kNonceBytes = 32;
constexpr size_t kSaltBytes = 16;
constexpr size_t kHostIdBytes = 16;
constexpr size_t kKeyBytes = 32;
constexpr size_t kMacBytes = 32;
constexpr size_t kSessionIdBytes = 8;
constexpr size_t kChallengeBytes = kNonceBytes + kSaltBytes + 4 + 1 + kHostIdBytes;  // 69
constexpr size_t kResponseBytes = kNonceBytes + kMacBytes;                          // 64

constexpr uint8_t kTypeResponse = 0x03;
constexpr uint8_t kTypeResult = 0x04;
constexpr uint8_t kTypeChallenge = 0x05;

// No 0x05 or 0x04 within this long after connect: a 0.3.x host (design §8).
constexpr int kOldHostTimeoutMs = 2000;
// First wait for 0x05 before the transition probe (design §9).
constexpr int kProbeWaitMs = 300;
// The host gives the viewer 5 s after AUTH_CHALLENGE; a RESULT that takes
// longer than this is a dead connection.
constexpr int kResultTimeoutMs = 5000;

enum class Channel : uint8_t { Control = 1, Clipboard = 2, File = 3, Ping = 4 };

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
using Key = std::array<uint8_t, kKeyBytes>;
using HostId = std::array<uint8_t, kHostIdBytes>;
using Salt = std::array<uint8_t, kSaltBytes>;

inline void wipe(void* p, size_t n) { if (p && n) SecureZeroMemory(p, n); }
inline void wipe(std::wstring& s) { if (!s.empty()) wipe(&s[0], s.size() * sizeof(wchar_t)); s.clear(); }
inline void wipe(std::string& s) { if (!s.empty()) wipe(&s[0], s.size()); s.clear(); }

inline std::string hex(const uint8_t* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { out.push_back(d[p[i] >> 4]); out.push_back(d[p[i] & 15]); }
    return out;
}

// MARK: Maths

// NFC, then UTF-8. Empty or invalid input gives an empty result.
inline std::string normalizedUtf8(const std::wstring& password) {
    if (password.empty()) return {};
    std::wstring nfc;
    int need = NormalizeString(NormalizationC, password.c_str(), int(password.size()), nullptr, 0);
    for (int attempt = 0; attempt < 4 && need > 0; ++attempt) {
        nfc.assign(size_t(need), L'\0');
        int got = NormalizeString(NormalizationC, password.c_str(), int(password.size()), &nfc[0], need);
        if (got > 0) { nfc.resize(size_t(got)); break; }
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) { wipe(nfc); return {}; }
        need = -got;
        nfc.clear();
    }
    if (nfc.empty()) return {};
    int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, nfc.c_str(), int(nfc.size()), nullptr, 0, nullptr, nullptr);
    std::string out;
    if (bytes > 0) {
        out.assign(size_t(bytes), '\0');
        WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, nfc.c_str(), int(nfc.size()), &out[0], bytes, nullptr, nullptr);
    }
    wipe(nfc);
    return out;
}

inline bool pbkdf2(const std::string& utf8, const uint8_t* salt, size_t saltLen, uint32_t iterations, uint8_t* out, size_t outLen) {
    if (utf8.empty() || iterations == 0) return false;
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG))) return false;
    NTSTATUS st = BCryptDeriveKeyPBKDF2(alg, reinterpret_cast<PUCHAR>(const_cast<char*>(utf8.data())), ULONG(utf8.size()),
                                        const_cast<PUCHAR>(salt), ULONG(saltLen), iterations, out, ULONG(outLen), 0);
    BCryptCloseAlgorithmProvider(alg, 0);
    return NT_SUCCESS(st);
}

inline std::optional<Key> deriveKey(const std::wstring& password, const uint8_t* salt, size_t saltLen, uint32_t iterations) {
    std::string utf8 = normalizedUtf8(password);
    Key k{};
    bool ok = pbkdf2(utf8, salt, saltLen, iterations, k.data(), k.size());
    wipe(utf8);
    if (!ok) { wipe(k.data(), k.size()); return std::nullopt; }
    return k;
}

inline std::array<uint8_t, 32> hmacSha256(const uint8_t* key, size_t keyLen, std::initializer_list<std::pair<const uint8_t*, size_t>> parts) {
    std::array<uint8_t, 32> out{};
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE h = nullptr;
    if (NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG))) {
        if (NT_SUCCESS(BCryptCreateHash(alg, &h, nullptr, 0, const_cast<PUCHAR>(key), ULONG(keyLen), 0))) {
            bool ok = true;
            for (const auto& part : parts) {
                if (part.second && !NT_SUCCESS(BCryptHashData(h, const_cast<PUCHAR>(part.first), ULONG(part.second), 0))) ok = false;
            }
            if (!ok || !NT_SUCCESS(BCryptFinishHash(h, out.data(), ULONG(out.size()), 0))) out.fill(0);
            BCryptDestroyHash(h);
        }
        BCryptCloseAlgorithmProvider(alg, 0);
    }
    return out;
}

inline std::array<uint8_t, 32> macClient(const Key& k, const uint8_t* hostNonce, const uint8_t* clientNonce, Channel ch, const uint8_t* hostId) {
    const uint8_t label[4] = {'j', 'l', '-', 'c'};
    const uint8_t c = uint8_t(ch);
    return hmacSha256(k.data(), k.size(), {{label, 4}, {hostNonce, kNonceBytes}, {clientNonce, kNonceBytes}, {&c, 1}, {hostId, kHostIdBytes}});
}

inline std::array<uint8_t, 32> macHost(const Key& k, const uint8_t* hostNonce, const uint8_t* clientNonce, Channel ch) {
    const uint8_t label[4] = {'j', 'l', '-', 'h'};
    const uint8_t c = uint8_t(ch);
    return hmacSha256(k.data(), k.size(), {{label, 4}, {hostNonce, kNonceBytes}, {clientNonce, kNonceBytes}, {&c, 1}});
}

inline bool constantTimeEqual(const uint8_t* a, const uint8_t* b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) diff |= uint8_t(a[i] ^ b[i]);
    return diff == 0;
}

inline bool randomBytes(uint8_t* p, size_t n) {
    return NT_SUCCESS(BCryptGenRandom(nullptr, p, ULONG(n), BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}

// MARK: Wire

struct Challenge {
    std::array<uint8_t, kNonceBytes> hostNonce{};
    Salt salt{};
    uint32_t iterations = 0;
    uint8_t kdf = 0;
    HostId hostId{};

    static std::optional<Challenge> decode(const Bytes& p) {
        if (p.size() != kChallengeBytes) return std::nullopt;
        Challenge c;
        std::memcpy(c.hostNonce.data(), p.data(), kNonceBytes);
        std::memcpy(c.salt.data(), p.data() + 32, kSaltBytes);
        c.iterations = uint32_t(p[48]) << 24 | uint32_t(p[49]) << 16 | uint32_t(p[50]) << 8 | uint32_t(p[51]);
        c.kdf = p[52];
        std::memcpy(c.hostId.data(), p.data() + 53, kHostIdBytes);
        return c;
    }
};

struct Result {
    enum class Status : uint8_t { Ok = 0, Fail = 1, Locked = 2, Blocked = 3, AuthRequired = 4, OpenIpOnly = 5 };
    Status status = Status::Fail;
    std::array<uint8_t, kMacBytes> macH{};
    std::array<uint8_t, kSessionIdBytes> sessionId{};
    uint8_t triesLeft = 0;
    uint32_t retrySeconds = 0;

    static std::optional<Result> decode(const Bytes& p) {
        if (p.empty()) return std::nullopt;
        Result r;
        switch (p[0]) {
        case 0:
            if (p.size() != 1 + kMacBytes + kSessionIdBytes) return std::nullopt;
            r.status = Status::Ok;
            std::memcpy(r.macH.data(), p.data() + 1, kMacBytes);
            std::memcpy(r.sessionId.data(), p.data() + 1 + kMacBytes, kSessionIdBytes);
            return r;
        case 1:
            if (p.size() != 2) return std::nullopt;
            r.status = Status::Fail; r.triesLeft = p[1];
            return r;
        case 2:
            if (p.size() != 5) return std::nullopt;
            r.status = Status::Locked;
            r.retrySeconds = uint32_t(p[1]) << 24 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 8 | uint32_t(p[4]);
            return r;
        case 3: if (p.size() != 1) return std::nullopt; r.status = Status::Blocked; return r;
        case 4: if (p.size() != 1) return std::nullopt; r.status = Status::AuthRequired; return r;
        case 5: if (p.size() != 1) return std::nullopt; r.status = Status::OpenIpOnly; return r;
        default: return std::nullopt;
        }
    }
};

inline Bytes frame(uint8_t type, const uint8_t* payload, size_t n) {
    Bytes b{'M', 'R', 'C', '1', 1, type, uint8_t(n >> 8), uint8_t(n)};
    b.insert(b.end(), payload, payload + n);
    return b;
}

// MARK: Socket I/O with deadlines (independent of SO_RCVTIMEO)

using Clock = std::chrono::steady_clock;

inline int msUntil(Clock::time_point deadline) {
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
    return ms < 0 ? 0 : int(ms);
}

enum class Io { Ok, Timeout, Closed };

inline Io waitReadable(SOCKET s, Clock::time_point deadline) {
    for (;;) {
        int ms = msUntil(deadline);
        fd_set rs; FD_ZERO(&rs); FD_SET(s, &rs);
        timeval tv{ms / 1000, (ms % 1000) * 1000};
        int rc = select(0, &rs, nullptr, nullptr, &tv);
        if (rc > 0) return Io::Ok;
        if (rc == SOCKET_ERROR) return Io::Closed;
        if (ms == 0) return Io::Timeout;
    }
}

inline Io recvExactBy(SOCKET s, uint8_t* p, size_t n, Clock::time_point deadline) {
    size_t off = 0;
    while (off < n) {
        Io w = waitReadable(s, deadline);
        if (w != Io::Ok) return w;
        int r = recv(s, reinterpret_cast<char*>(p + off), int(n - off), 0);
        if (r <= 0) return Io::Closed;
        off += size_t(r);
    }
    return Io::Ok;
}

inline Io recvFrame(SOCKET s, Clock::time_point deadline, uint8_t& type, Bytes& payload) {
    uint8_t h[8]{};
    Io io = recvExactBy(s, h, 8, deadline);
    if (io != Io::Ok) return io;
    if (!(h[0] == 'M' && h[1] == 'R' && h[2] == 'C' && h[3] == '1' && h[4] == 1)) return Io::Closed;
    type = h[5];
    size_t len = size_t(h[6]) << 8 | h[7];
    payload.assign(len, 0);
    if (len) {
        // The rest of a frame that has started arrives promptly.
        io = recvExactBy(s, payload.data(), len, std::max(deadline, Clock::now() + std::chrono::milliseconds(1000)));
    }
    return io;
}

inline bool sendAllBytes(SOCKET s, const Bytes& b) {
    size_t off = 0;
    while (off < b.size()) {
        int r = send(s, reinterpret_cast<const char*>(b.data() + off), int(b.size() - off), 0);
        if (r <= 0) return false;
        off += size_t(r);
    }
    return true;
}

// MARK: Saved keys (DPAPI, CurrentUser)

// One file per host: <dir>\<hex host_id>.bin = CryptProtectData("JLK1" |
// host_id | salt | iter | K). The password itself is never stored.
class HostKeyStore {
public:
    struct Entry { HostId hostId{}; Salt salt{}; uint32_t iterations = 0; Key key{}; };

    explicit HostKeyStore(std::wstring dir) : dir_(std::move(dir)) {}

    // %LOCALAPPDATA%\JerisLink\hosts
    static std::wstring defaultDir() {
        wchar_t buf[MAX_PATH]{};
        DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", buf, MAX_PATH);
        if (n == 0 || n >= MAX_PATH) return {};
        return std::wstring(buf) + L"\\JerisLink\\hosts";
    }

    const std::wstring& dir() const { return dir_; }

    std::wstring pathFor(const HostId& id) const {
        std::string h = hex(id.data(), id.size());
        return dir_ + L"\\" + std::wstring(h.begin(), h.end()) + L".bin";
    }

    bool save(const Entry& e) const {
        if (dir_.empty() || !ensureDir()) return false;
        Bytes plain;
        plain.insert(plain.end(), {'J', 'L', 'K', '1'});
        plain.insert(plain.end(), e.hostId.begin(), e.hostId.end());
        plain.insert(plain.end(), e.salt.begin(), e.salt.end());
        plain.insert(plain.end(), {uint8_t(e.iterations >> 24), uint8_t(e.iterations >> 16), uint8_t(e.iterations >> 8), uint8_t(e.iterations)});
        plain.insert(plain.end(), e.key.begin(), e.key.end());
        DATA_BLOB in{DWORD(plain.size()), plain.data()};
        DATA_BLOB ent = entropy();
        DATA_BLOB out{};
        BOOL ok = CryptProtectData(&in, L"JerisLink host key", &ent, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out);
        wipe(plain.data(), plain.size());
        if (!ok) return false;
        const std::wstring path = pathFor(e.hostId);
        const std::wstring tmp = path + L".tmp";
        bool written = false;
        HANDLE f = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (f != INVALID_HANDLE_VALUE) {
            DWORD w = 0;
            written = WriteFile(f, out.pbData, out.cbData, &w, nullptr) && w == out.cbData;
            CloseHandle(f);
        }
        LocalFree(out.pbData);
        if (!written || !MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING)) {
            DeleteFileW(tmp.c_str());
            return false;
        }
        return true;
    }

    std::optional<Entry> load(const HostId& id) const {
        if (dir_.empty()) return std::nullopt;
        HANDLE f = CreateFileW(pathFor(id).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (f == INVALID_HANDLE_VALUE) return std::nullopt;
        Bytes sealed(4096);
        DWORD got = 0;
        BOOL r = ReadFile(f, sealed.data(), DWORD(sealed.size()), &got, nullptr);
        CloseHandle(f);
        if (!r || got == 0) return std::nullopt;
        DATA_BLOB in{got, sealed.data()};
        DATA_BLOB ent = entropy();
        DATA_BLOB out{};
        if (!CryptUnprotectData(&in, nullptr, &ent, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) return std::nullopt;
        std::optional<Entry> e;
        constexpr size_t want = 4 + kHostIdBytes + kSaltBytes + 4 + kKeyBytes;
        if (out.cbData == want && std::memcmp(out.pbData, "JLK1", 4) == 0) {
            Entry x;
            const uint8_t* p = out.pbData + 4;
            std::memcpy(x.hostId.data(), p, kHostIdBytes); p += kHostIdBytes;
            std::memcpy(x.salt.data(), p, kSaltBytes); p += kSaltBytes;
            x.iterations = uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | uint32_t(p[3]); p += 4;
            std::memcpy(x.key.data(), p, kKeyBytes);
            if (x.hostId == id) e = x;
            wipe(x.key.data(), x.key.size());
        }
        wipe(out.pbData, out.cbData);
        LocalFree(out.pbData);
        return e;
    }

    bool exists(const HostId& id) const {
        return !dir_.empty() && GetFileAttributesW(pathFor(id).c_str()) != INVALID_FILE_ATTRIBUTES;
    }

    bool remove(const HostId& id) const {
        if (dir_.empty()) return false;
        return DeleteFileW(pathFor(id).c_str()) != 0 || GetLastError() == ERROR_FILE_NOT_FOUND;
    }

private:
    static DATA_BLOB entropy() {
        static const char kEntropy[] = "org.jeris.jerislink/host-key/v1";
        return DATA_BLOB{DWORD(sizeof(kEntropy) - 1), reinterpret_cast<BYTE*>(const_cast<char*>(kEntropy))};
    }

    bool ensureDir() const {
        // Create each missing level (…\JerisLink, then …\hosts).
        for (size_t pos = dir_.find(L'\\', 3); ; pos = dir_.find(L'\\', pos + 1)) {
            std::wstring part = pos == std::wstring::npos ? dir_ : dir_.substr(0, pos);
            if (!CreateDirectoryW(part.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) return false;
            if (pos == std::wstring::npos) return true;
        }
    }

    std::wstring dir_;
};

// MARK: Outcomes

enum class Outcome {
    Ok,            // authenticated (mac_h checked)
    Open,          // transition host: open_ip_only, no password set on the Mac
    Fail,          // wrong password; triesLeft
    Locked,        // too many wrong tries; retrySeconds
    Blocked,       // this PC is on the Mac's blacklist
    AuthRequired,  // the Mac wants a password this viewer did not prove
    HostMismatch,  // OK without a valid mac_h: not the Mac that holds K
    HostTooOld,    // nothing within 2 s: a 0.3.x host
    NeedPassword,  // the Mac wants a password and none is known for it
    Retry,         // probe crossed a late challenge; reconnect once
    Network,       // connection closed / malformed: an ordinary reconnect
};

inline const char* outcomeName(Outcome o) {
    switch (o) {
    case Outcome::Ok: return "ok";
    case Outcome::Open: return "open_ip_only";
    case Outcome::Fail: return "fail";
    case Outcome::Locked: return "locked";
    case Outcome::Blocked: return "blocked";
    case Outcome::AuthRequired: return "auth_required";
    case Outcome::HostMismatch: return "host_mismatch";
    case Outcome::HostTooOld: return "host_too_old";
    case Outcome::NeedPassword: return "need_password";
    case Outcome::Retry: return "retry";
    case Outcome::Network: return "network";
    }
    return "?";
}

// The answers that need the user: the viewer stops connecting until a new
// attempt starts from the launch screen.
inline bool isTerminal(Outcome o) {
    switch (o) {
    case Outcome::Fail: case Outcome::Locked: case Outcome::Blocked: case Outcome::AuthRequired:
    case Outcome::HostMismatch: case Outcome::HostTooOld: case Outcome::NeedPassword:
        return true;
    default:
        return false;
    }
}

struct Report {
    Outcome outcome = Outcome::Network;
    uint8_t triesLeft = 0;
    uint32_t retrySeconds = 0;
    bool usedSavedKey = false;    // a Fail with a saved key: the file was deleted
};

// MARK: Client (one per host attempt; shared by every channel)

class Client {
public:
    using LogFn = std::function<void(const std::string&)>;
    using TerminalFn = std::function<void(const Report&)>;

    struct Options {
        std::wstring password;     // typed on the launch screen; wiped once K is derived
        bool remember = false;     // "Remember password" ticked
        std::wstring storeDir;     // empty: HostKeyStore::defaultDir()
        LogFn log;
    };

    explicit Client(Options o)
        : password_(std::move(o.password)), remember_(o.remember),
          store_(o.storeDir.empty() ? HostKeyStore::defaultDir() : o.storeDir), log_(std::move(o.log)) {
        wipe(o.password);
    }
    ~Client() {
        wipe(password_);
        if (key_) wipe(key_->data(), key_->size());
    }
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    void setTerminalHandler(TerminalFn fn) { std::lock_guard<std::mutex> g(m_); onTerminal_ = std::move(fn); }

    enum class Mode { Unknown, Password, Transition };
    Mode mode() const { std::lock_guard<std::mutex> g(m_); return mode_; }
    bool transition() const { return mode() == Mode::Transition; }
    bool halted() const { return halted_.load(); }
    Report lastTerminal() const { std::lock_guard<std::mutex> g(m_); return terminal_; }
    const HostKeyStore& store() const { return store_; }

    // Runs the AUTH exchange on a freshly connected TCP socket, before the
    // channel's first message. `connectMs` is how long the TCP connect took
    // (sets the transition probe wait on slow links).
    Report handshake(SOCKET s, Channel ch, double connectMs) {
        Report r = exchange(s, ch, connectMs);
        note(std::string("auth.result chan=") + channelName(ch) + " outcome=" + outcomeName(r.outcome) +
             (r.outcome == Outcome::Fail ? " tries=" + std::to_string(r.triesLeft) : std::string()) +
             (r.outcome == Outcome::Locked ? " retry_s=" + std::to_string(r.retrySeconds) : std::string()) +
             (r.usedSavedKey ? " saved_key=deleted" : std::string()));
        if (isTerminal(r.outcome)) halt(r);
        return r;
    }

private:
    Report exchange(SOCKET s, Channel ch, double connectMs) {
        Report rep;
        if (halted_) { rep = lastTerminal(); return rep; }
        const auto start = Clock::now();
        const auto oldHostDeadline = start + std::chrono::milliseconds(kOldHostTimeoutMs);
        const Mode known = mode();

        // How long to wait for 0x05 before the transition probe. A host
        // known to want a password is never probed: a probe it took as an
        // answer would count as a wrong password.
        int probeWaitMs = 0;
        if (known == Mode::Transition) {
            probeWaitMs = std::clamp(int(connectMs * 3), 100, kProbeWaitMs);
        } else if (known == Mode::Unknown) {
            probeWaitMs = std::clamp(int(connectMs * 2), kProbeWaitMs, 1500);
        }

        uint8_t type = 0;
        Bytes payload;
        bool probed = false;
        Io io = Io::Timeout;
        if (known == Mode::Password) {
            io = recvFrame(s, oldHostDeadline, type, payload);
        } else {
            io = recvFrame(s, start + std::chrono::milliseconds(probeWaitMs), type, payload);
            if (io == Io::Timeout) {
                // Transition probe: random nonce, zero MAC (design §9).
                uint8_t probe[kResponseBytes]{};
                randomBytes(probe, kNonceBytes);
                if (!sendAllBytes(s, frame(kTypeResponse, probe, sizeof(probe)))) { rep.outcome = Outcome::Network; return rep; }
                probed = true;
                note(std::string("auth.probe chan=") + channelName(ch) + " waited_ms=" + std::to_string(probeWaitMs));
                io = recvFrame(s, oldHostDeadline, type, payload);
            }
        }
        if (io == Io::Timeout) {
            note("auth.no_challenge waited_ms=" + std::to_string(kOldHostTimeoutMs) + (probed ? " probed=1" : " probed=0"));
            rep.outcome = Outcome::HostTooOld;
            return rep;
        }
        if (io == Io::Closed) { rep.outcome = Outcome::Network; return rep; }

        if (type == kTypeResult) {
            // No challenge: locked / blocked before one, or the probe answer.
            auto res = Result::decode(payload);
            if (!res) { rep.outcome = Outcome::Network; return rep; }
            if (res->status == Result::Status::OpenIpOnly) {
                if (!probed) { rep.outcome = Outcome::Network; return rep; }
                setMode(Mode::Transition);
                rep.outcome = Outcome::Open;
                return rep;
            }
            return fromResult(*res, false);
        }
        if (type != kTypeChallenge) { rep.outcome = Outcome::Network; return rep; }

        auto ch5 = Challenge::decode(payload);
        if (!ch5 || ch5->kdf != kKdfPbkdf2Sha256 || ch5->iterations < kMinIterations || ch5->iterations > kMaxIterations) {
            note("auth.bad_challenge");
            rep.outcome = Outcome::Network;
            return rep;
        }
        setMode(Mode::Password);
        if (probed) {
            // The challenge was on its way when the probe left; the host now
            // reads the probe as the answer. Drop this socket (nothing more is
            // sent) and reconnect without a probe.
            note("auth.probe_race");
            rep.outcome = Outcome::Retry;
            return rep;
        }

        bool fromStore = false;
        std::optional<Key> key = keyFor(*ch5, fromStore);
        if (!key) { rep.outcome = Outcome::NeedPassword; return rep; }

        uint8_t resp[kResponseBytes]{};
        if (!randomBytes(resp, kNonceBytes)) { wipe(key->data(), key->size()); rep.outcome = Outcome::Network; return rep; }
        auto macC = macClient(*key, ch5->hostNonce.data(), resp, ch, ch5->hostId.data());
        std::memcpy(resp + kNonceBytes, macC.data(), kMacBytes);
        if (!sendAllBytes(s, frame(kTypeResponse, resp, sizeof(resp)))) { wipe(key->data(), key->size()); rep.outcome = Outcome::Network; return rep; }

        io = recvFrame(s, Clock::now() + std::chrono::milliseconds(kResultTimeoutMs), type, payload);
        if (io != Io::Ok || type != kTypeResult) { wipe(key->data(), key->size()); rep.outcome = Outcome::Network; return rep; }
        auto res = Result::decode(payload);
        if (!res) { wipe(key->data(), key->size()); rep.outcome = Outcome::Network; return rep; }

        if (res->status == Result::Status::Ok) {
            auto want = macHost(*key, ch5->hostNonce.data(), resp, ch);
            if (!constantTimeEqual(want.data(), res->macH.data(), kMacBytes)) {
                // Not the Mac that holds K. Keep nothing from this attempt.
                note("auth.host_mismatch chan=" + std::string(channelName(ch)));
                forgetKey();
                wipe(key->data(), key->size());
                rep.outcome = Outcome::HostMismatch;
                return rep;
            }
            accept(*ch5, *key, fromStore);
            wipe(key->data(), key->size());
            rep.outcome = Outcome::Ok;
            return rep;
        }
        wipe(key->data(), key->size());
        if (res->status == Result::Status::OpenIpOnly) {
            setMode(Mode::Transition);
            rep.outcome = Outcome::Open;
            return rep;
        }
        return fromResult(*res, fromStore, &ch5->hostId);
    }

    Report fromResult(const Result& r, bool fromStore, const HostId* id = nullptr) {
        Report rep;
        switch (r.status) {
        case Result::Status::Fail:
            rep.outcome = Outcome::Fail;
            rep.triesLeft = r.triesLeft;
            // The key is wrong: forget it, and delete the saved copy at once.
            forgetKey();
            if (id && store_.exists(*id)) {
                store_.remove(*id);
                note("auth.saved_key_deleted reason=fail");
            }
            rep.usedSavedKey = fromStore;
            break;
        case Result::Status::Locked: rep.outcome = Outcome::Locked; rep.retrySeconds = r.retrySeconds; break;
        case Result::Status::Blocked: rep.outcome = Outcome::Blocked; break;
        case Result::Status::AuthRequired: rep.outcome = Outcome::AuthRequired; break;
        default: rep.outcome = Outcome::Network; break;
        }
        return rep;
    }

    // Priority: the password typed for this attempt, then K cached for the
    // same host/salt/iter, then the DPAPI copy. PBKDF2 runs at most once per
    // typed password; the lock makes concurrent channels share that run.
    std::optional<Key> keyFor(const Challenge& c, bool& fromStore) {
        std::lock_guard<std::mutex> g(keyM_);
        {
            std::lock_guard<std::mutex> g2(m_);
            if (key_ && keyHost_ == c.hostId && keySalt_ == c.salt && keyIter_ == c.iterations) {
                fromStore = keyFromStore_;
                return *key_;
            }
        }
        std::wstring pw;
        {
            std::lock_guard<std::mutex> g2(m_);
            pw = password_;
        }
        if (!pw.empty()) {
            auto t0 = Clock::now();
            auto k = deriveKey(pw, c.salt.data(), c.salt.size(), c.iterations);
            wipe(pw);
            if (!k) return std::nullopt;
            note("auth.kdf ms=" + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count()));
            std::lock_guard<std::mutex> g2(m_);
            wipe(password_);
            cache(c, *k, false);
            fromStore = false;
            return k;
        }
        if (auto e = store_.load(c.hostId)) {
            if (e->salt == c.salt && e->iterations == c.iterations) {
                std::lock_guard<std::mutex> g2(m_);
                cache(c, e->key, true);
                fromStore = true;
                Key k = e->key;
                wipe(e->key.data(), e->key.size());
                return k;
            }
            // The Mac's password changed (new salt): the saved key is stale.
            wipe(e->key.data(), e->key.size());
            store_.remove(c.hostId);
            note("auth.saved_key_stale deleted=1");
        }
        return std::nullopt;
    }

    void cache(const Challenge& c, const Key& k, bool fromStore) {
        if (key_) wipe(key_->data(), key_->size());
        key_ = k;
        keyHost_ = c.hostId;
        keySalt_ = c.salt;
        keyIter_ = c.iterations;
        keyFromStore_ = fromStore;
        keyVerified_ = false;
    }

    void forgetKey() {
        std::lock_guard<std::mutex> g(m_);
        if (key_) wipe(key_->data(), key_->size());
        key_.reset();
        wipe(password_);
    }

    // First OK for a typed password: save it if asked, else make sure no
    // old copy stays behind. Later OKs change nothing.
    void accept(const Challenge& c, const Key& k, bool fromStore) {
        bool firstOk = false;
        {
            std::lock_guard<std::mutex> g(m_);
            if (!keyVerified_) { keyVerified_ = true; firstOk = true; }
        }
        if (!firstOk || fromStore) return;
        if (remember_) {
            HostKeyStore::Entry e{c.hostId, c.salt, c.iterations, k};
            bool ok = store_.save(e);
            wipe(e.key.data(), e.key.size());
            note(std::string("auth.saved_key ") + (ok ? "written=1" : "written=0"));
        } else if (store_.exists(c.hostId)) {
            store_.remove(c.hostId);
            note("auth.saved_key_removed reason=remember_off");
        }
    }

    void setMode(Mode m) { std::lock_guard<std::mutex> g(m_); mode_ = m; }

    void halt(const Report& r) {
        TerminalFn fn;
        {
            std::lock_guard<std::mutex> g(m_);
            if (halted_) return;
            terminal_ = r;
            halted_ = true;
            fn = onTerminal_;
        }
        if (fn) fn(r);
    }

    void note(const std::string& s) const { if (log_) log_(s); }

    mutable std::mutex m_;
    std::mutex keyM_;
    std::wstring password_;
    bool remember_ = false;
    HostKeyStore store_;
    LogFn log_;
    TerminalFn onTerminal_;
    Mode mode_ = Mode::Unknown;
    std::optional<Key> key_;
    HostId keyHost_{};
    Salt keySalt_{};
    uint32_t keyIter_ = 0;
    bool keyFromStore_ = false;
    bool keyVerified_ = false;
    std::atomic<bool> halted_{false};
    Report terminal_;
};

// MARK: Process-wide hook for the channels

// The viewer sets this once per session attempt; tests and tools leave it
// empty, and the channels then connect without AUTH as before.
inline std::shared_ptr<Client>& currentSlot() {
    static std::shared_ptr<Client> slot;
    return slot;
}
inline std::mutex& currentMutex() {
    static std::mutex m;
    return m;
}
inline std::shared_ptr<Client> current() {
    std::lock_guard<std::mutex> g(currentMutex());
    return currentSlot();
}
inline void setCurrent(std::shared_ptr<Client> c) {
    std::lock_guard<std::mutex> g(currentMutex());
    currentSlot() = std::move(c);
}

// Before connecting: false while the current attempt is halted.
inline bool mayConnect() {
    auto c = current();
    return !c || !c->halted();
}

// After connecting: true when the channel may send its first message.
inline bool gate(SOCKET s, Channel ch, double connectMs) {
    auto c = current();
    if (!c) return true;
    Report r = c->handshake(s, ch, connectMs);
    return r.outcome == Outcome::Ok || r.outcome == Outcome::Open;
}

inline double msSince(Clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
}

}  // namespace jl::auth
