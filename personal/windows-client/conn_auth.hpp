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
// lockout budget. Channels also take connectSlot() before they connect, so
// only one connection at a time can probe or answer a challenge. What a host
// answered (password / transition) is kept per host address, so a host known
// to want a password is not probed again by a later attempt.
//
// open_ip_only is accepted only as the answer to our probe on a host that
// sent no challenge; after a challenge it means the host skipped mac_h
// (host identity mismatch). If CNG cannot compute a MAC nothing is sent
// (LocalError). A probe that crosses a late challenge is read by a PR-A host
// as a wrong try; the host's answer decides between one reconnect without a
// probe and stopping for the user. A saved key that fails or goes stale is
// never loaded again, even when its file could not be deleted.
// personal/protocol/auth_vectors.json has vectors for the maths here;
// conn_auth_test.cpp checks them.

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
using HostId = std::array<uint8_t, kHostIdBytes>;
using Salt = std::array<uint8_t, kSaltBytes>;

inline void wipe(void* p, size_t n) { if (p && n) SecureZeroMemory(p, n); }
inline void wipe(std::wstring& s) { if (!s.empty()) wipe(&s[0], s.size() * sizeof(wchar_t)); s.clear(); }
inline void wipe(std::string& s) { if (!s.empty()) wipe(&s[0], s.size()); s.clear(); }

// K. Every copy, temporaries included (PBKDF2 output, the DPAPI copy, the
// cache), is wiped when it goes out of scope.
struct Key : std::array<uint8_t, kKeyBytes> {
    Key() : std::array<uint8_t, kKeyBytes>{} {}
    Key(const Key&) = default;
    Key& operator=(const Key&) = default;
    ~Key() { wipe(data(), size()); }
};

using Mac = std::array<uint8_t, kMacBytes>;

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
        wipe(nfc);  // a partial NFC copy may already hold password text
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
    Key k;
    bool ok = pbkdf2(utf8, salt, saltLen, iterations, k.data(), k.size());
    wipe(utf8);
    if (!ok) return std::nullopt;
    return k;
}

// Tests only: the next n HMAC computations fail as if CNG had failed.
inline std::atomic<int>& hmacFaultsForTest() {
    static std::atomic<int> n{0};
    return n;
}

// False when CNG fails; `out` is then all zero and must not be used (no
// handshake goes on with it).
inline bool hmacSha256(const uint8_t* key, size_t keyLen, std::initializer_list<std::pair<const uint8_t*, size_t>> parts, Mac& out) {
    out.fill(0);
    if (hmacFaultsForTest().load() > 0 && hmacFaultsForTest().fetch_sub(1) > 0) return false;
    bool ok = false;
    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE h = nullptr;
    if (NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG))) {
        if (NT_SUCCESS(BCryptCreateHash(alg, &h, nullptr, 0, const_cast<PUCHAR>(key), ULONG(keyLen), 0))) {
            ok = true;
            for (const auto& part : parts) {
                if (part.second && !NT_SUCCESS(BCryptHashData(h, const_cast<PUCHAR>(part.first), ULONG(part.second), 0))) ok = false;
            }
            if (!ok || !NT_SUCCESS(BCryptFinishHash(h, out.data(), ULONG(out.size()), 0))) ok = false;
            BCryptDestroyHash(h);
        }
        BCryptCloseAlgorithmProvider(alg, 0);
    }
    if (!ok) out.fill(0);
    return ok;
}

inline std::optional<Mac> macClient(const Key& k, const uint8_t* hostNonce, const uint8_t* clientNonce, Channel ch, const uint8_t* hostId) {
    const uint8_t label[4] = {'j', 'l', '-', 'c'};
    const uint8_t c = uint8_t(ch);
    Mac out;
    if (!hmacSha256(k.data(), k.size(), {{label, 4}, {hostNonce, kNonceBytes}, {clientNonce, kNonceBytes}, {&c, 1}, {hostId, kHostIdBytes}}, out)) return std::nullopt;
    return out;
}

inline std::optional<Mac> macHost(const Key& k, const uint8_t* hostNonce, const uint8_t* clientNonce, Channel ch) {
    const uint8_t label[4] = {'j', 'l', '-', 'h'};
    const uint8_t c = uint8_t(ch);
    Mac out;
    if (!hmacSha256(k.data(), k.size(), {{label, 4}, {hostNonce, kNonceBytes}, {clientNonce, kNonceBytes}, {&c, 1}}, out)) return std::nullopt;
    return out;
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

// A thread that may be told to give up (the control channel's reconnect
// worker, see ControlChannel::stop()) points this at its flag. Waits then
// end within kCancelSliceMs: shutdown() does not wake select() on Windows.
inline thread_local const std::atomic<bool>* tCancel = nullptr;
constexpr int kCancelSliceMs = 50;
inline bool cancelled() { return tCancel && tCancel->load(); }

inline Io waitReadable(SOCKET s, Clock::time_point deadline) {
    for (;;) {
        if (cancelled()) return Io::Closed;
        int ms = msUntil(deadline);
        const int slice = tCancel ? std::min(ms, kCancelSliceMs) : ms;
        fd_set rs; FD_ZERO(&rs); FD_SET(s, &rs);
        timeval tv{slice / 1000, (slice % 1000) * 1000};
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

// Reads MRC1 frames and keeps a part-read frame across deadlines: a header
// split over the probe wait is finished by the next read, not dropped.
class FrameReader {
public:
    explicit FrameReader(SOCKET s) : s_(s) {}

    // Some bytes of the next frame have arrived.
    bool started() const { return have_ > 0; }

    Io next(Clock::time_point deadline, uint8_t& type, Bytes& payload) {
        Io io = fill(h_, sizeof(h_), have_, deadline);
        if (io != Io::Ok) return io;
        if (!(h_[0] == 'M' && h_[1] == 'R' && h_[2] == 'C' && h_[3] == '1' && h_[4] == 1)) return Io::Closed;
        const size_t len = size_t(h_[6]) << 8 | h_[7];
        if (!bodyStarted_) { body_.assign(len, 0); bodyHave_ = 0; bodyStarted_ = true; }
        // The rest of a frame that has started arrives promptly.
        io = fill(body_.data(), len, bodyHave_, std::max(deadline, Clock::now() + std::chrono::milliseconds(1000)));
        if (io != Io::Ok) return io;
        type = h_[5];
        payload = std::move(body_);
        body_.clear();
        have_ = 0;
        bodyHave_ = 0;
        bodyStarted_ = false;
        return Io::Ok;
    }

private:
    Io fill(uint8_t* p, size_t n, size_t& got, Clock::time_point deadline) {
        while (got < n) {
            Io w = waitReadable(s_, deadline);
            if (w != Io::Ok) return w;
            int r = recv(s_, reinterpret_cast<char*>(p + got), int(n - got), 0);
            if (r <= 0) return Io::Closed;
            got += size_t(r);
        }
        return Io::Ok;
    }

    SOCKET s_;
    uint8_t h_[8]{};
    size_t have_ = 0;
    Bytes body_;
    size_t bodyHave_ = 0;
    bool bodyStarted_ = false;
};

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
    struct Entry { HostId hostId{}; Salt salt{}; uint32_t iterations = 0; Key key; };

    // What remove() did. Emptied: the file could not be deleted, so it was
    // cut to zero bytes and never loads again.
    enum class Removal { Deleted, Missing, Emptied, Failed };
    static const char* removalName(Removal r) {
        switch (r) {
        case Removal::Deleted: return "deleted";
        case Removal::Missing: return "missing";
        case Removal::Emptied: return "emptied";
        case Removal::Failed: return "failed";
        }
        return "?";
    }

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
        }
        wipe(out.pbData, out.cbData);
        LocalFree(out.pbData);
        return e;
    }

    bool exists(const HostId& id) const {
        return !dir_.empty() && GetFileAttributesW(pathFor(id).c_str()) != INVALID_FILE_ATTRIBUTES;
    }

    Removal remove(const HostId& id) const {
        if (dir_.empty()) return Removal::Failed;
        const std::wstring path = pathFor(id);
        if (DeleteFileW(path.c_str())) return Removal::Deleted;
        const DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) return Removal::Missing;
        HANDLE f = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, TRUNCATE_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (f != INVALID_HANDLE_VALUE) { CloseHandle(f); return Removal::Emptied; }
        return Removal::Failed;
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
    LocalError,    // Windows could not compute the HMAC: nothing was sent
    RaceUnanswered,  // probe crossed a late challenge, the host said nothing: maybe one try spent
    Retry,         // probe crossed a late challenge and cost one try; reconnect once
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
    case Outcome::LocalError: return "local_error";
    case Outcome::RaceUnanswered: return "race_unanswered";
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
    case Outcome::LocalError: case Outcome::RaceUnanswered:
        return true;
    default:
        return false;
    }
}

struct Report {
    Outcome outcome = Outcome::Network;
    uint8_t triesLeft = 0;
    uint32_t retrySeconds = 0;
    bool usedSavedKey = false;    // a Fail with a saved key (see savedKeyFile for what removal did)
    bool probeRace = false;       // the host counted our transition probe as a wrong try
    const char* savedKeyFile = nullptr;  // removal result when a saved key was dropped
};

// MARK: Saved keys judged invalid

// A saved key that failed (or went stale) is never loaded again, even if
// deleting its file did not work: for this process (every later Client,
// e.g. the next Connect on the launch screen) and, through
// JERISLINK_DISTRUSTED_HOSTS, the process a session relaunches into.
inline std::mutex& distrustMutex() { static std::mutex m; return m; }
inline std::vector<HostId>& distrustList() { static std::vector<HostId> v; return v; }
inline void distrustHost(const HostId& id) {
    std::lock_guard<std::mutex> g(distrustMutex());
    auto& v = distrustList();
    if (std::find(v.begin(), v.end(), id) == v.end() && v.size() < 64) v.push_back(id);
}
// The user proved a new key for this host and it was saved: the mark goes,
// so the next start (and a relaunch) loads the new copy.
inline void undistrustHost(const HostId& id) {
    std::lock_guard<std::mutex> g(distrustMutex());
    auto& v = distrustList();
    v.erase(std::remove(v.begin(), v.end(), id), v.end());
}
inline bool hostDistrusted(const HostId& id) {
    std::lock_guard<std::mutex> g(distrustMutex());
    const auto& v = distrustList();
    return std::find(v.begin(), v.end(), id) != v.end();
}
// Comma-separated host_id hex, for the relaunch environment.
inline std::string encodeDistrusted() {
    std::lock_guard<std::mutex> g(distrustMutex());
    std::string out;
    for (const auto& id : distrustList()) {
        if (!out.empty()) out.push_back(',');
        out += hex(id.data(), id.size());
    }
    return out;
}
inline void loadDistrusted(const std::string& text) {
    size_t pos = 0;
    while (pos < text.size()) {
        size_t end = text.find(',', pos);
        if (end == std::string::npos) end = text.size();
        const std::string item = text.substr(pos, end - pos);
        pos = end + 1;
        if (item.size() != kHostIdBytes * 2) continue;
        HostId id{};
        bool ok = true;
        for (size_t i = 0; i < kHostIdBytes && ok; ++i) {
            unsigned v = 0;
            for (int j = 0; j < 2; ++j) {
                const char c = item[i * 2 + j];
                v <<= 4;
                if (c >= '0' && c <= '9') v |= unsigned(c - '0');
                else if (c >= 'a' && c <= 'f') v |= unsigned(c - 'a' + 10);
                else if (c >= 'A' && c <= 'F') v |= unsigned(c - 'A' + 10);
                else ok = false;
            }
            id[i] = uint8_t(v);
        }
        if (ok) distrustHost(id);
    }
}
inline void clearDistrustedForTest() {
    std::lock_guard<std::mutex> g(distrustMutex());
    distrustList().clear();
}

// MARK: Known host mode

// What a host answered last time, per host address (ip:port of its control
// port): for this process (every later Client, e.g. the next Connect) and,
// for Password, through JERISLINK_PASSWORD_HOSTS the process a session
// relaunches into. A host known to want a password is never probed again.
enum class HostMode { Unknown, Password, Transition };
inline std::mutex& knownModeMutex() { static std::mutex m; return m; }
inline std::vector<std::pair<std::string, HostMode>>& knownModeList() {
    static std::vector<std::pair<std::string, HostMode>> v;
    return v;
}
inline HostMode knownMode(const std::string& host) {
    if (host.empty()) return HostMode::Unknown;
    std::lock_guard<std::mutex> g(knownModeMutex());
    for (const auto& e : knownModeList()) if (e.first == host) return e.second;
    return HostMode::Unknown;
}
inline void rememberMode(const std::string& host, HostMode m) {
    if (host.empty()) return;
    std::lock_guard<std::mutex> g(knownModeMutex());
    auto& v = knownModeList();
    auto it = std::find_if(v.begin(), v.end(), [&](const auto& e) { return e.first == host; });
    if (m == HostMode::Unknown) { if (it != v.end()) v.erase(it); return; }
    if (it != v.end()) it->second = m;
    else if (v.size() < 64) v.emplace_back(host, m);
}
// Comma-separated ip:port of hosts known to want a password.
inline std::string encodePasswordHosts() {
    std::lock_guard<std::mutex> g(knownModeMutex());
    std::string out;
    for (const auto& e : knownModeList()) {
        if (e.second != HostMode::Password) continue;
        if (!out.empty()) out.push_back(',');
        out += e.first;
    }
    return out;
}
inline void loadPasswordHosts(const std::string& text) {
    size_t pos = 0;
    while (pos < text.size()) {
        size_t end = text.find(',', pos);
        if (end == std::string::npos) end = text.size();
        const std::string item = text.substr(pos, end - pos);
        pos = end + 1;
        const bool ok = !item.empty() && item.size() <= 64 &&
            std::all_of(item.begin(), item.end(), [](char c) { return (c >= '0' && c <= '9') || c == '.' || c == ':'; });
        if (ok) rememberMode(item, HostMode::Password);
    }
}
inline void clearKnownModesForTest() {
    std::lock_guard<std::mutex> g(knownModeMutex());
    knownModeList().clear();
}

// MARK: Client (one per host attempt; shared by every channel)

class Client {
public:
    using LogFn = std::function<void(const std::string&)>;
    using TerminalFn = std::function<void(const Report&)>;

    struct Options {
        std::wstring password;     // typed on the launch screen; wiped once K is derived
        bool remember = false;     // "Remember password" ticked
        std::wstring storeDir;     // empty: HostKeyStore::defaultDir()
        std::string hostKey;       // "ip:port" of the host; empty: mode not kept across Clients
        LogFn log;
    };

    explicit Client(Options o)
        : password_(std::move(o.password)), remember_(o.remember),
          store_(o.storeDir.empty() ? HostKeyStore::defaultDir() : o.storeDir), log_(std::move(o.log)),
          hostKey_(std::move(o.hostKey)) {
        wipe(o.password);
        mode_ = knownMode(hostKey_);
        modeInherited_ = mode_ == Mode::Password;
    }
    ~Client() {
        std::lock_guard<std::mutex> g(m_);
        wipeSecretsLocked();
    }
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    void setTerminalHandler(TerminalFn fn) { std::lock_guard<std::mutex> g(m_); onTerminal_ = std::move(fn); }

    using Mode = HostMode;
    Mode mode() const { std::lock_guard<std::mutex> g(m_); return mode_; }
    bool transition() const { return mode() == Mode::Transition; }
    bool halted() const { return halted_.load(); }
    Report lastTerminal() const { std::lock_guard<std::mutex> g(m_); return terminal_; }
    // The outcome of the most recent handshake on any channel.
    Outcome lastOutcome() const { std::lock_guard<std::mutex> g(m_); return last_; }
    const HostKeyStore& store() const { return store_; }
    // Tests: the client holds neither the typed password nor K.
    bool holdsSecrets() const { std::lock_guard<std::mutex> g(m_); return !password_.empty() || key_.has_value(); }

    // Taken by a channel before it connects, held until its handshake ends,
    // in every mode: a transition host can turn on a password at any time,
    // and a probe that crosses its first challenge spends a try. So one
    // connection at a time probes or answers; the next sees the outcome
    // (mode Password, halted, or K proven) instead of spending a try of its
    // own. Taken before connect, so no host is kept waiting meanwhile.
    std::unique_lock<std::mutex> connectSlot() {
        return std::unique_lock<std::mutex>(flightM_);
    }

    // Runs the AUTH exchange on a freshly connected TCP socket, before the
    // channel's first message. `connectMs` is how long the TCP connect took
    // (sets the transition probe wait on slow links).
    Report handshake(SOCKET s, Channel ch, double connectMs) {
        Report r = exchange(s, ch, connectMs);
        note(std::string("auth.result chan=") + channelName(ch) + " outcome=" + outcomeName(r.outcome) +
             (r.outcome == Outcome::Fail ? " tries=" + std::to_string(r.triesLeft) : std::string()) +
             (r.outcome == Outcome::Locked ? " retry_s=" + std::to_string(r.retrySeconds) : std::string()) +
             (r.savedKeyFile ? std::string(" saved_key=") + r.savedKeyFile : std::string()));
        {
            std::lock_guard<std::mutex> g(m_);
            last_ = r.outcome;
        }
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

        FrameReader rd(s);
        uint8_t type = 0;
        Bytes payload;
        bool probed = false;
        Io io = Io::Timeout;
        if (known == Mode::Password) {
            io = rd.next(oldHostDeadline, type, payload);
        } else {
            io = rd.next(start + std::chrono::milliseconds(probeWaitMs), type, payload);
            if (io == Io::Timeout && rd.started()) {
                // A frame has begun: the host is answering. No probe; the
                // bytes read so far are kept.
                note(std::string("auth.probe_skipped chan=") + channelName(ch) + " reason=frame_started");
                io = rd.next(oldHostDeadline, type, payload);
            } else if (io == Io::Timeout) {
                // Transition probe: random nonce, zero MAC (design §9).
                uint8_t probe[kResponseBytes]{};
                randomBytes(probe, kNonceBytes);
                if (!sendAllBytes(s, frame(kTypeResponse, probe, sizeof(probe)))) { rep.outcome = Outcome::Network; return rep; }
                probed = true;
                note(std::string("auth.probe chan=") + channelName(ch) + " waited_ms=" + std::to_string(probeWaitMs));
                io = rd.next(oldHostDeadline, type, payload);
            }
        }
        if (io == Io::Timeout) {
            note("auth.no_challenge waited_ms=" + std::to_string(kOldHostTimeoutMs) + (probed ? " probed=1" : " probed=0"));
            if (known == Mode::Password && inheritedPasswordMode()) {
                // Only the mark from an earlier attempt said "password": the
                // Mac may have dropped its password since. Forget the mark;
                // the next connection probes as for an unknown host.
                note("auth.known_mode_cleared reason=no_challenge");
                setMode(Mode::Unknown);
                rep.outcome = Outcome::Retry;
                return rep;
            }
            rep.outcome = Outcome::HostTooOld;
            return rep;
        }
        if (io == Io::Closed) { rep.outcome = Outcome::Network; return rep; }

        if (type == kTypeResult) {
            // No challenge: locked / blocked before one, or the probe answer.
            auto res = Result::decode(payload);
            if (!res) { rep.outcome = Outcome::Network; return rep; }
            if (res->status == Result::Status::OpenIpOnly) {
                // Only the answer to our probe on a host that sent no challenge.
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
        if (probed) return afterProbeRace(rd, ch);

        bool fromStore = false;
        std::optional<Key> key = keyFor(*ch5, fromStore);
        if (!key) { rep.outcome = Outcome::NeedPassword; return rep; }

        uint8_t resp[kResponseBytes]{};
        if (!randomBytes(resp, kNonceBytes)) { rep.outcome = Outcome::Network; return rep; }
        auto macC = macClient(*key, ch5->hostNonce.data(), resp, ch, ch5->hostId.data());
        if (!macC) {
            // Never answer with a MAC CNG did not produce; closing without
            // an answer costs no try on the host.
            note(std::string("auth.hmac_failed chan=") + channelName(ch) + " step=mac_c sent=0");
            rep.outcome = Outcome::LocalError;
            return rep;
        }
        std::memcpy(resp + kNonceBytes, macC->data(), kMacBytes);
        if (!sendAllBytes(s, frame(kTypeResponse, resp, sizeof(resp)))) { rep.outcome = Outcome::Network; return rep; }

        io = rd.next(Clock::now() + std::chrono::milliseconds(kResultTimeoutMs), type, payload);
        if (io != Io::Ok || type != kTypeResult) { rep.outcome = Outcome::Network; return rep; }
        auto res = Result::decode(payload);
        if (!res) { rep.outcome = Outcome::Network; return rep; }

        if (res->status == Result::Status::Ok) {
            auto want = macHost(*key, ch5->hostNonce.data(), resp, ch);
            if (!want) {
                note(std::string("auth.hmac_failed chan=") + channelName(ch) + " step=mac_h");
                rep.outcome = Outcome::LocalError;
                return rep;
            }
            if (!constantTimeEqual(want->data(), res->macH.data(), kMacBytes)) {
                // Not the Mac that holds K. Keep nothing from this attempt.
                note("auth.host_mismatch chan=" + std::string(channelName(ch)) + " reason=mac_h");
                forgetKey();
                rep.outcome = Outcome::HostMismatch;
                return rep;
            }
            accept(*ch5, *key, fromStore);
            rep.outcome = Outcome::Ok;
            return rep;
        }
        if (res->status == Result::Status::OpenIpOnly) {
            // open_ip_only only answers a probe on a host that sent no
            // challenge. After a challenge and our proof it skips the mac_h
            // check: not the Mac that holds K (or someone rewrote the answer).
            note("auth.host_mismatch chan=" + std::string(channelName(ch)) + " reason=open_after_challenge");
            forgetKey();
            rep.outcome = Outcome::HostMismatch;
            return rep;
        }
        return fromResult(*res, fromStore, &ch5->hostId);
    }

    // The challenge was on its way when the probe left. A PR-A host reads
    // the probe as this challenge's answer and counts a wrong try. Nothing
    // more is sent on this socket; the host's answer says what that cost.
    // No password was tried, so K and any saved copy stay.
    Report afterProbeRace(FrameReader& rd, Channel ch) {
        Report rep;
        rep.probeRace = true;
        uint8_t type = 0;
        Bytes payload;
        std::optional<Result> res;
        if (rd.next(Clock::now() + std::chrono::milliseconds(kResultTimeoutMs), type, payload) == Io::Ok && type == kTypeResult) {
            res = Result::decode(payload);
        }
        if (!res) {
            // We cannot tell whether that cost a try: no automatic retry.
            // The host is now known to want a password, so the next attempt
            // never probes.
            note(std::string("auth.probe_race chan=") + channelName(ch) + " answer=none");
            rep.outcome = Outcome::RaceUnanswered;
            return rep;
        }
        switch (res->status) {
        case Result::Status::Fail: {
            rep.triesLeft = res->triesLeft;
            // One reconnect without a probe, only while it cannot be the
            // try that starts a lockout. Otherwise the user decides.
            bool retry = res->triesLeft >= 2;
            if (retry) {
                std::lock_guard<std::mutex> g(m_);
                retry = !raceRetried_;
                raceRetried_ = true;
            }
            rep.outcome = retry ? Outcome::Retry : Outcome::Fail;
            break;
        }
        case Result::Status::Locked: rep.outcome = Outcome::Locked; rep.retrySeconds = res->retrySeconds; break;
        case Result::Status::Blocked: rep.outcome = Outcome::Blocked; break;
        case Result::Status::AuthRequired: rep.outcome = Outcome::AuthRequired; break;
        default:
            // OK or open_ip_only to a zero MAC after a challenge: not a host
            // that checks K.
            forgetKey();
            rep.outcome = Outcome::HostMismatch;
            break;
        }
        note(std::string("auth.probe_race chan=") + channelName(ch) + " answer=" + outcomeName(rep.outcome) +
             (res->status == Result::Status::Fail ? " tries=" + std::to_string(rep.triesLeft) : std::string()));
        return rep;
    }

    // A saved key judged invalid: delete it, log what really happened, and
    // never load it again in this run whatever the delete did.
    const char* dropSaved(const HostId& id, const char* reason) {
        distrustHost(id);
        const auto r = store_.remove(id);
        note(std::string("auth.saved_key_dropped reason=") + reason + " file=" + HostKeyStore::removalName(r));
        return HostKeyStore::removalName(r);
    }

    Report fromResult(const Result& r, bool fromStore, const HostId* id = nullptr) {
        Report rep;
        switch (r.status) {
        case Result::Status::Fail:
            rep.outcome = Outcome::Fail;
            rep.triesLeft = r.triesLeft;
            // The key is wrong: forget it, and delete the saved copy at once.
            forgetKey();
            if (id && (fromStore || store_.exists(*id))) rep.savedKeyFile = dropSaved(*id, "fail");
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
                return key_;
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
        if (hostDistrusted(c.hostId)) {
            note("auth.saved_key_skipped reason=distrusted");
            return std::nullopt;
        }
        if (auto e = store_.load(c.hostId)) {
            if (e->salt == c.salt && e->iterations == c.iterations) {
                std::lock_guard<std::mutex> g2(m_);
                cache(c, e->key, true);
                fromStore = true;
                return e->key;
            }
            // The Mac's password changed (new salt): the saved key is stale.
            e.reset();
            dropSaved(c.hostId, "stale_salt");
        }
        return std::nullopt;
    }

    void cache(const Challenge& c, const Key& k, bool fromStore) {
        key_ = k;
        keyHost_ = c.hostId;
        keySalt_ = c.salt;
        keyIter_ = c.iterations;
        keyFromStore_ = fromStore;
        keyVerified_ = false;
    }

    void forgetKey() {
        std::lock_guard<std::mutex> g(m_);
        wipeSecretsLocked();
    }

    // The one place the typed password and the cached K are cleared: a
    // wrong or unproven key, any answer that ends the attempt, and the
    // destructor. (Key copies wipe themselves when they go out of scope.)
    void wipeSecretsLocked() {
        wipe(password_);
        key_.reset();
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
            // Mutual check passed and DPAPI wrote the new copy: a mark from
            // an older key that failed must not hide this one.
            const bool wasDistrusted = ok && hostDistrusted(c.hostId);
            if (ok) undistrustHost(c.hostId);
            note(std::string("auth.saved_key ") + (ok ? "written=1" : "written=0") +
                 (wasDistrusted ? " distrust=cleared" : ""));
        } else if (store_.exists(c.hostId)) {
            const auto r = store_.remove(c.hostId);
            note(std::string("auth.saved_key_removed reason=remember_off file=") + HostKeyStore::removalName(r));
        }
    }

    void setMode(Mode m) {
        {
            std::lock_guard<std::mutex> g(m_);
            mode_ = m;
            modeInherited_ = false;
        }
        rememberMode(hostKey_, m);
    }
    bool inheritedPasswordMode() const { std::lock_guard<std::mutex> g(m_); return modeInherited_; }

    void halt(const Report& r) {
        TerminalFn fn;
        {
            std::lock_guard<std::mutex> g(m_);
            if (halted_) return;
            terminal_ = r;
            halted_ = true;
            wipeSecretsLocked();
            fn = onTerminal_;
        }
        if (fn) fn(r);
    }

    void note(const std::string& s) const { if (log_) log_(s); }

    mutable std::mutex m_;
    std::mutex keyM_;
    std::mutex flightM_;
    bool raceRetried_ = false;
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
    Outcome last_ = Outcome::Network;
    std::string hostKey_;
    bool modeInherited_ = false;  // mode_ came from knownMode(), not from this host's answer yet
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

// See Client::connectSlot. Keeps the client alive while the slot is held.
struct ConnectSlot {
    std::shared_ptr<Client> client;
    std::unique_lock<std::mutex> lock;
};
inline ConnectSlot connectSlot() {
    ConnectSlot s;
    s.client = current();
    if (s.client) s.lock = s.client->connectSlot();
    return s;
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
