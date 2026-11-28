// JerisLink Windows host, H3 tests: the connection password.
//
// Portable (Linux with any C++20 compiler, Windows in CI): the shared
// vectors through a portable HMAC-SHA256, the wrong-password limits
// (AuthGuard), the session broker (takeover, auto reconnects, other
// channels, policy changes, blocks), the UDP checks, and the whole AUTH
// exchange over loopback sockets against a scripted viewer, with the Mac
// host's log lines. On Windows also: CNG against the vectors, and the real
// viewer client (windows-client/conn_auth.hpp) against this host.
//
// Usage: JerisLinkHostAuthTest <path to personal/protocol/auth_vectors.json>

#include "host_auth_conn.hpp"  // Winsock headers before any windows.h
#include "host_settings.hpp"
#include "host_protocol.hpp"  // InputClaims, for the void rule

#ifdef _WIN32
#include "host_config_win.hpp"
#include "host_crypto_win.hpp"
#else
#include <arpa/inet.h>
#include <csignal>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace jlh::auth;
using jlh::SocketHandle;

static int gFailures = 0;
static int gChecks = 0;
#define CHECK(cond)                                                     \
    do {                                                                \
        ++gChecks;                                                      \
        if (!(cond)) {                                                  \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++gFailures;                                                \
        }                                                               \
    } while (0)

// ---------------------------------------------------------- SHA-256 / HMAC

namespace sha {
struct Ctx {
    uint32_t h[8];
    uint8_t buf[64];
    uint64_t len = 0;
    size_t used = 0;
};
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
static void block(Ctx& c, const uint8_t* p) {
    uint32_t w[64];
    for (int i = 0; i < 16; ++i)
        w[i] = uint32_t(p[4 * i]) << 24 | uint32_t(p[4 * i + 1]) << 16 | uint32_t(p[4 * i + 2]) << 8 | p[4 * i + 3];
    for (int i = 16; i < 64; ++i) {
        const uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = c.h[0], b = c.h[1], cc = c.h[2], d = c.h[3], e = c.h[4], f = c.h[5], g = c.h[6], hh = c.h[7];
    for (int i = 0; i < 64; ++i) {
        const uint32_t t1 = hh + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
        const uint32_t t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & cc) ^ (b & cc));
        hh = g;
        g = f;
        f = e;
        e = d + t1;
        d = cc;
        cc = b;
        b = a;
        a = t1 + t2;
    }
    c.h[0] += a; c.h[1] += b; c.h[2] += cc; c.h[3] += d; c.h[4] += e; c.h[5] += f; c.h[6] += g; c.h[7] += hh;
}
static void init(Ctx& c) {
    static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    std::memcpy(c.h, iv, sizeof(iv));
    c.len = 0;
    c.used = 0;
}
static void update(Ctx& c, const uint8_t* p, size_t n) {
    c.len += n;
    while (n) {
        const size_t take = std::min(n, 64 - c.used);
        std::memcpy(c.buf + c.used, p, take);
        c.used += take;
        p += take;
        n -= take;
        if (c.used == 64) {
            block(c, c.buf);
            c.used = 0;
        }
    }
}
static void finish(Ctx& c, uint8_t out[32]) {
    const uint64_t bits = c.len * 8;
    const uint8_t pad = 0x80, zero = 0;
    update(c, &pad, 1);
    while (c.used != 56) update(c, &zero, 1);
    uint8_t l[8];
    for (int i = 0; i < 8; ++i) l[i] = uint8_t(bits >> (56 - 8 * i));
    update(c, l, 8);
    for (int i = 0; i < 8; ++i) {
        out[4 * i] = uint8_t(c.h[i] >> 24);
        out[4 * i + 1] = uint8_t(c.h[i] >> 16);
        out[4 * i + 2] = uint8_t(c.h[i] >> 8);
        out[4 * i + 3] = uint8_t(c.h[i]);
    }
}
}  // namespace sha

static std::atomic<int> gHmacFaults{0};

static bool portableHmac(const uint8_t* key, size_t keyLen, const Part* parts, size_t nParts, Mac& out) {
    if (gHmacFaults.load() > 0) {
        --gHmacFaults;
        out.fill(0);
        return false;
    }
    uint8_t k[64] = {};
    if (keyLen > 64) {
        sha::Ctx c;
        sha::init(c);
        sha::update(c, key, keyLen);
        sha::finish(c, k);
    } else {
        std::memcpy(k, key, keyLen);
    }
    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; ++i) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    sha::Ctx c;
    sha::init(c);
    sha::update(c, ipad, 64);
    for (size_t i = 0; i < nParts; ++i)
        if (parts[i].n) sha::update(c, parts[i].p, parts[i].n);
    uint8_t inner[32];
    sha::finish(c, inner);
    sha::init(c);
    sha::update(c, opad, 64);
    sha::update(c, inner, 32);
    sha::finish(c, out.data());
    return true;
}

// A UdpTags on the portable HMAC (the host uses CNG's Tagger).
class PortableTags : public UdpTags {
public:
    explicit PortableTags(const Key& k) : k_(k) {}
    size_t seal(const uint8_t* p, size_t n, uint8_t* out) const override {
        if (n <= kUdpVersionByte) return 0;
        std::memcpy(out, p, n);
        out[kUdpVersionByte] |= kUdpTagFlag;
        return udpTag(portableHmac, k_, true, out, n, out + n) ? n + kTagBytes : 0;
    }
    bool verify(const uint8_t* p, size_t n) const override {
        if (n <= kTagBytes + kUdpVersionByte || !(p[kUdpVersionByte] & kUdpTagFlag)) return false;
        uint8_t want[kTagBytes];
        if (!udpTag(portableHmac, k_, false, p, n - kTagBytes, want)) return false;
        return constantTimeEqual(want, p + n - kTagBytes, kTagBytes);
    }

private:
    Key k_;
};
static UdpTagsFactory portableTags() {
    return [](const Key& k) -> std::shared_ptr<const UdpTags> { return std::make_shared<PortableTags>(k); };
}

// ------------------------------------------------------------- the vectors

static std::string jsonField(const std::string& obj, const std::string& name) {
    const std::string k = "\"" + name + "\"";
    size_t p = obj.find(k);
    if (p == std::string::npos) return {};
    p = obj.find(':', p + k.size());
    if (p == std::string::npos) return {};
    ++p;
    while (p < obj.size() && (obj[p] == ' ' || obj[p] == '\n' || obj[p] == '\r' || obj[p] == '\t')) ++p;
    if (p >= obj.size()) return {};
    if (obj[p] != '"') {
        const size_t e = obj.find_first_of(",}\n", p);
        return obj.substr(p, e - p);
    }
    const size_t e = obj.find('"', p + 1);
    return obj.substr(p + 1, e - p - 1);
}
static Bytes unhex(const std::string& h) {
    Bytes b;
    for (size_t i = 0; i + 1 < h.size(); i += 2) b.push_back(uint8_t(std::strtoul(h.substr(i, 2).c_str(), nullptr, 16)));
    return b;
}
template <size_t N>
static std::array<uint8_t, N> arr(const std::string& h) {
    std::array<uint8_t, N> a{};
    const Bytes b = unhex(h);
    if (b.size() == N) std::memcpy(a.data(), b.data(), N);
    return a;
}

struct Vector {
    std::string name;
    Key key;
    Salt salt;
    uint32_t iterations = 0;
    Nonce hn, cn;
    Channel channel = Channel::Control;
    HostId hostId;
    Mac macC, macH;
    SessionId sid;
    Key sessionKey;
    Bytes v2hPacket, v2hTag, h2vPacket, h2vTag, challenge, response, resultOk;
    std::string password;
};

static std::vector<Vector> loadVectors(const char* path) {
    std::ifstream f(path, std::ios::binary);
    const std::string all((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    std::vector<Vector> out;
    size_t p = all.find("\"vectors\"");
    while (p != std::string::npos) {
        const size_t s = all.find('{', p);
        if (s == std::string::npos) break;
        const size_t e = all.find('}', s);
        if (e == std::string::npos) break;
        const std::string o = all.substr(s, e - s + 1);
        Vector v;
        v.name = jsonField(o, "name");
        v.key = arr<32>(jsonField(o, "key"));
        v.salt = arr<16>(jsonField(o, "salt"));
        v.iterations = uint32_t(std::strtoul(jsonField(o, "iterations").c_str(), nullptr, 10));
        v.hn = arr<32>(jsonField(o, "host_nonce"));
        v.cn = arr<32>(jsonField(o, "client_nonce"));
        const std::string ch = jsonField(o, "channel");
        v.channel = ch == "clipboard" ? Channel::Clipboard : ch == "file" ? Channel::File : ch == "ping" ? Channel::Ping
                                                                                                         : Channel::Control;
        v.hostId = arr<16>(jsonField(o, "host_id"));
        v.macC = arr<32>(jsonField(o, "mac_c"));
        v.macH = arr<32>(jsonField(o, "mac_h"));
        v.sid = arr<8>(jsonField(o, "session_id"));
        v.sessionKey = arr<32>(jsonField(o, "session_key"));
        v.v2hPacket = unhex(jsonField(o, "udp_v2h_packet"));
        v.v2hTag = unhex(jsonField(o, "udp_v2h_tag"));
        v.h2vPacket = unhex(jsonField(o, "udp_h2v_packet"));
        v.h2vTag = unhex(jsonField(o, "udp_h2v_tag"));
        v.challenge = unhex(jsonField(o, "challenge_payload"));
        v.response = unhex(jsonField(o, "response_payload"));
        v.resultOk = unhex(jsonField(o, "result_ok_payload"));
        v.password = jsonField(o, "password");
        out.push_back(v);
        p = all.find('{', e);
        if (p != std::string::npos) p = p - 1;
    }
    return out;
}

static void testVectors(const std::vector<Vector>& vs, HmacFn hmac, const char* which) {
    std::printf("vectors (%s): %zu\n", which, vs.size());
    CHECK(vs.size() >= 3);
    for (const auto& v : vs) {
        Mac m{};
        CHECK(macClient(hmac, v.key, v.hn, v.cn, v.channel, v.hostId, nullptr, m) && m == v.macC);
        CHECK(macHost(hmac, v.key, v.hn, v.cn, v.channel, m) && m == v.macH);
        Key ks{};
        CHECK(sessionKey(hmac, v.key, v.hn, v.cn, v.sid, ks) && ks == v.sessionKey);
        uint8_t tag[kTagBytes];
        CHECK(udpTag(hmac, v.sessionKey, false, v.v2hPacket.data(), v.v2hPacket.size(), tag) &&
              Bytes(tag, tag + kTagBytes) == v.v2hTag);
        CHECK(udpTag(hmac, v.sessionKey, true, v.h2vPacket.data(), v.h2vPacket.size(), tag) &&
              Bytes(tag, tag + kTagBytes) == v.h2vTag);
        CHECK(challengePayload(v.hn, v.salt, v.iterations, v.hostId) == v.challenge);
        CHECK(resultOk(v.macH, v.sid) == v.resultOk);
        const auto r = decodeResponse(v.response.data(), v.response.size());
        CHECK(r && r->clientNonce == v.cn && r->mac == v.macC && !r->hasResume && !r->zeroMac());
        // The host finds the channel the viewer proved, and only that one.
        const auto ch = matchChannel(hmac, v.key, v.hn, *r, v.hostId);
        CHECK(ch && *ch == v.channel);
        Response bad = *r;
        bad.mac[0] ^= 1;
        CHECK(!matchChannel(hmac, v.key, v.hn, bad, v.hostId));
        HostId otherHost = v.hostId;
        otherHost[0] ^= 1;
        CHECK(!matchChannel(hmac, v.key, v.hn, *r, otherHost));
    }
}

// ------------------------------------------------------------------- units

static void testWire() {
    CHECK(resultFail(4) == (Bytes{1, 4}));
    CHECK(resultLocked(300) == (Bytes{2, 0, 0, 1, 0x2c}));
    CHECK(resultStatus(Status::Blocked) == Bytes{3});
    CHECK(resultStatus(Status::AuthRequired) == Bytes{4});
    CHECK(resultStatus(Status::Replaced) == Bytes{6});
    uint8_t buf[80] = {};
    CHECK(!decodeResponse(buf, 63));
    CHECK(!decodeResponse(buf, 65));
    CHECK(!decodeResponse(buf, 73));
    for (int i = 0; i < 8; ++i) buf[64 + i] = kAutoMarker[i];
    const auto r = decodeResponse(buf, 72);
    CHECK(r && r->hasResume && r->zeroMac() && std::memcmp(r->resume.data(), kAutoMarker, 8) == 0);

    // r3: only a 0.3.x viewer's exact first headers skip the count.
    CHECK(isLegacyFirstHeader(0x01, 4));
    CHECK(!isLegacyFirstHeader(0x01, 5));
    CHECK(isLegacyFirstHeader(0x10, 3));
    CHECK(isLegacyFirstHeader(0x21, 2));
    CHECK(isLegacyFirstHeader(0x25, 3));
    CHECK(isLegacyFirstHeader(0x30, 0));
    CHECK(!isLegacyFirstHeader(0x30, 1));
    CHECK(isLegacyFirstHeader(0x40, 6));
    CHECK(isLegacyFirstHeader(0x50, 3));
    CHECK(isLegacyFirstHeader(0x60, 0));
    CHECK(!isLegacyFirstHeader(0x03, 64));
    CHECK(!isLegacyFirstHeader(0x77, 0));

    CHECK(channelAllows(Channel::Ping, 0x01, true));
    CHECK(!channelAllows(Channel::Ping, 0x10, false));
    CHECK(channelAllows(Channel::Clipboard, 0x30, true));
    CHECK(!channelAllows(Channel::Clipboard, 0x10, true));
    CHECK(channelAllows(Channel::Clipboard, 0x31, false));
    CHECK(channelAllows(Channel::File, 0x50, true));
    CHECK(!channelAllows(Channel::File, 0x30, true));
    CHECK(channelAllows(Channel::Control, 0x10, true));
    CHECK(!channelAllows(Channel::Control, 0x30, true));
    CHECK(!channelAllows(Channel::Control, 0x50, false));
}

static void testAddresses() {
    CHECK(isIpv4("100.64.0.1"));
    CHECK(isIpv4("0.0.0.0"));
    CHECK(!isIpv4("100.064.0.1"));
    CHECK(!isIpv4("256.1.1.1"));
    CHECK(!isIpv4("1.2.3"));
    CHECK(!isIpv4("1.2.3.4.5"));
    CHECK(!isIpv4(" 1.2.3.4"));
    CHECK(!isIpv4("1.2.3.4 "));
    CHECK(!isIpv4(""));
    CHECK(!isIpv4("1..2.3"));
    CHECK(!isIpv4("1234.1.1.1"));
    CHECK(isTailnetIpv4("100.64.0.0"));
    CHECK(isTailnetIpv4("100.127.255.255"));
    CHECK(isTailnetIpv4("100.101.102.103"));
    CHECK(!isTailnetIpv4("100.128.0.1"));
    CHECK(!isTailnetIpv4("100.63.255.255"));
    CHECK(!isTailnetIpv4("192.168.1.10"));
    CHECK(!isTailnetIpv4("0.0.0.0"));
    CHECK(ipv4String(0x64400001u) == "100.64.0.1");

    const IpList l = parseIpList("100.64.0.1, 100.64.0.2\n100.64.0.1;bad 300.1.1.1\t100.70.1.1\r\n");
    CHECK((l.ips == std::vector<std::string>{"100.64.0.1", "100.64.0.2", "100.70.1.1"}));
    CHECK((l.bad == std::vector<std::string>{"bad", "300.1.1.1"}));
    CHECK(parseIpList("").ips.empty() && parseIpList(" \n ,").bad.empty());
}

static void testPasswordRules() {
    CHECK(passwordProblems(U"Correct-Horse.42").empty());
    CHECK(passwordProblems(U"Aa!aaaaaaa").empty());  // exactly 10
    const auto p = passwordProblems(U"Aa!aaaaaa");     // 9
    CHECK(p.size() == 1 && p[0] == PasswordProblem::TooShort);
    CHECK((passwordProblems(U"aaaaaaaaa!") == std::vector<PasswordProblem>{PasswordProblem::NoUpper}));
    CHECK((passwordProblems(U"AAAAAAAAA!") == std::vector<PasswordProblem>{PasswordProblem::NoLower}));
    CHECK((passwordProblems(U"Aaaaaaaaa1") == std::vector<PasswordProblem>{PasswordProblem::NoSymbol}));
    // White space is not a symbol; a non-ASCII letter is.
    CHECK((passwordProblems(U"Aaaaa aaaa") == std::vector<PasswordProblem>{PasswordProblem::NoSymbol}));
    CHECK((passwordProblems(U"Aaaaa　aaaa") == std::vector<PasswordProblem>{PasswordProblem::NoSymbol}));
    CHECK(passwordProblems(U"Aaaaaéaaaa").empty());
    CHECK(passwordProblems(U"").size() == 4);
}

struct FakeClock {
    std::atomic<double> t{1000};
    std::atomic<int64_t> wall{1'800'000'000};
};

static AuthGuard::Hooks testHooks(FakeClock& c, std::vector<std::string>* lines = nullptr, std::mutex* m = nullptr) {
    AuthGuard::Hooks h;
    h.now = [&c] { return c.t.load(); };
    h.wallNow = [&c] { return c.wall.load(); };
    h.pause = [](double) {};
    h.log = [lines, m](const std::string& s) {
        if (!lines) return;
        std::lock_guard<std::mutex> g(*m);
        lines->push_back(s);
    };
    return h;
}

static void testGuardLadder() {
    FakeClock clock;
    MemoryBlocklist store;
    MemoryPendingBlocks journal;
    AuthGuard g({}, store, &journal, testHooks(clock));
    const std::string ip = "100.64.0.9";
    const auto wrong = [&] { return g.settle(ip, [] { return false; }); };

    for (int stage = 1; stage <= 3; ++stage) {
        for (int i = 1; i <= 4; ++i) {
            const auto s = wrong();
            CHECK(s.kind == AuthGuard::Settlement::Failed);
            CHECK(s.failure.outcome.kind == AuthGuard::FailureOutcome::Retry);
            CHECK(s.failure.outcome.triesLeft == 5 - i);
            CHECK(g.probe(ip).triesLeft == 5 - i);
        }
        const auto s = wrong();
        CHECK(s.failure.outcome.kind == AuthGuard::FailureOutcome::Locked);
        CHECK(s.failure.outcome.retrySeconds == uint32_t(300 * stage));
        CHECK(s.failure.outcome.stage == stage);
        CHECK(s.failure.failures == 5 * stage);
        const auto a = g.admit(ip);
        CHECK(a.kind == AuthGuard::Admission::Locked && a.stage == stage && a.retrySeconds == uint32_t(300 * stage));
        // An answer to a challenge issued before the wait: refused, not counted.
        const auto late = wrong();
        CHECK(late.kind == AuthGuard::Settlement::Refused && late.admission.kind == AuthGuard::Admission::Locked);
        CHECK(g.probe(ip).refused);
        CHECK(g.failures(ip) == 5 * stage);
        clock.t = clock.t + 300.0 * stage + 1;
        CHECK(g.admit(ip).kind == AuthGuard::Admission::Challenge);
    }
    for (int i = 0; i < 4; ++i) wrong();
    const auto s = wrong();
    CHECK(s.failure.failures == 20);
    CHECK(s.failure.outcome.kind == AuthGuard::FailureOutcome::Blacklisted && s.failure.outcome.persisted);
    CHECK(g.admit(ip).kind == AuthGuard::Admission::Blocked);
    CHECK(store.entries.size() == 1 && store.entries[0].ip == ip && store.entries[0].reason == "20 wrong passwords");
    CHECK(g.inputRefusal(ip) == std::optional<std::string>("blocked"));
    CHECK(g.takeNewlyBlocked() == std::vector<std::string>{ip});
    CHECK(g.takeNewlyBlocked().empty());
    // Still blocked after days, and for a fresh guard reading the store.
    clock.t = clock.t + 1e6;
    CHECK(g.admit(ip).kind == AuthGuard::Admission::Blocked);
    AuthGuard g2({}, store, &journal, testHooks(clock));
    CHECK(g2.admit(ip).kind == AuthGuard::Admission::Blocked);
    // Released: off the store, count cleared.
    CHECK(g.release(ip) == AuthGuard::ReleaseResult::Released);
    CHECK(store.entries.empty() && g.admit(ip).kind == AuthGuard::Admission::Challenge && g.failures(ip) == 0);
    CHECK(g.release(ip) == AuthGuard::ReleaseResult::NotBlocked);

    // One right password clears this IP's count.
    for (int i = 0; i < 3; ++i) wrong();
    CHECK(g.failures(ip) == 3);
    CHECK(g.settle(ip, [] { return true; }).kind == AuthGuard::Settlement::Ok);
    CHECK(g.failures(ip) == 0);
}

static void testGuardGlobalAndLists() {
    FakeClock clock;
    MemoryBlocklist store;
    std::vector<std::string> lines;
    std::mutex lm;
    AuthGuard g({}, store, nullptr, testHooks(clock, &lines, &lm));
    // 20 failures from 20 addresses inside 60 s: nobody gets a challenge.
    bool triggered = false;
    for (int i = 0; i < 20; ++i) {
        const auto s = g.settle("100.64.1." + std::to_string(i), [] { return false; });
        triggered = triggered || s.failure.globalTriggered;
        CHECK(s.failure.globalTriggered == (i == 19));
        clock.t = clock.t + 2;
    }
    CHECK(triggered);
    auto a = g.admit("100.64.9.9");
    CHECK(a.kind == AuthGuard::Admission::GlobalLocked && a.retrySeconds > 250 && a.retrySeconds <= 300);
    // A right password does not clear the host-wide wait.
    CHECK(g.settle("100.64.9.9", [] { return true; }).kind == AuthGuard::Settlement::Refused);
    clock.t = clock.t + 301;
    CHECK(g.admit("100.64.9.9").kind == AuthGuard::Admission::Challenge);

    // Whitelist (Windows: changed while running).
    g.setWhitelist({"100.64.0.5"});
    CHECK(g.admit("100.64.0.6").kind == AuthGuard::Admission::NotAllowed);
    CHECK(g.admit("100.64.0.5").kind == AuthGuard::Admission::Challenge);
    // The blacklist wins over the whitelist; an outside add applies at once.
    store.entries.push_back({"100.64.0.5", 1, "manual"});
    ++store.stamp.b;
    CHECK(g.admit("100.64.0.5").kind == AuthGuard::Admission::Blocked);
    CHECK(g.takeNewlyBlocked() == std::vector<std::string>{"100.64.0.5"});
    // Windows: an outside removal (the settings window) releases it here.
    store.entries.clear();
    ++store.stamp.b;
    CHECK(g.admit("100.64.0.5").kind == AuthGuard::Admission::Challenge);
    g.setWhitelist({});
    std::lock_guard<std::mutex> lg(lm);
    bool added = false, removed = false;
    for (const auto& l : lines) {
        added |= l.rfind("auth.block_added peers=1 source=registry", 0) == 0;
        removed |= l.rfind("auth.block_removed peers=1 source=registry", 0) == 0;
    }
    CHECK(added && removed);
}

static void testGuardUnpersisted() {
    FakeClock clock;
    MemoryBlocklist store;
    MemoryPendingBlocks journal;
    AuthGuard g({}, store, &journal, testHooks(clock));
    const std::string ip = "100.64.3.3";
    store.failNextSaves = 100;
    AuthGuard::Settlement s;
    for (int i = 0; i < 20; ++i) {
        s = g.settle(ip, [] { return false; });
        clock.t = clock.t + 1000;
    }
    CHECK(s.failure.outcome.kind == AuthGuard::FailureOutcome::Blacklisted && !s.failure.outcome.persisted);
    CHECK(store.saveCalls >= AuthGuard::kSaveAttempts);
    // B5 r4: in the journal; nobody else is admitted until the store holds it.
    CHECK(journal.entries.size() == 1 && journal.entries[0].ip == ip);
    auto a = g.admit("100.64.3.4");
    CHECK(a.kind == AuthGuard::Admission::GlobalLocked && a.retrySeconds == AuthGuard::kPendingRetrySeconds);
    CHECK(g.admit(ip).kind == AuthGuard::Admission::Blocked);
    // A restart still enforces it from the journal.
    {
        AuthGuard g2({}, store, &journal, testHooks(clock));
        CHECK(g2.admit(ip).kind == AuthGuard::Admission::Blocked);
        CHECK(g2.admit("100.64.3.4").kind == AuthGuard::Admission::GlobalLocked);
    }
    store.failNextSaves = 0;
    clock.t = clock.t + 2;
    CHECK(g.admit("100.64.3.4").kind == AuthGuard::Admission::Challenge);
    CHECK(g.pendingIPs().empty() && store.entries.size() == 1 && journal.entries.empty());

    // A journal that stops reading holds everyone and every open connection.
    journal.unreadable = true;
    ++journal.stamp.b;
    CHECK(g.inputRefusal("100.64.3.4") == std::optional<std::string>("pending_journal_unreadable"));
    CHECK(g.admit("100.64.3.4").kind == AuthGuard::Admission::GlobalLocked);
    CHECK(g.lockdownReason().has_value());
    journal.unreadable = false;
    clock.t = clock.t + 2;
    CHECK(!g.lockdownReason().has_value());
    CHECK(g.inputRefusal("100.64.3.4") == std::nullopt);
}

static Key keyOf(uint8_t b) {
    Key k;
    k.fill(b);
    return k;
}
static SessionId sidOf(uint8_t b) {
    SessionId s;
    s.fill(b);
    return s;
}

static void testBroker() {
    std::vector<std::string> lines;
    std::mutex lm;
    SessionBroker b(portableTags(), [&](const std::string& s) {
        std::lock_guard<std::mutex> g(lm);
        lines.push_back(s);
    });
    std::atomic<int> closedA{-1}, closedB{-1}, closedClip{-1};
    const auto pol = b.policyGeneration();
    CHECK(b.generation() == 0 && !b.current());
    auto a = b.admit("100.64.0.1", Channel::Control, keyOf(1), sidOf(1), std::nullopt, false, pol,
                     [&](CloseReason w) { closedA = int(w); });
    CHECK(a.refused == SessionBroker::Refusal::None && b.live(a.token) && b.controlOpen());
    CHECK(b.generation() == 1 && b.current() && b.current()->peerIp == "100.64.0.1" && b.current()->tags);
    // Another channel only with the newest control session's id.
    auto bad = b.admit("100.64.0.1", Channel::Clipboard, std::nullopt, std::nullopt, sidOf(9), false, pol, {});
    CHECK(bad.refused == SessionBroker::Refusal::Resume);
    auto none = b.admit("100.64.0.1", Channel::Clipboard, std::nullopt, std::nullopt, std::nullopt, false, pol, {});
    CHECK(none.refused == SessionBroker::Refusal::Resume);
    auto clip = b.admit("100.64.0.1", Channel::Clipboard, std::nullopt, std::nullopt, sidOf(1), false, pol,
                        [&](CloseReason w) { closedClip = int(w); });
    CHECK(clip.refused == SessionBroker::Refusal::None && b.live(clip.token));
    CHECK(b.generation() == 1);  // the session did not change
    // r14: auto never takes over.
    CHECK(b.autoRefused(true) && !b.autoRefused(false));
    auto autoB = b.admit("100.64.0.2", Channel::Control, keyOf(2), sidOf(2), std::nullopt, true, pol, {});
    CHECK(autoB.refused == SessionBroker::Refusal::Resume && b.live(a.token));
    // A typed-in control AUTH takes over: everything before is void.
    auto bb = b.admit("100.64.0.2", Channel::Control, keyOf(2), sidOf(2), std::nullopt, false, pol,
                      [&](CloseReason w) { closedB = int(w); });
    CHECK(bb.refused == SessionBroker::Refusal::None && b.live(bb.token));
    CHECK(!b.live(a.token) && !b.live(clip.token));
    CHECK(b.voidReason(a.token) == CloseReason::Replaced && b.voidReason(clip.token) == CloseReason::Replaced);
    CHECK(!b.voidReason(bb.token));
    b.flushClosesForTest();
    CHECK(closedA == int(CloseReason::Replaced) && closedClip == int(CloseReason::Replaced) && closedB == -1);
    CHECK(b.generation() == 2 && b.current()->peerIp == "100.64.0.2" && b.replaced() == 2);
    // The old session's id no longer opens channels.
    CHECK(b.admit("100.64.0.1", Channel::Clipboard, std::nullopt, std::nullopt, sidOf(1), false, pol, {}).refused ==
          SessionBroker::Refusal::Resume);
    b.end(a.token);
    b.end(clip.token);
    CHECK(!b.voidReason(a.token));

    // Policy change: every connection void, no notice, old AUTHs refused.
    b.voidAll(CloseReason::Policy, true);
    CHECK(!b.live(bb.token) && b.voidReason(bb.token) == CloseReason::Policy);
    CHECK(b.policyGeneration() == pol + 1);
    CHECK(b.admit("100.64.0.3", Channel::Control, keyOf(3), sidOf(3), std::nullopt, false, pol, {}).refused ==
          SessionBroker::Refusal::Policy);
    b.flushClosesForTest();
    CHECK(closedB == int(CloseReason::Policy));
    CHECK(!b.current() && b.generation() == 3);
    b.end(bb.token);

    // A blocked address loses its connections; others go on.
    const auto p2 = b.policyGeneration();
    std::atomic<int> closedC{-1}, closedD{-1};
    auto c = b.admit("100.64.0.3", Channel::Control, keyOf(3), sidOf(3), std::nullopt, false, p2,
                     [&](CloseReason w) { closedC = int(w); });
    auto d = b.admit("100.64.0.3", Channel::Ping, std::nullopt, std::nullopt, sidOf(3), false, p2,
                     [&](CloseReason w) { closedD = int(w); });
    CHECK(c.refused == SessionBroker::Refusal::None && d.refused == SessionBroker::Refusal::None);
    CHECK(b.kickPeer("100.64.0.99", CloseReason::Blocked) == 0 && b.live(c.token));
    CHECK(b.kickPeer("100.64.0.3", CloseReason::Blocked) == 2);
    CHECK(!b.live(c.token) && b.voidReason(d.token) == CloseReason::Blocked && !b.controlOpen());
    b.flushClosesForTest();
    CHECK(closedC == int(CloseReason::Blocked) && closedD == int(CloseReason::Blocked));
    b.end(c.token);
    b.end(d.token);

    // r9: an OK that did not go out drops its session id.
    auto e = b.admit("100.64.0.4", Channel::Control, keyOf(4), sidOf(4), std::nullopt, false, p2, {});
    b.abandon(e.token);
    CHECK(!b.controlOpen() && b.openConnections() == 0);
    CHECK(b.admit("100.64.0.4", Channel::Clipboard, std::nullopt, std::nullopt, sidOf(4), false, p2, {}).refused ==
          SessionBroker::Refusal::Resume);
    std::lock_guard<std::mutex> g(lm);
    bool replacedLine = false, policyLine = false, blockedLine = false;
    for (const auto& l : lines) {
        replacedLine |= l == "auth.replaced old_peer=100.64.0.1 chan=control new_peer=100.64.0.2; old connection closed";
        policyLine |= l == "auth.closed peer=100.64.0.2 chan=control reason=policy_changed; connection closed";
        blockedLine |= l == "auth.closed peer=100.64.0.3 chan=ping reason=blocked; connection closed";
    }
    CHECK(replacedLine && policyLine && blockedLine);
}

// The Mac r11 whileLive rule, for input (host_main.cpp wires it the same
// way): a void (a takeover, a password or whitelist change, a block) runs
// SessionBroker::onVoid before it returns, which retires the input owner
// (InputClaims::retire): what it holds goes up at once and its MRM1 socket
// is unbound. A frame of the old connection that passed its check is
// still going in (a slow SendInput) when the void comes: it lands before
// the void returns, so before a takeover's AUTH_OK. A frame read before the
// void and acted on after it changes nothing (frameIfLive): no injection,
// no takeover, even for a connection that had never been the owner.
static void testVoidRetiresOwner() {
    using jlh::HeldInput;
    using jlh::InputClaims;
    using jlh::InputEvent;
    constexpr uint32_t kIp = 0x64400001;
    const char* hows[] = {"takeover", "policy", "block"};
    for (int how = 0; how < 3; ++how) {
        std::printf("void rule: %s\n", hows[how]);
        SessionBroker b(portableTags(), {});
        InputClaims claims;
        std::mutex wm;
        std::vector<std::string> win;
        auto log = [&](const std::string& s) {
            std::lock_guard<std::mutex> g(wm);
            win.push_back(s);
        };
        auto upKey = [&](uint16_t v) {
            log("Ku" + std::to_string(v));
            return true;
        };
        auto upButton = [&](uint8_t v) {
            log("Bu" + std::to_string(v));
            return true;
        };
        std::atomic<int> retiredCount{0};
        b.onVoid([&] {
            bool retired = false;
            claims.retire([&](uint64_t o) { return b.live(o); }, upKey, upButton, &retired);
            if (retired) ++retiredCount;
        });
        const auto pol = b.policyGeneration();
        const auto a = b.admit("100.64.0.1", Channel::Control, keyOf(1), sidOf(1), std::nullopt, false, pol, {});
        // A second control login from the same viewer that never sent input
        // (auto refused it in production; here a clipboard channel of A's
        // session stands for "admitted, never the owner").
        const auto c = b.admit("100.64.0.1", Channel::Clipboard, std::nullopt, std::nullopt, sidOf(1), false, pol, {});
        CHECK(a.refused == SessionBroker::Refusal::None && c.refused == SessionBroker::Refusal::None);
        claims.openAs(a.token);
        claims.openAs(c.token);
        const auto liveA = [&] { return b.live(a.token); };
        const auto liveC = [&] { return b.live(c.token); };
        InputEvent press;
        press.kind = InputEvent::Kind::Key;
        press.down = true;
        CHECK(claims
                  .frameIfLive(
                      a.token, kIp, press, liveA,
                      [&](HeldInput& h) {
                          log("Kd65");
                          h.pressKey('A', a.token);
                          return true;
                      },
                      upKey, upButton)
                  .tookOver);
        std::atomic<bool> inside{false}, voidCalling{false}, voidDone{false};
        bool voidDoneDuringA = true;
        InputClaims::Frame fa;
        std::thread ta([&] {
            fa = claims.frameIfLive(
                a.token, kIp, press, liveA,
                [&](HeldInput& h) {
                    inside = true;
                    while (!voidCalling) std::this_thread::yield();
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));  // the void has every chance to run
                    voidDoneDuringA = voidDone.load();
                    log("Kd66");
                    h.pressKey('B', a.token);
                    return true;
                },
                upKey, upButton);
        });
        while (!inside) std::this_thread::yield();
        SessionBroker::Admitted nb;
        std::thread tv([&] {
            voidCalling = true;
            if (how == 0)
                nb = b.admit("100.64.0.2", Channel::Control, keyOf(2), sidOf(2), std::nullopt, false, pol, {});
            else if (how == 1)
                b.voidAll(CloseReason::Policy, true);
            else
                b.kickPeer("100.64.0.1", CloseReason::Blocked);
            log("void");
            voidDone = true;
        });
        ta.join();
        tv.join();
        CHECK(fa.admitted && fa.injected && !voidDoneDuringA);
        {
            std::lock_guard<std::mutex> g(wm);
            const std::set<std::string> want{"Ku65", "Ku66"};
            const std::set<std::string> ups(win.begin() + std::min<size_t>(2, win.size()),
                                            win.begin() + std::min<size_t>(4, win.size()));
            CHECK(win.size() == 5 && win[0] == "Kd65" && win[1] == "Kd66" && win[4] == "void" &&
                  ups == want);
        }
        CHECK(retiredCount == 1 && claims.owner() == 0 && !claims.anyHeld());
        // Read before the void, acted on after it: nothing goes in.
        bool called = false;
        const auto late = claims.frameIfLive(
            a.token, kIp, press, liveA,
            [&](HeldInput&) {
                called = true;
                return true;
            },
            upKey, upButton);
        CHECK(late.revoked && !late.admitted && !late.tookOver && !called);
        // c had never been the owner and is newer than every owner: without
        // the check it would take input now.
        const auto lateC = claims.frameIfLive(
            c.token, kIp, press, liveC,
            [&](HeldInput&) {
                called = true;
                return true;
            },
            upKey, upButton);
        CHECK(lateC.revoked && !lateC.admitted && !lateC.tookOver && !called && claims.owner() == 0);
        if (how == 0) {
            // The new viewer's first input takes ownership; nothing is left to release.
            CHECK(nb.refused == SessionBroker::Refusal::None);
            claims.openAs(nb.token);
            const auto fb = claims.frameIfLive(
                nb.token, kIp + 1, press, [&] { return b.live(nb.token); },
                [&](HeldInput& h) {
                    log("Kd67");
                    h.pressKey('C', nb.token);
                    return true;
                },
                upKey, upButton);
            CHECK(fb.admitted && fb.tookOver && fb.replaced == 0 && fb.released == 0 && claims.owner() == nb.token);
            // A block of another address leaves the live owner alone.
            CHECK(b.kickPeer("100.64.0.9", CloseReason::Blocked) == 0);
            CHECK(retiredCount == 1 && claims.owner() == nb.token && claims.held().keyOwnedBy('C', nb.token));
            b.end(nb.token);
        }
        claims.close(a.token, upKey, upButton);
        claims.close(c.token, upKey, upButton);
        b.end(a.token);
        b.end(c.token);
        b.flushClosesForTest();
    }
}

static void testUdpChecks(const std::vector<Vector>& vs) {
    // The vector tags are over the raw bytes; a sealed datagram sets the
    // flag first and the tag covers it (udp_tag.hpp).
    const Vector& v = vs.front();
    PortableTags t(v.sessionKey);
    Bytes flagged = v.v2hPacket;
    flagged[kUdpVersionByte] |= kUdpTagFlag;
    uint8_t want[kTagBytes];
    CHECK(udpTag(portableHmac, v.sessionKey, false, flagged.data(), flagged.size(), want));
    // The host verifies v2h: the viewer's sealed datagram.
    Bytes in = flagged;
    in.insert(in.end(), want, want + kTagBytes);
    CHECK(t.verify(in.data(), in.size()));
    CHECK(std::string(badTagReason(in.data(), in.size())) == "bad_tag");  // the caller asks only after verify failed
    in[in.size() - 1] ^= 1;
    CHECK(!t.verify(in.data(), in.size()));
    Bytes untagged = v.v2hPacket;
    CHECK(!t.verify(untagged.data(), untagged.size()));
    CHECK(std::string(badTagReason(untagged.data(), untagged.size())) == "no_tag");
    CHECK(std::string(badTagReason(in.data(), kUdpVersionByte)) == "short");
    // The host seals h2v: flag set, tag over the flagged bytes.
    const Bytes& plain = v.h2vPacket;
    std::vector<uint8_t> out(plain.size() + kTagBytes);
    CHECK(t.seal(plain.data(), plain.size(), out.data()) == plain.size() + kTagBytes);
    Bytes expect = plain;
    expect[kUdpVersionByte] |= kUdpTagFlag;
    CHECK(udpTag(portableHmac, v.sessionKey, true, expect.data(), expect.size(), want));
    expect.insert(expect.end(), want, want + kTagBytes);
    CHECK(Bytes(out.begin(), out.end()) == expect);
    // A reflected host datagram does not verify as viewer -> host.
    CHECK(!t.verify(out.data(), out.size()));

    SeqReplayWindow w;
    CHECK(w.check(100) == SeqReplayWindow::Verdict::Newest);
    w.mark(100);
    CHECK(w.check(100) == SeqReplayWindow::Verdict::Duplicate);
    CHECK(w.check(99) == SeqReplayWindow::Verdict::Late);
    w.mark(99);
    CHECK(w.check(99) == SeqReplayWindow::Verdict::Duplicate);
    CHECK(w.check(36) == SeqReplayWindow::Verdict::TooOld);
    CHECK(w.check(37) == SeqReplayWindow::Verdict::Late);
    CHECK(w.check(200) == SeqReplayWindow::Verdict::Newest);
    CHECK(w.check(100) == SeqReplayWindow::Verdict::TooOld);
    CHECK(w.check(0xFFFFFFF0u) == SeqReplayWindow::Verdict::TooOld);

    double now = 0;
    std::vector<std::string> lines;
    BadTagLog log("mrm1", [&] { return now; }, [&](const std::string& s) { lines.push_back(s); });
    log.drop("100.64.0.1", "bad_tag");
    log.drop("100.64.0.1", "bad_tag");
    now = 11;
    log.drop("100.64.0.2", "no_tag");
    CHECK(lines.size() == 2 && log.total() == 3);
    CHECK(lines[0] == "udp.bad_tag entry=mrm1 peer=100.64.0.1 reason=bad_tag n=1 total=1");
    CHECK(lines[1] == "udp.bad_tag entry=mrm1 peer=100.64.0.2 reason=no_tag n=2 total=3");

    std::vector<std::string> al;
    double at = 0;
    AuthLogThrottle th([&] { return at; }, [&](const std::string& s) { al.push_back(s); });
    th.log("auth.blocked", "1.2.3.4", "a");
    th.log("auth.blocked", "1.2.3.4", "b");
    th.log("auth.blocked", "1.2.3.5", "c");
    at = 10.5;
    th.log("auth.blocked", "1.2.3.4", "d");
    CHECK((al == std::vector<std::string>{"a", "c", "d suppressed=1"}));
    for (int i = 0; i < 1100; ++i) th.log("auth.x", std::to_string(i), "x");
    CHECK(th.keyCount() <= AuthLogThrottle::kMaxKeys);
}

class MemoryFailureLog : public FailureLogStore {
public:
    std::vector<FailureRecord> records;
    std::vector<int64_t> times;
    std::vector<FailureRecord> loadRecords() override { return records; }
    std::vector<int64_t> loadTimes() override { return times; }
    void save(const std::vector<FailureRecord>& r, const std::vector<int64_t>& t) override {
        records = r;
        times = t;
    }
};

static void testFailureLog() {
    MemoryFailureLog store;
    {
        AuthFailureLog log(store);
        for (int i = 0; i < 25; ++i) log.record("100.64.0." + std::to_string(i), "wrong_password", i + 1, 1000 + i);
        log.flush();
    }
    CHECK(store.records.size() == kFailureRecordLimit);
    CHECK(store.records.back().ip == "100.64.0.24" && store.records.front().ip == "100.64.0.5");
    CHECK(store.times.size() == 25);
    const auto pruned = prunedFailureTimes({1, 2, 3}, 1 + kFailureWindowSeconds, 5000);
    CHECK((pruned == std::vector<int64_t>{2, 3, 1 + kFailureWindowSeconds}));
    const auto capped = prunedFailureTimes({10, 11, 12}, 13, 2);
    CHECK((capped == std::vector<int64_t>{12, 13}));
    const auto s = summarizeFailures(store.records, store.times, 1030);
    CHECK(s.last24h == 25 && s.lastIp == "100.64.0.24" && s.lastAt == 1024 && !s.capped);
}

// ------------------------------------------------------------ socket tests

#ifdef _WIN32
using SockLen = int;
static void closeSock(SocketHandle s) { closesocket(s); }
#else
using SockLen = socklen_t;
static void closeSock(SocketHandle s) { close(s); }
#endif
#ifdef _WIN32
static const SocketHandle kNoSocket = INVALID_SOCKET;
#else
static const SocketHandle kNoSocket = -1;
#endif

static SocketHandle listenLoopback(uint16_t& port) {
    SocketHandle l = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    bind(l, reinterpret_cast<sockaddr*>(&a), sizeof(a));
    listen(l, 16);
    SockLen len = sizeof(a);
    getsockname(l, reinterpret_cast<sockaddr*>(&a), &len);
    port = ntohs(a.sin_port);
    return l;
}

// `src`: another loopback address to connect from (127.0.0.2: another
// viewer machine as far as the host can tell).
static SocketHandle connectLoopback(uint16_t port, int rcvbuf = 0, const char* src = nullptr) {
    SocketHandle s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (rcvbuf) setsockopt(s, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&rcvbuf), sizeof(rcvbuf));
    if (src) {
        sockaddr_in from{};
        from.sin_family = AF_INET;
        inet_pton(AF_INET, src, &from.sin_addr);
        if (bind(s, reinterpret_cast<sockaddr*>(&from), sizeof(from)) != 0) {
            std::printf("  (cannot bind %s, error %d)\n", src, sockError());
            closeSock(s);
            return kNoSocket;
        }
    }
#ifdef _WIN32
    DWORD tv = 8000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
    timeval tv{8, 0};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(port);
    if (connect(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
        closeSock(s);
        return kNoSocket;
    }
    return s;
}

static bool sendAllBlocking(SocketHandle s, const Bytes& b) {
    size_t off = 0;
    while (off < b.size()) {
        const long r = rawSend(s, b.data() + off, b.size() - off);
        if (r <= 0) return false;
        off += size_t(r);
    }
    return true;
}
static Bytes frame(uint8_t type, const Bytes& p) {
    Bytes b{'M', 'R', 'C', '1', 1, type, uint8_t(p.size() >> 8), uint8_t(p.size())};
    b.insert(b.end(), p.begin(), p.end());
    return b;
}

// 1: a frame; 0: the connection ended (FIN or reset); -1: nothing in time.
static int readFrame(SocketHandle s, uint8_t& type, Bytes& payload) {
    uint8_t h[8];
    size_t got = 0;
    while (got < 8) {
        const long r = rawRecv(s, h + got, 8 - got);
        if (r == 0) return 0;
        if (r < 0) return sockWouldBlock(sockError()) ? -1 : 0;
        got += size_t(r);
    }
    type = h[5];
    payload.assign(size_t(h[6]) << 8 | h[7], 0);
    got = 0;
    while (got < payload.size()) {
        const long r = rawRecv(s, payload.data() + got, payload.size() - got);
        if (r <= 0) return 0;
        got += size_t(r);
    }
    return 1;
}

// The scripted viewer.
struct Viewer {
    SocketHandle s = kNoSocket;
    Nonce hn{};
    Salt salt{};
    uint32_t iterations = 0;
    HostId hostId{};
    Nonce cn{};
    Channel ch = Channel::Control;
    const char* src = nullptr;  // connect from this loopback address

    Viewer() = default;
    explicit Viewer(const char* from) : src(from) {}
    ~Viewer() {
        if (s != kNoSocket) closeSock(s);
    }
    bool open(uint16_t port, int rcvbuf = 0) {
        s = connectLoopback(port, rcvbuf, src);
        return s != kNoSocket;
    }
    bool readChallenge() {
        uint8_t t = 0;
        Bytes p;
        if (readFrame(s, t, p) != 1 || t != kMsgChallenge || p.size() != kChallengeBytes) return false;
        std::memcpy(hn.data(), p.data(), 32);
        std::memcpy(salt.data(), p.data() + 32, 16);
        iterations = uint32_t(p[48]) << 24 | uint32_t(p[49]) << 16 | uint32_t(p[50]) << 8 | p[51];
        std::memcpy(hostId.data(), p.data() + 53, 16);
        return p[52] == kKdfPbkdf2Sha256;
    }
    bool answer(const Key& k, Channel c, const std::optional<SessionId>& resume = std::nullopt, bool zeroMac = false) {
        ch = c;
        for (size_t i = 0; i < cn.size(); ++i) cn[i] = uint8_t(i * 7 + 3);
        Mac m{};
        if (!zeroMac) macClient(portableHmac, k, hn, cn, c, hostId, resume ? &*resume : nullptr, m);
        Bytes p(cn.begin(), cn.end());
        p.insert(p.end(), m.begin(), m.end());
        if (resume) p.insert(p.end(), resume->begin(), resume->end());
        return sendAllBlocking(s, frame(kMsgResponse, p));
    }
    // RESULT payload, or empty when none came.
    Bytes result() {
        uint8_t t = 0;
        Bytes p;
        if (readFrame(s, t, p) != 1 || t != kMsgResult) return {};
        return p;
    }
    // Logs in; returns the session id (and checks mac_h).
    std::optional<SessionId> login(uint16_t port, const Key& k, Channel c,
                                   const std::optional<SessionId>& resume = std::nullopt) {
        if (!open(port) || !readChallenge()) return std::nullopt;
        return finishLogin(k, c, resume);
    }
    // The rest of a login after readChallenge().
    std::optional<SessionId> finishLogin(const Key& k, Channel c,
                                         const std::optional<SessionId>& resume = std::nullopt) {
        if (!answer(k, c, resume)) return std::nullopt;
        const Bytes r = result();
        if (r.size() != 41 || r[0] != 0) return std::nullopt;
        Mac want{};
        macHost(portableHmac, k, hn, cn, c, want);
        if (std::memcmp(want.data(), r.data() + 1, 32) != 0) return std::nullopt;
        SessionId sid{};
        std::memcpy(sid.data(), r.data() + 33, 8);
        return sid;
    }
    // A PING answered by PONG with the same payload.
    bool ping(uint8_t n) {
        if (!sendAllBlocking(s, frame(0x01, Bytes{n, 0, 0, 0}))) return false;
        uint8_t t = 0;
        Bytes p;
        return readFrame(s, t, p) == 1 && t == 0x02 && p == (Bytes{n, 0, 0, 0});
    }
    // After the last frame: 0 for a clean FIN, -1 for a reset (or a read
    // error), 1 if more bytes came.
    int closeKind() {
        uint8_t b = 0;
        const long r = rawRecv(s, &b, 1);
        return r > 0 ? 1 : r == 0 ? 0 : -1;
    }
    // The connection ended with no frame (0) or something came (1/-1).
    int endsWithoutFrame() {
        uint8_t t = 0;
        Bytes p;
        return readFrame(s, t, p);
    }
};

// One host listener with the real AuthConn on its connections.
struct HostRig {
    FakeClock clock;
    MemoryBlocklist store;
    MemoryPendingBlocks journal;
    std::vector<std::string> lines;
    std::mutex lm;
    AuthGuard guard;
    SessionBroker broker;
    AuthLogThrottle throttle;
    AuthCounters counters;
    MemoryFailureLog failureStore;
    AuthFailureLog failureLog;
    AuthEnv env;
    std::shared_ptr<const AuthSecret> secret;
    std::atomic<bool> stopping{false};
    uint16_t port = 0;
    SocketHandle listener = kNoSocket;
    std::vector<std::thread> threads;
    std::atomic<int> served{0};
    uint32_t seed = 1;
    std::mutex rm;
    // runAcceptLoop(): host_main.cpp's controlListener and serveControl.
    jlh::ConnectionSlots slots;
    std::atomic<int> workers{0};  // connections that got a worker thread
    std::vector<std::thread> workerThreads;
    std::mutex wm;

    explicit HostRig(const Vector& v)
        : guard({}, store, &journal, testHooks(clock, &lines, &lm)),
          broker(portableTags(), [this](const std::string& s) { note(s); }),
          throttle([this] { return clock.t.load(); }, [this](const std::string& s) { note(s); }),
          failureLog(failureStore) {
        auto s = std::make_shared<AuthSecret>();
        s->key = v.key;
        s->salt = v.salt;
        s->iterations = v.iterations;
        s->hostId = v.hostId;
        secret = s;
        env.hmac = portableHmac;
        env.random = [this](uint8_t* p, size_t n) {
            std::lock_guard<std::mutex> g(rm);
            std::mt19937 r(seed++);
            for (size_t i = 0; i < n; ++i) p[i] = uint8_t(r());
            return true;
        };
        env.guard = &guard;
        env.broker = &broker;
        env.failureLog = &failureLog;
        env.authLog = &throttle;
        env.counters = &counters;
        env.log = [this](const std::string& s) { note(s); };
        env.wallNow = [this] { return clock.wall.load(); };
        env.stopping = [this] { return stopping.load(); };
        env.policy = [this] {
            std::lock_guard<std::mutex> g(lm);
            return PolicySnapshot{secret, broker.policyGeneration()};
        };
        listener = listenLoopback(port);
        env.endpoint = "127.0.0.1:" + std::to_string(port);
    }
    ~HostRig() {
        stopping = true;
        for (auto& t : threads) t.join();  // the accept loop first: no new workers after it
        for (auto& t : workerThreads) t.join();
        closeSock(listener);
    }
    void note(const std::string& s) {
        std::lock_guard<std::mutex> g(lm);
        lines.push_back(s);
    }
    bool saw(const std::string& prefix) {
        std::lock_guard<std::mutex> g(lm);
        for (const auto& l : lines)
            if (l.rfind(prefix, 0) == 0) return true;
        return false;
    }
    int count(const std::string& prefix) {
        std::lock_guard<std::mutex> g(lm);
        int n = 0;
        for (const auto& l : lines) n += l.rfind(prefix, 0) == 0;
        return n;
    }
    bool waitFor(const std::string& prefix, int ms = 4000) {
        for (int i = 0; i < ms / 10; ++i) {
            if (saw(prefix)) return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        std::printf("  (no log line starting \"%s\")\n", prefix.c_str());
        return false;
    }
    void dump() {
        std::lock_guard<std::mutex> g(lm);
        for (const auto& l : lines) std::printf("  log: %s\n", l.c_str());
    }

    // Serves the next connection on its own thread, as serveControl does.
    void serveNext(int sndbuf = 0) {
        threads.emplace_back([this, sndbuf] {
            sockaddr_in a{};
            SockLen len = sizeof(a);
            SocketHandle s = accept(listener, reinterpret_cast<sockaddr*>(&a), &len);
            if (s == kNoSocket) return;
            if (sndbuf) setsockopt(s, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char*>(&sndbuf), sizeof(sndbuf));
            char ipb[32] = {};
            inet_ntop(AF_INET, &a.sin_addr, ipb, sizeof(ipb));
            if (!setNonBlocking(s)) {
                closeSock(s);
                return;
            }
            serveConn(s, ipb, 0, false);
        });
    }
    // host_main.cpp's controlListener: every connection on this listener
    // goes through acceptStep on this one thread; only Serve starts a
    // worker, which holds the place taken there.
    void runAcceptLoop() {
        threads.emplace_back([this] {
            while (!stopping) {
                if (waitSocket(listener, false, 20) != 1) continue;
                sockaddr_in a{};
                SockLen len = sizeof(a);
                SocketHandle s = accept(listener, reinterpret_cast<sockaddr*>(&a), &len);
                if (s == kNoSocket) continue;
                char ipb[32] = {};
                inet_ntop(AF_INET, &a.sin_addr, ipb, sizeof(ipb));
                const uint32_t source = uint32_t(a.sin_addr.s_addr);
                if (acceptStep(env, slots, s, ipb, source) != AcceptVerdict::Serve) {
                    closeSock(s);
                    continue;
                }
                ++workers;
                std::lock_guard<std::mutex> g(wm);
                workerThreads.emplace_back([this, s, ip = std::string(ipb), source] { serveConn(s, ip, source, true); });
            }
        });
    }
    // serveControl after the socket is set up. `slotted`: it holds a place
    // in `slots` (runAcceptLoop): the handshake part goes back when the
    // password matched, the rest when the connection ends.
    void serveConn(SocketHandle s, const std::string& ip, uint32_t source, bool slotted) {
        {
            AuthConn c(env, s, ip);
            auto life = std::make_shared<ConnLife>();
            const auto ok = c.authenticate();
            bool inHandshake = true;
            if (ok && slotted) {
                slots.authenticated(source);
                inHandshake = false;
            }
            std::optional<uint64_t> token;
            if (ok) token = c.admit(*ok, life);
            if (ok && token) {
                bool first = true;
                for (;;) {
                    jlh::Mrc1Header h;
                    Bytes payload;
                    const auto r = jlh::readMrc1FrameUntil(s, h, payload, jlh::kReadSliceMs,
                                                           [&] { return stopping.load() || life->revoked(); });
                    if (r != jlh::ReadResult::Ok) break;
                    if (!c.admitMessage(*ok, *life, h.type, first)) break;
                    first = false;
                    if (h.type == 0x01 && payload.size() == 4) {
                        if (c.sendChecked(life.get(), "ping", 0x02, payload, -1, ok->channel == Channel::Control) !=
                            CheckedSend::Sent)
                            break;
                    } else if (h.type == 0x7E) {
                        // Test hook: a stream of large frames until refused.
                        Bytes big(60000, 0x5A);
                        while (c.sendChecked(life.get(), "video", 0x7F, big, -1, true) == CheckedSend::Sent) {
                        }
                        break;
                    }
                }
                c.finish(*ok, *token, *life);
            }
            finishSocket(s, c.resetRequested());
            if (slotted) slots.release(source, inHandshake);
        }
        ++served;
    }
    void waitServed(int n) {
        for (int i = 0; i < 800 && served.load() < n; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
};

static void testAuthOverLoopback(const Vector& v) {
    // Right password, every channel, and the takeover.
    {
        HostRig h(v);
        h.serveNext();
        Viewer a;
        const auto sidA = a.login(h.port, v.key, Channel::Control);
        CHECK(sidA.has_value());
        CHECK(a.ping(1));
        CHECK(h.waitFor("auth.ok peer=127.0.0.1 chan=control session=" + (sidA ? hex(*sidA) : std::string("?"))));
        CHECK(h.broker.current() && h.broker.current()->peerIp == "127.0.0.1");
        CHECK(a.iterations == v.iterations && a.salt == v.salt && a.hostId == v.hostId);

        // Clipboard with the control session's id.
        h.serveNext();
        Viewer clip;
        CHECK(clip.login(h.port, v.key, Channel::Clipboard, sidA).has_value());
        CHECK(sendAllBlocking(clip.s, frame(0x30, {})));
        // Clipboard with someone else's id: closed, no REPLACED.
        h.serveNext();
        Viewer clip2;
        CHECK(clip2.open(h.port) && clip2.readChallenge() && clip2.answer(v.key, Channel::Clipboard, sidOf(0xEE)));
        CHECK(clip2.endsWithoutFrame() == 0);
        CHECK(h.waitFor("auth.channel_unadmitted peer=127.0.0.1 chan=clipboard resume=eeeeeeeeeeeeeeee counted=0"));

        // r14: an auto reconnect while A is connected: REPLACED, A stays.
        h.serveNext();
        Viewer autoV;
        SessionId marker;
        std::memcpy(marker.data(), kAutoMarker, 8);
        CHECK(autoV.open(h.port) && autoV.readChallenge() && autoV.answer(v.key, Channel::Control, marker));
        CHECK(autoV.result() == Bytes{6});
        CHECK(h.waitFor("auth.resume_refused peer=127.0.0.1 chan=control stage=auth reason=auto_while_connected sent=1"));
        CHECK(a.ping(2));

        // Ping channel: only PING.
        h.serveNext();
        Viewer pv;
        CHECK(pv.login(h.port, v.key, Channel::Ping, sidA).has_value());
        CHECK(pv.ping(3));
        CHECK(sendAllBlocking(pv.s, frame(0x10, Bytes{1, 2, 3})));
        CHECK(pv.endsWithoutFrame() == 0);
        CHECK(h.waitFor("auth.channel_mismatch peer=127.0.0.1 chan=ping type=0x10"));

        // B logs in: A gets REPLACED and then the end; the clipboard
        // connection is closed with no notice; B works.
        h.serveNext();
        Viewer b;
        const auto sidB = b.login(h.port, v.key, Channel::Control);
        CHECK(sidB && sidA && *sidB != *sidA);
        CHECK(a.result() == Bytes{6});
        CHECK(a.endsWithoutFrame() == 0);
        CHECK(clip.endsWithoutFrame() == 0);
        CHECK(h.waitFor("auth.replaced old_peer=127.0.0.1 chan=control new_peer=127.0.0.1"));
        CHECK(h.waitFor("auth.replaced_notice peer=127.0.0.1 sent=1"));
        CHECK(b.ping(4));
        // Every reconnect is a fresh AUTH: A's old id opens nothing.
        h.serveNext();
        Viewer stale;
        CHECK(stale.open(h.port) && stale.readChallenge() && stale.answer(v.key, Channel::File, sidA));
        CHECK(stale.endsWithoutFrame() == 0);

        // Password changed in the settings window: B closed, no notice.
        {
            std::lock_guard<std::mutex> g(h.lm);
            auto s2 = std::make_shared<AuthSecret>(*h.secret);
            s2->key = keyOf(0x42);
            h.secret = s2;
        }
        h.broker.voidAll(CloseReason::Policy, true);
        CHECK(b.endsWithoutFrame() == 0);
        CHECK(h.waitFor("auth.closed peer=127.0.0.1 chan=control reason=policy_changed"));
        // The old password no longer works; the new one does.
        h.serveNext();
        Viewer old;
        CHECK(old.open(h.port) && old.readChallenge() && old.answer(v.key, Channel::Control));
        CHECK(old.result() == (Bytes{1, 4}));
        h.serveNext();
        Viewer fresh;
        CHECK(fresh.login(h.port, keyOf(0x42), Channel::Control).has_value());
        CHECK(fresh.ping(5));
        CHECK(h.counters.failures == 1 && h.guard.failures("127.0.0.1") == 0);

        // Blocked in the settings window: closed at once (reset), and a new
        // connection gets BLOCKED before any challenge.
        h.store.entries.push_back({"127.0.0.1", 1, "manual"});
        ++h.store.stamp.b;
        h.guard.probeJournal();
        kickNewlyBlocked(h.guard, h.broker);
        CHECK(fresh.endsWithoutFrame() == 0);
        CHECK(h.waitFor("auth.closed peer=127.0.0.1 chan=control reason=blocked"));
        h.serveNext();
        Viewer blocked;
        CHECK(blocked.open(h.port));
        CHECK(blocked.result() == Bytes{3});
        CHECK(h.waitFor("auth.blocked peer=127.0.0.1; connection closed"));
        h.waitServed(11);
        if (gFailures) h.dump();
    }

    // Wrong passwords over the wire: the whole ladder, as the viewer sees it.
    {
        HostRig h(v);
        const Key wrong = keyOf(0x13);
        for (int stage = 1; stage <= 4; ++stage) {
            for (int i = 1; i <= 5; ++i) {
                h.serveNext();
                Viewer w;
                CHECK(w.open(h.port) && w.readChallenge() && w.answer(wrong, Channel::Control));
                const Bytes r = w.result();
                if (stage == 4 && i == 5)
                    CHECK(r == Bytes{3});
                else if (i == 5)
                    CHECK(r == resultLocked(uint32_t(300 * stage)));
                else
                    CHECK(r == resultFail(uint8_t(5 - i)));
            }
            if (stage < 4) {
                // Locked: no challenge, LOCKED first.
                h.serveNext();
                Viewer l;
                CHECK(l.open(h.port));
                const Bytes r = l.result();
                CHECK(r.size() == 5 && r[0] == 2);
                h.clock.t = h.clock.t + 300.0 * stage + 1;
            }
        }
        CHECK(h.waitFor("auth.fail peer=127.0.0.1 chan=unknown reason=wrong_password failures=1 tries=4"));
        CHECK(h.waitFor("auth.fail peer=127.0.0.1 chan=unknown reason=wrong_password failures=5"));
        CHECK(h.waitFor("auth.locked peer=127.0.0.1 retry_s=300 stage=1"));
        CHECK(h.waitFor("auth.locked peer=127.0.0.1 retry_s=300 stage=1; connection closed"));
        CHECK(h.waitFor("auth.locked peer=127.0.0.1 retry_s=900 stage=3"));
        CHECK(h.waitFor("auth.blocked peer=127.0.0.1 failures=20 persisted=registry"));
        CHECK(h.store.entries.size() == 1 && h.store.entries[0].ip == "127.0.0.1");
        h.failureLog.flush();
        CHECK(h.failureStore.records.size() == kFailureRecordLimit && h.failureStore.times.size() == 20);
        CHECK(h.failureStore.records.back().failures == 20);
        h.serveNext();
        Viewer right;
        CHECK(right.open(h.port) && right.result() == Bytes{3});
        h.waitServed(24);
    }

    // Answers that are not a password: what is counted and what is not.
    {
        HostRig h(v);
        h.env.authTimeoutMs = 300;
        // A 0.3.x viewer's first message: AUTH_REQUIRED, not counted.
        h.serveNext();
        Viewer o;
        CHECK(o.open(h.port) && o.readChallenge());
        CHECK(sendAllBlocking(o.s, frame(0x01, Bytes{0, 0, 0, 1})));
        CHECK(o.result() == Bytes{4});
        CHECK(h.waitFor("auth.old_viewer peer=127.0.0.1 type=0x1 counted=0"));
        // PR-C item 5: a probe that crossed the challenge: tries left, not counted.
        h.serveNext();
        Viewer p;
        CHECK(p.open(h.port) && p.readChallenge() && p.answer(v.key, Channel::Control, std::nullopt, true));
        CHECK(p.result() == (Bytes{1, 5}));
        CHECK(h.waitFor("auth.probe_race peer=127.0.0.1 tries=5 counted=0"));
        // The viewer closes without answering: not counted.
        h.serveNext();
        {
            Viewer c;
            CHECK(c.open(h.port) && c.readChallenge());
        }
        CHECK(h.waitFor("auth.no_response peer=127.0.0.1 reason=closed counted=0"));
        CHECK(h.guard.failures("127.0.0.1") == 0 && h.counters.oldViewers == 1 && h.counters.probes == 1);
        // Silence past the timeout: counted.
        h.serveNext();
        Viewer t;
        CHECK(t.open(h.port) && t.readChallenge());
        CHECK(t.result() == (Bytes{1, 4}));
        CHECK(h.waitFor("auth.fail peer=127.0.0.1 chan=unknown reason=timeout failures=1 tries=4"));
        // An unknown first header and a bad length: counted.
        h.serveNext();
        Viewer bh;
        CHECK(bh.open(h.port) && bh.readChallenge() && sendAllBlocking(bh.s, frame(0x77, Bytes(3, 0))));
        CHECK(bh.result() == (Bytes{1, 3}));
        // The unread payload is drained: a FIN, not a reset (an RST can
        // throw the RESULT away on Windows).
        CHECK(bh.closeKind() == 0);
        CHECK(h.waitFor("auth.fail peer=127.0.0.1 chan=unknown reason=bad_header failures=2 tries=3"));
        h.serveNext();
        Viewer bl;
        CHECK(bl.open(h.port) && bl.readChallenge() && sendAllBlocking(bl.s, frame(kMsgResponse, Bytes(65, 1))));
        CHECK(bl.result() == (Bytes{1, 2}));
        CHECK(bl.closeKind() == 0);
        CHECK(h.waitFor("auth.fail peer=127.0.0.1 chan=unknown reason=bad_response failures=3 tries=2"));
        // r9: an OK that did not go out drops the session.
        h.env.failAuthOKForTest = [](const AuthOK& ok) { return ok.channel == Channel::Control; };
        h.serveNext();
        Viewer u;
        CHECK(u.open(h.port) && u.readChallenge() && u.answer(v.key, Channel::Control));
        CHECK(u.endsWithoutFrame() == 0);
        CHECK(h.waitFor("auth.ok_unsent peer=127.0.0.1 chan=control; session dropped, the viewer reconnects"));
        CHECK(!h.broker.controlOpen() && h.guard.failures("127.0.0.1") == 0);
        h.env.failAuthOKForTest = nullptr;
        // D9: no password set: nobody gets a challenge.
        {
            std::lock_guard<std::mutex> g(h.lm);
            h.secret.reset();
        }
        h.serveNext();
        Viewer np;
        CHECK(np.open(h.port) && np.endsWithoutFrame() == 0);
        CHECK(h.waitFor("Control reject peer=127.0.0.1 reason=no_password on 127.0.0.1:"));
        h.waitServed(8);
    }

    // An open connection whose address is blocked (not kicked yet): its
    // next message is refused and the connection reset.
    {
        HostRig h(v);
        h.serveNext();
        Viewer a;
        CHECK(a.login(h.port, v.key, Channel::Control).has_value());
        CHECK(a.ping(1));
        h.store.entries.push_back({"127.0.0.1", 1, "manual"});
        ++h.store.stamp.b;
        CHECK(sendAllBlocking(a.s, frame(0x01, Bytes{2, 0, 0, 0})));
        CHECK(a.endsWithoutFrame() == 0);
        CHECK(h.waitFor("auth.peer_refused peer=127.0.0.1 reason=blocked entry=open_connection; closed"));
        CHECK(h.waitFor("Control reject peer=127.0.0.1 reason=peer_refused type=0x1 on 127.0.0.1:"));
        h.waitServed(1);
    }

    // A takeover while the old connection is stuck in a send (the viewer
    // stopped reading): the send stops within a slice, the old line gets
    // no REPLACED after half a frame (r14), and the new one works.
    {
        HostRig h(v);
        h.serveNext(8192);
        Viewer a;
        CHECK(a.open(h.port, 4096) && a.readChallenge() && a.answer(v.key, Channel::Control));
        CHECK(a.result().size() == 41);
        CHECK(sendAllBlocking(a.s, frame(0x7E, {})));
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        h.serveNext();
        Viewer b;
        const auto t0 = std::chrono::steady_clock::now();
        CHECK(b.login(h.port, v.key, Channel::Control).has_value());
        CHECK(h.waitFor("auth.replaced_notice peer=127.0.0.1 sent=0"));
        const auto took = std::chrono::steady_clock::now() - t0;
        CHECK(took < std::chrono::milliseconds(2500));
#ifndef _WIN32
        CHECK(h.saw("auth.replaced_notice peer=127.0.0.1 sent=0 skipped=partial_frame; connection reset"));
#endif
        CHECK(b.ping(9));
        h.waitServed(2);
        if (gFailures) h.dump();
    }
}

// ------------------------------------------ H3 r2 (Pepper's review r1)

static uint32_t addrOf(const char* ip) {
    in_addr a{};
    inet_pton(AF_INET, ip, &a);
    return uint32_t(a.s_addr);
}

// Item 1: the accept thread answers an address the guard refuses (here the
// blacklist, then its own wait) by itself. It never gets a worker or a
// place, however often it connects.
static void testAcceptScreen(const Vector& v) {
    HostRig h(v);
    h.store.entries.push_back({"127.0.0.2", 1, "manual"});
    ++h.store.stamp.b;
    h.runAcceptLoop();
    for (int i = 0; i < 12; ++i) {
        Viewer x("127.0.0.2");
        CHECK(x.open(h.port));
        CHECK(x.result() == Bytes{3});  // BLOCKED, before any challenge
        CHECK(x.closeKind() == 0);      // then a plain FIN
    }
    CHECK(h.workers == 0 && h.slots.inUse() == 0 && h.slots.handshakes() == 0);
    CHECK(h.waitFor("auth.blocked peer=127.0.0.2; connection closed"));

    // 127.0.0.4 locks itself out with five wrong answers; from then on it
    // is refused at accept too.
    for (int i = 0; i < 5; ++i) {
        Viewer w("127.0.0.4");
        CHECK(w.open(h.port) && w.readChallenge() && w.answer(keyOf(0x42), Channel::Control));
        const Bytes r = w.result();
        CHECK(i < 4 ? r == (Bytes{1, uint8_t(4 - i)}) : (r.size() == 5 && r[0] == 2));
    }
    CHECK(h.workers == 5);
    for (int i = 0; i < 12; ++i) {
        Viewer x("127.0.0.4");
        CHECK(x.open(h.port));
        const Bytes r = x.result();
        CHECK(r.size() == 5 && r[0] == 2);  // LOCKED
    }
    CHECK(h.workers == 5);
    CHECK(h.waitFor("auth.locked peer=127.0.0.4 retry_s=300 stage=1; connection closed"));
    CHECK(h.count("auth.locked peer=127.0.0.4 retry_s=300 stage=1; connection closed") == 1);  // one per 10 s

    // Not on the whitelist: closed with no frame, no worker, one log line.
    h.guard.setWhitelist({"127.0.0.1"});
    for (int i = 0; i < 12; ++i) {
        Viewer x("127.0.0.5");
        CHECK(x.open(h.port));
        CHECK(x.endsWithoutFrame() == 0);
    }
    CHECK(h.workers == 5);
    CHECK(h.waitFor("Control reject peer=127.0.0.5 expected=whitelist on 127.0.0.1:"));
    CHECK(h.count("Control reject peer=127.0.0.5") == 1);
    CHECK(h.counters.rejected >= 12);

    // The whitelisted viewer: served as before.
    Viewer ok;
    CHECK(ok.login(h.port, v.key, Channel::Control).has_value());
    CHECK(ok.ping(1));
    CHECK(h.workers == 6);
    if (gFailures) h.dump();
}

// Item 1: an address that opens connections and never answers holds
// kMaxHandshakesPerSource handshakes at most; the rest are closed at
// accept. A viewer from another address still logs in with all four
// channels in their handshakes at once, and a third address still takes
// over. The flood's handshakes end at the AUTH timeout, each a failure.
static void testHandshakePlaces(const Vector& v) {
    static_assert(jlh::kMaxHandshakes >= 2 * jlh::kMaxHandshakesPerSource, "a viewer fits beside one flood");
    HostRig h(v);
    h.env.authTimeoutMs = 3000;
    h.runAcceptLoop();
    const int per = jlh::kMaxHandshakesPerSource;
    std::vector<std::unique_ptr<Viewer>> flood;
    int challenged = 0, closed = 0;
    for (int i = 0; i < 12; ++i) {
        flood.push_back(std::make_unique<Viewer>("127.0.0.2"));
        Viewer& x = *flood.back();
        CHECK(x.open(h.port));
        uint8_t t = 0;
        Bytes p;
        const int r = readFrame(x.s, t, p);
        if (r == 1 && t == kMsgChallenge) ++challenged;
        else if (r == 0) ++closed;
    }
    CHECK(challenged == per && closed == 12 - per);
    CHECK(h.workers == per && h.slots.handshakesFrom(addrOf("127.0.0.2")) == per);
    CHECK(h.waitFor("control.rejected peer=127.0.0.2 reason=source_handshakes_full"));

    // The viewer, 127.0.0.1: four channels challenged at once.
    Viewer lc, lclip, lfile, lping;
    for (Viewer* x : {&lc, &lclip, &lfile, &lping}) CHECK(x->open(h.port) && x->readChallenge());
    CHECK(h.slots.handshakes() == 2 * per);
    const auto sid = lc.finishLogin(v.key, Channel::Control);
    CHECK(sid.has_value());
    CHECK(lclip.finishLogin(v.key, Channel::Clipboard, sid).has_value());
    CHECK(lfile.finishLogin(v.key, Channel::File, sid).has_value());
    CHECK(lping.finishLogin(v.key, Channel::Ping, sid).has_value());
    CHECK(lc.ping(1) && lping.ping(2));
    CHECK(h.slots.handshakes() == per);  // logged in: out of the handshake count

    // A takeover from 127.0.0.3, again four at once, the flood still there.
    Viewer tc("127.0.0.3"), tclip("127.0.0.3"), tfile("127.0.0.3"), tping("127.0.0.3");
    for (Viewer* x : {&tc, &tclip, &tfile, &tping}) CHECK(x->open(h.port) && x->readChallenge());
    const auto sidT = tc.finishLogin(v.key, Channel::Control);
    CHECK(sidT && sid && *sidT != *sid);
    CHECK(tclip.finishLogin(v.key, Channel::Clipboard, sidT).has_value());
    CHECK(tfile.finishLogin(v.key, Channel::File, sidT).has_value());
    CHECK(tping.finishLogin(v.key, Channel::Ping, sidT).has_value());
    CHECK(lc.result() == Bytes{6});  // REPLACED
    CHECK(h.waitFor("auth.replaced old_peer=127.0.0.1 chan=control new_peer=127.0.0.3"));
    CHECK(tc.ping(3) && tping.ping(4));

    // The flood times out: places back, four failures for 127.0.0.2.
    for (int i = 0; i < 600 && h.slots.handshakes() != 0; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    CHECK(h.slots.handshakes() == 0 && h.slots.handshakesFrom(addrOf("127.0.0.2")) == 0);
    CHECK(h.guard.failures("127.0.0.2") == per);
    if (gFailures) h.dump();
}

static SessionBroker::Admitted takeOver(SessionBroker& b, uint8_t n) {
    return b.admit("100.64.0." + std::to_string(n), Channel::Control, keyOf(n), sidOf(n), std::nullopt, false,
                   b.policyGeneration(), {});
}

// Item 2: a frame goes out packet by packet, each checked against the
// session under the broker's send gate; a takeover between two packets
// stops the frame there.
static void testFrameSendCut() {
    SessionBroker b(portableTags(), [](const std::string&) {});
    CHECK(takeOver(b, 1).refused == SessionBroker::Refusal::None);
    const uint64_t gen = b.generation();
    std::vector<size_t> sent;
    const FrameSend r = sendFrameWhileCurrent(
        b, gen, 10,
        [&](size_t i) {
            if (i == 4) CHECK(takeOver(b, 2).refused == SessionBroker::Refusal::None);
        },
        [&](size_t i) {
            sent.push_back(i);
            return true;
        });
    CHECK(r.cut && r.sent == 4 && r.failed == 0);
    CHECK((sent == std::vector<size_t>{0, 1, 2, 3}));
    CHECK(b.generation() != gen && !b.sendIfCurrent(gen, [] {}));
    // A send that fails is counted; the frame goes on.
    const FrameSend r2 = sendFrameWhileCurrent(b, b.generation(), 3, [](size_t) {}, [](size_t i) { return i != 1; });
    CHECK(!r2.cut && r2.sent == 2 && r2.failed == 1);
}

// Item 2: a void (a takeover, a policy change, a block) does not return
// while a datagram checked against the old session is still going out,
// and after it returns none goes out under the old session.
static void testSendGate() {
    for (int kind = 0; kind < 3; ++kind) {
        SessionBroker b(portableTags(), [](const std::string&) {});
        CHECK(takeOver(b, 1).refused == SessionBroker::Refusal::None);
        const uint64_t gen = b.generation();
        std::atomic<bool> inSend{false}, voidReturned{false}, returnedDuringSend{false};
        bool ran = false;
        std::thread sender([&] {
            ran = b.sendIfCurrent(gen, [&] {
                inSend = true;
                for (int i = 0; i < 30; ++i) {  // a slow send, 300 ms
                    if (voidReturned) {
                        returnedDuringSend = true;
                        break;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
            });
        });
        while (!inSend) std::this_thread::sleep_for(std::chrono::milliseconds(1));
        std::thread voider([&] {
            if (kind == 0) (void)takeOver(b, 2);
            else if (kind == 1) b.voidAll(CloseReason::Policy, true);
            else (void)b.kickPeer("100.64.0.1", CloseReason::Blocked);
            voidReturned = true;
        });
        sender.join();
        voider.join();
        CHECK(ran && voidReturned);
        CHECK(!returnedDuringSend);
        if (returnedDuringSend) std::printf("  (void kind %d returned during the send)\n", kind);
        CHECK(b.generation() != gen);
        bool late = false;
        CHECK(!b.sendIfCurrent(gen, [&] { late = true; }) && !late);
    }
}

// Item 3: a blacklist that is there but does not read at start is not an
// empty one. Nobody is admitted and every open connection is held until it
// reads (tried once a second); then its blocks apply. One that read once
// and fails later keeps what it read (r8). No list at all is an empty one.
static void testBlocklistUnreadAtStart() {
    FakeClock clock;
    MemoryBlocklist store;
    store.entries.push_back({"100.64.0.9", 1, "manual"});
    store.unreadable = true;
    std::vector<std::string> lines;
    std::mutex lm;
    AuthGuard g({}, store, nullptr, testHooks(clock, &lines, &lm));
    for (const char* ip : {"100.64.0.9", "100.64.0.1"}) {
        const auto a = g.admit(ip);
        CHECK(a.kind == AuthGuard::Admission::GlobalLocked && a.retrySeconds == AuthGuard::kPendingRetrySeconds);
    }
    CHECK(g.lockdownReason() == std::optional<std::string>("blocklist_unreadable"));
    CHECK(g.inputRefusal("100.64.0.1") == std::optional<std::string>("blocklist_unreadable"));
    clock.t = clock.t + 1.5;
    CHECK(g.admit("100.64.0.1").kind == AuthGuard::Admission::GlobalLocked);
    store.unreadable = false;
    CHECK(g.admit("100.64.0.1").kind == AuthGuard::Admission::GlobalLocked);  // tried under a second ago
    clock.t = clock.t + 1.5;
    CHECK(g.admit("100.64.0.9").kind == AuthGuard::Admission::Blocked);
    CHECK(g.admit("100.64.0.1").kind == AuthGuard::Admission::Challenge);
    CHECK(!g.lockdownReason());
    CHECK(g.inputRefusal("100.64.0.1") == std::nullopt);
    CHECK(g.inputRefusal("100.64.0.9") == std::optional<std::string>("blocked"));
    {
        std::lock_guard<std::mutex> lg(lm);
        bool down = false, cleared = false;
        for (const auto& l : lines) {
            down |= l.rfind("auth.lockdown reason=blocklist_unreadable source=", 0) == 0;
            cleared |= l.rfind("auth.lockdown_cleared reason=blocklist_readable source=", 0) == 0 &&
                       l.find(" peers=1") != std::string::npos;
        }
        CHECK(down && cleared);
    }
    store.unreadable = true;
    ++store.stamp.b;
    clock.t = clock.t + 2;
    CHECK(g.admit("100.64.0.9").kind == AuthGuard::Admission::Blocked);
    CHECK(g.admit("100.64.0.1").kind == AuthGuard::Admission::Challenge && !g.lockdownReason());

    MemoryBlocklist none;
    AuthGuard g2({}, none, nullptr, testHooks(clock));
    CHECK(g2.admit("100.64.0.1").kind == AuthGuard::Admission::Challenge && !g2.lockdownReason());
}

// ------------------------------------------------------- settings (H3)

namespace st = jlh::settings;

static void testSettingsRows() {
    const BlockedEntry e{"100.64.0.7", 1'800'000'123, "20 wrong passwords"};
    CHECK(st::formatBlocked(e) == "100.64.0.7\t1800000123\t20 wrong passwords");
    const auto back = st::parseBlocked(st::formatBlocked(e));
    CHECK(back && back->ip == e.ip && back->at == e.at && back->reason == e.reason);
    // A reason cannot break the row.
    const auto odd = st::parseBlocked(st::formatBlocked({"100.64.0.8", 5, "a\tb\nc" + std::string(100, 'x')}));
    CHECK(odd && odd->reason.size() == 64 && odd->reason.substr(0, 5) == "a b c");
    CHECK(!st::parseBlocked("100.64.0.7"));
    CHECK(st::parseBlocked("100.64.0.7\t12\t") && st::parseBlocked("100.64.0.7\t12\t")->reason.empty());
    CHECK(!st::parseBlocked("100.64.0.7\tx\tmanual"));
    CHECK(!st::parseBlocked("100.64.0.7\t12\tmanual\textra"));
    CHECK(!st::parseBlocked("host\t12\tmanual"));
    CHECK(!st::parseBlocked("100.64.0.7\t99999999999999999999\tmanual"));
    CHECK(st::parseBlocked("100.64.0.7\t-5\tmanual") && st::parseBlocked("100.64.0.7\t-5\tmanual")->at == -5);

    const FailureRecord r{1'800'000'000, "100.64.0.9", "wrong_password", 7};
    CHECK(st::formatRecord(r) == "1800000000\t100.64.0.9\twrong_password\t7");
    const auto rb = st::parseRecord(st::formatRecord(r));
    CHECK(rb && rb->at == r.at && rb->ip == r.ip && rb->reason == r.reason && rb->failures == 7);
    CHECK(!st::parseRecord("1\t100.64.0.9\tx\t-1"));
    CHECK(!st::parseRecord("1\t100.64.0.9\tx\t1000001"));
    CHECK(!st::parseRecord("1\tnope\tx\t1"));
    CHECK(!st::parseRecord("1\t100.64.0.9\tx"));

    const std::vector<int64_t> times{0, 1, -1, 1'800'000'000, INT64_MAX};
    CHECK(st::decodeTimes(st::encodeTimes(times)) == times);
    CHECK(st::encodeTimes({1}).size() == 8 && st::encodeTimes({1})[0] == 1);
    CHECK(st::decodeTimes(Bytes(7, 0)).empty());
}

static void testSecretBlob() {
    AuthSecret s;
    s.key = keyOf(0x11);
    for (size_t i = 0; i < s.salt.size(); ++i) s.salt[i] = uint8_t(0x20 + i);
    for (size_t i = 0; i < s.hostId.size(); ++i) s.hostId[i] = uint8_t(0x40 + i);
    s.iterations = kIterations;
    const Bytes b = st::encodeSecret(s);
    CHECK(b.size() == 72 && b[0] == 'J' && b[3] == '1');
    CHECK(b[4] == 0x00 && b[5] == 0x09 && b[6] == 0x27 && b[7] == 0xC0);  // 600000 BE
    const auto d = st::decodeSecret(b);
    CHECK(d && d->key == s.key && d->salt == s.salt && d->hostId == s.hostId && d->iterations == kIterations);
    auto copy = std::make_shared<const AuthSecret>(s);
    CHECK(st::sameSecret(d, copy) && st::sameSecret(nullptr, nullptr) && !st::sameSecret(d, nullptr));
    AuthSecret other = s;
    other.salt[0] ^= 1;
    CHECK(!st::sameSecret(d, std::make_shared<const AuthSecret>(other)));
    Bytes bad = b;
    bad[0] = 'X';
    CHECK(!st::decodeSecret(bad));
    CHECK(!st::decodeSecret(Bytes(b.begin(), b.end() - 1)));
    Bytes low = b;
    low[4] = 0, low[5] = 0, low[6] = 0x01, low[7] = 0;  // 256 iterations
    CHECK(!st::decodeSecret(low));
    Bytes high = b;
    high[4] = 0x01, high[5] = 0, high[6] = 0, high[7] = 0;  // 16,777,216
    CHECK(!st::decodeSecret(high));
}

static void testSettingsTexts() {
    const auto u = [](const char* s) {
        std::u32string out;
        for (const char* p = s; *p; ++p) out.push_back(char32_t(uint8_t(*p)));
        return out;
    };
    CHECK(st::passwordRefusal(false, u("Good-Pass.123"))->text == "兩次輸入嘅密碼唔一樣。");
    CHECK(!st::passwordRefusal(true, u("Good-Pass.123")));
    const auto weak = st::passwordRefusal(true, u("short"));
    CHECK(weak && !weak->ok &&
          weak->text == "密碼唔夠強：最少 10 個字；要有大楷字母 (A-Z)；要有符號（唔係字母、數字或空格）");
    CHECK(st::passwordSaved(false).ok && st::passwordSaved(false).text == "已設定連線密碼。");
    CHECK(st::passwordSaved(true).text == "已更改連線密碼；已記住密碼嘅 viewer 要重新輸入。");

    const auto l = st::parseTailnetList("100.64.0.1, 100.127.255.254\r\n192.168.1.4\tbogus 100.64.0.1,,100.128.0.1");
    CHECK((l.ips == std::vector<std::string>{"100.64.0.1", "100.127.255.254"}));
    CHECK(st::kNotTailnet + st::joined(l.invalid, ", ") ==
          "唔係 tailnet IPv4 地址（要喺 100.64.0.0/10 範圍內）：192.168.1.4, bogus, 100.128.0.1");
    CHECK(st::parseTailnetList(" \n").ips.empty() && st::parseTailnetList("").invalid.empty());
    CHECK(st::whitelistSaved(0).text == "白名單已清空：任何 IP 都要輸入密碼。");
    CHECK(st::whitelistSaved(2).text == "白名單已儲存（2 個 IP）。");
    CHECK(st::trimmed("  100.64.0.1 \r\n") == "100.64.0.1" && st::trimmed(" \t").empty());
    CHECK(st::reasonText("manual") == "人手加入" && st::reasonText("20 wrong passwords") == "錯密碼 20 次");
    CHECK(st::reasonText("something") == "something" && st::reasonText("x wrong passwords") == "x wrong passwords");
    CHECK(st::failureReasonText("wrong_password") == "密碼錯");
    FailureSummary f;
    CHECK(st::failureSummaryText(f, "") == "最近 24 小時錯 0 次。");
    f.last24h = 3, f.lastIp = "100.64.0.9", f.capped = true;
    CHECK(st::failureSummaryText(f, "11-28 10:00") == "最近 24 小時錯至少 3 次；最後一個 IP：100.64.0.9（11-28 10:00）。");
}

static void testResolveListen() {
    using P = st::ListenPlan;
    const std::vector<std::string> ips{"192.168.1.20", "100.101.5.6", "100.64.3.4", "127.0.0.1"};
    auto p = st::resolveListen("", "", ips);
    CHECK(p.kind == P::Ready && p.mode == "tailnet" && p.bindIp == "100.64.3.4");
    p = st::resolveListen("tailnet", "100.101.5.6", ips);
    CHECK(p.kind == P::Ready && p.bindIp == "100.101.5.6");
    p = st::resolveListen("tailnet", "100.101.5.7", ips);
    CHECK(p.kind == P::Waiting && p.bindIp.empty());
    p = st::resolveListen("tailnet", "192.168.1.20", ips);
    CHECK(p.kind == P::NotConfigured && p.bindIp.empty());
    p = st::resolveListen("tailnet", "", {"192.168.1.20", "10.0.0.1"});
    CHECK(p.kind == P::Waiting && p.bindIp.empty());
    p = st::resolveListen("loopback", "100.101.5.6", ips);
    CHECK(p.kind == P::Ready && p.bindIp == "127.0.0.1");
    p = st::resolveListen("lan", "", ips);
    CHECK(p.kind == P::NotConfigured && p.bindIp.empty());
    // Numeric order, not text order: 100.64.10.1 < 100.100.0.1.
    p = st::resolveListen("", "", {"100.100.0.1", "100.64.10.1"});
    CHECK(p.bindIp == "100.64.10.1");
}

class FakePolicySource : public st::PolicySource {
public:
    st::PolicyValues values;
    st::PolicyStamp stamp;
    bool stampFails = false;
    int loads = 0;
    std::optional<st::PolicyStamp> probe() override {
        if (stampFails) return std::nullopt;
        return stamp;
    }
    st::PolicyValues load() override {
        ++loads;
        return values;
    }
    void moved() { ++stamp.settings.b; }
};

static void testPolicyHolder() {
    FakeClock clock;
    MemoryBlocklist store;
    MemoryPendingBlocks journal;
    std::vector<std::string> lines;
    std::mutex lm;
    AuthGuard guard({}, store, &journal, testHooks(clock, &lines, &lm));
    SessionBroker broker(portableTags(), [&](const std::string& s) {
        std::lock_guard<std::mutex> g(lm);
        lines.push_back(s);
    });
    FakePolicySource src;
    st::PolicyHolder holder(src, guard, broker, [&](const std::string& s) {
        std::lock_guard<std::mutex> g(lm);
        lines.push_back(s);
    });
    const auto saw = [&](const std::string& l) {
        std::lock_guard<std::mutex> g(lm);
        return std::find(lines.begin(), lines.end(), l) != lines.end();
    };

    // No password yet: nobody gets in, said as no_password.
    holder.load();
    CHECK(saw("auth.policy password=unset whitelist=0 source=registry"));
    auto snap = holder.snapshot();
    CHECK(!snap.secret && snap.noSecretReason == "no_password" && !holder.passwordSet());
    const auto pol0 = broker.policyGeneration();

    // The window sets one: every connection void, old AUTHs refused at admit.
    std::atomic<int> closed{-1};
    auto a = broker.admit("100.64.0.1", Channel::Control, keyOf(1), sidOf(1), std::nullopt, false, pol0,
                          [&](CloseReason w) { closed = int(w); });
    CHECK(a.refused == SessionBroker::Refusal::None);
    AuthSecret s1;
    s1.key = keyOf(1);
    s1.iterations = kIterations;
    src.values.secret = std::make_shared<const AuthSecret>(s1);
    src.moved();
    holder.refresh();
    CHECK(saw("auth.policy_changed password=set whitelist=0 source=registry; every connection closed"));
    CHECK(holder.passwordSet() && holder.snapshot().secret && holder.snapshot().generation == pol0 + 1);
    CHECK(!broker.live(a.token) && broker.voidReason(a.token) == CloseReason::Policy);
    CHECK(broker.admit("100.64.0.1", Channel::Control, keyOf(1), sidOf(2), std::nullopt, false, pol0, {}).refused ==
          SessionBroker::Refusal::Policy);
    broker.flushClosesForTest();
    CHECK(closed == int(CloseReason::Policy));
    broker.end(a.token);

    // Same stamp: not read again. Stamp moved, same values: nothing closed.
    const int loads = src.loads;
    holder.refresh();
    CHECK(src.loads == loads);
    src.moved();
    holder.refresh();
    CHECK(src.loads == loads + 1 && broker.policyGeneration() == pol0 + 1);
    // An equal secret in a new object is the same password.
    src.values.secret = std::make_shared<const AuthSecret>(s1);
    src.moved();
    holder.refresh();
    CHECK(broker.policyGeneration() == pol0 + 1);

    // Whitelist: the guard follows, every connection void.
    src.values.whitelist = {"100.64.0.5"};
    src.moved();
    holder.refresh();
    CHECK(saw("auth.policy_changed password=same whitelist=1 source=registry; every connection closed"));
    CHECK(guard.whitelist() == std::vector<std::string>{"100.64.0.5"});
    CHECK(guard.admit("100.64.0.6").kind == AuthGuard::Admission::NotAllowed);
    CHECK(broker.policyGeneration() == pol0 + 2);

    // New password (new salt): changed.
    AuthSecret s2 = s1;
    s2.salt[0] = 9;
    src.values.secret = std::make_shared<const AuthSecret>(s2);
    src.moved();
    holder.refresh();
    CHECK(saw("auth.policy_changed password=changed whitelist=1 source=registry; every connection closed"));
    CHECK(broker.policyGeneration() == pol0 + 3);

    // Settings stop reading: no secret, said as settings_unreadable.
    src.values.problem = "secret_unprotect_failed_13";
    src.moved();
    holder.refresh();
    CHECK(saw("auth.policy_unreadable reason=secret_unprotect_failed_13 found=running (nobody is admitted until it reads)"));
    snap = holder.snapshot();
    CHECK(!snap.secret && snap.noSecretReason == "settings_unreadable" && !holder.passwordSet());
    CHECK(broker.policyGeneration() == pol0 + 4);
    // ...and read again.
    src.values.problem.clear();
    src.moved();
    holder.refresh();
    CHECK(saw("auth.policy_changed password=set whitelist=1 source=registry; every connection closed"));
    CHECK(holder.snapshot().noSecretReason == "no_password" && holder.passwordSet());

    // A stamp that cannot be taken: read every time.
    src.stampFails = true;
    const int l2 = src.loads;
    holder.refresh();
    holder.refresh();
    CHECK(src.loads == l2 + 2 && broker.policyGeneration() == pol0 + 5);
    src.stampFails = false;
    holder.refresh();

    // tick: a block from the window closes that peer's connections.
    const auto p = broker.policyGeneration();
    std::atomic<int> closedB{-1}, closedC{-1};
    auto b = broker.admit("100.64.0.5", Channel::Control, keyOf(2), sidOf(5), std::nullopt, false, p,
                          [&](CloseReason w) { closedB = int(w); });
    CHECK(b.refused == SessionBroker::Refusal::None);
    store.entries.push_back({"100.64.0.5", 1, "manual"});
    ++store.stamp.b;
    holder.tick();
    CHECK(!broker.live(b.token) && broker.voidReason(b.token) == CloseReason::Blocked);
    broker.flushClosesForTest();
    CHECK(closedB == int(CloseReason::Blocked));
    broker.end(b.token);
    // ...and its removal releases it in place.
    store.entries.clear();
    ++store.stamp.b;
    holder.tick();
    CHECK(guard.admit("100.64.0.5").kind == AuthGuard::Admission::Challenge);
    CHECK(broker.policyGeneration() == p);

    // tick: the journal stops reading: every connection closed, once.
    auto c = broker.admit("100.64.0.5", Channel::Control, keyOf(3), sidOf(6), std::nullopt, false, p,
                          [&](CloseReason w) { closedC = int(w); });
    CHECK(c.refused == SessionBroker::Refusal::None);
    journal.unreadable = true;
    ++journal.stamp.b;
    holder.tick();
    CHECK(!broker.live(c.token) && broker.voidReason(c.token) == CloseReason::Lockdown);
    CHECK(guard.lockdownReason() == std::optional<std::string>("pending_journal_unreadable"));
    broker.flushClosesForTest();
    CHECK(closedC == int(CloseReason::Lockdown));
    broker.end(c.token);
    auto d = broker.admit("100.64.0.5", Channel::Control, keyOf(4), sidOf(7), std::nullopt, false, p, {});
    holder.tick();
    CHECK(broker.live(d.token));  // still locked down: not closed again by tick (AUTH refuses new ones)
    broker.end(d.token);
    journal.unreadable = false;
    ++journal.stamp.b;
    clock.t = clock.t + AuthGuard::kPendingRetryInterval + 0.5;  // retried once a second
    holder.tick();
    CHECK(!guard.lockdownReason());
    if (gFailures) {
        std::lock_guard<std::mutex> g(lm);
        for (const auto& l : lines) std::printf("  log: %s\n", l.c_str());
    }
}

#ifdef _WIN32
// The real viewer client (windows-client/conn_auth.hpp) against this host.
static void testViewerClientInterop(const Vector& v) {
    HostRig h(v);
    h.env.hmac = jlh::auth::win::hmac;
    const std::wstring dir = L".\\auth_test_keys";
    auto handshake = [&](const std::wstring& password, jl::auth::Channel ch) {
        h.serveNext();
        jl::auth::Client::Options o;
        o.password = password;
        o.storeDir = dir;
        jl::auth::Client c(std::move(o));
        SocketHandle s = connectLoopback(h.port);
        const auto r = c.handshake(s, ch, 1.0);
        closeSock(s);
        return r;
    };
    const int n = MultiByteToWideChar(CP_UTF8, 0, v.password.data(), int(v.password.size()), nullptr, 0);
    std::wstring pw(size_t(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, v.password.data(), int(v.password.size()), pw.data(), n);
    CHECK(handshake(pw, jl::auth::Channel::Control).outcome == jl::auth::Outcome::Ok);
    const auto wrong = handshake(L"Wrong-Horse.42", jl::auth::Channel::Control);
    CHECK(wrong.outcome == jl::auth::Outcome::Fail && wrong.triesLeft == 4);
    CHECK(h.waitFor("auth.ok peer=127.0.0.1 chan=control session="));
    CHECK(h.waitFor("auth.fail peer=127.0.0.1 chan=unknown reason=wrong_password failures=1 tries=4"));
    // The settings window derives the same K the viewer does.
    const auto k = jlh::auth::win::deriveKey(pw, v.salt, v.iterations);
    CHECK(k && *k == v.key);
    h.waitServed(2);
}

// The registry store under HKCU\Software\JerisTest\<unique> (never HKLM):
// the window's own writes (password, whitelist, blacklist, theme) read back
// by the host's readers, the stores the guard and the failure list use, a
// whitelist change voiding connections through PolicyHolder, and the
// Secret key's DACL when elevated. The test key is deleted at the end.
static void testRegistryStore() {
    namespace cfg = jlh::config;
    cfg::Location loc;
    loc.hive = HKEY_CURRENT_USER;
    const std::wstring name =
        L"JLH-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64());
    loc.path = L"Software\\JerisTest\\" + name;
    loc.mutexName = L"Local\\JerisLinkHostConfigTest-" + name;
    loc.protect = cfg::isElevated();
    std::printf("registry test under HKCU\\Software\\JerisTest (protect=%s)\n", loc.protect ? "yes" : "no");

    CHECK(!cfg::readSettings(loc).exists);
    {
        const auto r = cfg::readSecret(loc);
        CHECK(!r.secret && r.problem.empty());
    }
    cfg::RegistryPolicySource src(loc);
    CHECK(!src.load().secret);

    // The password: refused when the two differ or it is weak; every set
    // makes a new salt and keeps the host id.
    const std::wstring pw1 = L"Correct-Horse.42", pw2 = L"Battery-Staple.43";
    CHECK(!cfg::setPassword(loc, pw1, pw2).ok);
    CHECK(!cfg::setPassword(loc, L"Aa!aaaaaa", L"Aa!aaaaaa").ok);
    CHECK(!cfg::readSecret(loc).secret);
    CHECK(cfg::setPassword(loc, pw1, pw1).ok);
    const auto s1 = cfg::readSecret(loc);
    CHECK(s1.secret && s1.problem.empty());
    if (s1.secret) {
        CHECK(s1.secret->iterations == jlh::auth::kIterations);
        const auto k = jlh::auth::win::deriveKey(pw1, s1.secret->salt, s1.secret->iterations);
        CHECK(k && *k == s1.secret->key);
    }
    CHECK(cfg::readSettings(loc).passwordSet);
    const auto stamp1 = src.probe();
    CHECK(cfg::setPassword(loc, pw2, pw2).ok);
    const auto s2 = cfg::readSecret(loc);
    CHECK(s1.secret && s2.secret && s2.secret->salt != s1.secret->salt && s2.secret->hostId == s1.secret->hostId &&
          s2.secret->key != s1.secret->key);
    const auto stamp2 = src.probe();
    CHECK(stamp1 && stamp2 && !(*stamp1 == *stamp2));
    if (loc.protect) {
        // D8: SYSTEM and Administrators only, not inherited.
        const std::wstring dacl = cfg::secretDacl(loc);
        size_t aces = 0;
        for (size_t at = dacl.find(L"(A;"); at != std::wstring::npos; at = dacl.find(L"(A;", at + 1)) ++aces;
        const bool ok = dacl.rfind(L"D:P", 0) == 0 && dacl.find(L"(A;OICI;KA;;;SY)") != std::wstring::npos &&
                        dacl.find(L"(A;OICI;KA;;;BA)") != std::wstring::npos && aces == 2;
        CHECK(ok);
        if (!ok) std::printf("  secret dacl: %ls\n", dacl.c_str());
    }

    // The whitelist: tailnet addresses only, deduplicated.
    CHECK(cfg::saveWhitelist(loc, "100.64.0.5\n100.64.0.6, 100.64.0.5").ok);
    CHECK((cfg::readSettings(loc).whitelist == std::vector<std::string>{"100.64.0.5", "100.64.0.6"}));
    CHECK(!cfg::saveWhitelist(loc, "100.64.0.7 192.168.1.2").ok);
    CHECK((cfg::readSettings(loc).whitelist == std::vector<std::string>{"100.64.0.5", "100.64.0.6"}));

    // The blacklist, as the window writes it.
    CHECK(cfg::block(loc, " 100.64.0.9 ", 1'800'000'000).ok);
    CHECK(cfg::blockedHas(loc, "100.64.0.9"));
    CHECK(!cfg::block(loc, "10.0.0.1", 1'800'000'000).ok);
    CHECK(!cfg::blockedHas(loc, "10.0.0.1"));
    CHECK(cfg::unblock(loc, "100.64.0.9").ok);
    CHECK(!cfg::blockedHas(loc, "100.64.0.9"));

    CHECK(cfg::setTheme(loc, "blue").ok && cfg::readSettings(loc).theme == "blue");
    CHECK(!cfg::setTheme(loc, "red").ok && cfg::readSettings(loc).theme == "blue");

    // The failure list and the pending journal round-trip.
    {
        cfg::RegistryFailureLog fl(loc);
        fl.save({FailureRecord{1'800'000'000, "100.64.0.3", "wrong_password", 2}}, {1'800'000'000, 1'800'000'001});
        const auto recs = fl.loadRecords();
        CHECK(recs.size() == 1 && recs[0].ip == "100.64.0.3" && recs[0].failures == 2);
        CHECK((fl.loadTimes() == std::vector<int64_t>{1'800'000'000, 1'800'000'001}));
        cfg::RegistryPendingBlocks pj(loc);
        CHECK(pj.save({BlockedEntry{"100.64.0.4", 1'800'000'000, "failures"}}));
        const auto rows = pj.load();
        CHECK(rows && rows->size() == 1 && (*rows)[0].ip == "100.64.0.4");
        CHECK(pj.save({}));
        CHECK(pj.load() && pj.load()->empty());
    }

    // The host's view: PolicyHolder over this store. A whitelist change
    // voids every connection (a new policy generation); an address the
    // window blacklists reaches the guard.
    {
        FakeClock clock;
        cfg::RegistryBlocklist bl(loc);
        cfg::RegistryPendingBlocks pj(loc);
        AuthGuard guard({}, bl, &pj, testHooks(clock));
        SessionBroker broker(portableTags(), [](const std::string&) {});
        std::vector<std::string> lines;
        jlh::settings::PolicyHolder holder(src, guard, broker, [&](const std::string& s) { lines.push_back(s); });
        holder.load();
        CHECK(holder.passwordSet());
        const uint64_t g0 = broker.policyGeneration();
        holder.refresh(false);
        CHECK(broker.policyGeneration() == g0);
        CHECK(cfg::saveWhitelist(loc, "100.64.0.7").ok);
        holder.refresh(false);
        CHECK(broker.policyGeneration() != g0);
        CHECK(!lines.empty() && lines.back().rfind("auth.policy_changed password=same whitelist=1", 0) == 0);
        CHECK(!guard.isBlocked("100.64.0.8"));
        CHECK(cfg::block(loc, "100.64.0.8", 1'800'000'000).ok);
        CHECK(guard.isBlocked("100.64.0.8"));
        CHECK(guard.inputRefusal("100.64.0.8") == std::optional<std::string>("blocked"));
    }

    // H3 r2 (Pepper's review r1, item 3): a BlockedIPs value that does not
    // read (here the wrong type) shuts a host starting on it until it
    // reads; no value at all is an empty list.
    {
        FakeClock clock;
        const DWORD bad = 7;
        CHECK(RegSetKeyValueW(HKEY_CURRENT_USER, loc.path.c_str(), L"BlockedIPs", REG_DWORD, &bad, sizeof(bad)) ==
              ERROR_SUCCESS);
        cfg::RegistryBlocklist bl(loc);
        CHECK(!bl.load());
        AuthGuard guard({}, bl, nullptr, testHooks(clock));
        CHECK(guard.admit("100.64.0.1").kind == AuthGuard::Admission::GlobalLocked);
        CHECK(guard.lockdownReason() == std::optional<std::string>("blocklist_unreadable"));
        CHECK(RegDeleteKeyValueW(HKEY_CURRENT_USER, loc.path.c_str(), L"BlockedIPs") == ERROR_SUCCESS);
        CHECK(bl.load() && bl.load()->empty());
        clock.t = clock.t + 2;
        CHECK(guard.admit("100.64.0.1").kind == AuthGuard::Admission::Challenge && !guard.lockdownReason());
    }

    CHECK(RegDeleteTreeW(HKEY_CURRENT_USER, loc.path.c_str()) == ERROR_SUCCESS);
    RegDeleteKeyExW(HKEY_CURRENT_USER, L"Software\\JerisTest", KEY_WOW64_64KEY, 0);  // only when empty
    CHECK(!cfg::readSettings(loc).exists);
}
#endif

int main(int argc, char** argv) {
    if (argc < 2) {
        std::printf("usage: JerisLinkHostAuthTest <auth_vectors.json>\n");
        return 2;
    }
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#else
    signal(SIGPIPE, SIG_IGN);
#endif
    const auto vs = loadVectors(argv[1]);
    if (vs.empty()) {
        std::printf("FAIL no vectors in %s\n", argv[1]);
        return 1;
    }
    testVectors(vs, portableHmac, "portable");
#ifdef _WIN32
    testVectors(vs, jlh::auth::win::hmac, "cng");
#endif
    testWire();
    testAddresses();
    testPasswordRules();
    testGuardLadder();
    testGuardGlobalAndLists();
    testGuardUnpersisted();
    testBroker();
    testVoidRetiresOwner();
    testUdpChecks(vs);
    testFailureLog();
    testSettingsRows();
    testSecretBlob();
    testSettingsTexts();
    testResolveListen();
    testPolicyHolder();
    testAuthOverLoopback(vs.front());
    testAcceptScreen(vs.front());
    testHandshakePlaces(vs.front());
    testFrameSendCut();
    testSendGate();
    testBlocklistUnreadAtStart();
#ifdef _WIN32
    testViewerClientInterop(vs.front());
    testRegistryStore();
#endif
    std::printf("%d checks, %d failures\n", gChecks, gFailures);
    return gFailures ? 1 : 0;
}
