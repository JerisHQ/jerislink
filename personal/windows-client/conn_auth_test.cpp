// Connection password, viewer side (conn_auth.hpp): the shared vectors in
// personal/protocol/auth_vectors.json, then the whole AUTH exchange against
// a fake host on loopback: correct password with and without Remember, the
// DPAPI copy, wrong password, saved key deleted on fail, mutual check
// failure, locked / blocked / auth_required, password needed, 0.3.x host
// timeout, transition probe and the probe that crosses a late challenge;
// then the PR-B review fixes: open_ip_only after a proof, HMAC failure,
// a header split across the probe wait, what a counted probe race costs,
// one channel at a time, distrusted saved keys, secrets wiped.
//
// Usage: JerislinkConnAuthTest <path to auth_vectors.json>
#include "conn_auth.hpp"

#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <fstream>
#include <iterator>
#include <sstream>
#include <thread>

#pragma comment(lib, "ws2_32.lib")

namespace {

using namespace jl::auth;
namespace udptag = jl::udptag;

int gPass = 0;
int gFail = 0;

void expect(bool cond, const std::string& what) {
    if (cond) { ++gPass; std::printf("PASS %s\n", what.c_str()); }
    else { ++gFail; std::printf("FAIL %s\n", what.c_str()); }
}

// MARK: Tiny JSON field reader (the vectors file is flat strings / numbers)

std::string jsonField(const std::string& obj, const std::string& name) {
    const std::string k = "\"" + name + "\"";
    size_t p = obj.find(k);
    if (p == std::string::npos) return {};
    p = obj.find(':', p + k.size());
    if (p == std::string::npos) return {};
    ++p;
    while (p < obj.size() && (obj[p] == ' ' || obj[p] == '\n' || obj[p] == '\r' || obj[p] == '\t')) ++p;
    if (p >= obj.size()) return {};
    if (obj[p] != '"') {
        size_t e = obj.find_first_of(",}\n", p);
        return obj.substr(p, e - p);
    }
    std::string out;
    for (++p; p < obj.size() && obj[p] != '"'; ++p) {
        if (obj[p] != '\\') { out.push_back(obj[p]); continue; }
        ++p;
        if (p >= obj.size()) break;
        if (obj[p] == 'u' && p + 4 < obj.size()) {
            // \uXXXX (BMP only) -> UTF-8
            unsigned cp = unsigned(std::strtoul(obj.substr(p + 1, 4).c_str(), nullptr, 16));
            p += 4;
            if (cp < 0x80) out.push_back(char(cp));
            else if (cp < 0x800) { out.push_back(char(0xC0 | (cp >> 6))); out.push_back(char(0x80 | (cp & 0x3F))); }
            else { out.push_back(char(0xE0 | (cp >> 12))); out.push_back(char(0x80 | ((cp >> 6) & 0x3F))); out.push_back(char(0x80 | (cp & 0x3F))); }
        } else {
            out.push_back(obj[p] == 'n' ? '\n' : obj[p]);
        }
    }
    return out;
}

Bytes unhex(const std::string& h) {
    Bytes b;
    for (size_t i = 0; i + 1 < h.size(); i += 2) b.push_back(uint8_t(std::strtoul(h.substr(i, 2).c_str(), nullptr, 16)));
    return b;
}

std::wstring widen(const std::string& utf8) {
    int n = MultiByteToWideChar(CP_UTF8, 0, utf8.data(), int(utf8.size()), nullptr, 0);
    std::wstring w(size_t(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.data(), int(utf8.size()), &w[0], n);
    return w;
}

Channel channelFrom(const std::string& s) {
    if (s == "clipboard") return Channel::Clipboard;
    if (s == "file") return Channel::File;
    if (s == "ping") return Channel::Ping;
    return Channel::Control;
}

void vectorTests(const char* path) {
    std::ifstream f(path, std::ios::binary);
    expect(bool(f), std::string("vectors file opens: ") + path);
    if (!f) return;
    std::stringstream ss;
    ss << f.rdbuf();
    const std::string all = ss.str();
    size_t p = all.find("\"vectors\"");
    expect(p != std::string::npos, "vectors array present");
    int count = 0;
    int udpVectors = 0;
    while (p != std::string::npos) {
        size_t a = all.find('{', p);
        if (a == std::string::npos) break;
        size_t b = all.find('}', a);
        if (b == std::string::npos) break;
        const std::string v = all.substr(a, b - a + 1);
        p = b + 1;
        const std::string name = jsonField(v, "name");
        if (name.empty()) break;
        ++count;
        const std::wstring pw = widen(jsonField(v, "password"));
        const std::string nfc = normalizedUtf8(pw);
        expect(hex(reinterpret_cast<const uint8_t*>(nfc.data()), nfc.size()) == jsonField(v, "password_nfc_utf8"),
               "vector '" + name + "': NFC UTF-8 bytes");
        const Bytes salt = unhex(jsonField(v, "salt"));
        const uint32_t iter = uint32_t(std::strtoul(jsonField(v, "iterations").c_str(), nullptr, 10));
        auto k = deriveKey(pw, salt.data(), salt.size(), iter);
        expect(k && hex(k->data(), k->size()) == jsonField(v, "key"), "vector '" + name + "': PBKDF2 key");
        if (!k) continue;
        const Bytes hn = unhex(jsonField(v, "host_nonce"));
        const Bytes cn = unhex(jsonField(v, "client_nonce"));
        const Bytes hid = unhex(jsonField(v, "host_id"));
        const Channel ch = channelFrom(jsonField(v, "channel"));
        auto mc = *macClient(*k, hn.data(), cn.data(), ch, hid.data());
        auto mh = *macHost(*k, hn.data(), cn.data(), ch);
        expect(hex(mc.data(), mc.size()) == jsonField(v, "mac_c"), "vector '" + name + "': mac_c");
        expect(hex(mh.data(), mh.size()) == jsonField(v, "mac_h"), "vector '" + name + "': mac_h");
        // Wire layout.
        auto c = Challenge::decode(unhex(jsonField(v, "challenge_payload")));
        expect(c && Bytes(c->hostNonce.begin(), c->hostNonce.end()) == hn && Bytes(c->salt.begin(), c->salt.end()) == salt &&
                   c->iterations == iter && c->kdf == kKdfPbkdf2Sha256 && Bytes(c->hostId.begin(), c->hostId.end()) == hid,
               "vector '" + name + "': AUTH_CHALLENGE decodes");
        Bytes resp = cn;
        resp.insert(resp.end(), mc.begin(), mc.end());
        expect(hex(resp.data(), resp.size()) == jsonField(v, "response_payload"), "vector '" + name + "': AUTH_RESPONSE bytes");
        auto r = Result::decode(unhex(jsonField(v, "result_ok_payload")));
        expect(r && r->status == Result::Status::Ok && hex(r->macH.data(), r->macH.size()) == jsonField(v, "mac_h") &&
                   hex(r->sessionId.data(), r->sessionId.size()) == jsonField(v, "session_id"),
               "vector '" + name + "': AUTH_RESULT ok decodes");
        // A wrong key gives a different mac_h (the mutual check can fail).
        Key bad = *k;
        bad[0] ^= 1;
        auto mhBad = *macHost(bad, hn.data(), cn.data(), ch);
        expect(!constantTimeEqual(mhBad.data(), mh.data(), kMacBytes), "vector '" + name + "': wrong K fails mac_h");
        // PR-C: K_s and the UDP tags, where the vector has them.
        if (!jsonField(v, "session_key").empty()) {
            const Bytes sid = unhex(jsonField(v, "session_id"));
            auto ks = sessionKey(*k, hn.data(), cn.data(), sid.data());
            expect(ks && hex(ks->data(), ks->size()) == jsonField(v, "session_key"), "vector '" + name + "': session_key");
            if (ks) {
                const Bytes pv = unhex(jsonField(v, "udp_v2h_packet"));
                const Bytes ph = unhex(jsonField(v, "udp_h2v_packet"));
                auto tv = udpTag(*ks, false, pv.data(), pv.size());
                auto th = udpTag(*ks, true, ph.data(), ph.size());
                expect(tv && hex(tv->data(), tv->size()) == jsonField(v, "udp_v2h_tag"), "vector '" + name + "': udp v2h tag");
                expect(th && hex(th->data(), th->size()) == jsonField(v, "udp_h2v_tag"), "vector '" + name + "': udp h2v tag");
                // The reusable CNG tagger the viewer sends and checks with
                // gives the same bytes.
                uint8_t t1[8], t2[8];
                expect(udptag::Tagger(*ks, false).tag(pv.data(), pv.size(), t1) && hex(t1, 8) == jsonField(v, "udp_v2h_tag") &&
                           udptag::Tagger(*ks, true).tag(ph.data(), ph.size(), t2) && hex(t2, 8) == jsonField(v, "udp_h2v_tag"),
                       "vector '" + name + "': Tagger matches udp_tag");
                ++udpVectors;
            }
        }
    }
    expect(udpVectors >= 1, "at least 1 vector with UDP tags (" + std::to_string(udpVectors) + ")");
    expect(count >= 3, "at least 3 vectors read (" + std::to_string(count) + ")");
}

void wireTests() {
    expect(!Challenge::decode(Bytes(68)).has_value(), "challenge of 68 bytes rejected");
    expect(!Result::decode(Bytes{1}).has_value(), "fail without tries rejected");
    auto r = Result::decode(Bytes{2, 0, 0, 1, 44});
    expect(r && r->status == Result::Status::Locked && r->retrySeconds == 300, "locked 300 s decodes");
    r = Result::decode(Bytes{1, 3});
    expect(r && r->status == Result::Status::Fail && r->triesLeft == 3, "fail 3 tries decodes");
    expect(Result::decode(Bytes{5}) && Result::decode(Bytes{5})->status == Result::Status::OpenIpOnly, "open_ip_only decodes");
    expect(!Result::decode(Bytes{9}).has_value(), "unknown status rejected");
}

// MARK: Fake host on loopback

struct Secret {
    Key key;
    Salt salt{};
    HostId hostId{};
    uint32_t iter = kMinIterations;
};

Secret makeSecret(const std::wstring& password) {
    Secret s;
    randomBytes(s.salt.data(), s.salt.size());
    randomBytes(s.hostId.data(), s.hostId.size());
    s.key = *deriveKey(password, s.salt.data(), s.salt.size(), s.iter);
    return s;
}

bool hostSend(SOCKET s, uint8_t type, const Bytes& payload) {
    return sendAllBytes(s, frame(type, payload.data(), payload.size()));
}

Io hostRecv(SOCKET s, int ms, uint8_t& type, Bytes& payload) {
    return recvFrame(s, Clock::now() + std::chrono::milliseconds(ms), type, payload);
}

Bytes challengeFor(const Secret& sec, std::array<uint8_t, kNonceBytes>& hn) {
    randomBytes(hn.data(), hn.size());
    Bytes p(hn.begin(), hn.end());
    p.insert(p.end(), sec.salt.begin(), sec.salt.end());
    p.insert(p.end(), {uint8_t(sec.iter >> 24), uint8_t(sec.iter >> 16), uint8_t(sec.iter >> 8), uint8_t(sec.iter)});
    p.push_back(kKdfPbkdf2Sha256);
    p.insert(p.end(), sec.hostId.begin(), sec.hostId.end());
    return p;
}

enum class HostAnswer { Ok, BadMacH, Fail, AuthRequired, OpenIpOnly };

// What the fake host saw on one connection.
struct Seen {
    bool gotResponse = false;
    bool macValid = false;
    bool probe = false;           // a 0x03 with an all-zero MAC
    bool anyData = false;
    int responseAfterMs = -1;
    uint8_t chan = 0;
};

// Challenge -> response -> result, as a v0.4.0 host with a password.
// splitMs > 0: the challenge's first 3 bytes now, the rest splitMs later.
void hostWithPassword(SOCKET s, const Secret& sec, HostAnswer ans, Channel expectChan, Seen& seen, uint8_t tries = 4,
                      int splitMs = 0) {
    std::array<uint8_t, kNonceBytes> hn{};
    const Bytes chPayload = challengeFor(sec, hn);
    if (splitMs > 0) {
        const Bytes f = frame(kTypeChallenge, chPayload.data(), chPayload.size());
        send(s, reinterpret_cast<const char*>(f.data()), 3, 0);
        Sleep(DWORD(splitMs));
        send(s, reinterpret_cast<const char*>(f.data() + 3), int(f.size() - 3), 0);
    } else {
        hostSend(s, kTypeChallenge, chPayload);
    }
    uint8_t type = 0;
    Bytes p;
    if (hostRecv(s, 15000, type, p) != Io::Ok || type != kTypeResponse || p.size() != kResponseBytes) return;
    seen.gotResponse = true;
    auto want = *macClient(sec.key, hn.data(), p.data(), expectChan, sec.hostId.data());
    seen.macValid = constantTimeEqual(want.data(), p.data() + kNonceBytes, kMacBytes);
    {
        bool zero = true;
        for (size_t i = kNonceBytes; i < p.size(); ++i) zero = zero && p[i] == 0;
        seen.probe = zero;
    }
    Bytes res;
    if (ans == HostAnswer::Ok || ans == HostAnswer::BadMacH) {
        if (!seen.macValid) {
            res = {1, tries};
        } else {
            auto mh = *macHost(sec.key, hn.data(), p.data(), expectChan);
            if (ans == HostAnswer::BadMacH) mh[5] ^= 0x40;
            res.push_back(0);
            res.insert(res.end(), mh.begin(), mh.end());
            res.insert(res.end(), {1, 2, 3, 4, 5, 6, 7, 8});
        }
    } else if (ans == HostAnswer::Fail) {
        res = {1, tries};
    } else if (ans == HostAnswer::OpenIpOnly) {
        res = {5};
    } else {
        res = {4};
    }
    hostSend(s, kTypeResult, res);
}

class FakeHost {
public:
    using Script = std::function<void(SOCKET)>;
    FakeHost() {
        ls_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = 0;
        bind(ls_, reinterpret_cast<sockaddr*>(&a), sizeof(a));
        listen(ls_, 4);
        int n = sizeof(a);
        getsockname(ls_, reinterpret_cast<sockaddr*>(&a), &n);
        port_ = ntohs(a.sin_port);
    }
    ~FakeHost() { closesocket(ls_); }

    // Accept one connection, run `script` on it in a thread; `run` then
    // connects a client socket, hands it to `client`, and joins.
    Report run(Client& c, Channel ch, Script script, double* connectMsOut = nullptr) {
        std::thread t([&] {
            SOCKET s = accept(ls_, nullptr, nullptr);
            if (s == INVALID_SOCKET) return;
            script(s);
            // Let the client finish reading before the close.
            shutdown(s, SD_SEND);
            char buf[64];
            fd_set rs; FD_ZERO(&rs); FD_SET(s, &rs);
            timeval tv{0, 200000};
            if (select(0, &rs, nullptr, nullptr, &tv) > 0) recv(s, buf, sizeof(buf), 0);
            closesocket(s);
        });
        SOCKET cs = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = htons(port_);
        const auto t0 = Clock::now();
        connect(cs, reinterpret_cast<sockaddr*>(&a), sizeof(a));
        const double ms = msSince(t0);
        if (connectMsOut) *connectMsOut = ms;
        Report r = c.handshake(cs, ch, ms);
        closesocket(cs);
        t.join();
        return r;
    }

private:
    SOCKET ls_ = INVALID_SOCKET;
    uint16_t port_ = 0;
};

// MARK: Client helpers

struct Logged {
    std::mutex m;
    std::vector<std::string> lines;
    Client::LogFn fn() {
        return [this](const std::string& s) { std::lock_guard<std::mutex> g(m); lines.push_back(s); };
    }
    int count(const std::string& prefix) {
        std::lock_guard<std::mutex> g(m);
        int n = 0;
        for (auto& l : lines) if (l.rfind(prefix, 0) == 0) ++n;
        return n;
    }
    bool containsText(const std::string& needle) {
        std::lock_guard<std::mutex> g(m);
        for (auto& l : lines) if (l.find(needle) != std::string::npos) return true;
        return false;
    }
};

std::wstring tempStore(const wchar_t* tag) {
    wchar_t base[MAX_PATH]{};
    GetTempPathW(MAX_PATH, base);
    wchar_t name[64];
    std::swprintf(name, 64, L"jl-auth-test-%ls-%lu", tag, GetCurrentProcessId());
    std::wstring dir = std::wstring(base) + name;
    return dir;
}

void removeStore(const std::wstring& dir) {
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (fd.cFileName[0] != L'.') DeleteFileW((dir + L"\\" + fd.cFileName).c_str());
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    RemoveDirectoryW(dir.c_str());
}

int filesIn(const std::wstring& dir) {
    int n = 0;
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    do { if (fd.cFileName[0] != L'.') ++n; } while (FindNextFileW(h, &fd));
    FindClose(h);
    return n;
}

std::shared_ptr<Client> makeClient(const std::wstring& pw, bool remember, const std::wstring& dir, Logged& log) {
    Client::Options o;
    o.password = pw;
    o.remember = remember;
    o.storeDir = dir;
    o.log = log.fn();
    return std::make_shared<Client>(std::move(o));
}

const wchar_t* kGood = L"t\u00e9st-good-1";   // NFC form; the client is given the decomposed one below
const wchar_t* kGoodNfd = L"te\u0301st-good-1";
const wchar_t* kBad = L"test-bad-2";

// MARK: Scenarios

void dpapiTests() {
    const std::wstring dir = tempStore(L"dpapi");
    removeStore(dir);
    HostKeyStore st(dir);
    HostKeyStore::Entry e;
    randomBytes(e.hostId.data(), e.hostId.size());
    randomBytes(e.salt.data(), e.salt.size());
    randomBytes(e.key.data(), e.key.size());
    e.iterations = kIterations;
    expect(!st.exists(e.hostId), "dpapi: no file before save");
    expect(st.save(e), "dpapi: save");
    expect(st.exists(e.hostId), "dpapi: file at <dir>\\<host_id hex>.bin");
    auto back = st.load(e.hostId);
    expect(back && back->key == e.key && back->salt == e.salt && back->iterations == e.iterations && back->hostId == e.hostId,
           "dpapi: round trip gives the same host_id, salt, iter, K");
    // The file is sealed: K does not appear in it.
    {
        std::ifstream f(st.pathFor(e.hostId), std::ios::binary);
        std::string raw((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        std::string k(reinterpret_cast<const char*>(e.key.data()), e.key.size());
        expect(raw.find(k) == std::string::npos && raw.find("JLK1") == std::string::npos, "dpapi: file holds no plain K");
    }
    // Another host id never loads this file.
    HostId other = e.hostId;
    other[0] ^= 0xFF;
    expect(!st.load(other).has_value(), "dpapi: other host id loads nothing");
    // A damaged file loads nothing.
    {
        std::fstream f(st.pathFor(e.hostId), std::ios::in | std::ios::out | std::ios::binary);
        f.seekp(40);
        f.put('\x5A');
    }
    expect(!st.load(e.hostId).has_value(), "dpapi: damaged file loads nothing");
    expect(st.remove(e.hostId) == HostKeyStore::Removal::Deleted && !st.exists(e.hostId), "dpapi: remove reports deleted");
    expect(st.remove(e.hostId) == HostKeyStore::Removal::Missing, "dpapi: remove of a missing file reports missing");
    // A file that cannot be deleted (open without delete sharing) is emptied
    // instead, and an empty file never loads.
    expect(st.save(e), "dpapi: save again");
    {
        HANDLE hold = CreateFileW(st.pathFor(e.hostId).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        const auto r = st.remove(e.hostId);
        expect(r == HostKeyStore::Removal::Emptied, std::string("dpapi: undeletable file reports emptied (") + HostKeyStore::removalName(r) + ")");
        CloseHandle(hold);
        expect(!st.load(e.hostId).has_value(), "dpapi: emptied file loads nothing");
        st.remove(e.hostId);
    }
    removeStore(dir);
}

void passwordHostTests() {
    const Secret sec = makeSecret(kGood);
    FakeHost host;

    // Correct password, Remember off: OK, no file, K cached for the next channel.
    {
        const std::wstring dir = tempStore(L"nosave");
        removeStore(dir);
        Logged log;
        auto c = makeClient(kGoodNfd, false, dir, log);
        Seen seen;
        Report r = host.run(*c, Channel::Control, [&](SOCKET s) { hostWithPassword(s, sec, HostAnswer::Ok, Channel::Control, seen); });
        expect(r.outcome == Outcome::Ok, "password host, correct (NFD typed), remember off: ok");
        expect(seen.macValid, "  host accepted mac_c on control (chan 1)");
        expect(c->mode() == Client::Mode::Password, "  mode = password");
        expect(filesIn(dir) == 0, "  remember off: no file written");
        Seen seen2;
        r = host.run(*c, Channel::Clipboard, [&](SOCKET s) { hostWithPassword(s, sec, HostAnswer::Ok, Channel::Clipboard, seen2); });
        expect(r.outcome == Outcome::Ok && seen2.macValid, "  clipboard channel (chan 2) authenticates on its own");
        Seen seen3, seen4;
        r = host.run(*c, Channel::File, [&](SOCKET s) { hostWithPassword(s, sec, HostAnswer::Ok, Channel::File, seen3); });
        expect(r.outcome == Outcome::Ok && seen3.macValid, "  file channel (chan 3) authenticates on its own");
        r = host.run(*c, Channel::Ping, [&](SOCKET s) { hostWithPassword(s, sec, HostAnswer::Ok, Channel::Ping, seen4); });
        expect(r.outcome == Outcome::Ok && seen4.macValid, "  ping channel (chan 4) authenticates on its own");
        expect(log.count("auth.kdf") == 1, "  PBKDF2 ran once for 4 channels (" + std::to_string(log.count("auth.kdf")) + ")");
        expect(log.count("auth.probe") == 0, "  password host is never probed");
        expect(filesIn(dir) == 0, "  still no file after 4 channels");
        // A channel that answers with the wrong channel number fails the host's check.
        Seen seen5;
        r = host.run(*c, Channel::Clipboard, [&](SOCKET s) { hostWithPassword(s, sec, HostAnswer::Ok, Channel::Control, seen5); });
        expect(!seen5.macValid, "  mac_c binds the channel (clipboard MAC fails as control)");
        removeStore(dir);
    }

    // Correct password, Remember on: file written; a new viewer run with no
    // password connects from it without PBKDF2.
    {
        const std::wstring dir = tempStore(L"save");
        removeStore(dir);
        Logged log;
        auto c = makeClient(kGood, true, dir, log);
        Seen seen;
        Report r = host.run(*c, Channel::Control, [&](SOCKET s) { hostWithPassword(s, sec, HostAnswer::Ok, Channel::Control, seen); });
        expect(r.outcome == Outcome::Ok, "password host, correct, remember on: ok");
        HostKeyStore st(dir);
        expect(st.exists(sec.hostId) && filesIn(dir) == 1, "  remember on: one file written");
        auto e = st.load(sec.hostId);
        expect(e && e->key == sec.key && e->salt == sec.salt && e->iterations == sec.iter, "  file holds {host_id, salt, iter, K}");

        Logged log2;
        auto c2 = makeClient(L"", false, dir, log2);  // viewer restarted
        Seen seen2;
        r = host.run(*c2, Channel::Control, [&](SOCKET s) { hostWithPassword(s, sec, HostAnswer::Ok, Channel::Control, seen2); });
        expect(r.outcome == Outcome::Ok && seen2.macValid, "  restart: remembered host connects with no password typed");
        expect(log2.count("auth.kdf") == 0, "  restart: no PBKDF2 (K from DPAPI)");
        expect(st.exists(sec.hostId), "  restart: file kept");

        // The Mac's password changed (new salt): the stale file goes.
        Secret changed = makeSecret(kGood);
        changed.hostId = sec.hostId;
        Logged log3;
        auto c3 = makeClient(L"", false, dir, log3);
        Seen seen3;
        r = host.run(*c3, Channel::Control, [&](SOCKET s) { hostWithPassword(s, changed, HostAnswer::Ok, Channel::Control, seen3); });
        expect(r.outcome == Outcome::NeedPassword && !seen3.gotResponse, "  new salt: need password, nothing sent");
        expect(!st.exists(sec.hostId), "  new salt: stale file deleted");
        clearDistrustedForTest();

        // Typed password with Remember off deletes an old file on success.
        st.save(HostKeyStore::Entry{sec.hostId, sec.salt, sec.iter, sec.key});
        Logged log4;
        auto c4 = makeClient(kGood, false, dir, log4);
        Seen seen4;
        r = host.run(*c4, Channel::Control, [&](SOCKET s) { hostWithPassword(s, sec, HostAnswer::Ok, Channel::Control, seen4); });
        expect(r.outcome == Outcome::Ok && !st.exists(sec.hostId), "  typed + remember off: old file removed");
        removeStore(dir);
    }

    // Wrong password: fail with tries left, nothing saved, the client halts.
    {
        const std::wstring dir = tempStore(L"wrong");
        removeStore(dir);
        Logged log;
        auto c = makeClient(kBad, true, dir, log);
        int terminals = 0;
        Report last;
        c->setTerminalHandler([&](const Report& r) { ++terminals; last = r; });
        Seen seen;
        Report r = host.run(*c, Channel::Control, [&](SOCKET s) { hostWithPassword(s, sec, HostAnswer::Ok, Channel::Control, seen, 4); });
        expect(seen.gotResponse && !seen.macValid, "wrong password: host saw a bad mac_c");
        expect(r.outcome == Outcome::Fail && r.triesLeft == 4 && !r.usedSavedKey, "wrong password: fail, 4 tries left");
        expect(filesIn(dir) == 0, "  remember on but wrong: no file");
        expect(c->halted() && terminals == 1 && last.outcome == Outcome::Fail, "  client halts and tells the viewer once");
        expect(!c->halted() || c->lastTerminal().triesLeft == 4, "  last answer kept for the launch screen");
        removeStore(dir);
    }

    // Saved key no longer works: file deleted at once.
    {
        const std::wstring dir = tempStore(L"failsaved");
        removeStore(dir);
        HostKeyStore st(dir);
        st.save(HostKeyStore::Entry{sec.hostId, sec.salt, sec.iter, sec.key});
        Logged log;
        auto c = makeClient(L"", false, dir, log);
        Seen seen;
        Report r = host.run(*c, Channel::Control, [&](SOCKET s) { hostWithPassword(s, sec, HostAnswer::Fail, Channel::Control, seen, 2); });
        expect(r.outcome == Outcome::Fail && r.usedSavedKey && r.triesLeft == 2, "saved key fails: fail, usedSavedKey");
        expect(!st.exists(sec.hostId), "  saved key file deleted after fail");
        clearDistrustedForTest();
        removeStore(dir);
    }

    // Mutual check: the host says OK but its mac_h is wrong.
    {
        const std::wstring dir = tempStore(L"mutual");
        removeStore(dir);
        Logged log;
        auto c = makeClient(kGood, true, dir, log);
        Seen seen;
        Report r = host.run(*c, Channel::Control, [&](SOCKET s) { hostWithPassword(s, sec, HostAnswer::BadMacH, Channel::Control, seen); });
        expect(r.outcome == Outcome::HostMismatch, "bad mac_h: host identity mismatch");
        expect(filesIn(dir) == 0, "  bad mac_h: nothing saved even with remember on");
        expect(c->halted(), "  bad mac_h: client halts");
        removeStore(dir);
    }

    // Answers before the challenge, and auth_required after the response.
    {
        Logged log;
        auto c = makeClient(kGood, false, L"", log);
        Report r = host.run(*c, Channel::Control, [&](SOCKET s) { hostSend(s, kTypeResult, Bytes{2, 0, 0, 0, 125}); });
        expect(r.outcome == Outcome::Locked && r.retrySeconds == 125, "locked before challenge: locked 125 s");
        auto c2 = makeClient(kGood, false, L"", log);
        r = host.run(*c2, Channel::Control, [&](SOCKET s) { hostSend(s, kTypeResult, Bytes{3}); });
        expect(r.outcome == Outcome::Blocked, "blocked before challenge: blocked");
        auto c3 = makeClient(kGood, false, L"", log);
        Seen seen;
        r = host.run(*c3, Channel::Control, [&](SOCKET s) { hostWithPassword(s, sec, HostAnswer::AuthRequired, Channel::Control, seen); });
        expect(r.outcome == Outcome::AuthRequired, "auth_required result: auth_required");
        // open_ip_only without a probe is not trusted.
        auto c4 = makeClient(kGood, false, L"", log);
        r = host.run(*c4, Channel::Control, [&](SOCKET s) { hostSend(s, kTypeResult, Bytes{5}); });
        expect(r.outcome == Outcome::Network && c4->mode() == Client::Mode::Unknown, "unasked open_ip_only: ignored");
    }

    // No password and no saved key: nothing is sent.
    {
        const std::wstring dir = tempStore(L"none");
        removeStore(dir);
        Logged log;
        auto c = makeClient(L"", false, dir, log);
        Seen seen;
        Report r = host.run(*c, Channel::Control, [&](SOCKET s) { hostWithPassword(s, sec, HostAnswer::Ok, Channel::Control, seen); });
        expect(r.outcome == Outcome::NeedPassword && !seen.gotResponse, "no password known: need password, no response sent");
        removeStore(dir);
    }

    // Halted: later handshakes do not touch the network.
    {
        Logged log;
        auto c = makeClient(kBad, false, L"", log);
        Seen seen;
        host.run(*c, Channel::Control, [&](SOCKET s) { hostWithPassword(s, sec, HostAnswer::Ok, Channel::Control, seen, 3); });
        setCurrent(c);
        expect(!mayConnect(), "halted: channels may not connect");
        Seen seen2;
        Report r = host.run(*c, Channel::Clipboard, [&](SOCKET s) { hostWithPassword(s, sec, HostAnswer::Ok, Channel::Clipboard, seen2); });
        expect(r.outcome == Outcome::Fail && !seen2.gotResponse, "halted: no second try spent");
        setCurrent(nullptr);
        expect(mayConnect(), "no client: channels connect as before");
    }
}

void oldAndTransitionTests() {
    FakeHost host;

    // 0.3.x host: says nothing. The viewer gives up at 2 s; any probe carries
    // no password (zero MAC).
    {
        Logged log;
        auto c = makeClient(kGood, false, L"", log);
        Seen seen;
        const auto t0 = Clock::now();
        Report r = host.run(*c, Channel::Control, [&](SOCKET s) {
            uint8_t type = 0;
            Bytes p;
            while (hostRecv(s, 2600, type, p) == Io::Ok) {
                seen.anyData = true;
                if (type == kTypeResponse && p.size() == kResponseBytes) {
                    bool zero = true;
                    for (size_t i = kNonceBytes; i < p.size(); ++i) zero = zero && p[i] == 0;
                    seen.probe = zero;
                }
            }
        });
        const double ms = msSince(t0);
        expect(r.outcome == Outcome::HostTooOld, "old host: host too old");
        expect(ms >= 1900 && ms < 3200, "old host: gave up at about 2 s (" + std::to_string(int(ms)) + " ms)");
        expect(!seen.anyData || seen.probe, "old host: only a zero-MAC probe was sent, never the password");
        expect(log.count("auth.kdf") == 0, "old host: password never used");
        expect(c->halted(), "old host: no fallback to an unauthenticated session");
    }

    // Transition host: no challenge, answers the probe with open_ip_only.
    {
        Logged log;
        auto c = makeClient(L"", false, L"", log);
        int afterMs = -1;
        Report r = host.run(*c, Channel::Control, [&](SOCKET s) {
            const auto t0 = Clock::now();
            uint8_t type = 0;
            Bytes p;
            if (hostRecv(s, 3000, type, p) == Io::Ok && type == kTypeResponse && p.size() == kResponseBytes) {
                afterMs = int(msSince(t0));
                hostSend(s, kTypeResult, Bytes{5});
            }
        });
        expect(r.outcome == Outcome::Open, "transition host: open_ip_only");
        expect(afterMs >= 280 && afterMs < 1700, "transition: probe after >= 300 ms (" + std::to_string(afterMs) + " ms)");
        expect(c->transition(), "transition: mode remembered (overlay shows the no-password notice)");
        // Next channel: shorter wait, same answer.
        int afterMs2 = -1;
        r = host.run(*c, Channel::Clipboard, [&](SOCKET s) {
            const auto t0 = Clock::now();
            uint8_t type = 0;
            Bytes p;
            if (hostRecv(s, 3000, type, p) == Io::Ok && type == kTypeResponse) {
                afterMs2 = int(msSince(t0));
                hostSend(s, kTypeResult, Bytes{5});
            }
        });
        expect(r.outcome == Outcome::Open && afterMs2 >= 0 && afterMs2 <= 400,
               "transition: next channel probes after <= 300 ms (" + std::to_string(afterMs2) + " ms)");
    }

    // A late challenge crosses the probe and the host never says what it
    // counted: no automatic retry (r3), and the next attempt (a new Client
    // for the same host) authenticates without a probe.
    {
        clearKnownModesForTest();
        const Secret sec = makeSecret(kGood);
        Logged log;
        Client::Options o;
        o.password = kGood;
        o.hostKey = "127.0.0.9:7001";
        o.log = log.fn();
        auto c = std::make_shared<Client>(std::move(o));
        Report r = host.run(*c, Channel::Control, [&](SOCKET s) {
            Sleep(450);
            std::array<uint8_t, kNonceBytes> hn{};
            hostSend(s, kTypeChallenge, challengeFor(sec, hn));
            uint8_t type = 0;
            Bytes p;
            hostRecv(s, 1500, type, p);  // the probe; no answer
        });
        expect(r.outcome == Outcome::RaceUnanswered && r.probeRace, "probe race, no answer: race_unanswered, no retry");
        expect(c->halted() && c->mode() == Client::Mode::Password, "  halted; host known to want a password");
        Client::Options o2;
        o2.password = kGood;
        o2.hostKey = "127.0.0.9:7001";
        o2.log = log.fn();
        auto c2 = std::make_shared<Client>(std::move(o2));
        Seen seen;
        r = host.run(*c2, Channel::Control, [&](SOCKET s) {
            Sleep(450);  // still slow, but a password host is not probed again
            hostWithPassword(s, sec, HostAnswer::Ok, Channel::Control, seen);
        });
        expect(r.outcome == Outcome::Ok && seen.macValid && !seen.probe, "  next attempt: no probe, authenticated");
        clearKnownModesForTest();
    }
}

// Pepper's PR-B review (blockers 1, 2, should-fix 5, 6).
void reviewFixTests() {
    const Secret sec = makeSecret(kGood);
    FakeHost host;

    // 1: after our proof, open_ip_only skips mac_h: host identity mismatch.
    {
        const std::wstring dir = tempStore(L"openafter");
        removeStore(dir);
        Logged log;
        auto c = makeClient(kGood, true, dir, log);
        Seen seen;
        Report r = host.run(*c, Channel::Control, [&](SOCKET s) { hostWithPassword(s, sec, HostAnswer::OpenIpOnly, Channel::Control, seen); });
        expect(seen.gotResponse && seen.macValid, "open_ip_only after proof: host got a real mac_c");
        expect(r.outcome == Outcome::HostMismatch, "open_ip_only after proof: host identity mismatch, no channel");
        expect(c->halted() && c->mode() != Client::Mode::Transition, "  halted, not treated as a transition host");
        expect(filesIn(dir) == 0, "  nothing saved even with remember on");
        expect(!c->holdsSecrets(), "  password and K wiped");
        expect(log.containsText("reason=open_after_challenge"), "  logged reason=open_after_challenge");
        removeStore(dir);
    }

    // 1: CNG fails computing mac_c: stop, send nothing (no all-zero MAC).
    {
        Logged log;
        auto c = makeClient(kGood, false, L"", log);
        Seen seen;
        hmacFaultsForTest() = 1;
        Report r = host.run(*c, Channel::Control, [&](SOCKET s) { hostWithPassword(s, sec, HostAnswer::Ok, Channel::Control, seen); });
        hmacFaultsForTest() = 0;
        expect(r.outcome == Outcome::LocalError, "hmac failure: local error");
        expect(!seen.gotResponse, "  hmac failure: no response sent to the host");
        expect(c->halted() && !c->holdsSecrets(), "  hmac failure: halted, secrets wiped");
        expect(log.containsText("auth.hmac_failed"), "  logged auth.hmac_failed");
    }
    // ...and computing mac_h after an OK: no channel.
    {
        Logged log;
        auto c = makeClient(kGood, false, L"", log);
        Seen seen;
        Report r = host.run(*c, Channel::Control, [&](SOCKET s) {
            // The client's mac_c succeeds; the next HMAC (its mac_h check) fails.
            std::array<uint8_t, kNonceBytes> hn{};
            hostSend(s, kTypeChallenge, challengeFor(sec, hn));
            uint8_t type = 0;
            Bytes p;
            if (hostRecv(s, 15000, type, p) != Io::Ok || p.size() != kResponseBytes) return;
            seen.gotResponse = true;
            auto mh = *macHost(sec.key, hn.data(), p.data(), Channel::Control);
            hmacFaultsForTest() = 1;
            Bytes res{0};
            res.insert(res.end(), mh.begin(), mh.end());
            res.insert(res.end(), {1, 2, 3, 4, 5, 6, 7, 8});
            hostSend(s, kTypeResult, res);
        });
        hmacFaultsForTest() = 0;
        expect(r.outcome == Outcome::LocalError, "hmac failure on mac_h: local error, no channel");
    }

    // 2: the challenge's header arrives in pieces across the probe wait:
    // the bytes are kept and no probe goes out.
    {
        Logged log;
        auto c = makeClient(kGood, false, L"", log);
        Seen seen;
        Report r = host.run(*c, Channel::Control, [&](SOCKET s) {
            Sleep(100);
            hostWithPassword(s, sec, HostAnswer::Ok, Channel::Control, seen, 4, 600);
        });
        expect(r.outcome == Outcome::Ok && seen.macValid && !seen.probe, "split header: kept, no probe, ok");
        expect(log.count("auth.probe ") == 0 && log.containsText("auth.probe_skipped"), "  probe skipped (frame started)");
    }

    // 2: probe crosses a late challenge and the host counted it.
    auto raceHost = [&](Bytes answer) {
        return [&sec, answer](SOCKET s) {
            Sleep(450);
            std::array<uint8_t, kNonceBytes> hn{};
            hostSend(s, kTypeChallenge, challengeFor(sec, hn));
            uint8_t type = 0;
            Bytes p;
            if (hostRecv(s, 1500, type, p) == Io::Ok) hostSend(s, kTypeResult, answer);
        };
    };
    {
        const std::wstring dir = tempStore(L"race");
        removeStore(dir);
        HostKeyStore st(dir);
        Logged log;
        auto c = makeClient(kGood, false, dir, log);
        Report r = host.run(*c, Channel::Control, raceHost(Bytes{1, 4}));
        expect(r.outcome == Outcome::Retry && r.probeRace && r.triesLeft == 4, "probe race counted (4 left): one retry");
        expect(!c->halted() && c->holdsSecrets(), "  not halted; the password was never tried, so it is kept");
        Seen seen;
        r = host.run(*c, Channel::Control, [&](SOCKET s) { hostWithPassword(s, sec, HostAnswer::Ok, Channel::Control, seen); });
        expect(r.outcome == Outcome::Ok && seen.macValid && !seen.probe, "  retry: no probe, ok");
        removeStore(dir);
    }
    {
        Logged log;
        auto c = makeClient(kGood, false, L"", log);
        Report r = host.run(*c, Channel::Control, raceHost(Bytes{1, 1}));
        expect(r.outcome == Outcome::Fail && r.probeRace && r.triesLeft == 1, "probe race with 1 try left: stop, the user decides");
        expect(c->halted(), "  halted (no retry can start a lockout)");
    }
    {
        Logged log;
        auto c = makeClient(kGood, false, L"", log);
        Report r = host.run(*c, Channel::Control, raceHost(Bytes{2, 0, 0, 1, 44}));
        expect(r.outcome == Outcome::Locked && r.retrySeconds == 300 && r.probeRace, "probe race that locked: locked 300 s, no retry");
        expect(c->halted(), "  halted");
    }
    {
        // A saved key is not touched by a probe race (no password tried).
        const std::wstring dir = tempStore(L"racesaved");
        removeStore(dir);
        HostKeyStore st(dir);
        st.save(HostKeyStore::Entry{sec.hostId, sec.salt, sec.iter, sec.key});
        Logged log;
        auto c = makeClient(L"", false, dir, log);
        Report r = host.run(*c, Channel::Control, raceHost(Bytes{1, 1}));
        expect(r.outcome == Outcome::Fail && !r.usedSavedKey && st.exists(sec.hostId), "probe race: saved key kept");
        removeStore(dir);
    }

    // 2: two background channels reconnect together against a host that
    // answers Fail: only one of them answers a challenge.
    {
        Logged log;
        auto c = makeClient(kBad, false, L"", log);  // mode unknown: still one at a time
        SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        bind(ls, reinterpret_cast<sockaddr*>(&a), sizeof(a));
        listen(ls, 4);
        int n = sizeof(a);
        getsockname(ls, reinterpret_cast<sockaddr*>(&a), &n);
        std::atomic<int> responses{0};
        std::atomic<int> accepted{0};
        std::thread hostT([&] {
            for (int i = 0; i < 2; ++i) {
                fd_set rs; FD_ZERO(&rs); FD_SET(ls, &rs);
                timeval tv{2, 0};
                if (select(0, &rs, nullptr, nullptr, &tv) <= 0) break;
                SOCKET s = accept(ls, nullptr, nullptr);
                if (s == INVALID_SOCKET) break;
                ++accepted;
                std::thread([&, s] {
                    Seen seen;
                    hostWithPassword(s, sec, HostAnswer::Fail, Channel::Clipboard, seen, 4);
                    if (seen.gotResponse) ++responses;
                    shutdown(s, SD_SEND);
                    Sleep(300);
                    closesocket(s);
                }).detach();
            }
        });
        setCurrent(c);
        Report out[2];
        auto channel = [&](int i) {
            auto slot = connectSlot();
            if (!mayConnect()) { out[i] = c->lastTerminal(); return; }
            SOCKET cs = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            connect(cs, reinterpret_cast<sockaddr*>(&a), sizeof(a));
            out[i] = c->handshake(cs, Channel::Clipboard, 1.0);
            closesocket(cs);
        };
        std::thread t1(channel, 0), t2(channel, 1);
        t1.join(); t2.join();
        hostT.join();
        Sleep(400);
        setCurrent(nullptr);
        closesocket(ls);
        expect(responses.load() == 1, "single flight: host saw one response for two channels (" + std::to_string(responses.load()) + ")");
        expect(out[0].outcome == Outcome::Fail && out[1].outcome == Outcome::Fail, "  both channels end with the same fail");
        expect(accepted.load() == 1, "  the second channel did not even connect (" + std::to_string(accepted.load()) + ")");
    }

    // 6: a failed saved key whose file could not be deleted is never loaded
    // again, by this client or the next one.
    {
        const std::wstring dir = tempStore(L"distrust");
        removeStore(dir);
        clearDistrustedForTest();
        HostKeyStore st(dir);
        st.save(HostKeyStore::Entry{sec.hostId, sec.salt, sec.iter, sec.key});
        // Read-only share: neither delete nor truncate can succeed.
        HANDLE hold = CreateFileW(st.pathFor(sec.hostId).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        Logged log;
        auto c = makeClient(L"", false, dir, log);
        Seen seen;
        Report r = host.run(*c, Channel::Control, [&](SOCKET s) { hostWithPassword(s, sec, HostAnswer::Fail, Channel::Control, seen, 3); });
        expect(r.outcome == Outcome::Fail && r.usedSavedKey, "distrust: saved key fails");
        expect(log.containsText("auth.saved_key_dropped reason=fail file=failed"), "  log says the delete failed (not 'deleted')");
        expect(r.savedKeyFile && std::string(r.savedKeyFile) == "failed" && log.containsText("tries=3 saved_key=failed") &&
                   !log.containsText("saved_key=deleted"),
               "  auth.result logs saved_key=failed, the real removal result");
        CloseHandle(hold);
        expect(st.load(sec.hostId).has_value(), "  (the file really is still there and readable)");
        Logged log2;
        auto c2 = makeClient(L"", false, dir, log2);
        Seen seen2;
        r = host.run(*c2, Channel::Control, [&](SOCKET s) { hostWithPassword(s, sec, HostAnswer::Ok, Channel::Control, seen2); });
        expect(r.outcome == Outcome::NeedPassword && !seen2.gotResponse, "  next client: not used again, nothing sent");
        expect(log2.containsText("auth.saved_key_skipped reason=distrusted"), "  logged saved_key_skipped");
        // Carried to a relaunched process.
        const std::string enc = encodeDistrusted();
        clearDistrustedForTest();
        loadDistrusted("zz," + enc + ",0123");
        expect(hostDistrusted(sec.hostId) && encodeDistrusted() == enc, "  relaunch list round trip (junk ignored)");
        clearDistrustedForTest();
        st.remove(sec.hostId);
        removeStore(dir);
    }
    // 6: a successful delete is logged as such.
    {
        const std::wstring dir = tempStore(L"dropok");
        removeStore(dir);
        HostKeyStore st(dir);
        st.save(HostKeyStore::Entry{sec.hostId, sec.salt, sec.iter, sec.key});
        Logged log;
        auto c = makeClient(L"", false, dir, log);
        Seen seen;
        host.run(*c, Channel::Control, [&](SOCKET s) { hostWithPassword(s, sec, HostAnswer::Fail, Channel::Control, seen, 3); });
        expect(log.containsText("auth.saved_key_dropped reason=fail file=deleted") && !st.exists(sec.hostId), "drop: deleted and logged deleted");
        expect(log.containsText("tries=3 saved_key=deleted"), "  auth.result logs saved_key=deleted");
        clearDistrustedForTest();
        removeStore(dir);
    }

    // 5: every terminal answer wipes the password and K.
    {
        Logged log;
        auto c = makeClient(kGood, false, L"", log);
        expect(c->holdsSecrets(), "wipe: typed password held before the attempt");
        Report r = host.run(*c, Channel::Control, [&](SOCKET s) { hostSend(s, kTypeResult, Bytes{2, 0, 0, 0, 60}); });
        expect(r.outcome == Outcome::Locked && !c->holdsSecrets(), "wipe: locked before a challenge wipes the typed password");
        auto c2 = makeClient(kGood, false, L"", log);
        Seen seen;
        host.run(*c2, Channel::Control, [&](SOCKET s) { hostWithPassword(s, sec, HostAnswer::Ok, Channel::Control, seen); });
        expect(c2->holdsSecrets(), "wipe: K kept in memory while the session runs");
        Seen seen2;
        r = host.run(*c2, Channel::File, [&](SOCKET s) { hostWithPassword(s, sec, HostAnswer::AuthRequired, Channel::File, seen2); });
        expect(r.outcome == Outcome::AuthRequired && !c2->holdsSecrets(), "wipe: a background channel's terminal answer wipes K");
    }
}

// Pepper's PR-B review r2 (blockers 1, 4).
// What a fake host saw on a connection where it sends no challenge (or
// one too late): any byte from the viewer would be a probe or an answer.
struct SilentHost {
    std::atomic<bool> gotData{false};
    // Waits ms, then (lateChallenge) sends a challenge nobody reads any
    // more, then watches for anything the viewer sends.
    void run(SOCKET s, int ms, const Secret* lateChallenge) {
        uint8_t type = 0;
        Bytes p;
        const Io io = hostRecv(s, ms, type, p);
        if (io == Io::Ok) { gotData = true; return; }
        if (io == Io::Closed) return;  // the viewer gave up first (its 2 s wait)
        if (lateChallenge) {
            std::array<uint8_t, kNonceBytes> hn{};
            hostSend(s, kTypeChallenge, challengeFor(*lateChallenge, hn));
        }
        if (hostRecv(s, 300, type, p) == Io::Ok) gotData = true;
    }
};

void r4KnownPasswordTests() {
    const std::string hostKey = "127.0.0.9:7002";
    const Secret sec = makeSecret(kGood);
    // a. Known from an earlier attempt (the relaunch list); the challenge
    // is lost on a slow line.
    {
        clearKnownModesForTest();
        loadPasswordHosts(hostKey);
        Logged log;
        Client::Options o;
        o.password = kGood;
        o.hostKey = hostKey;
        o.log = log.fn();
        auto c = std::make_shared<Client>(std::move(o));
        FakeHost host;
        SilentHost h;
        const auto t0 = Clock::now();
        Report r = host.run(*c, Channel::Ping, [&](SOCKET s) { h.run(s, 2300, nullptr); });
        expect(r.outcome == Outcome::NoChallenge && c->halted() && isTerminal(r.outcome),
               "r4 known password, challenge lost: no_challenge, ends the attempt");
        expect(!h.gotData && log.count("auth.probe ") == 0, "  no probe, nothing sent: no try spent");
        expect(knownMode(hostKey) == HostMode::Password && log.containsText("auth.known_mode_kept reason=no_challenge") &&
                   !log.containsText("known_mode_cleared"),
               "  password mark kept (not cleared on a timeout)");
        expect(msSince(t0) < 3000.0, "  gave up after the 2 s challenge wait");
    }
    // b. Learned in this attempt (first connection got a challenge); the
    // next connection's challenge comes 2.5 s late. Not 'host too old', no
    // probe, and the late challenge gets no answer.
    {
        clearKnownModesForTest();
        Logged log;
        Client::Options o;
        o.password = kGood;
        o.hostKey = hostKey;
        o.log = log.fn();
        auto c = std::make_shared<Client>(std::move(o));
        FakeHost host;
        Seen seen;
        Report r = host.run(*c, Channel::Ping, [&](SOCKET s) { hostWithPassword(s, sec, HostAnswer::Ok, Channel::Ping, seen); });
        expect(r.outcome == Outcome::Ok && knownMode(hostKey) == HostMode::Password, "r4 learned password mode on the first connection");
        SilentHost h;
        r = host.run(*c, Channel::Control, [&](SOCKET s) { h.run(s, 2500, &sec); });
        expect(r.outcome == Outcome::NoChallenge && !h.gotData && log.count("auth.probe ") == 0,
               "  late challenge on the next connection: no_challenge, no probe, no answer");
        expect(knownMode(hostKey) == HostMode::Password, "  mark kept");
    }
    // c. The next Connect (a new Client) still never probes: the host's
    // prompt challenge is answered with the password.
    {
        Logged log;
        Client::Options o;
        o.password = kGood;
        o.hostKey = hostKey;
        o.log = log.fn();
        auto c = std::make_shared<Client>(std::move(o));
        FakeHost host;
        Seen seen;
        Report r = host.run(*c, Channel::Ping, [&](SOCKET s) {
            Sleep(900);  // slower than any probe wait: a probe would have gone
            hostWithPassword(s, sec, HostAnswer::Ok, Channel::Ping, seen);
        });
        expect(r.outcome == Outcome::Ok && seen.macValid && !seen.probe && log.count("auth.probe ") == 0,
               "  next Connect: waits for the challenge (900 ms), no probe, authenticated");
    }
    // d. "Retry without password": the user's call forgets the mark; the
    // next attempt probes and the IP-only Mac lets it in.
    {
        expect(forgetPasswordMode(hostKey) && knownMode(hostKey) == HostMode::Unknown && !forgetPasswordMode(hostKey),
               "retry without password: mark forgotten (once)");
        expect(encodePasswordHosts().empty(), "  not carried to a relaunch");
        Logged log;
        Client::Options o;
        o.hostKey = hostKey;
        o.log = log.fn();
        auto c = std::make_shared<Client>(std::move(o));
        FakeHost host;
        Report r = host.run(*c, Channel::Ping, [&](SOCKET s) {
            uint8_t type = 0;
            Bytes p;
            if (hostRecv(s, 3000, type, p) == Io::Ok) hostSend(s, kTypeResult, Bytes{5});
        });
        expect(r.outcome == Outcome::Open && log.count("auth.probe ") == 1, "  probes and connects (open_ip_only)");
        clearKnownModesForTest();
    }
}

// Pepper's PR-B review r4, item 2: a background NoChallenge (the session
// is up) keeps the session; the channel retries with backoff, no probe.
void r5BackgroundNoChallengeTests() {
    const std::string hostKey = "127.0.0.9:7005";
    const Secret sec = makeSecret(kGood);
    clearKnownModesForTest();
    Logged log;
    Client::Options o;
    o.password = kGood;
    o.hostKey = hostKey;
    o.log = log.fn();
    auto c = std::make_shared<Client>(std::move(o));
    int terminals = 0;
    c->setTerminalHandler([&](const Report&) { ++terminals; });
    FakeHost host;
    {
        // Before the session is up, NoChallenge still ends the attempt.
        loadPasswordHosts(hostKey);
        Logged log0;
        Client::Options o0;
        o0.password = kGood;
        o0.hostKey = hostKey;
        o0.log = log0.fn();
        auto c0 = std::make_shared<Client>(std::move(o0));
        SilentHost h;
        Report r = host.run(*c0, Channel::Control, [&](SOCKET s) { h.run(s, 2300, nullptr); });
        expect(r.outcome == Outcome::NoChallenge && c0->halted() && !c0->authenticatedOnce(),
               "r5 first connection NoChallenge: still ends the attempt (first-connect timeout may stop)");
        clearKnownModesForTest();
    }
    Seen seen;
    Report r = host.run(*c, Channel::Ping, [&](SOCKET s) { hostWithPassword(s, sec, HostAnswer::Ok, Channel::Ping, seen); });
    expect(r.outcome == Outcome::Ok && c->authenticatedOnce(), "r5 session up (first channel authenticated)");
    SilentHost h;
    r = host.run(*c, Channel::Clipboard, [&](SOCKET s) { h.run(s, 2500, &sec); });
    expect(r.outcome == Outcome::NoChallenge && !c->halted() && terminals == 0,
           "r5 background NoChallenge (challenge 2.5 s late): session kept, viewer not told to end");
    expect(!h.gotData && log.count("auth.probe ") == 0, "  no probe, nothing sent: no try spent");
    expect(c->mode() == Client::Mode::Password && knownMode(hostKey) == HostMode::Password,
           "  Password mode kept");
    expect(log.containsText("auth.no_challenge_background chan=clipboard session=kept"), "  logged as background");
    // The channel's retry budget (thread that ran the gate).
    setCurrent(c);
    NoChallengeRetry retry(Channel::Clipboard);
    tLastGate = Outcome::Network;
    expect(retry.afterFailure() == 0, "  retry: other failure keeps the channel's usual path");
    int waits[5];
    for (int& w : waits) {
        tLastGate = Outcome::NoChallenge;
        w = retry.afterFailure();
    }
    expect(waits[0] == 500 && waits[1] == 1000 && waits[2] == 2000 && waits[3] == 4000 && waits[4] == -1,
           "  retry: backoff 500/1000/2000/4000 ms, then paused");
    expect(c->takePausedChannels() == (1u << unsigned(Channel::Clipboard)) && c->takePausedChannels() == 0,
           "  paused channel reported once (only the clipboard)");
    expect(log.count("auth.no_challenge_retry chan=clipboard") == 4 &&
               log.containsText("auth.channel_paused chan=clipboard reason=no_challenge retries=4"),
           "  each retry and the pause logged");
    // r6 (Pepper's r5 review, item 2): no new round on its own; only
    // reset() (a good connection, or the user's fresh key press) ends it.
    tLastGate = Outcome::NoChallenge;
    const int again1 = retry.afterFailure();
    const int again2 = retry.afterFailure();
    expect(again1 == -1 && again2 == -1 && retry.paused() && c->takePausedChannels() == 0 &&
               log.count("auth.channel_paused chan=clipboard") == 1,
           "  r6: stays paused after the budget ran out (no new round, not reported again)");
    retry.reset();
    expect(retry.failures() == 0 && !retry.paused() && !c->halted() && terminals == 0,
           "  reset after a good connection; session never ended");
    tLastGate = Outcome::NoChallenge;
    expect(retry.afterFailure() == 500, "  r6: after reset() the next attempt gets a new budget");
    retry.reset();
    // Then the late Mac answers in time: the same client authenticates.
    Seen seen2;
    r = host.run(*c, Channel::Clipboard, [&](SOCKET s) { hostWithPassword(s, sec, HostAnswer::Ok, Channel::Clipboard, seen2); });
    expect(r.outcome == Outcome::Ok && seen2.macValid && !seen2.probe, "  next try authenticates with the password, no probe");
    tLastGate = Outcome::Network;
    setCurrent(nullptr);
    clearKnownModesForTest();
}

void r3Tests() {
    const Secret sec = makeSecret(kGood);

    // 1: a transition host turns on a password. Three channels reconnect at
    // once; each connection gets the challenge 200 ms late, after the
    // known-transition probe (100 ms on loopback) has left. Only the first
    // may probe; the others wait for its outcome and never probe.
    {
        clearKnownModesForTest();
        SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        bind(ls, reinterpret_cast<sockaddr*>(&a), sizeof(a));
        listen(ls, 8);
        int n = sizeof(a);
        getsockname(ls, reinterpret_cast<sockaddr*>(&a), &n);
        const std::string hostKey = "127.0.0.1:" + std::to_string(ntohs(a.sin_port));
        rememberMode(hostKey, HostMode::Transition);  // an earlier attempt saw open_ip_only
        std::atomic<int> probes{0}, proofs{0}, accepted{0};
        std::vector<std::thread> conns;
        std::mutex connsM;
        std::thread hostT([&] {
            // 3 channels + the one reconnect after a counted probe.
            for (int i = 0; i < 4; ++i) {
                fd_set rs; FD_ZERO(&rs); FD_SET(ls, &rs);
                timeval tv{3, 0};
                if (select(0, &rs, nullptr, nullptr, &tv) <= 0) break;
                SOCKET s = accept(ls, nullptr, nullptr);
                if (s == INVALID_SOCKET) break;
                ++accepted;
                std::lock_guard<std::mutex> g(connsM);
                conns.emplace_back([&, s] {
                    Sleep(200);
                    Seen seen;
                    // A PR-A host: a zero-MAC answer is a wrong try (4 left).
                    hostWithPassword(s, sec, HostAnswer::Ok, Channel::Clipboard, seen, 4);
                    if (seen.gotResponse && seen.probe) ++probes;
                    if (seen.gotResponse && seen.macValid) ++proofs;
                    shutdown(s, SD_SEND);
                    Sleep(200);
                    closesocket(s);
                });
            }
        });
        Logged log;
        Client::Options o;
        o.password = kGood;
        o.hostKey = hostKey;
        o.log = log.fn();
        auto c = std::make_shared<Client>(std::move(o));
        expect(c->mode() == Client::Mode::Transition, "known mode: new client starts as transition");
        setCurrent(c);
        Report out[3];
        auto channel = [&](int i) {
            for (int attempt = 0; attempt < 2; ++attempt) {
                auto slot = connectSlot();
                if (!mayConnect()) { out[i] = c->lastTerminal(); return; }
                SOCKET cs = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                const auto t0 = Clock::now();
                connect(cs, reinterpret_cast<sockaddr*>(&a), sizeof(a));
                out[i] = c->handshake(cs, Channel::Clipboard, msSince(t0));
                closesocket(cs);
                if (out[i].outcome != Outcome::Retry) return;
            }
        };
        std::thread t1(channel, 0), t2(channel, 1), t3(channel, 2);
        t1.join(); t2.join(); t3.join();
        hostT.join();
        {
            std::lock_guard<std::mutex> g(connsM);
            for (auto& t : conns) t.join();
        }
        setCurrent(nullptr);
        closesocket(ls);
        expect(probes.load() <= 1, "concurrent probes: host counted at most 1 probe for 3 channels (" +
                                       std::to_string(probes.load()) + ")");
        expect(out[0].outcome == Outcome::Ok && out[1].outcome == Outcome::Ok && out[2].outcome == Outcome::Ok,
               "  all three channels end authenticated");
        expect(proofs.load() == 3, "  each channel proved K once (" + std::to_string(proofs.load()) + " proofs, " +
                                       std::to_string(accepted.load()) + " connections)");
        expect(knownMode(hostKey) == HostMode::Password, "  host now known to want a password");

        // The next Connect on the same host (a new Client) does not probe.
        Logged log2;
        Client::Options o2;
        o2.password = kGood;
        o2.hostKey = hostKey;
        o2.log = log2.fn();
        auto c2 = std::make_shared<Client>(std::move(o2));
        expect(c2->mode() == Client::Mode::Password, "known mode: next Connect starts as password");
        FakeHost host;
        Seen seen;
        // (FakeHost listens on another port; the mode comes from the Client.)
        Report r = host.run(*c2, Channel::Ping, [&](SOCKET s) {
            Sleep(450);
            hostWithPassword(s, sec, HostAnswer::Ok, Channel::Ping, seen);
        });
        expect(r.outcome == Outcome::Ok && seen.macValid && !seen.probe && log2.count("auth.probe ") == 0,
               "  next Connect: no probe, authenticated");

        // Carried across a relaunch (password hosts only).
        rememberMode("10.0.0.5:7001", HostMode::Transition);
        const std::string enc = encodePasswordHosts();
        clearKnownModesForTest();
        loadPasswordHosts("x;y," + enc + ",bad host");
        expect(enc == hostKey && knownMode(hostKey) == HostMode::Password && knownMode("10.0.0.5:7001") == HostMode::Unknown,
               "  relaunch list: password hosts round trip (junk ignored)");
        clearKnownModesForTest();
    }

    // r4 (Pepper r3 review, item 1): a host known to want a password
    // whose challenge is late or lost. The mark stays, nothing probes and
    // nothing is sent (no try spent); only the user's "Retry without
    // password" (forgetPasswordMode) lets the next attempt probe.
    r4KnownPasswordTests();

    // 4: an old saved key failed (host distrusted); the user types the
    // right password with Remember: the mark goes once the mutual check
    // passed and DPAPI wrote the new key, so the next start uses it.
    {
        const std::wstring dir = tempStore(L"undistrust");
        removeStore(dir);
        clearDistrustedForTest();
        distrustHost(sec.hostId);
        FakeHost host;
        Logged log;
        auto c = makeClient(kGood, true, dir, log);
        Seen seen;
        Report r = host.run(*c, Channel::Control, [&](SOCKET s) { hostWithPassword(s, sec, HostAnswer::Ok, Channel::Control, seen); });
        HostKeyStore st(dir);
        expect(r.outcome == Outcome::Ok && st.exists(sec.hostId), "undistrust: right password saved");
        expect(!hostDistrusted(sec.hostId) && encodeDistrusted().empty() &&
                   log.containsText("auth.saved_key written=1 distrust=cleared"),
               "  mark lifted after mutual check + DPAPI write (not carried to a relaunch)");
        Logged log2;
        auto c2 = makeClient(L"", false, dir, log2);
        Seen seen2;
        r = host.run(*c2, Channel::Control, [&](SOCKET s) { hostWithPassword(s, sec, HostAnswer::Ok, Channel::Control, seen2); });
        expect(r.outcome == Outcome::Ok && seen2.macValid && !log2.containsText("saved_key_skipped"),
               "  next start: connects with the new saved key");
        removeStore(dir);

        // DPAPI write fails: the mark stays.
        distrustHost(sec.hostId);
        Logged log3;
        auto c3 = makeClient(kGood, true, dir + L"\bad?name", log3);
        Seen seen3;
        r = host.run(*c3, Channel::Control, [&](SOCKET s) { hostWithPassword(s, sec, HostAnswer::Ok, Channel::Control, seen3); });
        expect(r.outcome == Outcome::Ok && hostDistrusted(sec.hostId) && log3.containsText("auth.saved_key written=0"),
               "  save failed: mark kept");
        clearDistrustedForTest();
        removeStore(dir);
    }
}

// PR-C: seal and check, every drop case, the three session states, and
// the cost of one tag at 1200 bytes (the 4K60 numbers in the report).
void udpTagTests() {
    using namespace jl::udptag;
    SessionKey k{}, k2{};
    for (size_t i = 0; i < k.size(); ++i) { k[i] = uint8_t(i + 1); k2[i] = uint8_t(0xA0 + i); }
    Tagger hv(k, true), vh(k, false), hvOld(k2, true);
    expect(hv.ok() && vh.ok() && hvOld.ok(), "udp: CNG reusable HMAC taggers set up");
    // A 30-byte MR02-like datagram from the host.
    uint8_t pkt[30];
    std::memcpy(pkt, "MR02", 4);
    pkt[4] = 2;
    for (int i = 5; i < 30; ++i) pkt[i] = uint8_t(i * 7);
    uint8_t sealed[64];
    const size_t n = hv.seal(pkt, sizeof(pkt), sealed);
    expect(n == sizeof(pkt) + kTagBytes && (sealed[4] & kFlag), "udp: seal sets the flag and appends 8 bytes");
    expect(hv.verify(sealed, n), "udp: a sealed datagram verifies");
    {
        auto t = udpTag(k, true, sealed, sizeof(pkt));
        expect(t && std::memcmp(t->data(), sealed + sizeof(pkt), kTagBytes) == 0, "udp: seal's tag is udp_tag of the flagged bytes");
    }
    auto bad = [&](const char* what, auto mutate, const Tagger& t) {
        uint8_t c[64];
        std::memcpy(c, sealed, n);
        size_t m = n;
        mutate(c, m);
        expect(!t.verify(c, m), std::string("udp: dropped: ") + what);
    };
    bad("no tag", [&](uint8_t* c, size_t& m) { std::memcpy(c, pkt, sizeof(pkt)); m = sizeof(pkt); }, hv);
    bad("zero tag", [&](uint8_t* c, size_t& m) { std::memset(c + m - 8, 0, 8); }, hv);
    bad("wrong tag", [&](uint8_t* c, size_t& m) { c[m - 1] ^= 1; }, hv);
    bad("payload changed", [&](uint8_t* c, size_t&) { c[12] ^= 0x40; }, hv);
    bad("flag cleared", [&](uint8_t* c, size_t&) { c[4] &= 0x7F; }, hv);
    bad("truncated", [&](uint8_t* c, size_t& m) { m -= 1; }, hv);
    bad("too short", [&](uint8_t*, size_t& m) { m = 10; }, hv);
    bad("old session key", [](uint8_t*, size_t&) {}, hvOld);
    bad("reflected direction (h2v checked as v2h)", [](uint8_t*, size_t&) {}, vh);

    // States as the viewer sees them.
    View view;
    auto openCopy = [&](const uint8_t* src, size_t len, int& outLen) {
        static uint8_t c[64];
        std::memcpy(c, src, len);
        outLen = int(len);
        return view.open(c, outLen);
    };
    int len = 0;
    publishOpen();
    expect(openCopy(pkt, sizeof(pkt), len) == Verdict::Ok && len == int(sizeof(pkt)), "udp: open mode takes untagged (0.3 behaviour)");
    expect(openCopy(sealed, n, len) == Verdict::TaggedInOpen, "udp: open mode drops a tagged datagram");
    publishPending();
    expect(openCopy(pkt, sizeof(pkt), len) == Verdict::Pending && openCopy(sealed, n, len) == Verdict::Pending,
           "udp: pending (password host, no control session yet) drops everything");
    expect(publishKey(k), "udp: key published");
    expect(openCopy(sealed, n, len) == Verdict::Ok && len == int(sizeof(pkt)), "udp: keyed takes a good tag, strips it");
    {
        uint8_t c[64];
        std::memcpy(c, sealed, n);
        int l = int(n);
        expect(view.open(c, l) == Verdict::Ok && c[4] == 2 && std::memcmp(c, pkt, sizeof(pkt)) == 0,
               "udp: after open the parser sees the 0.3 datagram (flag cleared)");
    }
    expect(openCopy(pkt, sizeof(pkt), len) == Verdict::NoTag, "udp: keyed drops untagged");
    {
        uint8_t c[64];
        const size_t m = hvOld.seal(pkt, sizeof(pkt), c);
        int l = int(m);
        expect(view.open(c, l) == Verdict::BadTag, "udp: keyed drops an old session's tag");
    }
    // Send side: sealed v2h, the host's view of it verifies, h2v does not.
    uint8_t out[64];
    int outLen = 0;
    const uint8_t mouse[14] = {'M', 'R', 'M', '1', 1, 0x24, 0, 0, 0, 1, 0x10, 0, 0x20, 0};
    const int r = view.send(mouse, sizeof(mouse), [&](const uint8_t* b, int l) { std::memcpy(out, b, size_t(l)); outLen = l; return l; });
    expect(r == int(sizeof(mouse)) && outLen == int(sizeof(mouse) + kTagBytes) && vh.verify(out, size_t(outLen)) &&
               !hv.verify(out, size_t(outLen)),
           "udp: keyed send is sealed v2h (not valid as h2v)");
    // A new control session: the old key stops working at once.
    expect(publishKey(k2), "udp: new session key published");
    expect(openCopy(sealed, n, len) == Verdict::BadTag, "udp: after a reconnect the old key's datagrams are dropped");
    publishOpen();
    outLen = 0;
    view.send(mouse, sizeof(mouse), [&](const uint8_t* b, int l) { std::memcpy(out, b, size_t(l)); outLen = l; return l; });
    expect(outLen == int(sizeof(mouse)) && std::memcmp(out, mouse, sizeof(mouse)) == 0, "udp: open mode sends untagged");

    // Drop log: one line per 10 s.
    DropLog dl;
    int lines = 0;
    for (int i = 0; i < 500; ++i) dl.note("mr02", Verdict::BadTag, [&](const std::string&) { ++lines; });
    expect(lines == 1 && dl.total() == 500, "udp: 500 drops log one line");

    // Cost at 1200 bytes (MR02 packet), for the 4K60 numbers.
    uint8_t big[1200];
    for (size_t i = 0; i < sizeof(big); ++i) big[i] = uint8_t(i);
    std::memcpy(big, "MR02", 4);
    uint8_t bigSealed[1208];
    const size_t bn = hv.seal(big, sizeof(big), bigSealed);
    const int iters = 200000;
    auto t0 = Clock::now();
    bool allOk = true;
    for (int i = 0; i < iters; ++i) allOk &= hv.verify(bigSealed, bn);
    const double verifyNs = std::chrono::duration<double, std::nano>(Clock::now() - t0).count() / iters;
    t0 = Clock::now();
    for (int i = 0; i < iters; ++i) vh.seal(big, sizeof(big), bigSealed);
    const double sealNs = std::chrono::duration<double, std::nano>(Clock::now() - t0).count() / iters;
    expect(allOk, "udp: bench verifies every time");
    std::printf("BENCH udp_tag verify_1208B_ns=%.0f seal_1200B_ns=%.0f\n", verifyNs, sealNs);
    for (int mbps : {50, 80, 150}) {
        const double pps = mbps * 1e6 / 8.0 / 1180.0;
        std::printf("BENCH udp_tag 4k60 mbps=%d pps=%.0f core_pct=%.2f us_per_frame=%.0f\n", mbps, pps,
                    pps * verifyNs / 1e9 * 100.0, pps / 60.0 * verifyNs / 1000.0);
    }
    publishOpen();
}

}  // namespace

int main(int argc, char** argv) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    if (argc < 2) {
        std::printf("FAIL usage: JerislinkConnAuthTest <auth_vectors.json>\n");
        return 2;
    }
    vectorTests(argv[1]);
    wireTests();
    dpapiTests();
    passwordHostTests();
    oldAndTransitionTests();
    reviewFixTests();
    r3Tests();
    r5BackgroundNoChallengeTests();
    udpTagTests();
    WSACleanup();
    std::printf("%d passed, %d failed\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
