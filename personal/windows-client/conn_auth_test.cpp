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
    }
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

    // A late challenge crosses the probe: drop, reconnect without a probe.
    {
        const Secret sec = makeSecret(kGood);
        Logged log;
        auto c = makeClient(kGood, false, L"", log);
        Report r = host.run(*c, Channel::Control, [&](SOCKET s) {
            Sleep(450);
            std::array<uint8_t, kNonceBytes> hn{};
            hostSend(s, kTypeChallenge, challengeFor(sec, hn));
            uint8_t type = 0;
            Bytes p;
            hostRecv(s, 1500, type, p);  // the probe
        });
        expect(r.outcome == Outcome::Retry, "probe race: retry");
        expect(!c->halted() && c->mode() == Client::Mode::Password, "probe race: not halted, host known to want a password");
        Seen seen;
        r = host.run(*c, Channel::Control, [&](SOCKET s) {
            Sleep(450);  // still slow, but a password host is not probed again
            hostWithPassword(s, sec, HostAnswer::Ok, Channel::Control, seen);
        });
        expect(r.outcome == Outcome::Ok && seen.macValid, "probe race: reconnect authenticates without a probe");
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
    WSACleanup();
    std::printf("%d passed, %d failed\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
