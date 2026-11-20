// Control channel reconnect off the UI thread (control_channel.hpp): while
// the connection and its connection password are re-made, sendKey and the
// mouse calls return at once (the UI thread also presents video), events
// wait in order and go out once connected, and an answer that ends the
// attempt (Locked) reaches the viewer from the background thread.
// r3: stop() cancels a reconnect in progress and joins the worker; input
// queued before focus left is discarded; a queued click carries its pointer
// position.
//
// A loopback fake host with a password. Its challenge comes 600 ms late once
// the viewer knows the Mac wants a password (no probe then); the first
// connection answers after 150 ms, before the transition probe would go.
#include "control_channel.hpp"

#include <atomic>
#include <cstdio>
#include <memory>
#include <string>
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

constexpr int kSlowAuthMs = 600;
constexpr int kFirstAuthMs = 150;
constexpr double kUiBudgetMs = 50.0;  // a UI-thread call never waits longer
const wchar_t* kPw = L"reconnect-test-1";

struct Secret {
    Key key;
    Salt salt{};
    HostId hostId{};
    uint32_t iter = kMinIterations;
};

Bytes challengeFor(const Secret& sec, std::array<uint8_t, kNonceBytes>& hn) {
    randomBytes(hn.data(), hn.size());
    Bytes p(hn.begin(), hn.end());
    p.insert(p.end(), sec.salt.begin(), sec.salt.end());
    p.insert(p.end(), {uint8_t(sec.iter >> 24), uint8_t(sec.iter >> 16), uint8_t(sec.iter >> 8), uint8_t(sec.iter)});
    p.push_back(kKdfPbkdf2Sha256);
    p.insert(p.end(), sec.hostId.begin(), sec.hostId.end());
    return p;
}

enum class Answer { Ok, Locked };

// One host-side connection: slow challenge, check the proof, answer.
bool hostAuth(SOCKET s, const Secret& sec, Answer ans, int delayMs = kSlowAuthMs) {
    Sleep(DWORD(delayMs));
    std::array<uint8_t, kNonceBytes> hn{};
    const Bytes ch = challengeFor(sec, hn);
    if (!sendAllBytes(s, frame(kTypeChallenge, ch.data(), ch.size()))) return false;
    uint8_t type = 0;
    Bytes p;
    if (recvFrame(s, Clock::now() + std::chrono::seconds(10), type, p) != Io::Ok ||
        type != kTypeResponse || p.size() != kResponseBytes) return false;
    auto want = macClient(sec.key, hn.data(), p.data(), Channel::Control, sec.hostId.data());
    if (!want || !constantTimeEqual(want->data(), p.data() + kNonceBytes, kMacBytes)) return false;
    Bytes res;
    if (ans == Answer::Locked) {
        res = {2, 0, 0, 0, 90};
    } else {
        auto mh = *macHost(sec.key, hn.data(), p.data(), Channel::Control);
        res.push_back(0);
        res.insert(res.end(), mh.begin(), mh.end());
        res.insert(res.end(), {1, 2, 3, 4, 5, 6, 7, 8});
    }
    if (!sendAllBytes(s, frame(kTypeResult, res.data(), res.size()))) return false;
    return ans == Answer::Ok;
}

struct Listener {
    SOCKET ls = INVALID_SOCKET;
    uint16_t port = 0;
    Listener() {
        ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        bind(ls, reinterpret_cast<sockaddr*>(&a), sizeof(a));
        listen(ls, 4);
        int n = sizeof(a);
        getsockname(ls, reinterpret_cast<sockaddr*>(&a), &n);
        port = ntohs(a.sin_port);
    }
    ~Listener() { closesocket(ls); }
    SOCKET accept(int timeoutMs) {
        fd_set rs; FD_ZERO(&rs); FD_SET(ls, &rs);
        timeval tv{timeoutMs / 1000, (timeoutMs % 1000) * 1000};
        if (select(0, &rs, nullptr, nullptr, &tv) <= 0) return INVALID_SOCKET;
        return ::accept(ls, nullptr, nullptr);
    }
};

// Reads control frames (type + payload) until `n` arrived or the deadline.
std::vector<std::pair<uint8_t, Bytes>> readFrames(SOCKET s, size_t n, int ms) {
    std::vector<std::pair<uint8_t, Bytes>> out;
    const auto deadline = Clock::now() + std::chrono::milliseconds(ms);
    while (out.size() < n) {
        uint8_t type = 0;
        Bytes p;
        if (recvFrame(s, deadline, type, p) != Io::Ok) break;
        out.emplace_back(type, std::move(p));
    }
    return out;
}

struct UiClock {
    double maxMs = 0.0;
    template <typename F> bool call(F f) {
        const auto t0 = Clock::now();
        const bool r = f();
        maxMs = std::max(maxMs, msSince(t0));
        return r;
    }
};

std::shared_ptr<Client> makeClient(std::atomic<int>& terminals, std::atomic<int>& lastOutcome,
                                   const std::string& hostKey = "") {
    Client::Options o;
    o.hostKey = hostKey;
    o.password = kPw;
    o.remember = false;
    o.storeDir = L"";
    {
        wchar_t base[MAX_PATH]{};
        GetTempPathW(MAX_PATH, base);
        o.storeDir = std::wstring(base) + L"jl-reconnect-test";
    }
    auto c = std::make_shared<Client>(std::move(o));
    c->setTerminalHandler([&](const Report& r) { ++terminals; lastOutcome = int(r.outcome); });
    return c;
}

void reconnectTests() {
    Secret sec;
    randomBytes(sec.salt.data(), sec.salt.size());
    randomBytes(sec.hostId.data(), sec.hostId.size());
    sec.key = *deriveKey(kPw, sec.salt.data(), sec.salt.size(), sec.iter);

    std::atomic<int> terminals{0};
    std::atomic<int> lastOutcome{-1};
    auto client = makeClient(terminals, lastOutcome);
    setCurrent(client);

    Listener l;
    ControlChannel control("127.0.0.1", "127.0.0.1", l.port);
    control.setIoTimeoutMs(100);
    control.setBackgroundReconnect(true);

    // 1. Not connected yet: the first events start a reconnect whose AUTH
    // takes > 150 ms plus PBKDF2 (600k iterations). The calls return at once.
    std::vector<std::pair<uint8_t, Bytes>> got1;
    bool auth1 = false;
    SOCKET hs1 = INVALID_SOCKET;
    std::thread host1([&] {
        hs1 = l.accept(5000);
        if (hs1 == INVALID_SOCKET) return;
        auth1 = hostAuth(hs1, sec, Answer::Ok, kFirstAuthMs);
        if (auth1) got1 = readFrames(hs1, 3, 8000);
    });
    UiClock ui;
    ui.call([&] { return control.sendKey(true, 0x0041); });
    for (uint16_t x = 100; x <= 500; x += 100) {
        ui.call([&] { return control.sendMouseMoveAbsolute(x, 200); });
        Sleep(5);
    }
    ui.call([&] { return control.sendKey(false, 0x0041); });
    expect(ui.maxMs < kUiBudgetMs, "reconnect in background: UI calls return at once (max " + std::to_string(int(ui.maxMs)) + " ms)");
    expect(control.reconnectStats().connecting, "  reconnect running on its own thread");
    host1.join();
    expect(auth1, "  background reconnect passed the connection password");
    expect(got1.size() == 3 && got1[0].first == 0x10 && got1[0].second.size() == 3 && got1[0].second[0] == 1,
           "  queued key down delivered first");
    expect(got1.size() == 3 && got1[1].first == 0x23 && got1[1].second.size() == 4 && got1[1].second[0] == 0x01 &&
               got1[1].second[1] == 0xF4,
           "  pointer moves coalesced to the latest (x=500)");
    expect(got1.size() == 3 && got1[2].first == 0x10 && got1[2].second[0] == 0, "  key up delivered last, in order");
    auto st = control.reconnectStats();
    expect(st.reconnects == 1 && st.flushed == 3 && st.dropped == 0, "  stats: 1 reconnect, 3 flushed, 0 dropped");
    // Connected: an event goes straight out.
    ui.maxMs = 0;
    ui.call([&] { return control.sendKey(true, 0x0042); });
    auto direct = readFrames(hs1, 1, 2000);
    expect(direct.size() == 1 && direct[0].first == 0x10 && ui.maxMs < kUiBudgetMs, "connected: sent at once");

    // 2. The host drops the connection mid-session. Input keeps flowing every
    // 16 ms (one frame) while the reconnect runs; no call stalls.
    std::atomic<bool> got2{false};
    bool auth2 = false;
    std::thread host2([&] {
        SOCKET s = l.accept(5000);
        if (s == INVALID_SOCKET) return;
        auth2 = hostAuth(s, sec, Answer::Ok);
        if (auth2 && !readFrames(s, 1, 4000).empty()) got2 = true;
        Sleep(100);
        closesocket(s);
    });
    shutdown(hs1, SD_BOTH);
    closesocket(hs1);
    ui.maxMs = 0;
    int calls = 0;
    const auto t0 = Clock::now();
    while (!got2 && msSince(t0) < 6000) {
        ui.call([&] { return control.sendMouseMoveAbsolute(uint16_t(calls % 1000), 300); });
        ++calls;
        Sleep(16);
    }
    host2.join();
    expect(auth2 && got2, "disconnect: reconnected in the background and input arrives again");
    expect(ui.maxMs < kUiBudgetMs, "disconnect: no UI call stalled during the reconnect (max " + std::to_string(int(ui.maxMs)) +
                                       " ms over " + std::to_string(calls) + " calls)");
    expect(control.reconnectStats().reconnects == 2, "  stats: 2 reconnects");

    // 3. The next reconnect is answered Locked (a background channel hits
    // the lockout): the viewer is told from that thread, the queue is
    // dropped, and later calls return false at once without connecting.
    bool lockedSent = false;
    std::thread host3([&] {
        SOCKET s = l.accept(5000);
        if (s == INVALID_SOCKET) return;
        hostAuth(s, sec, Answer::Locked);
        lockedSent = true;
        Sleep(200);
        closesocket(s);
    });
    // Our end of the last connection is gone too (host2 closed it).
    ui.maxMs = 0;
    const auto t1 = Clock::now();
    while (terminals.load() == 0 && msSince(t1) < 6000) {
        ui.call([&] { return control.sendKey(true, 0x0043); });
        Sleep(16);
    }
    host3.join();
    expect(lockedSent && terminals.load() == 1 && lastOutcome.load() == int(Outcome::Locked),
           "locked via background channel: viewer told once (Locked)");
    expect(client->lastTerminal().retrySeconds == 90, "  deadline kept for the launch screen (90 s)");
    expect(ui.maxMs < kUiBudgetMs, "  no UI call stalled (max " + std::to_string(int(ui.maxMs)) + " ms)");
    Sleep(100);
    ui.maxMs = 0;
    const bool sent = ui.call([&] { return control.sendKey(false, 0x0043); });
    expect(!sent && ui.maxMs < kUiBudgetMs && !mayConnect(), "  after the lockout: calls fail fast, no new connection");
    expect(l.accept(300) == INVALID_SOCKET, "  no further connection attempt");
    setCurrent(nullptr);
}

// Pepper's PR-B review r2, blocker 2: closing the session while a
// reconnect runs. The host accepts and never answers; stop() must cut the
// attempt short and join the worker (no thread left using a socket).
void stopTests() {
    std::atomic<int> terminals{0};
    std::atomic<int> lastOutcome{-1};
    // A host known to need a password: the worker waits the full 2 s for a
    // challenge, so only the cancel flag can end that wait early.
    jl::auth::rememberMode("127.0.0.1:stop", jl::auth::HostMode::Password);
    auto client = makeClient(terminals, lastOutcome, "127.0.0.1:stop");
    setCurrent(client);
    Listener l;
    auto control = std::make_unique<ControlChannel>("127.0.0.1", "127.0.0.1", l.port);
    control->setIoTimeoutMs(3000);
    control->setBackgroundReconnect(true);
    std::atomic<bool> accepted{false};
    std::thread host([&] {
        SOCKET s = l.accept(3000);
        if (s == INVALID_SOCKET) return;
        accepted = true;
        Sleep(2500);  // silent host
        closesocket(s);
    });
    UiClock ui;
    ui.call([&] { return control->sendKey(true, 0x0041); });
    for (int i = 0; i < 50 && !accepted; ++i) Sleep(10);
    Sleep(100);
    expect(accepted && control->reconnectStats().connecting, "stop: a reconnect is running (host silent)");
    const double joinMs = control->stop();
    const auto st = control->reconnectStats();
    expect(joinMs >= 0.0 && st.joined, "stop: worker joined (" + std::to_string(int(joinMs)) + " ms)");
    expect(joinMs < 1000.0, "  join did not wait for the challenge timeout (host known to need a password)");
    expect(st.reconnects == 0 && !st.connecting, "  attempt cancelled, nothing connected");
    const bool sent = ui.call([&] { return control->sendKey(false, 0x0041); });
    expect(!sent && ui.maxMs < kUiBudgetMs, "  after stop: calls fail fast");
    control.reset();  // destructor after stop(): no second join, no crash
    expect(l.accept(300) == INVALID_SOCKET, "  no further connection attempt");
    host.join();
    // Destroyed without stop() while a reconnect runs: the destructor joins.
    auto c2 = std::make_unique<ControlChannel>("127.0.0.1", "127.0.0.1", l.port);
    c2->setIoTimeoutMs(3000);
    c2->setBackgroundReconnect(true);
    std::thread host2([&] {
        SOCKET s = l.accept(3000);
        if (s == INVALID_SOCKET) return;
        Sleep(2500);
        closesocket(s);
    });
    c2->sendKey(true, 0x0041);
    Sleep(150);
    const auto t0 = Clock::now();
    c2.reset();
    expect(msSince(t0) < 1000.0, "destructor during a reconnect: joined (" + std::to_string(int(msSince(t0))) + " ms)");
    host2.join();
    setCurrent(nullptr);
    jl::auth::clearKnownModesForTest();
}

// Blocker 3: stale input. Keys and clicks queued before the viewer lost
// focus never reach the Mac; a queued click goes out with its position.
void staleInputTests() {
    Secret sec;
    randomBytes(sec.salt.data(), sec.salt.size());
    randomBytes(sec.hostId.data(), sec.hostId.size());
    sec.key = *deriveKey(kPw, sec.salt.data(), sec.salt.size(), sec.iter);
    std::atomic<int> terminals{0};
    std::atomic<int> lastOutcome{-1};
    auto client = makeClient(terminals, lastOutcome);
    setCurrent(client);
    Listener l;
    ControlChannel control("127.0.0.1", "127.0.0.1", l.port);
    control.setIoTimeoutMs(100);
    control.setBackgroundReconnect(true);

    SOCKET hs = INVALID_SOCKET;
    bool auth1 = false;
    std::vector<std::pair<uint8_t, Bytes>> early;
    std::thread host1([&] {
        hs = l.accept(5000);
        if (hs == INVALID_SOCKET) return;
        auth1 = hostAuth(hs, sec, Answer::Ok, kFirstAuthMs);
        if (auth1) early = readFrames(hs, 1, 800);
    });
    control.sendKey(true, 0x0041);
    control.sendMouseButtonExtended(0, true, 1);
    const size_t dropped = control.discardQueuedInput();  // WM_KILLFOCUS
    host1.join();
    expect(auth1 && dropped == 2, "focus lost: 2 queued events discarded");
    expect(early.empty(), "  nothing replayed after the reconnect");
    for (int i = 0; i < 100 && control.reconnectStats().reconnects == 0; ++i) Sleep(10);
    expect(control.reconnectStats().discarded == 2 && control.reconnectStats().reconnects == 1, "  stats: discarded=2, reconnected");
    control.sendKey(true, 0x0042);
    auto fresh = readFrames(hs, 1, 2000);
    expect(fresh.size() == 1 && fresh[0].first == 0x10 && fresh[0].second[2] == 0x42, "  new input after focus returns goes out");

    // Click queued during a reconnect: its position (sent by UDP in the
    // viewer) is queued right in front of it.
    control.notePointer(0x1234, 0xABCD);
    control.close();
    shutdown(hs, SD_BOTH);
    closesocket(hs);
    std::vector<std::pair<uint8_t, Bytes>> got;
    bool auth2 = false;
    std::thread host2([&] {
        SOCKET s = l.accept(5000);
        if (s == INVALID_SOCKET) return;
        auth2 = hostAuth(s, sec, Answer::Ok, kFirstAuthMs);
        if (auth2) got = readFrames(s, 4, 3000);
        Sleep(100);
        closesocket(s);
    });
    control.sendMouseButtonExtended(0, true, 1);
    control.sendMouseButtonExtended(0, false, 1);
    host2.join();
    const Bytes pos{0x12, 0x34, 0xAB, 0xCD};
    expect(auth2 && got.size() == 4 && got[0].first == 0x24 && got[0].second == pos && got[1].first == 0x25 &&
               got[1].second[1] == 1 && got[2].first == 0x24 && got[3].first == 0x25 && got[3].second[1] == 0,
           "queued click: position, down, position, up (" + std::to_string(got.size()) + " frames)");
    expect(control.reconnectStats().positioned == 2, "  stats: positioned=2");
    control.stop();
    setCurrent(nullptr);
}

}  // namespace

int main() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    reconnectTests();
    stopTests();
    staleInputTests();
    WSACleanup();
    std::printf("%d passed, %d failed\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
