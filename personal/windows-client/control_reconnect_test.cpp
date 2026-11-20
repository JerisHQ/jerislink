// Control channel reconnect off the UI thread (control_channel.hpp): while
// the connection and its connection password are re-made, sendKey and the
// mouse calls return at once (the UI thread also presents video), events
// wait in order and go out once connected, and an answer that ends the
// attempt (Locked) reaches the viewer from the background thread.
// r3: stop() cancels a reconnect in progress and joins the worker; input
// queued before focus left is discarded; a queued click carries its pointer
// position.
// r4: focus loss also cancels an event the worker already took from the
// queue but has not sent; a click and its position are one queue item
// (pushed out of a full queue and aged out together).
// r5: the generation check and the start of the send are one step under the
// lock focus loss takes (the socket is non-blocking while flushing); a
// background NoChallenge on control is retried with backoff, never probing,
// and never ends the session.
// r6: a key or button whose down reached the Mac is released on focus loss
// (at once when live, else first after the reconnect), and its later up is
// not sent twice; a down that never went out (dropped from the queue, or
// its send failed) is dropped with its up. Once the retries ran out only a
// fresh key press starts a new round (pointer moves and auto-repeat do not).
// r7: input dropped unsent on any path (aged out, full queue, paused, a
// flush that failed before any byte went out) keeps downs and ups paired on
// the Mac; a button up not sent again takes its queued position along.
//
// A loopback fake host with a password. Its challenge comes 600 ms late once
// the viewer knows the Mac wants a password (no probe then); the first
// connection answers after 150 ms, before the transition probe would go.
#include "control_channel.hpp"

#include <atomic>
#include <cstdio>
#include <memory>
#include <set>
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

// Pepper's r3 review, item 2.
void r4InputTests() {
    Secret sec;
    randomBytes(sec.salt.data(), sec.salt.size());
    randomBytes(sec.hostId.data(), sec.hostId.size());
    sec.key = *deriveKey(kPw, sec.salt.data(), sec.salt.size(), sec.iter);
    std::atomic<int> terminals{0};
    std::atomic<int> lastOutcome{-1};
    auto client = makeClient(terminals, lastOutcome);
    setCurrent(client);
    Listener l;

    // (a) In flight: the worker has taken key A down from the queue (held
    // in the test hook) when focus leaves. Neither it nor key A up reaches
    // the Mac.
    {
        ControlChannel control("127.0.0.1", "127.0.0.1", l.port);
        control.setIoTimeoutMs(100);
        control.setBackgroundReconnect(true);
        std::atomic<bool> entered{false}, release{false};
        control.setBeforeFlushSendForTest([&] {
            entered = true;
            for (int i = 0; i < 400 && !release; ++i) Sleep(5);
        });
        SOCKET hs = INVALID_SOCKET;
        bool auth = false;
        std::vector<std::pair<uint8_t, Bytes>> got;
        std::thread host([&] {
            hs = l.accept(5000);
            if (hs == INVALID_SOCKET) return;
            auth = hostAuth(hs, sec, Answer::Ok, kFirstAuthMs);
            if (auth) got = readFrames(hs, 1, 1500);
        });
        control.sendKey(true, 0x0041);
        control.sendKey(false, 0x0041);
        for (int i = 0; i < 600 && !entered; ++i) Sleep(5);
        const size_t queued = control.discardQueuedInput();  // WM_KILLFOCUS while key A down is in flight
        release = true;
        host.join();
        for (int i = 0; i < 100 && control.reconnectStats().reconnects == 0; ++i) Sleep(10);
        const auto st = control.reconnectStats();
        expect(entered && auth && queued == 1, "r4 in flight: worker held key A down when focus left (1 more queued)");
        expect(got.empty(), "  nothing reached the Mac (" + std::to_string(got.size()) + " frames)");
        expect(st.discarded == 2 && st.flushed == 0 && st.reconnects == 1, "  stats: discarded=2 (1 in flight), flushed=0");
        control.setBeforeFlushSendForTest(nullptr);
        control.sendKey(true, 0x0042);
        auto fresh = readFrames(hs, 1, 2000);
        expect(fresh.size() == 1 && fresh[0].second[2] == 0x42, "  new input after focus returns goes out");
        control.stop();
        closesocket(hs);
    }

    // (b) Full queue: a queued click with its position is at the front when
    // the queue overflows. Both go; no lone click and no lone position.
    {
        ControlChannel control("127.0.0.1", "127.0.0.1", l.port);
        control.setIoTimeoutMs(100);
        control.setBackgroundReconnect(true);
        std::atomic<bool> release{false};
        control.setBeforeFlushSendForTest([&] { for (int i = 0; i < 400 && !release; ++i) Sleep(5); });
        std::vector<std::pair<uint8_t, Bytes>> got;
        bool auth = false;
        std::thread host([&] {
            SOCKET s = l.accept(5000);
            if (s == INVALID_SOCKET) return;
            auth = hostAuth(s, sec, Answer::Ok, kFirstAuthMs);
            if (auth) got = readFrames(s, ControlChannel::kQueueMax + 2, 4000);
            Sleep(100);
            closesocket(s);
        });
        control.notePointer(0x1111, 0x2222);
        control.sendMouseButtonExtended(0, true, 1);  // one item: 0x24 + 0x25
        for (size_t i = 0; i < ControlChannel::kQueueMax; ++i) control.sendKey(i % 2 == 0, 0x0041);
        release = true;
        host.join();
        size_t keys = 0, pointer = 0;
        for (auto& f : got) {
            if (f.first == 0x10) ++keys;
            if (f.first == 0x24 || f.first == 0x25) ++pointer;
        }
        const auto st = control.reconnectStats();
        expect(auth && keys == ControlChannel::kQueueMax && pointer == 0,
               "r4 full queue: click and its position pushed out together (" + std::to_string(keys) + " keys, " +
                   std::to_string(pointer) + " pointer frames)");
        expect(st.positioned == 1 && st.dropped == 1 && st.flushed == ControlChannel::kQueueMax,
               "  stats: positioned=1, dropped=1 item, flushed=" + std::to_string(st.flushed));
        control.stop();
    }

    // (c) Too old: the click and its position age out as one item, behind
    // a key the worker holds past kQueueMaxAgeMs.
    {
        ControlChannel control("127.0.0.1", "127.0.0.1", l.port);
        control.setIoTimeoutMs(100);
        control.setBackgroundReconnect(true);
        std::atomic<int> calls{0};
        control.setBeforeFlushSendForTest([&] {
            if (calls++ == 0) Sleep(DWORD(ControlChannel::kQueueMaxAgeMs + 300));
        });
        std::vector<std::pair<uint8_t, Bytes>> got;
        bool auth = false;
        std::thread host([&] {
            SOCKET s = l.accept(5000);
            if (s == INVALID_SOCKET) return;
            auth = hostAuth(s, sec, Answer::Ok, kFirstAuthMs);
            if (auth) got = readFrames(s, 3, ControlChannel::kQueueMaxAgeMs + 2500);
            Sleep(100);
            closesocket(s);
        });
        control.notePointer(0x3333, 0x4444);
        control.sendKey(true, 0x0041);
        control.sendMouseButtonExtended(0, true, 1);
        host.join();
        const auto st = control.reconnectStats();
        expect(auth && got.size() == 1 && got[0].first == 0x10,
               "r4 too old: click and its position aged out together (" + std::to_string(got.size()) + " frames)");
        expect(st.dropped == 1 && st.flushed == 1, "  stats: dropped=1 item, flushed=1");
        control.stop();
    }
    setCurrent(nullptr);
}

// A host connection that sends no challenge for `ms` (then a late one),
// watching for anything the viewer sends (a probe or an answer).
bool silentConn(SOCKET s, const Secret& sec, int ms) {
    uint8_t type = 0;
    Bytes p;
    const Io io = recvFrame(s, Clock::now() + std::chrono::milliseconds(ms), type, p);
    if (io == Io::Ok) return true;
    std::array<uint8_t, kNonceBytes> hn{};
    const Bytes ch = challengeFor(sec, hn);
    sendAllBytes(s, frame(kTypeChallenge, ch.data(), ch.size()));
    return recvFrame(s, Clock::now() + std::chrono::milliseconds(300), type, p) == Io::Ok;
}

// Pepper's r4 review: item 1 (focus loss between check and send) and item 2
// (background NoChallenge on control).
void r5Tests() {
    Secret sec;
    randomBytes(sec.salt.data(), sec.salt.size());
    randomBytes(sec.hostId.data(), sec.hostId.size());
    sec.key = *deriveKey(kPw, sec.salt.data(), sec.salt.size(), sec.iter);
    std::atomic<int> terminals{0};
    std::atomic<int> lastOutcome{-1};
    auto client = makeClient(terminals, lastOutcome);
    setCurrent(client);
    Listener l;

    // (d) The gap between the check and the send: the worker took key A
    // down, the generation matched, and the send found no room (nothing
    // written). Focus leaves exactly then, while the worker waits without
    // the lock. Before the next send the check runs again: nothing goes.
    {
        ControlChannel control("127.0.0.1", "127.0.0.1", l.port);
        control.setIoTimeoutMs(100);
        control.setBackgroundReconnect(true);
        std::atomic<int> gaps{0};
        size_t queued = 99;
        control.setFlushWouldBlockForTest(1, [&] {
            ++gaps;
            queued = control.discardQueuedInput();  // WM_KILLFOCUS in the gap
        });
        SOCKET hs = INVALID_SOCKET;
        bool auth = false;
        std::vector<std::pair<uint8_t, Bytes>> got;
        std::thread host([&] {
            hs = l.accept(5000);
            if (hs == INVALID_SOCKET) return;
            auth = hostAuth(hs, sec, Answer::Ok, kFirstAuthMs);
            if (auth) got = readFrames(hs, 1, 1500);
        });
        control.sendKey(true, 0x0041);
        control.sendKey(false, 0x0041);
        host.join();
        for (int i = 0; i < 100 && control.reconnectStats().reconnects == 0; ++i) Sleep(10);
        const auto st = control.reconnectStats();
        expect(auth && gaps == 1 && queued == 1, "r5 gap: focus left while key A down waited for room (1 more queued)");
        expect(got.empty(), "  nothing reached the Mac (" + std::to_string(got.size()) + " frames)");
        expect(st.discarded == 2 && st.flushed == 0 && st.flushWaits == 1,
               "  stats: discarded=2 (1 rechecked after the gap), flushed=0, flushWaits=1");
        control.sendKey(true, 0x0042);
        auto fresh = readFrames(hs, 1, 2000);
        expect(fresh.size() == 1 && fresh[0].second[2] == 0x42, "  new input after focus returns goes out (blocking again)");
        control.stop();
        closesocket(hs);
    }

    // (e) The commit point: the check passed and send() is next, under the
    // lock. Focus loss now waits for that send (it cannot slip in between),
    // then drops what is still queued. r6: key A down did reach the Mac, so
    // A is released: the Mac gets a pair, never a held key.
    {
        ControlChannel control("127.0.0.1", "127.0.0.1", l.port);
        control.setIoTimeoutMs(100);
        control.setBackgroundReconnect(true);
        std::atomic<int> commits{0};
        std::atomic<bool> discardDone{false};
        std::atomic<bool> blockedAtCommit{false};
        std::atomic<size_t> queued{99};
        std::thread focus;
        control.setAtCommitForTest([&] {
            if (commits++ != 0) return;
            focus = std::thread([&] { queued = control.discardQueuedInput(); discardDone = true; });
            Sleep(150);
            blockedAtCommit = !discardDone;  // still waiting for the lock
        });
        SOCKET hs = INVALID_SOCKET;
        bool auth = false;
        std::vector<std::pair<uint8_t, Bytes>> got;
        std::thread host([&] {
            hs = l.accept(5000);
            if (hs == INVALID_SOCKET) return;
            auth = hostAuth(hs, sec, Answer::Ok, kFirstAuthMs);
            if (auth) got = readFrames(hs, 3, 1500);
        });
        control.sendKey(true, 0x0041);
        control.sendKey(false, 0x0041);
        host.join();
        if (focus.joinable()) focus.join();
        for (int i = 0; i < 100 && control.reconnectStats().reconnects == 0; ++i) Sleep(10);
        const auto st = control.reconnectStats();
        expect(auth && commits == 1 && blockedAtCommit && queued <= 1,
               "r5 commit: focus loss waited for the send already committed");
        expect(got.size() == 2 && got[0].first == 0x10 && got[0].second[0] == 1 && got[0].second[2] == 0x41 &&
                   got[1].first == 0x10 && got[1].second[0] == 0 && got[1].second[2] == 0x41,
               "  r6: the Mac got key A down and then key A up, a pair, nothing held (" +
                   std::to_string(got.size()) + " frames)");
        expect(st.flushed == 1 && st.discarded == 1 && st.released == 1,
               "  stats: flushed=1, discarded=1 (the queued up), released=1 (sent for the down)");
        control.setAtCommitForTest(nullptr);
        control.stop();
        closesocket(hs);
    }

    // (f) Background NoChallenge: the session is up (authenticated), the
    // control socket drops, and the reconnect's challenge comes 2.5 s late.
    // The worker tries again on control after 0.5 s; no probe, Password
    // mode kept, the session is not ended, the queued key goes out.
    {
        clearKnownModesForTest();
        std::atomic<int> terms{0};
        std::atomic<int> lastO{-1};
        auto c = makeClient(terms, lastO, "127.0.0.1:" + std::to_string(l.port));
        setCurrent(c);
        ControlChannel control("127.0.0.1", "127.0.0.1", l.port);
        control.setIoTimeoutMs(100);
        control.setBackgroundReconnect(true);
        bool auth1 = false, auth2 = false;
        std::atomic<bool> probed{false};
        std::vector<std::pair<uint8_t, Bytes>> first, got;
        std::thread host([&] {
            SOCKET s = l.accept(5000);
            if (s == INVALID_SOCKET) return;
            auth1 = hostAuth(s, sec, Answer::Ok, kFirstAuthMs);
            if (auth1) first = readFrames(s, 1, 2000);
            closesocket(s);  // the control connection drops
            s = l.accept(5000);
            if (s == INVALID_SOCKET) return;
            if (silentConn(s, sec, 2500)) probed = true;
            closesocket(s);
            s = l.accept(5000);
            if (s == INVALID_SOCKET) return;
            auth2 = hostAuth(s, sec, Answer::Ok, 100);
            if (auth2) got = readFrames(s, 64, 2000);
            closesocket(s);
        });
        control.sendKey(true, 0x0041);
        for (int i = 0; i < 300 && control.reconnectStats().reconnects == 0; ++i) Sleep(10);
        Sleep(200);
        // Input until the worker sees the dropped socket and reconnects.
        for (int i = 0; i < 200 && !control.reconnectStats().connecting; ++i) {
            control.sendKey(true, 0x0043);
            Sleep(16);
        }
        for (int i = 0; i < 500 && control.reconnectStats().noChallengeRetries == 0; ++i) Sleep(10);
        control.sendKey(true, 0x0046);  // typed while the retry waits: queued for it
        host.join();
        const auto st = control.reconnectStats();
        const bool sawF = !got.empty() && got.back().first == 0x10 && got.back().second[2] == 0x46;
        expect(auth1 && first.size() == 1, "r5 background: session up, first key delivered");
        expect(!probed && c->mode() == Client::Mode::Password && knownMode("127.0.0.1:" + std::to_string(l.port)) == HostMode::Password,
               "  late challenge: no probe, nothing sent, Password mode kept");
        expect(terms == 0 && !c->halted(), "  session not ended (no terminal answer, client not halted)");
        expect(st.noChallengeRetries == 1 && auth2 && sawF,
               "  retried on control after backoff, then the queued key went out (" +
                   std::to_string(st.noChallengeRetries) + " retries, " + std::to_string(got.size()) + " frames)");
        control.stop();
        setCurrent(nullptr);
        clearKnownModesForTest();
    }

    // (g) The Mac stays silent through every retry: control pauses (queue
    // dropped, reported once) and the session still goes on. r6: pointer
    // moves and auto-repeat start no new round (no connection reaches the
    // host); a fresh key press does, and that attempt goes through.
    {
        clearKnownModesForTest();
        std::atomic<int> terms{0};
        std::atomic<int> lastO{-1};
        auto c = makeClient(terms, lastO, "127.0.0.1:" + std::to_string(l.port));
        setCurrent(c);
        ControlChannel control("127.0.0.1", "127.0.0.1", l.port);
        control.setIoTimeoutMs(100);
        control.setBackgroundReconnect(true);
        bool auth1 = false, auth2 = false;
        std::atomic<int> silent{0}, probes{0}, noiseConns{0};
        std::atomic<bool> noiseDone{false}, noiseOver{false};
        std::vector<std::pair<uint8_t, Bytes>> got;
        std::thread host([&] {
            SOCKET s = l.accept(5000);
            if (s == INVALID_SOCKET) return;
            auth1 = hostAuth(s, sec, Answer::Ok, kFirstAuthMs);
            if (auth1) readFrames(s, 1, 2000);
            closesocket(s);
            for (int i = 0; i < 1 + kNoChallengeRetries; ++i) {
                s = l.accept(8000);
                if (s == INVALID_SOCKET) return;
                ++silent;
                if (silentConn(s, sec, 2300)) ++probes;
                closesocket(s);
            }
            // Paused: any connection now is a new round nobody asked for.
            while (!noiseDone) {
                s = l.accept(50);
                if (s != INVALID_SOCKET) { ++noiseConns; closesocket(s); }
            }
            noiseOver = true;  // the fresh key's connection is not taken for noise
            s = l.accept(15000);
            if (s == INVALID_SOCKET) return;
            auth2 = hostAuth(s, sec, Answer::Ok, 100);
            if (auth2) got = readFrames(s, 64, 2000);
            closesocket(s);
        });
        control.sendKey(true, 0x0041);
        for (int i = 0; i < 300 && control.reconnectStats().reconnects == 0; ++i) Sleep(10);
        Sleep(200);
        for (int i = 0; i < 200 && !control.reconnectStats().connecting; ++i) {
            control.sendKey(true, 0x0044);
            Sleep(16);
        }
        for (int i = 0; i < 3000 && control.reconnectStats().paused == 0; ++i) Sleep(10);
        Sleep(300);  // past the normal retry gap
        const auto mid = control.reconnectStats();
        const uint32_t pausedBits = c->takePausedChannels();
        expect(mid.paused == 1 && mid.noChallengeRetries == uint64_t(kNoChallengeRetries) && silent == 1 + kNoChallengeRetries,
               "r5 retries spent: control paused after " + std::to_string(mid.noChallengeRetries) + " retries");
        expect(probes == 0 && pausedBits == (1u << unsigned(Channel::Control)) && terms == 0 && !c->halted(),
               "  no probe, only control reported paused, session not ended");
        // r6: pointer moves and a held key's auto-repeat (the viewer does
        // not call resumeOnUserKey for those) for 1.5 s, then past the gap.
        UiClock ui;
        for (int i = 0; i < 90; ++i) {
            ui.call([&] { return control.sendMouseMoveAbsolute(uint16_t(100 + i), 200); });
            ui.call([&] { return control.sendKey(true, 0x0044); });  // auto-repeat
            Sleep(16);
        }
        Sleep(600);
        noiseDone = true;
        const auto quiet = control.reconnectStats();
        expect(noiseConns == 0 && !quiet.connecting && quiet.pausedNow && quiet.pausedDrops >= 180 &&
                   quiet.noChallengeRetries == uint64_t(kNoChallengeRetries) && quiet.paused == 1,
               "  r6: moves and auto-repeat after the pause start no new round (" + std::to_string(noiseConns) +
                   " connections, " + std::to_string(quiet.pausedDrops) + " dropped)");
        expect(ui.maxMs < kUiBudgetMs && c->takePausedChannels() == 0,
               "  r6: UI calls return at once while paused, no second paused report");
        for (int i = 0; i < 100 && !noiseOver; ++i) Sleep(10);
        const bool resumed = control.resumeOnUserKey();  // a fresh key press
        control.sendKey(true, 0x0045);
        host.join();
        for (int i = 0; i < 300 && control.reconnectStats().reconnects < 2; ++i) Sleep(10);
        const auto after = control.reconnectStats();
        expect(resumed && after.resumes == 1 && !after.pausedNow && !control.resumeOnUserKey(),
               "  r6: a fresh key press ends the pause (once)");
        expect(auth2 && got.size() == 1 && got[0].first == 0x10 && got[0].second[2] == 0x45 && after.reconnects == 2,
               "  that key starts a new round, reconnects and goes out; the stale ones were dropped (" +
                   std::to_string(got.size()) + " frames)");
        control.stop();
        setCurrent(nullptr);
        clearKnownModesForTest();
    }
    setCurrent(nullptr);
}

// Pepper's r5 review: item 1 (a key or button down that reached the Mac
// is released on focus loss) and item 2's helper.
void r6Tests() {
    expect(ControlChannel::isFreshKeyDown(0x001E0001) && ControlChannel::isFreshKeyDown(0x20380001),
           "r6 fresh key: WM_KEYDOWN / WM_SYSKEYDOWN with lParam bit 30 clear counts");
    expect(!ControlChannel::isFreshKeyDown(0x401E0001) && !ControlChannel::isFreshKeyDown(0x60380001),
           "  auto-repeat (bit 30 set) does not");

    Secret sec;
    randomBytes(sec.salt.data(), sec.salt.size());
    randomBytes(sec.hostId.data(), sec.hostId.size());
    sec.key = *deriveKey(kPw, sec.salt.data(), sec.salt.size(), sec.iter);
    std::atomic<int> terminals{0};
    std::atomic<int> lastOutcome{-1};
    auto client = makeClient(terminals, lastOutcome);
    setCurrent(client);
    Listener l;
    auto isKey = [](const std::pair<uint8_t, Bytes>& f, int down, uint8_t k) {
        return f.first == 0x10 && f.second.size() == 3 && f.second[0] == down && f.second[2] == k;
    };

    // (h) Handoff: the worker commits key A down at the moment focus leaves
    // (the reconnect hands over right after). The up comes from the viewer
    // only after the focus loss (WM_KEYUP or its own cleanup): the Mac gets
    // A down, the release for it, and that later up is not sent again.
    {
        ControlChannel control("127.0.0.1", "127.0.0.1", l.port);
        control.setIoTimeoutMs(100);
        control.setBackgroundReconnect(true);
        std::atomic<int> commits{0};
        std::atomic<bool> discardDone{false};
        std::thread focus;
        control.setAtCommitForTest([&] {
            if (commits++ != 0) return;
            focus = std::thread([&] { control.discardQueuedInput(); discardDone = true; });
            Sleep(50);
        });
        SOCKET hs = INVALID_SOCKET;
        bool auth = false;
        std::vector<std::pair<uint8_t, Bytes>> got;
        std::thread host([&] {
            hs = l.accept(5000);
            if (hs == INVALID_SOCKET) return;
            auth = hostAuth(hs, sec, Answer::Ok, kFirstAuthMs);
            if (auth) got = readFrames(hs, 4, 2500);
        });
        control.sendKey(true, 0x0041);
        for (int i = 0; i < 300 && !discardDone; ++i) Sleep(10);
        if (focus.joinable()) focus.join();
        for (int i = 0; i < 300 && control.reconnectStats().reconnects == 0; ++i) Sleep(10);
        control.sendKey(false, 0x0041);  // after the focus loss
        control.sendKey(true, 0x0042);   // focus back: new input
        control.sendKey(false, 0x0042);
        host.join();
        const auto st = control.reconnectStats();
        expect(auth && discardDone && got.size() == 4 && isKey(got[0], 1, 0x41) && isKey(got[1], 0, 0x41) &&
                   isKey(got[2], 1, 0x42) && isKey(got[3], 0, 0x42),
               "r6 handoff: A down sent at the handoff, up queued after focus loss: one A pair, then B (" +
                   std::to_string(got.size()) + " frames)");
        expect(st.released == 1 && st.swallowed == 1, "  stats: released=1, swallowed=1 (the later A up)");
        control.setAtCommitForTest(nullptr);
        control.stop();
        closesocket(hs);
    }

    // (i) Live: key A and the right button (0x21) went out on the live
    // connection; focus leaves: both ups go at once. The viewer's own ups
    // that follow are not sent again; new input goes after them.
    {
        ControlChannel control("127.0.0.1", "127.0.0.1", l.port);
        control.setIoTimeoutMs(100);
        control.setBackgroundReconnect(true);
        SOCKET hs = INVALID_SOCKET;
        bool auth = false;
        std::vector<std::pair<uint8_t, Bytes>> first, got;
        std::atomic<bool> firstIn{false};
        std::thread host([&] {
            hs = l.accept(5000);
            if (hs == INVALID_SOCKET) return;
            auth = hostAuth(hs, sec, Answer::Ok, kFirstAuthMs);
            if (auth) first = readFrames(hs, 1, 2000);
            firstIn = true;
            if (auth) got = readFrames(hs, 6, 2500);
        });
        control.sendKey(true, 0x0050);  // starts the connection
        for (int i = 0; i < 300 && !firstIn; ++i) Sleep(10);
        for (int i = 0; i < 300 && control.reconnectStats().connecting; ++i) Sleep(10);
        control.sendKey(false, 0x0050);
        control.sendKey(true, 0x0041);
        control.sendMouseButton(1, true);
        Sleep(100);
        const size_t n = control.discardQueuedInput();
        const auto mid = control.reconnectStats();
        control.sendKey(false, 0x0041);    // viewer: WM_KEYUP after the focus loss
        control.sendMouseButton(1, false);  // viewer: releaseRemoteButtons
        control.sendKey(true, 0x0042);
        host.join();
        const auto st = control.reconnectStats();
        auto isBtn = [](const std::pair<uint8_t, Bytes>& f, int down) {
            return f.first == 0x21 && f.second.size() == 2 && f.second[0] == 1 && f.second[1] == down;
        };
        expect(auth && first.size() == 1 && n == 0 && mid.released == 2 && got.size() == 6 &&
                   isKey(got[0], 0, 0x50) && isKey(got[1], 1, 0x41) && isBtn(got[2], 1) && isKey(got[3], 0, 0x41) &&
                   isBtn(got[4], 0) && isKey(got[5], 1, 0x42),
               "r6 live: focus left with A and the right button down: both ups sent at once, then new input (" +
                   std::to_string(got.size()) + " frames)");
        expect(st.released == 2 && st.swallowed == 2, "  stats: released=2, swallowed=2 (the viewer's later ups)");
        control.stop();
        closesocket(hs);
    }

    // (j) Reconnect: key A and the left button with a click count (0x25)
    // went out live, then the connection dropped. The viewer's A up waits for
    // the reconnect, and focus leaves before it is back. The new connection
    // gets A up and the button up (same frame type and click count) before
    // anything else; the viewer's later button up is not sent again.
    {
        ControlChannel control("127.0.0.1", "127.0.0.1", l.port);
        control.setIoTimeoutMs(100);
        control.setBackgroundReconnect(true);
        bool auth1 = false, auth2 = false;
        std::atomic<bool> firstIn{false};
        std::vector<std::pair<uint8_t, Bytes>> first, got;
        std::thread host([&] {
            SOCKET s = l.accept(5000);
            if (s == INVALID_SOCKET) return;
            auth1 = hostAuth(s, sec, Answer::Ok, kFirstAuthMs);
            if (auth1) first = readFrames(s, 2, 2000);
            firstIn = true;
            SOCKET s2 = l.accept(5000);
            closesocket(s);
            if (s2 == INVALID_SOCKET) return;
            auth2 = hostAuth(s2, sec, Answer::Ok);  // 600 ms: focus leaves meanwhile
            if (auth2) got = readFrames(s2, 4, 2000);
            closesocket(s2);
        });
        control.sendKey(true, 0x0041);
        for (int i = 0; i < 300 && control.reconnectStats().reconnects == 0; ++i) Sleep(10);
        control.sendMouseButtonExtended(0, true, 2);
        for (int i = 0; i < 300 && !firstIn; ++i) Sleep(10);
        control.close();                 // the connection dropped
        control.sendKey(false, 0x0041);  // waits for the reconnect
        for (int i = 0; i < 100 && !control.reconnectStats().connecting; ++i) Sleep(10);
        const size_t n = control.discardQueuedInput();
        const auto mid = control.reconnectStats();
        for (int i = 0; i < 300 && control.reconnectStats().reconnects < 2; ++i) Sleep(10);
        control.sendMouseButtonExtended(0, false, 2);  // viewer: releaseRemoteButtons
        control.sendKey(true, 0x0042);
        host.join();
        const auto st = control.reconnectStats();
        const bool btnUp = got.size() >= 2 && got[1].first == 0x25 && got[1].second.size() == 3 &&
                           got[1].second[0] == 0 && got[1].second[1] == 0 && got[1].second[2] == 2;
        expect(auth1 && first.size() == 2 && mid.connecting && n == 1 && mid.released == 0,
               "r6 reconnect: A and the left button were down when the connection dropped; focus left during the reconnect");
        expect(auth2 && got.size() == 3 && isKey(got[0], 0, 0x41) && btnUp && isKey(got[2], 1, 0x42),
               "  the new connection got A up and the button up (0x25, 2 clicks) first, then B; nothing more (" +
                   std::to_string(got.size()) + " frames)");
        expect(st.released == 2 && st.swallowed == 1, "  stats: released=2, swallowed=1 (the viewer's later button up)");
        control.stop();
    }

    // (k) Found in the win01 hand test: key X and the right button went
    // down while control was reconnecting, so they waited in the queue, and
    // focus left before the reconnect was back: both downs are dropped. The
    // viewer handles X's WM_KEYUP (still in its message queue) and the
    // button up only after that: their downs never reached the Mac, so they
    // are not sent either. B goes out as usual.
    {
        ControlChannel control("127.0.0.1", "127.0.0.1", l.port);
        control.setIoTimeoutMs(100);
        control.setBackgroundReconnect(true);
        bool auth1 = false, auth2 = false;
        std::atomic<bool> firstIn{false};
        std::vector<std::pair<uint8_t, Bytes>> first, got;
        std::thread host([&] {
            SOCKET s = l.accept(5000);
            if (s == INVALID_SOCKET) return;
            auth1 = hostAuth(s, sec, Answer::Ok, kFirstAuthMs);
            if (auth1) first = readFrames(s, 2, 2000);
            firstIn = true;
            SOCKET s2 = l.accept(5000);
            closesocket(s);
            if (s2 == INVALID_SOCKET) return;
            auth2 = hostAuth(s2, sec, Answer::Ok);  // 600 ms: focus leaves meanwhile
            if (auth2) got = readFrames(s2, 4, 2000);
            closesocket(s2);
        });
        control.sendKey(true, 0x0041);
        control.sendKey(false, 0x0041);
        for (int i = 0; i < 300 && !firstIn; ++i) Sleep(10);
        control.close();                 // the connection dropped
        control.sendKey(true, 0x0058);   // starts the reconnect, waits for it
        control.sendMouseButton(1, true);
        for (int i = 0; i < 100 && !control.reconnectStats().connecting; ++i) Sleep(10);
        const size_t n = control.discardQueuedInput();
        const auto mid = control.reconnectStats();
        control.sendKey(false, 0x0058);  // the WM_KEYUP handled after the focus change
        control.sendMouseButton(1, false);
        for (int i = 0; i < 300 && control.reconnectStats().reconnects < 2; ++i) Sleep(10);
        control.sendKey(true, 0x0042);
        control.sendKey(false, 0x0042);
        host.join();
        const auto st = control.reconnectStats();
        expect(auth1 && first.size() == 2 && mid.connecting && n == 2 && mid.released == 0,
               "r6 dropped downs: X and the right button waited for the reconnect when focus left (2 dropped)");
        expect(auth2 && got.size() == 2 && isKey(got[0], 1, 0x42) && isKey(got[1], 0, 0x42),
               "  their later ups were not sent: the new connection got only B down and up (" +
                   std::to_string(got.size()) + " frames)");
        expect(st.released == 0 && st.swallowed == 2, "  stats: released=0, swallowed=2 (X up, button up)");
        control.stop();
    }

    // (l) Found in the win01 hand test: key A is held on the live
    // connection, the Mac resets it, and the viewer's next key X still sees
    // it as live. Its send fails, so X down waits for the reconnect; focus
    // leaves before that. The Mac must get A up (A was down) but no X up:
    // X down never reached it.
    {
        ControlChannel control("127.0.0.1", "127.0.0.1", l.port);
        control.setIoTimeoutMs(100);
        control.setBackgroundReconnect(true);
        bool auth1 = false, auth2 = false;
        std::atomic<bool> reset{false};
        std::vector<std::pair<uint8_t, Bytes>> first, got;
        std::thread host([&] {
            SOCKET s = l.accept(5000);
            if (s == INVALID_SOCKET) { reset = true; return; }
            auth1 = hostAuth(s, sec, Answer::Ok, kFirstAuthMs);
            if (auth1) first = readFrames(s, 1, 2000);
            linger lg{1, 0};  // closesocket sends RST
            setsockopt(s, SOL_SOCKET, SO_LINGER, reinterpret_cast<const char*>(&lg), sizeof(lg));
            closesocket(s);
            reset = true;
            SOCKET s2 = l.accept(5000);
            if (s2 == INVALID_SOCKET) return;
            auth2 = hostAuth(s2, sec, Answer::Ok);  // 600 ms: focus leaves meanwhile
            if (auth2) got = readFrames(s2, 4, 2000);
            closesocket(s2);
        });
        control.sendKey(true, 0x0041);
        for (int i = 0; i < 300 && !reset; ++i) Sleep(10);
        Sleep(200);                      // the RST has arrived
        control.sendKey(true, 0x0058);   // the send fails: waits for the reconnect
        for (int i = 0; i < 100 && !control.reconnectStats().connecting; ++i) Sleep(10);
        const size_t n = control.discardQueuedInput();
        const auto mid = control.reconnectStats();
        control.sendKey(false, 0x0058);
        for (int i = 0; i < 300 && control.reconnectStats().reconnects < 2; ++i) Sleep(10);
        control.sendKey(true, 0x0042);
        control.sendKey(false, 0x0042);
        host.join();
        const auto st = control.reconnectStats();
        expect(auth1 && first.size() == 1 && isKey(first[0], 1, 0x41) && mid.connecting && n == 1,
               "r6 failed send: A held, the Mac reset the connection, X's send failed and X waited; focus left");
        expect(auth2 && got.size() == 3 && isKey(got[0], 0, 0x41) && isKey(got[1], 1, 0x42) && isKey(got[2], 0, 0x42),
               "  the new connection got A up, then B; no X up (" + std::to_string(got.size()) + " frames)");
        expect(st.released == 1 && st.swallowed == 1, "  stats: released=1 (A), swallowed=1 (X up)");
        control.stop();
    }
    setCurrent(nullptr);
}

// Host side of the r7 checks: every key or button the Mac gets down also
// gets its up, and no up arrives for something it does not hold. `held` is
// what it already holds when these frames start.
bool pairedOnly(const std::vector<std::pair<uint8_t, Bytes>>& got, std::set<int> held, std::string& why) {
    for (size_t i = 0; i < got.size(); ++i) {
        const auto& f = got[i];
        int id = -1, down = 0;
        if (f.first == 0x10 && f.second.size() == 3) { id = (f.second[1] << 8) | f.second[2]; down = f.second[0]; }
        else if (f.first == 0x21 && f.second.size() == 2) { id = 0x10000 | f.second[0]; down = f.second[1]; }
        else if (f.first == 0x25 && f.second.size() == 3) { id = 0x10000 | f.second[0]; down = f.second[1]; }
        else continue;
        if (down) { held.insert(id); continue; }
        if (!held.erase(id)) { why = "lone up at frame " + std::to_string(i); return false; }
    }
    if (!held.empty()) { why = std::to_string(held.size()) + " left held"; return false; }
    why = "paired";
    return true;
}

// Pepper's r6 review. Item 1: every path that drops input unsent follows one
// rule (a down that never went out takes its up with it; an up whose down
// reached the Mac is still delivered). Focus loss and a failed live send
// are (h)-(l) above; these are the queue's own drops. Item 2: a button up
// that is not sent again takes its queued pointer position along.
void r7Tests() {
    Secret sec;
    randomBytes(sec.salt.data(), sec.salt.size());
    randomBytes(sec.hostId.data(), sec.hostId.size());
    sec.key = *deriveKey(kPw, sec.salt.data(), sec.salt.size(), sec.iter);
    Listener l;
    auto isKey = [](const std::pair<uint8_t, Bytes>& f, int down, uint8_t k) {
        return f.first == 0x10 && f.second.size() == 3 && f.second[0] == down && f.second[2] == k;
    };
    const std::string hostKey = "127.0.0.1:" + std::to_string(l.port);

    // (m) Aged out: A reached the Mac down, then the connection dropped. A up and
    // X down wait while the Mac's challenge is late twice (background
    // NoChallenge retries), and age out when X up is queued 3.3 s later.
    // The Mac still gets A up (first, owed) and never a lone X up.
    {
        clearKnownModesForTest();
        std::atomic<int> terms{0};
        std::atomic<int> lastO{-1};
        auto c = makeClient(terms, lastO, hostKey);
        setCurrent(c);
        ControlChannel control("127.0.0.1", "127.0.0.1", l.port);
        control.setIoTimeoutMs(100);
        control.setBackgroundReconnect(true);
        bool auth1 = false, auth2 = false;
        std::atomic<bool> firstIn{false};
        std::vector<std::pair<uint8_t, Bytes>> first, got;
        std::thread host([&] {
            SOCKET s = l.accept(5000);
            if (s == INVALID_SOCKET) { firstIn = true; return; }
            auth1 = hostAuth(s, sec, Answer::Ok, kFirstAuthMs);
            if (auth1) first = readFrames(s, 1, 2000);
            firstIn = true;
            for (int i = 0; i < 2; ++i) {
                SOCKET q = l.accept(5000);
                if (i == 0) closesocket(s);
                if (q == INVALID_SOCKET) return;
                silentConn(q, sec, 2300);
                closesocket(q);
            }
            s = l.accept(8000);
            if (s == INVALID_SOCKET) return;
            auth2 = hostAuth(s, sec, Answer::Ok, 100);
            if (auth2) got = readFrames(s, 4, 2000);
            closesocket(s);
        });
        control.sendKey(true, 0x0041);
        for (int i = 0; i < 300 && !firstIn; ++i) Sleep(10);
        for (int i = 0; i < 300 && control.reconnectStats().connecting; ++i) Sleep(10);
        control.close();                 // the connection dropped
        control.sendKey(false, 0x0041);  // waits for the reconnect
        control.sendKey(true, 0x0058);
        Sleep(DWORD(ControlChannel::kQueueMaxAgeMs + 300));
        const auto mid = control.reconnectStats();
        control.sendKey(false, 0x0058);  // A up and X down age out here
        control.sendKey(true, 0x0042);
        control.sendKey(false, 0x0042);
        host.join();
        const auto st = control.reconnectStats();
        std::string why;
        const bool paired = pairedOnly(got, {0x41}, why);
        expect(auth1 && first.size() == 1 && isKey(first[0], 1, 0x41) && mid.connecting && mid.reconnects == 1,
               "r7 aged: A down reached the Mac; A up and X down still waited for the reconnect after 3.3 s");
        expect(auth2 && got.size() == 3 && isKey(got[0], 0, 0x41) && isKey(got[1], 1, 0x42) && isKey(got[2], 0, 0x42) && paired,
               "  aged out: the Mac got A up first, then B; no lone X up (" + std::to_string(got.size()) + " frames, " + why + ")");
        expect(st.owedOnDrop == 1 && st.swallowed == 1, "  stats: owedOnDrop=1 (A up), swallowed=1 (X up)");
        control.stop();
        setCurrent(nullptr);
        clearKnownModesForTest();
    }

    std::atomic<int> terminals{0};
    std::atomic<int> lastOutcome{-1};
    auto client = makeClient(terminals, lastOutcome);
    setCurrent(client);

    // (n) Full queue: A reached the Mac down, the connection dropped, and while it
    // is re-made the queue overflows. A up, X down and the first C down are
    // pushed out. The Mac gets A up first, the C presses that are whole,
    // and no lone X up or C up.
    {
        ControlChannel control("127.0.0.1", "127.0.0.1", l.port);
        control.setIoTimeoutMs(100);
        control.setBackgroundReconnect(true);
        bool auth1 = false, auth2 = false;
        std::atomic<bool> firstIn{false};
        std::vector<std::pair<uint8_t, Bytes>> first, got;
        std::thread host([&] {
            SOCKET s = l.accept(5000);
            if (s == INVALID_SOCKET) { firstIn = true; return; }
            auth1 = hostAuth(s, sec, Answer::Ok, kFirstAuthMs);
            if (auth1) first = readFrames(s, 1, 2000);
            firstIn = true;
            SOCKET s2 = l.accept(5000);
            closesocket(s);
            if (s2 == INVALID_SOCKET) return;
            auth2 = hostAuth(s2, sec, Answer::Ok);  // 600 ms: the queue fills meanwhile
            if (auth2) got = readFrames(s2, 300, 2500);
            closesocket(s2);
        });
        control.sendKey(true, 0x0041);
        for (int i = 0; i < 300 && !firstIn; ++i) Sleep(10);
        for (int i = 0; i < 300 && control.reconnectStats().connecting; ++i) Sleep(10);
        control.close();
        control.sendKey(false, 0x0041);
        control.sendKey(true, 0x0058);
        for (size_t i = 0; i + 2 < ControlChannel::kQueueMax; ++i) control.sendKey(i % 2 == 0, 0x0043);
        control.sendKey(false, 0x0058);  // pushes out A up
        control.sendKey(true, 0x0042);   // pushes out X down
        control.sendKey(false, 0x0042);  // pushes out the first C down
        host.join();
        const auto st = control.reconnectStats();
        std::string why;
        const bool paired = pairedOnly(got, {0x41}, why);
        size_t x = 0, cPairs = 0;
        for (size_t i = 0; i < got.size(); ++i) {
            if (got[i].first == 0x10 && got[i].second.size() == 3 && got[i].second[2] == 0x58) ++x;
            if (isKey(got[i], 1, 0x43)) ++cPairs;
        }
        const size_t pairs = (ControlChannel::kQueueMax - 2) / 2 - 1;
        expect(auth1 && auth2 && got.size() == 1 + 2 * pairs + 2 && isKey(got[0], 0, 0x41) && x == 0 && cPairs == pairs &&
                   isKey(got[got.size() - 2], 1, 0x42) && isKey(got.back(), 0, 0x42) && paired,
               "r7 full queue: A up first, " + std::to_string(cPairs) + " whole C presses, B; no X, no lone C up (" +
                   std::to_string(got.size()) + " frames, " + why + ")");
        expect(st.owedOnDrop == 1 && st.swallowed == 2, "  stats: owedOnDrop=1 (A up), swallowed=2 (X up, first C up)");
        control.stop();
    }

    // (o) A flush that fails before any byte goes out (send buffer full
    // for 2 s): X down is dropped there, so X up queued behind it is not
    // sent on the next connection; A up (A reached the Mac down) still is.
    {
        ControlChannel control("127.0.0.1", "127.0.0.1", l.port);
        control.setIoTimeoutMs(100);
        control.setBackgroundReconnect(true);
        bool auth1 = false, auth2 = false, auth3 = false;
        std::atomic<bool> firstIn{false};
        std::vector<std::pair<uint8_t, Bytes>> first, mid, got;
        std::thread host([&] {
            SOCKET s = l.accept(5000);
            if (s == INVALID_SOCKET) { firstIn = true; return; }
            auth1 = hostAuth(s, sec, Answer::Ok, kFirstAuthMs);
            if (auth1) first = readFrames(s, 1, 2000);
            firstIn = true;
            SOCKET s2 = l.accept(5000);
            closesocket(s);
            if (s2 == INVALID_SOCKET) return;
            auth2 = hostAuth(s2, sec, Answer::Ok, 100);
            if (auth2) mid = readFrames(s2, 1, 3500);  // the viewer gives up on it
            closesocket(s2);
            SOCKET s3 = l.accept(8000);
            if (s3 == INVALID_SOCKET) return;
            auth3 = hostAuth(s3, sec, Answer::Ok, 100);
            if (auth3) got = readFrames(s3, 4, 2000);
            closesocket(s3);
        });
        control.sendKey(true, 0x0041);
        for (int i = 0; i < 300 && !firstIn; ++i) Sleep(10);
        for (int i = 0; i < 300 && control.reconnectStats().connecting; ++i) Sleep(10);
        control.setFlushWouldBlockForTest(1000000, [] { Sleep(60); });
        control.close();
        const auto before = control.reconnectStats();
        control.sendKey(true, 0x0058);   // the flush of this one fails
        control.sendKey(false, 0x0041);
        control.sendKey(false, 0x0058);
        for (int i = 0; i < 600 && control.reconnectStats().dropped == before.dropped; ++i) Sleep(10);
        for (int i = 0; i < 300 && control.reconnectStats().connecting; ++i) Sleep(10);
        control.setFlushWouldBlockForTest(0, nullptr);
        Sleep(DWORD(ControlChannel::kRetryGapMs + 50));  // B may start the next attempt
        const auto failed = control.reconnectStats();
        control.sendKey(true, 0x0042);
        control.sendKey(false, 0x0042);
        host.join();
        const auto st = control.reconnectStats();
        std::string why;
        const bool paired = pairedOnly(got, {0x41}, why);
        expect(auth1 && auth2 && mid.empty() && failed.dropped == before.dropped + 1 && failed.flushWaits > 0,
               "r7 failed flush: nothing of X down went out in 2 s; it was dropped and the connection given up");
        expect(auth3 && got.size() == 3 && isKey(got[0], 0, 0x41) && isKey(got[1], 1, 0x42) && isKey(got[2], 0, 0x42) && paired,
               "  next connection: A up, then B; no lone X up (" + std::to_string(got.size()) + " frames, " + why + ")");
        expect(st.swallowed == 1, "  stats: swallowed=1 (X up)");
        control.stop();
    }

    // (p) Item 2: the left button went down live with the pointer known
    // (notePointer, as the viewer does for its UDP moves), the connection
    // dropped, and focus left: the button up is owed. The viewer's own
    // button up (releaseRemoteButtons) is queued as a positioned click.
    // After the reconnect the Mac gets the owed up, and neither that later
    // up nor its old position: the Mac cursor does not move.
    {
        ControlChannel control("127.0.0.1", "127.0.0.1", l.port);
        control.setIoTimeoutMs(100);
        control.setBackgroundReconnect(true);
        bool auth1 = false, auth2 = false;
        std::atomic<bool> firstIn{false};
        std::vector<std::pair<uint8_t, Bytes>> first, got;
        std::thread host([&] {
            SOCKET s = l.accept(5000);
            if (s == INVALID_SOCKET) { firstIn = true; return; }
            auth1 = hostAuth(s, sec, Answer::Ok, kFirstAuthMs);
            if (auth1) first = readFrames(s, 3, 2000);
            firstIn = true;
            SOCKET s2 = l.accept(5000);
            closesocket(s);
            if (s2 == INVALID_SOCKET) return;
            auth2 = hostAuth(s2, sec, Answer::Ok);
            if (auth2) got = readFrames(s2, 4, 2000);
            closesocket(s2);
        });
        control.sendKey(true, 0x0050);  // starts the connection
        control.sendKey(false, 0x0050);
        for (int i = 0; i < 300 && control.reconnectStats().reconnects == 0; ++i) Sleep(10);
        control.notePointer(0x5555, 0x6666);
        control.sendMouseButton(0, true);   // live: the Mac has it down
        for (int i = 0; i < 300 && !firstIn; ++i) Sleep(10);
        control.close();                    // the connection dropped
        control.discardQueuedInput();       // focus leaves: button up owed
        control.sendMouseButton(0, false);  // viewer: releaseRemoteButtons, queued with 0x24
        for (int i = 0; i < 300 && control.reconnectStats().reconnects < 2; ++i) Sleep(10);
        control.sendKey(true, 0x0042);
        control.sendKey(false, 0x0042);
        host.join();
        const auto st = control.reconnectStats();
        size_t positions = 0;
        for (const auto& f : got) if (f.first == 0x24) ++positions;
        std::string why;
        const bool paired = pairedOnly(got, {0x10000}, why);
        const bool btnUp = !got.empty() && got[0].first == 0x21 && got[0].second.size() == 2 && got[0].second[0] == 0 &&
                           got[0].second[1] == 0;
        expect(auth1 && first.size() == 3 && first[2].first == 0x21 && st.positioned == 1,
               "r7 position: left button down went out live; its later up was queued with the pointer position");
        expect(auth2 && got.size() == 3 && btnUp && positions == 0 && isKey(got[1], 1, 0x42) && isKey(got[2], 0, 0x42) && paired,
               "  after the reconnect: the owed button up, then B; no 0x24, the Mac cursor did not move (" +
                   std::to_string(got.size()) + " frames, " + why + ")");
        expect(st.released == 1 && st.swallowed == 1 && st.positionsSkipped == 1,
               "  stats: released=1, swallowed=1, positionsSkipped=1");
        control.stop();
    }
    setCurrent(nullptr);

    // (q) Paused: A and B reached the Mac down, then the Mac stays silent through
    // every retry. A up waited in the queue (dropped when control paused);
    // B up and a whole X press come while paused. A fresh key press
    // reconnects: the Mac gets A up and B up first, then E; no X.
    {
        clearKnownModesForTest();
        std::atomic<int> terms{0};
        std::atomic<int> lastO{-1};
        auto c = makeClient(terms, lastO, hostKey);
        setCurrent(c);
        ControlChannel control("127.0.0.1", "127.0.0.1", l.port);
        control.setIoTimeoutMs(100);
        control.setBackgroundReconnect(true);
        bool auth1 = false, auth2 = false;
        std::atomic<bool> firstIn{false};
        std::atomic<int> silent{0};
        std::vector<std::pair<uint8_t, Bytes>> first, got;
        std::thread host([&] {
            SOCKET s = l.accept(5000);
            if (s == INVALID_SOCKET) { firstIn = true; return; }
            auth1 = hostAuth(s, sec, Answer::Ok, kFirstAuthMs);
            if (auth1) first = readFrames(s, 2, 2000);
            firstIn = true;
            for (int i = 0; i < 1 + kNoChallengeRetries; ++i) {
                SOCKET q = l.accept(8000);
                if (i == 0) closesocket(s);
                if (q == INVALID_SOCKET) return;
                ++silent;
                silentConn(q, sec, 2300);
                closesocket(q);
            }
            s = l.accept(20000);
            if (s == INVALID_SOCKET) return;
            auth2 = hostAuth(s, sec, Answer::Ok, 100);
            if (auth2) got = readFrames(s, 5, 2000);
            closesocket(s);
        });
        control.sendKey(true, 0x0041);
        control.sendKey(true, 0x0042);
        for (int i = 0; i < 300 && !firstIn; ++i) Sleep(10);
        for (int i = 0; i < 300 && control.reconnectStats().connecting; ++i) Sleep(10);
        control.close();
        control.sendKey(false, 0x0041);  // waits through the retries
        for (int i = 0; i < 3000 && control.reconnectStats().paused == 0; ++i) Sleep(10);
        control.sendKey(false, 0x0042);  // paused: dropped, B up owed
        control.sendKey(true, 0x0058);   // paused: a whole press dropped
        control.sendKey(false, 0x0058);
        control.sendMouseMoveAbsolute(300, 300);
        const auto mid = control.reconnectStats();
        const bool resumed = control.resumeOnUserKey();
        control.sendKey(true, 0x0045);
        control.sendKey(false, 0x0045);
        host.join();
        const auto st = control.reconnectStats();
        std::string why;
        const bool paired = pairedOnly(got, {0x41, 0x42}, why);
        expect(auth1 && first.size() == 2 && silent == 1 + kNoChallengeRetries && mid.pausedNow && mid.owedOnDrop == 2 &&
                   mid.pausedDrops == 4,
               "r7 paused: A up dropped at the pause and B up while paused are owed (" + std::to_string(mid.owedOnDrop) +
                   "), X press and a move dropped");
        expect(resumed && auth2 && got.size() == 4 && isKey(got[0], 0, 0x41) && isKey(got[1], 0, 0x42) &&
                   isKey(got[2], 1, 0x45) && isKey(got[3], 0, 0x45) && paired,
               "  fresh key: the Mac got A up and B up first, then E; no X (" + std::to_string(got.size()) + " frames, " +
                   why + ")");
        expect(st.released == 2, "  stats: released=2");
        control.stop();
        setCurrent(nullptr);
        clearKnownModesForTest();
    }
}

}  // namespace

int main() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    reconnectTests();
    stopTests();
    staleInputTests();
    r4InputTests();
    r5Tests();
    r6Tests();
    r7Tests();
    WSACleanup();
    std::printf("%d passed, %d failed\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
