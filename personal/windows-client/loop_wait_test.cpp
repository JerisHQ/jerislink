// Console test for loop_wait.hpp (the viewer receive loop's wait set).
// 1. Timer resolution: how long a 1 ms and a 5 ms wait really sleep,
//    without and with ScopedTimerResolution (before/after numbers).
// 2. MRM1 wake: a pong arriving on the MRM1 socket wakes the loop at once
//    when its event is in the wait set; the old set (video + present only)
//    sleeps until the timeout (negative test).
// 3. Event semantics the viewer relies on: reset + drain leaves no
//    spurious wake; a datagram left unread re-signals the event.
// 4. Null handles are skipped and results map back to the right source.
#include "loop_wait.hpp"

#include <ws2tcpip.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <thread>
#include <vector>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "user32.lib")

using namespace jl;
using Clock = std::chrono::steady_clock;

static int gFailures = 0;
static int gPasses = 0;
#define CHECK(cond)                                                     \
    do {                                                                \
        if (!(cond)) {                                                  \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++gFailures;                                                \
        } else {                                                        \
            ++gPasses;                                                  \
        }                                                               \
    } while (0)

static double msSince(Clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
}

static double medianWaitMs(DWORD waitMs, int samples) {
    LoopWait none;  // no handles: only the timeout or a message ends it
    std::vector<double> v;
    for (int i = 0; i < samples; ++i) {
        const auto t0 = Clock::now();
        none.wait(waitMs);
        v.push_back(msSince(t0));
    }
    std::sort(v.begin(), v.end());
    return v[v.size() / 2];
}

static void testTimerResolution() {
    const double before1 = medianWaitMs(1, 40);
    const double before5 = medianWaitMs(5, 40);
    double after1 = 0, after5 = 0;
    {
        ScopedTimerResolution period(1);
        CHECK(period.active());
        after1 = medianWaitMs(1, 40);
        after5 = medianWaitMs(5, 40);
    }
    std::printf("timer: 1 ms wait p50 before=%.2f ms after=%.2f ms\n", before1, after1);
    std::printf("timer: 5 ms wait p50 before=%.2f ms after=%.2f ms\n", before5, after5);
    CHECK(after1 <= 3.0);
    CHECK(after5 <= 7.5);
}

struct UdpPair {
    SOCKET rx = INVALID_SOCKET, tx = INVALID_SOCKET;
    sockaddr_in rxAddr{};
    WSAEVENT ev = WSA_INVALID_EVENT;

    UdpPair() {
        rx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        tx = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        rxAddr.sin_family = AF_INET;
        rxAddr.sin_port = 0;
        inet_pton(AF_INET, "127.0.0.1", &rxAddr.sin_addr);
        bind(rx, reinterpret_cast<sockaddr*>(&rxAddr), sizeof(rxAddr));
        int len = sizeof(rxAddr);
        getsockname(rx, reinterpret_cast<sockaddr*>(&rxAddr), &len);
        // Same setup as MouseMoveUdpChannel: event select on FD_READ.
        ev = WSACreateEvent();
        WSAEventSelect(rx, ev, FD_READ);
    }
    ~UdpPair() {
        if (ev != WSA_INVALID_EVENT) WSACloseEvent(ev);
        if (rx != INVALID_SOCKET) closesocket(rx);
        if (tx != INVALID_SOCKET) closesocket(tx);
    }
    void send() {
        const char p[18] = {'M', 'R', 'M', '1', 1, 0x44};
        sendto(tx, p, sizeof(p), 0, reinterpret_cast<const sockaddr*>(&rxAddr), sizeof(rxAddr));
    }
    // What pollCursorShape() does: reset, then read until WSAEWOULDBLOCK.
    int drain() {
        WSAResetEvent(ev);
        int got = 0;
        char buf[64];
        while (recv(rx, buf, sizeof(buf), 0) != SOCKET_ERROR) ++got;
        return got;
    }
    bool readOne() {
        char buf[64];
        return recv(rx, buf, sizeof(buf), 0) != SOCKET_ERROR;
    }
};

static void testMrm1Wake() {
    HANDLE videoEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);  // never signalled here

    // New wait set: a pong 30 ms after the wait starts ends a 1000 ms wait.
    {
        UdpPair mrm1;
        LoopWait w;
        w.add(videoEvent, LoopWait::Video);
        w.add(nullptr, LoopWait::Present);  // no latency object (CPU path)
        w.add(mrm1.ev, LoopWait::Mrm1);
        CHECK(w.count == 2);
        std::thread sender([&] { Sleep(30); mrm1.send(); });
        const auto t0 = Clock::now();
        const LoopWait::Wake r = w.wait(1000);
        const double ms = msSince(t0);
        sender.join();
        std::printf("mrm1: with MRM1 in the wait set, pong wakes after %.1f ms (sent at 30 ms)\n", ms);
        CHECK(r == LoopWait::Mrm1);
        CHECK(ms < 200.0);
        CHECK(mrm1.drain() == 1);
    }

    // Negative: the old wait set (video + present). The pong arrives but the
    // loop sleeps until its timeout.
    {
        UdpPair mrm1;
        LoopWait w;
        w.add(videoEvent, LoopWait::Video);
        std::thread sender([&] { Sleep(30); mrm1.send(); });
        const auto t0 = Clock::now();
        const LoopWait::Wake r = w.wait(200);
        const double ms = msSince(t0);
        sender.join();
        std::printf("mrm1: old wait set, pong waits %.1f ms for the timeout\n", ms);
        CHECK(r == LoopWait::Timeout);
        CHECK(ms >= 150.0);
        CHECK(mrm1.drain() == 1);  // the pong was there all along
    }

    // Reset + drain: no busy loop. Draining two datagrams re-posts FD_READ
    // once (data was still queued after the first recv), so the loop may
    // wake one more time; that pass reads nothing, and then it sleeps.
    {
        UdpPair mrm1;
        LoopWait w;
        w.add(mrm1.ev, LoopWait::Mrm1);
        mrm1.send();
        mrm1.send();
        Sleep(20);  // both datagrams queued
        CHECK(w.wait(500) == LoopWait::Mrm1);
        CHECK(mrm1.drain() == 2);
        int extraWakes = 0;
        while (extraWakes < 5 && w.wait(50) == LoopWait::Mrm1) {
            ++extraWakes;
            CHECK(mrm1.drain() == 0);
        }
        std::printf("mrm1: extra wakes after draining a burst of 2: %d\n", extraWakes);
        CHECK(extraWakes <= 1);
        CHECK(w.wait(50) == LoopWait::Timeout);
    }

    // A datagram left unread re-signals the event after a reset, so the
    // loop cannot sleep on data it has not read.
    {
        UdpPair mrm1;
        LoopWait w;
        w.add(mrm1.ev, LoopWait::Mrm1);
        mrm1.send();
        mrm1.send();
        CHECK(w.wait(500) == LoopWait::Mrm1);
        Sleep(20);  // both datagrams queued
        WSAResetEvent(mrm1.ev);
        CHECK(mrm1.readOne());
        CHECK(w.wait(200) == LoopWait::Mrm1);
        CHECK(mrm1.drain() == 1);
    }

    CloseHandle(videoEvent);
}

static void testMapping() {
    HANDLE a = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE c = CreateEventW(nullptr, TRUE, TRUE, nullptr);  // signalled
    LoopWait w;
    w.add(a, LoopWait::Video);
    w.add(nullptr, LoopWait::Present);
    w.add(c, LoopWait::Mrm1);
    CHECK(w.count == 2);
    CHECK(w.wait(0) == LoopWait::Mrm1);
    ResetEvent(c);
    SetEvent(a);
    CHECK(w.wait(0) == LoopWait::Video);
    ResetEvent(a);
    CHECK(w.wait(0) == LoopWait::Timeout);
    // A posted window message ends the wait as Message.
    MSG m;
    PeekMessageW(&m, nullptr, 0, 0, PM_NOREMOVE);  // make sure this thread has a queue
    PostThreadMessageW(GetCurrentThreadId(), WM_USER, 0, 0);
    CHECK(w.wait(500) == LoopWait::Message);
    while (PeekMessageW(&m, nullptr, 0, 0, PM_REMOVE)) {}
    CloseHandle(a);
    CloseHandle(c);
}

int main() {
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::printf("FAIL WSAStartup\n");
        return 1;
    }
    testMapping();
    testMrm1Wake();
    testTimerResolution();
    WSACleanup();
    std::printf("%d PASS, %d FAIL\n", gPasses, gFailures);
    if (gFailures) return 1;
    std::printf("LOOP WAIT TEST OK\n");
    return 0;
}
