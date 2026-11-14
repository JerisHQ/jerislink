// Console test for loop_wait.hpp (the viewer receive loop's wait set).
// 1. Timer resolution: how long a 1 ms and a 5 ms wait really sleep,
//    without and with ScopedTimerResolution (before/after numbers).
// 2. MRM1 wake: a pong arriving on the MRM1 socket wakes the loop at once
//    when its event is in the wait set; the old set (video + present only)
//    sleeps until the timeout (negative test).
// 3. Event semantics the viewer relies on: reset + drain leaves no
//    spurious wake; a datagram left unread re-signals the event.
// 4. Null handles are skipped and results map back to the right source.
// 5. video_worker.hpp: a stalled decoder does not block the main loop;
//    order, overflow -> keyframe, failure, latency wait, clean stop.
// 6. present_scheduler.hpp: max frame latency 2 vs 1 under a jittery
//    50 fps arrival pattern (busy drops before/after, added queue time),
//    and a hidden window holds the newest frame without busy drops.
#include "loop_wait.hpp"
#include "present_scheduler.hpp"
#include "video_worker.hpp"

#include <ws2tcpip.h>

#include <algorithm>
#include <deque>
#include <chrono>
#include <cstdio>
#include <mutex>
#include <stdexcept>
#include <string>
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

// ---- video_worker.hpp: decode/present thread ----

// A pipeline stand-in: records what it is asked to do, can block in
// submit (a stalled decoder) and can throw.
struct FakeSink : VideoWorkerSink {
    std::mutex mu;
    std::vector<std::string> calls;
    DWORD stallMs = 0;
    uint64_t stallFid = 0;
    HANDLE entered = CreateEventW(nullptr, TRUE, FALSE, nullptr);  // set when stallFid starts
    HANDLE release = nullptr;  // if set, submit of stallFid waits for it
    uint64_t throwFid = 0;
    HANDLE presentHandle = nullptr;
    bool pending = false;
    int presentSignals = 0, repaints = 0, finishes = 0, publishes = 0;
    HWND finishSendTo = nullptr;  // finish() SendMessage()s here (DXGI-like)

    ~FakeSink() override { CloseHandle(entered); }
    void submit(uint64_t fid, const std::vector<uint8_t>& frame, bool disc, bool key) override {
        if (fid == throwFid) throw std::runtime_error("decoder exploded");
        if (fid == stallFid) {
            SetEvent(entered);
            if (release) WaitForSingleObject(release, 5000);
            if (stallMs) Sleep(stallMs);
        }
        std::lock_guard<std::mutex> lk(mu);
        calls.push_back("F" + std::to_string(fid) + (disc ? "d" : "") + (key ? "k" : "") +
                        ":" + std::to_string(frame.size()));
    }
    void resetForNewStream() override { std::lock_guard<std::mutex> lk(mu); calls.push_back("R"); }
    void repaint() override { std::lock_guard<std::mutex> lk(mu); ++repaints; }
    void servicePresent() override {}
    bool presentPending() override { return pending; }
    HANDLE presentWaitHandle() override { return presentHandle; }
    void onPresentWaitSignaled() override { std::lock_guard<std::mutex> lk(mu); ++presentSignals; pending = false; }
    void published() override { std::lock_guard<std::mutex> lk(mu); ++publishes; }
    void finish() override {
        if (finishSendTo) SendMessageW(finishSendTo, WM_USER + 7, 0, 0);
        std::lock_guard<std::mutex> lk(mu);
        ++finishes;
        calls.push_back("finish");
    }
    std::string joined() {
        std::lock_guard<std::mutex> lk(mu);
        std::string s;
        for (const auto& c : calls) { if (!s.empty()) s += ' '; s += c; }
        return s;
    }
};

static std::vector<uint8_t> bytes(size_t n) { return std::vector<uint8_t>(n, 0xAB); }

// The point of the thread: a decoder stuck for 500 ms (as seen in the field)
// must not hold up the main loop. Pushing frames and handling a window
// message stay fast while the worker is stuck; the frames are then
// decoded in order.
static void testWorkerInputNotBlockedByDecode() {
    FakeSink sink;
    sink.stallFid = 2;
    sink.stallMs = 500;
    VideoWorker w(sink, VideoWorkerConfig{}, nullptr, nullptr);
    w.start();
    w.pushFrame(1, bytes(10), true, true);
    w.pushFrame(2, bytes(10), false, false);
    CHECK(WaitForSingleObject(sink.entered, 2000) == WAIT_OBJECT_0);  // worker is now stuck
    double worstPushMs = 0;
    const auto t0 = Clock::now();
    for (uint64_t f = 3; f <= 20; ++f) {
        const auto p0 = Clock::now();
        w.pushFrame(f, bytes(1000), false, false);
        worstPushMs = std::max(worstPushMs, msSince(p0));
    }
    // An input message posted now is seen by the main loop at once.
    MSG m;
    PeekMessageW(&m, nullptr, 0, 0, PM_NOREMOVE);
    PostThreadMessageW(GetCurrentThreadId(), WM_KEYDOWN, 'A', 0);
    LoopWait lw;
    const auto m0 = Clock::now();
    CHECK(lw.wait(100) == LoopWait::Message);
    const double messageMs = msSince(m0);
    while (PeekMessageW(&m, nullptr, 0, 0, PM_REMOVE)) {}
    const double mainMs = msSince(t0);
    std::printf("worker: decode stalled 500 ms; main thread: 18 pushes worst %.3f ms, "
                "message seen after %.3f ms, total %.3f ms\n", worstPushMs, messageMs, mainMs);
    CHECK(worstPushMs < 5.0);
    CHECK(messageMs < 20.0);
    CHECK(mainMs < 100.0);  // the stall is 500 ms
    w.stopAndWait();
    std::string want = "F1dk:10 F2:10";
    for (int f = 3; f <= 20; ++f) want += " F" + std::to_string(f) + ":1000";
    want += " finish";
    CHECK(sink.joined() == want);
    CHECK(w.framesSubmitted() == 20);
    std::vector<float> dec, wait;
    w.takeSamples(dec, wait);
    CHECK(dec.size() == 20);
    CHECK(!dec.empty() && *std::max_element(dec.begin(), dec.end()) >= 450.0f);
    CHECK(!wait.empty() && *std::max_element(wait.begin(), wait.end()) >= 400.0f);
    CHECK(w.overflows() == 0);
}

// Frames and stream resets keep the order the receiver produced.
static void testWorkerOrder() {
    FakeSink sink;
    VideoWorker w(sink, VideoWorkerConfig{}, nullptr, nullptr);
    w.start();
    w.pushReset();
    w.pushFrame(1, bytes(3), true, true);
    w.pushFrame(2, bytes(4), false, false);
    w.pushReset();
    w.pushFrame(9, bytes(5), true, true);
    w.stopAndWait();
    CHECK(sink.joined() == "R F1dk:3 F2:4 R F9dk:5 finish");
    CHECK(sink.finishes == 1);
    // Nothing is accepted after stop.
    w.pushFrame(10, bytes(1), false, false);
    w.pushReset();
    w.stopAndWait();  // second stop is a no-op
    CHECK(sink.joined() == "R F1dk:3 F2:4 R F9dk:5 finish");
    CHECK(sink.finishes == 1);
}

// A stall far past the queue cap: the queue is dropped, a keyframe is
// requested and frames are dropped until one comes; it goes in as a
// discontinuity. Resets queued meanwhile are kept.
static void testWorkerOverflowToKeyframe() {
    FakeSink sink;
    sink.stallFid = 1;
    sink.release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    int keyRequests = 0;
    std::vector<std::string> logs;
    VideoWorkerConfig cfg;
    cfg.maxFrames = 4;
    cfg.rerequestEvery = 3;
    VideoWorker w(sink, cfg, [&] { ++keyRequests; }, [&](const std::string& s) { logs.push_back(s); });
    w.start();
    w.pushFrame(1, bytes(1), true, true);
    CHECK(WaitForSingleObject(sink.entered, 2000) == WAIT_OBJECT_0);
    for (uint64_t f = 2; f <= 5; ++f) w.pushFrame(f, bytes(1), false, false);
    CHECK(w.queuedFrames() == 4);
    w.pushReset();
    w.pushFrame(6, bytes(1), false, false);  // overflow: 2..5 and 6 dropped
    CHECK(w.overflows() == 1);
    CHECK(keyRequests == 1);
    CHECK(w.queuedFrames() == 0);
    w.pushFrame(7, bytes(1), false, false);  // dropped (2 since request)
    CHECK(keyRequests == 1);
    w.pushFrame(8, bytes(1), false, false);  // dropped (3): asks again
    CHECK(keyRequests == 2);
    w.pushFrame(9, bytes(1), false, true);   // keyframe: back in, as a discontinuity
    w.pushFrame(10, bytes(1), false, false);
    CHECK(w.overflowDrops() == 7);
    SetEvent(sink.release);
    w.stopAndWait();
    CHECK(sink.joined() == "F1dk:1 R F9dk:1 F10:1 finish");
    CHECK(!logs.empty() && logs.front().find("video.queue_overflow dropped=4") == 0);
    CloseHandle(sink.release);
}

// A sink exception (HEVC with no CPU fallback) ends the worker; the main
// loop sees failed() and the message, finish() is not called, and pushes
// after that are ignored without blocking.
static void testWorkerFailure() {
    FakeSink sink;
    sink.throwFid = 3;
    VideoWorker w(sink, VideoWorkerConfig{}, nullptr, nullptr);
    w.start();
    for (uint64_t f = 1; f <= 5; ++f) w.pushFrame(f, bytes(2), f == 1, f == 1);
    const auto t0 = Clock::now();
    while (!w.failed() && msSince(t0) < 2000) Sleep(1);
    CHECK(w.failed());
    CHECK(w.error() == "decoder exploded");
    w.pushFrame(6, bytes(2), false, false);
    w.stopAndWait();
    CHECK(sink.finishes == 0);
    CHECK(sink.joined() == "F1dk:2 F2:2");
}

// The worker waits on the swap chain latency object and tells the sink
// when it fired; a repaint request reaches the sink.
static void testWorkerPresentWaitAndRepaint() {
    FakeSink sink;
    HANDLE latency = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    sink.presentHandle = latency;
    sink.pending = true;
    VideoWorker w(sink, VideoWorkerConfig{}, nullptr, nullptr);
    w.start();
    SetEvent(latency);
    w.requestRepaint();
    const auto t0 = Clock::now();
    for (;;) {
        {
            std::lock_guard<std::mutex> lk(sink.mu);
            if (sink.presentSignals >= 1 && sink.repaints >= 1) break;
        }
        if (msSince(t0) > 2000) break;
        Sleep(1);
    }
    w.stopAndWait();
    CHECK(sink.presentSignals >= 1);
    CHECK(sink.repaints >= 1);
    CHECK(sink.publishes >= 1);
    CloseHandle(latency);
}

// A sink that drives the real LatestFramePresenter, with an auto-reset event
// standing in for the swap chain's frame latency object (max latency 1).
// Presenter state is touched only on the worker thread; the test reads it
// after stopAndWait().
struct PresenterSink : VideoWorkerSink {
    HANDLE latency = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    HANDLE entered = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    HANDLE release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    uint64_t holdFid = 0;         // submit of this frame waits for `release`
    uint64_t vblankAfterFid = 0;  // latency object signals right after this frame decodes
    uint64_t newest = 0;
    std::vector<uint64_t> shown;
    LatestFramePresenter presenter{makeOps()};

    ~PresenterSink() override { CloseHandle(latency); CloseHandle(entered); CloseHandle(release); }
    PresentOps makeOps() {
        PresentOps ops;
        ops.latencyReady = [this] { return WaitForSingleObject(latency, 0) == WAIT_OBJECT_0; };
        ops.render = [] {};
        ops.present = [this] { shown.push_back(newest); return PresentResult::Ok; };
        ops.nowMs = [] { return 0.0; };  // never hit the 50 ms latency cap
        return ops;
    }
    void submit(uint64_t fid, const std::vector<uint8_t>&, bool, bool) override {
        if (fid == holdFid) {
            SetEvent(entered);
            WaitForSingleObject(release, 5000);
        }
        newest = fid;
        presenter.onDecoded();
        if (fid == vblankAfterFid) SetEvent(latency);
    }
    void resetForNewStream() override { presenter.clear(); }
    void repaint() override { presenter.onRepaint(); }
    void servicePresent() override { presenter.service(); }
    bool presentPending() override { return presenter.wantsService(); }  // as HardwareVideoPipeline
    HANDLE presentWaitHandle() override { return presenter.waitingForLatency() ? latency : nullptr; }
    void onPresentWaitSignaled() override { presenter.onLatencySignalled(); }
    void published() override {}
    void finish() override {}
};

// Field regression after F2 (busy drops ~10 % of decoded frames instead of
// ~0.1 %): frame 1 waits for the latency object, the object signals, and
// frame 2 is decoded before the worker serviced that signal. The presenter
// then replaces frame 1 although it could have been shown. The worker must
// service a ready present before it hands the next frame to the decoder.
static void testWorkerServicesReadyPresentBeforeNextFrame() {
    PresenterSink sink;
    SetEvent(sink.latency);  // the first frame can be shown at once
    sink.holdFid = 100;
    sink.vblankAfterFid = 1;
    VideoWorker w(sink, VideoWorkerConfig{}, nullptr, nullptr);
    w.start();
    // Frame 100 holds the worker so frames 1 and 2 are queued back to back.
    w.pushFrame(100, bytes(1), true, true);
    CHECK(WaitForSingleObject(sink.entered, 2000) == WAIT_OBJECT_0);
    w.pushFrame(1, bytes(1), false, false);
    w.pushFrame(2, bytes(1), false, false);
    SetEvent(sink.release);
    const auto t0 = Clock::now();
    while (w.framesSubmitted() < 3 && msSince(t0) < 2000) Sleep(1);
    Sleep(20);
    w.stopAndWait();
    const PresentCounters& c = sink.presenter.counters();
    std::string shown;
    for (uint64_t f : sink.shown) shown += (shown.empty() ? "" : " ") + std::to_string(f);
    std::printf("worker: ready present before next frame: decoded=%llu presented=%llu busy_drops=%llu shown=[%s]\n",
                static_cast<unsigned long long>(c.decoded), static_cast<unsigned long long>(c.presented),
                static_cast<unsigned long long>(c.busyDrops), shown.c_str());
    CHECK(c.decoded == 3);
    CHECK(c.busyDrops == 0);
    CHECK(c.presented == 2);
    CHECK(shown == "100 1");
    CHECK(sink.presenter.pending());  // frame 2 waits for the next vblank
}

// Simulated swap chain with max frame latency N on a 60 Hz display:
// a present is allowed while fewer than N presented frames wait for the
// screen; every vblank shows (retires) one of them. Frames arrive at
// 50 fps, and every 10th frame a 40 ms network hiccup delivers three
// frames within 4 ms (a burst). Returns the counters and the average time
// a presented frame waited for its vblank.
struct LatencySimResult {
    PresentCounters c;
    double avgQueueMs = 0.0;
    double maxQueueMs = 0.0;
};
static LatencySimResult simulateLatency(int maxLatency) {
    int queued = 0;
    std::deque<double> presentTimes;
    double now = 0.0;
    double queueSum = 0.0, queueMax = 0.0;
    uint64_t shownCount = 0;
    PresentOps ops;
    ops.latencyReady = [&] { return queued < maxLatency; };
    ops.render = [] {};
    ops.present = [&] {
        ++queued;
        presentTimes.push_back(now);
        return PresentResult::Ok;
    };
    ops.nowMs = [] { return 0.0; };  // never hit the 50 ms latency cap
    LatestFramePresenter p(ops);

    // Arrival times: every 20 ms, but frames 10k+8 and 10k+9 are late
    // and arrive with frame 10k+10 (burst of three, 2 ms apart).
    std::vector<double> arrivals;
    for (int i = 0; i < 3000; ++i) {
        double t = i * 20.0;
        const int m = i % 10;
        if (m == 8) t = (i + 2) * 20.0 - 4.0;
        if (m == 9) t = (i + 1) * 20.0 - 2.0;
        arrivals.push_back(t);
    }
    std::sort(arrivals.begin(), arrivals.end());
    const double vblank = 1000.0 / 60.0;
    double nextVblank = vblank;
    size_t ai = 0;
    while (ai < arrivals.size()) {
        if (nextVblank <= arrivals[ai]) {
            now = nextVblank;
            if (queued > 0) {
                --queued;
                const double waited = now - presentTimes.front();
                presentTimes.pop_front();
                queueSum += waited;
                queueMax = std::max(queueMax, waited);
                ++shownCount;
            }
            p.service();
            nextVblank += vblank;
        } else {
            now = arrivals[ai++];
            p.onDecoded();
        }
    }
    LatencySimResult r;
    r.c = p.counters();
    r.avgQueueMs = shownCount ? queueSum / static_cast<double>(shownCount) : 0.0;
    r.maxQueueMs = queueMax;
    return r;
}

// G2 field log: ~50 fps content, focused fullscreen, presented 41-43 fps
// with 43-50 busy drops per 5 s. Latency 2 lets a short burst through;
// the cost is up to one extra refresh of queue time on those frames.
static void testPresenterLatency2AbsorbsBursts() {
    const LatencySimResult l1 = simulateLatency(1);
    const LatencySimResult l2 = simulateLatency(2);
    for (int i = 0; i < 2; ++i) {
        const LatencySimResult& r = i ? l2 : l1;
        std::printf("presenter: max_frame_latency=%d decoded=%llu presented=%llu busy_drops=%llu "
                    "queue_ms_avg=%.2f queue_ms_max=%.2f\n",
                    i ? 2 : 1, static_cast<unsigned long long>(r.c.decoded),
                    static_cast<unsigned long long>(r.c.presented),
                    static_cast<unsigned long long>(r.c.busyDrops), r.avgQueueMs, r.maxQueueMs);
    }
    CHECK(l1.c.decoded == 3000 && l2.c.decoded == 3000);
    CHECK(l1.c.busyDrops >= 100);      // a burst of three often loses one
    CHECK(l2.c.busyDrops == 0);
    CHECK(l2.c.presented >= 2999);     // the last frame may still be pending
    // The extra queue time stays within one 60 Hz refresh on average.
    CHECK(l2.avgQueueMs - l1.avgQueueMs < 1000.0 / 60.0);
    CHECK(l2.maxQueueMs <= 2.0 * 1000.0 / 60.0 + 0.01);
}

// Minimized / occluded: nothing is rendered or presented, replaced frames
// are hidden drops (not busy drops), the worker is not asked to poll, and
// the newest frame is shown once the window is visible again.
static void testPresenterHiddenHoldsNewest() {
    int renders = 0;
    uint64_t newest = 0;
    std::vector<uint64_t> shown;
    PresentOps ops;
    ops.latencyReady = [] { return true; };
    ops.render = [&] { ++renders; };
    ops.present = [&] { shown.push_back(newest); return PresentResult::Ok; };
    ops.nowMs = [] { return 0.0; };
    LatestFramePresenter p(ops);
    newest = 1;
    p.onDecoded();
    CHECK(shown.size() == 1 && renders == 1);
    p.setHidden(true);
    for (uint64_t f = 2; f <= 6; ++f) {
        newest = f;
        p.onDecoded();
    }
    p.onRepaint();
    CHECK(p.service());   // still pending
    CHECK(renders == 1);
    CHECK(shown.size() == 1);
    CHECK(p.counters().busyDrops == 0);
    CHECK(p.counters().hiddenDrops == 4);  // 2..5 replaced, 6 waits
    CHECK(p.pending() && !p.wantsService() && !p.waitingForLatency());
    p.setHidden(false);
    CHECK(p.wantsService());
    CHECK(!p.service());
    CHECK(shown.size() == 2 && shown.back() == 6);
    CHECK(renders == 2);
    CHECK(p.counters().presented == 2);
    CHECK(p.counters().busyDrops == 0);
}

static int gSentToMain = 0;
static LRESULT CALLBACK workerTestWndProc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_USER + 7) { ++gSentToMain; return 0; }
    return DefWindowProcW(h, msg, wp, lp);
}

// Shutdown while the worker needs the main thread (DXGI can send window
// messages from Present/ResizeBuffers): stopAndWait keeps pumping, so the
// worker's SendMessage completes instead of deadlocking.
static void testWorkerStopPumpsMessages() {
    WNDCLASSW wc{};
    wc.lpfnWndProc = workerTestWndProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = L"JerislinkWorkerTest";
    RegisterClassW(&wc);
    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"", 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, wc.hInstance, nullptr);
    CHECK(hwnd != nullptr);
    FakeSink sink;
    sink.finishSendTo = hwnd;
    gSentToMain = 0;
    {
        VideoWorker w(sink, VideoWorkerConfig{}, nullptr, nullptr);
        w.start();
        w.pushFrame(1, bytes(1), true, true);
        const auto t0 = Clock::now();
        w.stopAndWait();
        std::printf("worker: stop with a SendMessage to the main thread took %.3f ms\n", msSince(t0));
    }
    CHECK(gSentToMain == 1);
    CHECK(sink.finishes == 1);
    // The destructor alone also stops cleanly (exception path in the viewer).
    FakeSink sink2;
    sink2.finishSendTo = hwnd;
    {
        VideoWorker w(sink2, VideoWorkerConfig{}, nullptr, nullptr);
        w.start();
        w.pushFrame(1, bytes(1), true, true);
    }
    CHECK(gSentToMain == 2);
    CHECK(sink2.finishes == 1);
    DestroyWindow(hwnd);
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
    testWorkerInputNotBlockedByDecode();
    testWorkerOrder();
    testWorkerOverflowToKeyframe();
    testWorkerFailure();
    testWorkerPresentWaitAndRepaint();
    testWorkerServicesReadyPresentBeforeNextFrame();
    testPresenterLatency2AbsorbsBursts();
    testPresenterHiddenHoldsNewest();
    testWorkerStopPumpsMessages();
    WSACleanup();
    std::printf("%d PASS, %d FAIL\n", gPasses, gFailures);
    if (gFailures) return 1;
    std::printf("LOOP WAIT TEST OK\n");
    return 0;
}
