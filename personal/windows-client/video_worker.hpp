// Decode and present on their own thread, so a slow decoder call (seen as
// ~450 ms stalls in ProcessInput) never freezes the input loop. Header-only
// so the console test (loop_wait_test.cpp) runs the same code as the viewer.
//
// Threads:
// - Main thread (window messages, input, UDP receive, VideoReceiver): calls
//   pushFrame / pushReset / requestRepaint. These only take a short lock and
//   never wait for the decoder.
// - Worker thread: owns the sink (VideoPipeline) after start(): decode,
//   present, repaint, the swap chain latency wait and finish().
//
// Order: frames and resets go through one FIFO, so the decoder sees exactly
// the order VideoReceiver produced (keyframe / NACK logic is unchanged).
// A backlog is decoded in order and only the newest picture is shown, as
// before. Past maxFrames / maxBytes queued (a stall much longer than a
// second) the queued frames are dropped and a keyframe is requested; frames
// are then dropped until a keyframe, which goes in as a discontinuity.
//
// Shutdown: stopAndWait() lets the worker finish what is queued, call
// finish() and exit, while the caller keeps pumping window messages (DXGI
// may send messages to the window thread while presenting).
#pragma once

#include <windows.h>
#include <objbase.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#pragma comment(lib, "ole32.lib")

namespace jl {

// What the worker drives. Every call happens on the worker thread.
struct VideoWorkerSink {
    virtual ~VideoWorkerSink() = default;
    virtual void submit(uint64_t fid, const std::vector<uint8_t>& frame, bool discontinuity, bool keyFrame) = 0;
    virtual void resetForNewStream() = 0;
    virtual void repaint() = 0;
    virtual void servicePresent() = 0;
    virtual bool presentPending() = 0;
    virtual HANDLE presentWaitHandle() = 0;
    virtual void onPresentWaitSignaled() = 0;
    // After each round of work: publish counters for the main thread.
    virtual void published() {}
    virtual void finish() = 0;
};

struct VideoWorkerConfig {
    size_t maxFrames = 120;            // about 2 s at 60 fps
    size_t maxBytes = 64u << 20;       // queued frame bytes
    DWORD idleWaitMs = 16;             // nothing queued, nothing pending
    size_t rerequestEvery = 30;        // dropped frames between keyframe requests
};

class VideoWorker {
public:
    VideoWorker(VideoWorkerSink& sink, VideoWorkerConfig cfg,
                std::function<void()> requestKeyframe,
                std::function<void(const std::string&)> log)
        : sink_(sink), cfg_(cfg), requestKeyframe_(std::move(requestKeyframe)), log_(std::move(log)) {
        wake_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        done_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    }
    ~VideoWorker() {
        stopAndWait();
        if (wake_) CloseHandle(wake_);
        if (done_) CloseHandle(done_);
    }
    VideoWorker(const VideoWorker&) = delete;
    VideoWorker& operator=(const VideoWorker&) = delete;

    void start() {
        if (thread_.joinable() || !wake_ || !done_) return;
        thread_ = std::thread([this] { run(); });
    }

    // Main thread. Never waits for the decoder.
    void pushFrame(uint64_t fid, std::vector<uint8_t> frame, bool discontinuity, bool keyFrame) {
        bool request = false;
        std::string note;
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (stopRequested_) return;
            if (dropUntilKey_) {
                if (!keyFrame) {
                    ++overflowDrops_;
                    request = cfg_.rerequestEvery && (++dropsSinceRequest_ % cfg_.rerequestEvery) == 0;
                    if (request) note = "video.queue_keyframe_rerequest dropped=" + std::to_string(dropsSinceRequest_);
                } else {
                    dropUntilKey_ = false;
                    discontinuity = true;
                    note = "video.queue_keyframe_resumed fid=" + std::to_string(fid);
                }
            } else if (queuedFrames_ >= cfg_.maxFrames || queuedBytes_ + frame.size() > cfg_.maxBytes) {
                uint64_t dropped = 0;
                for (auto it = q_.begin(); it != q_.end();) {
                    if (it->kind == Cmd::Frame) { ++dropped; it = q_.erase(it); } else ++it;
                }
                overflowDrops_ += dropped;
                queuedFrames_ = 0;
                queuedBytes_ = 0;
                ++overflows_;
                note = "video.queue_overflow dropped=" + std::to_string(dropped) + " fid=" + std::to_string(fid);
                if (!keyFrame) {
                    dropUntilKey_ = true;
                    dropsSinceRequest_ = 1;
                    ++overflowDrops_;
                    request = true;
                } else {
                    discontinuity = true;
                }
            }
            if (!dropUntilKey_) {
                Cmd c;
                c.kind = Cmd::Frame;
                c.fid = fid;
                c.disc = discontinuity;
                c.key = keyFrame;
                c.queued = std::chrono::steady_clock::now();
                queuedBytes_ += frame.size();
                c.data = std::move(frame);
                q_.push_back(std::move(c));
                ++queuedFrames_;
                if (queuedFrames_ > maxDepth_) maxDepth_ = queuedFrames_;
            }
        }
        if (!note.empty() && log_) log_(note);
        if (request && requestKeyframe_) requestKeyframe_();
        SetEvent(wake_);
    }

    void pushReset() {
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (stopRequested_) return;
            Cmd c;
            c.kind = Cmd::Reset;
            q_.push_back(std::move(c));
        }
        SetEvent(wake_);
    }

    // Coalesced: one repaint after whatever is queued now.
    void requestRepaint() {
        repaint_.store(true);
        SetEvent(wake_);
    }

    // The worker ended by itself because the sink threw (e.g. HEVC with
    // no CPU fallback). The main loop rethrows the message.
    bool failed() const { return failed_.load(); }
    std::string error() const {
        std::lock_guard<std::mutex> lk(mu_);
        return error_;
    }

    // Decode everything that is queued, then finish() and exit. The pump
    // runs while waiting (window messages); default: PeekMessage loop.
    void stopAndWait(const std::function<void()>& pump = {}) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            stopRequested_ = true;
        }
        if (!thread_.joinable()) return;
        SetEvent(wake_);
        for (;;) {
            const DWORD w = MsgWaitForMultipleObjects(1, &done_, FALSE, INFINITE, QS_ALLINPUT);
            if (w == WAIT_OBJECT_0) break;
            if (w == WAIT_OBJECT_0 + 1) {
                if (pump) pump();
                else defaultPump();
                continue;
            }
            break;  // WAIT_FAILED: fall through to join
        }
        thread_.join();
        if (sawQuit_) PostQuitMessage(quitCode_);
    }

    // Samples since the last take (main thread, for the 5 s stats line).
    void takeSamples(std::vector<float>& decodeMs, std::vector<float>& queueWaitMs) {
        std::lock_guard<std::mutex> lk(mu_);
        decodeMs.insert(decodeMs.end(), decodeMs_.begin(), decodeMs_.end());
        queueWaitMs.insert(queueWaitMs.end(), queueWaitMs_.begin(), queueWaitMs_.end());
        decodeMs_.clear();
        queueWaitMs_.clear();
    }
    size_t queuedFrames() const { std::lock_guard<std::mutex> lk(mu_); return queuedFrames_; }
    size_t maxDepth() const { std::lock_guard<std::mutex> lk(mu_); return maxDepth_; }
    // Max depth since the previous call (window value for the stats line).
    size_t takeWindowMaxDepth() {
        std::lock_guard<std::mutex> lk(mu_);
        const size_t v = std::max(windowMaxDepth_, queuedFrames_);
        windowMaxDepth_ = queuedFrames_;
        return v;
    }
    uint64_t overflows() const { std::lock_guard<std::mutex> lk(mu_); return overflows_; }
    uint64_t overflowDrops() const { std::lock_guard<std::mutex> lk(mu_); return overflowDrops_; }
    uint64_t framesSubmitted() const { return submitted_.load(); }

private:
    struct Cmd {
        enum Kind { Frame, Reset } kind = Frame;
        uint64_t fid = 0;
        bool disc = false, key = false;
        std::vector<uint8_t> data;
        std::chrono::steady_clock::time_point queued{};
    };

    void defaultPump() {
        MSG m{};
        while (PeekMessageW(&m, nullptr, 0, 0, PM_REMOVE)) {
            if (m.message == WM_QUIT) { sawQuit_ = true; quitCode_ = int(m.wParam); continue; }
            TranslateMessage(&m);
            DispatchMessageW(&m);
        }
    }

    void record(std::vector<float>& v, float ms) {
        // Capped; the main thread takes them every 5 s.
        if (v.size() < (1u << 16)) v.push_back(ms);
    }

    void run() {
        const HRESULT co = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        try {
            std::deque<Cmd> batch;
            for (;;) {
                bool stop = false;
                {
                    std::lock_guard<std::mutex> lk(mu_);
                    batch.swap(q_);
                    if (queuedFrames_ > windowMaxDepth_) windowMaxDepth_ = queuedFrames_;
                    queuedFrames_ = 0;
                    queuedBytes_ = 0;
                    stop = stopRequested_;
                }
                for (auto& c : batch) {
                    if (c.kind == Cmd::Reset) {
                        sink_.resetForNewStream();
                        continue;
                    }
                    // The latency object may have signalled since the last
                    // service (while we waited on wake_, or while the previous
                    // frame of this batch decoded). Show the pending frame
                    // now; otherwise the decoder's next output replaces it and
                    // it counts as a busy drop. Non-blocking.
                    if (sink_.presentPending()) sink_.servicePresent();
                    const auto t0 = std::chrono::steady_clock::now();
                    sink_.submit(c.fid, c.data, c.disc, c.key);
                    const auto t1 = std::chrono::steady_clock::now();
                    ++submitted_;
                    std::lock_guard<std::mutex> lk(mu_);
                    record(decodeMs_, std::chrono::duration<float, std::milli>(t1 - t0).count());
                    record(queueWaitMs_, std::chrono::duration<float, std::milli>(t0 - c.queued).count());
                }
                batch.clear();
                if (repaint_.exchange(false)) sink_.repaint();
                if (stop) break;
                sink_.servicePresent();
                sink_.published();
                {
                    std::lock_guard<std::mutex> lk(mu_);
                    if (!q_.empty() || stopRequested_) continue;
                }
                const HANDLE presentWait = sink_.presentWaitHandle();
                HANDLE hs[2] = {wake_, presentWait};
                const DWORD n = presentWait ? 2 : 1;
                // A pending frame without a latency object to wait on: poll.
                const DWORD ms = (sink_.presentPending() && !presentWait) ? 1 : cfg_.idleWaitMs;
                if (WaitForMultipleObjects(n, hs, FALSE, ms) == WAIT_OBJECT_0 + 1) {
                    sink_.onPresentWaitSignaled();
                }
            }
            sink_.finish();
            sink_.published();
        } catch (const std::exception& e) {
            {
                std::lock_guard<std::mutex> lk(mu_);
                error_ = e.what();
                stopRequested_ = true;
                q_.clear();
            }
            failed_.store(true);
        } catch (...) {
            {
                std::lock_guard<std::mutex> lk(mu_);
                error_ = "unknown video worker failure";
                stopRequested_ = true;
                q_.clear();
            }
            failed_.store(true);
        }
        if (SUCCEEDED(co)) CoUninitialize();
        SetEvent(done_);
    }

    VideoWorkerSink& sink_;
    VideoWorkerConfig cfg_;
    std::function<void()> requestKeyframe_;
    std::function<void(const std::string&)> log_;
    HANDLE wake_ = nullptr;
    HANDLE done_ = nullptr;
    std::thread thread_;
    mutable std::mutex mu_;
    std::deque<Cmd> q_;
    size_t queuedFrames_ = 0, queuedBytes_ = 0, maxDepth_ = 0, windowMaxDepth_ = 0;
    bool stopRequested_ = false;
    bool dropUntilKey_ = false;
    uint64_t dropsSinceRequest_ = 0;
    uint64_t overflows_ = 0, overflowDrops_ = 0;
    std::vector<float> decodeMs_, queueWaitMs_;
    std::string error_;
    std::atomic<bool> repaint_{false};
    std::atomic<bool> failed_{false};
    std::atomic<uint64_t> submitted_{0};
    bool sawQuit_ = false;
    int quitCode_ = 0;
};

}  // namespace jl
