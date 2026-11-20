#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include "conn_auth.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

struct VideoConfigResult {
    bool negotiated = false;
    bool streamRestarted = false;
    bool hostSupportsHevc = false;
    bool codecFallback = false;
    bool hostSupportsNack = false;  // ACK flag 0x20: host keeps a frame cache and answers MRM1 0x41
    bool hostSupportsAbr = false;   // ACK flag 0x40: host adapts its bitrate to MRM1 0x42 reports
    bool hostSupportsAudio = false; // ACK flag 0x80: host streams MRA1 audio on an MRM1 0x45 request
    std::string codec = "h264";
    uint16_t bitrateMbps = 25;
    uint16_t remoteWidth = 0;
    uint16_t remoteHeight = 0;
};

class ControlChannel {
public:
    ControlChannel(std::string localIp, std::string remoteIp, uint16_t port)
        : localIp_(std::move(localIp)), remoteIp_(std::move(remoteIp)), port_(port) {}
    ~ControlChannel() {
        stop();
        close();
    }

    void close() {
        if (async_) {
            std::lock_guard<std::mutex> g(async_->m);
            closeSocket(async_->s);
            return;
        }
        closeSocket(s_);
    }

    // Ends background reconnects: cancels a connect or AUTH in progress
    // (shutdown of its socket), drops what is still queued and joins the
    // worker thread. Returns how long the join took, in ms (-1: there was no
    // worker). After this no thread of ours uses a socket, so Winsock may be
    // cleaned up. Safe to call more than once.
    double stop() {
        std::shared_ptr<Async> a = async_;
        if (!a) return -1.0;
        const auto t0 = std::chrono::steady_clock::now();
        {
            std::lock_guard<std::mutex> g(a->m);
            a->stopping = true;
            a->stats.dropped += a->queue.size();
            a->queue.clear();
            if (a->pending != INVALID_SOCKET) shutdown(a->pending, SD_BOTH);
        }
        a->cv.notify_all();
        if (a->worker.joinable()) a->worker.join();
        const double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
        std::lock_guard<std::mutex> g(a->m);
        if (!a->stats.joined) {
            a->stats.joined = true;
            a->stats.joinMs = ms;
        }
        return a->stats.joinMs;
    }

    // Once the session runs: a lost connection is re-made (TCP connect and
    // the connection password, up to a few seconds) on a background thread,
    // so a key or mouse event never waits for it on the UI thread, which
    // also presents the video. Events sent meanwhile wait in a short queue
    // (kQueueMax, kQueueMaxAgeMs) and go out in order once it is back.
    // Startup (ping, video negotiation) stays synchronous.
    //
    // Threads: the send methods, close(), stop() and discardQueuedInput()
    // are called from one thread (the viewer's UI thread). One worker thread
    // per channel makes the connections. Neither holds the shared lock while
    // a socket call runs: the UI sends on the live socket only while no
    // reconnect runs, and the worker connects and flushes on its own socket,
    // handing it over (under the lock) once the queue is empty.
    void setBackgroundReconnect(bool on) {
        if (on == bool(async_)) return;
        if (on) {
            auto a = std::make_shared<Async>();
            a->s = s_;
            s_ = INVALID_SOCKET;
            a->worker = std::thread(workerLoop, a, localIp_, remoteIp_, port_, ioTimeoutMs_, authChannel_);
            async_ = std::move(a);
        } else {
            stop();
            std::shared_ptr<Async> a = std::move(async_);
            std::lock_guard<std::mutex> g(a->m);
            closeSocket(a->s);
        }
    }

    struct ReconnectStats {
        uint64_t reconnects = 0;   // background reconnects that succeeded
        uint64_t queued = 0;       // events that waited for one
        uint64_t flushed = 0;      // of those, sent once connected
        uint64_t dropped = 0;      // too old, queue full, discarded, or the attempt halted
        uint64_t discarded = 0;    // of those, dropped because the viewer lost focus
        uint64_t positioned = 0;   // queued clicks given their pointer position
        bool connecting = false;
        bool joined = false;       // stop() joined the worker
        double joinMs = 0.0;
    };

    // The viewer lost focus: input still waiting for a reconnect is stale
    // (the user is elsewhere) and must not reach the Mac later. Returns how
    // many events were dropped.
    size_t discardQueuedInput() {
        if (!async_) return 0;
        std::lock_guard<std::mutex> g(async_->m);
        const size_t n = async_->queue.size();
        async_->queue.clear();
        async_->stats.dropped += n;
        async_->stats.discarded += n;
        return n;
    }

    // The pointer position (MRC1 0x24 units) the viewer last showed the
    // Mac, by UDP or TCP. A click that has to wait for a reconnect is
    // queued right after this position, so it lands where it was made,
    // not wherever the Mac cursor is when the queue is flushed.
    void notePointer(uint16_t nx, uint16_t ny) {
        lastPointer_.store((uint64_t(1) << 32) | (uint64_t(nx) << 16) | uint64_t(ny), std::memory_order_relaxed);
    }
    ReconnectStats reconnectStats() const {
        if (!async_) return {};
        std::lock_guard<std::mutex> g(async_->m);
        ReconnectStats r = async_->stats;
        r.connecting = async_->connecting;
        return r;
    }

    static constexpr size_t kQueueMax = 256;
    static constexpr int kQueueMaxAgeMs = 3000;
    static constexpr int kRetryGapMs = 250;

    bool ping(double* rttMs = nullptr) {
        const uint32_t seq = 0x4d523031;
        std::vector<uint8_t> p{
            uint8_t(seq >> 24), uint8_t(seq >> 16), uint8_t(seq >> 8), uint8_t(seq)};
        auto t0 = std::chrono::steady_clock::now();
        if (!sendPacket(0x01, p)) return false;
        uint8_t h[8]{};
        if (!recvExact(h, sizeof(h))) { close(); return false; }
        uint16_t len = uint16_t((uint16_t(h[6]) << 8) | h[7]);
        std::vector<uint8_t> reply(len);
        if (len && !recvExact(reply.data(), len)) { close(); return false; }
        bool ok = h[0]=='M' && h[1]=='R' && h[2]=='C' && h[3]=='1' && h[4]==1 && h[5]==0x02 && reply==p;
        if (ok && rttMs) {
            *rttMs = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now()-t0).count();
        }
        if (!ok) close();
        return ok;
    }

    bool sendKey(bool down, uint16_t semantic) {
        return sendPacketRetry(0x10, {uint8_t(down ? 1 : 0), uint8_t(semantic >> 8), uint8_t(semantic)});
    }

    bool sendMouseMove(int16_t dx, int16_t dy) {
        std::vector<uint8_t> p;
        putI16(p, dx); putI16(p, dy);
        return sendPacketRetry(0x20, p);
    }

    bool sendMouseMoveAbsolute(uint16_t x, uint16_t y) {
        std::vector<uint8_t> p;
        putU16(p, x); putU16(p, y);
        return sendPacketRetry(0x23, p);
    }

    bool sendMouseMoveNormalized(uint16_t nx, uint16_t ny) {
        std::vector<uint8_t> p;
        putU16(p, nx); putU16(p, ny);
        return sendPacketRetry(0x24, p);
    }

    bool sendMouseButton(uint8_t button, bool down) {
        return sendPacketRetry(0x21, {button, uint8_t(down ? 1 : 0)});
    }

    bool sendMouseButtonExtended(uint8_t button, bool down, uint8_t clickCount) {
        return sendPacketRetry(0x25, {button, uint8_t(down ? 1 : 0), clickCount});
    }

    bool sendScroll(int16_t dx, int16_t dy) {
        std::vector<uint8_t> p;
        putI16(p, dx); putI16(p, dy);
        return sendPacketRetry(0x22, p);
    }

    // FORCE_QUIT_OPEN, empty payload: the host opens the Mac's Force Quit
    // Applications window (Apple menu > Force Quit, through Accessibility).
    static constexpr uint8_t kForceQuitOpenType = 0x60;
    bool sendForceQuitOpen() {
        return sendPacketRetry(kForceQuitOpenType, {});
    }

    void setIoTimeoutMs(DWORD timeoutMs) {
        ioTimeoutMs_ = timeoutMs ? timeoutMs : 1;
        std::unique_lock<std::mutex> g;
        SOCKET* sp = &s_;
        if (async_) { g = std::unique_lock<std::mutex>(async_->m); sp = &async_->s; }
        if (*sp != INVALID_SOCKET) {
            setsockopt(*sp, SOL_SOCKET, SO_SNDTIMEO,
                       reinterpret_cast<const char*>(&ioTimeoutMs_), sizeof(ioTimeoutMs_));
            setsockopt(*sp, SOL_SOCKET, SO_RCVTIMEO,
                       reinterpret_cast<const char*>(&ioTimeoutMs_), sizeof(ioTimeoutMs_));
        }
    }

    VideoConfigResult negotiateVideo(
        const std::string& requestedCodec,
        bool clientH264,
        bool clientHevc,
        uint16_t requestedBitrateMbps,
        bool clientAudio = false) {
        VideoConfigResult result;
        uint8_t codec = 0;
        if (requestedCodec == "h264") codec = 1;
        else if (requestedCodec == "hevc") codec = 2;
        else if (requestedCodec != "auto") return result;

        uint8_t caps = 0;
        if (clientH264) caps |= 0x01;
        if (clientHevc) caps |= 0x02;
        // 0x04: this viewer wants audio. Informational for the host log; the
        // audio itself starts with MRM1 0x45 on the video process.
        if (clientAudio) caps |= 0x04;
        std::vector<uint8_t> payload{
            1,
            codec,
            caps,
            0,
            uint8_t(requestedBitrateMbps >> 8),
            uint8_t(requestedBitrateMbps)
        };

        if (!sendPacket(0x40, payload)) {
            close();
            return result;
        }

        // Applying a new video configuration can synchronously stop the old
        // Host before ACK so the client never feeds old-codec packets into a
        // newly selected decoder. Allow more time than the low-latency input
        // path's normal 100 ms receive timeout for this one control exchange.
        const DWORD previousTimeoutMs = ioTimeoutMs_;
        DWORD configTimeoutMs = std::max<DWORD>(1500, previousTimeoutMs);
        setsockopt(s_, SOL_SOCKET, SO_RCVTIMEO,
                   reinterpret_cast<const char*>(&configTimeoutMs),
                   sizeof(configTimeoutMs));

        uint8_t h[8]{};
        if (!recvExact(h, sizeof(h))) {
            close();
            return result;
        }
        uint16_t len = uint16_t((uint16_t(h[6]) << 8) | h[7]);
        std::vector<uint8_t> reply(len);
        if (len && !recvExact(reply.data(), len)) {
            close();
            return result;
        }
        DWORD normalTimeoutMs = previousTimeoutMs;
        setsockopt(s_, SOL_SOCKET, SO_RCVTIMEO,
                   reinterpret_cast<const char*>(&normalTimeoutMs),
                   sizeof(normalTimeoutMs));
        if (!(h[0]=='M' && h[1]=='R' && h[2]=='C' && h[3]=='1' &&
              h[4]==1 && h[5]==0x41 &&
              (reply.size()==6 || reply.size()==10) && reply[0]==1)) {
            close();
            return result;
        }

        const uint8_t status = reply[1];
        const uint8_t selected = reply[2];
        const uint8_t flags = reply[3];
        const uint16_t bitrate = uint16_t((uint16_t(reply[4]) << 8) | reply[5]);
        if (status != 0 || (selected != 1 && selected != 2) ||
            (selected == 2 && !clientHevc)) {
            return result;
        }

        result.negotiated = true;
        result.streamRestarted = (flags & 0x01) != 0;
        result.hostSupportsHevc = (flags & 0x02) != 0;
        result.codecFallback = (flags & 0x04) != 0;
        result.hostSupportsNack = (flags & 0x20) != 0;
        result.hostSupportsAbr = (flags & 0x40) != 0;
        result.hostSupportsAudio = (flags & 0x80) != 0;
        result.codec = selected == 2 ? "hevc" : "h264";
        result.bitrateMbps = bitrate;
        if (reply.size() >= 10 && (flags & 0x08) != 0) {
            result.remoteWidth = uint16_t((uint16_t(reply[6]) << 8) | reply[7]);
            result.remoteHeight = uint16_t((uint16_t(reply[8]) << 8) | reply[9]);
        }
        return result;
    }

    // The AUTH channel this connection proves (design §5). Control by
    // default; the launch screen check uses Ping.
    void setAuthChannel(jl::auth::Channel c) { authChannel_ = c; }

    bool connected() const {
        if (async_) {
            std::lock_guard<std::mutex> g(async_->m);
            return async_->s != INVALID_SOCKET;
        }
        return s_ != INVALID_SOCKET;
    }
    uint64_t sentEvents() const { return sentEvents_; }
    uint64_t failures() const { return failures_; }

private:
    static void putI16(std::vector<uint8_t>& p, int16_t v) {
        uint16_t u = static_cast<uint16_t>(v);
        p.push_back(uint8_t(u >> 8)); p.push_back(uint8_t(u));
    }

    static void putU16(std::vector<uint8_t>& p, uint16_t v) {
        p.push_back(uint8_t(v >> 8)); p.push_back(uint8_t(v));
    }

    static void closeSocket(SOCKET& s) {
        if (s != INVALID_SOCKET) {
            shutdown(s, SD_BOTH);
            closesocket(s);
            s = INVALID_SOCKET;
        }
    }

    bool ensureConnected() {
        if (s_ != INVALID_SOCKET) return true;
        s_ = openSocket(localIp_, remoteIp_, port_, ioTimeoutMs_, authChannel_);
        return s_ != INVALID_SOCKET;
    }

    // TCP connect, then the connection password (v0.4.0) before the first
    // message. Blocking: the UI thread only reaches it at startup.
    // `onSocket` (the background worker) is told the socket while it is
    // being connected, so stop() can cut it short, and INVALID_SOCKET just
    // before it is closed here; returning false aborts the attempt.
    static SOCKET openSocket(const std::string& localIp, const std::string& remoteIp, uint16_t port,
                             DWORD ioTimeoutMs, jl::auth::Channel authChannel,
                             const std::function<bool(SOCKET)>& onSocket = {}) {
        // One connection at a time may answer a challenge (conn_auth.hpp).
        const auto slot = jl::auth::connectSlot();
        if (!jl::auth::mayConnect()) return INVALID_SOCKET;
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) return INVALID_SOCKET;
        if (onSocket && !onSocket(s)) { closesocket(s); return INVALID_SOCKET; }
        auto closesocket = [&onSocket](SOCKET x) {
            if (onSocket) onSocket(INVALID_SOCKET);
            return ::closesocket(x);
        };
        BOOL noDelay = TRUE;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&noDelay), sizeof(noDelay));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&ioTimeoutMs), sizeof(ioTimeoutMs));
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&ioTimeoutMs), sizeof(ioTimeoutMs));
        sockaddr_in local{};
        local.sin_family = AF_INET;
        local.sin_port = 0;
        if (inet_pton(AF_INET, localIp.c_str(), &local.sin_addr) != 1 ||
            bind(s, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
            closesocket(s); return INVALID_SOCKET;
        }
        sockaddr_in remote{};
        remote.sin_family = AF_INET;
        remote.sin_port = htons(port);
        if (inet_pton(AF_INET, remoteIp.c_str(), &remote.sin_addr) != 1) {
            closesocket(s); return INVALID_SOCKET;
        }

        u_long nonBlocking = 1;
        if (ioctlsocket(s, FIONBIO, &nonBlocking) != 0) {
            closesocket(s); return INVALID_SOCKET;
        }
        const auto connectStart = jl::auth::Clock::now();
        int rc = connect(s, reinterpret_cast<sockaddr*>(&remote), sizeof(remote));
        if (rc == SOCKET_ERROR) {
            int e = WSAGetLastError();
            if (e != WSAEWOULDBLOCK && e != WSAEINPROGRESS && e != WSAEINVAL) {
                closesocket(s); return INVALID_SOCKET;
            }
            fd_set writeSet, errorSet;
            FD_ZERO(&writeSet); FD_ZERO(&errorSet);
            FD_SET(s, &writeSet); FD_SET(s, &errorSet);
            timeval tv{};
            tv.tv_sec = static_cast<long>(ioTimeoutMs / 1000);
            tv.tv_usec = static_cast<long>((ioTimeoutMs % 1000) * 1000);
            rc = select(0, nullptr, &writeSet, &errorSet, &tv);
            if (rc <= 0 || FD_ISSET(s, &errorSet)) {
                closesocket(s); return INVALID_SOCKET;
            }
            int soError = 0;
            int soLen = sizeof(soError);
            if (getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soError), &soLen) != 0 || soError != 0) {
                closesocket(s); return INVALID_SOCKET;
            }
        }
        nonBlocking = 0;
        if (ioctlsocket(s, FIONBIO, &nonBlocking) != 0) {
            closesocket(s); return INVALID_SOCKET;
        }
        // v0.4.0: prove the connection password before the first message.
        if (!jl::auth::gate(s, authChannel, jl::auth::msSince(connectStart))) {
            closesocket(s); return INVALID_SOCKET;
        }
        return s;
    }

    // Shared by the UI thread and the worker thread.
    struct Queued {
        std::vector<uint8_t> bytes;
        std::chrono::steady_clock::time_point at;
    };
    struct Async {
        std::mutex m;
        std::condition_variable cv;
        std::thread worker;
        SOCKET s = INVALID_SOCKET;        // live connection (UI sends on it)
        SOCKET pending = INVALID_SOCKET;  // being connected by the worker
        bool connecting = false;          // a reconnect is asked for or running
        bool wake = false;                // the worker should start one
        bool stopping = false;
        std::chrono::steady_clock::time_point nextTry{};
        std::deque<Queued> queue;
        ReconnectStats stats;
    };

    static bool sendAllOn(SOCKET s, const std::vector<uint8_t>& b) {
        size_t off = 0;
        while (off < b.size()) {
            int r = send(s, reinterpret_cast<const char*>(b.data() + off), static_cast<int>(b.size() - off), 0);
            if (r <= 0) return false;
            off += static_cast<size_t>(r);
        }
        return true;
    }

    static bool isMouseMove(const std::vector<uint8_t>& b) {
        return b.size() > 5 && (b[5] == 0x23 || b[5] == 0x24);
    }
    static bool isMouseButton(const std::vector<uint8_t>& b) {
        return b.size() > 5 && (b[5] == 0x21 || b[5] == 0x25);
    }

    static void dropAgedLocked(Async& a, std::chrono::steady_clock::time_point now) {
        while (!a.queue.empty() && now - a.queue.front().at > std::chrono::milliseconds(kQueueMaxAgeMs)) {
            a.queue.pop_front();
            ++a.stats.dropped;
        }
    }

    static void enqueueLocked(Async& a, std::vector<uint8_t> b, std::chrono::steady_clock::time_point now) {
        dropAgedLocked(a, now);
        // Only the latest absolute pointer position matters.
        if (isMouseMove(b) && !a.queue.empty() && isMouseMove(a.queue.back().bytes) &&
            a.queue.back().bytes[5] == b[5]) {
            a.queue.back() = Queued{std::move(b), now};
            return;
        }
        if (a.queue.size() >= kQueueMax) {
            a.queue.pop_front();
            ++a.stats.dropped;
        }
        a.queue.push_back(Queued{std::move(b), now});
        ++a.stats.queued;
    }

    // The worker: one per channel, joined by stop(). Waits for a request,
    // connects (TCP and AUTH, without the lock), then sends the queue one
    // event at a time (lock only to pop) and hands the socket to the UI.
    static void workerLoop(std::shared_ptr<Async> a, std::string localIp, std::string remoteIp, uint16_t port,
                           DWORD timeout, jl::auth::Channel ch) {
        const auto onSocket = [a](SOCKET x) {
            std::lock_guard<std::mutex> g(a->m);
            if (x != INVALID_SOCKET && a->stopping) return false;
            a->pending = x;
            return true;
        };
        std::unique_lock<std::mutex> lk(a->m);
        for (;;) {
            a->cv.wait(lk, [&] { return a->stopping || a->wake; });
            if (a->stopping) break;
            a->wake = false;
            lk.unlock();
            SOCKET s = openSocket(localIp, remoteIp, port, timeout, ch, onSocket);
            lk.lock();
            a->pending = INVALID_SOCKET;
            if (a->stopping) { closeSocket(s); break; }
            if (s == INVALID_SOCKET) {
                // The queue waits for the next event's attempt (or ages out).
                a->connecting = false;
                a->nextTry = std::chrono::steady_clock::now() + std::chrono::milliseconds(kRetryGapMs);
                if (!jl::auth::mayConnect()) {
                    a->stats.dropped += a->queue.size();
                    a->queue.clear();
                }
                continue;
            }
            bool alive = true;
            while (!a->stopping) {
                dropAgedLocked(*a, std::chrono::steady_clock::now());
                if (a->queue.empty()) break;
                Queued q = std::move(a->queue.front());
                a->queue.pop_front();
                lk.unlock();
                const bool ok = sendAllOn(s, q.bytes);
                lk.lock();
                if (ok) { ++a->stats.flushed; continue; }
                ++a->stats.dropped;
                alive = false;
                break;
            }
            if (a->stopping) { closeSocket(s); break; }
            a->connecting = false;
            if (!alive) {
                closeSocket(s);
                a->nextTry = std::chrono::steady_clock::now() + std::chrono::milliseconds(kRetryGapMs);
                continue;
            }
            closeSocket(a->s);
            a->s = s;
            ++a->stats.reconnects;
        }
    }

    // UI thread. Sends at once when connected and nothing waits ahead of
    // it; otherwise queues the event and asks the worker for a reconnect.
    // Never waits for TCP connect or AUTH, and never sends under the lock.
    bool sendQueued(std::vector<uint8_t> b) {
        std::shared_ptr<Async> a = async_;
        SOCKET live = INVALID_SOCKET;
        {
            std::lock_guard<std::mutex> g(a->m);
            if (a->stopping) return false;
            if (!a->connecting && a->queue.empty()) live = a->s;
        }
        if (live != INVALID_SOCKET) {
            // Only this thread uses or closes a->s while no reconnect runs.
            if (sendAllOn(live, b)) return true;
            std::lock_guard<std::mutex> g(a->m);
            if (a->s == live) closeSocket(a->s);
        }
        std::lock_guard<std::mutex> g(a->m);
        if (a->stopping) return false;
        if (!jl::auth::mayConnect()) {
            // The attempt ended (wrong password, lockout...): nothing to wait for.
            a->stats.dropped += a->queue.size() + 1;
            a->queue.clear();
            return false;
        }
        const auto now = std::chrono::steady_clock::now();
        const uint64_t ptr = lastPointer_.load(std::memory_order_relaxed);
        if (isMouseButton(b) && (ptr >> 32)) {
            // The pointer moves by UDP; the click waits here for TCP. Put
            // its position right in front of it.
            enqueueLocked(*a, packet(0x24, {uint8_t(ptr >> 24), uint8_t(ptr >> 16),
                                            uint8_t(ptr >> 8), uint8_t(ptr)}), now);
            ++a->stats.positioned;
        }
        enqueueLocked(*a, std::move(b), now);
        if (!a->connecting && now >= a->nextTry) {
            a->connecting = true;
            a->wake = true;
            a->cv.notify_all();
        }
        return false;
    }

    std::vector<uint8_t> packet(uint8_t type, const std::vector<uint8_t>& payload) const {
        uint16_t n = static_cast<uint16_t>(payload.size());
        std::vector<uint8_t> b{'M','R','C','1',1,type,uint8_t(n >> 8),uint8_t(n)};
        b.insert(b.end(), payload.begin(), payload.end());
        return b;
    }

    bool sendAll(const uint8_t* p, size_t n) {
        size_t off = 0;
        while (off < n) {
            int r = send(s_, reinterpret_cast<const char*>(p + off), static_cast<int>(n-off), 0);
            if (r <= 0) return false;
            off += static_cast<size_t>(r);
        }
        return true;
    }

    bool recvExact(uint8_t* p, size_t n) {
        size_t off = 0;
        while (off < n) {
            int r = recv(s_, reinterpret_cast<char*>(p+off), static_cast<int>(n-off), 0);
            if (r <= 0) return false;
            off += static_cast<size_t>(r);
        }
        return true;
    }

    bool sendPacket(uint8_t type, const std::vector<uint8_t>& payload) {
        if (!ensureConnected()) return false;
        auto b = packet(type, payload);
        if (!sendAll(b.data(), b.size())) { close(); return false; }
        return true;
    }

    bool sendPacketRetry(uint8_t type, const std::vector<uint8_t>& payload) {
        if (async_) {
            if (sendQueued(packet(type, payload))) { ++sentEvents_; return true; }
            ++failures_;
            return false;
        }
        if (sendPacket(type, payload)) { ++sentEvents_; return true; }
        ++failures_;
        close();
        if (sendPacket(type, payload)) { ++sentEvents_; return true; }
        ++failures_;
        return false;
    }

    std::string localIp_, remoteIp_;
    uint16_t port_;
    SOCKET s_ = INVALID_SOCKET;
    DWORD ioTimeoutMs_ = 100;
    jl::auth::Channel authChannel_ = jl::auth::Channel::Control;
    std::shared_ptr<Async> async_;
    std::atomic<uint64_t> lastPointer_{0};  // 1 << 32 | nx << 16 | ny once known
    uint64_t sentEvents_ = 0;
    uint64_t failures_ = 0;
};
