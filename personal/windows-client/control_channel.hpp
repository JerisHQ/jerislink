#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include "conn_auth.hpp"
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <deque>
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
        if (async_) {
            // A reconnect still running finishes on its own and closes
            // its socket (it shares only `async_`).
            std::lock_guard<std::mutex> g(async_->m);
            async_->stopping = true;
            async_->queue.clear();
        }
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

    // Once the session runs: a lost connection is re-made (TCP connect and
    // the connection password, up to a few seconds) on a background thread,
    // so a key or mouse event never waits for it on the UI thread, which
    // also presents the video. Events sent meanwhile wait in a short queue
    // (kQueueMax, kQueueMaxAgeMs) and go out in order once it is back.
    // Startup (ping, video negotiation) stays synchronous.
    void setBackgroundReconnect(bool on) {
        if (on == bool(async_)) return;
        if (on) {
            async_ = std::make_shared<Async>();
            async_->s = s_;
            s_ = INVALID_SOCKET;
        } else {
            std::shared_ptr<Async> a = std::move(async_);
            std::lock_guard<std::mutex> g(a->m);
            a->stopping = true;
            a->queue.clear();
            closeSocket(a->s);
        }
    }

    struct ReconnectStats {
        uint64_t reconnects = 0;   // background reconnects that succeeded
        uint64_t queued = 0;       // events that waited for one
        uint64_t flushed = 0;      // of those, sent once connected
        uint64_t dropped = 0;      // too old, queue full, or the attempt halted
        bool connecting = false;
    };
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
    static SOCKET openSocket(const std::string& localIp, const std::string& remoteIp, uint16_t port,
                             DWORD ioTimeoutMs, jl::auth::Channel authChannel) {
        // One connection at a time may answer a challenge (conn_auth.hpp).
        const auto slot = jl::auth::connectSlot();
        if (!jl::auth::mayConnect()) return INVALID_SOCKET;
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) return INVALID_SOCKET;
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

    // Shared with the background reconnect thread, which may outlive us.
    struct Queued {
        std::vector<uint8_t> bytes;
        std::chrono::steady_clock::time_point at;
    };
    struct Async {
        std::mutex m;
        SOCKET s = INVALID_SOCKET;
        bool connecting = false;
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

    static void enqueueLocked(Async& a, std::vector<uint8_t> b, std::chrono::steady_clock::time_point now) {
        while (!a.queue.empty() && now - a.queue.front().at > std::chrono::milliseconds(kQueueMaxAgeMs)) {
            a.queue.pop_front();
            ++a.stats.dropped;
        }
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

    // UI thread. Sends at once when connected; otherwise queues the event and
    // starts one background reconnect. Never waits for TCP connect or AUTH.
    bool sendQueued(std::vector<uint8_t> b) {
        std::shared_ptr<Async> a = async_;
        std::lock_guard<std::mutex> g(a->m);
        if (a->s != INVALID_SOCKET) {
            if (sendAllOn(a->s, b)) return true;
            closeSocket(a->s);
        }
        if (!jl::auth::mayConnect()) {
            // The attempt ended (wrong password, lockout...): nothing to wait for.
            a->stats.dropped += a->queue.size() + 1;
            a->queue.clear();
            return false;
        }
        const auto now = std::chrono::steady_clock::now();
        enqueueLocked(*a, std::move(b), now);
        if (!a->connecting && now >= a->nextTry) {
            a->connecting = true;
            std::thread([a, localIp = localIp_, remoteIp = remoteIp_, port = port_,
                         timeout = ioTimeoutMs_, ch = authChannel_] {
                SOCKET s = openSocket(localIp, remoteIp, port, timeout, ch);
                std::lock_guard<std::mutex> lk(a->m);
                a->connecting = false;
                if (a->stopping) { closeSocket(s); return; }
                if (s == INVALID_SOCKET) {
                    // The queue waits for the next event's attempt (or ages out).
                    a->nextTry = std::chrono::steady_clock::now() + std::chrono::milliseconds(kRetryGapMs);
                    if (!jl::auth::mayConnect()) {
                        a->stats.dropped += a->queue.size();
                        a->queue.clear();
                    }
                    return;
                }
                const auto t = std::chrono::steady_clock::now();
                while (!a->queue.empty()) {
                    Queued& q = a->queue.front();
                    if (t - q.at > std::chrono::milliseconds(kQueueMaxAgeMs)) {
                        ++a->stats.dropped;
                    } else if (sendAllOn(s, q.bytes)) {
                        ++a->stats.flushed;
                    } else {
                        closeSocket(s);
                        break;
                    }
                    a->queue.pop_front();
                }
                if (s != INVALID_SOCKET) {
                    closeSocket(a->s);
                    a->s = s;
                    ++a->stats.reconnects;
                }
            }).detach();
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
    uint64_t sentEvents_ = 0;
    uint64_t failures_ = 0;
};
