#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

struct VideoConfigResult {
    bool negotiated = false;
    bool streamRestarted = false;
    bool hostSupportsHevc = false;
    bool codecFallback = false;
    std::string codec = "h264";
    uint16_t bitrateMbps = 25;
    uint16_t remoteWidth = 0;
    uint16_t remoteHeight = 0;
};

class ControlChannel {
public:
    ControlChannel(std::string localIp, std::string remoteIp, uint16_t port)
        : localIp_(std::move(localIp)), remoteIp_(std::move(remoteIp)), port_(port) {}
    ~ControlChannel() { close(); }

    void close() {
        if (s_ != INVALID_SOCKET) {
            shutdown(s_, SD_BOTH);
            closesocket(s_);
            s_ = INVALID_SOCKET;
        }
    }

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

    void setIoTimeoutMs(DWORD timeoutMs) {
        ioTimeoutMs_ = timeoutMs ? timeoutMs : 1;
        if (s_ != INVALID_SOCKET) {
            setsockopt(s_, SOL_SOCKET, SO_SNDTIMEO,
                       reinterpret_cast<const char*>(&ioTimeoutMs_), sizeof(ioTimeoutMs_));
            setsockopt(s_, SOL_SOCKET, SO_RCVTIMEO,
                       reinterpret_cast<const char*>(&ioTimeoutMs_), sizeof(ioTimeoutMs_));
        }
    }

    VideoConfigResult negotiateVideo(
        const std::string& requestedCodec,
        bool clientH264,
        bool clientHevc,
        uint16_t requestedBitrateMbps) {
        VideoConfigResult result;
        uint8_t codec = 0;
        if (requestedCodec == "h264") codec = 1;
        else if (requestedCodec == "hevc") codec = 2;
        else if (requestedCodec != "auto") return result;

        uint8_t caps = 0;
        if (clientH264) caps |= 0x01;
        if (clientHevc) caps |= 0x02;
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
        result.codec = selected == 2 ? "hevc" : "h264";
        result.bitrateMbps = bitrate;
        if (reply.size() >= 10 && (flags & 0x08) != 0) {
            result.remoteWidth = uint16_t((uint16_t(reply[6]) << 8) | reply[7]);
            result.remoteHeight = uint16_t((uint16_t(reply[8]) << 8) | reply[9]);
        }
        return result;
    }

    bool connected() const { return s_ != INVALID_SOCKET; }
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

    bool ensureConnected() {
        if (s_ != INVALID_SOCKET) return true;
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) return false;
        BOOL noDelay = TRUE;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&noDelay), sizeof(noDelay));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&ioTimeoutMs_), sizeof(ioTimeoutMs_));
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&ioTimeoutMs_), sizeof(ioTimeoutMs_));
        sockaddr_in local{};
        local.sin_family = AF_INET;
        local.sin_port = 0;
        if (inet_pton(AF_INET, localIp_.c_str(), &local.sin_addr) != 1 ||
            bind(s, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
            closesocket(s); return false;
        }
        sockaddr_in remote{};
        remote.sin_family = AF_INET;
        remote.sin_port = htons(port_);
        if (inet_pton(AF_INET, remoteIp_.c_str(), &remote.sin_addr) != 1) {
            closesocket(s); return false;
        }

        u_long nonBlocking = 1;
        if (ioctlsocket(s, FIONBIO, &nonBlocking) != 0) {
            closesocket(s); return false;
        }
        int rc = connect(s, reinterpret_cast<sockaddr*>(&remote), sizeof(remote));
        if (rc == SOCKET_ERROR) {
            int e = WSAGetLastError();
            if (e != WSAEWOULDBLOCK && e != WSAEINPROGRESS && e != WSAEINVAL) {
                closesocket(s); return false;
            }
            fd_set writeSet, errorSet;
            FD_ZERO(&writeSet); FD_ZERO(&errorSet);
            FD_SET(s, &writeSet); FD_SET(s, &errorSet);
            timeval tv{};
            tv.tv_sec = static_cast<long>(ioTimeoutMs_ / 1000);
            tv.tv_usec = static_cast<long>((ioTimeoutMs_ % 1000) * 1000);
            rc = select(0, nullptr, &writeSet, &errorSet, &tv);
            if (rc <= 0 || FD_ISSET(s, &errorSet)) {
                closesocket(s); return false;
            }
            int soError = 0;
            int soLen = sizeof(soError);
            if (getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soError), &soLen) != 0 || soError != 0) {
                closesocket(s); return false;
            }
        }
        nonBlocking = 0;
        if (ioctlsocket(s, FIONBIO, &nonBlocking) != 0) {
            closesocket(s); return false;
        }
        s_ = s;
        return true;
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
    uint64_t sentEvents_ = 0;
    uint64_t failures_ = 0;
};
