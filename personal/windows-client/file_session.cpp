#include "file_session.hpp"

#include "file_proto.hpp"

#include <windows.h>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <utility>

namespace {
constexpr int kAckTimeoutMs = 2000;
constexpr int kPingIntervalMs = 15000;
constexpr int kPollMs = 250;
constexpr int kBackoffMinMs = 1000;
constexpr int kBackoffMaxMs = 30000;

enum class Outcome { ConnectFailed, NoAck, Closed, Stopped };

std::string hex4(uint16_t v) {
    char buf[8];
    std::snprintf(buf, sizeof(buf), "%04x", unsigned(v));
    return buf;
}
}  // namespace

FileSession::FileSession(std::string localIp, std::string remoteIp, uint16_t port, LogFn logFn)
    : localIp_(std::move(localIp)), remoteIp_(std::move(remoteIp)), port_(port), logFn_(std::move(logFn)) {}

FileSession::~FileSession() {
    stop();
}

void FileSession::start() {
    if (worker_.joinable()) return;
    stopRequested_ = false;
    worker_ = std::thread([this] { run(); });
}

void FileSession::stop() {
    {
        std::lock_guard<std::mutex> lock(wakeMutex_);
        stopRequested_ = true;
    }
    wake_.notify_all();
    if (worker_.joinable()) worker_.join();
}

void FileSession::log(const std::string& message) const {
    if (logFn_) logFn_(message);
}

bool FileSession::sleepFor(int ms) {
    std::unique_lock<std::mutex> lock(wakeMutex_);
    wake_.wait_for(lock, std::chrono::milliseconds(ms), [this] { return stopRequested_.load(); });
    return !stopRequested_;
}

void FileSession::closeSocket(SOCKET& s) {
    if (s != INVALID_SOCKET) {
        shutdown(s, SD_BOTH);
        closesocket(s);
        s = INVALID_SOCKET;
    }
}

// Same connect as ClipboardChannel: bound to the tailnet address, 250 ms
// non-blocking connect, then blocking I/O with a send/receive guard.
SOCKET FileSession::connectSocket() {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    BOOL noDelay = TRUE;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&noDelay), sizeof(noDelay));
    DWORD ioTimeoutMs = kAckTimeoutMs;
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&ioTimeoutMs), sizeof(ioTimeoutMs));
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&ioTimeoutMs), sizeof(ioTimeoutMs));

    sockaddr_in local{};
    local.sin_family = AF_INET;
    if (inet_pton(AF_INET, localIp_.c_str(), &local.sin_addr) != 1 ||
        bind(s, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    sockaddr_in remote{};
    remote.sin_family = AF_INET;
    remote.sin_port = htons(port_);
    if (inet_pton(AF_INET, remoteIp_.c_str(), &remote.sin_addr) != 1) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    u_long nonBlocking = 1;
    if (ioctlsocket(s, FIONBIO, &nonBlocking) != 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    int rc = connect(s, reinterpret_cast<sockaddr*>(&remote), sizeof(remote));
    if (rc == SOCKET_ERROR) {
        const int e = WSAGetLastError();
        if (e != WSAEWOULDBLOCK && e != WSAEINPROGRESS && e != WSAEINVAL) {
            closesocket(s);
            return INVALID_SOCKET;
        }
        fd_set writeSet, errorSet;
        FD_ZERO(&writeSet);
        FD_ZERO(&errorSet);
        FD_SET(s, &writeSet);
        FD_SET(s, &errorSet);
        timeval tv{};
        tv.tv_usec = 250000;
        rc = select(0, nullptr, &writeSet, &errorSet, &tv);
        if (rc <= 0 || FD_ISSET(s, &errorSet)) {
            closesocket(s);
            return INVALID_SOCKET;
        }
        int soError = 0;
        int soLen = sizeof(soError);
        if (getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soError), &soLen) != 0 || soError != 0) {
            closesocket(s);
            return INVALID_SOCKET;
        }
    }
    nonBlocking = 0;
    if (ioctlsocket(s, FIONBIO, &nonBlocking) != 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

bool FileSession::waitReadable(SOCKET s, int ms) {
    fd_set readSet;
    FD_ZERO(&readSet);
    FD_SET(s, &readSet);
    timeval tv{};
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    return select(0, &readSet, nullptr, nullptr, &tv) > 0;
}

bool FileSession::sendAll(SOCKET s, const uint8_t* data, size_t size) {
    size_t offset = 0;
    while (offset < size) {
        const int n = send(s, reinterpret_cast<const char*>(data + offset), static_cast<int>(size - offset), 0);
        if (n <= 0) return false;
        offset += static_cast<size_t>(n);
    }
    return true;
}

bool FileSession::recvExact(SOCKET s, uint8_t* data, size_t size) {
    size_t offset = 0;
    while (offset < size) {
        const int n = recv(s, reinterpret_cast<char*>(data + offset), static_cast<int>(size - offset), 0);
        if (n <= 0) return false;
        offset += static_cast<size_t>(n);
    }
    return true;
}

bool FileSession::sendPacket(SOCKET s, uint8_t type, const std::vector<uint8_t>& payload) {
    if (payload.size() > jl::file::kMaxPayload) return false;
    const uint16_t len = static_cast<uint16_t>(payload.size());
    std::vector<uint8_t> packet{'M', 'R', 'C', '1', 1, type, uint8_t(len >> 8), uint8_t(len)};
    packet.insert(packet.end(), payload.begin(), payload.end());
    return sendAll(s, packet.data(), packet.size());
}

bool FileSession::recvPacket(SOCKET s, uint8_t& type, std::vector<uint8_t>& payload) {
    uint8_t header[8]{};
    if (!recvExact(s, header, sizeof(header))) return false;
    if (header[0] != 'M' || header[1] != 'R' || header[2] != 'C' || header[3] != '1' || header[4] != 1) return false;
    const uint16_t len = uint16_t((uint16_t(header[6]) << 8) | header[7]);
    if (len > jl::file::kMaxPayload) return false;
    type = header[5];
    payload.assign(len, 0);
    return len == 0 || recvExact(s, payload.data(), len);
}

void FileSession::run() {
    int backoffMs = kBackoffMinMs;
    while (!stopRequested_) {
        SOCKET s = connectSocket();
        Outcome outcome = Outcome::ConnectFailed;
        if (s != INVALID_SOCKET) {
            using namespace jl::file;
            const auto hello = encode(Hello{kVersion, caps::kViewer});
            if (hello && sendPacket(s, type::kHello, *hello)) {
                outcome = Outcome::NoAck;
                // Wait for HELLO_ACK in short slices so stop() is prompt.
                const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(kAckTimeoutMs);
                bool acked = false;
                while (!stopRequested_ && !acked && std::chrono::steady_clock::now() < deadline) {
                    if (!waitReadable(s, kPollMs)) continue;
                    uint8_t t = 0;
                    std::vector<uint8_t> p;
                    if (!recvPacket(s, t, p)) break;
                    const auto msg = decode(t, p);
                    const HelloAck* ack = msg ? std::get_if<HelloAck>(&*msg) : nullptr;
                    if (!ack || ack->proto < 1) break;
                    acked = true;
                    hostCaps_ = ack->caps;
                }
                if (stopRequested_) outcome = Outcome::Stopped;
                else if (acked) outcome = Outcome::Closed;
            }
            if (outcome == Outcome::Closed) {
                ++sessions_;
                backoffMs = kBackoffMinMs;
                if (capability() != Capability::Yes) {
                    capability_ = static_cast<int>(Capability::Yes);
                    log("file.capability=yes caps=0x" + hex4(hostCaps_.load()));
                }
                // Keepalive: PING every 15 s; the next PING finds the last
                // one unanswered only if the host stopped answering.
                std::string reason = "peer_closed";
                auto lastPing = std::chrono::steady_clock::now();
                uint32_t token = 0;
                bool outstanding = false;
                while (true) {
                    if (stopRequested_) { reason = "stopping"; outcome = Outcome::Stopped; break; }
                    if (std::chrono::steady_clock::now() - lastPing >= std::chrono::milliseconds(kPingIntervalMs)) {
                        if (outstanding) { reason = "ping_timeout"; break; }
                        ++token;
                        const auto ping = encode(Ping{{uint8_t(token >> 24), uint8_t(token >> 16), uint8_t(token >> 8), uint8_t(token)}});
                        if (!ping || !sendPacket(s, type::kPing, *ping)) { reason = "send_failed"; break; }
                        ++pings_;
                        outstanding = true;
                        lastPing = std::chrono::steady_clock::now();
                    }
                    if (!waitReadable(s, kPollMs)) continue;
                    uint8_t t = 0;
                    std::vector<uint8_t> p;
                    if (!recvPacket(s, t, p)) break;
                    const auto msg = decode(t, p);
                    if (!msg) { reason = "malformed"; break; }
                    if (const Ping* pong = std::get_if<Ping>(&*msg)) {
                        const uint32_t got = (uint32_t(pong->token[0]) << 24) | (uint32_t(pong->token[1]) << 16) |
                                             (uint32_t(pong->token[2]) << 8) | uint32_t(pong->token[3]);
                        if (got == token) outstanding = false;
                    }
                    // F1: nothing else is expected yet; anything well-formed is ignored.
                }
                log("file.session=closed reason=" + reason);
            }
            closeSocket(s);
        }

        if (outcome == Outcome::Stopped) break;
        if (outcome == Outcome::NoAck) {
            // An old host ignores 0x50 and keeps the socket open; a new host
            // that refused us closed it. Either way, do not probe again in
            // this viewer session.
            capability_ = static_cast<int>(Capability::No);
            log("file.capability=no");
            break;
        }
        if (!sleepFor(backoffMs)) break;
        backoffMs = std::min(backoffMs * 2, kBackoffMaxMs);
    }
}
