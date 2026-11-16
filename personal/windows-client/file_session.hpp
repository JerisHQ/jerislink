#pragma once

// File session (F1): a probe on its own TCP connection to the control port.
// It sends FILE_HELLO, waits up to 2 s for HELLO_ACK and logs
// file.capability=yes|no. With a capable host it keeps the session open with
// a PING every 15 s and reconnects with backoff if it drops. An old host
// (no ACK) is probed once per viewer session and never again, so it does not
// log an unknown message every few seconds. No file data moves in F1, and
// nothing here runs on the UI, render or input threads.

#include <winsock2.h>
#include <ws2tcpip.h>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

class FileSession {
public:
    using LogFn = std::function<void(const std::string&)>;
    enum class Capability : int { Unknown = 0, Yes = 1, No = 2 };

    FileSession(std::string localIp, std::string remoteIp, uint16_t port, LogFn logFn);
    ~FileSession();

    FileSession(const FileSession&) = delete;
    FileSession& operator=(const FileSession&) = delete;

    void start();
    void stop();

    Capability capability() const { return static_cast<Capability>(capability_.load()); }
    uint16_t hostCaps() const { return hostCaps_.load(); }
    uint64_t sessions() const { return sessions_.load(); }
    uint64_t pings() const { return pings_.load(); }

private:
    void run();
    SOCKET connectSocket();
    static void closeSocket(SOCKET& s);
    bool waitReadable(SOCKET s, int ms);
    bool sendPacket(SOCKET s, uint8_t type, const std::vector<uint8_t>& payload);
    bool recvPacket(SOCKET s, uint8_t& type, std::vector<uint8_t>& payload);
    static bool sendAll(SOCKET s, const uint8_t* data, size_t size);
    static bool recvExact(SOCKET s, uint8_t* data, size_t size);
    // Sleeps up to ms, waking early on stop(). Returns false if stopping.
    bool sleepFor(int ms);
    void log(const std::string& message) const;

    std::string localIp_;
    std::string remoteIp_;
    uint16_t port_ = 0;
    LogFn logFn_;
    std::atomic<bool> stopRequested_{false};
    std::mutex wakeMutex_;
    std::condition_variable wake_;
    std::thread worker_;
    std::atomic<int> capability_{0};
    std::atomic<uint16_t> hostCaps_{0};
    std::atomic<uint64_t> sessions_{0};
    std::atomic<uint64_t> pings_{0};
};
