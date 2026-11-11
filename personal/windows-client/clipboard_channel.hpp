#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>

class ClipboardChannel {
public:
    using LogFn = std::function<void(const std::string&)>;

    ClipboardChannel(std::string localIp, std::string remoteIp, uint16_t port, LogFn logFn);
    ~ClipboardChannel();

    ClipboardChannel(const ClipboardChannel&) = delete;
    ClipboardChannel& operator=(const ClipboardChannel&) = delete;

    void start();
    void stop();

    uint64_t sent() const { return sent_.load(); }
    uint64_t received() const { return received_.load(); }
    uint64_t reconnects() const { return reconnects_.load(); }
    uint64_t skippedOversize() const { return skippedOversize_.load(); }

private:
    static constexpr uint8_t kClipboardHello = 0x30;
    static constexpr uint8_t kClipboardText = 0x31;
    static constexpr size_t kMaxClipboardBytes = 60 * 1024;

    void run();
    SOCKET connectSocket();
    void closeSocket(SOCKET& s);
    bool sendPacket(SOCKET s, uint8_t type, const std::string& payload);
    bool recvPacket(SOCKET s, uint8_t& type, std::string& payload);
    bool sendAll(SOCKET s, const uint8_t* data, size_t size);
    bool recvExact(SOCKET s, uint8_t* data, size_t size);

    static bool readClipboardText(std::wstring& text);
    static bool writeClipboardText(const std::wstring& text);
    static bool wideToUtf8(const std::wstring& text, std::string& utf8);
    static bool utf8ToWide(const std::string& utf8, std::wstring& text);

    void log(const std::string& message) const;

    std::string localIp_;
    std::string remoteIp_;
    uint16_t port_ = 0;
    LogFn logFn_;
    std::atomic<bool> stopRequested_{false};
    std::thread worker_;
    std::atomic<uint64_t> sent_{0};
    std::atomic<uint64_t> received_{0};
    std::atomic<uint64_t> reconnects_{0};
    std::atomic<uint64_t> skippedOversize_{0};
};
