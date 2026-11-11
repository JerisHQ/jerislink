#include "clipboard_channel.hpp"

#include <windows.h>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <thread>
#include <utility>
#include <vector>

ClipboardChannel::ClipboardChannel(std::string localIp, std::string remoteIp, uint16_t port, LogFn logFn)
    : localIp_(std::move(localIp)), remoteIp_(std::move(remoteIp)), port_(port), logFn_(std::move(logFn)) {}

ClipboardChannel::~ClipboardChannel() {
    stop();
}

void ClipboardChannel::start() {
    if (worker_.joinable()) return;
    stopRequested_ = false;
    worker_ = std::thread([this] { run(); });
}

void ClipboardChannel::stop() {
    stopRequested_ = true;
    if (worker_.joinable()) worker_.join();
}

void ClipboardChannel::log(const std::string& message) const {
    if (logFn_) logFn_(message);
}

void ClipboardChannel::closeSocket(SOCKET& s) {
    if (s != INVALID_SOCKET) {
        shutdown(s, SD_BOTH);
        closesocket(s);
        s = INVALID_SOCKET;
    }
}

SOCKET ClipboardChannel::connectSocket() {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    BOOL noDelay = TRUE;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&noDelay), sizeof(noDelay));
    DWORD ioTimeoutMs = 500;
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&ioTimeoutMs), sizeof(ioTimeoutMs));
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&ioTimeoutMs), sizeof(ioTimeoutMs));

    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_port = 0;
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

bool ClipboardChannel::sendAll(SOCKET s, const uint8_t* data, size_t size) {
    size_t offset = 0;
    while (offset < size) {
        const int n = send(s, reinterpret_cast<const char*>(data + offset), static_cast<int>(size - offset), 0);
        if (n <= 0) return false;
        offset += static_cast<size_t>(n);
    }
    return true;
}

bool ClipboardChannel::recvExact(SOCKET s, uint8_t* data, size_t size) {
    size_t offset = 0;
    while (offset < size) {
        const int n = recv(s, reinterpret_cast<char*>(data + offset), static_cast<int>(size - offset), 0);
        if (n <= 0) return false;
        offset += static_cast<size_t>(n);
    }
    return true;
}

bool ClipboardChannel::sendPacket(SOCKET s, uint8_t type, const std::string& payload) {
    if (payload.size() > 0xffff) return false;
    const uint16_t len = static_cast<uint16_t>(payload.size());
    std::vector<uint8_t> packet{'M','R','C','1',1,type,uint8_t(len >> 8),uint8_t(len)};
    packet.insert(packet.end(), payload.begin(), payload.end());
    return sendAll(s, packet.data(), packet.size());
}

bool ClipboardChannel::recvPacket(SOCKET s, uint8_t& type, std::string& payload) {
    uint8_t header[8]{};
    if (!recvExact(s, header, sizeof(header))) return false;
    if (header[0] != 'M' || header[1] != 'R' || header[2] != 'C' || header[3] != '1' || header[4] != 1) return false;
    const uint16_t len = uint16_t((uint16_t(header[6]) << 8) | header[7]);
    if (len > kMaxClipboardBytes) return false;
    type = header[5];
    payload.assign(len, '\0');
    if (len && !recvExact(s, reinterpret_cast<uint8_t*>(payload.data()), len)) return false;
    return true;
}

bool ClipboardChannel::wideToUtf8(const std::wstring& text, std::string& utf8) {
    utf8.clear();
    if (text.empty()) return true;
    const int needed = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return false;
    utf8.resize(static_cast<size_t>(needed));
    return WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), utf8.data(), needed, nullptr, nullptr) == needed;
}

bool ClipboardChannel::utf8ToWide(const std::string& utf8, std::wstring& text) {
    text.clear();
    if (utf8.empty()) return true;
    const int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
    if (needed <= 0) return false;
    text.resize(static_cast<size_t>(needed));
    return MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(), static_cast<int>(utf8.size()), text.data(), needed) == needed;
}

bool ClipboardChannel::readClipboardText(std::wstring& text) {
    text.clear();
    for (int attempt = 0; attempt < 5; ++attempt) {
        if (OpenClipboard(nullptr)) {
            HANDLE h = GetClipboardData(CF_UNICODETEXT);
            if (!h) {
                CloseClipboard();
                return false;
            }
            const wchar_t* p = static_cast<const wchar_t*>(GlobalLock(h));
            if (!p) {
                CloseClipboard();
                return false;
            }
            text.assign(p);
            GlobalUnlock(h);
            CloseClipboard();
            return true;
        }
        Sleep(10);
    }
    return false;
}

bool ClipboardChannel::writeClipboardText(const std::wstring& text) {
    for (int attempt = 0; attempt < 5; ++attempt) {
        if (OpenClipboard(nullptr)) {
            if (!EmptyClipboard()) {
                CloseClipboard();
                return false;
            }
            const SIZE_T bytes = (text.size() + 1) * sizeof(wchar_t);
            HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, bytes);
            if (!h) {
                CloseClipboard();
                return false;
            }
            void* p = GlobalLock(h);
            if (!p) {
                GlobalFree(h);
                CloseClipboard();
                return false;
            }
            std::memcpy(p, text.c_str(), bytes);
            GlobalUnlock(h);
            if (!SetClipboardData(CF_UNICODETEXT, h)) {
                GlobalFree(h);
                CloseClipboard();
                return false;
            }
            CloseClipboard();
            return true;
        }
        Sleep(10);
    }
    return false;
}

void ClipboardChannel::run() {
    SOCKET s = INVALID_SOCKET;
    UINT lastSequence = GetClipboardSequenceNumber();
    std::string lastSent;
    std::string lastRemoteApplied;
    bool everConnected = false;

    while (!stopRequested_) {
        if (s == INVALID_SOCKET) {
            s = connectSocket();
            if (s == INVALID_SOCKET) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                continue;
            }
            if (!sendPacket(s, kClipboardHello, {})) {
                closeSocket(s);
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                continue;
            }
            if (everConnected) ++reconnects_;
            everConnected = true;
            lastSequence = GetClipboardSequenceNumber();
            lastRemoteApplied.clear();
            log("clipboard.connected");
        }

        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(s, &readSet);
        timeval tv{};
        tv.tv_usec = 100000;
        const int ready = select(0, &readSet, nullptr, nullptr, &tv);
        if (ready == SOCKET_ERROR) {
            log("clipboard.disconnected select_error");
            closeSocket(s);
            continue;
        }
        if (ready > 0 && FD_ISSET(s, &readSet)) {
            uint8_t type = 0;
            std::string payload;
            if (!recvPacket(s, type, payload)) {
                log("clipboard.disconnected recv_error");
                closeSocket(s);
                continue;
            }
            if (type == kClipboardText) {
                std::wstring wide;
                if (!utf8ToWide(payload, wide)) {
                    log("clipboard.remote_invalid_utf8");
                } else if (writeClipboardText(wide)) {
                    lastRemoteApplied = payload;
                    lastSent = payload;
                    lastSequence = GetClipboardSequenceNumber();
                    ++received_;
                    log("clipboard.rx bytes=" + std::to_string(payload.size()));
                } else {
                    log("clipboard.remote_apply_failed");
                }
            }
        }

        const UINT sequence = GetClipboardSequenceNumber();
        if (sequence != lastSequence) {
            lastSequence = sequence;
            std::wstring wide;
            std::string utf8;
            if (!readClipboardText(wide) || !wideToUtf8(wide, utf8)) continue;
            if (utf8.size() > kMaxClipboardBytes) {
                ++skippedOversize_;
                log("clipboard.skip_oversize bytes=" + std::to_string(utf8.size()));
                continue;
            }
            if (utf8 == lastRemoteApplied) {
                lastRemoteApplied.clear();
                lastSent = utf8;
                continue;
            }
            if (utf8 == lastSent) continue;
            if (!sendPacket(s, kClipboardText, utf8)) {
                log("clipboard.disconnected send_error");
                closeSocket(s);
                continue;
            }
            lastSent = utf8;
            ++sent_;
            log("clipboard.tx bytes=" + std::to_string(utf8.size()));
        }
    }

    closeSocket(s);
    log("clipboard.stopped");
}
