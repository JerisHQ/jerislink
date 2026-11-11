#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#pragma comment(lib, "ws2_32.lib")

static bool sendAll(SOCKET s, const std::vector<uint8_t>& b) {
    size_t off = 0;
    while (off < b.size()) {
        int n = send(s, reinterpret_cast<const char*>(b.data() + off), static_cast<int>(b.size() - off), 0);
        if (n <= 0) return false;
        off += static_cast<size_t>(n);
    }
    return true;
}

static bool recvExact(SOCKET s, uint8_t* p, size_t n) {
    size_t off = 0;
    while (off < n) {
        int r = recv(s, reinterpret_cast<char*>(p + off), static_cast<int>(n - off), 0);
        if (r <= 0) return false;
        off += static_cast<size_t>(r);
    }
    return true;
}

static std::vector<uint8_t> packet(uint8_t type, const std::vector<uint8_t>& payload) {
    uint16_t len = static_cast<uint16_t>(payload.size());
    std::vector<uint8_t> b{'M','R','C','1',1,type,static_cast<uint8_t>(len >> 8),static_cast<uint8_t>(len & 0xff)};
    b.insert(b.end(), payload.begin(), payload.end());
    return b;
}

static void sendKey(SOCKET s, bool down, uint16_t code) {
    std::vector<uint8_t> payload{static_cast<uint8_t>(down ? 1 : 0),
                                 static_cast<uint8_t>(code >> 8),
                                 static_cast<uint8_t>(code & 0xff)};
    if (!sendAll(s, packet(0x10, payload))) throw std::runtime_error("send key failed");
}


static void appendI16(std::vector<uint8_t>& p, int16_t v) {
    uint16_t u = static_cast<uint16_t>(v);
    p.push_back(static_cast<uint8_t>(u >> 8));
    p.push_back(static_cast<uint8_t>(u & 0xff));
}

static void sendMouseMove(SOCKET s, int16_t dx, int16_t dy) {
    std::vector<uint8_t> payload;
    appendI16(payload, dx); appendI16(payload, dy);
    if (!sendAll(s, packet(0x20, payload))) throw std::runtime_error("send mouse move failed");
}

static void sendMouseButton(SOCKET s, uint8_t button, bool down) {
    if (!sendAll(s, packet(0x21, {button, static_cast<uint8_t>(down ? 1 : 0)})))
        throw std::runtime_error("send mouse button failed");
}

static void sendScroll(SOCKET s, int16_t dx, int16_t dy) {
    std::vector<uint8_t> payload;
    appendI16(payload, dx); appendI16(payload, dy);
    if (!sendAll(s, packet(0x22, payload))) throw std::runtime_error("send scroll failed");
}

int main(int argc, char** argv) {
    bool ctrlCTest = false;
    bool mouseSmoke = false;
    std::string bindIp;
    std::string sourceIp;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--ctrl-c-test") ctrlCTest = true;
        if (a == "--mouse-smoke") mouseSmoke = true;
        if (a == "--bind-ip" && i + 1 < argc) bindIp = argv[++i];
        else if (a == "--source-ip" && i + 1 < argc) sourceIp = argv[++i];
    }
    if (bindIp.empty() || sourceIp.empty()) {
        std::cerr << "Usage: JerislinkControlProbe --bind-ip <local-tailscale-ip> --source-ip <mac-host-ip> [--ctrl-c-test] [--mouse-smoke]\n";
        return 64;
    }
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) return 1;
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return 2;

    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_port = 0;
    inet_pton(AF_INET, bindIp.c_str(), &local.sin_addr);
    if (bind(s, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
        std::cerr << "bind failed " << WSAGetLastError() << "\n";
        return 3;
    }

    sockaddr_in remote{};
    remote.sin_family = AF_INET;
    remote.sin_port = htons(38400);
    inet_pton(AF_INET, sourceIp.c_str(), &remote.sin_addr);
    if (connect(s, reinterpret_cast<sockaddr*>(&remote), sizeof(remote)) != 0) {
        std::cerr << "connect failed " << WSAGetLastError() << "\n";
        return 4;
    }

    uint32_t seq = 0x12345678;
    std::vector<uint8_t> ping{static_cast<uint8_t>(seq >> 24), static_cast<uint8_t>(seq >> 16),
                              static_cast<uint8_t>(seq >> 8), static_cast<uint8_t>(seq)};
    auto start = std::chrono::steady_clock::now();
    if (!sendAll(s, packet(0x01, ping))) return 5;

    uint8_t hdr[8]{};
    if (!recvExact(s, hdr, 8)) return 6;
    uint16_t len = static_cast<uint16_t>((uint16_t(hdr[6]) << 8) | hdr[7]);
    std::vector<uint8_t> payload(len);
    if (len && !recvExact(s, payload.data(), payload.size())) return 7;
    auto end = std::chrono::steady_clock::now();
    double rtt = std::chrono::duration<double, std::milli>(end - start).count();

    bool pongOK = hdr[0]=='M' && hdr[1]=='R' && hdr[2]=='C' && hdr[3]=='1' && hdr[4]==1 && hdr[5]==0x02 && payload==ping;
    std::cout << "MRC1 pong=" << (pongOK ? "OK" : "BAD") << " rtt_ms=" << rtt << "\n";
    if (!pongOK) return 8;

    if (ctrlCTest) {
        sendKey(s, true, 1);
        Sleep(20);
        sendKey(s, true, 67);
        Sleep(20);
        sendKey(s, false, 67);
        Sleep(20);
        sendKey(s, false, 1);
        std::cout << "sent Control+C test sequence\n";
    }
    if (mouseSmoke) {
        sendMouseMove(s, 30, 12);
        Sleep(250);
        sendMouseMove(s, -30, -12);
        std::cout << "sent mouse relative move smoke test\n";
    }
    shutdown(s, SD_SEND);
    closesocket(s);
    WSACleanup();
    if (!ctrlCTest && !mouseSmoke) std::cout << "ping-only complete\n";
    return 0;
}
