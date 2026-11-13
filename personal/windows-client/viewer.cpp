#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shellapi.h>
#include <dwmapi.h>
#include <iphlpapi.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mftransform.h>
#include <mferror.h>
#include <wmcodecdsp.h>
#include <d3d11.h>
#include <d3dcompiler.h>
#include <dxgi1_2.h>
#include <dxgi1_3.h>
#include <dxgi1_4.h>
#include <wrl/client.h>
#include "control_channel.hpp"
#include <cstdlib>
#include "clipboard_channel.hpp"
#include "hardware_video_pipeline.hpp"
#include "resource.h"
#include "viewer_options.hpp"
#include "video_receiver.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "mfplat.lib")
#pragma comment(lib, "mf.lib")
#pragma comment(lib, "mfuuid.lib")
#pragma comment(lib, "wmcodecdspuuid.lib")
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "d3dcompiler.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "dwmapi.lib")

using Microsoft::WRL::ComPtr;

static std::string tempLogPath(const char* filename) {
    char buf[MAX_PATH + 2]{};
    DWORD n = GetTempPathA(static_cast<DWORD>(sizeof(buf)), buf);
    if (n == 0 || n >= sizeof(buf)) return filename;
    return std::string(buf) + filename;
}
static const std::string kLogPath = tempLogPath("jerislink-viewer.log");
static const std::string kHistoryLogPath = tempLogPath("jerislink-viewer-history.log");
extern "C" const char* __asan_default_options() {
    return "log_path=shader-asan:abort_on_error=1";
}
class CpuPresenter;
static CpuPresenter* gCpuPresenter = nullptr;
static bool gHardwarePresenterActive = false;
static void paintCpuFrame(HWND hwnd);
static void logLine(const std::string& s);

class MouseMoveUdpChannel {
public:
    MouseMoveUdpChannel(const std::string& localIp, const std::string& remoteIp, uint16_t port) {
        s_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s_ == INVALID_SOCKET) throw std::runtime_error("mouse UDP socket failed");

        sockaddr_in local{};
        local.sin_family = AF_INET;
        local.sin_port = 0;
        if (inet_pton(AF_INET, localIp.c_str(), &local.sin_addr) != 1 ||
            bind(s_, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
            closesocket(s_); s_ = INVALID_SOCKET;
            throw std::runtime_error("mouse UDP bind failed");
        }

        remote_.sin_family = AF_INET;
        remote_.sin_port = htons(port);
        if (inet_pton(AF_INET, remoteIp.c_str(), &remote_.sin_addr) != 1) {
            closesocket(s_); s_ = INVALID_SOCKET;
            throw std::runtime_error("mouse UDP remote IP invalid");
        }

        u_long nonBlocking = 1;
        if (ioctlsocket(s_, FIONBIO, &nonBlocking) != 0) {
            closesocket(s_); s_ = INVALID_SOCKET;
            throw std::runtime_error("mouse UDP nonblocking failed");
        }
    }

    ~MouseMoveUdpChannel() {
        if (s_ != INVALID_SOCKET) closesocket(s_);
    }

    bool sendNormalized(uint16_t nx, uint16_t ny) {
        if (s_ == INVALID_SOCKET) return false;
        const uint32_t seq = ++sequence_;
        uint8_t p[14]{
            'M','R','M','1', 1, 0x24,
            uint8_t(seq >> 24), uint8_t(seq >> 16), uint8_t(seq >> 8), uint8_t(seq),
            uint8_t(nx >> 8), uint8_t(nx), uint8_t(ny >> 8), uint8_t(ny)
        };
        const int n = sendto(s_, reinterpret_cast<const char*>(p), sizeof(p), 0,
                             reinterpret_cast<const sockaddr*>(&remote_), sizeof(remote_));
        if (n == sizeof(p)) { ++sent_; return true; }
        ++dropped_;
        return false;
    }

    bool requestKeyframe() {
        if (s_ == INVALID_SOCKET) return false;
        const auto now = std::chrono::steady_clock::now();
        if (haveKeyframeRequestTime_ &&
            std::chrono::duration_cast<std::chrono::milliseconds>(now - lastKeyframeRequest_).count() < 100) {
            ++keyframeRequestsSuppressed_;
            return true;
        }
        lastKeyframeRequest_ = now;
        haveKeyframeRequestTime_ = true;

        const uint32_t seq = ++sequence_;
        uint8_t p[10]{
            'M','R','M','1', 1, 0x40,
            uint8_t(seq >> 24), uint8_t(seq >> 16), uint8_t(seq >> 8), uint8_t(seq)
        };
        const int n = sendto(s_, reinterpret_cast<const char*>(p), sizeof(p), 0,
                             reinterpret_cast<const sockaddr*>(&remote_), sizeof(remote_));
        if (n == sizeof(p)) { ++keyframeRequestsSent_; return true; }
        ++keyframeRequestDrops_;
        return false;
    }

    // MRM1 0x41: ask the host to send these packets of frame fid again.
    bool sendNack(uint64_t fid, const std::vector<jl::NackRange>& ranges) {
        if (s_ == INVALID_SOCKET || ranges.empty()) return false;
        const auto p = jl::encodeNack(++sequence_, fid, ranges);
        const int n = sendto(s_, reinterpret_cast<const char*>(p.data()), static_cast<int>(p.size()), 0,
                             reinterpret_cast<const sockaddr*>(&remote_), sizeof(remote_));
        if (n == static_cast<int>(p.size())) { ++nackSent_; return true; }
        ++nackDrops_;
        return false;
    }

    // MRM1 0x43 ping carrying the viewer's send time; the host echoes it as
    // 0x44 and pollCursorShape() turns the echo into an RTT sample.
    bool sendPing() {
        if (s_ == INVALID_SOCKET) return false;
        const uint32_t seq = ++sequence_;
        const uint64_t t = nowUs();
        uint8_t p[18]{'M','R','M','1', 1, 0x43,
                      uint8_t(seq >> 24), uint8_t(seq >> 16), uint8_t(seq >> 8), uint8_t(seq)};
        for (int i = 0; i < 8; ++i) p[10 + i] = uint8_t(t >> (56 - 8 * i));
        const int n = sendto(s_, reinterpret_cast<const char*>(p), sizeof(p), 0,
                             reinterpret_cast<const sockaddr*>(&remote_), sizeof(remote_));
        if (n == sizeof(p)) { ++pingSent_; return true; }
        return false;
    }

    // Smoothed RTT from 0x44 echoes (EWMA 1/8), 0 until the first echo.
    double rttMs() const { return rttEwmaMs_; }
    double rttMaxMs() const { return rttMaxMs_; }
    double rttLastMs() const { return rttLastMs_; }
    uint64_t pingSent() const { return pingSent_; }
    uint64_t pongRx() const { return pongRx_; }
    uint64_t nackSent() const { return nackSent_; }
    uint64_t nackDrops() const { return nackDrops_; }

    bool pollCursorShape(uint8_t& shape) {
        if (s_ == INVALID_SOCKET) return false;
        bool updated = false;
        for (;;) {
            uint8_t p[64]{};
            sockaddr_in peer{};
            int plen = sizeof(peer);
            const int n = recvfrom(s_, reinterpret_cast<char*>(p), sizeof(p), 0,
                                   reinterpret_cast<sockaddr*>(&peer), &plen);
            if (n == SOCKET_ERROR) {
                const int e = WSAGetLastError();
                if (e == WSAEWOULDBLOCK) break;
                ++cursorRxBad_;
                break;
            }
            if (peer.sin_addr.s_addr == remote_.sin_addr.s_addr &&
                peer.sin_port == remote_.sin_port &&
                n == 18 && std::memcmp(p, "MRM1", 4) == 0 && p[4] == 1 && p[5] == 0x44) {
                uint64_t sentUs = 0;
                for (int i = 0; i < 8; ++i) sentUs = (sentUs << 8) | p[10 + i];
                const uint64_t now = nowUs();
                if (sentUs <= now && now - sentUs < 10'000'000) {
                    const double rtt = double(now - sentUs) / 1000.0;
                    rttLastMs_ = rtt;
                    rttMaxMs_ = std::max(rttMaxMs_, rtt);
                    rttEwmaMs_ = pongRx_ == 0 ? rtt : rttEwmaMs_ + (rtt - rttEwmaMs_) / 8.0;
                    ++pongRx_;
                }
                continue;
            }
            if (peer.sin_addr.s_addr != remote_.sin_addr.s_addr ||
                peer.sin_port != remote_.sin_port ||
                n != 11 ||
                std::memcmp(p, "MRM1", 4) != 0 || p[4] != 1 || p[5] != 0x31) {
                ++cursorRxBad_;
                continue;
            }
            const uint32_t seq = (uint32_t(p[6]) << 24) |
                                 (uint32_t(p[7]) << 16) |
                                 (uint32_t(p[8]) << 8) |
                                 uint32_t(p[9]);
            if (haveCursorSequence_ && static_cast<int32_t>(seq - cursorSequence_) <= 0) {
                ++cursorRxStale_;
                continue;
            }
            haveCursorSequence_ = true;
            cursorSequence_ = seq;
            shape = p[10];
            ++cursorRx_;
            updated = true;
        }
        return updated;
    }

    uint64_t sent() const { return sent_; }
    uint64_t dropped() const { return dropped_; }
    uint64_t keyframeRequestsSent() const { return keyframeRequestsSent_; }
    uint64_t keyframeRequestsSuppressed() const { return keyframeRequestsSuppressed_; }
    uint64_t keyframeRequestDrops() const { return keyframeRequestDrops_; }
    uint64_t cursorRx() const { return cursorRx_; }
    uint64_t cursorRxBad() const { return cursorRxBad_; }
    uint64_t cursorRxStale() const { return cursorRxStale_; }

private:
    SOCKET s_ = INVALID_SOCKET;
    sockaddr_in remote_{};
    uint32_t sequence_ = 0;
    uint64_t sent_ = 0;
    uint64_t dropped_ = 0;
    std::chrono::steady_clock::time_point lastKeyframeRequest_{};
    bool haveKeyframeRequestTime_ = false;
    uint64_t keyframeRequestsSent_ = 0;
    uint64_t keyframeRequestsSuppressed_ = 0;
    uint64_t keyframeRequestDrops_ = 0;
    bool haveCursorSequence_ = false;
    uint32_t cursorSequence_ = 0;
    uint64_t cursorRx_ = 0;
    uint64_t cursorRxBad_ = 0;
    uint64_t cursorRxStale_ = 0;
    static uint64_t nowUs() {
        return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    }
    uint64_t nackSent_ = 0;
    uint64_t nackDrops_ = 0;
    uint64_t pingSent_ = 0;
    uint64_t pongRx_ = 0;
    double rttEwmaMs_ = 0.0;
    double rttMaxMs_ = 0.0;
    double rttLastMs_ = 0.0;
};

static bool gWindowClosed = false;
static ControlChannel* gControl = nullptr;
static MouseMoveUdpChannel* gMouseMoveUdp = nullptr;
static double gScrollScale = 1.0 / 3.0;
static bool gViewerFocused = false;
static bool gHaveMouse = false;
static POINT gLastMouse{};
static UINT32 gRemoteWidth = 1760;
static UINT32 gRemoteHeight = 990;
static HWND gViewerHwnd = nullptr;
static HHOOK gKeyboardHook = nullptr;
static bool gHookWinDown = false;
static bool gHookInterceptingWinC = false;
static bool gHookInterceptingWinSpace = false;
static bool gHookCapsDown = false;
static bool gLoggedFirstInput = false;
static constexpr UINT WM_MR_WIN_C = WM_APP + 41;
static constexpr UINT WM_MR_WIN_DOWN = WM_APP + 42;
static constexpr UINT WM_MR_WIN_UP = WM_APP + 43;
static constexpr UINT WM_MR_WIN_SPACE = WM_APP + 44;
static constexpr UINT WM_MR_CAPS_LOCK = WM_APP + 45;
static WPARAM gSuppressedShortcutKey = 0;
static uint16_t gTemporarilyReleasedModifier = 0;
static uint8_t gLeftClickCount = 1;
static uint8_t gRemoteCursorShape = 0;
static HCURSOR gRemoteCursor = nullptr;

struct ConnectionInfoState {
    std::string configuredCodec = "h264";
    uint16_t configuredBitrateMbps = 25;
    std::string effectiveCodec = "h264";
    uint16_t effectiveBitrateMbps = 25;
    UINT32 remoteWidth = 0;
    UINT32 remoteHeight = 0;
    UINT32 fps = 0;
    double rttMs = 0.0;
    bool controlConnected = false;
    std::string backend = "pending";
    std::string decoder = "pending";
    std::string adapter;
};

static ConnectionInfoState gConnectionInfo;

static HCURSOR cursorForRemoteShape(uint8_t shape) {
    LPCWSTR id = IDC_ARROW;
    switch (shape) {
    case 1:  id = IDC_IBEAM; break;
    case 2:  id = IDC_HAND; break;
    case 3:  id = IDC_SIZEWE; break;
    case 4:  id = IDC_SIZENS; break;
    case 5:  id = IDC_SIZENWSE; break;
    case 6:  id = IDC_SIZENESW; break;
    case 7:  id = IDC_CROSS; break;
    case 8:  id = IDC_HAND; break;
    case 9:  id = IDC_HAND; break;
    case 10: id = IDC_NO; break;
    case 11: id = IDC_IBEAM; break;
    default: id = IDC_ARROW; break;
    }
    return LoadCursorW(nullptr, id);
}

static void applyRemoteCursorShape(HWND hwnd, uint8_t shape) {
    if (shape == gRemoteCursorShape && gRemoteCursor) return;
    gRemoteCursorShape = shape;
    gRemoteCursor = cursorForRemoteShape(shape);
    if (hwnd && gRemoteCursor) SetCursor(gRemoteCursor);
}

static void applyModernWindowChrome(HWND hwnd) {
    // These DWM attributes are best-effort. Older Windows builds may ignore
    // one or more of them, while Windows 11 gets a dark caption and rounded
    // corners without replacing the native non-client controls.
    BOOL dark = TRUE;
    (void)DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark, sizeof(dark));

    const COLORREF caption = RGB(12, 20, 36);
    const COLORREF border = RGB(43, 68, 99);
    const COLORREF text = RGB(244, 248, 255);
    (void)DwmSetWindowAttribute(hwnd, DWMWA_CAPTION_COLOR, &caption, sizeof(caption));
    (void)DwmSetWindowAttribute(hwnd, DWMWA_BORDER_COLOR, &border, sizeof(border));
    (void)DwmSetWindowAttribute(hwnd, DWMWA_TEXT_COLOR, &text, sizeof(text));

    DWM_WINDOW_CORNER_PREFERENCE corners = DWMWCP_ROUND;
    (void)DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &corners, sizeof(corners));
}

static bool physicalKeyDown(int vk) {
    return (GetKeyState(vk) & 0x8000) != 0;
}

static bool viewerHasInteractiveFocus(HWND hwnd) {
    if (!hwnd) return false;
    return gViewerFocused || GetFocus() == hwnd || GetForegroundWindow() == hwnd;
}

static void logFirstInput(const char* kind) {
    if (gLoggedFirstInput) return;
    gLoggedFirstInput = true;
    logLine(std::string("input.first=") + kind);
}

static bool sendRemoteChord(uint16_t modifier, uint16_t key) {
    if (!gControl) return false;
    bool ok = true;
    ok = gControl->sendKey(true, modifier) && ok;
    ok = gControl->sendKey(true, key) && ok;
    ok = gControl->sendKey(false, key) && ok;
    ok = gControl->sendKey(false, modifier) && ok;
    return ok;
}

static bool isWindowsCtrlCompatShortcut(WPARAM vk) {
    return vk == 'A' || vk == 'C' || vk == 'V' || vk == 'Z';
}

static LRESULT CALLBACK ViewerKeyboardHook(int code, WPARAM wParam, LPARAM lParam) {
    if (code == HC_ACTION && gViewerHwnd && viewerHasInteractiveFocus(gViewerHwnd)) {
        const auto* k = reinterpret_cast<const KBDLLHOOKSTRUCT*>(lParam);
        if (k) {
            const bool keyDown = wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN;
            const bool keyUp = wParam == WM_KEYUP || wParam == WM_SYSKEYUP;

            if (k->vkCode == VK_CAPITAL) {
                if (keyDown && !gHookCapsDown) {
                    gHookCapsDown = true;
                    PostMessageW(gViewerHwnd, WM_MR_CAPS_LOCK, 0, 0);
                } else if (keyUp) {
                    gHookCapsDown = false;
                }
                return 1;
            }

            if (k->vkCode == VK_LWIN || k->vkCode == VK_RWIN) {
                if (keyDown && !gHookWinDown) {
                    gHookWinDown = true;
                    PostMessageW(gViewerHwnd, WM_MR_WIN_DOWN, 0, 0);
                } else if (keyUp && gHookWinDown) {
                    gHookWinDown = false;
                    PostMessageW(gViewerHwnd, WM_MR_WIN_UP, 0, 0);
                }
                return 1;
            }

            if (k->vkCode == 'C' && gHookWinDown) {
                if (keyDown) {
                    if (!gHookInterceptingWinC) {
                        gHookInterceptingWinC = true;
                        PostMessageW(gViewerHwnd, WM_MR_WIN_C, 0, 0);
                    }
                    return 1;
                }
                if (keyUp && gHookInterceptingWinC) {
                    gHookInterceptingWinC = false;
                    return 1;
                }
            }

            if (k->vkCode == VK_SPACE && gHookWinDown) {
                if (keyDown) {
                    if (!gHookInterceptingWinSpace) {
                        gHookInterceptingWinSpace = true;
                        PostMessageW(gViewerHwnd, WM_MR_WIN_SPACE, 0, 0);
                    }
                    return 1;
                }
                if (keyUp && gHookInterceptingWinSpace) {
                    gHookInterceptingWinSpace = false;
                    return 1;
                }
            }
        }
    }
    return CallNextHookEx(gKeyboardHook, code, wParam, lParam);
}

static bool sendAbsolutePointer(HWND hwnd, POINT p) {
    if ((!gControl && !gMouseMoveUdp) || gRemoteWidth == 0 || gRemoteHeight == 0) return false;
    RECT client{};
    GetClientRect(hwnd, &client);
    const int cw = std::max<LONG>(1, client.right - client.left);
    const int ch = std::max<LONG>(1, client.bottom - client.top);
    const double srcAspect = static_cast<double>(gRemoteWidth) / gRemoteHeight;
    int dw = cw, dh = ch, dx = 0, dy = 0;
    if (static_cast<double>(cw) / ch > srcAspect) {
        dw = std::max(1, static_cast<int>(ch * srcAspect));
        dx = (cw - dw) / 2;
    } else {
        dh = std::max(1, static_cast<int>(cw / srcAspect));
        dy = (ch - dh) / 2;
    }
    if (p.x < dx || p.y < dy || p.x >= dx + dw || p.y >= dy + dh) return false;
    const double nx = static_cast<double>(p.x - dx) / std::max(1, dw - 1);
    const double ny = static_cast<double>(p.y - dy) / std::max(1, dh - 1);
    const uint16_t qx = static_cast<uint16_t>(std::clamp<long>(std::lround(nx * 65535.0), 0, 65535));
    const uint16_t qy = static_cast<uint16_t>(std::clamp<long>(std::lround(ny * 65535.0), 0, 65535));
    if (gMouseMoveUdp) return gMouseMoveUdp->sendNormalized(qx, qy);
    return gControl->sendMouseMoveNormalized(qx, qy);
}

static uint16_t semanticKey(WPARAM vk) {
    switch (vk) {
    case VK_CONTROL: case VK_LCONTROL: case VK_RCONTROL: return 1;
    case VK_MENU: case VK_LMENU: case VK_RMENU: return 2;
    case VK_LWIN: case VK_RWIN: return 3;
    case VK_SHIFT: case VK_LSHIFT: case VK_RSHIFT: return 4;
    case VK_CAPITAL: return static_cast<uint16_t>(VK_CAPITAL);

    // Editing/navigation keys. For non-modifiers we keep the Windows VK value
    // as the semantic code; the Mac side maps that semantic to a CGKeyCode.
    case VK_BACK: case VK_TAB: case VK_RETURN: case VK_ESCAPE: case VK_SPACE:
    case VK_PRIOR: case VK_NEXT: case VK_END: case VK_HOME:
    case VK_LEFT: case VK_UP: case VK_RIGHT: case VK_DOWN:
    case VK_INSERT: case VK_DELETE:

    // Number pad.
    case VK_NUMPAD0: case VK_NUMPAD1: case VK_NUMPAD2: case VK_NUMPAD3: case VK_NUMPAD4:
    case VK_NUMPAD5: case VK_NUMPAD6: case VK_NUMPAD7: case VK_NUMPAD8: case VK_NUMPAD9:
    case VK_MULTIPLY: case VK_ADD: case VK_SUBTRACT: case VK_DECIMAL: case VK_DIVIDE:

    // Function keys.
    case VK_F1: case VK_F2: case VK_F3: case VK_F4: case VK_F5: case VK_F6:
    case VK_F7: case VK_F8: case VK_F9: case VK_F10: case VK_F11: case VK_F12:

    // US/HK physical punctuation keys. Shift state is carried separately, so
    // these naturally produce ! @ # ... and other shifted symbols.
    case VK_OEM_1: case VK_OEM_PLUS: case VK_OEM_COMMA: case VK_OEM_MINUS:
    case VK_OEM_PERIOD: case VK_OEM_2: case VK_OEM_3: case VK_OEM_4:
    case VK_OEM_5: case VK_OEM_6: case VK_OEM_7:
        return static_cast<uint16_t>(vk);
    default:
        if ((vk >= 'A' && vk <= 'Z') || (vk >= '0' && vk <= '9')) {
            return static_cast<uint16_t>(vk);
        }
        return 0;
    }
}

static void releaseRemoteModifiers() {
    if (!gControl) return;
    for (uint16_t k = 1; k <= 4; ++k) gControl->sendKey(false, k);
}

static void logLine(const std::string& s) {
    std::ofstream f(kLogPath, std::ios::app);
    f << s << "\n";
    f.flush();
    std::ofstream h(kHistoryLogPath, std::ios::app);
    h << s << "\n";
    h.flush();
}

static void check(HRESULT hr, const char* what) {
    if (FAILED(hr)) {
        char buf[192];
        std::snprintf(buf, sizeof(buf), "%s failed: 0x%08lx", what, static_cast<unsigned long>(hr));
        throw std::runtime_error(buf);
    }
}

static std::optional<std::string> detectTailscaleIPv4() {
    ULONG size = 16 * 1024;
    std::vector<uint8_t> buffer(size);
    auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
    ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG rc = GetAdaptersAddresses(AF_INET, flags, nullptr, adapters, &size);
    if (rc == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(size);
        adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
        rc = GetAdaptersAddresses(AF_INET, flags, nullptr, adapters, &size);
    }
    if (rc != NO_ERROR) return std::nullopt;

    for (auto* a = adapters; a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp) continue;
        for (auto* u = a->FirstUnicastAddress; u; u = u->Next) {
            if (!u->Address.lpSockaddr || u->Address.lpSockaddr->sa_family != AF_INET) continue;
            auto* sin = reinterpret_cast<sockaddr_in*>(u->Address.lpSockaddr);
            uint32_t host = ntohl(sin->sin_addr.S_un.S_addr);
            if ((host & 0xFFC00000u) != 0x64400000u) continue;
            char ip[32]{};
            std::snprintf(ip, sizeof(ip), "%u.%u.%u.%u",
                          (host >> 24) & 0xff, (host >> 16) & 0xff,
                          (host >> 8) & 0xff, host & 0xff);
            return std::string(ip);
        }
    }
    return std::nullopt;
}

static constexpr UINT IDM_VIDEO_SETTINGS = 0x1F10;
static constexpr UINT IDM_CONNECTION_INFO = 0x1F11;
static constexpr wchar_t kJerislinkSettingsKey[] = L"Software\\Jeris\\Jerislink";

using SavedSettings = jl::SavedSettings;

static std::string savedCodecName(DWORD value) {
    if (value == 0) return "auto";
    if (value == 2) return "hevc";
    return "h264";
}

static DWORD savedCodecValue(const std::string& codec) {
    if (codec == "auto") return 0;
    if (codec == "hevc") return 2;
    return 1;
}

// IPv4 text is ASCII; anything else is dropped (and then fails jl::isIPv4).
static std::string asciiFromWide(const std::wstring& text) {
    std::string out;
    for (wchar_t c : text) {
        if (c == L' ' || c == L'\t') continue;
        if (c > 0x7f) return {};
        out.push_back(static_cast<char>(c));
    }
    return out;
}

static std::wstring wideFromAscii(const std::string& text) {
    return std::wstring(text.begin(), text.end());
}

static std::string readRegString(HKEY key, const wchar_t* name) {
    wchar_t buffer[64]{};
    DWORD size = sizeof(buffer);
    if (RegGetValueW(key, nullptr, name, RRF_RT_REG_SZ, nullptr, buffer, &size) != ERROR_SUCCESS) {
        return {};
    }
    return asciiFromWide(buffer);
}

static LONG writeRegString(HKEY key, const wchar_t* name, const std::string& value) {
    const std::wstring wide = wideFromAscii(value);
    return RegSetValueExW(key, name, 0, REG_SZ, reinterpret_cast<const BYTE*>(wide.c_str()),
                          static_cast<DWORD>((wide.size() + 1) * sizeof(wchar_t)));
}

// Per-user settings in HKCU\Software\Jeris\Jerislink:
//   HostIp (REG_SZ), BindIp (REG_SZ, empty = auto), VideoCodec, VideoBitrateMbps (REG_DWORD).
static SavedSettings loadSavedSettings() {
    SavedSettings settings;
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kJerislinkSettingsKey, 0, KEY_READ, &key) != ERROR_SUCCESS) {
        return settings;
    }

    DWORD codec = 1;
    DWORD bitrate = 25;
    DWORD size = sizeof(DWORD);
    if (RegGetValueW(key, nullptr, L"VideoCodec", RRF_RT_REG_DWORD,
                     nullptr, &codec, &size) != ERROR_SUCCESS || codec > 2) {
        codec = 1;
    }
    size = sizeof(DWORD);
    if (RegGetValueW(key, nullptr, L"VideoBitrateMbps", RRF_RT_REG_DWORD,
                     nullptr, &bitrate, &size) != ERROR_SUCCESS ||
        (bitrate != 0 && (bitrate < 4 || bitrate > 100))) {
        bitrate = 25;
    }
    settings.hostIp = readRegString(key, L"HostIp");
    settings.bindIp = readRegString(key, L"BindIp");
    RegCloseKey(key);
    settings.codec = savedCodecName(codec);
    settings.bitrateMbps = static_cast<uint16_t>(bitrate);
    return settings;
}

static bool saveSettings(const SavedSettings& settings) {
    HKEY key = nullptr;
    DWORD disposition = 0;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kJerislinkSettingsKey, 0, nullptr, 0,
                        KEY_WRITE, nullptr, &key, &disposition) != ERROR_SUCCESS) {
        return false;
    }
    DWORD codec = savedCodecValue(settings.codec);
    DWORD bitrate = settings.bitrateMbps;
    const LONG codecResult = RegSetValueExW(
        key, L"VideoCodec", 0, REG_DWORD,
        reinterpret_cast<const BYTE*>(&codec), sizeof(codec));
    const LONG bitrateResult = RegSetValueExW(
        key, L"VideoBitrateMbps", 0, REG_DWORD,
        reinterpret_cast<const BYTE*>(&bitrate), sizeof(bitrate));
    const LONG hostResult = writeRegString(key, L"HostIp", settings.hostIp);
    const LONG bindResult = writeRegString(key, L"BindIp", settings.bindIp);
    RegCloseKey(key);
    return codecResult == ERROR_SUCCESS && bitrateResult == ERROR_SUCCESS &&
           hostResult == ERROR_SUCCESS && bindResult == ERROR_SUCCESS;
}

// lParam of the dialog: kSettingsDialogConnect when shown before connecting
// (button says "Connect"), kSettingsDialogSave from the running viewer.
static constexpr LPARAM kSettingsDialogSave = 0;
static constexpr LPARAM kSettingsDialogConnect = 1;

static std::wstring dialogText(HWND dlg, int id) {
    wchar_t text[64]{};
    GetDlgItemTextW(dlg, id, text, static_cast<int>(std::size(text)));
    return text;
}

static INT_PTR CALLBACK SettingsDlgProc(HWND dlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_INITDIALOG: {
        SendDlgItemMessageW(dlg, IDC_VIDEO_CODEC, CB_ADDSTRING, 0,
                            reinterpret_cast<LPARAM>(L"Auto"));
        SendDlgItemMessageW(dlg, IDC_VIDEO_CODEC, CB_ADDSTRING, 0,
                            reinterpret_cast<LPARAM>(L"H.264"));
        SendDlgItemMessageW(dlg, IDC_VIDEO_CODEC, CB_ADDSTRING, 0,
                            reinterpret_cast<LPARAM>(L"HEVC (H.265)"));
        const auto settings = loadSavedSettings();
        int index = 1;
        if (settings.codec == "auto") index = 0;
        else if (settings.codec == "hevc") index = 2;
        SendDlgItemMessageW(dlg, IDC_VIDEO_CODEC, CB_SETCURSEL, index, 0);
        SetDlgItemInt(dlg, IDC_VIDEO_BITRATE, settings.bitrateMbps, FALSE);
        SetDlgItemTextW(dlg, IDC_HOST_IP, wideFromAscii(settings.hostIp).c_str());
        SetDlgItemTextW(dlg, IDC_BIND_IP, wideFromAscii(settings.bindIp).c_str());
        const auto detected = detectTailscaleIPv4();
        const std::wstring hint = detected
            ? L"Leave empty to use this PC's Tailscale address (now " +
                  wideFromAscii(*detected) + L")."
            : std::wstring(L"Leave empty to use this PC's Tailscale address (none found now).");
        SetDlgItemTextW(dlg, IDC_BIND_HINT, hint.c_str());
        if (lParam == kSettingsDialogConnect) {
            SetDlgItemTextW(dlg, IDOK, L"Connect");
            SetDlgItemTextW(dlg, IDC_APPLY_NOTE,
                            L"Saved for next time. Hold Shift while starting JerisLink to change them.");
        }
        SetForegroundWindow(dlg);
        if (settings.hostIp.empty()) {
            SetFocus(GetDlgItem(dlg, IDC_HOST_IP));
            return FALSE;  // focus set manually
        }
        return TRUE;
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == IDCANCEL) {
            EndDialog(dlg, IDCANCEL);
            return TRUE;
        }
        if (LOWORD(wParam) == IDOK) {
            const std::string host = asciiFromWide(dialogText(dlg, IDC_HOST_IP));
            const std::string bind = asciiFromWide(dialogText(dlg, IDC_BIND_IP));
            const LRESULT selected = SendDlgItemMessageW(
                dlg, IDC_VIDEO_CODEC, CB_GETCURSEL, 0, 0);
            const std::wstring bitrateText = dialogText(dlg, IDC_VIDEO_BITRATE);
            bool bitrateValid = !bitrateText.empty();
            unsigned long bitrateValue = 0;
            if (bitrateValid) {
                try {
                    size_t consumed = 0;
                    bitrateValue = std::stoul(bitrateText, &consumed, 10);
                    bitrateValid = consumed == bitrateText.size() && bitrateValue <= 100;
                } catch (...) {
                    bitrateValid = false;
                }
            }
            const UINT bitrate = bitrateValid ? static_cast<UINT>(bitrateValue) : 0;
            logLine("settings.save_attempt host=" + host + " bind=" + bind +
                    " selected=" + std::to_string(selected) +
                    " valid_bitrate=" + (bitrateValid ? "yes" : "no") +
                    " bitrate=" + std::to_string(bitrate));
            if (!jl::isIPv4(host)) {
                MessageBoxW(dlg,
                    L"Enter the Mac host's Tailscale IPv4 address, for example 100.101.102.103.",
                    L"JerisLink Settings", MB_OK | MB_ICONWARNING);
                SetFocus(GetDlgItem(dlg, IDC_HOST_IP));
                return TRUE;
            }
            if (!bind.empty() && !jl::isIPv4(bind)) {
                MessageBoxW(dlg,
                    L"This PC's address must be an IPv4 address, or empty for automatic.",
                    L"JerisLink Settings", MB_OK | MB_ICONWARNING);
                SetFocus(GetDlgItem(dlg, IDC_BIND_IP));
                return TRUE;
            }
            if (selected == CB_ERR || !bitrateValid ||
                (bitrate != 0 && (bitrate < 4 || bitrate > 100))) {
                MessageBoxW(dlg,
                    L"Bitrate must be 0 (Auto) or a value from 4 to 100 Mbps.",
                    L"JerisLink Settings", MB_OK | MB_ICONWARNING);
                return TRUE;
            }
            SavedSettings settings;
            settings.hostIp = host;
            settings.bindIp = bind;
            settings.codec = selected == 0 ? "auto" : (selected == 2 ? "hevc" : "h264");
            settings.bitrateMbps = static_cast<uint16_t>(bitrate);
            if (!saveSettings(settings)) {
                logLine("settings.save_failed");
                MessageBoxW(dlg, L"Could not save JerisLink settings.",
                            L"JerisLink", MB_OK | MB_ICONERROR);
                return TRUE;
            }
            logLine("settings.saved host=" + settings.hostIp +
                    " bind=" + (settings.bindIp.empty() ? std::string("auto") : settings.bindIp) +
                    " codec=" + settings.codec +
                    " bitrate_mbps=" + std::to_string(settings.bitrateMbps));
            EndDialog(dlg, IDOK);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

static INT_PTR runSettingsDialog(HWND owner, LPARAM mode) {
    const INT_PTR result = DialogBoxParamW(
        GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDD_VIDEO_SETTINGS),
        owner, SettingsDlgProc, mode);
    if (result == -1) {
        logLine("settings.dialog_create_failed error=" + std::to_string(GetLastError()));
    }
    return result;
}

static void showVideoSettings(HWND owner) {
    if (runSettingsDialog(owner, kSettingsDialogSave) == IDOK) {
        MessageBoxW(owner,
            L"Settings saved. They apply the next time JerisLink starts.",
            L"JerisLink", MB_OK | MB_ICONINFORMATION);
    }
}

static std::wstring utf8ToWide(const std::string& text) {
    if (text.empty()) return {};
    const int chars = MultiByteToWideChar(
        CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
    if (chars <= 0) return {};
    std::wstring out(static_cast<size_t>(chars), L'\0');
    MultiByteToWideChar(
        CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), out.data(), chars);
    return out;
}

static std::wstring codecDisplayName(const std::string& codec) {
    if (codec == "hevc") return L"HEVC";
    if (codec == "h264") return L"H.264";
    if (codec == "auto") return L"Auto";
    return utf8ToWide(codec);
}

static void updateViewerTitle(HWND hwnd) {
    if (!hwnd) return;
    std::wostringstream title;
    title << L"JerisLink \u2014 " << codecDisplayName(gConnectionInfo.effectiveCodec)
          << L" \u00b7 " << gConnectionInfo.effectiveBitrateMbps << L" Mbps";
    SetWindowTextW(hwnd, title.str().c_str());
}

static void showConnectionInfo(HWND owner) {
    const std::wstring configuredCodec = codecDisplayName(gConnectionInfo.configuredCodec);
    const std::wstring effectiveCodec = codecDisplayName(gConnectionInfo.effectiveCodec);
    const std::wstring configuredBitrate = gConnectionInfo.configuredBitrateMbps == 0
        ? L"Auto"
        : std::to_wstring(gConnectionInfo.configuredBitrateMbps) + L" Mbps";

    std::wostringstream info;
    info << L"Configured\n"
         << L"  Codec: " << configuredCodec << L"\n"
         << L"  Bandwidth: " << configuredBitrate << L"\n\n"
         << L"Effective connection\n"
         << L"  Codec: " << effectiveCodec << L"\n"
         << L"  Bandwidth: " << gConnectionInfo.effectiveBitrateMbps << L" Mbps\n"
         << L"  Remote: " << gConnectionInfo.remoteWidth << L" x "
         << gConnectionInfo.remoteHeight << L" @ " << gConnectionInfo.fps << L" fps\n";

    if (gConnectionInfo.controlConnected) {
        info << L"  Control RTT: " << std::fixed << std::setprecision(1)
             << gConnectionInfo.rttMs << L" ms\n";
    } else {
        info << L"  Control RTT: unavailable\n";
    }

    info << L"\nDecoder\n"
         << L"  Backend: " << utf8ToWide(gConnectionInfo.backend) << L"\n"
         << L"  Decoder: " << utf8ToWide(gConnectionInfo.decoder) << L"\n"
         << L"  GPU: "
         << (gConnectionInfo.adapter.empty()
                ? L"CPU / unavailable"
                : utf8ToWide(gConnectionInfo.adapter))
         << L"\n";

    MessageBoxW(owner, info.str().c_str(), L"JerisLink Connection Info",
                MB_OK | MB_ICONINFORMATION);
    logLine("connection.info.opened");
}

using jl::Options;

static std::string envValue(const char* name) {
    char* value = nullptr;
    size_t len = 0;
    if (_dupenv_s(&value, &len, name) != 0 || value == nullptr) return {};
    std::string out(value);
    free(value);
    return out;
}

static LRESULT CALLBACK ViewerWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDM_VIDEO_SETTINGS:
            logLine("video.settings.command source=menu");
            showVideoSettings(hwnd);
            return 0;
        case IDM_CONNECTION_INFO:
            showConnectionInfo(hwnd);
            return 0;
        default:
            break;
        }
        break;
    case WM_SYSCOMMAND:
        if ((wParam & 0xFFF0u) == IDM_VIDEO_SETTINGS) {
            logLine("video.settings.command source=system-menu");
            showVideoSettings(hwnd);
            return 0;
        }
        break;
    case WM_SETFOCUS:
        gViewerFocused = true;
        gHaveMouse = false;
        logLine("focus.set");
        return 0;
    case WM_KILLFOCUS:
        gViewerFocused = false;
        gHaveMouse = false;
        gHookWinDown = false;
        gHookInterceptingWinC = false;
        gHookInterceptingWinSpace = false;
        gHookCapsDown = false;
        gSuppressedShortcutKey = 0;
        gTemporarilyReleasedModifier = 0;
        releaseRemoteModifiers();
        logLine("focus.kill");
        return 0;
    case WM_ACTIVATE:
        gViewerFocused = LOWORD(wParam) != WA_INACTIVE;
        logLine(gViewerFocused ? "focus.activate" : "focus.deactivate");
        return 0;
    case WM_MOUSEACTIVATE:
        gViewerFocused = true;
        logLine("focus.mouse_activate");
        return MA_ACTIVATE;
    case WM_KEYDOWN:
    case WM_SYSKEYDOWN: {
        if (!viewerHasInteractiveFocus(hwnd) || !gControl) break;
        logFirstInput("keyboard");
        const bool repeat = (lParam & (1LL << 30)) != 0;

        // Windows+C is Jerislink's explicit native macOS Control+C escape hatch.
        // The Windows key normally maps to macOS Command, so release it remotely
        // before sending the true Control+C chord.
        const bool winDown = physicalKeyDown(VK_LWIN) || physicalKeyDown(VK_RWIN);
        if (!repeat && wParam == VK_SPACE && winDown) {
            gControl->sendKey(false, 3);
            sendRemoteChord(1, VK_SPACE);
            gSuppressedShortcutKey = VK_SPACE;
            gTemporarilyReleasedModifier = 3;
            logLine("shortcut.win_space=control_space");
            return 0;
        }
        if (!repeat && wParam == 'C' && winDown) {
            gControl->sendKey(false, 3);
            sendRemoteChord(1, 'C');
            gSuppressedShortcutKey = 'C';
            gTemporarilyReleasedModifier = 3;
            logLine("shortcut.win_c=control_c");
            return 0;
        }

        // Preserve Windows editing muscle memory: Ctrl+A/C/V become macOS
        // Command+A/C/V. The physical Ctrl key was already forwarded as Control,
        // so temporarily release it remotely while emitting the Command chord.
        const bool ctrlDown = physicalKeyDown(VK_CONTROL);
        if (!repeat && ctrlDown && isWindowsCtrlCompatShortcut(wParam)) {
            gControl->sendKey(false, 1);
            sendRemoteChord(3, static_cast<uint16_t>(wParam));
            gSuppressedShortcutKey = wParam;
            gTemporarilyReleasedModifier = 1;
            logLine(std::string("shortcut.ctrl_") + static_cast<char>(std::tolower(static_cast<unsigned char>(wParam))) + "=command");
            return 0;
        }

        // Windows generates repeated WM_KEYDOWN / WM_SYSKEYDOWN messages while
        // an ordinary key is held. Forward each repeat so the remote Mac keeps
        // native key-repeat behaviour (Space, Backspace, arrows, etc.). A key
        // currently owned by one of our remapped shortcuts must remain suppressed
        // until its physical key-up; otherwise holding Ctrl+C/V/Z/A would leak the
        // underlying letter after the first translated Command shortcut.
        if (repeat && gSuppressedShortcutKey != 0 &&
            wParam == gSuppressedShortcutKey) {
            return 0;
        }

        const uint16_t key = semanticKey(wParam);
        if (!key) break;
        gControl->sendKey(true, key);
        return 0;
    }
    case WM_KEYUP:
    case WM_SYSKEYUP: {
        if (!viewerHasInteractiveFocus(hwnd) || !gControl) break;
        if (gSuppressedShortcutKey != 0 && wParam == gSuppressedShortcutKey) {
            if (gTemporarilyReleasedModifier == 1 && physicalKeyDown(VK_CONTROL)) {
                gControl->sendKey(true, 1);
            } else if (gTemporarilyReleasedModifier == 3 &&
                       (physicalKeyDown(VK_LWIN) || physicalKeyDown(VK_RWIN))) {
                gControl->sendKey(true, 3);
            }
            gSuppressedShortcutKey = 0;
            gTemporarilyReleasedModifier = 0;
            return 0;
        }
        const uint16_t key = semanticKey(wParam);
        if (!key) break;
        gControl->sendKey(false, key);
        return 0;
    }
    case WM_MR_WIN_DOWN:
        if (viewerHasInteractiveFocus(hwnd) && gControl) {
            gControl->sendKey(true, 3);
            logLine("shortcut.win_hook=command_down");
        }
        return 0;
    case WM_MR_WIN_UP:
        if (gControl) {
            gControl->sendKey(false, 3);
            logLine("shortcut.win_hook=command_up");
        }
        return 0;
    case WM_MR_WIN_C:
        if (viewerHasInteractiveFocus(hwnd) && gControl) {
            // The hook owns the Windows key while the Viewer is focused, so the
            // Windows Shell never sees a Win press/release. Momentarily release
            // remote Command, emit true macOS Control+C, then restore Command
            // until the hook receives the Windows-key release.
            gControl->sendKey(false, 3);
            sendRemoteChord(1, 'C');
            if (gHookWinDown) gControl->sendKey(true, 3);
            logLine("shortcut.win_c_hook=control_c");
        }
        return 0;
    case WM_MR_WIN_SPACE:
        if (viewerHasInteractiveFocus(hwnd) && gControl) {
            // Preserve the user's Parsec muscle memory: Windows+Space becomes
            // native macOS Control+Space for switching input sources. Other
            // Windows-key combinations continue to map to Command unchanged.
            gControl->sendKey(false, 3);
            sendRemoteChord(1, VK_SPACE);
            if (gHookWinDown) gControl->sendKey(true, 3);
            logLine("shortcut.win_space_hook=control_space");
        }
        return 0;
    case WM_MR_CAPS_LOCK:
        if (viewerHasInteractiveFocus(hwnd) && gControl) {
            gControl->sendKey(true, VK_CAPITAL);
            gControl->sendKey(false, VK_CAPITAL);
            logLine("key.caps_lock=remote_only");
        }
        return 0;
    case WM_SETCURSOR:
        if (LOWORD(lParam) == HTCLIENT && gRemoteCursor) {
            SetCursor(gRemoteCursor);
            return TRUE;
        }
        break;
    case WM_MOUSEMOVE: {
        if (!viewerHasInteractiveFocus(hwnd) || !gControl) break;
        logFirstInput("mouse");
        POINT p{static_cast<short>(LOWORD(lParam)), static_cast<short>(HIWORD(lParam))};
        sendAbsolutePointer(hwnd, p);
        gLastMouse = p;
        gHaveMouse = true;
        return 0;
    }
    case WM_LBUTTONDOWN:
        if (viewerHasInteractiveFocus(hwnd) && gControl) {
            POINT p{static_cast<short>(LOWORD(lParam)), static_cast<short>(HIWORD(lParam))};
            sendAbsolutePointer(hwnd, p);
            gLeftClickCount = 1;
            SetCapture(hwnd);
            gControl->sendMouseButtonExtended(0, true, gLeftClickCount);
            return 0;
        }
        break;
    case WM_LBUTTONDBLCLK:
        if (viewerHasInteractiveFocus(hwnd) && gControl) {
            POINT p{static_cast<short>(LOWORD(lParam)), static_cast<short>(HIWORD(lParam))};
            sendAbsolutePointer(hwnd, p);
            gLeftClickCount = 2;
            SetCapture(hwnd);
            gControl->sendMouseButtonExtended(0, true, gLeftClickCount);
            return 0;
        }
        break;
    case WM_LBUTTONUP:
        if (viewerHasInteractiveFocus(hwnd) && gControl) {
            POINT p{static_cast<short>(LOWORD(lParam)), static_cast<short>(HIWORD(lParam))};
            sendAbsolutePointer(hwnd, p);
            gControl->sendMouseButtonExtended(0, false, gLeftClickCount);
            if (gLeftClickCount >= 2) gLeftClickCount = 1;
            ReleaseCapture();
            return 0;
        }
        break;
    case WM_RBUTTONDOWN:
        if (viewerHasInteractiveFocus(hwnd) && gControl) {
            POINT p{static_cast<short>(LOWORD(lParam)), static_cast<short>(HIWORD(lParam))};
            sendAbsolutePointer(hwnd, p);
            SetCapture(hwnd); gControl->sendMouseButton(1, true); return 0;
        }
        break;
    case WM_RBUTTONUP:
        if (viewerHasInteractiveFocus(hwnd) && gControl) {
            POINT p{static_cast<short>(LOWORD(lParam)), static_cast<short>(HIWORD(lParam))};
            sendAbsolutePointer(hwnd, p);
            gControl->sendMouseButton(1, false); ReleaseCapture(); return 0;
        }
        break;
    case WM_MBUTTONDOWN:
        if (viewerHasInteractiveFocus(hwnd) && gControl) {
            POINT p{static_cast<short>(LOWORD(lParam)), static_cast<short>(HIWORD(lParam))};
            sendAbsolutePointer(hwnd, p);
            SetCapture(hwnd); gControl->sendMouseButton(2, true); return 0;
        }
        break;
    case WM_MBUTTONUP:
        if (viewerHasInteractiveFocus(hwnd) && gControl) {
            POINT p{static_cast<short>(LOWORD(lParam)), static_cast<short>(HIWORD(lParam))};
            sendAbsolutePointer(hwnd, p);
            gControl->sendMouseButton(2, false); ReleaseCapture(); return 0;
        }
        break;
    case WM_MOUSEWHEEL: {
        if (viewerHasInteractiveFocus(hwnd) && gControl) {
            int delta = static_cast<short>(HIWORD(wParam));
            delta = std::clamp(static_cast<int>(std::lround(delta * gScrollScale)), -32767, 32767);
            gControl->sendScroll(0, static_cast<int16_t>(delta));
            return 0;
        }
        break;
    }
    case WM_MOUSEHWHEEL: {
        if (viewerHasInteractiveFocus(hwnd) && gControl) {
            int delta = static_cast<short>(HIWORD(wParam));
            delta = std::clamp(static_cast<int>(std::lround(delta * gScrollScale)), -32767, 32767);
            gControl->sendScroll(static_cast<int16_t>(delta), 0);
            return 0;
        }
        break;
    }
    case WM_SIZE:
        gHaveMouse = false;
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT:
        paintCpuFrame(hwnd);
        return 0;
    case WM_CLOSE:
        gWindowClosed = true;
        releaseRemoteModifiers();
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        gWindowClosed = true;
        if (gKeyboardHook) {
            UnhookWindowsHookEx(gKeyboardHook);
            gKeyboardHook = nullptr;
        }
        gViewerHwnd = nullptr;
        PostQuitMessage(0);
        return 0;
    default:
        break;
    }
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

static HMENU createViewerMenu() {
    HMENU menuBar = CreateMenu();
    HMENU connectionMenu = CreatePopupMenu();
    HMENU settingsMenu = CreatePopupMenu();
    if (!menuBar || !connectionMenu || !settingsMenu) {
        if (settingsMenu) DestroyMenu(settingsMenu);
        if (connectionMenu) DestroyMenu(connectionMenu);
        if (menuBar) DestroyMenu(menuBar);
        return nullptr;
    }

    const bool ok =
        AppendMenuW(connectionMenu, MF_STRING, IDM_CONNECTION_INFO, L"&Connection Info...") &&
        AppendMenuW(settingsMenu, MF_STRING, IDM_VIDEO_SETTINGS, L"&Connection Settings...") &&
        AppendMenuW(menuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(connectionMenu), L"&Connection") &&
        AppendMenuW(menuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(settingsMenu), L"&Settings");
    if (!ok) {
        DestroyMenu(menuBar);
        return nullptr;
    }
    return menuBar;
}

static HWND createViewerWindow(UINT32 clientW, UINT32 clientH) {
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    HINSTANCE hi = GetModuleHandleW(nullptr);
    const wchar_t* cls = L"JerislinkViewerClass";
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.style = CS_DBLCLKS;
    wc.lpfnWndProc = ViewerWndProc;
    wc.hInstance = hi;
    wc.hIcon = static_cast<HICON>(LoadImageW(hi, MAKEINTRESOURCEW(IDI_JERISLINK), IMAGE_ICON, 32, 32, LR_DEFAULTCOLOR));
    wc.hIconSm = static_cast<HICON>(LoadImageW(hi, MAKEINTRESOURCEW(IDI_JERISLINK), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR));
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
    wc.lpszClassName = cls;
    if (!RegisterClassExW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        throw std::runtime_error("RegisterClassExW failed");
    }

    DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX |
                  WS_MAXIMIZEBOX | WS_THICKFRAME;
    HMENU menuBar = createViewerMenu();
    RECT r{0, 0, static_cast<LONG>(clientW), static_cast<LONG>(clientH)};
    AdjustWindowRect(&r, style, menuBar != nullptr);
    HWND hwnd = CreateWindowExW(0, cls, L"JerisLink \u2014 Connecting...",
                                style, CW_USEDEFAULT, CW_USEDEFAULT,
                                r.right - r.left, r.bottom - r.top,
                                nullptr, menuBar, hi, nullptr);
    if (!hwnd) {
        if (menuBar) DestroyMenu(menuBar);
        throw std::runtime_error("CreateWindowExW failed");
    }
    logLine(menuBar
        ? "viewer.menu connection_info=yes video_settings=yes"
        : "viewer.menu unavailable");
    if (HMENU systemMenu = GetSystemMenu(hwnd, FALSE)) {
        AppendMenuW(systemMenu, MF_SEPARATOR, 0, nullptr);
        AppendMenuW(systemMenu, MF_STRING, IDM_VIDEO_SETTINGS, L"Connection Settings...");
    }
    applyModernWindowChrome(hwnd);
    SendMessageW(hwnd, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(wc.hIcon));
    SendMessageW(hwnd, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(wc.hIconSm));
    gViewerHwnd = hwnd;
    gRemoteCursorShape = 0;
    gRemoteCursor = LoadCursorW(nullptr, IDC_ARROW);
    gKeyboardHook = SetWindowsHookExW(WH_KEYBOARD_LL, ViewerKeyboardHook, hi, 0);
    if (gKeyboardHook) logLine("keyboard_hook=installed");
    else logLine("keyboard_hook=failed error=" + std::to_string(GetLastError()));
    return hwnd;
}

static void pumpMessages() {
    MSG m{};
    while (PeekMessageW(&m, nullptr, 0, 0, PM_REMOVE)) {
        if (m.message == WM_QUIT) gWindowClosed = true;
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
}

class CpuPresenter {
public:
    CpuPresenter(HWND hwnd, UINT32 srcW, UINT32 srcH, UINT32 outW, UINT32 outH)
        : hwnd_(hwnd), srcW_(srcW), srcH_(srcH), outW_(outW), outH_(outH),
          bgra_(static_cast<size_t>(srcW) * srcH * 4) {
        std::memset(&bmi_, 0, sizeof(bmi_));
        bmi_.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bmi_.bmiHeader.biWidth = static_cast<LONG>(srcW_);
        bmi_.bmiHeader.biHeight = -static_cast<LONG>(srcH_);
        bmi_.bmiHeader.biPlanes = 1;
        bmi_.bmiHeader.biBitCount = 32;
        bmi_.bmiHeader.biCompression = BI_RGB;
        gCpuPresenter = this;
        ensureBackBuffer(static_cast<int>(outW_), static_cast<int>(outH_));
        logLine("present.path=cpu-nv12-gdi-doublebuffer");
    }

    ~CpuPresenter() {
        if (memDC_) {
            if (oldBitmap_) SelectObject(memDC_, oldBitmap_);
            if (memBitmap_) DeleteObject(memBitmap_);
            DeleteDC(memDC_);
        }
        if (gCpuPresenter == this) gCpuPresenter = nullptr;
    }

    void setLayout(UINT32 stride, UINT32 storageHeight) {
        stride_ = stride ? stride : srcW_;
        storageHeight_ = storageHeight ? storageHeight : srcH_;
        std::ostringstream os;
        os << "cpu.nv12_layout stride=" << stride_ << " storageHeight=" << storageHeight_;
        logLine(os.str());
    }

    uint64_t presented() const { return presented_; }
    uint64_t busyDrops() const { return 0; }
    uint64_t nonDxgiDrops() const { return bufferDrops_; }
    double avgPresentMs() const { return presented_ ? totalMs_ / double(presented_) : 0.0; }
    double maxPresentMs() const { return maxMs_; }

    void present(IMFSample* sample) {
        if (!sample || gWindowClosed) return;
        ComPtr<IMFMediaBuffer> buffer;
        if (FAILED(sample->ConvertToContiguousBuffer(&buffer))) {
            ++bufferDrops_;
            return;
        }

        BYTE* data = nullptr;
        DWORD maxLen = 0, curLen = 0;
        if (FAILED(buffer->Lock(&data, &maxLen, &curLen))) {
            ++bufferDrops_;
            return;
        }
        const size_t required = static_cast<size_t>(stride_) * storageHeight_ * 3 / 2;
        if (!data || curLen < required) {
            buffer->Unlock();
            ++bufferDrops_;
            return;
        }

        const auto t0 = std::chrono::steady_clock::now();
        if (presented_ == 0) logFirstFrameStats(data, curLen);
        convertNv12ToBgra(data, stride_);
        if (presented_ == 0) dumpFirstFrameBmp();
        buffer->Unlock();
        hasFrame_ = true;
        drawFrame();
        const double ms = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - t0).count();
        ++presented_;
        totalMs_ += ms;
        maxMs_ = std::max(maxMs_, ms);

        if (presented_ == 1) {
            std::ostringstream os;
            os << "FIRST_PRESENT cpu-nv12-gdi size=" << srcW_ << "x" << srcH_;
            logLine(os.str());
        }
    }

    void paintToDc(HDC dc) {
        RECT client{};
        GetClientRect(hwnd_, &client);
        const int cw = std::max<LONG>(1, client.right - client.left);
        const int ch = std::max<LONG>(1, client.bottom - client.top);
        ensureBackBuffer(cw, ch);
        if (!memDC_) return;

        RECT fill{0, 0, cw, ch};
        FillRect(memDC_, &fill, static_cast<HBRUSH>(GetStockObject(BLACK_BRUSH)));
        if (hasFrame_) {
            const double srcAspect = static_cast<double>(srcW_) / srcH_;
            int dw = cw, dh = ch, dx = 0, dy = 0;
            if (static_cast<double>(cw) / ch > srcAspect) {
                dw = std::max(1, static_cast<int>(ch * srcAspect));
                dx = (cw - dw) / 2;
            } else {
                dh = std::max(1, static_cast<int>(cw / srcAspect));
                dy = (ch - dh) / 2;
            }
            SetStretchBltMode(memDC_, COLORONCOLOR);
            StretchDIBits(memDC_, dx, dy, dw, dh,
                0, 0, static_cast<int>(srcW_), static_cast<int>(srcH_),
                bgra_.data(), &bmi_, DIB_RGB_COLORS, SRCCOPY);
        }
        BitBlt(dc, 0, 0, cw, ch, memDC_, 0, 0, SRCCOPY);
    }

private:
    void ensureBackBuffer(int width, int height) {
        if (memDC_ && memBitmap_ && width == backW_ && height == backH_) return;
        if (memDC_) {
            if (oldBitmap_) SelectObject(memDC_, oldBitmap_);
            if (memBitmap_) DeleteObject(memBitmap_);
            DeleteDC(memDC_);
            memDC_ = nullptr;
            memBitmap_ = nullptr;
            oldBitmap_ = nullptr;
        }
        HDC windowDC = GetDC(hwnd_);
        if (!windowDC) return;
        memDC_ = CreateCompatibleDC(windowDC);
        memBitmap_ = CreateCompatibleBitmap(windowDC, width, height);
        ReleaseDC(hwnd_, windowDC);
        if (!memDC_ || !memBitmap_) {
            if (memBitmap_) DeleteObject(memBitmap_);
            if (memDC_) DeleteDC(memDC_);
            memDC_ = nullptr;
            memBitmap_ = nullptr;
            return;
        }
        oldBitmap_ = static_cast<HBITMAP>(SelectObject(memDC_, memBitmap_));
        backW_ = width;
        backH_ = height;
    }

    void logFirstFrameStats(const uint8_t* nv12, size_t curLen) {
        uint8_t ymin = 255, ymax = 0, umin = 255, umax = 0, vmin = 255, vmax = 0;
        uint64_t ysum = 0, usum = 0, vsum = 0, yc = 0, uvc = 0;
        const uint8_t* uv = nv12 + static_cast<size_t>(stride_) * storageHeight_;
        for (UINT y = 0; y < srcH_; y += 4) {
            const uint8_t* row = nv12 + static_cast<size_t>(y) * stride_;
            for (UINT x = 0; x < srcW_; x += 4) { ymin = std::min(ymin, row[x]); ymax = std::max(ymax, row[x]); ysum += row[x]; ++yc; }
        }
        for (UINT y = 0; y < srcH_ / 2; y += 2) {
            const uint8_t* row = uv + static_cast<size_t>(y) * stride_;
            for (UINT x = 0; x + 1 < srcW_; x += 4) {
                umin = std::min(umin, row[x]); umax = std::max(umax, row[x]); usum += row[x];
                vmin = std::min(vmin, row[x + 1]); vmax = std::max(vmax, row[x + 1]); vsum += row[x + 1]; ++uvc;
            }
        }
        std::ostringstream os;
        os << "firstframe.nv12 len=" << curLen
           << " Y=" << int(ymin) << ".." << int(ymax) << " avg=" << (yc ? double(ysum)/yc : 0)
           << " U=" << int(umin) << ".." << int(umax) << " avg=" << (uvc ? double(usum)/uvc : 0)
           << " V=" << int(vmin) << ".." << int(vmax) << " avg=" << (uvc ? double(vsum)/uvc : 0);
        logLine(os.str());
    }

    void dumpFirstFrameBmp() {
        const std::string path = tempLogPath("jerislink-first-frame.bmp");
        BITMAPFILEHEADER fh{};
        fh.bfType = 0x4D42;
        fh.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
        fh.bfSize = fh.bfOffBits + static_cast<DWORD>(bgra_.size());
        BITMAPINFOHEADER ih = bmi_.bmiHeader;
        ih.biSizeImage = static_cast<DWORD>(bgra_.size());
        std::ofstream f(path, std::ios::binary | std::ios::trunc);
        f.write(reinterpret_cast<const char*>(&fh), sizeof(fh));
        f.write(reinterpret_cast<const char*>(&ih), sizeof(ih));
        f.write(reinterpret_cast<const char*>(bgra_.data()), static_cast<std::streamsize>(bgra_.size()));
        f.flush();
        logLine("firstframe.bmp=" + std::string(path));
    }

    static uint8_t clamp8(int v) {
        return static_cast<uint8_t>(v < 0 ? 0 : (v > 255 ? 255 : v));
    }

    void writePixel(uint8_t* dst, int y, int u, int v) {
        int c = y - 16;
        if (c < 0) c = 0;
        const int d = u - 128;
        const int e = v - 128;
        const int r = (298 * c + 459 * e + 128) >> 8;
        const int g = (298 * c - 55 * d - 136 * e + 128) >> 8;
        const int b = (298 * c + 541 * d + 128) >> 8;
        dst[0] = clamp8(b);
        dst[1] = clamp8(g);
        dst[2] = clamp8(r);
        dst[3] = 255;
    }

    void convertNv12ToBgra(const uint8_t* nv12, UINT stride) {
        const uint8_t* yPlane = nv12;
        const uint8_t* uvPlane = nv12 + static_cast<size_t>(stride) * storageHeight_;
        for (UINT y = 0; y < srcH_; ++y) {
            const uint8_t* yRow = yPlane + static_cast<size_t>(y) * stride;
            const uint8_t* uvRow = uvPlane + static_cast<size_t>(y / 2) * stride;
            uint8_t* out = bgra_.data() + static_cast<size_t>(y) * srcW_ * 4;
            for (UINT x = 0; x < srcW_; x += 2) {
                const int u = uvRow[x];
                const int v = uvRow[x + 1];
                writePixel(out + static_cast<size_t>(x) * 4, yRow[x], u, v);
                if (x + 1 < srcW_) {
                    writePixel(out + static_cast<size_t>(x + 1) * 4, yRow[x + 1], u, v);
                }
            }
        }
    }

    void drawFrame() {
        InvalidateRect(hwnd_, nullptr, FALSE);
        UpdateWindow(hwnd_);
    }

    HWND hwnd_ = nullptr;
    UINT32 srcW_, srcH_, outW_, outH_;
    UINT32 stride_ = 0;
    UINT32 storageHeight_ = 0;
    BITMAPINFO bmi_{};
    HDC memDC_ = nullptr;
    HBITMAP memBitmap_ = nullptr;
    HBITMAP oldBitmap_ = nullptr;
    int backW_ = 0;
    int backH_ = 0;
    std::vector<uint8_t> bgra_;
    bool hasFrame_ = false;
    uint64_t presented_ = 0;
    uint64_t bufferDrops_ = 0;
    double totalMs_ = 0.0;
    double maxMs_ = 0.0;
};

static void paintCpuFrame(HWND hwnd) {
    PAINTSTRUCT ps{};
    HDC dc = BeginPaint(hwnd, &ps);
    if (dc) {
        if (gHardwarePresenterActive) {
            // DXGI owns the client area while the hardware presenter is
            // active. Validate WM_PAINT without painting over the swapchain.
        } else if (gCpuPresenter) {
            gCpuPresenter->paintToDc(dc);
        } else {
            RECT r{};
            GetClientRect(hwnd, &r);
            FillRect(dc, &r, static_cast<HBRUSH>(GetStockObject(BLACK_BRUSH)));
        }
        EndPaint(hwnd, &ps);
    }
}

class MfCpuDecoder {
public:
    MfCpuDecoder(CpuPresenter& presenter, UINT32 width, UINT32 height, UINT32 fps,
                 JerisVideoCodec codec)
        : presenter_(presenter), width_(width), height_(height), fps_(fps), codec_(codec) {
        createDecoder();
    }
    ~MfCpuDecoder() {
        if (decoder_ && !finished_) {
            decoder_->ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0);
            decoder_->ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0);
        }
    }

    bool hardwarePath() const { return false; }
    uint64_t decodedFrames() const { return decodedFrames_; }
    uint64_t streamChanges() const { return streamChanges_; }
    uint64_t inputBackpressure() const { return inputBackpressure_; }

    void resetForNewStream() {
        if (!decoder_) return;
        check(decoder_->ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0), "decoder flush");
        check(decoder_->ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0), "decoder restart stream");
        logLine("decoder.stream_reset");
    }

    void submit(uint64_t frameId, const std::vector<uint8_t>& annexB, bool discontinuity) {
        ComPtr<IMFSample> sample;
        ComPtr<IMFMediaBuffer> buffer;
        check(MFCreateSample(&sample), "MFCreateSample");
        check(MFCreateMemoryBuffer(static_cast<DWORD>(annexB.size()), &buffer), "MFCreateMemoryBuffer");
        BYTE* dst = nullptr;
        DWORD maxLen = 0, curLen = 0;
        check(buffer->Lock(&dst, &maxLen, &curLen), "buffer Lock");
        std::memcpy(dst, annexB.data(), annexB.size());
        buffer->Unlock();
        check(buffer->SetCurrentLength(static_cast<DWORD>(annexB.size())), "SetCurrentLength");
        check(sample->AddBuffer(buffer.Get()), "AddBuffer");

        const LONGLONG t = static_cast<LONGLONG>((frameId - 1) * 10000000ULL / fps_);
        const LONGLONG d = static_cast<LONGLONG>(10000000ULL / fps_);
        sample->SetSampleTime(t);
        sample->SetSampleDuration(d);
        if (discontinuity) sample->SetUINT32(MFSampleExtension_Discontinuity, TRUE);

        HRESULT hr = decoder_->ProcessInput(0, sample.Get(), 0);
        if (hr == MF_E_NOTACCEPTING) {
            ++inputBackpressure_;
            drain();
            hr = decoder_->ProcessInput(0, sample.Get(), 0);
        }
        check(hr, "decoder ProcessInput");
        drain();
    }

    void finish() {
        if (finished_) return;
        check(decoder_->ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0), "NOTIFY_END_OF_STREAM");
        check(decoder_->ProcessMessage(MFT_MESSAGE_COMMAND_DRAIN, 0), "COMMAND_DRAIN");
        drain();
        check(decoder_->ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0), "NOTIFY_END_STREAMING");
        finished_ = true;
    }

private:
    void drain() {
        for (;;) {
            MFT_OUTPUT_STREAM_INFO osi{};
            check(decoder_->GetOutputStreamInfo(0, &osi), "GetOutputStreamInfo");
            ComPtr<IMFSample> clientSample;
            ComPtr<IMFMediaBuffer> clientBuffer;
            MFT_OUTPUT_DATA_BUFFER odb{};
            if ((osi.dwFlags & MFT_OUTPUT_STREAM_PROVIDES_SAMPLES) == 0 &&
                (osi.dwFlags & MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES) == 0) {
                check(MFCreateSample(&clientSample), "MFCreateSample output");
                const DWORD cb = std::max<DWORD>(osi.cbSize, width_ * height_ * 3 / 2);
                check(MFCreateMemoryBuffer(cb, &clientBuffer), "MFCreateMemoryBuffer output");
                check(clientSample->AddBuffer(clientBuffer.Get()), "AddBuffer output");
                odb.pSample = clientSample.Get();
            }
            DWORD status = 0;
            HRESULT hr = decoder_->ProcessOutput(0, 1, &odb, &status);
            if (odb.pEvents) odb.pEvents->Release();
            if (hr == MF_E_TRANSFORM_NEED_MORE_INPUT) return;
            if (hr == MF_E_TRANSFORM_STREAM_CHANGE) {
                ++streamChanges_;
                setOutputType();
                continue;
            }
            check(hr, "decoder ProcessOutput");
            if (odb.pSample) {
                ++decodedFrames_;
                presenter_.present(odb.pSample);
            }
            if (odb.pSample && odb.pSample != clientSample.Get()) odb.pSample->Release();
        }
    }

    void createDecoder() {
        std::string decoderName;
        decoder_ = createJerisMfDecoder(codec_, false, &decoderName);
        ComPtr<IMFAttributes> attrs;
        if (SUCCEEDED(decoder_->GetAttributes(&attrs))) {
            attrs->SetUINT32(MF_LOW_LATENCY, TRUE);
        }

        ComPtr<IMFMediaType> input;
        check(MFCreateMediaType(&input), "MFCreateMediaType input");
        check(input->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video), "input major type");
        check(input->SetGUID(MF_MT_SUBTYPE, jerisVideoCodecInputSubtype(codec_)), "input subtype");
        check(MFSetAttributeSize(input.Get(), MF_MT_FRAME_SIZE, width_, height_), "input frame size");
        check(MFSetAttributeRatio(input.Get(), MF_MT_FRAME_RATE, fps_, 1), "input frame rate");
        check(input->SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive), "input interlace");
        check(decoder_->SetInputType(0, input.Get(), 0), "SetInputType");
        setOutputType();
        check(decoder_->ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0), "BEGIN_STREAMING");
        check(decoder_->ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0), "START_OF_STREAM");
        logLine("decoder.mft=" + decoderName);
        logLine(std::string("decoder.backend=cpu-mf-") + jerisVideoCodecName(codec_) + "-nv12");
    }

    void setOutputType() {
        ComPtr<IMFMediaType> chosen;
        for (DWORD i = 0;; ++i) {
            ComPtr<IMFMediaType> t;
            HRESULT hr = decoder_->GetOutputAvailableType(0, i, &t);
            if (hr == MF_E_NO_MORE_TYPES) break;
            check(hr, "GetOutputAvailableType");
            GUID subtype{};
            if (SUCCEEDED(t->GetGUID(MF_MT_SUBTYPE, &subtype)) && subtype == MFVideoFormat_NV12) {
                chosen = t;
                break;
            }
        }
        if (!chosen) throw std::runtime_error("decoder did not offer NV12 output");
        check(decoder_->SetOutputType(0, chosen.Get(), 0), "SetOutputType NV12");

        UINT32 strideValue = 0;
        if (FAILED(chosen->GetUINT32(MF_MT_DEFAULT_STRIDE, &strideValue)) || strideValue == 0) {
            LONG computedStride = 0;
            if (SUCCEEDED(MFGetStrideForBitmapInfoHeader(MFVideoFormat_NV12.Data1, width_, &computedStride))) {
                strideValue = static_cast<UINT32>(computedStride < 0 ? -computedStride : computedStride);
            } else {
                strideValue = width_;
            }
        }
        UINT32 mtW = 0, mtH = 0;
        (void)MFGetAttributeSize(chosen.Get(), MF_MT_FRAME_SIZE, &mtW, &mtH);
        presenter_.setLayout(strideValue, mtH ? mtH : height_);
        std::ostringstream os;
        os << "decoder.output=NV12 " << mtW << "x" << mtH << " stride=" << strideValue;
        logLine(os.str());
    }

    CpuPresenter& presenter_;
    UINT32 width_, height_, fps_;
    JerisVideoCodec codec_ = JerisVideoCodec::H264;
    ComPtr<IMFTransform> decoder_;
    bool finished_ = false;
    uint64_t decodedFrames_ = 0;
    uint64_t streamChanges_ = 0;
    uint64_t inputBackpressure_ = 0;
};

class VideoPipeline {
public:
    VideoPipeline(HWND hwnd, UINT32 width, UINT32 height, UINT32 fps,
                  const std::string& requestedBackend, const std::string& codecName)
        : hwnd_(hwnd), width_(width), height_(height), fps_(fps),
          requestedBackend_(requestedBackend), codec_(jerisVideoCodecFromString(codecName)) {
        logLine("video.backend.requested=" + requestedBackend_);
        logLine(std::string("video.codec=") + jerisVideoCodecName(codec_));
        if (requestedBackend_ != "cpu") {
            try {
                logLine("gpu.init=attempt");
                hardware_ = std::make_unique<HardwareVideoPipeline>(
                    hwnd_, width_, height_, fps_, codec_,
                    [](const std::string& message) { logLine(message); });
                adapterName_ = hardware_->adapterName();
                gHardwarePresenterActive = true;
                logLine("video.backend.active=hardware-d3d11-video-processor");
                return;
            } catch (const std::exception& e) {
                ++fallbacks_;
                logLine(std::string("gpu.init_failed reason=") + e.what());
                if (codec_ == JerisVideoCodec::HEVC) {
                    logLine("gpu.fallback=blocked reason=hevc-requires-hardware");
                    throw;
                }
                logLine("gpu.fallback=cpu-gdi reason=initialization");
            }
        }
        startCpu();
    }

    ~VideoPipeline() {
        gHardwarePresenterActive = false;
    }

    void submit(uint64_t frameId, const std::vector<uint8_t>& annexB,
                bool discontinuity, bool keyFrame) {
        if (hardware_) {
            try {
                hardware_->submit(frameId, annexB, discontinuity);
                const UINT32 activeW = hardware_->activeWidth();
                const UINT32 activeH = hardware_->activeHeight();
                if (activeW && activeH &&
                    (activeW != gRemoteWidth || activeH != gRemoteHeight)) {
                    gRemoteWidth = activeW;
                    gRemoteHeight = activeH;
                    gConnectionInfo.remoteWidth = activeW;
                    gConnectionInfo.remoteHeight = activeH;
                    logLine("input.remote_size=" + std::to_string(activeW) + "x" +
                            std::to_string(activeH));
                }
                return;
            } catch (const std::exception& e) {
                logLine(std::string("gpu.runtime_failure reason=") + e.what());
                fallbackToCpu();
            }
        }

        if (waitingForCpuKeyframe_) {
            if (!keyFrame) {
                ++keyframeWaitDrops_;
                return;
            }
            waitingForCpuKeyframe_ = false;
            discontinuity = true;
            logLine("gpu.fallback_keyframe_reacquired fid=" + std::to_string(frameId));
        }
        cpuDecoder_->submit(frameId, annexB, discontinuity);
    }

    void resetForNewStream() {
        // The Windows HEVCVideoExtension can accept a new IDR after a discontinuity,
        // but FLUSH + START_OF_STREAM during loss recovery can leave ProcessInput
        // blocked on the next complete HEVC IDR. Keep the HEVC MFT alive and let
        // strict recovery wait for a complete forced IDR instead. H.264 retains
        // the existing explicit decoder reset path.
        if (codec_ == JerisVideoCodec::HEVC) {
            logLine("decoder.stream_reset_skipped codec=hevc");
            return;
        }
        if (hardware_) {
            try {
                hardware_->resetForNewStream();
                return;
            } catch (const std::exception& e) {
                logLine(std::string("gpu.reset_failure reason=") + e.what());
                fallbackToCpu();
                return;
            }
        }
        if (cpuDecoder_) cpuDecoder_->resetForNewStream();
    }

    void finish() {
        if (hardware_) {
            try {
                hardware_->finish();
            } catch (const std::exception& e) {
                logLine(std::string("gpu.finish_failure reason=") + e.what());
                snapshotHardware();
                gHardwarePresenterActive = false;
                hardware_->abandon();
                hardware_.reset();
                ++fallbacks_;
            }
            return;
        }
        if (cpuDecoder_) cpuDecoder_->finish();
    }

    uint64_t decodedFrames() const {
        return hardwareDecodedSaved_ + (hardware_ ? hardware_->decodedFrames() : 0) +
               (cpuDecoder_ ? cpuDecoder_->decodedFrames() : 0);
    }
    uint64_t presented() const {
        return hardwarePresentedSaved_ + (hardware_ ? hardware_->presented() : 0) +
               (cpuPresenter_ ? cpuPresenter_->presented() : 0);
    }
    uint64_t busyDrops() const {
        return hardwareBusySaved_ + (hardware_ ? hardware_->busyDrops() : 0) +
               (cpuPresenter_ ? cpuPresenter_->busyDrops() : 0);
    }
    uint64_t nonDxgiDrops() const {
        return hardwareNonDxgiSaved_ + (hardware_ ? hardware_->nonDxgiDrops() : 0) +
               (cpuPresenter_ ? cpuPresenter_->nonDxgiDrops() : 0);
    }
    uint64_t streamChanges() const {
        return hardwareStreamChangesSaved_ + (hardware_ ? hardware_->streamChanges() : 0) +
               (cpuDecoder_ ? cpuDecoder_->streamChanges() : 0);
    }
    uint64_t inputBackpressure() const {
        return hardwareBackpressureSaved_ + (hardware_ ? hardware_->inputBackpressure() : 0) +
               (cpuDecoder_ ? cpuDecoder_->inputBackpressure() : 0);
    }
    double avgPresentMs() const {
        const uint64_t hwLiveFrames = hardware_ ? hardware_->presented() : 0;
        const uint64_t cpuFrames = cpuPresenter_ ? cpuPresenter_->presented() : 0;
        const uint64_t count = hardwarePresentedSaved_ + hwLiveFrames + cpuFrames;
        if (!count) return 0.0;
        double total = hardwarePresentMsSaved_;
        if (hardware_) total += hardware_->avgPresentMs() * static_cast<double>(hwLiveFrames);
        if (cpuPresenter_) total += cpuPresenter_->avgPresentMs() * static_cast<double>(cpuFrames);
        return total / static_cast<double>(count);
    }
    double maxPresentMs() const {
        double value = hardwarePresentMaxSaved_;
        if (hardware_) value = std::max(value, hardware_->maxPresentMs());
        if (cpuPresenter_) value = std::max(value, cpuPresenter_->maxPresentMs());
        return value;
    }
    uint64_t fallbackCount() const { return fallbacks_; }
    uint64_t keyframeWaitDrops() const { return keyframeWaitDrops_; }
    std::string activeBackend() const {
        return hardware_ ? "hardware-d3d11-video-processor" : "cpu-gdi";
    }
    const std::string& adapterName() const { return adapterName_; }
    std::string decoderName() const {
        if (hardware_) return hardware_->decoderName();
        return codec_ == JerisVideoCodec::HEVC
            ? "Media Foundation HEVC decoder"
            : "CMSH264DecoderMFT";
    }

private:
    void startCpu() {
        gHardwarePresenterActive = false;
        cpuPresenter_ = std::make_unique<CpuPresenter>(
            hwnd_, width_, height_, width_, height_);
        cpuDecoder_ = std::make_unique<MfCpuDecoder>(*cpuPresenter_, width_, height_, fps_, codec_);
        logLine("decoder.d3d11_aware=NO");
        logLine("video.backend.active=cpu-gdi");
        InvalidateRect(hwnd_, nullptr, FALSE);
    }

    void snapshotHardware() {
        if (!hardware_) return;
        const uint64_t frames = hardware_->presented();
        hardwareDecodedSaved_ += hardware_->decodedFrames();
        hardwarePresentedSaved_ += frames;
        hardwareBusySaved_ += hardware_->busyDrops();
        hardwareNonDxgiSaved_ += hardware_->nonDxgiDrops();
        hardwareStreamChangesSaved_ += hardware_->streamChanges();
        hardwareBackpressureSaved_ += hardware_->inputBackpressure();
        hardwarePresentMsSaved_ += hardware_->avgPresentMs() * static_cast<double>(frames);
        hardwarePresentMaxSaved_ = std::max(hardwarePresentMaxSaved_, hardware_->maxPresentMs());
    }

    void fallbackToCpu() {
        if (codec_ == JerisVideoCodec::HEVC) {
            throw std::runtime_error("HEVC hardware pipeline failed; CPU HEVC fallback is disabled");
        }
        snapshotHardware();
        gHardwarePresenterActive = false;
        hardware_->abandon();
        hardware_.reset();
        ++fallbacks_;
        logLine("gpu.fallback=cpu-gdi reason=runtime");
        startCpu();
        gConnectionInfo.backend = activeBackend();
        gConnectionInfo.decoder = decoderName();
        gConnectionInfo.adapter.clear();
        waitingForCpuKeyframe_ = true;
    }

    HWND hwnd_ = nullptr;
    UINT32 width_ = 0;
    UINT32 height_ = 0;
    UINT32 fps_ = 0;
    std::string requestedBackend_;
    JerisVideoCodec codec_ = JerisVideoCodec::H264;
    std::string adapterName_;
    std::unique_ptr<HardwareVideoPipeline> hardware_;
    std::unique_ptr<CpuPresenter> cpuPresenter_;
    std::unique_ptr<MfCpuDecoder> cpuDecoder_;
    bool waitingForCpuKeyframe_ = false;
    uint64_t fallbacks_ = 0;
    uint64_t keyframeWaitDrops_ = 0;
    uint64_t hardwareDecodedSaved_ = 0;
    uint64_t hardwarePresentedSaved_ = 0;
    uint64_t hardwareBusySaved_ = 0;
    uint64_t hardwareNonDxgiSaved_ = 0;
    uint64_t hardwareStreamChangesSaved_ = 0;
    uint64_t hardwareBackpressureSaved_ = 0;
    double hardwarePresentMsSaved_ = 0.0;
    double hardwarePresentMaxSaved_ = 0.0;
};

static jl::LaunchRequest resolveLaunchFromSystem(int argc, char** argv) {
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) args.emplace_back(argv[i]);
    return jl::resolveLaunch(args, loadSavedSettings(), envValue("JERISLINK_SOURCE_IP"),
                             detectTailscaleIPv4());
}

static int appMain(int argc, char** argv) {
    std::remove(kLogPath.c_str());
    logLine(std::string("viewer.start pid=") + std::to_string(GetCurrentProcessId()));
    auto request = resolveLaunchFromSystem(argc, argv);

    // --print-config PATH: write the resolved connection and exit. Never shows UI.
    if (!request.printConfigPath.empty()) {
        std::ofstream out(request.printConfigPath, std::ios::trunc);
        out << jl::describeLaunch(request);
        return out ? (request.status == jl::LaunchStatus::Ok ? 0 : 3) : 4;
    }
    if (request.status == jl::LaunchStatus::InvalidArgs) {
        logLine("usage error: " + request.error);
        const std::wstring message =
            L"JerisLink could not read its command-line arguments (" +
            wideFromAscii(request.error) +
            L").\n\nStart JerisLink without arguments to use the saved settings.";
        MessageBoxW(nullptr, message.c_str(), L"JerisLink", MB_OK | MB_ICONERROR);
        return 2;
    }

    // First run (no host anywhere), --settings, or Shift held while starting:
    // show the settings dialog, then connect with what was saved.
    const bool shiftHeld = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
    if (request.status == jl::LaunchStatus::NeedsSetup || request.openSettings || shiftHeld) {
        logLine(std::string("settings.startup_dialog reason=") +
                (request.status == jl::LaunchStatus::NeedsSetup ? "no-host"
                 : request.openSettings ? "flag" : "shift"));
        if (runSettingsDialog(nullptr, kSettingsDialogConnect) != IDOK) {
            logLine("settings.startup_dialog cancelled");
            return 0;
        }
        request = resolveLaunchFromSystem(argc, argv);
    }
    if (request.status == jl::LaunchStatus::NeedsSetup) {
        logLine("usage error: no host address");
        MessageBoxW(nullptr, L"JerisLink needs the Mac host address. Start JerisLink again and enter it.",
                    L"JerisLink", MB_OK | MB_ICONERROR);
        return 2;
    }
    if (request.status == jl::LaunchStatus::NoTailnet) {
        logLine("usage error: no active Tailscale IPv4 address");
        MessageBoxW(nullptr,
            L"This PC has no active Tailscale address (100.64.x.x).\n\n"
            L"Connect Tailscale and start JerisLink again, or hold Shift while starting "
            L"JerisLink and enter this PC's address.",
            L"JerisLink", MB_OK | MB_ICONERROR);
        return 2;
    }
    logLine("launch.config host=" + request.options.sourceIp +
            " host_source=" + request.hostSource +
            " bind=" + request.options.bindIp +
            " bind_source=" + request.bindSource);
    Options o = request.options;
    gConnectionInfo = ConnectionInfoState{};
    gConnectionInfo.configuredCodec = o.codec;
    gConnectionInfo.configuredBitrateMbps = o.bitrateMbps;
    gConnectionInfo.remoteWidth = o.width;
    gConnectionInfo.remoteHeight = o.height;
    gConnectionInfo.fps = o.fps;
    logLine("video.requested codec=" + o.codec +
            " bitrate_mbps=" + std::to_string(o.bitrateMbps));
    std::string effectiveCodec = "h264";
    uint16_t effectiveBitrateMbps = 25;
    bool hostSupportsNack = false;
    gRemoteWidth = o.width;
    gRemoteHeight = o.height;
    gScrollScale = o.scrollScale;
    {
        std::ostringstream scroll;
        scroll << "scroll.scale=" << gScrollScale;
        logLine(scroll.str());
    }

    HRESULT coHr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(coHr)) return 3;
    bool mfStarted = false;
    bool wsaStarted = false;
    try {
        check(MFStartup(MF_VERSION, MFSTARTUP_FULL), "MFStartup");
        mfStarted = true;
        WSADATA wsa{};
        if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) throw std::runtime_error("WSAStartup failed");
        wsaStarted = true;

        const bool h264Supported = jerisVideoCodecSupported(JerisVideoCodec::H264, false);
        const bool hevcSupported =
            o.videoBackend != "cpu" &&
            jerisVideoCodecSupported(JerisVideoCodec::HEVC, true);
        logLine(std::string("video.capability.h264=") + (h264Supported ? "yes" : "no"));
        logLine(std::string("video.capability.hevc=") + (hevcSupported ? "yes" : "no"));
        if (!h264Supported) throw std::runtime_error("Media Foundation H.264 decoder unavailable");

        std::unique_ptr<ControlChannel> control;
        std::unique_ptr<ClipboardChannel> clipboard;
        std::unique_ptr<MouseMoveUdpChannel> mouseMoveUdp;
        if (o.controlEnabled) {
            control = std::make_unique<ControlChannel>(o.bindIp, o.sourceIp, o.controlPort);
            gControl = control.get();
            // Startup negotiation may traverse a degraded Tailscale/DERP path.
            // Give the initial handshake enough headroom, then restore the
            // low-latency 100 ms control timeout immediately afterwards.
            control->setIoTimeoutMs(4000);
            double controlRtt = 0.0;
            bool controlReady = false;
            for (int attempt = 1; attempt <= 3 && !controlReady; ++attempt) {
                if (control->ping(&controlRtt)) {
                    controlReady = true;
                    break;
                }
                logLine("control.startup_retry attempt=" + std::to_string(attempt));
                Sleep(250);
            }
            if (controlReady) {
                std::ostringstream ctl;
                ctl << "control.connected rtt_ms=" << controlRtt;
                logLine(ctl.str());
                gConnectionInfo.controlConnected = true;
                gConnectionInfo.rttMs = controlRtt;

                const auto videoConfig = control->negotiateVideo(
                    o.codec, h264Supported, hevcSupported, o.bitrateMbps);
                if (videoConfig.negotiated) {
                    effectiveCodec = videoConfig.codec;
                    hostSupportsNack = videoConfig.hostSupportsNack;
                    effectiveBitrateMbps = videoConfig.bitrateMbps;
                    if (!o.widthExplicit &&
                        videoConfig.remoteWidth > 0 && videoConfig.remoteHeight > 0) {
                        o.width = videoConfig.remoteWidth;
                        o.height = videoConfig.remoteHeight;
                        gRemoteWidth = o.width;
                        gRemoteHeight = o.height;
                    }
                    std::ostringstream cfg;
                    cfg << "video.negotiated codec=" << effectiveCodec
                        << " bitrate_mbps=" << effectiveBitrateMbps
                        << " restarted=" << (videoConfig.streamRestarted ? "yes" : "no")
                        << " host_hevc=" << (videoConfig.hostSupportsHevc ? "yes" : "no")
                        << " fallback=" << (videoConfig.codecFallback ? "yes" : "no")
                        << " host_nack=" << (videoConfig.hostSupportsNack ? "yes" : "no")
                        << " remote_size=" << videoConfig.remoteWidth << "x"
                        << videoConfig.remoteHeight;
                    logLine(cfg.str());
                    if (effectiveCodec == "hevc" && !o.widthExplicit &&
                        (videoConfig.remoteWidth == 0 || videoConfig.remoteHeight == 0)) {
                        logLine("video.hevc_remote_size_missing; requesting h264 fallback");
                        const auto fallbackConfig = control->negotiateVideo(
                            "h264", true, hevcSupported, o.bitrateMbps);
                        if (fallbackConfig.negotiated && fallbackConfig.codec == "h264") {
                            effectiveCodec = "h264";
                            effectiveBitrateMbps = fallbackConfig.bitrateMbps;
                            if (fallbackConfig.remoteWidth > 0 && fallbackConfig.remoteHeight > 0) {
                                o.width = fallbackConfig.remoteWidth;
                                o.height = fallbackConfig.remoteHeight;
                                gRemoteWidth = o.width;
                                gRemoteHeight = o.height;
                            }
                            logLine("video.fallback_selected codec=h264 bitrate_mbps=" +
                                    std::to_string(effectiveBitrateMbps));
                        } else {
                            effectiveCodec = "h264";
                            effectiveBitrateMbps = 25;
                            logLine("video.hevc_remote_size_missing fallback=legacy-h264");
                        }
                    }
                } else {
                    effectiveCodec = "h264";
                    effectiveBitrateMbps = 25;
                    logLine("video.negotiation=legacy-fallback codec=h264 bitrate_mbps=25");
                }
            } else {
                gConnectionInfo.controlConnected = false;
                logLine("control.initial_connect_failed; will reconnect on input");
                effectiveCodec = "h264";
                effectiveBitrateMbps = 25;
                logLine("video.negotiation=control-unavailable codec=h264 bitrate_mbps=25");
            }
            control->setIoTimeoutMs(100);

            if (o.mouseMoveTransport == "udp") {
                mouseMoveUdp = std::make_unique<MouseMoveUdpChannel>(o.bindIp, o.sourceIp, o.mouseUdpPort);
                gMouseMoveUdp = mouseMoveUdp.get();
                logLine("mouse.move_transport=udp remote=" + o.sourceIp + ":" + std::to_string(o.mouseUdpPort));
            } else {
                gMouseMoveUdp = nullptr;
                logLine("mouse.move_transport=tcp");
            }

            clipboard = std::make_unique<ClipboardChannel>(
                o.bindIp, o.sourceIp, o.controlPort,
                [](const std::string& message) { logLine(message); });
            clipboard->start();
            logLine("clipboard.enabled mode=unicode-text max_bytes=61440");
        } else {
            gControl = nullptr;
            gMouseMoveUdp = nullptr;
            logLine("control.disabled");
            logLine("clipboard.disabled");
            if (o.codec == "hevc" && hevcSupported) effectiveCodec = "hevc";
            else effectiveCodec = "h264";
            effectiveBitrateMbps = o.bitrateMbps == 0
                ? (effectiveCodec == "hevc" ? 18 : 25)
                : o.bitrateMbps;
            logLine("video.negotiation=disabled codec=" + effectiveCodec +
                    " bitrate_mbps=" + std::to_string(effectiveBitrateMbps));
        }

        HWND hwnd = createViewerWindow(o.windowWidth, o.windowHeight);
        ShowWindow(hwnd, o.startMaximized ? SW_MAXIMIZE : SW_SHOW);
        UpdateWindow(hwnd);
        logLine(o.startMaximized ? "window.start=maximized" : "window.start=normal");
        logLine("present.mode=adaptive");
        std::unique_ptr<VideoPipeline> video;
        try {
            video = std::make_unique<VideoPipeline>(
                hwnd, o.width, o.height, o.fps, o.videoBackend, effectiveCodec);
        } catch (const std::exception& e) {
            if (effectiveCodec != "hevc" || !control) throw;
            logLine(std::string("video.hevc_init_failed reason=") + e.what());
            logLine("video.fallback_request=h264");
            const auto fallbackConfig = control->negotiateVideo(
                "h264", true, hevcSupported, o.bitrateMbps);
            if (!fallbackConfig.negotiated || fallbackConfig.codec != "h264") {
                throw;
            }
            effectiveCodec = "h264";
            effectiveBitrateMbps = fallbackConfig.bitrateMbps;
            logLine("video.fallback_selected codec=h264 bitrate_mbps=" +
                    std::to_string(effectiveBitrateMbps));
            video = std::make_unique<VideoPipeline>(
                hwnd, o.width, o.height, o.fps, o.videoBackend, effectiveCodec);
        }

        gConnectionInfo.effectiveCodec = effectiveCodec;
        gConnectionInfo.effectiveBitrateMbps = effectiveBitrateMbps;
        gConnectionInfo.remoteWidth = o.width;
        gConnectionInfo.remoteHeight = o.height;
        gConnectionInfo.fps = o.fps;
        gConnectionInfo.backend = video->activeBackend();
        gConnectionInfo.decoder = video->decoderName();
        gConnectionInfo.adapter = video->adapterName();
        updateViewerTitle(hwnd);
        logLine("viewer.title_status codec=" + effectiveCodec +
                " bitrate_mbps=" + std::to_string(effectiveBitrateMbps));

        SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s == INVALID_SOCKET) throw std::runtime_error("socket failed");
        int rcvbuf = 4 * 1024 * 1024;
        setsockopt(s, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&rcvbuf), sizeof(rcvbuf));
        DWORD shortTimeout = 16;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&shortTimeout), sizeof(shortTimeout));

        sockaddr_in local{};
        local.sin_family = AF_INET;
        local.sin_port = htons(o.port);
        if (inet_pton(AF_INET, o.bindIp.c_str(), &local.sin_addr) != 1 ||
            bind(s, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
            closesocket(s);
            throw std::runtime_error("bind failed");
        }
        in_addr allowed{};
        if (inet_pton(AF_INET, o.sourceIp.c_str(), &allowed) != 1) {
            closesocket(s);
            throw std::runtime_error("bad source IP");
        }

        logLine("viewer.waiting_for_stream");
        const bool strictLossRecovery = o.lossRecovery == "strict";
        logLine("loss.recovery=" + o.lossRecovery);
        // NACK needs strict recovery, the MRM1 channel and a host that said so.
        const bool nackEnabled = strictLossRecovery && o.nack == "on" && hostSupportsNack && mouseMoveUdp;
        logLine(std::string("loss.nack=") + (nackEnabled ? "on" : "off") +
                " requested=" + o.nack +
                " host_nack=" + (hostSupportsNack ? "yes" : "no"));
        if (nackEnabled) {
            // Wake up often enough for the 2 ms reorder grace and 40 ms hold.
            DWORD nackTimeout = 5;
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&nackTimeout), sizeof(nackTimeout));
        }

        uint64_t rejected = 0;
        std::vector<float> decodeMs;           // per submitted frame, whole session (capped)
        std::vector<float> decodeWindowMs;     // last 5 s, for the periodic stats line
        constexpr size_t kMaxDecodeSamples = 1u << 20;

        jl::ReceiverConfig rcfg;
        rcfg.strict = strictLossRecovery;
        rcfg.nack = nackEnabled;
        if (gConnectionInfo.rttMs > 0) rcfg.defaultRttMs = gConnectionInfo.rttMs;
        jl::ReceiverHooks hooks;
        hooks.submit = [&](uint64_t fid, const std::vector<uint8_t>& frame, bool discontinuity, bool keyFrame) {
            const auto t0 = std::chrono::steady_clock::now();
            video->submit(fid, frame, discontinuity, keyFrame);
            const float ms = std::chrono::duration<float, std::milli>(std::chrono::steady_clock::now() - t0).count();
            if (decodeMs.size() < kMaxDecodeSamples) decodeMs.push_back(ms);
            decodeWindowMs.push_back(ms);
        };
        hooks.resetForNewStream = [&] { video->resetForNewStream(); };
        hooks.requestKeyframe = [] { if (gMouseMoveUdp) gMouseMoveUdp->requestKeyframe(); };
        hooks.sendNack = [](uint64_t fid, const std::vector<jl::NackRange>& ranges) {
            if (gMouseMoveUdp) gMouseMoveUdp->sendNack(fid, ranges);
        };
        hooks.log = [](const std::string& line) { logLine(line); };
        jl::VideoReceiver receiver(rcfg, std::move(hooks));
        receiver.start();

        std::vector<uint8_t> buf(2048);
        auto start = std::chrono::steady_clock::now();
        auto lastPacket = start;
        auto lastPing = start - std::chrono::seconds(1);
        auto lastStats = start;
        bool gotAny = false;
        const auto msSince = [&start](std::chrono::steady_clock::time_point t) {
            return std::chrono::duration<double, std::milli>(t - start).count();
        };
        jl::PresentedFpsSampler presentedFps;
        // Receiver loss counters at the previous stats line (window deltas).
        uint64_t prevHoles = 0, prevRecovered = 0, prevOriginals = 0;

        while (!gWindowClosed) {
            if (mouseMoveUdp) {
                uint8_t cursorShape = gRemoteCursorShape;
                if (mouseMoveUdp->pollCursorShape(cursorShape)) {
                    applyRemoteCursorShape(hwnd, cursorShape);
                }
                if (mouseMoveUdp->pongRx() > 0) receiver.setRttMs(mouseMoveUdp->rttMs());
            }
            pumpMessages();
            if (gWindowClosed) break;

            auto now = std::chrono::steady_clock::now();
            presentedFps.update(msSince(now), video->presented());
            if (hostSupportsNack && mouseMoveUdp && now - lastPing >= std::chrono::seconds(1)) {
                mouseMoveUdp->sendPing();
                lastPing = now;
            }
            if (now - lastStats >= std::chrono::seconds(5)) {
                const auto& st = receiver.stats();
                const jl::ReceiverLoss wloss = jl::receiverLoss(st.lostPacketsRaw - prevHoles,
                                                                st.holesRecovered - prevRecovered,
                                                                st.originalPackets - prevOriginals);
                std::ostringstream line;
                line << std::fixed << std::setprecision(1)
                     << "stats.5s rtt_ms=" << (mouseMoveUdp ? mouseMoveUdp->rttMs() : 0.0)
                     << " decode_ms_p50=" << jl::receiverPercentile(decodeWindowMs, 50)
                     << " decode_ms_p95=" << jl::receiverPercentile(decodeWindowMs, 95)
                     << " decode_ms_max=" << jl::receiverPercentile(decodeWindowMs, 100)
                     << " frames=" << decodeWindowMs.size()
                     << " presented_fps_p5=" << jl::receiverPercentile(presentedFps.window(), 5)
                     << " presented_fps_p50=" << jl::receiverPercentile(presentedFps.window(), 50)
                     << " presented_fps_p95=" << jl::receiverPercentile(presentedFps.window(), 95)
                     << " nack_tx=" << st.nackTx
                     << " frames_repaired=" << st.framesRepaired
                     << " nack_deadline_miss=" << st.nackDeadlineMiss
                     << " strict_recovery_events=" << st.strictRecoveryEvents
                     << " nack_paused_rtt=" << st.nackPausedRtt
                     << std::setprecision(3)
                     << " loss_raw_pct=" << wloss.rawPct
                     << " loss_after_nack_pct=" << wloss.afterNackPct
                     << " held_frames=" << receiver.heldFrames();
                logLine(line.str());
                decodeWindowMs.clear();
                presentedFps.clearWindow();
                prevHoles = st.lostPacketsRaw;
                prevRecovered = st.holesRecovered;
                prevOriginals = st.originalPackets;
                lastStats = now;
            }

            sockaddr_in peer{}; int plen = sizeof(peer);
            int n = recvfrom(s, reinterpret_cast<char*>(buf.data()), static_cast<int>(buf.size()), 0,
                             reinterpret_cast<sockaddr*>(&peer), &plen);
            now = std::chrono::steady_clock::now();
            if (n == SOCKET_ERROR) {
                int e = WSAGetLastError();
                if (e == WSAETIMEDOUT || e == WSAEWOULDBLOCK) {
                    receiver.tick(msSince(now));
                    auto base = gotAny ? lastPacket : start;
                    const int timeoutMs = gotAny ? o.idleTimeoutMs : o.startupTimeoutMs;
                    if (std::chrono::duration_cast<std::chrono::milliseconds>(now - base).count() >= timeoutMs) break;
                    continue;
                }
                closesocket(s);
                throw std::runtime_error("recvfrom failed");
            }
            const auto packetGapMs = gotAny
                ? std::chrono::duration_cast<std::chrono::milliseconds>(now - lastPacket).count()
                : 0;
            gotAny = true;
            lastPacket = now;
            if (peer.sin_addr.s_addr != allowed.s_addr) { ++rejected; continue; }
            receiver.onPacket(buf.data(), static_cast<size_t>(n), msSince(now), packetGapMs);
            receiver.tick(msSince(now));
        }

        video->finish();
        closesocket(s);
        pumpMessages();

        const auto& rst = receiver.stats();
        const jl::ReceiverLoss loss = jl::receiverLoss(rst.lostPacketsRaw, rst.holesRecovered, rst.originalPackets);
        const uint64_t packets = rst.packets, complete = rst.complete, bad = rst.bad;
        std::ostringstream summary;
        summary << "SUMMARY packets=" << packets
                << " complete_frames=" << complete
                << " decoded_frames=" << video->decodedFrames()
                << " presented_frames=" << video->presented()
                << " presented_fps_p5=" << jl::receiverPercentile(presentedFps.session(), 5)
                << " presented_fps_p50=" << jl::receiverPercentile(presentedFps.session(), 50)
                << " presented_fps_p95=" << jl::receiverPercentile(presentedFps.session(), 95)
                << " present_busy_drops=" << video->busyDrops()
                << " present_avg_ms=" << video->avgPresentMs()
                << " present_max_ms=" << video->maxPresentMs()
                << " non_dxgi_drops=" << video->nonDxgiDrops()
                << " stale_incomplete_dropped=" << rst.incompleteDropped
                << " strict_recovery_events=" << rst.strictRecoveryEvents
                << " late_frames_dropped=" << rst.lateFramesDropped
                << " recovery_wait_packet_drops=" << rst.recoveryWaitPacketDrops
                << " stream_restarts=" << rst.streamRestarts
                << " nack=" << (receiver.nackActive() ? "on" : "off")
                << " nack_tx=" << rst.nackTx
                << " nack_send_drops=" << (mouseMoveUdp ? mouseMoveUdp->nackDrops() : 0)
                << " nack_packets_requested=" << rst.nackPacketsRequested
                << " nack_whole_frames=" << rst.nackWholeFrames
                << " lost_packets_raw=" << rst.lostPacketsRaw
                << " original_packets=" << rst.originalPackets
                << " loss_raw_pct=" << loss.rawPct
                << " loss_after_nack_pct=" << loss.afterNackPct
                << " nack_paused_rtt=" << rst.nackPausedRtt
                << " retransmit_rx=" << rst.retransmitRx
                << " frames_repaired=" << rst.framesRepaired
                << " nack_deadline_miss=" << rst.nackDeadlineMiss
                << " nack_held_cap_miss=" << rst.heldCapMiss
                << " nack_keyframe_jumps=" << rst.keyframeJumps
                << " held_frames_max=" << rst.heldFramesMax
                << " duplicate_packets=" << rst.duplicatePackets
                << " late_packets_ignored=" << rst.latePacketsIgnored
                << " repair_ms_p50=" << jl::receiverPercentile(rst.repairMs, 50)
                << " repair_ms_p95=" << jl::receiverPercentile(rst.repairMs, 95)
                << " repair_ms_max=" << jl::receiverPercentile(rst.repairMs, 100)
                << " decode_ms_p50=" << jl::receiverPercentile(decodeMs, 50)
                << " decode_ms_p95=" << jl::receiverPercentile(decodeMs, 95)
                << " decode_ms_max=" << jl::receiverPercentile(decodeMs, 100)
                << " rtt_ms=" << (mouseMoveUdp ? mouseMoveUdp->rttMs() : 0.0)
                << " rtt_max_ms=" << (mouseMoveUdp ? mouseMoveUdp->rttMaxMs() : 0.0)
                << " rtt_samples=" << (mouseMoveUdp ? mouseMoveUdp->pongRx() : 0)
                << " connect_rtt_ms=" << gConnectionInfo.rttMs
                << " stream_changes=" << video->streamChanges()
                << " backpressure=" << video->inputBackpressure()
                << " video_backend=" << video->activeBackend()
                << " gpu_fallbacks=" << video->fallbackCount()
                << " gpu_keyframe_wait_drops=" << video->keyframeWaitDrops()
                << " control_events=" << (control ? control->sentEvents() : 0)
                << " control_failures=" << (control ? control->failures() : 0)
                << " mouse_udp_tx=" << (mouseMoveUdp ? mouseMoveUdp->sent() : 0)
                << " mouse_udp_drops=" << (mouseMoveUdp ? mouseMoveUdp->dropped() : 0)
                << " keyframe_req_tx=" << (mouseMoveUdp ? mouseMoveUdp->keyframeRequestsSent() : 0)
                << " keyframe_req_suppressed=" << (mouseMoveUdp ? mouseMoveUdp->keyframeRequestsSuppressed() : 0)
                << " keyframe_req_drops=" << (mouseMoveUdp ? mouseMoveUdp->keyframeRequestDrops() : 0)
                << " cursor_state_rx=" << (mouseMoveUdp ? mouseMoveUdp->cursorRx() : 0)
                << " cursor_state_bad=" << (mouseMoveUdp ? mouseMoveUdp->cursorRxBad() : 0)
                << " cursor_state_stale=" << (mouseMoveUdp ? mouseMoveUdp->cursorRxStale() : 0)
                << " clipboard_tx=" << (clipboard ? clipboard->sent() : 0)
                << " clipboard_rx=" << (clipboard ? clipboard->received() : 0)
                << " clipboard_reconnects=" << (clipboard ? clipboard->reconnects() : 0)
                << " clipboard_oversize=" << (clipboard ? clipboard->skippedOversize() : 0)
                << " bad=" << bad << " rejected=" << rejected;
        logLine(summary.str());
        gControl = nullptr;
        gMouseMoveUdp = nullptr;

        // Stop the clipboard worker before Winsock shutdown and before the
        // control channel is released. Video/keyboard/mouse paths remain
        // independent from this second TCP session.
        if (clipboard) clipboard->stop();

        // Release Media Foundation / D3D objects before MFShutdown/CoUninitialize.
        video.reset();
        clipboard.reset();
        mouseMoveUdp.reset();
        control.reset();

        if (wsaStarted) { WSACleanup(); wsaStarted = false; }
        if (mfStarted) { MFShutdown(); mfStarted = false; }
        CoUninitialize();
        return 0;
    } catch (const std::exception& e) {
        gControl = nullptr;
        logLine(std::string("FATAL ") + e.what());
        MessageBoxA(nullptr, e.what(), "JerisLink", MB_OK | MB_ICONERROR);
        if (wsaStarted) WSACleanup();
        if (mfStarted) MFShutdown();
        CoUninitialize();
        return 1;
    }
}

static std::string wideArgToUtf8(const wchar_t* text) {
    if (!text) return {};
    const int bytes = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
    if (bytes <= 1) return {};
    std::string out(static_cast<size_t>(bytes), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text, -1, out.data(), bytes, nullptr, nullptr);
    out.pop_back();
    return out;
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    int argc = 0;
    LPWSTR* wideArgv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!wideArgv || argc <= 0) {
        if (wideArgv) LocalFree(wideArgv);
        return 2;
    }

    std::vector<std::string> utf8Args;
    utf8Args.reserve(static_cast<size_t>(argc));
    for (int i = 0; i < argc; ++i) {
        utf8Args.push_back(wideArgToUtf8(wideArgv[i]));
    }

    std::vector<char*> argv;
    argv.reserve(utf8Args.size());
    for (auto& arg : utf8Args) {
        argv.push_back(arg.empty() ? const_cast<char*>("") : arg.data());
    }

    LocalFree(wideArgv);
    return appMain(argc, argv.data());
}
