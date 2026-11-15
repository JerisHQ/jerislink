#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <commctrl.h>
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
#include "abr.hpp"
#include "loop_wait.hpp"
#include "loop_accounting.hpp"
#include "viewer_log.hpp"
#include "mouse_buttons.hpp"
#include "video_worker.hpp"
#include "audio_player.hpp"
#include "ui_theme.hpp"
#include "ui_overlay.hpp"

#include <algorithm>
#include <atomic>
#include <bitset>
#include <chrono>
#include <cmath>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
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
// Both logs are written by one background thread through handles kept
// open for the run; each is capped at 10 MB (history keeps one .old).
static jl::ViewerLog gLog;
extern "C" const char* __asan_default_options() {
    return "log_path=shader-asan:abort_on_error=1";
}
class CpuPresenter;
// Set by the presenter (on the video thread after a CPU fallback), read by
// WM_PAINT on the main thread.
static std::atomic<CpuPresenter*> gCpuPresenter{nullptr};
static std::atomic<bool> gHardwarePresenterActive{false};
// WM_PAINT on the hardware path: the main loop re-presents the newest frame
// after pumpMessages() (never from inside the window procedure).
static bool gHardwareRepaintRequested = false;
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
        // FD_READ event so the receive loop wakes for pongs and cursor
        // shapes as they arrive. If it cannot be set up the channel still
        // works: the loop polls it once per iteration as before.
        event_ = WSACreateEvent();
        if (event_ != WSA_INVALID_EVENT && WSAEventSelect(s_, event_, FD_READ) != 0) {
            WSACloseEvent(event_);
            event_ = WSA_INVALID_EVENT;
        }
    }

    ~MouseMoveUdpChannel() {
        if (s_ != INVALID_SOCKET) closesocket(s_);
        if (event_ != WSA_INVALID_EVENT) WSACloseEvent(event_);
    }

    // Signalled when an MRM1 datagram (pong, cursor shape) is waiting.
    HANDLE readEvent() const { return event_ == WSA_INVALID_EVENT ? nullptr : event_; }

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

    // MRM1 0x45 audio request: flags 0x01 = send audio to this viewer's IP at
    // `port` (the player's own socket); 0 = stop now. 0x02 = this viewer
    // decodes Opus (MRA1 v2); an A1 host ignores it and sends PCM (v1). Sent from this socket
    // on purpose: the host keys the MRM1 session on its source port.
    bool sendAudioRequest(bool enable, uint16_t port) {
        if (s_ == INVALID_SOCKET) return false;
        const uint32_t seq = ++sequence_;
        uint8_t p[13]{'M','R','M','1', 1, 0x45,
                      uint8_t(seq >> 24), uint8_t(seq >> 16), uint8_t(seq >> 8), uint8_t(seq),
                      uint8_t(enable ? (jl::audio::kRequestEnable | jl::audio::kRequestOpus) : 0x00),
                      uint8_t(port >> 8), uint8_t(port)};
        const int n = sendto(s_, reinterpret_cast<const char*>(p), sizeof(p), 0,
                             reinterpret_cast<const sockaddr*>(&remote_), sizeof(remote_));
        if (n == sizeof(p)) { ++audioRequestsSent_; return true; }
        ++audioRequestDrops_;
        return false;
    }
    uint64_t audioRequestsSent() const { return audioRequestsSent_; }
    uint64_t audioRequestDrops() const { return audioRequestDrops_; }

    // Smoothed RTT from 0x44 echoes (EWMA 1/8), 0 until the first echo.
    // MRM1 0x42 receiver report (ABR), only when the host set ACK flag 0x40.
    bool sendReceiverReport(const jl::ReceiverReport& r) {
        if (s_ == INVALID_SOCKET) return false;
        const auto p = jl::encodeReceiverReport(++sequence_, r);
        const int n = sendto(s_, reinterpret_cast<const char*>(p.data()), static_cast<int>(p.size()), 0,
                             reinterpret_cast<const sockaddr*>(&remote_), sizeof(remote_));
        if (n == static_cast<int>(p.size())) { ++reportSent_; return true; }
        ++reportDrops_;
        return false;
    }
    uint64_t reportSent() const { return reportSent_; }
    uint64_t reportDrops() const { return reportDrops_; }

    double rttMs() const { return rttEwmaMs_; }
    double rttMaxMs() const { return rttMaxMs_; }
    double rttLastMs() const { return rttLastMs_; }
    uint64_t pingSent() const { return pingSent_; }
    uint64_t pongRx() const { return pongRx_; }
    uint64_t nackSent() const { return nackSent_; }
    uint64_t nackDrops() const { return nackDrops_; }

    bool pollCursorShape(uint8_t& shape) {
        if (s_ == INVALID_SOCKET) return false;
        // Reset before draining: a datagram that arrives after the last
        // read sets the event again.
        if (event_ != WSA_INVALID_EVENT) WSAResetEvent(event_);
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
    WSAEVENT event_ = WSA_INVALID_EVENT;
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
    uint64_t audioRequestsSent_ = 0;
    uint64_t audioRequestDrops_ = 0;
    uint64_t nackDrops_ = 0;
    uint64_t reportSent_ = 0;
    uint64_t reportDrops_ = 0;
    uint64_t pingSent_ = 0;
    uint64_t pongRx_ = 0;
    double rttEwmaMs_ = 0.0;
    double rttMaxMs_ = 0.0;
    double rttLastMs_ = 0.0;
};

static std::atomic<bool> gWindowClosed{false};  // read by the video thread too
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
// Buttons sent down to the host and not yet up: every down gets one up.
static RemoteButtons gRemoteButtons;
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

// Changes found by the video thread (decoded size, CPU fallback). The main
// thread applies them to gRemoteWidth/Height (input mapping) and
// gConnectionInfo, which only the main thread reads.
struct VideoInfoMailbox {
    std::mutex mu;
    bool sizeChanged = false;
    UINT32 width = 0, height = 0;
    bool backendChanged = false;
    std::string backend, decoder, adapter;
};
static VideoInfoMailbox gVideoInfo;

// How long input messages waited in our queue while the main loop was busy
// (jl::splitInputWait: the message's age, GetTickCount - MSG::time, capped
// by the time since the loop was last responsive). A stall of the main
// loop shows up here. Main thread only.
static std::vector<float> gInputQueueWindowMs;
static std::vector<float> gInputQueueSessionMs;
// The rest of the age: the event was already that old when it reached our
// queue (delivery outside the loop, or a stale timestamp).
static double gInputDeliveryWindowMaxMs = 0.0;
static double gInputDeliverySessionMaxMs = 0.0;
static uint64_t gInputDeliveryLateEvents = 0;  // delivery part > 16 ms
// steady ms when the loop last could take a message at once: the pump
// drained the queue, or the loop wait (QS_ALLINPUT) returned.
static double gLoopResponsiveMs = 0.0;
// Any input older than this is logged (input.slow), one line per second.
static constexpr double kInputSlowMs = 16.0;
static double gInputSlowLastLogMs = -1e9;
static uint64_t gInputSlowSuppressed = 0;
static uint64_t gInputSlowEvents = 0;
// Windows modal loops (caption buttons, move/size, menus, our dialogs).
// Their time is not the loop's own stall; reported as loop_modal_*.
static jl::ModalClock gModal;
static UINT gModalMsg = 0;  // message that opened the current modal stretch
// Pump detail of the current loop iteration (keyboard hook, window
// procedure, peek and dispatch time), logged in loop.slow_iter. Main thread.
static jl::PumpDetail gIterPump;
static int gWndProcDepth = 0;
// Input that was queued before the main loop started (it waited behind
// GPU / decoder setup on this thread). Kept out of the numbers above so
// they describe the running loop; reported once as input.startup_queued.
static std::vector<float> gInputQueueStartupMs;
static DWORD gLoopStartTick = 0;
static bool gLoopStarted = false;

// Main thread: one PeekMessage / DispatchMessage call that took this long
// is logged (loop.slow) with the message, so a long loop iteration can be
// tied to the call. Rate-limited to one line per second below 200 ms.
static constexpr double kLoopSlowCallMs = 50.0;
static double gLoopSlowLastLogMs = -1e9;
static uint64_t gLoopSlowSuppressed = 0;
static UINT gLastSizeType = 0xFFFFFFFFu;

static double steadyMsNow() {
    return std::chrono::duration<double, std::milli>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

static bool loopSlowShouldLog(double ms) {
    if (ms < kLoopSlowCallMs) return false;
    const double now = steadyMsNow();
    if (ms < 200.0 && now - gLoopSlowLastLogMs < 1000.0) {
        ++gLoopSlowSuppressed;
        return false;
    }
    gLoopSlowLastLogMs = now;
    return true;
}

// Messages whose default handling can run a Windows modal loop (caption
// button tracking, move/size, system and window menus) or that open our own
// modal dialogs. WM_ENTERSIZEMOVE / WM_ENTERMENULOOP arrive inside these.
static bool mayRunModalLoop(UINT msg) {
    switch (msg) {
    case WM_NCLBUTTONDOWN:
    case WM_NCLBUTTONDBLCLK:
    case WM_NCRBUTTONDOWN:
    case WM_NCRBUTTONUP:
    case WM_CONTEXTMENU:
    case WM_SYSCOMMAND:
    case WM_COMMAND:
    case WM_ENTERSIZEMOVE:
    case WM_ENTERMENULOOP:
        return true;
    default:
        return false;
    }
}

// Times one window-procedure call as modal (outermost scope only). While
// Windows runs the modal loop it dispatches our messages itself, so the
// loop counts as responsive again when the stretch ends.
struct ModalScope {
    const bool on;
    explicit ModalScope(UINT msg) : on(mayRunModalLoop(msg)) {
        if (!on) return;
        if (!gModal.active()) gModalMsg = msg;
        gModal.enter(steadyMsNow());
    }
    ~ModalScope() {
        if (!on) return;
        const double now = steadyMsNow();
        const double ms = gModal.exit(now);
        if (gModal.active()) return;
        gLoopResponsiveMs = now;
        if (ms >= kLoopSlowCallMs) {
            char buf[112];
            std::snprintf(buf, sizeof(buf), "loop.modal msg=0x%04x ms=%.1f focused=%d iconic=%d",
                          gModalMsg, ms, gViewerFocused ? 1 : 0,
                          gViewerHwnd && IsIconic(gViewerHwnd) ? 1 : 0);
            logLine(buf);
        }
    }
    ModalScope(const ModalScope&) = delete;
    ModalScope& operator=(const ModalScope&) = delete;
};

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

// Dark caption, border and rounded corners; shared with the settings and
// volume dialogs (ui_theme.hpp).
static void applyModernWindowChrome(HWND hwnd) {
    jl::ui::applyWindowChrome(hwnd);
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

static LRESULT viewerKeyboardHookImpl(int code, WPARAM wParam, LPARAM lParam) {
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

// Times every hook call (including CallNextHookEx) for loop.slow_iter. The
// hook runs on the main thread inside PeekMessage, so it lands in peek_ms.
static LRESULT CALLBACK ViewerKeyboardHook(int code, WPARAM wParam, LPARAM lParam) {
    const double t0 = steadyMsNow();
    const LRESULT r = viewerKeyboardHookImpl(code, wParam, lParam);
    gIterPump.noteHook(steadyMsNow() - t0);
    return r;
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

static void sendRemoteButtonUp(uint8_t button) {
    if (!gControl) return;
    if (button == 0) gControl->sendMouseButtonExtended(0, false, gLeftClickCount);
    else gControl->sendMouseButton(button, false);
}

// Sends an up for every button still held on the host (focus moved, capture
// taken by another window, window closing) and logs which ones.
static void releaseRemoteButtons(const char* reason) {
    const uint8_t mask = gRemoteButtons.releaseAll(sendRemoteButtonUp);
    if (!mask) return;
    gLeftClickCount = 1;
    logLine(std::string("input.buttons_released reason=") + reason + " mask=" + std::to_string(mask));
}

// UTC wall clock with milliseconds, e.g. 2026-11-14T02:47:20.123Z, so viewer
// lines can be matched against host logs.
static std::string logTimestamp() {
    SYSTEMTIME t;
    GetSystemTime(&t);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
                  t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond, t.wMilliseconds);
    return buf;
}

static void logLine(const std::string& s) {
    // Timestamp taken at the call, not when the background writer runs.
    gLog.line(logTimestamp() + " " + s);
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

// Tailcat bridge present: jeris-support-transport listens for the viewer's
// control connection on 127.0.0.1:48400 (see bind_choices.hpp).
static bool detectTailcatBridge() {
    ULONG size = 0;
    if (GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0) !=
        ERROR_INSUFFICIENT_BUFFER) {
        return false;
    }
    std::vector<uint8_t> buffer(size + 1024);
    size = static_cast<ULONG>(buffer.size());
    auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buffer.data());
    if (GetExtendedTcpTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0) !=
        NO_ERROR) {
        return false;
    }
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const auto& row = table->table[i];
        const uint32_t addr = ntohl(row.dwLocalAddr);
        const uint16_t port = ntohs(static_cast<u_short>(row.dwLocalPort));
        if (addr == 0x7F000001u && port == jl::kTailcatControlPort) return true;
    }
    return false;
}

#ifdef JERISLINK_UI_SNAPSHOT
// The snapshot build shows fixed, made-up addresses.
static std::optional<jl::BindDetection> gBindDetectionOverride;
#endif

static jl::BindDetection detectBindAddresses() {
#ifdef JERISLINK_UI_SNAPSHOT
    if (gBindDetectionOverride) return *gBindDetectionOverride;
#endif
    return jl::BindDetection{detectTailscaleIPv4(), detectTailcatBridge()};
}

// The viewer has no menu bar and adds nothing to the system menu: every
// action lives on the launch screen, the in-session overlay or a shortcut
// (Win32 menus run a modal loop). The snapshot build checks that the old
// command range 0x1F10-0x1F3F stays out of the system menu.
static constexpr UINT kRemovedMenuIdFirst = 0x1F10;
static constexpr UINT kRemovedMenuIdLast = 0x1F3F;

// Mac audio. The player lives in the session (runViewer); mute is local to
// this viewer, kept across reconnects, and never sent to the Mac.
static jl::audio::AudioPlayer* gAudio = nullptr;
static bool gAudioMuted = false;
// Viewer volume, 0-100, kept across reconnects and saved in HKCU. Mute is a
// separate switch and never changes it.
static int gAudioVolumePct = jl::audio::kDefaultVolumePercent;
static int gSavedAudioVolumePct = jl::audio::kDefaultVolumePercent;
static bool gAudioVolumeLoaded = false;
static HWND gVolumeDlg = nullptr;  // modeless "Volume..." window
static HWND gSettingsDlg = nullptr;  // settings dialog while open (Audio section)
static HWND gInfoDlg = nullptr;      // modeless "Connection info" window
static bool gSettingsNoteError = false;  // its footer note shows a validation error

static void overlayRefresh();  // repaints the in-session overlay, if shown

// Mute shows in the volume window, the settings dialog and the overlay.
static void syncMuteUi() {
    for (HWND dlg : {gVolumeDlg, gSettingsDlg}) {
        if (dlg) jl::ui::setOwnerChecked(dlg, IDC_VOLUME_MUTE, gAudioMuted);
    }
    overlayRefresh();
}

static void toggleAudioMute(const char* source) {
    gAudioMuted = !gAudioMuted;
    if (gAudio) gAudio->setMuted(gAudioMuted);
    syncMuteUi();
    logLine(std::string("audio.mute=") + (gAudioMuted ? "on" : "off") + " source=" + source);
}


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

// Viewer volume in HKCU\Software\Jeris\Jerislink\AudioVolumePercent
// (REG_DWORD 0-100). Missing or unreadable means 100%; larger values clamp.
static int loadAudioVolumePercent() {
    DWORD value = 0;
    DWORD size = sizeof(value);
    const bool ok = RegGetValueW(HKEY_CURRENT_USER, kJerislinkSettingsKey, L"AudioVolumePercent",
                                 RRF_RT_REG_DWORD, nullptr, &value, &size) == ERROR_SUCCESS;
    return jl::audio::volumePercentFromSaved(ok, value);
}

// Dialog accent in HKCU\Software\Jeris\Jerislink\UiAccent (REG_SZ):
// "blue" uses the blue accent; anything else, empty or missing, the icon green.
static void loadUiAccent() {
    const bool blue = [] {
        HKEY key = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, kJerislinkSettingsKey, 0, KEY_READ, &key) !=
            ERROR_SUCCESS) {
            return false;
        }
        const std::string value = readRegString(key, L"UiAccent");
        RegCloseKey(key);
        return value == "blue";
    }();
    jl::ui::setAccent(blue ? jl::ui::Accent::Blue : jl::ui::Accent::Green);
    logLine(std::string("ui.accent=") + (blue ? "blue" : "green"));
}

// The theme picker on the launch screen: applies at once and is saved.
static bool saveUiAccent(bool blue) {
    jl::ui::setAccent(blue ? jl::ui::Accent::Blue : jl::ui::Accent::Green);
    HKEY key = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kJerislinkSettingsKey, 0, nullptr, 0, KEY_SET_VALUE,
                        nullptr, &key, nullptr) != ERROR_SUCCESS) {
        logLine(std::string("ui.accent.save=") + (blue ? "blue" : "green") + " saved=no");
        return false;
    }
    const bool ok = writeRegString(key, L"UiAccent", blue ? "blue" : "green") == ERROR_SUCCESS;
    RegCloseKey(key);
    logLine(std::string("ui.accent.save=") + (blue ? "blue" : "green") +
            " saved=" + (ok ? "yes" : "no"));
    return ok;
}

static bool accentIsBlue() { return jl::ui::accent().accent == jl::ui::kBlueAccent.accent; }

static void ensureAudioVolumeLoaded() {
    if (gAudioVolumeLoaded) return;
    gAudioVolumeLoaded = true;
    gAudioVolumePct = gSavedAudioVolumePct = loadAudioVolumePercent();
}

static bool saveAudioVolumePercent(int pct) {
    HKEY key = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kJerislinkSettingsKey, 0, nullptr, 0,
                        KEY_SET_VALUE, nullptr, &key, nullptr) != ERROR_SUCCESS) {
        return false;
    }
    const DWORD value = static_cast<DWORD>(jl::audio::clampVolumePercent(pct));
    const LONG result = RegSetValueExW(key, L"AudioVolumePercent", 0, REG_DWORD,
                                       reinterpret_cast<const BYTE*>(&value), sizeof(value));
    RegCloseKey(key);
    return result == ERROR_SUCCESS;
}

static void setAudioVolume(int pct) {
    gAudioVolumePct = jl::audio::clampVolumePercent(pct);
    if (gAudio) gAudio->setVolumePercent(gAudioVolumePct);
}

// Saves once per gesture (thumb released, key up, window closed), not on
// every slider step.
static void commitAudioVolume(const char* source) {
    if (gAudioVolumePct == gSavedAudioVolumePct) return;
    const bool saved = saveAudioVolumePercent(gAudioVolumePct);
    if (saved) gSavedAudioVolumePct = gAudioVolumePct;
    logLine("audio.volume=" + std::to_string(gAudioVolumePct) + " source=" + source +
            " saved=" + (saved ? "yes" : "no"));
}

// ---- Themed dialogs (settings, volume) ------------------------------------
// Colours and DWM title bar come from ui_theme.hpp, the same helper the
// viewer window uses, so the dialogs match the viewer's title bar.

static constexpr UINT kMsgThemeDpiChanged = WM_APP + 0x31;
static constexpr int kSettingsFooterTop = 262;  // dialog units, see jerislink.rc
static constexpr int kVolumeFooterTop = 70;
static constexpr int kLaunchFooterTop = 238;
static constexpr int kInfoFooterTop = 172;

struct ThemedDialog;
using ThemedExtraPaint = void (*)(HWND dlg, HDC dc, const ThemedDialog& td);

struct ThemedDialog {
    jl::ui::DialogTheme theme;
    int titlePt = 15;
    int footerTopDlu = 0;
    ThemedExtraPaint extraPaint = nullptr;  // dialog-specific painting after the base
};

static ThemedDialog* themedDialog(HWND dlg) {
    return reinterpret_cast<ThemedDialog*>(GetWindowLongPtrW(dlg, DWLP_USER));
}

enum class TextRole { Other, Title, Subtitle, Section, Label, Value, Hint, Note, Hero, Brand, Error };

static TextRole textRole(int id) {
    switch (id) {
    case IDC_UI_TITLE: return TextRole::Title;
    case IDC_UI_SUBTITLE:
    case IDC_LAUNCH_TAGLINE: return TextRole::Subtitle;
    case IDC_LAUNCH_HERO: return TextRole::Hero;
    case IDC_LAUNCH_BRAND: return TextRole::Brand;
    case IDC_LAUNCH_ERROR: return TextRole::Error;
    case IDC_LAUNCH_PRIVACY: return TextRole::Note;
    case IDC_LAUNCH_CODE_NOTE: return TextRole::Hint;
    case IDC_UI_SECTION_THEME:
    case IDC_LAUNCH_EYEBROW:
    case IDC_LAUNCH_READY:
    case IDC_INFO_SECTION_CONFIGURED:
    case IDC_INFO_SECTION_EFFECTIVE:
    case IDC_INFO_SECTION_DECODER:
    case IDC_UI_SECTION_CONNECTION:
    case IDC_UI_SECTION_VIDEO:
    case IDC_UI_SECTION_AUDIO: return TextRole::Section;
    case IDC_UI_LABEL_HOST:
    case IDC_UI_LABEL_BIND:
    case IDC_UI_LABEL_CODEC:
    case IDC_UI_LABEL_BITRATE:
    case IDC_UI_LABEL_VOLUME: return TextRole::Label;
    case IDC_BITRATE_VALUE:
    case IDC_VOLUME_VALUE: return TextRole::Value;
    case IDC_UI_HINT_HOST:
    case IDC_UI_HINT_BITRATE:
    case IDC_UI_HINT_VOLUME:
    case IDC_BIND_HINT: return TextRole::Hint;
    case IDC_APPLY_NOTE: return TextRole::Note;
    default: return TextRole::Other;
    }
}

static int dialogUnitsY(HWND dlg, int dlu) {
    RECT r{0, 0, 0, dlu};
    MapDialogRect(dlg, &r);
    return r.bottom;
}

// Selection field height for the owner-drawn codec box: the combo box adds
// 3 px of frame above and below, and we want it as tall as an edit field
// (edit 10 DLU + 2 x 3 DLU padding).
static int comboFieldHeight(HWND dlg) {
    return std::max(8, dialogUnitsY(dlg, 16) - 6);
}

static void applyThemeFonts(HWND dlg) {
    ThemedDialog* td = themedDialog(dlg);
    if (!td) return;
    for (HWND c = GetWindow(dlg, GW_CHILD); c; c = GetWindow(c, GW_HWNDNEXT)) {
        HFONT font = td->theme.text;
        switch (textRole(GetDlgCtrlID(c))) {
        case TextRole::Title: font = td->theme.title; break;
        case TextRole::Hero: font = td->theme.hero; break;
        case TextRole::Section: font = td->theme.section; break;
        case TextRole::Label:
        case TextRole::Brand:
        case TextRole::Value: font = td->theme.label; break;
        case TextRole::Subtitle:
        case TextRole::Hint:
        case TextRole::Error:
        case TextRole::Note: font = td->theme.smallText; break;
        default: break;
        }
        SendMessageW(c, WM_SETFONT, reinterpret_cast<WPARAM>(font), FALSE);
    }
    for (int id : {IDC_VIDEO_CODEC, IDC_BIND_IP}) {
        HWND combo = GetDlgItem(dlg, id);
        if (!combo) continue;
        SendMessageW(combo, CB_SETITEMHEIGHT, static_cast<WPARAM>(-1), comboFieldHeight(dlg));
        SendMessageW(combo, CB_SETITEMHEIGHT, 0, jl::ui::px(td->theme.dpi, 26));
    }
    RedrawWindow(dlg, nullptr, nullptr, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN);
}

// The drop-downs (codec, this PC's address) paint their own closed state:
// rounded field, text and chevron, like the edit boxes. The list itself is
// owner-drawn items. Disabled: muted text, no chevron (greyed info).
// Classic GWLP_WNDPROC subclass: SetWindowSubclass is a comctl32 v6 API and
// the viewer does not load v6.
static constexpr wchar_t kComboOldProcProp[] = L"JerisLink.ComboProc";

static LRESULT CALLBACK ThemedComboProc(HWND combo, UINT msg, WPARAM wParam, LPARAM lParam) {
    const auto oldProc = reinterpret_cast<WNDPROC>(GetPropW(combo, kComboOldProcProp));
    switch (msg) {
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT: {
        ThemedDialog* td = themedDialog(GetParent(combo));
        if (!td) break;
        const auto& t = td->theme;
        PAINTSTRUCT ps{};
        HDC dc = BeginPaint(combo, &ps);
        RECT r{};
        GetClientRect(combo, &r);
        jl::ui::fillRect(dc, r, jl::ui::color::kBody);
        const bool focus = GetFocus() == combo;
        const bool enabled = IsWindowEnabled(combo) != FALSE;
        jl::ui::roundRect(dc, r, jl::ui::px(t.dpi, 8),
                          enabled ? jl::ui::color::kField : jl::ui::color::kBody,
                          focus ? jl::ui::accent().accent : jl::ui::color::kBorder,
                          jl::ui::px(t.dpi, 1));
        wchar_t text[64]{};
        const LRESULT sel = SendMessageW(combo, CB_GETCURSEL, 0, 0);
        if (sel != CB_ERR &&
            SendMessageW(combo, CB_GETLBTEXTLEN, sel, 0) < static_cast<LRESULT>(std::size(text))) {
            SendMessageW(combo, CB_GETLBTEXT, sel, reinterpret_cast<LPARAM>(text));
        }
        HGDIOBJ oldFont = SelectObject(dc, t.text);
        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, enabled ? jl::ui::color::kText : jl::ui::color::kMuted);
        RECT tr = r;
        tr.left += jl::ui::px(t.dpi, 10);
        tr.right -= jl::ui::px(t.dpi, 28);
        DrawTextW(dc, text, -1, &tr,
                  DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
        SelectObject(dc, oldFont);
        if (!enabled) {
            EndPaint(combo, &ps);
            return 0;
        }
        const int cx = r.right - jl::ui::px(t.dpi, 16);
        const int cy = (r.top + r.bottom) / 2;
        const int a = jl::ui::px(t.dpi, 4);
        const int w = jl::ui::px(t.dpi, 2);
        jl::ui::line(dc, cx - a, cy - a / 2, cx, cy + a / 2, jl::ui::color::kMuted, w);
        jl::ui::line(dc, cx, cy + a / 2, cx + a, cy - a / 2, jl::ui::color::kMuted, w);
        EndPaint(combo, &ps);
        return 0;
    }
    case WM_SETFOCUS:
    case WM_KILLFOCUS:
    case WM_ENABLE:
        InvalidateRect(combo, nullptr, FALSE);
        break;
    case WM_NCDESTROY:
        if (oldProc) {
            SetWindowLongPtrW(combo, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(oldProc));
            RemovePropW(combo, kComboOldProcProp);
        }
        break;
    default:
        break;
    }
    return oldProc ? CallWindowProcW(oldProc, combo, msg, wParam, lParam)
                   : DefWindowProcW(combo, msg, wParam, lParam);
}

// The drop-down list (a ComboLBox popup) is painted dark from its first
// frame: its class background brush and its erase both use the field colour,
// so the open animation never shows a white cell before the items draw.
static constexpr wchar_t kListOldProcProp[] = L"JerisLink.ListProc";

static HBRUSH fieldBrush() {
    static HBRUSH brush = CreateSolidBrush(jl::ui::color::kField);  // lives for the process
    return brush;
}

static LRESULT CALLBACK ThemedComboListProc(HWND list, UINT msg, WPARAM wParam, LPARAM lParam) {
    const auto oldProc = reinterpret_cast<WNDPROC>(GetPropW(list, kListOldProcProp));
    switch (msg) {
    case WM_ERASEBKGND: {
        RECT r{};
        GetClientRect(list, &r);
        FillRect(reinterpret_cast<HDC>(wParam), &r, fieldBrush());
        return 1;
    }
    case WM_NCDESTROY:
        if (oldProc) {
            SetWindowLongPtrW(list, GWLP_WNDPROC, reinterpret_cast<LONG_PTR>(oldProc));
            RemovePropW(list, kListOldProcProp);
        }
        break;
    default:
        break;
    }
    return oldProc ? CallWindowProcW(oldProc, list, msg, wParam, lParam)
                   : DefWindowProcW(list, msg, wParam, lParam);
}

static void themeComboBox(HWND combo) {
    const LONG_PTR old = SetWindowLongPtrW(combo, GWLP_WNDPROC,
                                           reinterpret_cast<LONG_PTR>(ThemedComboProc));
    SetPropW(combo, kComboOldProcProp, reinterpret_cast<HANDLE>(old));
    COMBOBOXINFO info{};
    info.cbSize = sizeof(info);
    if (!GetComboBoxInfo(combo, &info) || !info.hwndList) return;
    SetClassLongPtrW(info.hwndList, GCLP_HBRBACKGROUND, reinterpret_cast<LONG_PTR>(fieldBrush()));
    const LONG_PTR oldList = SetWindowLongPtrW(info.hwndList, GWLP_WNDPROC,
                                               reinterpret_cast<LONG_PTR>(ThemedComboListProc));
    SetPropW(info.hwndList, kListOldProcProp, reinterpret_cast<HANDLE>(oldList));
}

// Drops exactly as many rows as there are items, so the list has no empty
// area below the last item.
static void fitComboDropHeight(HWND combo) {
    COMBOBOXINFO info{};
    info.cbSize = sizeof(info);
    if (!GetComboBoxInfo(combo, &info)) return;
    const int count = std::max<int>(1, static_cast<int>(SendMessageW(combo, CB_GETCOUNT, 0, 0)));
    const int itemHeight = static_cast<int>(SendMessageW(combo, CB_GETITEMHEIGHT, 0, 0));
    const int closedHeight = info.rcItem.bottom + info.rcItem.top;  // frame is symmetric
    RECT r{};
    GetWindowRect(combo, &r);
    SetWindowPos(combo, nullptr, 0, 0, r.right - r.left, closedHeight + count * itemHeight + 2,
                 SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
}

static void initThemedDialog(HWND dlg, int titlePt, int footerTopDlu) {
    auto* td = new ThemedDialog;
    td->titlePt = titlePt;
    td->footerTopDlu = footerTopDlu;
    td->theme.build(dlg, titlePt);
    SetWindowLongPtrW(dlg, DWLP_USER, reinterpret_cast<LONG_PTR>(td));
    jl::ui::applyWindowChrome(dlg);
    for (int id : {IDC_VIDEO_CODEC, IDC_BIND_IP}) {
        if (HWND combo = GetDlgItem(dlg, id)) themeComboBox(combo);
    }
    applyThemeFonts(dlg);
}

// A control whose top edge is inside the footer band (below footerTopDlu)
// sits on the footer colour.
static bool isFooterControl(HWND dlg, HWND control) {
    const ThemedDialog* td = themedDialog(dlg);
    if (!td || !control) return false;
    RECT r{};
    GetWindowRect(control, &r);
    MapWindowPoints(nullptr, dlg, reinterpret_cast<POINT*>(&r), 2);
    return r.top >= dialogUnitsY(dlg, td->footerTopDlu);
}

static void paintThemedDialog(HWND dlg, const ThemedDialog& td) {
    const auto& t = td.theme;
    PAINTSTRUCT ps{};
    HDC dc = BeginPaint(dlg, &ps);
    RECT client{};
    GetClientRect(dlg, &client);
    const int footerTop = dialogUnitsY(dlg, td.footerTopDlu);
    RECT footer{client.left, footerTop, client.right, client.bottom};
    jl::ui::fillRect(dc, footer, jl::ui::color::kCaption);
    RECT divider{client.left, footerTop, client.right, footerTop + jl::ui::px(t.dpi, 1)};
    jl::ui::fillRect(dc, divider, jl::ui::color::kBorder);
    RECT pad{0, 0, 4, 3};
    MapDialogRect(dlg, &pad);
    HWND edit = GetDlgItem(dlg, IDC_HOST_IP);
    if (edit && IsWindowVisible(edit)) {
        RECT r = jl::ui::childRect(dlg, IDC_HOST_IP);
        InflateRect(&r, pad.right, pad.bottom);
        jl::ui::roundRect(dc, r, jl::ui::px(t.dpi, 8), jl::ui::color::kField,
                          GetFocus() == edit ? jl::ui::accent().accent : jl::ui::color::kBorder,
                          jl::ui::px(t.dpi, 1));
    }
    if (td.extraPaint) td.extraPaint(dlg, dc, td);
    EndPaint(dlg, &ps);
}

static void invalidateFieldAround(HWND dlg, HWND child) {
    RECT r{};
    GetWindowRect(child, &r);
    MapWindowPoints(nullptr, dlg, reinterpret_cast<POINT*>(&r), 2);
    RECT pad{0, 0, 8, 6};
    MapDialogRect(dlg, &pad);
    InflateRect(&r, pad.right, pad.bottom);
    InvalidateRect(dlg, &r, TRUE);
}

// Shared message handling for both dialogs. Returns true when handled and
// sets `result` to the dialog procedure's return value.
static bool handleThemedDialogMessage(HWND dlg, UINT msg, WPARAM wParam, LPARAM lParam,
                                      INT_PTR& result) {
    if (msg == WM_MEASUREITEM) {
        // Arrives while the controls are created, before WM_INITDIALOG.
        auto* mi = reinterpret_cast<MEASUREITEMSTRUCT*>(lParam);
        if (mi->CtlType != ODT_COMBOBOX) return false;
        mi->itemHeight = mi->itemID == static_cast<UINT>(-1)
            ? static_cast<UINT>(comboFieldHeight(dlg))
            : static_cast<UINT>(jl::ui::px(jl::ui::windowDpi(dlg), 26));
        result = TRUE;
        return true;
    }
    ThemedDialog* td = themedDialog(dlg);
    if (!td) return false;
    const auto& t = td->theme;
    switch (msg) {
    case WM_CTLCOLORDLG:
        result = reinterpret_cast<INT_PTR>(t.body);
        return true;
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wParam);
        const int id = GetDlgCtrlID(reinterpret_cast<HWND>(lParam));
        COLORREF fg = jl::ui::color::kText;
        switch (textRole(id)) {
        case TextRole::Section:
        case TextRole::Brand: fg = jl::ui::accent().accent; break;
        case TextRole::Error: fg = jl::ui::color::kError; break;
        case TextRole::Subtitle:
        case TextRole::Hint:
        case TextRole::Note: fg = jl::ui::color::kMuted; break;
        default: break;
        }
        if (id == IDC_APPLY_NOTE && gSettingsNoteError) fg = jl::ui::color::kText;
        if (!IsWindowEnabled(reinterpret_cast<HWND>(lParam))) fg = jl::ui::color::kDisabled;
        const bool footer = isFooterControl(dlg, reinterpret_cast<HWND>(lParam));
        SetTextColor(dc, fg);
        SetBkColor(dc, footer ? jl::ui::color::kCaption : jl::ui::color::kBody);
        SetBkMode(dc, TRANSPARENT);
        result = reinterpret_cast<INT_PTR>(footer ? t.footer : t.body);
        return true;
    }
    case WM_CTLCOLORBTN:
        result = reinterpret_cast<INT_PTR>(
            isFooterControl(dlg, reinterpret_cast<HWND>(lParam)) ? t.footer : t.body);
        return true;
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX: {
        HDC dc = reinterpret_cast<HDC>(wParam);
        SetTextColor(dc, jl::ui::color::kText);
        SetBkColor(dc, jl::ui::color::kField);
        result = reinterpret_cast<INT_PTR>(t.field);
        return true;
    }
    case WM_PAINT:
        paintThemedDialog(dlg, *td);
        result = TRUE;
        return true;
    case WM_DRAWITEM: {
        const auto& di = *reinterpret_cast<const DRAWITEMSTRUCT*>(lParam);
        if (di.CtlType == ODT_BUTTON) {
            const int id = static_cast<int>(di.CtlID);
            const COLORREF behind = isFooterControl(dlg, di.hwndItem) ? jl::ui::color::kCaption
                                                                      : jl::ui::color::kBody;
            if (id == IDOK || id == IDCANCEL) {
                // Settings: Save is primary. Volume window: Close is its only button.
                const bool primary = id == IDOK || GetDlgItem(dlg, IDOK) == nullptr;
                jl::ui::drawButton(di, t, primary, behind);
            } else {
                jl::ui::drawCheckBox(di, t, jl::ui::ownerChecked(dlg, id), behind);
            }
            result = TRUE;
            return true;
        }
        if (di.CtlType == ODT_COMBOBOX) {
            if (di.itemState & ODS_COMBOBOXEDIT) {
                // The closed field is painted by ThemedComboProc.
                InvalidateRect(di.hwndItem, nullptr, FALSE);
                result = TRUE;
                return true;
            }
            const bool selected = (di.itemState & ODS_SELECTED) != 0;
            jl::ui::fillRect(di.hDC, di.rcItem,
                             selected ? jl::ui::accent().listSelected : jl::ui::color::kField);
            if (di.itemID != static_cast<UINT>(-1)) {
                wchar_t text[64]{};
                if (SendMessageW(di.hwndItem, CB_GETLBTEXTLEN, di.itemID, 0) <
                    static_cast<LRESULT>(std::size(text))) {
                    SendMessageW(di.hwndItem, CB_GETLBTEXT, di.itemID,
                                 reinterpret_cast<LPARAM>(text));
                }
                HGDIOBJ oldFont = SelectObject(di.hDC, t.text);
                SetBkMode(di.hDC, TRANSPARENT);
                SetTextColor(di.hDC, jl::ui::color::kText);
                RECT tr = di.rcItem;
                tr.left += jl::ui::px(t.dpi, 10);
                DrawTextW(di.hDC, text, -1, &tr, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
                SelectObject(di.hDC, oldFont);
            }
            result = TRUE;
            return true;
        }
        return false;
    }
    case WM_NOTIFY: {
        const auto* hdr = reinterpret_cast<const NMHDR*>(lParam);
        if (hdr->code != NM_CUSTOMDRAW ||
            (hdr->idFrom != IDC_VOLUME_SLIDER && hdr->idFrom != IDC_VIDEO_BITRATE)) {
            return false;
        }
        SetWindowLongPtrW(dlg, DWLP_MSGRESULT,
                          jl::ui::drawSlider(*reinterpret_cast<const NMCUSTOMDRAW*>(lParam), t));
        result = TRUE;
        return true;
    }
    case WM_COMMAND: {
        // Repaint the field outline when an edit box gains or loses focus.
        const WORD code = HIWORD(wParam);
        if (code == EN_SETFOCUS || code == EN_KILLFOCUS) {
            invalidateFieldAround(dlg, reinterpret_cast<HWND>(lParam));
        }
        const int fromId = LOWORD(wParam);
        if (code == CBN_DROPDOWN && (fromId == IDC_VIDEO_CODEC || fromId == IDC_BIND_IP)) {
            fitComboDropHeight(reinterpret_cast<HWND>(lParam));
        }
        return false;  // the dialog's own handler still sees the command
    }
    case WM_DPICHANGED:
        // Let the dialog manager rescale the layout first, then rebuild fonts.
        PostMessageW(dlg, kMsgThemeDpiChanged, 0, 0);
        return false;
    case kMsgThemeDpiChanged:
        td->theme.build(dlg, td->titlePt);
        applyThemeFonts(dlg);
        result = TRUE;
        return true;
    case WM_NCDESTROY:
        SetWindowLongPtrW(dlg, DWLP_USER, 0);
        delete td;
        return false;
    default:
        return false;
    }
}

static void updateVolumeLabel(HWND dlg) {
    wchar_t text[16]{};
    swprintf(text, std::size(text), L"%d%%", gAudioVolumePct);
    SetDlgItemTextW(dlg, IDC_VOLUME_VALUE, text);
}

// The volume window and the settings dialog's Audio section show the same
// two values; whichever moves, both follow.
static void syncVolumeControls(HWND dlg) {
    if (!dlg) return;
    if (HWND slider = GetDlgItem(dlg, IDC_VOLUME_SLIDER)) {
        if (SendMessageW(slider, TBM_GETPOS, 0, 0) != gAudioVolumePct) {
            SendMessageW(slider, TBM_SETPOS, TRUE, gAudioVolumePct);
        }
    }
    updateVolumeLabel(dlg);
    jl::ui::setOwnerChecked(dlg, IDC_VOLUME_MUTE, gAudioMuted);
}

static void syncVolumeWindows() {
    syncVolumeControls(gVolumeDlg);
    syncVolumeControls(gSettingsDlg);
    overlayRefresh();
}

static void initVolumeControls(HWND dlg) {
    HWND slider = GetDlgItem(dlg, IDC_VOLUME_SLIDER);
    SendMessageW(slider, TBM_SETRANGE, FALSE, MAKELPARAM(0, 100));
    SendMessageW(slider, TBM_SETLINESIZE, 0, 1);
    SendMessageW(slider, TBM_SETPAGESIZE, 0, 10);
    SendMessageW(slider, TBM_SETPOS, TRUE, gAudioVolumePct);
    syncVolumeControls(dlg);
}

// WM_HSCROLL from a volume slider. Volume applies at once; it is saved once
// per gesture (thumb released, key up), not on every step.
static bool handleVolumeScroll(HWND dlg, WPARAM wParam, LPARAM lParam, const char* source) {
    HWND slider = GetDlgItem(dlg, IDC_VOLUME_SLIDER);
    if (!slider || reinterpret_cast<HWND>(lParam) != slider) return false;
    setAudioVolume(static_cast<int>(SendMessageW(slider, TBM_GETPOS, 0, 0)));
    syncVolumeWindows();
    InvalidateRect(slider, nullptr, FALSE);
    if (LOWORD(wParam) == TB_ENDTRACK) commitAudioVolume(source);
    return true;
}

static void ensureCommonControls() {
    static bool ready = false;
    if (ready) return;
    INITCOMMONCONTROLSEX icc{};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_BAR_CLASSES;
    ready = InitCommonControlsEx(&icc) != FALSE;
}

// Opens at the top-right corner of the viewer window, inside its monitor's
// work area, so it covers the corner of the picture and not the middle.
static void placeVolumeWindow(HWND dlg, HWND owner) {
    RECT o{}, d{};
    if (!owner || !GetWindowRect(owner, &o) || !GetWindowRect(dlg, &d)) return;
    const int w = d.right - d.left;
    const int h = d.bottom - d.top;
    const int margin = GetSystemMetrics(SM_CYCAPTION);
    int x = o.right - w - margin;
    int y = o.top + 2 * margin;
    MONITORINFO mi{};
    mi.cbSize = sizeof(mi);
    if (GetMonitorInfoW(MonitorFromWindow(owner, MONITOR_DEFAULTTONEAREST), &mi)) {
        const int left = mi.rcWork.left, top = mi.rcWork.top;
        x = std::clamp(x, left, std::max(left, static_cast<int>(mi.rcWork.right) - w));
        y = std::clamp(y, top, std::max(top, static_cast<int>(mi.rcWork.bottom) - h));
    }
    SetWindowPos(dlg, nullptr, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
}

static INT_PTR CALLBACK VolumeDlgProc(HWND dlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    INT_PTR themed = 0;
    if (handleThemedDialogMessage(dlg, msg, wParam, lParam, themed)) return themed;
    switch (msg) {
    case WM_INITDIALOG:
        initThemedDialog(dlg, 12, kVolumeFooterTop);
        initVolumeControls(dlg);
        placeVolumeWindow(dlg, reinterpret_cast<HWND>(lParam));
        return TRUE;  // focus on the slider, the first tab stop
    case WM_HSCROLL:
        if (handleVolumeScroll(dlg, wParam, lParam, "slider")) return TRUE;
        break;
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_VOLUME_MUTE:
            if (HIWORD(wParam) == BN_CLICKED) toggleAudioMute("volume-window");
            return TRUE;
        case IDOK:
        case IDCANCEL:
            DestroyWindow(dlg);
            return TRUE;
        default:
            break;
        }
        break;
    case WM_CLOSE:
        DestroyWindow(dlg);
        return TRUE;
    case WM_DESTROY:
        commitAudioVolume("close");
        gVolumeDlg = nullptr;
        return TRUE;
    default:
        break;
    }
    return FALSE;
}

// In-session windows (Volume, Settings, Info opened while the viewer runs)
// share the overlay's translucency: a layered window at the one
// jl::overlay::kSessionUiAlpha token. Only the window's composition changes;
// it stays a modeless owned dialog driven by the main loop, so nothing here
// runs a modal loop. Before connecting (owner is not the viewer) they stay
// opaque: there is no video behind them.
static bool isSessionOwner(HWND owner) { return owner != nullptr && owner == gViewerHwnd; }

static void applySessionTranslucency(HWND wnd, HWND owner, const char* what) {
    if (!wnd || !isSessionOwner(owner)) return;
    SetWindowLongPtrW(wnd, GWL_EXSTYLE, GetWindowLongPtrW(wnd, GWL_EXSTYLE) | WS_EX_LAYERED);
    if (!SetLayeredWindowAttributes(wnd, 0, jl::overlay::kSessionUiAlpha, LWA_ALPHA)) {
        logLine(std::string("session_ui.alpha_failed window=") + what +
                " error=" + std::to_string(GetLastError()));
    }
}

// Modeless, so video keeps running while the slider moves; the main loop
// routes its keyboard input through IsDialogMessage.
static void showVolumeWindow(HWND owner, const char* source) {
    ensureAudioVolumeLoaded();
    // One dialog at a time: Settings has the same volume controls.
    if (gSettingsDlg) {
        SetForegroundWindow(gSettingsDlg);
        logLine(std::string("audio.volume.window source=") + source + " focused=settings");
        return;
    }
    if (gVolumeDlg) {
        SetForegroundWindow(gVolumeDlg);
        return;
    }
    ensureCommonControls();
    gVolumeDlg = CreateDialogParamW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDD_AUDIO_VOLUME),
                                    owner, VolumeDlgProc, reinterpret_cast<LPARAM>(owner));
    if (!gVolumeDlg) {
        logLine("audio.volume_window_failed error=" + std::to_string(GetLastError()));
        return;
    }
    applySessionTranslucency(gVolumeDlg, owner, "volume");
    ShowWindow(gVolumeDlg, SW_SHOW);
    logLine(std::string("audio.volume.window source=") + source +
            " volume=" + std::to_string(gAudioVolumePct));
}

// lParam of the dialog: kSettingsDialogConnect when shown before connecting
// (button says "Connect"), kSettingsDialogSave from the running viewer.
static constexpr LPARAM kSettingsDialogSave = 0;
static constexpr LPARAM kSettingsDialogConnect = 1;

// Manual bitrate range on the slider; 0 (saved) means Auto.
static constexpr int kBitrateSliderMin = 4;
static constexpr int kBitrateSliderMax = 100;
static constexpr int kBitrateSliderDefault = 25;

static std::wstring dialogText(HWND dlg, int id) {
    wchar_t text[64]{};
    GetDlgItemTextW(dlg, id, text, static_cast<int>(std::size(text)));
    return text;
}

static void updateBitrateControls(HWND dlg) {
    const bool autoRate = jl::ui::ownerChecked(dlg, IDC_BITRATE_AUTO);
    HWND slider = GetDlgItem(dlg, IDC_VIDEO_BITRATE);
    EnableWindow(slider, autoRate ? FALSE : TRUE);
    InvalidateRect(slider, nullptr, FALSE);
    const int value = static_cast<int>(SendMessageW(slider, TBM_GETPOS, 0, 0));
    const std::wstring text = autoRate ? std::wstring(L"Auto") : std::to_wstring(value) + L" Mbps";
    SetDlgItemTextW(dlg, IDC_BITRATE_VALUE, text.c_str());
}

// "This PC's address" for the open settings dialog (one at a time).
static jl::BindDetection gBindDetection;
static std::vector<jl::BindChoice> gBindChoices;
static std::string gBindSaved;
// The modal copy runs before connecting (Connect); from the running viewer
// the dialog is modeless, so video and audio keep running while it is open.
static bool gSettingsModal = false;

static std::wstring bindChoiceLabel(const jl::BindChoice& c) {
    switch (c.kind) {
    case jl::BindKind::Auto: return L"Auto (match Mac address)";
    case jl::BindKind::Tailnet: return L"Tailscale  " + wideFromAscii(c.ip);
    case jl::BindKind::Tailcat: return L"Tailcat  " + wideFromAscii(c.ip);
    case jl::BindKind::Saved: return L"Saved  " + wideFromAscii(c.ip);
    }
    return {};
}

static void fillBindChoices(HWND dlg) {
    HWND combo = GetDlgItem(dlg, IDC_BIND_IP);
    SendMessageW(combo, CB_RESETCONTENT, 0, 0);
    gBindDetection = detectBindAddresses();
    gBindChoices = jl::bindChoices(gBindDetection, gBindSaved);
    for (const auto& c : gBindChoices) {
        SendMessageW(combo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(bindChoiceLabel(c).c_str()));
    }
    SendMessageW(combo, CB_SETCURSEL, jl::initialBindChoice(gBindChoices, gBindSaved), 0);
    // Nothing detected and nothing saved: Auto is the only entry, shown greyed.
    EnableWindow(combo, gBindChoices.size() > 1 ? TRUE : FALSE);
}

// Greyed info under the drop-down: what Auto would use for the Mac address
// typed above, or what the manual choice always uses.
static void updateBindHint(HWND dlg) {
    const LRESULT sel = SendDlgItemMessageW(dlg, IDC_BIND_IP, CB_GETCURSEL, 0, 0);
    std::wstring hint;
    if (sel > 0 && static_cast<size_t>(sel) < gBindChoices.size()) {
        hint = L"Always uses " + wideFromAscii(gBindChoices[static_cast<size_t>(sel)].ip) +
               L". Choose Auto to match the Mac address.";
    } else {
        const std::string host = asciiFromWide(dialogText(dlg, IDC_HOST_IP));
        const jl::AutoBind a = jl::autoBindFor(host, gBindDetection);
        const std::wstring ip = wideFromAscii(a.ip);
        if (a.reason == "auto-tailnet") {
            hint = L"Uses " + ip + L" (Tailscale), matching the Mac address.";
        } else if (a.reason == "auto-tailcat") {
            hint = L"Uses " + ip + L" (Tailcat bridge), matching the Mac address.";
        } else if (a.reason == "fallback") {
            if (jl::isTailcatIPv4(host)) {
                hint = L"No Tailcat bridge on this PC (127.0.0.1:48400). Falls back to " + ip +
                       L" (Tailscale).";
            } else if (jl::isIPv4(host)) {
                hint = L"The Mac address is not Tailscale or Tailcat. Falls back to " + ip +
                       L" (Tailscale).";
            } else {
                hint = L"Uses " + ip + L" (Tailscale) until the Mac address is set.";
            }
        } else if (jl::isTailnetIPv4(host)) {
            hint = L"No Tailscale address on this PC. Connect Tailscale first.";
        } else if (jl::isTailcatIPv4(host)) {
            hint = L"No Tailcat bridge on this PC (127.0.0.1:48400) and no Tailscale address.";
        } else {
            hint = L"No Tailscale or Tailcat address found on this PC.";
        }
    }
    SetDlgItemTextW(dlg, IDC_BIND_HINT, hint.c_str());
}

// Says what applies now and what needs a reconnect (Disconnect in the
// overlay, then Connect on the launch screen).
static std::wstring settingsApplyNote(bool connect) {
    return connect ? L"Used for your next connection. Volume applies now."
                   : L"Volume applies now. Connection and video changes apply when you reconnect.";
}

// Validation errors show in the footer note (no message box: it would stop
// the viewer's main loop like a modal dialog does).
static void showSettingsError(HWND dlg, const wchar_t* text, int focusId) {
    gSettingsNoteError = true;
    SetDlgItemTextW(dlg, IDC_APPLY_NOTE, text);
    MessageBeep(MB_ICONWARNING);
    if (focusId) SetFocus(GetDlgItem(dlg, focusId));
}

static void closeSettingsDialog(HWND dlg, INT_PTR result) {
    if (gSettingsModal) EndDialog(dlg, result);
    else DestroyWindow(dlg);
}

static INT_PTR CALLBACK SettingsDlgProc(HWND dlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    INT_PTR themed = 0;
    if (handleThemedDialogMessage(dlg, msg, wParam, lParam, themed)) return themed;
    switch (msg) {
    case WM_INITDIALOG: {
        gSettingsDlg = dlg;
        gSettingsModal = lParam == kSettingsDialogConnect;
        gSettingsNoteError = false;
        initThemedDialog(dlg, 15, kSettingsFooterTop);
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

        HWND bitrate = GetDlgItem(dlg, IDC_VIDEO_BITRATE);
        SendMessageW(bitrate, TBM_SETRANGE, FALSE, MAKELPARAM(kBitrateSliderMin, kBitrateSliderMax));
        SendMessageW(bitrate, TBM_SETLINESIZE, 0, 1);
        SendMessageW(bitrate, TBM_SETPAGESIZE, 0, 5);
        const bool autoRate = settings.bitrateMbps == 0;
        SendMessageW(bitrate, TBM_SETPOS, TRUE,
                     autoRate ? kBitrateSliderDefault
                              : std::clamp<int>(settings.bitrateMbps, kBitrateSliderMin,
                                                kBitrateSliderMax));
        jl::ui::setOwnerChecked(dlg, IDC_BITRATE_AUTO, autoRate);
        updateBitrateControls(dlg);

        SetDlgItemTextW(dlg, IDC_HOST_IP, wideFromAscii(settings.hostIp).c_str());
        gBindSaved = settings.bindIp;
        fillBindChoices(dlg);
        updateBindHint(dlg);

        ensureAudioVolumeLoaded();
        initVolumeControls(dlg);

        SetDlgItemTextW(dlg, IDC_APPLY_NOTE, settingsApplyNote(gSettingsModal).c_str());
        // Owner-drawn buttons cannot be BS_DEFPUSHBUTTON; Enter still means Save.
        SendMessageW(dlg, DM_SETDEFID, IDOK, 0);
        SetForegroundWindow(dlg);
        if (settings.hostIp.empty()) {
            SetFocus(GetDlgItem(dlg, IDC_HOST_IP));
            return FALSE;  // focus set manually
        }
        return TRUE;
    }
    case WM_HSCROLL:
        if (handleVolumeScroll(dlg, wParam, lParam, "settings")) return TRUE;
        if (reinterpret_cast<HWND>(lParam) == GetDlgItem(dlg, IDC_VIDEO_BITRATE)) {
            updateBitrateControls(dlg);
            return TRUE;
        }
        break;
    case WM_DESTROY:
        commitAudioVolume("settings");
        if (gSettingsDlg == dlg) gSettingsDlg = nullptr;
        break;
    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_BITRATE_AUTO && HIWORD(wParam) == BN_CLICKED) {
            jl::ui::setOwnerChecked(dlg, IDC_BITRATE_AUTO,
                                    !jl::ui::ownerChecked(dlg, IDC_BITRATE_AUTO));
            updateBitrateControls(dlg);
            return TRUE;
        }
        if (LOWORD(wParam) == IDC_VOLUME_MUTE && HIWORD(wParam) == BN_CLICKED) {
            toggleAudioMute("settings");
            return TRUE;
        }
        if ((LOWORD(wParam) == IDC_HOST_IP && HIWORD(wParam) == EN_CHANGE) ||
            (LOWORD(wParam) == IDC_BIND_IP && HIWORD(wParam) == CBN_SELCHANGE)) {
            updateBindHint(dlg);
            if (gSettingsNoteError) {
                gSettingsNoteError = false;
                SetDlgItemTextW(dlg, IDC_APPLY_NOTE, settingsApplyNote(gSettingsModal).c_str());
            }
            return TRUE;
        }
        if (LOWORD(wParam) == IDCANCEL) {
            // Volume and mute already applied and stay; nothing else was saved.
            closeSettingsDialog(dlg, IDCANCEL);
            return TRUE;
        }
        if (LOWORD(wParam) == IDOK) {
            const std::string host = asciiFromWide(dialogText(dlg, IDC_HOST_IP));
            const int bindIndex = static_cast<int>(
                SendDlgItemMessageW(dlg, IDC_BIND_IP, CB_GETCURSEL, 0, 0));
            const std::string bind = jl::bindValueToSave(gBindChoices, bindIndex, gBindSaved);
            const LRESULT selected = SendDlgItemMessageW(
                dlg, IDC_VIDEO_CODEC, CB_GETCURSEL, 0, 0);
            const bool autoRate = jl::ui::ownerChecked(dlg, IDC_BITRATE_AUTO);
            const int sliderValue = static_cast<int>(
                SendDlgItemMessageW(dlg, IDC_VIDEO_BITRATE, TBM_GETPOS, 0, 0));
            const UINT bitrate = autoRate
                ? 0u
                : static_cast<UINT>(std::clamp(sliderValue, kBitrateSliderMin, kBitrateSliderMax));
            logLine("settings.save_attempt host=" + host +
                    " bind=" + (bind.empty() ? std::string("auto") : bind) +
                    " selected=" + std::to_string(selected) +
                    " bitrate_auto=" + (autoRate ? "yes" : "no") +
                    " bitrate=" + std::to_string(bitrate));
            if (!jl::isIPv4(host)) {
                showSettingsError(dlg, L"Enter the Mac's IPv4 address, e.g. 100.64.0.10.",
                                  IDC_HOST_IP);
                return TRUE;
            }
            if (selected == CB_ERR) {
                showSettingsError(dlg, L"Choose a codec.", IDC_VIDEO_CODEC);
                return TRUE;
            }
            SavedSettings settings;
            settings.hostIp = host;
            settings.bindIp = bind;
            settings.codec = selected == 0 ? "auto" : (selected == 2 ? "hevc" : "h264");
            settings.bitrateMbps = static_cast<uint16_t>(bitrate);
            if (!saveSettings(settings)) {
                logLine("settings.save_failed");
                showSettingsError(dlg, L"Could not save the settings.", 0);
                return TRUE;
            }
            logLine("settings.saved host=" + settings.hostIp +
                    " bind=" + (settings.bindIp.empty() ? std::string("auto") : settings.bindIp) +
                    " codec=" + settings.codec +
                    " bitrate_mbps=" + std::to_string(settings.bitrateMbps));
            closeSettingsDialog(dlg, IDOK);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

// Before connecting: modal, the caller waits for Connect or Cancel.
static INT_PTR runSettingsDialog(HWND owner, LPARAM mode) {
    ensureCommonControls();
    const INT_PTR result = DialogBoxParamW(
        GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDD_VIDEO_SETTINGS),
        owner, SettingsDlgProc, mode);
    if (result == -1) {
        logLine("settings.dialog_create_failed error=" + std::to_string(GetLastError()));
    }
    return result;
}

// From the running viewer: modeless, like the volume window, so the main
// loop keeps presenting video and keeping audio alive. One dialog at a time:
// opening Settings closes the volume window (Settings has the same controls).
static void showVideoSettings(HWND owner) {
    if (gSettingsDlg) {
        SetForegroundWindow(gSettingsDlg);
        return;
    }
    if (gVolumeDlg) DestroyWindow(gVolumeDlg);
    ensureCommonControls();
    HWND dlg = CreateDialogParamW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDD_VIDEO_SETTINGS),
                                  owner, SettingsDlgProc, kSettingsDialogSave);
    if (!dlg) {
        logLine("settings.dialog_create_failed error=" + std::to_string(GetLastError()));
        return;
    }
    applySessionTranslucency(dlg, owner, "settings");
    ShowWindow(dlg, SW_SHOW);
    logLine("settings.window open=modeless");
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

// ---- Connection info (modeless) -------------------------------------------
// Replaces the old message box, which ran a modal loop and stopped the
// viewer's main loop. Refreshes every second while open.

static constexpr UINT_PTR kInfoRefreshTimer = 1;

static std::wstring connectionInfoText(int id) {
    const auto& c = gConnectionInfo;
    std::wostringstream s;
    if (id == IDC_INFO_CONFIGURED) {
        s << L"Codec: " << codecDisplayName(c.configuredCodec) << L"\r\nBandwidth: "
          << (c.configuredBitrateMbps == 0 ? std::wstring(L"Auto")
                                           : std::to_wstring(c.configuredBitrateMbps) + L" Mbps");
    } else if (id == IDC_INFO_EFFECTIVE) {
        s << L"Codec: " << codecDisplayName(c.effectiveCodec) << L"\r\nBandwidth: "
          << c.effectiveBitrateMbps << L" Mbps\r\nRemote: " << c.remoteWidth << L" x "
          << c.remoteHeight << L" @ " << c.fps << L" fps\r\nControl RTT: ";
        if (c.controlConnected) {
            s << std::fixed << std::setprecision(1) << c.rttMs << L" ms";
        } else {
            s << L"unavailable";
        }
    } else {
        s << L"Backend: " << utf8ToWide(c.backend) << L"\r\nDecoder: " << utf8ToWide(c.decoder)
          << L"\r\nGPU: "
          << (c.adapter.empty() ? std::wstring(L"CPU / unavailable") : utf8ToWide(c.adapter));
    }
    return s.str();
}

static std::wstring windowText(HWND hwnd) {
    const int n = hwnd ? GetWindowTextLengthW(hwnd) : 0;
    if (n <= 0) return {};
    std::wstring out(static_cast<size_t>(n) + 1, L'\0');
    out.resize(static_cast<size_t>(GetWindowTextW(hwnd, out.data(), n + 1)));
    return out;
}

// Only changed text is set, so the window does not flicker every second.
static void fillConnectionInfo(HWND dlg) {
    for (int id : {IDC_INFO_CONFIGURED, IDC_INFO_EFFECTIVE, IDC_INFO_DECODER}) {
        HWND item = GetDlgItem(dlg, id);
        const std::wstring next = connectionInfoText(id);
        if (item && windowText(item) != next) SetWindowTextW(item, next.c_str());
    }
}

static INT_PTR CALLBACK InfoDlgProc(HWND dlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    INT_PTR themed = 0;
    if (handleThemedDialogMessage(dlg, msg, wParam, lParam, themed)) return themed;
    switch (msg) {
    case WM_INITDIALOG:
        initThemedDialog(dlg, 13, kInfoFooterTop);
        fillConnectionInfo(dlg);
        placeVolumeWindow(dlg, reinterpret_cast<HWND>(lParam));
        SetTimer(dlg, kInfoRefreshTimer, 1000, nullptr);
        return TRUE;
    case WM_TIMER:
        if (wParam == kInfoRefreshTimer) {
            fillConnectionInfo(dlg);
            return TRUE;
        }
        break;
    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL) {
            DestroyWindow(dlg);
            return TRUE;
        }
        break;
    case WM_CLOSE:
        DestroyWindow(dlg);
        return TRUE;
    case WM_DESTROY:
        KillTimer(dlg, kInfoRefreshTimer);
        if (gInfoDlg == dlg) gInfoDlg = nullptr;
        return TRUE;
    default:
        break;
    }
    return FALSE;
}

static void showConnectionInfo(HWND owner, const char* source) {
    if (gInfoDlg) {
        SetForegroundWindow(gInfoDlg);
        return;
    }
    gInfoDlg = CreateDialogParamW(GetModuleHandleW(nullptr),
                                  MAKEINTRESOURCEW(IDD_CONNECTION_INFO), owner, InfoDlgProc,
                                  reinterpret_cast<LPARAM>(owner));
    if (!gInfoDlg) {
        logLine("connection.info_failed error=" + std::to_string(GetLastError()));
        return;
    }
    applySessionTranslucency(gInfoDlg, owner, "info");
    ShowWindow(gInfoDlg, SW_SHOW);
    logLine(std::string("connection.info.opened source=") + source + " window=modeless");
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

// JERISLINK_DEBUG=1: debug-only diagnostics (first-frame BMP). Read once.
static bool debugMode() {
    static const bool on = jl::debugModeEnabled(envValue("JERISLINK_DEBUG"));
    return on;
}

// ---- Session timers, disconnect and relaunch ------------------------------
// Windows runs its own modal loop while the caption is dragged, the window
// is sized or the system menu is open; the main loop is stopped then, but
// WM_TIMER is still dispatched. The session timer drains the socket and
// sends the keep-alives from there, so video and audio keep flowing. While
// the main loop runs it reads the socket itself and the tick does nothing.
static constexpr UINT_PTR kSessionTickTimer = 0x4A4C;
static constexpr UINT_PTR kOverlayHoverTimer = 0x4A4D;
static constexpr UINT kSessionTickMs = 10;
static constexpr UINT kOverlayHoverMs = 100;
static std::function<void()> gSessionModalTick;
static bool gInSessionTick = false;
static double gMainLoopRecvMs = 0.0;  // last time the main loop read the socket
static uint64_t gSessionTicks = 0;
// Disconnect, a timeout or an error ends the session and starts JerisLink
// again on the launch screen, which shows gRelaunchNote.
static bool gRelaunch = false;
static std::wstring gRelaunchNote;

static void runSessionModalTick() {
    if (!gSessionModalTick || gInSessionTick) return;
    if (steadyMsNow() - gMainLoopRecvMs < 20.0) return;  // the main loop is running
    gInSessionTick = true;
    ++gSessionTicks;
    try {
        gSessionModalTick();
    } catch (const std::exception& e) {
        logLine(std::string("session.tick_error ") + e.what());
    }
    gInSessionTick = false;
}

// ---- In-session overlay (B1) ----------------------------------------------
// A thin bar at the top centre of the viewer: status, mute, volume, Info,
// Settings, Disconnect. A non-activating owned popup: it never takes the
// keyboard from the viewer and never runs a modal loop. It is a layered
// window at ov::kSessionUiAlpha opacity, so the video shows through. Ctrl+Alt+O
// opens it for the keyboard; holding the pointer in the bottom-left corner of
// the viewer for 2 s opens it for the mouse (the bar still opens at the top).
namespace ov = jl::overlay;

static HWND gOverlay = nullptr;
static bool gOverlayKeyboard = false;  // opened with Ctrl+Alt+O: focus ring, keys
static ov::Item gOverlayFocus = ov::Item::Mute;
static ov::Item gOverlayHot = ov::Item::None;
static ov::Item gOverlayPressed = ov::Item::None;
static bool gOverlayDragging = false;
static bool gOverlayTracking = false;
static double gOverlayHideAtMs = 0.0;  // 0: no pending auto-hide
static ov::Dwell gOverlayDwell(2000.0);
static std::bitset<256> gOverlaySwallowUp;  // key-ups of keys the overlay used
static std::string gSessionHostLabel;
static jl::ui::DialogTheme gOverlayTheme;
static UINT gOverlayThemeDpi = 0;

static const char* overlayItemName(ov::Item item) {
    switch (item) {
    case ov::Item::Status: return "status";
    case ov::Item::Mute: return "mute";
    case ov::Item::Volume: return "volume";
    case ov::Item::Info: return "info";
    case ov::Item::Settings: return "settings";
    case ov::Item::Disconnect: return "disconnect";
    default: return "none";
    }
}

static bool overlayVisible() { return gOverlay && IsWindowVisible(gOverlay); }

static void overlayRefresh() {
    if (gOverlay) InvalidateRect(gOverlay, nullptr, FALSE);
}

static UINT overlayDpi() {
    return jl::ui::windowDpi(gOverlay ? gOverlay : gViewerHwnd);
}

static void overlayReposition() {
    if (!gOverlay || !gViewerHwnd) return;
    const UINT dpi = overlayDpi();
    const ov::Layout l = ov::layoutFor(dpi);
    RECT c{};
    GetClientRect(gViewerHwnd, &c);
    MapWindowPoints(gViewerHwnd, nullptr, reinterpret_cast<POINT*>(&c), 2);
    const ov::Point p = ov::placeInClient({c.left, c.top, c.right, c.bottom}, l.size.width(),
                                          l.size.height(), ov::scale(16, dpi));
    SetWindowPos(gOverlay, nullptr, p.x, p.y, l.size.width(), l.size.height(),
                 SWP_NOZORDER | SWP_NOACTIVATE);
}

static void overlayShow(bool keyboard, const char* source, double autoHideMs) {
    if (!gOverlay || !gViewerHwnd || IsIconic(gViewerHwnd)) return;
    const bool wasVisible = overlayVisible();
    gOverlayKeyboard = keyboard;
    if (keyboard && gOverlayFocus == ov::Item::None) gOverlayFocus = ov::Item::Mute;
    gOverlayHideAtMs = autoHideMs > 0 ? steadyMsNow() + autoHideMs : 0.0;
    overlayReposition();
    if (!wasVisible) ShowWindow(gOverlay, SW_SHOWNOACTIVATE);
    overlayRefresh();
    logLine(std::string("overlay.show source=") + source + " keyboard=" + (keyboard ? "1" : "0"));
}

static void overlayHide(const char* source) {
    if (!overlayVisible()) return;
    if (gOverlayDragging) {
        gOverlayDragging = false;
        if (GetCapture() == gOverlay) ReleaseCapture();
        commitAudioVolume("overlay");
    }
    ShowWindow(gOverlay, SW_HIDE);
    gOverlayKeyboard = false;
    gOverlayHot = ov::Item::None;
    gOverlayPressed = ov::Item::None;
    gOverlayHideAtMs = 0.0;
    logLine(std::string("overlay.hide source=") + source);
}

// Ends the session from the overlay: the main loop stops, the session is
// torn down as on close, and JerisLink starts again on the launch screen.
static void requestDisconnect(const char* source) {
    logLine(std::string("session.disconnect source=") + source);
    gRelaunch = true;
    overlayHide("disconnect");
    releaseRemoteButtons("disconnect");
    releaseRemoteModifiers();
    if (gViewerHwnd) ShowWindow(gViewerHwnd, SW_HIDE);
    gWindowClosed = true;
}

static void overlayActivate(ov::Item item, const char* source) {
    logLine(std::string("overlay.action item=") + overlayItemName(item) + " source=" + source);
    switch (item) {
    case ov::Item::Mute:
        toggleAudioMute("overlay");
        break;
    case ov::Item::Volume:
        overlayHide("action");
        showVolumeWindow(gViewerHwnd, "overlay");
        break;
    case ov::Item::Info:
        overlayHide("action");
        showConnectionInfo(gViewerHwnd, "overlay");
        break;
    case ov::Item::Settings:
        overlayHide("action");
        logLine("video.settings.command source=overlay");
        showVideoSettings(gViewerHwnd);
        break;
    case ov::Item::Disconnect:
        requestDisconnect("overlay");
        break;
    default:
        break;
    }
}

// Viewer-only shortcuts (Ctrl+Alt+letter); the letter never reaches the Mac.
static bool viewerHotkey(WPARAM vk, const char* source) {
    switch (vk) {
    case 'O':
        if (overlayVisible()) overlayHide(source);
        else overlayShow(true, source, 0);
        return true;
    case 'M':
        toggleAudioMute(source);
        return true;
    case 'V':
        showVolumeWindow(gViewerHwnd, source);
        return true;
    default:
        return false;
    }
}

static bool isViewerHotkey(WPARAM vk) {
    return (vk == 'O' || vk == 'M' || vk == 'V') && physicalKeyDown(VK_CONTROL) &&
           physicalKeyDown(VK_MENU);
}

static void overlaySetVolume(int pct) {
    if (pct == gAudioVolumePct) return;
    setAudioVolume(pct);
    syncVolumeWindows();
}

// Keys while the overlay is open for the keyboard.
static void overlayKey(WPARAM vk, bool repeat) {
    gOverlayHideAtMs = 0.0;
    switch (vk) {
    case VK_TAB:
        gOverlayFocus = ov::nextFocus(gOverlayFocus, physicalKeyDown(VK_SHIFT) ? -1 : 1);
        break;
    case VK_UP:
        gOverlayFocus = ov::nextFocus(gOverlayFocus, -1);
        break;
    case VK_DOWN:
        gOverlayFocus = ov::nextFocus(gOverlayFocus, 1);
        break;
    case VK_LEFT:
    case VK_RIGHT: {
        const int dir = vk == VK_RIGHT ? 1 : -1;
        if (gOverlayFocus == ov::Item::Volume) {
            overlaySetVolume(ov::volumeStep(gAudioVolumePct, dir));
            commitAudioVolume("overlay-key");
        } else {
            gOverlayFocus = ov::nextFocus(gOverlayFocus, dir);
        }
        break;
    }
    case VK_RETURN:
    case VK_SPACE:
        if (!repeat) overlayActivate(gOverlayFocus, "overlay-key");
        return;
    case VK_ESCAPE:
        overlayHide("escape");
        return;
    default:
        return;
    }
    overlayRefresh();
}

// WM_KEYDOWN / WM_SYSKEYDOWN on the viewer, before anything is forwarded.
// Returns true when the key belongs to the viewer and must not reach the Mac.
static bool overlayHandleKeyDown(WPARAM vk, LPARAM lParam) {
    const bool repeat = (lParam & (1LL << 30)) != 0;
    if (isViewerHotkey(vk)) {
        // The key-up is swallowed via gSuppressedShortcutKey. Ctrl and Alt
        // were already sent as plain modifier downs and are released normally.
        if (!repeat) viewerHotkey(vk, "shortcut");
        gSuppressedShortcutKey = vk;
        gTemporarilyReleasedModifier = 0;
        return true;
    }
    if (!gOverlayKeyboard || !overlayVisible()) return false;
    switch (vk) {
    case VK_TAB:
    case VK_LEFT:
    case VK_RIGHT:
    case VK_UP:
    case VK_DOWN:
    case VK_RETURN:
    case VK_SPACE:
    case VK_ESCAPE:
        gOverlaySwallowUp.set(static_cast<size_t>(vk));
        overlayKey(vk, repeat);
        return true;
    default:
        return false;
    }
}

static RECT toRECT(const ov::Rect& r) { return RECT{r.left, r.top, r.right, r.bottom}; }

static void overlayFocusFrame(HDC dc, const RECT& r, UINT dpi) {
    HPEN pen = CreatePen(PS_INSIDEFRAME, std::max(1, ov::scale(2, dpi)),
                         jl::ui::accent().focusRing);
    HGDIOBJ oldPen = SelectObject(dc, pen);
    HGDIOBJ oldBrush = SelectObject(dc, GetStockObject(NULL_BRUSH));
    const int radius = ov::scale(8, dpi);
    RoundRect(dc, r.left, r.top, r.right, r.bottom, radius, radius);
    SelectObject(dc, oldBrush);
    SelectObject(dc, oldPen);
    DeleteObject(pen);
}

static void overlayText(HDC dc, const std::wstring& text, RECT r, HFONT font, COLORREF color,
                        UINT format) {
    HGDIOBJ old = SelectObject(dc, font);
    SetTextColor(dc, color);
    DrawTextW(dc, text.c_str(), -1, &r, format | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
    SelectObject(dc, old);
}

// Speaker drawn with GDI (no icon font): body, cone, then two waves or an X.
static void drawSpeaker(HDC dc, const RECT& r, bool muted, COLORREF color, UINT dpi) {
    const auto s = [dpi](int v) { return ov::scale(v, dpi); };
    const int cx = (r.left + r.right) / 2 - s(2);
    const int cy = (r.top + r.bottom) / 2;
    POINT body[6] = {{cx - s(7), cy - s(3)}, {cx - s(3), cy - s(3)}, {cx + s(2), cy - s(7)},
                     {cx + s(2), cy + s(7)}, {cx - s(3), cy + s(3)}, {cx - s(7), cy + s(3)}};
    SetDCBrushColor(dc, color);
    SetDCPenColor(dc, color);
    HGDIOBJ oldBrush = SelectObject(dc, GetStockObject(DC_BRUSH));
    HGDIOBJ oldPen = SelectObject(dc, GetStockObject(DC_PEN));
    Polygon(dc, body, 6);
    SelectObject(dc, oldBrush);
    SelectObject(dc, oldPen);
    const int w = std::max(1, s(2));
    if (muted) {
        jl::ui::line(dc, cx + s(5), cy - s(4), cx + s(11), cy + s(4), color, w);
        jl::ui::line(dc, cx + s(11), cy - s(4), cx + s(5), cy + s(4), color, w);
        return;
    }
    HPEN pen = CreatePen(PS_SOLID, w, color);
    HGDIOBJ penWas = SelectObject(dc, pen);
    HGDIOBJ brushWas = SelectObject(dc, GetStockObject(NULL_BRUSH));
    for (int radius : {s(5), s(9)}) {
        const int ax = cx + s(2);
        Arc(dc, ax - radius, cy - radius, ax + radius, cy + radius, ax + radius, cy + radius,
            ax + radius, cy - radius);
    }
    SelectObject(dc, brushWas);
    SelectObject(dc, penWas);
    DeleteObject(pen);
}

static void overlayButton(HDC dc, const RECT& r, const wchar_t* text, ov::Item item,
                          COLORREF textColor, UINT dpi) {
    namespace c = jl::ui::color;
    const bool hot = gOverlayHot == item || gOverlayPressed == item;
    jl::ui::roundRect(dc, r, ov::scale(8, dpi), hot ? c::kSecondaryDown : c::kSecondary,
                      c::kBorder, 1);
    overlayText(dc, text, r, gOverlayTheme.text, textColor, DT_CENTER | DT_VCENTER);
}

static void paintOverlay(HWND hwnd) {
    namespace c = jl::ui::color;
    PAINTSTRUCT ps{};
    HDC wdc = BeginPaint(hwnd, &ps);
    RECT client{};
    GetClientRect(hwnd, &client);
    HDC dc = CreateCompatibleDC(wdc);
    HBITMAP bmp = CreateCompatibleBitmap(wdc, std::max<LONG>(1, client.right),
                                         std::max<LONG>(1, client.bottom));
    HGDIOBJ oldBmp = SelectObject(dc, bmp);

    const UINT dpi = overlayDpi();
    if (gOverlayThemeDpi != dpi || !gOverlayTheme.text) {
        gOverlayTheme.build(hwnd, 9);
        gOverlayThemeDpi = dpi;
    }
    const auto& t = gOverlayTheme;
    const auto& a = jl::ui::accent();
    const auto s = [dpi](int v) { return ov::scale(v, dpi); };
    const ov::Layout l = ov::layoutFor(dpi);
    SetBkMode(dc, TRANSPARENT);

    jl::ui::fillRect(dc, client, c::kBody);
    jl::ui::roundRect(dc, client, s(12), c::kBody, c::kBorder, 1);

    // Status: accent dot, "Connected", and the Mac's address.
    const RECT st = toRECT(l.status);
    const int mid = (st.top + st.bottom) / 2;
    const int dot = s(8);
    const RECT dotR{st.left, mid - s(10) - dot / 2, st.left + dot, mid - s(10) - dot / 2 + dot};
    jl::ui::ellipse(dc, dotR, a.accent, a.accent);
    overlayText(dc, L"Connected", RECT{st.left + dot + s(8), st.top, st.right, mid}, t.label,
                c::kText, DT_LEFT | DT_VCENTER);
    const std::wstring host = gSessionHostLabel.empty()
        ? std::wstring(L"Mac") : L"Mac " + wideFromAscii(gSessionHostLabel);
    overlayText(dc, host, RECT{st.left, mid, st.right, st.bottom}, t.smallText, c::kMuted,
                DT_LEFT | DT_VCENTER);

    for (int x : {l.sep1, l.sep2}) {
        jl::ui::fillRect(dc, RECT{x, l.bar.top + s(12), x + std::max(1, s(1)),
                                  l.bar.bottom - s(12)}, c::kBorder);
    }

    // Mute.
    const RECT mute = toRECT(l.mute);
    jl::ui::roundRect(dc, mute, s(8),
                      gOverlayHot == ov::Item::Mute || gOverlayPressed == ov::Item::Mute
                          ? c::kSecondaryDown : c::kSecondary,
                      c::kBorder, 1);
    drawSpeaker(dc, mute, gAudioMuted, gAudioMuted ? c::kError : c::kText, dpi);

    // Volume label and slider.
    const RECT vl = toRECT(l.volumeLabel);
    const int vmid = (vl.top + vl.bottom) / 2;
    overlayText(dc, L"Volume", RECT{vl.left, vl.top, vl.right, vmid}, t.smallText, c::kMuted,
                DT_LEFT | DT_VCENTER);
    overlayText(dc, gAudioMuted ? std::wstring(L"Muted") : std::to_wstring(gAudioVolumePct) + L"%",
                RECT{vl.left, vmid, vl.right, vl.bottom}, t.label,
                gAudioMuted ? c::kMuted : c::kText, DT_LEFT | DT_VCENTER);
    const RECT sl = toRECT(l.slider);
    const int scy = (sl.top + sl.bottom) / 2;
    const int th = std::max(2, s(4));
    const int r = ov::sliderKnobRadius(dpi);
    const int knobX = ov::sliderKnobX(l.slider, gAudioVolumePct, dpi);
    const COLORREF fill = gAudioMuted ? c::kDisabled : a.accent;
    jl::ui::roundRect(dc, RECT{sl.left + r, scy - th / 2, sl.right - r, scy - th / 2 + th}, th,
                      c::kBorder, c::kBorder);
    if (knobX > sl.left + r) {
        jl::ui::roundRect(dc, RECT{sl.left + r, scy - th / 2, knobX, scy - th / 2 + th}, th,
                          fill, fill);
    }
    jl::ui::ellipse(dc, RECT{knobX - r, scy - r, knobX + r, scy + r}, fill,
                    gOverlayHot == ov::Item::Volume || gOverlayDragging ? c::kText : fill);

    overlayButton(dc, toRECT(l.info), L"Info", ov::Item::Info, c::kText, dpi);
    overlayButton(dc, toRECT(l.settings), L"Settings", ov::Item::Settings, c::kText, dpi);
    overlayButton(dc, toRECT(l.disconnect), L"Disconnect", ov::Item::Disconnect, c::kError, dpi);

    if (gOverlayKeyboard) {
        RECT f{};
        switch (gOverlayFocus) {
        case ov::Item::Mute: f = mute; break;
        case ov::Item::Volume: f = RECT{vl.left - s(4), vl.top, sl.right + s(2), sl.bottom}; break;
        case ov::Item::Info: f = toRECT(l.info); break;
        case ov::Item::Settings: f = toRECT(l.settings); break;
        case ov::Item::Disconnect: f = toRECT(l.disconnect); break;
        default: break;
        }
        if (f.right > f.left) overlayFocusFrame(dc, f, dpi);
    }

    jl::ui::fillRect(dc, RECT{l.hint.left, l.bar.bottom - 1, l.hint.right, l.bar.bottom},
                     c::kBorder);
    overlayText(dc,
                gOverlayKeyboard
                    ? L"Tab or arrows to move \u00b7 Enter to choose \u00b7 Esc to close"
                    : L"Ctrl+Alt+O, or hold the pointer bottom-left for 2 s",
                toRECT(l.hint), t.smallText, c::kMuted, DT_LEFT | DT_VCENTER);

    BitBlt(wdc, 0, 0, client.right, client.bottom, dc, 0, 0, SRCCOPY);
    SelectObject(dc, oldBmp);
    DeleteObject(bmp);
    DeleteDC(dc);
    EndPaint(hwnd, &ps);
}

static LRESULT CALLBACK OverlayWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    const int x = static_cast<short>(LOWORD(lParam));
    const int y = static_cast<short>(HIWORD(lParam));
    switch (msg) {
    case WM_MOUSEACTIVATE:
        return MA_NOACTIVATE;  // the viewer keeps the keyboard
    case WM_SETCURSOR:
        SetCursor(LoadCursorW(nullptr, IDC_ARROW));
        return TRUE;
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT:
        paintOverlay(hwnd);
        return 0;
    case WM_MOUSEMOVE: {
        if (!gOverlayTracking) {
            TRACKMOUSEEVENT tme{};
            tme.cbSize = sizeof(tme);
            tme.dwFlags = TME_LEAVE;
            tme.hwndTrack = hwnd;
            gOverlayTracking = TrackMouseEvent(&tme) != FALSE;
        }
        gOverlayHideAtMs = 0.0;
        const UINT dpi = overlayDpi();
        if (gOverlayDragging) {
            overlaySetVolume(ov::sliderValueAt(ov::layoutFor(dpi).slider, x, dpi));
            return 0;
        }
        const ov::Item hot = ov::hitTest(ov::layoutFor(dpi), x, y);
        if (hot != gOverlayHot) {
            gOverlayHot = hot;
            overlayRefresh();
        }
        return 0;
    }
    case WM_MOUSELEAVE:
        gOverlayTracking = false;
        if (gOverlayHot != ov::Item::None) {
            gOverlayHot = ov::Item::None;
            overlayRefresh();
        }
        return 0;
    case WM_LBUTTONDOWN: {
        const UINT dpi = overlayDpi();
        const ov::Layout l = ov::layoutFor(dpi);
        gOverlayPressed = ov::hitTest(l, x, y);
        if (gOverlayPressed == ov::Item::None) return 0;
        SetCapture(hwnd);
        if (gOverlayPressed == ov::Item::Volume) {
            gOverlayDragging = true;
            overlaySetVolume(ov::sliderValueAt(l.slider, x, dpi));
        }
        overlayRefresh();
        return 0;
    }
    case WM_LBUTTONUP: {
        const ov::Item pressed = gOverlayPressed;
        gOverlayPressed = ov::Item::None;
        if (gOverlayDragging) {
            gOverlayDragging = false;
            if (GetCapture() == hwnd) ReleaseCapture();
            commitAudioVolume("overlay");
            overlayRefresh();
            return 0;
        }
        if (GetCapture() == hwnd) ReleaseCapture();
        if (pressed != ov::Item::None && pressed == ov::hitTest(ov::layoutFor(overlayDpi()), x, y)) {
            overlayActivate(pressed, "overlay-click");
        }
        overlayRefresh();
        return 0;
    }
    case WM_CAPTURECHANGED:
        if (gOverlayDragging) {
            gOverlayDragging = false;
            commitAudioVolume("overlay");
        }
        gOverlayPressed = ov::Item::None;
        overlayRefresh();
        return 0;
    case WM_DESTROY:
        if (gOverlay == hwnd) gOverlay = nullptr;
        return 0;
    default:
        break;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

static void overlayCreate(HWND viewer) {
    if (gOverlay || !viewer) return;
    HINSTANCE hi = GetModuleHandleW(nullptr);
    static bool registered = false;
    if (!registered) {
        WNDCLASSEXW wc{};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = OverlayWndProc;
        wc.hInstance = hi;
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.lpszClassName = L"JerislinkOverlay";
        registered = RegisterClassExW(&wc) != 0 || GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    }
    gOverlay = CreateWindowExW(WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_LAYERED,
                               L"JerislinkOverlay",
                               L"JerisLink controls", WS_POPUP, 0, 0, 1, 1, viewer, nullptr, hi,
                               nullptr);
    if (!gOverlay) {
        logLine("overlay.create_failed error=" + std::to_string(GetLastError()));
        return;
    }
    // Whole-window alpha: GDI painting stays as it is (no per-pixel alpha).
    if (!SetLayeredWindowAttributes(gOverlay, 0, ov::kSessionUiAlpha, LWA_ALPHA)) {
        logLine("overlay.alpha_failed error=" + std::to_string(GetLastError()));
    }
    // Rounded on Windows 11; Windows 10 keeps square corners.
    DWM_WINDOW_CORNER_PREFERENCE corners = DWMWCP_ROUND;
    DwmSetWindowAttribute(gOverlay, DWMWA_WINDOW_CORNER_PREFERENCE, &corners, sizeof(corners));
    ensureAudioVolumeLoaded();
    gOverlayFocus = ov::Item::Mute;
    gOverlayDwell.reset();
    gOverlaySwallowUp.reset();
    overlayReposition();
    logLine("overlay.created");
}

static void overlayDestroy() {
    if (gOverlay && IsWindow(gOverlay)) DestroyWindow(gOverlay);
    gOverlay = nullptr;
    gOverlayKeyboard = false;
    gOverlayDragging = false;
    gOverlayTracking = false;
    gOverlayHot = ov::Item::None;
    gOverlayPressed = ov::Item::None;
    gOverlaySwallowUp.reset();
}

// Every 100 ms: the bottom-left hover fallback and the auto-hide.
static void overlayHoverTick() {
    if (!gOverlay || !gViewerHwnd) return;
    const double now = steadyMsNow();
    if (IsIconic(gViewerHwnd) || !IsWindowVisible(gViewerHwnd)) {
        gOverlayDwell.reset();
        overlayHide("minimized");
        return;
    }
    POINT pt{};
    bool inZone = false;
    bool overOverlay = false;
    if (GetCursorPos(&pt)) {
        HWND under = WindowFromPoint(pt);
        overOverlay = under == gOverlay;
        if (under == gViewerHwnd) {
            POINT cp = pt;
            ScreenToClient(gViewerHwnd, &cp);
            RECT c{};
            GetClientRect(gViewerHwnd, &c);
            inZone = ov::inCornerZone(cp.x, cp.y, c.right, c.bottom,
                                      ov::scale(ov::kHoverZone, overlayDpi()));
        }
    }
    if (gOverlayDwell.update(inZone, now) && !overlayVisible()) overlayShow(false, "hover", 0);
    if (!overlayVisible() || gOverlayKeyboard || gOverlayDragging) return;
    if (overOverlay || inZone) {
        gOverlayHideAtMs = 0.0;
        return;
    }
    if (gOverlayHideAtMs == 0.0) gOverlayHideAtMs = now + 3000.0;
    else if (now >= gOverlayHideAtMs) overlayHide("auto");
}

static LRESULT viewerWndProcImpl(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    const ModalScope modal(msg);
    switch (msg) {
    case WM_SYSCOMMAND:
        // Alt or F10 on its own would enter the menu loop (a modal loop) and
        // Alt is a Mac key here: never start it.
        if ((wParam & 0xFFF0u) == SC_KEYMENU) return 0;
        break;
    case WM_TIMER:
        if (wParam == kSessionTickTimer) {
            runSessionModalTick();
            return 0;
        }
        if (wParam == kOverlayHoverTimer) {
            overlayHoverTick();
            return 0;
        }
        break;
    case WM_MOVE:
        overlayReposition();
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
        releaseRemoteButtons("focus_kill");
        releaseRemoteModifiers();
        logLine("focus.kill");
        return 0;
    case WM_CAPTURECHANGED:
        // Another window took the mouse capture while a button was held: the
        // WM_*BUTTONUP will not come here, so send the ups now.
        if (reinterpret_cast<HWND>(lParam) != hwnd) releaseRemoteButtons("capture_changed");
        return 0;
    case WM_ACTIVATE:
        gViewerFocused = LOWORD(wParam) != WA_INACTIVE;
        logLine(std::string(gViewerFocused ? "focus.activate" : "focus.deactivate") +
                " minimized=" + (HIWORD(wParam) ? "1" : "0") +
                " click=" + (LOWORD(wParam) == WA_CLICKACTIVE ? "1" : "0"));
        return 0;
    case WM_MOUSEACTIVATE:
        gViewerFocused = true;
        logLine("focus.mouse_activate");
        return MA_ACTIVATE;
    case WM_KEYDOWN:
    case WM_SYSKEYDOWN: {
        // Viewer shortcuts (Ctrl+Alt+O/M/V) and the keyboard-driven overlay
        // are handled before anything is forwarded to the Mac.
        if (viewerHasInteractiveFocus(hwnd) && overlayHandleKeyDown(wParam, lParam)) return 0;
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
        if (wParam < 256 && gOverlaySwallowUp.test(static_cast<size_t>(wParam))) {
            gOverlaySwallowUp.reset(static_cast<size_t>(wParam));
            return 0;
        }
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
    case WM_LBUTTONDBLCLK:
        if (viewerHasInteractiveFocus(hwnd) && gControl) {
            POINT p{static_cast<short>(LOWORD(lParam)), static_cast<short>(HIWORD(lParam))};
            sendAbsolutePointer(hwnd, p);
            gLeftClickCount = msg == WM_LBUTTONDBLCLK ? 2 : 1;
            SetCapture(hwnd);
            gControl->sendMouseButtonExtended(0, true, gLeftClickCount);
            gRemoteButtons.down(0);
            return 0;
        }
        break;
    case WM_RBUTTONDOWN:
    case WM_MBUTTONDOWN:
        if (viewerHasInteractiveFocus(hwnd) && gControl) {
            const uint8_t button = msg == WM_RBUTTONDOWN ? 1 : 2;
            POINT p{static_cast<short>(LOWORD(lParam)), static_cast<short>(HIWORD(lParam))};
            sendAbsolutePointer(hwnd, p);
            SetCapture(hwnd);
            gControl->sendMouseButton(button, true);
            gRemoteButtons.down(button);
            return 0;
        }
        break;
    case WM_LBUTTONUP:
    case WM_RBUTTONUP:
    case WM_MBUTTONUP: {
        // No focus gate: a down that was sent always gets its up, even when
        // focus moved while the button was held.
        const uint8_t button = msg == WM_LBUTTONUP ? 0 : (msg == WM_RBUTTONUP ? 1 : 2);
        if (!gRemoteButtons.up(button)) break;
        if (gControl) {
            if (viewerHasInteractiveFocus(hwnd)) {
                POINT p{static_cast<short>(LOWORD(lParam)), static_cast<short>(HIWORD(lParam))};
                sendAbsolutePointer(hwnd, p);
            }
            sendRemoteButtonUp(button);
        }
        if (button == 0 && gLeftClickCount >= 2) gLeftClickCount = 1;
        // Keep the capture while another button is still held.
        if (!gRemoteButtons.anyHeld() && GetCapture() == hwnd) ReleaseCapture();
        return 0;
    }
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
    case WM_SIZE: {
        gHaveMouse = false;
        // Minimize / restore / maximize (not every step of a drag resize).
        const UINT type = static_cast<UINT>(wParam);
        if (type != gLastSizeType) {
            gLastSizeType = type;
            const char* name = type == SIZE_MINIMIZED ? "minimized"
                             : type == SIZE_MAXIMIZED ? "maximized"
                             : type == SIZE_RESTORED ? "restored" : "other";
            logLine(std::string("window.size type=") + name + " client=" +
                    std::to_string(LOWORD(lParam)) + "x" + std::to_string(HIWORD(lParam)));
        }
        if (type == SIZE_MINIMIZED) overlayHide("minimized");
        else overlayReposition();
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT:
        paintCpuFrame(hwnd);
        return 0;
    case WM_CLOSE:
        gWindowClosed = true;
        releaseRemoteButtons("close");
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

// Times outermost window-procedure calls (posted, or sent by Windows or by
// our own calls such as SetWindowPos) for loop.slow_iter. Nested calls are
// part of the outer one.
static LRESULT CALLBACK ViewerWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (gWndProcDepth > 0) return viewerWndProcImpl(hwnd, msg, wParam, lParam);
    struct Depth {
        Depth() { ++gWndProcDepth; }
        ~Depth() { --gWndProcDepth; }
    } depth;
    const double t0 = steadyMsNow();
    const LRESULT r = viewerWndProcImpl(hwnd, msg, wParam, lParam);
    gIterPump.noteWndProc(msg, steadyMsNow() - t0);
    return r;
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
    RECT r{0, 0, static_cast<LONG>(clientW), static_cast<LONG>(clientH)};
    AdjustWindowRect(&r, style, FALSE);
    HWND hwnd = CreateWindowExW(0, cls, L"JerisLink \u2014 Connecting...",
                                style, CW_USEDEFAULT, CW_USEDEFAULT,
                                r.right - r.left, r.bottom - r.top,
                                nullptr, nullptr, hi, nullptr);
    if (!hwnd) throw std::runtime_error("CreateWindowExW failed");
    // No menu bar and nothing added to the system menu (see kRemovedMenuIdFirst).
    logLine("viewer.menu none");
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

static void logLoopSlowCall(const char* step, UINT msg, double ms) {
    if (!loopSlowShouldLog(ms)) return;
    char buf[160];
    std::snprintf(buf, sizeof(buf), "loop.slow step=%s msg=0x%04x ms=%.1f focused=%d iconic=%d suppressed=%llu",
                  step, msg, ms, gViewerFocused ? 1 : 0,
                  gViewerHwnd && IsIconic(gViewerHwnd) ? 1 : 0,
                  static_cast<unsigned long long>(gLoopSlowSuppressed));
    gLoopSlowSuppressed = 0;
    logLine(buf);
}

// Classifies where an input message came from, for input.slow. Pen and touch
// promoted mouse messages carry the 0xFF5157xx signature in their extra info.
static const char* inputSourceName(UINT msg) {
    if (msg >= WM_MR_WIN_C && msg <= WM_MR_CAPS_LOCK) return "posted";
    const LPARAM extra = GetMessageExtraInfo();
    if ((static_cast<ULONG_PTR>(extra) & 0xFFFFFF00u) == 0xFF515700u) return "pen_touch";
    return "hw";
}

// Splits an input message's age into the part our loop could have caused
// (time since the loop last drained its queue or woke from its wait) and the
// part that happened before the message reached our queue. The queue is
// drained to empty every pump and the wait wakes on QS_ALLINPUT, so a message
// cannot sit with us longer than the time since we were last responsive.
static void noteInputAge(const MSG& m) {
    const DWORD nowTick = GetTickCount();
    const double age = static_cast<double>(static_cast<DWORD>(nowTick - m.time));
    const double now = steadyMsNow();
    const double sinceResponsive = now - gLoopResponsiveMs;
    const jl::InputWaitSplit split = jl::splitInputWait(age, sinceResponsive);
    const float loopMs = static_cast<float>(split.loopMs);
    // Posted before the receive loop started: startup wait, not loop latency.
    const bool startup = !gLoopStarted ||
                         static_cast<LONG>(m.time - gLoopStartTick) < 0;
    if (startup) {
        if (gInputQueueStartupMs.size() < (1u << 12)) gInputQueueStartupMs.push_back(static_cast<float>(age));
        return;
    }
    if (gInputQueueWindowMs.size() < (1u << 16)) gInputQueueWindowMs.push_back(loopMs);
    if (gInputQueueSessionMs.size() < (1u << 20)) gInputQueueSessionMs.push_back(loopMs);
    gInputDeliveryWindowMaxMs = std::max(gInputDeliveryWindowMaxMs, split.deliveryMs);
    gInputDeliverySessionMaxMs = std::max(gInputDeliverySessionMaxMs, split.deliveryMs);
    if (split.deliveryMs > kInputSlowMs) ++gInputDeliveryLateEvents;
    if (age <= kInputSlowMs) return;
    ++gInputSlowEvents;
    if (now - gInputSlowLastLogMs < 1000.0) {
        ++gInputSlowSuppressed;
        return;
    }
    gInputSlowLastLogMs = now;
    char buf[320];
    std::snprintf(buf, sizeof(buf),
                  "input.slow msg=0x%04x src=%s age_ms=%.0f loop_ms=%.1f delivery_ms=%.1f "
                  "since_responsive_ms=%.1f event_tick=%lu now_tick=%lu modal=%d focused=%d iconic=%d "
                  "suppressed=%llu",
                  m.message, inputSourceName(m.message), age, split.loopMs, split.deliveryMs,
                  sinceResponsive, static_cast<unsigned long>(m.time),
                  static_cast<unsigned long>(nowTick), gModal.active() ? 1 : 0,
                  gViewerFocused ? 1 : 0, gViewerHwnd && IsIconic(gViewerHwnd) ? 1 : 0,
                  static_cast<unsigned long long>(gInputSlowSuppressed));
    gInputSlowSuppressed = 0;
    logLine(buf);
}

static void pumpMessages() {
    MSG m{};
    for (;;) {
        // PeekMessage also runs the low-level keyboard hook and sent
        // (cross-thread) messages, so it is timed on its own.
        const double peekStart = steadyMsNow();
        const BOOL got = PeekMessageW(&m, nullptr, 0, 0, PM_REMOVE);
        const double peekMs = steadyMsNow() - peekStart;
        gIterPump.peekMs += peekMs;
        logLoopSlowCall("peek", got ? m.message : 0, peekMs);
        if (!got) {
            gLoopResponsiveMs = steadyMsNow();  // queue drained
            break;
        }
        if (m.message == WM_QUIT) gWindowClosed = true;
        ++gIterPump.msgs;
        const bool input = (m.message >= WM_KEYFIRST && m.message <= WM_KEYLAST) ||
                           (m.message >= WM_MOUSEFIRST && m.message <= WM_MOUSELAST) ||
                           (m.message >= WM_MR_WIN_C && m.message <= WM_MR_CAPS_LOCK);
        if (input) noteInputAge(m);
        // Tab, arrows and Esc for the modeless volume, settings and info windows.
        if (gVolumeDlg && IsDialogMessageW(gVolumeDlg, &m)) continue;
        if (gSettingsDlg && IsDialogMessageW(gSettingsDlg, &m)) continue;
        if (gInfoDlg && IsDialogMessageW(gInfoDlg, &m)) continue;
        const double dispatchStart = steadyMsNow();
        const uint64_t modalEventsBefore = gModal.events();
        TranslateMessage(&m);
        DispatchMessageW(&m);
        const double dispatchMs = steadyMsNow() - dispatchStart;
        gIterPump.dispatchMs += dispatchMs;
        // A dispatch that ran the system modal loop is logged as loop.modal.
        if (gModal.events() == modalEventsBefore)
            logLoopSlowCall("dispatch", m.message, dispatchMs);
    }
}

// Windows 11 may slow a process whose window is in the background
// (EcoQoS) and ignore its 1 ms timer request while the window is occluded.
// The viewer keeps receiving video and NACK timing in the background, so
// opt out of both. Best effort: older Windows lacks the API.
static void optOutOfPowerThrottling() {
    struct ThrottlingState { ULONG Version, ControlMask, StateMask; };
    using SetInfoFn = BOOL(WINAPI*)(HANDLE, int, LPVOID, DWORD);
    const HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    const auto fn = k32 ? reinterpret_cast<SetInfoFn>(GetProcAddress(k32, "SetProcessInformation")) : nullptr;
    if (!fn) {
        logLine("process.power_throttling=unsupported");
        return;
    }
    constexpr int kProcessPowerThrottling = 4;      // PROCESS_INFORMATION_CLASS
    constexpr ULONG kExecutionSpeed = 0x1;           // PROCESS_POWER_THROTTLING_EXECUTION_SPEED
    constexpr ULONG kIgnoreTimerResolution = 0x4;    // PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION
    ThrottlingState st{1, kExecutionSpeed | kIgnoreTimerResolution, 0};  // StateMask 0 = never throttle
    BOOL ok = fn(GetCurrentProcess(), kProcessPowerThrottling, &st, sizeof(st));
    if (!ok) {
        // Windows 10 knows only the execution-speed bit.
        st.ControlMask = kExecutionSpeed;
        ok = fn(GetCurrentProcess(), kProcessPowerThrottling, &st, sizeof(st));
    }
    logLine(std::string("process.power_throttling=opt_out ok=") + (ok ? "1" : "0") +
            " timer_bit=" + (ok && st.ControlMask != kExecutionSpeed ? "1" : "0") +
            (ok ? "" : " error=" + std::to_string(GetLastError())));
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
        {
            // present() runs on the video thread, paintToDc() on the main
            // thread (WM_PAINT): bgra_ and hasFrame_ are shared.
            std::lock_guard<std::mutex> lk(frameMu_);
            if (presented_ == 0) logFirstFrameStats(data, curLen);
            convertNv12ToBgra(data, stride_);
            // The BMP is a picture of the Mac screen: debug mode only.
            if (presented_ == 0 && debugMode()) dumpFirstFrameBmp();
            hasFrame_ = true;
        }
        buffer->Unlock();
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
        std::lock_guard<std::mutex> lk(frameMu_);
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

    // Called on the video thread: only invalidate. The main thread paints on
    // its next message pump (UpdateWindow from here would block this thread
    // on the main thread).
    void drawFrame() {
        InvalidateRect(hwnd_, nullptr, FALSE);
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
    std::mutex frameMu_;  // bgra_ and hasFrame_
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
            // active. Validate WM_PAINT without painting over the swapchain
            // and ask the main loop to present the newest frame again.
            gHardwareRepaintRequested = true;
        } else if (CpuPresenter* cpu = gCpuPresenter.load()) {
            cpu->paintToDc(dc);
        } else {
            RECT r{};
            GetClientRect(hwnd, &r);
#ifdef JERISLINK_UI_SNAPSHOT
            // CI snapshots: coloured bars stand in for video, so the
            // overlay's translucency shows in the PNGs.
            static const COLORREF kBars[] = {RGB(200, 200, 200), RGB(200, 200, 0),
                                             RGB(0, 200, 200),   RGB(0, 200, 0),
                                             RGB(200, 0, 200),   RGB(200, 0, 0),
                                             RGB(0, 0, 200),     RGB(16, 16, 16)};
            const LONG n = static_cast<LONG>(sizeof(kBars) / sizeof(kBars[0]));
            for (LONG i = 0; i < n; ++i) {
                RECT b{r.left + (r.right - r.left) * i / n, r.top,
                       r.left + (r.right - r.left) * (i + 1) / n, r.bottom};
                HBRUSH br = CreateSolidBrush(kBars[i]);
                FillRect(dc, &b, br);
                DeleteObject(br);
            }
#else
            FillRect(dc, &r, static_cast<HBRUSH>(GetStockObject(BLACK_BRUSH)));
#endif
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
                  const std::string& requestedBackend, const std::string& codecName,
                  const std::string& presentMode)
        : hwnd_(hwnd), width_(width), height_(height), fps_(fps),
          requestedBackend_(requestedBackend), codec_(jerisVideoCodecFromString(codecName)) {
        logLine("video.backend.requested=" + requestedBackend_);
        logLine(std::string("video.codec=") + jerisVideoCodecName(codec_));
        if (requestedBackend_ != "cpu") {
            try {
                logLine("gpu.init=attempt");
                hardware_ = std::make_unique<HardwareVideoPipeline>(
                    hwnd_, width_, height_, fps_, codec_,
                    [](const std::string& message) { logLine(message); }, presentMode);
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
                    (activeW != reportedW_ || activeH != reportedH_)) {
                    reportedW_ = activeW;
                    reportedH_ = activeH;
                    {
                        // Applied to gRemoteWidth/Height on the main thread.
                        std::lock_guard<std::mutex> lk(gVideoInfo.mu);
                        gVideoInfo.sizeChanged = true;
                        gVideoInfo.width = activeW;
                        gVideoInfo.height = activeH;
                    }
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

    // Hardware path only (the CPU path paints synchronously). Non-blocking.
    void servicePresent() {
        if (!hardware_) return;
        try {
            hardware_->servicePresent();
        } catch (const std::exception& e) {
            logLine(std::string("gpu.runtime_failure reason=") + e.what());
            fallbackToCpu();
        }
    }
    void repaint() {
        if (!hardware_) return;
        try {
            hardware_->repaint();
        } catch (const std::exception& e) {
            logLine(std::string("gpu.runtime_failure reason=") + e.what());
            fallbackToCpu();
        }
    }
    bool presentPending() const { return hardware_ && hardware_->presentPending(); }
    HANDLE presentWaitHandle() const { return hardware_ ? hardware_->presentWaitHandle() : nullptr; }
    void onPresentWaitSignaled() {
        if (!hardware_) return;
        try {
            hardware_->onPresentWaitSignaled();
        } catch (const std::exception& e) {
            logLine(std::string("gpu.runtime_failure reason=") + e.what());
            fallbackToCpu();
        }
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
    uint64_t busyRetries() const {
        return hardwareRetriesSaved_ + (hardware_ ? hardware_->busyRetries() : 0);
    }
    uint64_t repaints() const {
        return hardwareRepaintsSaved_ + (hardware_ ? hardware_->repaints() : 0);
    }
    uint64_t latencyTimeouts() const {
        return hardwareLatencyTimeoutsSaved_ + (hardware_ ? hardware_->latencyTimeouts() : 0);
    }
    uint64_t hiddenDrops() const {
        return hardwareHiddenDropsSaved_ + (hardware_ ? hardware_->hiddenDrops() : 0);
    }
    uint64_t occludedPresents() const {
        return hardwareOccludedSaved_ + (hardware_ ? hardware_->occludedPresents() : 0);
    }
    uint64_t hiddenPeriods() const {
        return hardwareHiddenPeriodsSaved_ + (hardware_ ? hardware_->hiddenPeriods() : 0);
    }
    UINT maxFrameLatency() const { return hardware_ ? hardware_->maxFrameLatency() : 0; }
    // Worker thread (same thread as servicePresent).
    void takeDisplayLatencyMs(std::vector<float>& out) {
        if (hardware_) hardware_->takeDisplayLatencyMs(out);
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
        hardwareRetriesSaved_ += hardware_->busyRetries();
        hardwareRepaintsSaved_ += hardware_->repaints();
        hardwareLatencyTimeoutsSaved_ += hardware_->latencyTimeouts();
        hardwareHiddenDropsSaved_ += hardware_->hiddenDrops();
        hardwareOccludedSaved_ += hardware_->occludedPresents();
        hardwareHiddenPeriodsSaved_ += hardware_->hiddenPeriods();
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
        {
            // Applied to gConnectionInfo on the main thread.
            std::lock_guard<std::mutex> lk(gVideoInfo.mu);
            gVideoInfo.backendChanged = true;
            gVideoInfo.backend = activeBackend();
            gVideoInfo.decoder = decoderName();
            gVideoInfo.adapter.clear();
        }
        waitingForCpuKeyframe_ = true;
    }

    HWND hwnd_ = nullptr;
    UINT32 width_ = 0;
    UINT32 height_ = 0;
    UINT32 fps_ = 0;
    UINT32 reportedW_ = width_, reportedH_ = height_;  // last size sent to the main thread
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
    uint64_t hardwareRetriesSaved_ = 0;
    uint64_t hardwareRepaintsSaved_ = 0;
    uint64_t hardwareLatencyTimeoutsSaved_ = 0;
    uint64_t hardwareHiddenDropsSaved_ = 0;
    uint64_t hardwareOccludedSaved_ = 0;
    uint64_t hardwareHiddenPeriodsSaved_ = 0;
    uint64_t hardwareNonDxgiSaved_ = 0;
    uint64_t hardwareStreamChangesSaved_ = 0;
    uint64_t hardwareBackpressureSaved_ = 0;
    double hardwarePresentMsSaved_ = 0.0;
    double hardwarePresentMaxSaved_ = 0.0;
};

// The video thread drives the pipeline through this; the main thread reads
// the published counters for the 5 s stats line while the thread runs.
class PipelineSink : public jl::VideoWorkerSink {
public:
    explicit PipelineSink(VideoPipeline& video) : video_(video) {}
    void submit(uint64_t fid, const std::vector<uint8_t>& frame, bool discontinuity, bool keyFrame) override {
        video_.submit(fid, frame, discontinuity, keyFrame);
    }
    void resetForNewStream() override { video_.resetForNewStream(); }
    void repaint() override { video_.repaint(); }
    void servicePresent() override { video_.servicePresent(); }
    bool presentPending() override { return video_.presentPending(); }
    HANDLE presentWaitHandle() override { return video_.presentWaitHandle(); }
    void onPresentWaitSignaled() override { video_.onPresentWaitSignaled(); }
    void finish() override { video_.finish(); }
    void published() override {
        decoded.store(video_.decodedFrames(), std::memory_order_relaxed);
        presented.store(video_.presented(), std::memory_order_relaxed);
        busyDrops.store(video_.busyDrops(), std::memory_order_relaxed);
        busyRetries.store(video_.busyRetries(), std::memory_order_relaxed);
        hiddenDrops.store(video_.hiddenDrops(), std::memory_order_relaxed);
        occludedPresents.store(video_.occludedPresents(), std::memory_order_relaxed);
        scratch_.clear();
        video_.takeDisplayLatencyMs(scratch_);
        if (!scratch_.empty()) {
            std::lock_guard<std::mutex> lk(displayMu_);
            for (float v : scratch_) {
                if (displayLatencyMs_.size() >= (1u << 14)) break;
                displayLatencyMs_.push_back(v);
            }
        }
    }
    // Main thread: present -> vblank samples since the last take.
    void takeDisplayLatencyMs(std::vector<float>& out) {
        std::lock_guard<std::mutex> lk(displayMu_);
        out.insert(out.end(), displayLatencyMs_.begin(), displayLatencyMs_.end());
        displayLatencyMs_.clear();
    }

    std::atomic<uint64_t> decoded{0}, presented{0}, busyDrops{0}, busyRetries{0};
    std::atomic<uint64_t> hiddenDrops{0}, occludedPresents{0};

private:
    VideoPipeline& video_;
    std::vector<float> scratch_;  // worker thread only
    std::mutex displayMu_;
    std::vector<float> displayLatencyMs_;
};

// Main thread: take what the video thread found (decoded size, CPU fallback).
static void applyVideoInfo(HWND hwnd) {
    bool size = false, backend = false;
    UINT32 w = 0, h = 0;
    std::string be, dec, ad;
    {
        std::lock_guard<std::mutex> lk(gVideoInfo.mu);
        if (gVideoInfo.sizeChanged) {
            size = true;
            w = gVideoInfo.width;
            h = gVideoInfo.height;
            gVideoInfo.sizeChanged = false;
        }
        if (gVideoInfo.backendChanged) {
            backend = true;
            be = gVideoInfo.backend;
            dec = gVideoInfo.decoder;
            ad = gVideoInfo.adapter;
            gVideoInfo.backendChanged = false;
        }
    }
    if (size) {
        gRemoteWidth = w;
        gRemoteHeight = h;
        gConnectionInfo.remoteWidth = w;
        gConnectionInfo.remoteHeight = h;
    }
    if (backend) {
        gConnectionInfo.backend = be;
        gConnectionInfo.decoder = dec;
        gConnectionInfo.adapter = ad;
    }
    if (size || backend) updateViewerTitle(hwnd);
}

static std::vector<std::string> commandArgs(int argc, char** argv) {
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) args.emplace_back(argv[i]);
    return args;
}

static jl::LaunchRequest resolveLaunchArgs(const std::vector<std::string>& args) {
    return jl::resolveLaunch(args, loadSavedSettings(), envValue("JERISLINK_SOURCE_IP"),
                             detectBindAddresses());
}

// ---- Launch screen ---------------------------------------------------------
// Shown before every connection (unless --source-ip came on the command
// line) and again after a session ends. Left: brand, theme picker. Right:
// tabs, the Mac's address, Connect, Advanced settings. Nothing here runs
// while video is playing, so the modal dialog cannot stall a session.

static const wchar_t* const kNoTailnetNote =
    L"No Tailscale or Tailcat address on this PC. Connect one, or set this PC's "
    L"address in Advanced settings.";

struct LaunchContext {
    std::wstring note;              // why we are here (shown in the error line)
    std::vector<std::string> args;  // command-line arguments after argv[0]
    bool codeTab = false;
};
static LaunchContext* gLaunch = nullptr;

static RECT dluRect(HWND dlg, int x, int y, int w, int h) {
    RECT r{x, y, x + w, y + h};
    MapDialogRect(dlg, &r);
    return r;
}

static void paintLaunchExtras(HWND dlg, HDC dc, const ThemedDialog& td) {
    const UINT dpi = td.theme.dpi;
    const auto s = [dpi](int v) { return jl::ui::px(dpi, v); };
    const COLORREF accent = jl::ui::accent().accent;
    // App icon above the headline.
    const RECT iconAt = dluRect(dlg, 18, 18, 1, 1);
    const int iconSize = s(40);
    if (HICON icon = static_cast<HICON>(LoadImageW(GetModuleHandleW(nullptr),
                                                   MAKEINTRESOURCEW(IDI_JERISLINK), IMAGE_ICON,
                                                   iconSize, iconSize, LR_DEFAULTCOLOR))) {
        DrawIconEx(dc, iconAt.left, iconAt.top, icon, iconSize, iconSize, 0, nullptr, DI_NORMAL);
        DestroyIcon(icon);
    }
    // Column divider, stopping above the footer band.
    const int footerTop = dialogUnitsY(dlg, td.footerTopDlu);
    const RECT col = dluRect(dlg, 180, 12, 1, 1);
    RECT divider{col.left, col.top, col.left + s(1), footerTop - col.top};
    jl::ui::fillRect(dc, divider, jl::ui::color::kBorder);
    // Tab row: a hairline under both tabs, an accent bar under the active one.
    const RECT host = jl::ui::childRect(dlg, IDC_TAB_HOST);
    const RECT code = jl::ui::childRect(dlg, IDC_TAB_CODE);
    const RECT rightEdge = dluRect(dlg, 446, 0, 1, 1);
    RECT hair{host.left, host.bottom + s(2), rightEdge.left, host.bottom + s(3)};
    jl::ui::fillRect(dc, hair, jl::ui::color::kBorder);
    const RECT& active = gLaunch && gLaunch->codeTab ? code : host;
    RECT bar{active.left, host.bottom + s(1), active.right, host.bottom + s(3)};
    jl::ui::fillRect(dc, bar, accent);
    // Divider above Advanced settings.
    const RECT adv = jl::ui::childRect(dlg, IDC_LAUNCH_ADVANCED);
    const RECT gap = dluRect(dlg, 0, 0, 1, 8);
    RECT advLine{adv.left, adv.top - gap.bottom, adv.right, adv.top - gap.bottom + s(1)};
    jl::ui::fillRect(dc, advLine, jl::ui::color::kBorder);
    // Ready dot next to READY TO CONNECT.
    const RECT ready = jl::ui::childRect(dlg, IDC_LAUNCH_READY);
    const int d = s(7);
    const RECT dotAt = dluRect(dlg, 18, 0, 1, 1);
    const int cy = (ready.top + ready.bottom) / 2;
    RECT dot{dotAt.left, cy - d / 2, dotAt.left + d, cy - d / 2 + d};
    jl::ui::ellipse(dc, dot, accent, accent);
}

static void launchText(HDC dc, const wchar_t* text, RECT r, HFONT font, COLORREF color,
                       UINT format) {
    HGDIOBJ old = SelectObject(dc, font);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, color);
    DrawTextW(dc, text, -1, &r, format | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
    SelectObject(dc, old);
}

// Owner-drawn launch buttons: theme pills, tabs, Advanced and Connect.
static bool drawLaunchButton(HWND dlg, const DRAWITEMSTRUCT& di) {
    const ThemedDialog* td = themedDialog(dlg);
    if (!td || di.CtlType != ODT_BUTTON) return false;
    const auto& t = td->theme;
    const auto s = [&t](int v) { return jl::ui::px(t.dpi, v); };
    const auto& a = jl::ui::accent();
    HDC dc = di.hDC;
    const RECT r = di.rcItem;
    const bool focus = (di.itemState & ODS_FOCUS) && !(di.itemState & ODS_NOFOCUSRECT);
    const bool down = (di.itemState & ODS_SELECTED) != 0;
    const int id = static_cast<int>(di.CtlID);
    wchar_t text[96]{};
    GetWindowTextW(di.hwndItem, text, static_cast<int>(std::size(text)));
    switch (id) {
    case IDC_THEME_GREEN:
    case IDC_THEME_BLUE: {
        jl::ui::fillRect(dc, r, jl::ui::color::kBody);
        const bool blue = id == IDC_THEME_BLUE;
        const bool selected = blue == accentIsBlue();
        jl::ui::roundRect(dc, r, r.bottom - r.top,
                          selected || down ? jl::ui::color::kSecondaryDown
                                           : jl::ui::color::kSecondary,
                          selected ? a.accent : jl::ui::color::kBorder, selected ? s(2) : s(1));
        const int d = s(10);
        const int cy = (r.top + r.bottom) / 2;
        const COLORREF swatch = blue ? jl::ui::kBlueAccent.accent : jl::ui::kGreenAccent.accent;
        RECT sw{r.left + s(10), cy - d / 2, r.left + s(10) + d, cy - d / 2 + d};
        jl::ui::ellipse(dc, sw, swatch, swatch);
        RECT tr = r;
        tr.left = sw.right + s(7);
        launchText(dc, text, tr, selected ? t.label : t.text,
                   selected ? jl::ui::color::kText : jl::ui::color::kMuted, DT_LEFT | DT_VCENTER);
        if (focus) overlayFocusFrame(dc, r, t.dpi);
        return true;
    }
    case IDC_TAB_HOST:
    case IDC_TAB_CODE: {
        jl::ui::fillRect(dc, r, jl::ui::color::kBody);
        const bool active = (id == IDC_TAB_CODE) == (gLaunch && gLaunch->codeTab);
        launchText(dc, text, r, active ? t.label : t.text,
                   active ? jl::ui::color::kText : jl::ui::color::kMuted, DT_LEFT | DT_VCENTER);
        if (focus) {
            RECT f = r;
            f.left -= s(4);
            overlayFocusFrame(dc, f, t.dpi);
        }
        return true;
    }
    case IDC_LAUNCH_ADVANCED: {
        jl::ui::fillRect(dc, r, jl::ui::color::kBody);
        jl::ui::roundRect(dc, r, s(8),
                          down ? jl::ui::color::kSecondaryDown : jl::ui::color::kSecondary,
                          focus ? a.focusRing : jl::ui::color::kBorder, focus ? s(2) : s(1));
        const int mid = (r.top + r.bottom) / 2;
        RECT title{r.left + s(12), r.top, r.right - s(30), mid};
        launchText(dc, L"Advanced settings", title, t.label, jl::ui::color::kText,
                   DT_LEFT | DT_BOTTOM);
        RECT sub{r.left + s(12), mid + s(1), r.right - s(30), r.bottom};
        launchText(dc, L"Bandwidth, codec, this PC's address", sub, t.smallText,
                   jl::ui::color::kMuted, DT_LEFT | DT_TOP);
        RECT chevron{r.right - s(30), r.top, r.right - s(8), r.bottom};
        launchText(dc, L"\u203a", chevron, t.title, jl::ui::color::kMuted,
                   DT_CENTER | DT_VCENTER);
        return true;
    }
    case IDOK:
        if (IsWindowEnabled(di.hwndItem)) {
            jl::ui::drawButton(di, t, true, jl::ui::color::kBody);
        } else {
            jl::ui::fillRect(dc, r, jl::ui::color::kBody);
            jl::ui::roundRect(dc, r, s(8), jl::ui::color::kSecondary, jl::ui::color::kBorder,
                              s(1));
            launchText(dc, text, r, t.label, jl::ui::color::kDisabled, DT_CENTER | DT_VCENTER);
        }
        return true;
    default:
        return false;
    }
}

static void launchSetError(HWND dlg, const std::wstring& text) {
    SetDlgItemTextW(dlg, IDC_LAUNCH_ERROR, text.c_str());
    InvalidateRect(GetDlgItem(dlg, IDC_LAUNCH_ERROR), nullptr, TRUE);
}

// Host tab: address, hint, error line and Connect. Code tab: a note only
// (pairing codes are reserved for jerispair, not built yet).
static void launchSetTab(HWND dlg, bool code) {
    if (gLaunch) gLaunch->codeTab = code;
    for (int id : {IDC_UI_LABEL_HOST, IDC_HOST_IP, IDC_UI_HINT_HOST, IDC_LAUNCH_ERROR}) {
        ShowWindow(GetDlgItem(dlg, id), code ? SW_HIDE : SW_SHOW);
    }
    ShowWindow(GetDlgItem(dlg, IDC_LAUNCH_CODE_NOTE), code ? SW_SHOW : SW_HIDE);
    EnableWindow(GetDlgItem(dlg, IDOK), code ? FALSE : TRUE);
    InvalidateRect(dlg, nullptr, TRUE);
}

static std::string launchHostText(HWND dlg) {
    std::string host = asciiFromWide(windowText(GetDlgItem(dlg, IDC_HOST_IP)));
    const auto first = host.find_first_not_of(" \t");
    if (first == std::string::npos) return {};
    const auto last = host.find_last_not_of(" \t");
    return host.substr(first, last - first + 1);
}

static void launchConnect(HWND dlg) {
    if (gLaunch && gLaunch->codeTab) return;
    HWND edit = GetDlgItem(dlg, IDC_HOST_IP);
    const std::string host = launchHostText(dlg);
    if (!jl::isIPv4(host)) {
        launchSetError(dlg, L"Enter the Mac's IPv4 address, e.g. 100.64.0.10.");
        SetFocus(edit);
        return;
    }
    auto saved = loadSavedSettings();
    saved.hostIp = host;
    if (!saveSettings(saved)) {
        launchSetError(dlg, L"Could not save the address.");
        return;
    }
    const std::vector<std::string> none;
    const auto request = resolveLaunchArgs(jl::argsAfterLaunchScreen(gLaunch ? gLaunch->args : none));
    if (request.status == jl::LaunchStatus::NoTailnet) {
        logLine("launch.connect_blocked reason=no-tailnet bind_reason=" + request.bindReason);
        launchSetError(dlg, kNoTailnetNote);
        return;
    }
    if (request.status != jl::LaunchStatus::Ok) {
        logLine("launch.connect_blocked status=" + std::to_string(static_cast<int>(request.status)));
        launchSetError(dlg, L"JerisLink cannot start this connection. Check Advanced settings.");
        return;
    }
    logLine("launch.connect host_source=" + request.hostSource +
            " bind_source=" + request.bindSource);
    EndDialog(dlg, IDOK);
}

static INT_PTR CALLBACK LaunchDlgProc(HWND dlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_DRAWITEM &&
        drawLaunchButton(dlg, *reinterpret_cast<const DRAWITEMSTRUCT*>(lParam))) {
        return TRUE;
    }
    INT_PTR themed = 0;
    if (handleThemedDialogMessage(dlg, msg, wParam, lParam, themed)) return themed;
    switch (msg) {
    case WM_INITDIALOG: {
        gLaunch = reinterpret_cast<LaunchContext*>(lParam);
        initThemedDialog(dlg, 15, kLaunchFooterTop);
        if (ThemedDialog* td = themedDialog(dlg)) td->extraPaint = paintLaunchExtras;
        SetDlgItemTextW(dlg, IDC_LAUNCH_HERO, L"Your Mac,\r\nwithin reach.");
        SetDlgItemTextW(dlg, IDOK, L"Connect to Mac  \u2192");
        HINSTANCE inst = GetModuleHandleW(nullptr);
        SendMessageW(dlg, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(LoadImageW(
            inst, MAKEINTRESOURCEW(IDI_JERISLINK), IMAGE_ICON, GetSystemMetrics(SM_CXICON),
            GetSystemMetrics(SM_CYICON), LR_SHARED)));
        SendMessageW(dlg, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(LoadImageW(
            inst, MAKEINTRESOURCEW(IDI_JERISLINK), IMAGE_ICON, GetSystemMetrics(SM_CXSMICON),
            GetSystemMetrics(SM_CYSMICON), LR_SHARED)));
        HWND edit = GetDlgItem(dlg, IDC_HOST_IP);
        SendMessageW(edit, EM_LIMITTEXT, 15, 0);
        const std::string savedHost = loadSavedSettings().hostIp;
        SetWindowTextW(edit, wideFromAscii(savedHost).c_str());
        launchSetError(dlg, gLaunch ? gLaunch->note : std::wstring());
        launchSetTab(dlg, gLaunch && gLaunch->codeTab);
        SendMessageW(dlg, DM_SETDEFID, IDOK, 0);
        SetFocus(savedHost.empty() ? edit : GetDlgItem(dlg, IDOK));
        logLine(std::string("launch.screen shown saved_host=") + (savedHost.empty() ? "no" : "yes") +
                " note=" + (gLaunch && !gLaunch->note.empty() ? "yes" : "no"));
        return FALSE;  // focus set above
    }
    case WM_COMMAND: {
        const int id = LOWORD(wParam);
        const WORD code = HIWORD(wParam);
        switch (id) {
        case IDC_TAB_HOST:
        case IDC_TAB_CODE:
            if (code == BN_CLICKED) {
                launchSetTab(dlg, id == IDC_TAB_CODE);
                logLine(std::string("launch.tab=") + (id == IDC_TAB_CODE ? "code" : "host"));
            }
            return TRUE;
        case IDC_THEME_GREEN:
        case IDC_THEME_BLUE:
            if (code == BN_CLICKED) {
                const bool blue = id == IDC_THEME_BLUE;
                if (blue != accentIsBlue()) saveUiAccent(blue);
                RedrawWindow(dlg, nullptr, nullptr,
                             RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_UPDATENOW);
            }
            return TRUE;
        case IDC_LAUNCH_ADVANCED:
            if (code == BN_CLICKED &&
                runSettingsDialog(dlg, kSettingsDialogConnect) == IDOK) {
                SetDlgItemTextW(dlg, IDC_HOST_IP,
                                wideFromAscii(loadSavedSettings().hostIp).c_str());
                launchSetError(dlg, L"");
            }
            return TRUE;
        case IDC_HOST_IP:
            if (code == EN_CHANGE) launchSetError(dlg, L"");
            return FALSE;
        case IDOK:
            launchConnect(dlg);
            return TRUE;
        case IDCANCEL:
            EndDialog(dlg, IDCANCEL);
            return TRUE;
        default:
            break;
        }
        break;
    }
    case WM_CLOSE:
        EndDialog(dlg, IDCANCEL);
        return TRUE;
    default:
        break;
    }
    return FALSE;
}

static INT_PTR runLaunchScreen(LaunchContext& ctx) {
    ensureCommonControls();
    const INT_PTR result = DialogBoxParamW(GetModuleHandleW(nullptr),
                                           MAKEINTRESOURCEW(IDD_LAUNCH), nullptr, LaunchDlgProc,
                                           reinterpret_cast<LPARAM>(&ctx));
    gLaunch = nullptr;
    if (result == -1) {
        logLine("launch.dialog_create_failed error=" + std::to_string(GetLastError()));
    }
    return result;
}

static int appMain(int argc, char** argv) {
    gLog.start(kLogPath, kHistoryLogPath);
    logLine(std::string("viewer.start pid=") + std::to_string(GetCurrentProcessId()));
    loadUiAccent();
    const std::vector<std::string> args = commandArgs(argc, argv);
    auto request = resolveLaunchArgs(args);

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

    // The launch screen, unless the Mac's address came on the command line.
    // A session that ended (Disconnect, lost stream, error) restarts the
    // process with --settings and the reason in JERISLINK_LAUNCH_NOTE.
    LaunchContext launch;
    launch.args = args;
    {
        wchar_t note[1024]{};
        const DWORD len = GetEnvironmentVariableW(L"JERISLINK_LAUNCH_NOTE", note,
                                                  static_cast<DWORD>(std::size(note)));
        if (len > 0 && len < std::size(note)) launch.note = note;
        SetEnvironmentVariableW(L"JERISLINK_LAUNCH_NOTE", nullptr);
    }
    const bool shiftHeld = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
    bool show = jl::showLaunchScreen(request, shiftHeld);
    if (show) {
        logLine(std::string("launch.screen reason=") +
                (request.openSettings ? "flag" : shiftHeld ? "shift" : "default"));
    }
    for (;;) {
        if (show) {
            if (runLaunchScreen(launch) != IDOK) {
                logLine("launch.screen closed");
                return 0;
            }
            request = resolveLaunchArgs(jl::argsAfterLaunchScreen(args));
        }
        if (request.status == jl::LaunchStatus::Ok) break;
        if (request.status == jl::LaunchStatus::NoTailnet) {
            logLine("launch.blocked reason=no-tailnet bind_reason=" + request.bindReason);
            launch.note = kNoTailnetNote;
        } else {
            logLine("launch.blocked reason=no-host");
            launch.note = L"Enter the Mac's address to connect.";
        }
        show = true;
    }
    logLine("launch.config host=" + request.options.sourceIp +
            " host_source=" + request.hostSource +
            " bind=" + request.options.bindIp +
            " bind_source=" + request.bindSource +
            " bind_reason=" + request.bindReason);
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
    bool hostSupportsAbr = false;
    bool hostSupportsAudio = false;
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
        // Declared after mouseMoveUdp so it is destroyed (threads joined) first.
        std::unique_ptr<jl::audio::AudioPlayer> audio;
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
                    o.codec, h264Supported, hevcSupported, o.bitrateMbps, o.audio == "on");
                if (videoConfig.negotiated) {
                    effectiveCodec = videoConfig.codec;
                    hostSupportsNack = videoConfig.hostSupportsNack;
                    hostSupportsAbr = videoConfig.hostSupportsAbr;
                    hostSupportsAudio = videoConfig.hostSupportsAudio;
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
                        << " host_abr=" << (videoConfig.hostSupportsAbr ? "yes" : "no")
                        << " host_audio=" << (videoConfig.hostSupportsAudio ? "yes" : "no")
                        << " remote_size=" << videoConfig.remoteWidth << "x"
                        << videoConfig.remoteHeight;
                    logLine(cfg.str());
                    if (effectiveCodec == "hevc" && !o.widthExplicit &&
                        (videoConfig.remoteWidth == 0 || videoConfig.remoteHeight == 0)) {
                        logLine("video.hevc_remote_size_missing; requesting h264 fallback");
                        const auto fallbackConfig = control->negotiateVideo(
                            "h264", true, hevcSupported, o.bitrateMbps, o.audio == "on");
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
        logLine("present.mode=" + o.presentMode);
        std::unique_ptr<VideoPipeline> video;
        try {
            video = std::make_unique<VideoPipeline>(
                hwnd, o.width, o.height, o.fps, o.videoBackend, effectiveCodec, o.presentMode);
        } catch (const std::exception& e) {
            if (effectiveCodec != "hevc" || !control) throw;
            logLine(std::string("video.hevc_init_failed reason=") + e.what());
            logLine("video.fallback_request=h264");
            const auto fallbackConfig = control->negotiateVideo(
                "h264", true, hevcSupported, o.bitrateMbps, o.audio == "on");
            if (!fallbackConfig.negotiated || fallbackConfig.codec != "h264") {
                throw;
            }
            effectiveCodec = "h264";
            effectiveBitrateMbps = fallbackConfig.bitrateMbps;
            logLine("video.fallback_selected codec=h264 bitrate_mbps=" +
                    std::to_string(effectiveBitrateMbps));
            video = std::make_unique<VideoPipeline>(
                hwnd, o.width, o.height, o.fps, o.videoBackend, effectiveCodec, o.presentMode);
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
        // ABR: the host only adapts when it set ACK flag 0x40 and gets 0x42 reports.
        const bool abrEnabled = o.abr == "on" && hostSupportsAbr && mouseMoveUdp;
        logLine(std::string("abr=") + (abrEnabled ? "on" : "off") +
                " requested=" + o.abr +
                " host_abr=" + (hostSupportsAbr ? "yes" : "no"));
        // Audio: the host said it can (ACK flag 0x80) and the MRM1 channel is
        // up. The player has its own socket and threads; the loop below only
        // repeats the MRM1 0x45 request naming that socket's port every second.
        if (o.audio == "on" && hostSupportsAudio && mouseMoveUdp) {
            audio = std::make_unique<jl::audio::AudioPlayer>([](const std::string& m) { logLine(m); });
            std::string audioErr;
            if (audio->start(o.bindIp, o.sourceIp, audioErr)) {
                audio->setMuted(gAudioMuted);
                ensureAudioVolumeLoaded();
                audio->setVolumePercent(gAudioVolumePct);
                gAudio = audio.get();
                mouseMoveUdp->sendAudioRequest(true, audio->port());
            } else {
                logLine("audio.start_failed reason=" + audioErr);
                audio.reset();
            }
        }
        logLine(std::string("audio=") + (audio ? "on" : "off") +
                " requested=" + o.audio +
                " host_audio=" + (hostSupportsAudio ? "yes" : "no") +
                " port=" + std::to_string(audio ? audio->port() : 0) +
                " muted=" + (gAudioMuted ? "yes" : "no") +
                " volume=" + std::to_string(gAudioVolumePct));
        if (nackEnabled || abrEnabled) {
            // Wake up often enough for the 2 ms reorder grace and 40 ms hold.
            DWORD nackTimeout = 5;
            setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&nackTimeout), sizeof(nackTimeout));
        }
        // The loop waits on the socket, window messages, the MRM1 socket
        // (pongs, cursor shapes) and (while a decoded frame waits for a free
        // back buffer) the swap chain latency object, so a pending frame is
        // presented as soon as the display frees a buffer instead of after
        // the next packet or receive timeout.
        // WSAEventSelect makes the socket non-blocking.
        const DWORD loopWaitMs = (nackEnabled || abrEnabled) ? 5 : 16;
        WSAEVENT socketEvent = WSACreateEvent();
        if (socketEvent == WSA_INVALID_EVENT || WSAEventSelect(s, socketEvent, FD_READ) != 0) {
            if (socketEvent != WSA_INVALID_EVENT) WSACloseEvent(socketEvent);
            closesocket(s);
            throw std::runtime_error("WSAEventSelect failed");
        }
        // 1 ms timer while streaming, so the 1 ms / 5 ms waits below really
        // last 1 ms / 5 ms instead of a default ~15.6 ms tick. Released when
        // this scope ends.
        const jl::ScopedTimerResolution timerPeriod(1);
        logLine(std::string("timer.period_ms=1 active=") + (timerPeriod.active() ? "yes" : "no") +
                " mrm1_wait=" + (mouseMoveUdp && mouseMoveUdp->readEvent() ? "yes" : "no"));
        optOutOfPowerThrottling();

        uint64_t rejected = 0;
        std::vector<float> decodeMs;           // per submitted frame, whole session (capped)
        std::vector<float> decodeWindowMs;     // last 5 s, for the periodic stats line
        std::vector<float> queueWaitMs;        // frame queued -> decode starts, session (capped)
        std::vector<float> queueWaitWindowMs;
        std::vector<float> loopBusyWindowMs;   // main loop work per iteration (not its wait)
        // Busy max and stalls exclude time inside Windows modal loops
        // (caption buttons, move/size, menus), logged as loop.modal.
        jl::LoopStallCounter loopStalls;
        // loop.slow_iter: own time >= 16 ms, one line per second below 100 ms.
        jl::SlowIterLimiter slowIterLog(16.0, 100.0, 1000.0);
        std::vector<float> displayLatencyWindowMs;   // present -> vblank, last 5 s
        std::vector<float> displayLatencyMs;         // whole session (capped)
        constexpr size_t kMaxDecodeSamples = 1u << 20;
        const auto takeVideoSamples = [&](jl::VideoWorker& w) {
            const size_t d0 = decodeWindowMs.size(), q0 = queueWaitWindowMs.size();
            w.takeSamples(decodeWindowMs, queueWaitWindowMs);
            for (size_t i = d0; i < decodeWindowMs.size() && decodeMs.size() < kMaxDecodeSamples; ++i)
                decodeMs.push_back(decodeWindowMs[i]);
            for (size_t i = q0; i < queueWaitWindowMs.size() && queueWaitMs.size() < kMaxDecodeSamples; ++i)
                queueWaitMs.push_back(queueWaitWindowMs[i]);
        };

        // Decode and present run on their own thread from here on: the
        // pipeline is only touched by that thread until stopAndWait().
        PipelineSink videoSink(*video);
        videoSink.published();
        jl::VideoWorker videoWorker(videoSink, jl::VideoWorkerConfig{},
            [] { if (gMouseMoveUdp) gMouseMoveUdp->requestKeyframe(); },
            [](const std::string& line) { logLine(line); });
        videoWorker.start();
        logLine("video.thread=started");

        jl::ReceiverConfig rcfg;
        rcfg.strict = strictLossRecovery;
        rcfg.nack = nackEnabled;
        if (gConnectionInfo.rttMs > 0) rcfg.defaultRttMs = gConnectionInfo.rttMs;
        jl::ReceiverHooks hooks;
        hooks.submit = [&](uint64_t fid, const std::vector<uint8_t>& frame, bool discontinuity, bool keyFrame) {
            videoWorker.pushFrame(fid, frame, discontinuity, keyFrame);
        };
        hooks.resetForNewStream = [&] { videoWorker.pushReset(); };
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
        auto lastAudioRequest = start;
        auto lastAudioStats = start;
        uint64_t lastAudioPayloadBytes = 0;
        auto lastStats = start;
        bool gotAny = false;
        const auto msSince = [&start](std::chrono::steady_clock::time_point t) {
            return std::chrono::duration<double, std::milli>(t - start).count();
        };
        jl::PresentedFpsSampler presentedFps;
        // Present counters at the previous stats line (window deltas).
        uint64_t prevDecoded = 0, prevPresented = 0, prevBusyDrops = 0, prevBusyRetries = 0;
        uint64_t prevHiddenDrops = 0, prevOccluded = 0;
        bool loggedStartupInput = false;
        auto firstPacket = start;
        // Receiver loss counters at the previous stats line (window deltas).
        uint64_t prevLossExpected = 0, prevLossRaw = 0, prevLossAfter = 0;
        // ABR: arrival-delay slope and the loss deltas of each 250 ms report.
        jl::ArrivalSlope arrivalSlope(o.fps > 0 ? 1000.0 / o.fps : 1000.0 / 60);
        auto lastReport = start;
        uint64_t repLossExpected = 0, repLossRaw = 0, repLossAfter = 0;
        double lastSlopeMs = 0.0;

        // Main loop work per iteration, up to its wait or its next packet
        // (a stall here delays input).
        auto iterStart = std::chrono::steady_clock::now();
        // Where a long iteration went (logged as loop.slow_iter): each phase
        // runs from the previous mark to markPhase().
        jl::IterPhases iterPhases;
        double phaseMarkMs = 0.0;
        const auto markPhase = [&](jl::IterPhase p) {
            const double t = steadyMsNow();
            iterPhases.add(p, t - phaseMarkMs);
            phaseMarkMs = t;
        };
        const auto noteLoopBusy = [&](std::chrono::steady_clock::time_point end) {
            const double busy = std::chrono::duration<double, std::milli>(end - iterStart).count();
            const double modalMs = gModal.takeIterMs();
            const double own = loopStalls.note(busy, modalMs);
            if (loopBusyWindowMs.size() < (1u << 16)) loopBusyWindowMs.push_back(static_cast<float>(own));
            if (slowIterLog.shouldLog(own, steadyMsNow())) {
                using P = jl::IterPhase;
                const jl::PumpDetail& pd = gIterPump;
                double suppressedMaxMs = 0.0;
                const uint64_t suppressed = slowIterLog.takePending(suppressedMaxMs);
                char lb[640];
                std::snprintf(lb, sizeof(lb),
                              "loop.slow_iter ms=%.1f busy_ms=%.1f modal_ms=%.1f top=%s"
                              " pre_ms=%.1f pump_ms=%.1f video_info_ms=%.1f net_tx_ms=%.1f stats_ms=%.1f"
                              " recv_ms=%.1f packet_ms=%.1f other_ms=%.1f"
                              " peek_ms=%.1f dispatch_ms=%.1f msgs=%u hook_ms=%.1f hook_calls=%u"
                              " wndproc_ms=%.1f wndproc_calls=%u slow_msg=0x%04x slow_msg_ms=%.1f"
                              " focused=%d iconic=%d suppressed=%llu suppressed_max_ms=%.1f",
                              own, busy, modalMs, iterPhases.topName(busy),
                              iterPhases.get(P::Pre), iterPhases.get(P::Pump), iterPhases.get(P::VideoInfo),
                              iterPhases.get(P::NetTx), iterPhases.get(P::Stats), iterPhases.get(P::Recv),
                              iterPhases.get(P::Packet), iterPhases.other(busy),
                              pd.peekMs, pd.dispatchMs, static_cast<unsigned>(pd.msgs), pd.hookMs,
                              static_cast<unsigned>(pd.hookCalls), pd.wndprocMs,
                              static_cast<unsigned>(pd.wndprocCalls), static_cast<unsigned>(pd.slowMsg),
                              pd.slowMsgMs, gViewerFocused ? 1 : 0, IsIconic(hwnd) ? 1 : 0,
                              static_cast<unsigned long long>(suppressed), suppressedMaxMs);
                logLine(lb);
            }
        };
        // Keep-alives and packet handling, shared by the main loop and the
        // session timer that runs while Windows holds a modal loop.
        auto sendKeepAlives = [&](std::chrono::steady_clock::time_point now) {
            if (hostSupportsNack && mouseMoveUdp && now - lastPing >= std::chrono::seconds(1)) {
                mouseMoveUdp->sendPing();
                lastPing = now;
            }
            if (audio && now - lastAudioRequest >= std::chrono::seconds(1)) {
                // Keep-alive: the host stops capturing 3 s after the last request.
                mouseMoveUdp->sendAudioRequest(true, audio->port());
                lastAudioRequest = now;
            }
        };
        // Returns false for a datagram from another address (dropped).
        auto onDatagram = [&](int n, const sockaddr_in& peer,
                              std::chrono::steady_clock::time_point now) {
            const auto packetGapMs = gotAny
                ? std::chrono::duration_cast<std::chrono::milliseconds>(now - lastPacket).count()
                : 0;
            if (!gotAny) firstPacket = now;
            gotAny = true;
            lastPacket = now;
            if (peer.sin_addr.s_addr != allowed.s_addr) {
                ++rejected;
                return false;
            }
            if (abrEnabled && n >= 20 && std::memcmp(buf.data(), "MR02", 4) == 0) {
                arrivalSlope.onPacket(jl::receiverBe64(buf.data() + 6), (buf[5] & 0x04) != 0, msSince(now));
            }
            receiver.onPacket(buf.data(), static_cast<size_t>(n), msSince(now), packetGapMs);
            receiver.tick(msSince(now));
            return true;
        };
        gSessionModalTick = [&] {
            sendKeepAlives(std::chrono::steady_clock::now());
            for (int i = 0; i < 512; ++i) {
                sockaddr_in peer{};
                int plen = sizeof(peer);
                const int n = recvfrom(s, reinterpret_cast<char*>(buf.data()),
                                       static_cast<int>(buf.size()), 0,
                                       reinterpret_cast<sockaddr*>(&peer), &plen);
                if (n == SOCKET_ERROR) break;
                onDatagram(n, peer, std::chrono::steady_clock::now());
            }
            receiver.tick(msSince(std::chrono::steady_clock::now()));
        };
        // Clears the tick (it refers to this scope), the timers and the
        // overlay on every way out of the session, exceptions included.
        struct SessionTickGuard {
            ~SessionTickGuard() {
                gSessionModalTick = nullptr;
                if (gViewerHwnd) {
                    KillTimer(gViewerHwnd, kSessionTickTimer);
                    KillTimer(gViewerHwnd, kOverlayHoverTimer);
                }
                overlayDestroy();
            }
        } sessionTickGuard;
        gMainLoopRecvMs = steadyMsNow();
        SetTimer(hwnd, kSessionTickTimer, kSessionTickMs, nullptr);
        SetTimer(hwnd, kOverlayHoverTimer, kOverlayHoverMs, nullptr);
        gSessionHostLabel = o.sourceIp;
        overlayCreate(hwnd);
        overlayShow(false, "session-start", 4000);

        gLoopStartTick = GetTickCount();
        gLoopStarted = true;
        gLoopResponsiveMs = steadyMsNow();
        gModal.takeIterMs();
        gModal.takeWindowMs();
        while (!gWindowClosed) {
            iterStart = std::chrono::steady_clock::now();
            phaseMarkMs = steadyMsNow();
            iterPhases.reset();
            gIterPump.reset();
            if (videoWorker.failed()) throw std::runtime_error(videoWorker.error());
            if (mouseMoveUdp) {
                uint8_t cursorShape = gRemoteCursorShape;
                if (mouseMoveUdp->pollCursorShape(cursorShape)) {
                    applyRemoteCursorShape(hwnd, cursorShape);
                }
                if (mouseMoveUdp->pongRx() > 0) receiver.setRttMs(mouseMoveUdp->rttMs());
            }
            markPhase(jl::IterPhase::Pre);
            pumpMessages();
            markPhase(jl::IterPhase::Pump);
            if (gWindowClosed) break;
            if (gHardwareRepaintRequested) {
                gHardwareRepaintRequested = false;
                videoWorker.requestRepaint();
            }
            applyVideoInfo(hwnd);
            markPhase(jl::IterPhase::VideoInfo);

            auto now = std::chrono::steady_clock::now();
            presentedFps.update(msSince(now), videoSink.presented.load());
            sendKeepAlives(now);
            if (audio && now - lastAudioStats >= std::chrono::seconds(10)) {
                const auto a = audio->stats();
                const double statsSec = std::chrono::duration<double>(now - lastAudioStats).count();
                const double kbps = lastAudioPayloadBytes <= a.jb.payloadBytes && statsSec > 0
                    ? double(a.jb.payloadBytes - lastAudioPayloadBytes) * 8.0 / 1000.0 / statsSec : 0.0;
                lastAudioPayloadBytes = a.jb.payloadBytes;
                std::ostringstream as;
                as << std::fixed << std::setprecision(1)
                   << "audio.stats codec=" << jl::audio::codecName(a.jb.codec) << " bitrate_kbps=" << kbps
                   << " rx=" << a.jb.packetsRx << " lost=" << a.jb.lost
                   << " fec_recovered=" << a.jb.fecRecovered << " plc_frames=" << a.jb.plcFrames
                   << " drift_inserted=" << a.jb.driftInserted << " drift_dropped=" << a.jb.driftDropped
                   << " decode_errors=" << a.jb.decodeErrors
                   << " late=" << a.jb.late << " underruns=" << a.jb.underruns
                   << " overflow_drops=" << a.jb.overflowDrops << " idle_drops=" << a.jb.idleDrops
                   << " target_ms=" << a.jb.targetMs
                   << " jitter_ms=" << a.jb.jitterMs << " buffered_ms=" << a.jb.bufferedMs
                   << " latency_ms=" << a.outputLatencyMs()
                   << " device_ok=" << (a.deviceOk ? "yes" : "no") << " device_errors=" << a.deviceErrors
                   << " device_reopens=" << a.deviceReopens << " device_notify=" << (a.deviceNotify ? "on" : "off")
                   << " device_notifications=" << a.deviceNotifications
                   << " last_reopen=\"" << a.lastReopenReason << "\""
                   << " muted=" << (a.muted ? "yes" : "no")
                   << " volume=" << a.volumePercent
                   << " session_volume=" << (a.sessionVolume ? "yes" : "no");
                logLine(as.str());
                lastAudioStats = now;
            }
            if (abrEnabled && now - lastReport >= std::chrono::milliseconds(250)) {
                const auto& st = receiver.stats();
                const auto w = arrivalSlope.take();
                jl::ReceiverReport r;
                r.slopeValid = w.valid;
                r.slope01Ms = w.valid ? jl::abrSlopeTo01Ms(w.slopeMs) : 0;
                if (w.valid) lastSlopeMs = w.slopeMs;
                r.windowMs = uint16_t(std::min<long long>(65535,
                    std::chrono::duration_cast<std::chrono::milliseconds>(now - lastReport).count()));
                const auto clamp32 = [](uint64_t v) { return uint32_t(std::min<uint64_t>(v, 0xFFFFFFFFull)); };
                r.expected = clamp32(st.lossExpected - repLossExpected);
                r.lostRaw = clamp32(st.lossRaw - repLossRaw);
                r.lostAfterNack = clamp32(st.lossAfterNack - repLossAfter);
                r.rttMs = uint16_t(std::min(65535.0, mouseMoveUdp->rttMs() + 0.5));
                mouseMoveUdp->sendReceiverReport(r);
                repLossExpected = st.lossExpected;
                repLossRaw = st.lossRaw;
                repLossAfter = st.lossAfterNack;
                lastReport = now;
            }
            markPhase(jl::IterPhase::NetTx);
            if (now - lastStats >= std::chrono::seconds(5)) {
                const auto& st = receiver.stats();
                const jl::ReceiverLoss wloss = jl::receiverLoss(st.lossExpected - prevLossExpected,
                                                                st.lossRaw - prevLossRaw,
                                                                st.lossAfterNack - prevLossAfter);
                const double windowSec = std::max(0.001,
                    std::chrono::duration<double>(now - lastStats).count());
                takeVideoSamples(videoWorker);
                const uint64_t decodedNow = videoSink.decoded.load();
                const uint64_t presentedNow = videoSink.presented.load();
                const uint64_t busyDropsNow = videoSink.busyDrops.load();
                const uint64_t busyRetriesNow = videoSink.busyRetries.load();
                const uint64_t hiddenDropsNow = videoSink.hiddenDrops.load();
                const uint64_t occludedNow = videoSink.occludedPresents.load();
                {
                    const size_t d0 = displayLatencyWindowMs.size();
                    videoSink.takeDisplayLatencyMs(displayLatencyWindowMs);
                    for (size_t i = d0; i < displayLatencyWindowMs.size() && displayLatencyMs.size() < kMaxDecodeSamples; ++i)
                        displayLatencyMs.push_back(displayLatencyWindowMs[i]);
                }
                if (!loggedStartupInput && !gInputQueueStartupMs.empty()) {
                    loggedStartupInput = true;
                    std::ostringstream su;
                    su << std::fixed << std::setprecision(1)
                       << "input.startup_queued events=" << gInputQueueStartupMs.size()
                       << " max_ms=" << jl::receiverPercentile(gInputQueueStartupMs, 100)
                       << " note=queued_before_receive_loop";
                    logLine(su.str());
                }
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
                     << " decoded_fps=" << static_cast<double>(decodedNow - prevDecoded) / windowSec
                     << " presented_fps=" << static_cast<double>(presentedNow - prevPresented) / windowSec
                     << " present_busy_drops=" << (busyDropsNow - prevBusyDrops)
                     << " present_busy_retries=" << (busyRetriesNow - prevBusyRetries)
                     << " present_hidden_drops=" << (hiddenDropsNow - prevHiddenDrops)
                     << " present_occluded=" << (occludedNow - prevOccluded)
                     << " present_to_vblank_ms_p50=" << jl::receiverPercentile(displayLatencyWindowMs, 50)
                     << " present_to_vblank_ms_p95=" << jl::receiverPercentile(displayLatencyWindowMs, 95)
                     << " present_to_vblank_ms_max=" << jl::receiverPercentile(displayLatencyWindowMs, 100)
                     << " present_to_vblank_samples=" << displayLatencyWindowMs.size()
                     << " focused=" << (gViewerFocused ? 1 : 0)
                     << " nack_tx=" << st.nackTx
                     << " frames_repaired=" << st.framesRepaired
                     << " nack_deadline_miss=" << st.nackDeadlineMiss
                     << " strict_recovery_events=" << st.strictRecoveryEvents
                     << " nack_paused_rtt=" << st.nackPausedRtt
                     << std::setprecision(3)
                     << " loss_raw_pct=" << wloss.rawPct
                     << " loss_after_nack_pct=" << wloss.afterNackPct
                     << " held_frames=" << receiver.heldFrames()
                     << " abr_reports_tx=" << (mouseMoveUdp ? mouseMoveUdp->reportSent() : 0)
                     << " delay_slope_ms=" << lastSlopeMs
                     << std::setprecision(1)
                     << " video_queue_max=" << videoWorker.takeWindowMaxDepth()
                     << " video_queue_wait_ms_p95=" << jl::receiverPercentile(queueWaitWindowMs, 95)
                     << " video_queue_wait_ms_max=" << jl::receiverPercentile(queueWaitWindowMs, 100)
                     << " loop_busy_ms_p99=" << jl::receiverPercentile(loopBusyWindowMs, 99)
                     << " loop_busy_ms_max=" << jl::receiverPercentile(loopBusyWindowMs, 100)
                     << " input_queue_ms_p50=" << jl::receiverPercentile(gInputQueueWindowMs, 50)
                     << " input_queue_ms_p99=" << jl::receiverPercentile(gInputQueueWindowMs, 99)
                     << " input_queue_ms_max=" << jl::receiverPercentile(gInputQueueWindowMs, 100)
                     << " input_events=" << gInputQueueWindowMs.size()
                     << " input_delivery_ms_max=" << gInputDeliveryWindowMaxMs
                     << " loop_modal_ms=" << gModal.takeWindowMs();
                logLine(line.str());
                gInputDeliveryWindowMaxMs = 0.0;
                decodeWindowMs.clear();
                queueWaitWindowMs.clear();
                loopBusyWindowMs.clear();
                gInputQueueWindowMs.clear();
                displayLatencyWindowMs.clear();
                prevHiddenDrops = hiddenDropsNow;
                prevOccluded = occludedNow;
                presentedFps.clearWindow();
                prevDecoded = decodedNow;
                prevPresented = presentedNow;
                prevBusyDrops = busyDropsNow;
                prevBusyRetries = busyRetriesNow;
                prevLossExpected = st.lossExpected;
                prevLossRaw = st.lossRaw;
                prevLossAfter = st.lossAfterNack;
                lastStats = now;
            }
            markPhase(jl::IterPhase::Stats);

            sockaddr_in peer{}; int plen = sizeof(peer);
            WSAResetEvent(socketEvent);
            gMainLoopRecvMs = steadyMsNow();
            int n = recvfrom(s, reinterpret_cast<char*>(buf.data()), static_cast<int>(buf.size()), 0,
                             reinterpret_cast<sockaddr*>(&peer), &plen);
            markPhase(jl::IterPhase::Recv);
            now = std::chrono::steady_clock::now();
            if (n == SOCKET_ERROR) {
                int e = WSAGetLastError();
                if (e == WSAETIMEDOUT || e == WSAEWOULDBLOCK) {
                    // Nothing to read: sleep until a packet, a window message,
                    // an MRM1 pong or cursor shape, or the old receive-timeout
                    // tick. The swap chain latency wait is on the video thread.
                    jl::LoopWait waits;
                    waits.add(socketEvent, jl::LoopWait::Video);
                    waits.add(mouseMoveUdp ? mouseMoveUdp->readEvent() : nullptr, jl::LoopWait::Mrm1);
                    noteLoopBusy(now);
                    waits.wait(loopWaitMs);
                    gLoopResponsiveMs = steadyMsNow();  // woke: input is taken next pump
                    gMainLoopRecvMs = gLoopResponsiveMs;
                    now = std::chrono::steady_clock::now();
                    receiver.tick(msSince(now));
                    auto base = gotAny ? lastPacket : start;
                    const int timeoutMs = gotAny ? o.idleTimeoutMs : o.startupTimeoutMs;
                    if (std::chrono::duration_cast<std::chrono::milliseconds>(now - base).count() >= timeoutMs) {
                        // Back to the launch screen with the reason.
                        gRelaunch = true;
                        gRelaunchNote = gotAny
                            ? L"The connection was lost: no video from the Mac for a while."
                            : L"The Mac did not answer. Check that the JerisLink host is running.";
                        logLine(gotAny ? "session.end reason=idle-timeout"
                                       : "session.end reason=startup-timeout");
                        break;
                    }
                    continue;
                }
                WSACloseEvent(socketEvent);
                closesocket(s);
                throw std::runtime_error("recvfrom failed");
            }
            if (!onDatagram(n, peer, now)) continue;
            markPhase(jl::IterPhase::Packet);
            noteLoopBusy(std::chrono::steady_clock::now());
        }

        const auto loopEnd = std::chrono::steady_clock::now();
        gSessionModalTick = nullptr;  // the session is ending; stopAndWait pumps below
        logLine("session.modal_ticks=" + std::to_string(gSessionTicks));
        // Decode what is queued, finish() on the video thread, keep pumping
        // window messages meanwhile. After this the pipeline is ours again.
        videoWorker.stopAndWait([] { pumpMessages(); });
        if (videoWorker.failed()) throw std::runtime_error(videoWorker.error());
        takeVideoSamples(videoWorker);
        logLine("video.thread=stopped queue_max=" + std::to_string(videoWorker.maxDepth()) +
                " overflows=" + std::to_string(videoWorker.overflows()) +
                " overflow_drops=" + std::to_string(videoWorker.overflowDrops()));
        WSACloseEvent(socketEvent);
        closesocket(s);
        pumpMessages();

        receiver.flushLoss();
        const auto& rst = receiver.stats();
        const jl::ReceiverLoss loss = jl::receiverLoss(rst.lossExpected, rst.lossRaw, rst.lossAfterNack);
        const uint64_t packets = rst.packets, complete = rst.complete, bad = rst.bad;
        // Average over the streaming part of the session (first packet to loop end).
        const double streamSec = gotAny
            ? std::chrono::duration<double>(loopEnd - firstPacket).count() : 0.0;
        const auto sessionFps = [streamSec](uint64_t frames) {
            return streamSec > 0.5 ? static_cast<double>(frames) / streamSec : 0.0;
        };
        // Audio: tell the host to stop now (it would also stop 10 s later),
        // join the player threads, then report.
        jl::audio::PlayerStats audioStats;
        if (audio) {
            mouseMoveUdp->sendAudioRequest(false, 0);
            audio->stop();
            audioStats = audio->stats();
            gAudio = nullptr;
        }
        std::ostringstream summary;
        summary << "SUMMARY packets=" << packets
                << " complete_frames=" << complete
                << " decoded_frames=" << video->decodedFrames()
                << " presented_frames=" << video->presented()
                << " presented_fps_p5=" << jl::receiverPercentile(presentedFps.session(), 5)
                << " presented_fps_p50=" << jl::receiverPercentile(presentedFps.session(), 50)
                << " presented_fps_p95=" << jl::receiverPercentile(presentedFps.session(), 95)
                << " present_busy_drops=" << video->busyDrops()
                << " present_busy_retries=" << video->busyRetries()
                << " present_repaints=" << video->repaints()
                << " present_latency_timeouts=" << video->latencyTimeouts()
                << " present_hidden_drops=" << video->hiddenDrops()
                << " present_occluded=" << video->occludedPresents()
                << " present_hidden_periods=" << video->hiddenPeriods()
                << " max_frame_latency=" << video->maxFrameLatency()
                << " present_to_vblank_ms_p50=" << jl::receiverPercentile(displayLatencyMs, 50)
                << " present_to_vblank_ms_p95=" << jl::receiverPercentile(displayLatencyMs, 95)
                << " present_to_vblank_ms_max=" << jl::receiverPercentile(displayLatencyMs, 100)
                << " present_to_vblank_samples=" << displayLatencyMs.size()
                << " decoded_fps_avg=" << sessionFps(video->decodedFrames())
                << " presented_fps_avg=" << sessionFps(video->presented())
                << " present_avg_ms=" << video->avgPresentMs()
                << " present_max_ms=" << video->maxPresentMs()
                << " non_dxgi_drops=" << video->nonDxgiDrops()
                << " stale_incomplete_dropped=" << rst.incompleteDropped
                << " strict_recovery_events=" << rst.strictRecoveryEvents
                << " late_frames_dropped=" << rst.lateFramesDropped
                << " recovery_wait_packet_drops=" << rst.recoveryWaitPacketDrops
                << " stream_restarts=" << rst.streamRestarts
                << " nack=" << (receiver.nackActive() ? "on" : "off")
                << " abr=" << (abrEnabled ? "on" : "off")
                << " abr_reports_tx=" << (mouseMoveUdp ? mouseMoveUdp->reportSent() : 0)
                << " abr_report_drops=" << (mouseMoveUdp ? mouseMoveUdp->reportDrops() : 0)
                << " abr_slope_skipped=" << arrivalSlope.skipped()
                << " nack_tx=" << rst.nackTx
                << " nack_send_drops=" << (mouseMoveUdp ? mouseMoveUdp->nackDrops() : 0)
                << " nack_packets_requested=" << rst.nackPacketsRequested
                << " nack_whole_frames=" << rst.nackWholeFrames
                << " lost_packets_raw=" << rst.lostPacketsRaw
                << " original_packets=" << rst.originalPackets
                << " loss_expected_packets=" << rst.lossExpected
                << " loss_whole_frames=" << rst.lossWholeFrames
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
                << " video_queue_wait_ms_p50=" << jl::receiverPercentile(queueWaitMs, 50)
                << " video_queue_wait_ms_p99=" << jl::receiverPercentile(queueWaitMs, 99)
                << " video_queue_wait_ms_max=" << jl::receiverPercentile(queueWaitMs, 100)
                << " video_queue_max=" << videoWorker.maxDepth()
                << " video_queue_overflows=" << videoWorker.overflows()
                << " video_queue_overflow_drops=" << videoWorker.overflowDrops()
                << " loop_busy_ms_max=" << loopStalls.ownMaxMs
                << " loop_stalls_16ms=" << loopStalls.stalls16
                << " loop_stalls_100ms=" << loopStalls.stalls100
                << " loop_slow_iter_events=" << slowIterLog.events()
                << " loop_slow_iter_logged=" << slowIterLog.logged()
                << " loop_slow_iter_suppressed=" << slowIterLog.suppressedTotal()
                << " loop_modal_events=" << gModal.events()
                << " loop_modal_ms_total=" << gModal.totalMs()
                << " loop_modal_ms_max=" << gModal.maxMs()
                << " input_queue_ms_p50=" << jl::receiverPercentile(gInputQueueSessionMs, 50)
                << " input_queue_ms_p99=" << jl::receiverPercentile(gInputQueueSessionMs, 99)
                << " input_queue_ms_max=" << jl::receiverPercentile(gInputQueueSessionMs, 100)
                << " input_queue_startup_events=" << gInputQueueStartupMs.size()
                << " input_queue_startup_ms_max=" << jl::receiverPercentile(gInputQueueStartupMs, 100)
                << " input_delivery_ms_max=" << gInputDeliverySessionMaxMs
                << " input_delivery_late_events=" << gInputDeliveryLateEvents
                << " input_slow_events=" << gInputSlowEvents
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
                << " audio=" << (audio ? "on" : "off")
                << " audio_codec=" << jl::audio::codecName(audioStats.jb.codec)
                << " audio_bitrate_kbps=" << (audioStats.jb.framesPlayed + audioStats.jb.framesSilence > 0
                       ? double(audioStats.jb.payloadBytes) * 8.0 * 48.0
                             / double(audioStats.jb.framesPlayed + audioStats.jb.framesSilence) : 0.0)
                << " audio_packets_rx=" << audioStats.jb.packetsRx
                << " audio_fec_recovered=" << audioStats.jb.fecRecovered
                << " audio_plc_frames=" << audioStats.jb.plcFrames
                << " audio_decode_errors=" << audioStats.jb.decodeErrors
                << " audio_drift_inserted=" << audioStats.jb.driftInserted
                << " audio_drift_dropped=" << audioStats.jb.driftDropped
                << " audio_lost=" << audioStats.jb.lost
                << " audio_late=" << audioStats.jb.late
                << " audio_duplicates=" << audioStats.jb.duplicates
                << " audio_underruns=" << audioStats.jb.underruns
                << " audio_overflow_drops=" << audioStats.jb.overflowDrops
                << " audio_idle_drops=" << audioStats.jb.idleDrops
                << " audio_resets=" << audioStats.jb.resets
                << " audio_target_ms=" << audioStats.jb.targetMs
                << " audio_jitter_ms=" << audioStats.jb.jitterMs
                << " audio_played_ms=" << audioStats.jb.framesPlayed / 48
                << " audio_silence_ms=" << audioStats.jb.framesSilence / 48
                << " audio_rx_bad_peer=" << audioStats.rxBadPeer
                << " audio_rx_malformed=" << audioStats.rxMalformed
                << " audio_device_opens=" << audioStats.deviceOpens
                << " audio_device_errors=" << audioStats.deviceErrors
                << " audio_device_reopens=" << audioStats.deviceReopens
                << " audio_device_notifications=" << audioStats.deviceNotifications
                << " audio_latency_ms=" << audioStats.outputLatencyMs()
                << " audio_requests_tx=" << (mouseMoveUdp ? mouseMoveUdp->audioRequestsSent() : 0)
                << " audio_request_drops=" << (mouseMoveUdp ? mouseMoveUdp->audioRequestDrops() : 0)
                << " audio_muted=" << (gAudioMuted ? "yes" : "no")
                << " audio_volume_pct=" << gAudioVolumePct
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
        gAudio = nullptr;  // the player itself was destroyed during unwinding
        logLine(std::string("FATAL ") + e.what());
        // No message box (a modal loop): back to the launch screen, which
        // shows the reason.
        gRelaunch = true;
        gRelaunchNote = L"JerisLink stopped: " + utf8ToWide(e.what());
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

#ifdef JERISLINK_UI_SNAPSHOT
// CI-only build (JerislinkUiSnapshot.exe, never packaged): opens the real
// settings and volume dialogs from this file's resources and saves each
// window as a BMP, so the look can be reviewed without a Mac host.
static void pumpFor(DWORD ms) {
    const ULONGLONG until = GetTickCount64() + ms;
    while (GetTickCount64() < until) {
        MSG m{};
        while (PeekMessageW(&m, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&m);
            DispatchMessageW(&m);
        }
        Sleep(15);
    }
}

static bool writeBmp(const std::wstring& path, HDC src, int x, int y, int w, int h,
                     HWND printFrom) {
    HDC mem = CreateCompatibleDC(src);
    BITMAPINFO bi{};
    bi.bmiHeader.biSize = sizeof(bi.bmiHeader);
    bi.bmiHeader.biWidth = w;
    bi.bmiHeader.biHeight = h;  // bottom-up
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 24;
    bi.bmiHeader.biCompression = BI_RGB;
    void* bits = nullptr;
    HBITMAP bmp = CreateDIBSection(src, &bi, DIB_RGB_COLORS, &bits, nullptr, 0);
    if (!bmp) { DeleteDC(mem); return false; }
    HGDIOBJ old = SelectObject(mem, bmp);
    bool ok = printFrom ? PrintWindow(printFrom, mem, 2 /* PW_RENDERFULLCONTENT */) != FALSE
                        : BitBlt(mem, 0, 0, w, h, src, x, y, SRCCOPY | CAPTUREBLT) != FALSE;
    GdiFlush();
    const DWORD stride = (static_cast<DWORD>(w) * 3 + 3) & ~3u;
    const DWORD imageSize = stride * static_cast<DWORD>(h);
    BITMAPFILEHEADER fh{};
    fh.bfType = 0x4D42;
    fh.bfOffBits = sizeof(fh) + sizeof(bi.bmiHeader);
    fh.bfSize = fh.bfOffBits + imageSize;
    bi.bmiHeader.biSizeImage = imageSize;
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(&fh), sizeof(fh));
    out.write(reinterpret_cast<const char*>(&bi.bmiHeader), sizeof(bi.bmiHeader));
    out.write(static_cast<const char*>(bits), imageSize);
    ok = ok && out.good();
    SelectObject(mem, old);
    DeleteObject(bmp);
    DeleteDC(mem);
    return ok;
}

// Saves <name>-screen.bmp (screen pixels: DWM title bar as shown) and
// <name>-print.bmp (PrintWindow, for desktops where the screen is blank).
static void snapshotWindow(HWND hwnd, const std::wstring& dir, const std::wstring& name) {
    SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
    SetForegroundWindow(hwnd);
    RedrawWindow(hwnd, nullptr, nullptr, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN | RDW_FRAME);
    pumpFor(700);
    RECT r{};
    if (FAILED(DwmGetWindowAttribute(hwnd, DWMWA_EXTENDED_FRAME_BOUNDS, &r, sizeof(r)))) {
        GetWindowRect(hwnd, &r);
    }
    RECT wr{};
    GetWindowRect(hwnd, &wr);
    HDC screen = GetDC(nullptr);
    const bool a = writeBmp(dir + L"\\" + name + L"-screen.bmp", screen, r.left, r.top,
                            r.right - r.left, r.bottom - r.top, nullptr);
    const bool b = writeBmp(dir + L"\\" + name + L"-print.bmp", screen, 0, 0,
                            wr.right - wr.left, wr.bottom - wr.top, hwnd);
    ReleaseDC(nullptr, screen);
    std::wcout << name << L" dpi=" << GetDpiForWindow(hwnd) << L" screen=" << a
               << L" print=" << b << L"\n";
}

// Screen pixels of a dialog with one of its drop-downs open. "-early" is
// taken right after the list opens, to catch a first frame that is not dark.
static void snapshotDropDown(HWND dlg, int comboId, const std::wstring& dir,
                             const std::wstring& name) {
    SetForegroundWindow(dlg);
    pumpFor(200);
    HWND combo = GetDlgItem(dlg, comboId);
    SetFocus(combo);
    SendMessageW(combo, CB_SHOWDROPDOWN, TRUE, 0);
    RECT r{};
    if (FAILED(DwmGetWindowAttribute(dlg, DWMWA_EXTENDED_FRAME_BOUNDS, &r, sizeof(r)))) {
        GetWindowRect(dlg, &r);
    }
    HDC screen = GetDC(nullptr);
    pumpFor(16);
    const bool early = writeBmp(dir + L"\\" + name + L"-early-screen.bmp", screen, r.left, r.top,
                                r.right - r.left, r.bottom - r.top, nullptr);
    pumpFor(700);
    const bool open = SendMessageW(combo, CB_GETDROPPEDSTATE, 0, 0) != 0;
    const bool late = writeBmp(dir + L"\\" + name + L"-screen.bmp", screen, r.left, r.top,
                               r.right - r.left, r.bottom - r.top, nullptr);
    ReleaseDC(nullptr, screen);
    SendMessageW(combo, CB_SHOWDROPDOWN, FALSE, 0);
    pumpFor(200);
    std::wcout << name << L" dropped=" << open << L" early=" << early << L" screen=" << late
               << L"\n";
}

// ---- No-freeze checks ------------------------------------------------------
// Every in-session action (hotkeys, overlay keys, overlay buttons) must
// return at once and must not enter a Win32 modal loop: a WH_MSGFILTER hook
// counts dialog-box and menu loops, and a watchdog thread ends the process
// with exit code 9 if one action takes more than 5 s.
static int gSnapshotModalLoops = 0;
static std::atomic<double> gSnapshotActionStart{0.0};
static std::atomic<bool> gSnapshotDone{false};

static LRESULT CALLBACK snapshotMsgFilter(int code, WPARAM wParam, LPARAM lParam) {
    if (code == MSGF_DIALOGBOX || code == MSGF_MENU) ++gSnapshotModalLoops;
    return CallNextHookEx(nullptr, code, wParam, lParam);
}

static void snapshotWatchdog() {
    while (!gSnapshotDone.load()) {
        const double start = gSnapshotActionStart.load();
        if (start > 0.0 && steadyMsNow() - start > 5000.0) {
            std::wcout << L"no_freeze=FAIL watchdog\n" << std::flush;
            ExitProcess(9);
        }
        Sleep(100);
    }
}

// Opens the launch screen modeless (the app shows it modal before any
// session) so it can be captured and driven.
static HWND snapshotLaunchScreen(LaunchContext& ctx) {
    HWND dlg = CreateDialogParamW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDD_LAUNCH),
                                  nullptr, LaunchDlgProc, reinterpret_cast<LPARAM>(&ctx));
    if (dlg) ShowWindow(dlg, SW_SHOW);
    return dlg;
}

static std::string savedUiAccentValue() {
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, kJerislinkSettingsKey, 0, KEY_READ, &key) !=
        ERROR_SUCCESS) {
        return {};
    }
    const std::string value = readRegString(key, L"UiAccent");
    RegCloseKey(key);
    return value;
}

static int runUiSnapshot(const std::wstring& dir, const std::wstring& accentName) {
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    if (accentName != L"blue" && accentName != L"green") {
        std::wcout << L"unknown accent " << accentName << L"\n";
        return 12;
    }
    const bool wantBlue = accentName == L"blue";
    jl::ui::setAccent(wantBlue ? jl::ui::Accent::Blue : jl::ui::Accent::Green);
    std::wcout << L"accent=" << accentName << L"\n";
    // Made-up addresses: a tailnet IP and the Tailcat bridge both present.
    gBindDetectionOverride = jl::BindDetection{std::string("100.64.0.25"), true};
    ensureCommonControls();
    ensureAudioVolumeLoaded();
    HINSTANCE inst = GetModuleHandleW(nullptr);

    HWND settings = CreateDialogParamW(inst, MAKEINTRESOURCEW(IDD_VIDEO_SETTINGS), nullptr,
                                       SettingsDlgProc, kSettingsDialogSave);
    if (!settings) return 2;
    ShowWindow(settings, SW_SHOW);
    snapshotWindow(settings, dir, L"settings-auto");
    // Manual bitrate: Auto off, slider enabled; keyboard focus on the slider.
    SendMessageW(settings, WM_COMMAND, MAKEWPARAM(IDC_BITRATE_AUTO, BN_CLICKED), 0);
    SendMessageW(settings, WM_CHANGEUISTATE, MAKEWPARAM(UIS_CLEAR, UISF_HIDEFOCUS), 0);
    SetFocus(GetDlgItem(settings, IDC_VIDEO_BITRATE));
    snapshotWindow(settings, dir, L"settings-manual");
    snapshotDropDown(settings, IDC_VIDEO_CODEC, dir, L"settings-codec-open");
    snapshotDropDown(settings, IDC_BIND_IP, dir, L"settings-bind-open");
    // Manual pick (Tailcat) and Auto with a Tailcat Mac address.
    SendDlgItemMessageW(settings, IDC_BIND_IP, CB_SETCURSEL, 2, 0);
    SendMessageW(settings, WM_COMMAND, MAKEWPARAM(IDC_BIND_IP, CBN_SELCHANGE),
                 reinterpret_cast<LPARAM>(GetDlgItem(settings, IDC_BIND_IP)));
    snapshotWindow(settings, dir, L"settings-bind-manual");
    SendDlgItemMessageW(settings, IDC_BIND_IP, CB_SETCURSEL, 0, 0);
    SetDlgItemTextW(settings, IDC_HOST_IP, L"127.0.0.1");  // EN_CHANGE updates the hint
    SendMessageW(settings, WM_COMMAND, MAKEWPARAM(IDC_BIND_IP, CBN_SELCHANGE),
                 reinterpret_cast<LPARAM>(GetDlgItem(settings, IDC_BIND_IP)));
    snapshotWindow(settings, dir, L"settings-bind-tailcat");
    // Nothing detected: Auto only, greyed, with the reason below.
    gBindDetectionOverride = jl::BindDetection{};
    fillBindChoices(settings);
    SetDlgItemTextW(settings, IDC_HOST_IP, L"100.64.0.10");
    snapshotWindow(settings, dir, L"settings-bind-none");
    const bool bindGreyed = !IsWindowEnabled(GetDlgItem(settings, IDC_BIND_IP));
    gBindDetectionOverride = jl::BindDetection{std::string("100.64.0.25"), true};
    // Validation error in the footer, no message box.
    SetDlgItemTextW(settings, IDC_HOST_IP, L"");
    SendMessageW(settings, WM_COMMAND, MAKEWPARAM(IDOK, BN_CLICKED), 0);
    snapshotWindow(settings, dir, L"settings-error");
    const bool stillOpen = IsWindow(settings) && gSettingsDlg == settings;
    SetDlgItemTextW(settings, IDC_HOST_IP, L"100.64.0.10");
    // Settings Audio section and the volume window open together stay in step.
    SendMessageW(settings, WM_COMMAND, MAKEWPARAM(IDC_VOLUME_MUTE, BN_CLICKED), 0);

    HWND volume = CreateDialogParamW(inst, MAKEINTRESOURCEW(IDD_AUDIO_VOLUME), nullptr,
                                     VolumeDlgProc, 0);
    if (!volume) return 3;
    gVolumeDlg = volume;
    syncVolumeWindows();
    SetWindowPos(volume, nullptr, 40, 40, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
    ShowWindow(volume, SW_SHOW);
    snapshotWindow(volume, dir, L"volume-muted");
    SendMessageW(settings, WM_COMMAND, MAKEWPARAM(IDC_VOLUME_MUTE, BN_CLICKED), 0);
    snapshotWindow(volume, dir, L"volume");
    const bool synced =
        SendDlgItemMessageW(volume, IDC_VOLUME_SLIDER, TBM_GETPOS, 0, 0) == gAudioVolumePct &&
        SendDlgItemMessageW(settings, IDC_VOLUME_SLIDER, TBM_GETPOS, 0, 0) == gAudioVolumePct &&
        jl::ui::ownerChecked(volume, IDC_VOLUME_MUTE) == gAudioMuted &&
        jl::ui::ownerChecked(settings, IDC_VOLUME_MUTE) == gAudioMuted;
    std::wcout << L"volume_sync=" << (synced ? L"ok" : L"MISMATCH") << L"\n";
    DestroyWindow(volume);
    DestroyWindow(settings);
    pumpFor(100);

    // One dialog at a time, through the same calls as the viewer's menus.
    showVolumeWindow(nullptr, "snapshot");
    const bool volumeFirst = gVolumeDlg != nullptr;
    showVideoSettings(nullptr);  // closes the volume window
    pumpFor(100);
    const bool settingsClosedVolume = gSettingsDlg != nullptr && gVolumeDlg == nullptr;
    showVolumeWindow(nullptr, "snapshot");  // focuses settings instead
    const bool volumeRefused = gVolumeDlg == nullptr;
    const bool modeless = gSettingsDlg && !gSettingsModal;
    if (gSettingsDlg) SendMessageW(gSettingsDlg, WM_COMMAND, MAKEWPARAM(IDCANCEL, BN_CLICKED), 0);
    pumpFor(100);
    const bool closed = gSettingsDlg == nullptr;
    const bool oneDialog = volumeFirst && settingsClosedVolume && volumeRefused && modeless && closed;
    std::wcout << L"one_dialog=" << (oneDialog ? L"ok" : L"FAIL") << L" bind_greyed=" << bindGreyed
               << L" error_inline=" << stillOpen << L"\n";

    // Launch screen: host tab, code tab, inline error.
    LaunchContext launchCtx;
    HWND launch = snapshotLaunchScreen(launchCtx);
    if (!launch) return 11;
    snapshotWindow(launch, dir, L"launch-host");
    launchSetTab(launch, true);
    snapshotWindow(launch, dir, L"launch-code");
    const bool codeTabBlocks = !IsWindowEnabled(GetDlgItem(launch, IDOK)) &&
                               IsWindowVisible(GetDlgItem(launch, IDC_LAUNCH_CODE_NOTE));
    launchSetTab(launch, false);
    SetDlgItemTextW(launch, IDC_HOST_IP, L"");
    SendMessageW(launch, WM_COMMAND, MAKEWPARAM(IDOK, BN_CLICKED), 0);
    const bool launchError = IsWindow(launch) &&
                             !windowText(GetDlgItem(launch, IDC_LAUNCH_ERROR)).empty();
    snapshotWindow(launch, dir, L"launch-error");
    // Theme picker: the other theme, then back; each click saves UiAccent.
    SendMessageW(launch, WM_COMMAND,
                 MAKEWPARAM(wantBlue ? IDC_THEME_GREEN : IDC_THEME_BLUE, BN_CLICKED), 0);
    const bool switched = accentIsBlue() == !wantBlue &&
                          savedUiAccentValue() == (wantBlue ? "green" : "blue");
    SendMessageW(launch, WM_COMMAND,
                 MAKEWPARAM(wantBlue ? IDC_THEME_BLUE : IDC_THEME_GREEN, BN_CLICKED), 0);
    const bool restored = accentIsBlue() == wantBlue &&
                          savedUiAccentValue() == (wantBlue ? "blue" : "green");
    const bool accentSaved = switched && restored;
    std::wcout << L"launch code_tab=" << codeTabBlocks << L" error_inline=" << launchError
               << L" accent_saved=" << (accentSaved ? L"ok" : L"FAIL") << L"\n";
    DestroyWindow(launch);
    gLaunch = nullptr;
    pumpFor(100);

    // Viewer window: no menu bar, nothing added to the system menu.
    HWND viewer = createViewerWindow(960, 540);
    ShowWindow(viewer, SW_SHOWNORMAL);
    UpdateWindow(viewer);
    bool sysMenuClean = true;
    if (HMENU sys = GetSystemMenu(viewer, FALSE)) {
        for (int i = 0; i < GetMenuItemCount(sys); ++i) {
            const UINT id = GetMenuItemID(sys, i);
            if (id >= kRemovedMenuIdFirst && id <= kRemovedMenuIdLast) sysMenuClean = false;
        }
    }
    const bool noMenu = GetMenu(viewer) == nullptr && sysMenuClean;
    std::wcout << L"viewer_menu=" << (noMenu ? L"none" : L"PRESENT") << L"\n";

    // Overlay with made-up session values, open for the keyboard, then hidden.
    gSessionHostLabel = "100.64.0.10";
    gConnectionInfo = ConnectionInfoState{};
    gConnectionInfo.configuredCodec = "h265";
    gConnectionInfo.configuredBitrateMbps = 40;
    gConnectionInfo.effectiveCodec = "h265";
    gConnectionInfo.effectiveBitrateMbps = 40;
    gConnectionInfo.remoteWidth = 2560;
    gConnectionInfo.remoteHeight = 1440;
    gConnectionInfo.fps = 60;
    gConnectionInfo.rttMs = 3.2;
    gConnectionInfo.controlConnected = true;
    gConnectionInfo.backend = "d3d11";
    gConnectionInfo.decoder = "hardware";
    gConnectionInfo.adapter = "Sample GPU";
    overlayCreate(viewer);
    overlayShow(false, "snapshot", 0);
    snapshotWindow(viewer, dir, L"overlay-open-mouse");
    overlayShow(true, "snapshot", 0);
    snapshotWindow(viewer, dir, L"overlay-open");
    const bool overlayShown = overlayVisible();
    // Placement and translucency: top centre of the client area, a layered
    // window at ov::kSessionUiAlpha.
    bool overlayPlaced = false;
    BYTE overlayAlpha = 0;
    DWORD alphaFlags = 0;
    const bool layered =
        gOverlay && (GetWindowLongPtrW(gOverlay, GWL_EXSTYLE) & WS_EX_LAYERED) != 0 &&
        GetLayeredWindowAttributes(gOverlay, nullptr, &overlayAlpha, &alphaFlags) &&
        (alphaFlags & LWA_ALPHA) != 0 && overlayAlpha == ov::kSessionUiAlpha;
    if (gOverlay) {
        RECT c{}, o{};
        GetClientRect(viewer, &c);
        MapWindowPoints(viewer, nullptr, reinterpret_cast<POINT*>(&c), 2);
        GetWindowRect(gOverlay, &o);
        const LONG gapL = o.left - c.left, gapR = c.right - o.right;
        const LONG topGap = o.top - c.top;
        overlayPlaced = gapL >= 0 && gapR >= 0 && std::abs(gapL - gapR) <= 1 &&
                        topGap == ov::scale(16, overlayDpi());
        std::wcout << L"overlay_place=" << (overlayPlaced ? L"top-centre" : L"FAIL")
                   << L" gap_l=" << gapL << L" gap_r=" << gapR << L" top=" << topGap
                   << L" layered=" << layered
                   << L" alpha=" << static_cast<int>(overlayAlpha) << L"\n";
    }
    overlayHide("snapshot");
    snapshotWindow(viewer, dir, L"overlay-hidden");

    // Every in-session action, timed, with modal loops counted.
    std::thread watchdog(snapshotWatchdog);
    HHOOK filter = SetWindowsHookExW(WH_MSGFILTER, snapshotMsgFilter, nullptr,
                                     GetCurrentThreadId());
    double worstMs = 0.0;
    bool actionsOk = filter != nullptr;
    const auto timed = [&](const char* name, const std::function<void()>& action,
                           bool expect) {
        const double start = steadyMsNow();
        gSnapshotActionStart = start;
        action();
        const double ms = steadyMsNow() - start;
        gSnapshotActionStart = 0.0;
        pumpFor(60);
        worstMs = std::max(worstMs, ms);
        const bool ok = expect && ms < 1000.0;
        if (!ok) actionsOk = false;
        std::wcout << L"action " << name << L" ms=" << ms << L" ok=" << ok << L"\n";
    };
    const bool mutedBefore = gAudioMuted;
    // Info, Settings and Volume opened from the overlay share its opacity
    // token; checked on the real windows.
    int sessionLayered = 0;
    const auto sessionAlpha = [&sessionLayered](HWND w, const wchar_t* name) {
        BYTE a = 0;
        DWORD flags = 0;
        const bool ok = w && (GetWindowLongPtrW(w, GWL_EXSTYLE) & WS_EX_LAYERED) != 0 &&
                        GetLayeredWindowAttributes(w, nullptr, &a, &flags) &&
                        (flags & LWA_ALPHA) != 0 && a == ov::kSessionUiAlpha;
        if (ok) ++sessionLayered;
        std::wcout << L"session_alpha " << name << L" layered=" << ok
                   << L" alpha=" << static_cast<int>(a) << L"\n";
    };
    timed("hotkey-O-open", [] { viewerHotkey('O', "snapshot"); }, true);
    timed("hotkey-O-check", [] {}, overlayVisible() && gOverlayKeyboard);
    timed("overlay-key-tab", [] { overlayKey(VK_TAB, false); }, true);
    timed("overlay-key-right", [] { overlayKey(VK_RIGHT, false); }, true);
    timed("overlay-key-esc", [] { overlayKey(VK_ESCAPE, false); }, true);
    timed("overlay-hidden-check", [] {}, !overlayVisible());
    timed("hotkey-M", [] { viewerHotkey('M', "snapshot"); }, true);
    timed("hotkey-M-check", [] {}, gAudioMuted != mutedBefore);
    timed("hotkey-M-again", [] { viewerHotkey('M', "snapshot"); }, true);
    timed("hotkey-M-again-check", [] {}, gAudioMuted == mutedBefore);
    timed("hotkey-V", [] { viewerHotkey('V', "snapshot"); }, true);
    timed("hotkey-V-check", [] {}, gVolumeDlg != nullptr);
    if (gVolumeDlg) SendMessageW(gVolumeDlg, WM_COMMAND, MAKEWPARAM(IDCANCEL, BN_CLICKED), 0);
    pumpFor(60);
    timed("overlay-mute", [] { overlayActivate(ov::Item::Mute, "snapshot"); }, true);
    timed("overlay-mute-check", [] {}, gAudioMuted != mutedBefore);
    timed("overlay-mute-again", [] { overlayActivate(ov::Item::Mute, "snapshot"); }, true);
    timed("overlay-mute-again-check", [] {}, gAudioMuted == mutedBefore);
    timed("overlay-info", [] { overlayActivate(ov::Item::Info, "snapshot"); }, true);
    timed("overlay-info-check", [] {}, gInfoDlg != nullptr);
    if (gInfoDlg) {
        sessionAlpha(gInfoDlg, L"info");
        snapshotWindow(gInfoDlg, dir, L"connection-info");
        SendMessageW(gInfoDlg, WM_COMMAND, MAKEWPARAM(IDCANCEL, BN_CLICKED), 0);
    }
    pumpFor(60);
    timed("overlay-settings", [] { overlayActivate(ov::Item::Settings, "snapshot"); }, true);
    timed("overlay-settings-check", [] {}, gSettingsDlg != nullptr && !gSettingsModal);
    if (gSettingsDlg) {
        sessionAlpha(gSettingsDlg, L"settings");
        snapshotWindow(gSettingsDlg, dir, L"settings-session");
        SendMessageW(gSettingsDlg, WM_COMMAND, MAKEWPARAM(IDCANCEL, BN_CLICKED), 0);
    }
    pumpFor(60);
    timed("overlay-volume", [] { overlayActivate(ov::Item::Volume, "snapshot"); }, true);
    timed("overlay-volume-check", [] {}, gVolumeDlg != nullptr);
    if (gVolumeDlg) {
        sessionAlpha(gVolumeDlg, L"volume");
        snapshotWindow(gVolumeDlg, dir, L"volume-session");
        SendMessageW(gVolumeDlg, WM_COMMAND, MAKEWPARAM(IDCANCEL, BN_CLICKED), 0);
    }
    pumpFor(60);
    overlayShow(false, "snapshot", 0);
    timed("overlay-disconnect", [] { overlayActivate(ov::Item::Disconnect, "snapshot"); }, true);
    timed("overlay-disconnect-check", [] {},
          gRelaunch && gWindowClosed && !IsWindowVisible(viewer) && !overlayVisible());
    gRelaunch = false;
    gRelaunchNote.clear();
    gWindowClosed = false;
    if (filter) UnhookWindowsHookEx(filter);
    const bool noModal = gSnapshotModalLoops == 0;
    const bool sessionDialogsLayered = sessionLayered == 3;
    std::wcout << L"no_freeze=" << (actionsOk && noModal ? L"ok" : L"FAIL")
               << L" modal_loops=" << gSnapshotModalLoops << L" worst_ms=" << worstMs << L"\n";

    // While Windows holds a modal loop (here a popup menu, like a caption
    // drag or the system menu) the session timer still runs the tick.
    ShowWindow(viewer, SW_SHOWNORMAL);
    SetForegroundWindow(viewer);
    pumpFor(100);
    int tickCalls = 0;
    gSessionModalTick = [&tickCalls] { ++tickCalls; };
    gMainLoopRecvMs = 0.0;
    SetTimer(viewer, kSessionTickTimer, kSessionTickMs, nullptr);
    SetTimer(nullptr, 0, 800, [](HWND, UINT, UINT_PTR id, DWORD) {
        KillTimer(nullptr, id);
        EndMenu();
    });
    HMENU menu = CreatePopupMenu();
    AppendMenuW(menu, MF_STRING, 1, L"Modal loop");
    const double menuStart = steadyMsNow();
    gSnapshotActionStart = menuStart;
    TrackPopupMenu(menu, TPM_RETURNCMD | TPM_NONOTIFY, 120, 120, 0, viewer, nullptr);
    gSnapshotActionStart = 0.0;
    const double heldMs = steadyMsNow() - menuStart;
    KillTimer(viewer, kSessionTickTimer);
    gSessionModalTick = nullptr;
    DestroyMenu(menu);
    const bool tickOk = heldMs >= 500.0 && tickCalls >= 10;
    std::wcout << L"modal_tick=" << (tickOk ? L"ok" : L"FAIL") << L" held_ms=" << heldMs
               << L" ticks=" << tickCalls << L"\n";
    gSnapshotDone = true;
    watchdog.join();
    overlayDestroy();
    DestroyWindow(viewer);
    pumpFor(100);

    if (!synced) return 4;
    if (!oneDialog) return 5;
    if (!bindGreyed || !stillOpen) return 6;
    if (!noMenu) return 7;
    if (!actionsOk || !noModal || !overlayShown || !overlayPlaced || !layered ||
        !sessionDialogsLayered)
        return 8;
    if (!tickOk) return 10;
    if (!codeTabBlocks || !launchError) return 11;
    if (!accentSaved) return 12;
    return 0;
}
#endif

int WINAPI wWinMain(HINSTANCE, HINSTANCE, PWSTR, int) {
    int argc = 0;
    LPWSTR* wideArgv = CommandLineToArgvW(GetCommandLineW(), &argc);
#ifdef JERISLINK_UI_SNAPSHOT
    if (wideArgv && argc >= 2) {
        const std::wstring dir = wideArgv[1];
        const std::wstring accentName = argc >= 3 ? std::wstring(wideArgv[2]) : L"green";
        LocalFree(wideArgv);
        return runUiSnapshot(dir, accentName);
    }
#endif
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
    const int rc = appMain(argc, argv.data());
    if (gRelaunch) {
        // Back to the launch screen in a fresh process: the session's
        // threads, sockets and decoder are all gone with this one.
        std::vector<std::string> rest(utf8Args.begin() + 1, utf8Args.end());
        std::wstring cmd;
        wchar_t exe[MAX_PATH]{};
        GetModuleFileNameW(nullptr, exe, MAX_PATH);
        cmd = L"\"" + std::wstring(exe) + L"\"";
        for (const auto& a : jl::argsForRelaunch(rest)) {
            std::wstring w = utf8ToWide(a);
            std::wstring quoted = L" \"";
            for (wchar_t c : w) {
                if (c == L'"') quoted += L'\\';
                quoted += c;
            }
            cmd += quoted + L"\"";
        }
        SetEnvironmentVariableW(L"JERISLINK_LAUNCH_NOTE",
                                gRelaunchNote.empty() ? nullptr : gRelaunchNote.c_str());
        STARTUPINFOW si{};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        const BOOL ok = CreateProcessW(exe, cmd.data(), nullptr, nullptr, FALSE, 0, nullptr,
                                       nullptr, &si, &pi);
        logLine(std::string("launch.relaunch started=") + (ok ? "yes" : "no") +
                " error=" + std::to_string(ok ? 0 : GetLastError()));
        if (ok) {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
    }
    gLog.stop();  // write out every queued line before the process exits
    return rc;
}
