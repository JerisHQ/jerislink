// JerisLink Windows host, H2 (design doc 2026-11-27, phases H1 and H2).
//
// H1: captures the screen, encodes H.264 with the Media Foundation software
// encoder and sends it as MR02 to one viewer, so the existing viewer shows
// the picture.
// H2: the viewer's keyboard and mouse (MRC1 0x10, 0x20-0x25, MRM1 0x24) go
// in with SendInput, the Force Quit button (MRC1 0x60) opens Task Manager,
// the cursor shape goes back as MRM1 0x31, and MRC1 0x06 HOST_INFO tells a
// new viewer it talks to Windows.
// No audio, clipboard, files, NACK or ABR yet; no password: this dev build
// runs only with --dev-no-password and one allowed viewer IP.
//
//   JerisLinkHost.exe --dev-no-password --bind <host ip> --allow <viewer ip>
//                     [--fps 30] [--bitrate 25] [--max-size 1920x1080]
//                     [--capture auto|dda|gdi] [--log file] [--seconds N]
//                     [--snapshot file.bmp]
//   JerisLinkHost.exe --probe [--capture ...] [--snapshot file.bmp]
//
// Ports as the macOS host: control TCP 38400, MRM1 UDP 38412 on --bind;
// video to <viewer ip>:38402 from --bind.

#include "capture.hpp"
#include "color_convert.hpp"
#include "encoder_mf.hpp"
#include "host_protocol.hpp"
#include "input_win.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <mfapi.h>
#include <objbase.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <exception>
#include <fstream>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#ifndef JERISLINK_VERSION_STRING
#define JERISLINK_VERSION_STRING "dev"
#endif

namespace {

using Clock = std::chrono::steady_clock;

constexpr uint16_t kControlPort = 38400;
constexpr uint16_t kVideoPort = 38402;
constexpr uint16_t kMrm1Port = 38412;
constexpr int kActiveGraceMs = 10'000;    // viewer counts as present this long after its last packet
constexpr int kKeyframeMinGapMs = 200;    // forced IDRs closer than this are merged
constexpr int kStaticRefreshMs = 1000;    // a static screen is re-sent this often
constexpr int kMaxControlConnections = 8;   // includes sockets still in the handshake
constexpr int kHandshakeMs = 10'000;        // whole probe read; the viewer sends it ~300 ms after connect
constexpr int kCursorPollMs = 16;           // cursor shape check
constexpr int kCursorResendMs = 1000;       // unchanged shape re-sent this often (UDP loss repair)
constexpr uint32_t kHostCaps = jlh::kHostCapKeyboard | jlh::kHostCapPointer | jlh::kHostCapCursorShape |
                               jlh::kHostCapTaskManager | jlh::kHostCapPointerSync;

struct Options {
    bool devNoPassword = false;
    bool probe = false;
    std::string bindIp, allowIp, logPath, snapshotPath;
    int fps = 30;
    int bitrateMbps = 25;
    int maxW = 1920, maxH = 1080;
    int seconds = 0;
    jlh::CaptureMode capture = jlh::CaptureMode::Auto;
};

std::mutex gLogMutex;
FILE* gLogFile = nullptr;
const Clock::time_point gStart = Clock::now();

int64_t msSinceStart() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - gStart).count();
}

void logf(const char* fmt, ...) {
    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    SYSTEMTIME st;
    GetLocalTime(&st);
    char line[1200];
    std::snprintf(line, sizeof(line), "%04d-%02d-%02d %02d:%02d:%02d.%03d %s\n", st.wYear, st.wMonth, st.wDay,
                  st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, msg);
    std::lock_guard<std::mutex> g(gLogMutex);
    std::fputs(line, stdout);
    std::fflush(stdout);
    if (gLogFile) { std::fputs(line, gLogFile); std::fflush(gLogFile); }
}

bool parseSize(const std::string& s, int& w, int& h) {
    return std::sscanf(s.c_str(), "%dx%d", &w, &h) == 2 && w >= 16 && h >= 16;
}

bool parseIpv4(const std::string& s, in_addr& out) {
    return inet_pton(AF_INET, s.c_str(), &out) == 1;
}

bool parseArgs(int argc, char** argv, Options& o, std::string& err) {
    for (int i = 1; i < argc; ++i) {
        const std::string k = argv[i];
        auto val = [&](std::string& v) {
            if (i + 1 >= argc) { err = "missing value for " + k; return false; }
            v = argv[++i];
            return true;
        };
        std::string v;
        if (k == "--dev-no-password") o.devNoPassword = true;
        else if (k == "--probe") o.probe = true;
        else if (k == "--bind") { if (!val(o.bindIp)) return false; }
        else if (k == "--allow") { if (!val(o.allowIp)) return false; }
        else if (k == "--log") { if (!val(o.logPath)) return false; }
        else if (k == "--snapshot") { if (!val(o.snapshotPath)) return false; }
        else if (k == "--fps") { if (!val(v)) return false; o.fps = std::atoi(v.c_str()); }
        else if (k == "--bitrate") { if (!val(v)) return false; o.bitrateMbps = std::atoi(v.c_str()); }
        else if (k == "--seconds") { if (!val(v)) return false; o.seconds = std::atoi(v.c_str()); }
        else if (k == "--max-size") {
            if (!val(v) || !parseSize(v, o.maxW, o.maxH)) { err = "bad --max-size"; return false; }
        } else if (k == "--capture") {
            if (!val(v)) return false;
            if (v == "auto") o.capture = jlh::CaptureMode::Auto;
            else if (v == "dda") o.capture = jlh::CaptureMode::Dda;
            else if (v == "gdi") o.capture = jlh::CaptureMode::Gdi;
            else { err = "bad --capture"; return false; }
        } else { err = "unknown option " + k; return false; }
    }
    if (o.fps < 1 || o.fps > 240) { err = "--fps must be 1..240"; return false; }
    if (o.bitrateMbps < 4 || o.bitrateMbps > 100) { err = "--bitrate must be 4..100"; return false; }
    if (o.probe) return true;
    // No password support yet: refuse to listen unless told this is a dev
    // run, and only for one viewer IP on one host address.
    if (!o.devNoPassword) {
        err = "this dev build runs only with --dev-no-password (no password support yet)";
        return false;
    }
    in_addr a{};
    if (o.bindIp.empty() || !parseIpv4(o.bindIp, a) || a.s_addr == INADDR_ANY) {
        err = "--bind <host IPv4> is required (not 0.0.0.0)";
        return false;
    }
    if (o.allowIp.empty() || !parseIpv4(o.allowIp, a) || a.s_addr == INADDR_ANY) {
        err = "--allow <viewer IPv4> is required";
        return false;
    }
    return true;
}

bool writeBmp(const std::string& path, const jlh::CapturedFrame& f) {
    std::ofstream o(path, std::ios::binary);
    if (!o) return false;
    const uint32_t row = uint32_t(f.width) * 4, img = row * uint32_t(f.height);
    BITMAPFILEHEADER fh{};
    fh.bfType = 0x4D42;
    fh.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);
    fh.bfSize = fh.bfOffBits + img;
    BITMAPINFOHEADER ih{};
    ih.biSize = sizeof(ih);
    ih.biWidth = f.width;
    ih.biHeight = -f.height;  // top-down
    ih.biPlanes = 1;
    ih.biBitCount = 32;
    ih.biCompression = BI_RGB;
    ih.biSizeImage = img;
    o.write(reinterpret_cast<const char*>(&fh), sizeof(fh));
    o.write(reinterpret_cast<const char*>(&ih), sizeof(ih));
    for (int y = 0; y < f.height; ++y) o.write(reinterpret_cast<const char*>(f.bgra + size_t(y) * f.stride), row);
    return bool(o);
}

// ------------------------------------------------------------- shared state

struct State {
    Options opt;
    in_addr bindAddr{}, allowAddr{};
    std::atomic<bool> running{true};
    std::atomic<int64_t> lastActivityMs{-1'000'000};
    std::atomic<int> controlConnections{0};  // past the handshake: these keep the stream active
    jlh::ConnectionSlots controlSlots{kMaxControlConnections};
    std::atomic<bool> keyframeRequested{false};
    std::atomic<int> bitrateMbps{25};
    std::atomic<int> streamW{0}, streamH{0};
    // counters, read by the stats line
    std::atomic<uint64_t> keyframeRequests{0}, pings{0}, rejected{0};
    // H2 input. One injector for every connection: one viewer IP may connect,
    // but over more than one control connection at a time (a reconnect), so
    // each connection gets its own owner number for what it holds down.
    jlh::InputInjector input;
    std::atomic<uint64_t> nextInputOwner{1};
    // MRM1 pointer order. A UDP move and a POINTER_SYNC (control thread) both
    // take this, then the injector's own lock, in that order.
    std::mutex pointerMutex;
    jlh::Mrm1Session pointer;  // guarded by pointerMutex
    std::atomic<uint64_t> inputMalformed{0}, pointerUdp{0}, pointerUdpStale{0}, pointerSyncs{0};
    std::atomic<uint64_t> cursorSent{0}, cursorSendFail{0}, cursorChanges{0};
    // The MRM1 socket and the newest MRM1 session's viewer address: the
    // cursor shape goes there, from port 38412 (the viewer checks both).
    SOCKET mrm1Sock = INVALID_SOCKET;
    std::mutex mrm1PeerMutex;
    sockaddr_in mrm1Peer{};
    bool haveMrm1Peer = false;
    uint32_t mrm1Generation = 0;  // bumped for each new MRM1 session
};
State* gState = nullptr;

void touch(State& s) { s.lastActivityMs = msSinceStart(); }

BOOL WINAPI onConsoleCtrl(DWORD) {
    if (gState) gState->running = false;
    return TRUE;
}

std::string ipString(const in_addr& a) {
    char b[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &a, b, sizeof(b));
    return b;
}

// deadlineMs < 0: no deadline (the socket blocks). Otherwise every recv
// gets only the time left, so a peer trickling bytes cannot hold the
// handshake open past the deadline. If the timeout cannot be set, the read
// fails rather than block without one.
bool recvExact(SOCKET s, uint8_t* p, size_t n, int64_t deadlineMs = -1) {
    while (n) {
        if (deadlineMs >= 0) {
            const int64_t left = deadlineMs - msSinceStart();
            if (left <= 0) return false;
            const DWORD t = DWORD(left);
            if (setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&t), sizeof(t)) != 0)
                return false;
        }
        const int r = recv(s, reinterpret_cast<char*>(p), int(n), 0);
        if (r <= 0) return false;
        p += r;
        n -= size_t(r);
    }
    return true;
}

bool sendAll(SOCKET s, const std::vector<uint8_t>& b) {
    size_t off = 0;
    while (off < b.size()) {
        const int r = send(s, reinterpret_cast<const char*>(b.data() + off), int(b.size() - off), 0);
        if (r <= 0) return false;
        off += size_t(r);
    }
    return true;
}

// ---------------------------------------------------------- control channel

// POINTER_SYNC (Pepper's H2 review, item 5): the viewer's pointer position
// and MRM1 seq when a button went down or up, sent on the control
// connection just before that button. Under the pointer lock the pointer is
// put there, every UDP move up to that seq becomes stale, and the button is
// injected, with no UDP move in between: the press lands where the viewer
// clicked whether the move before it came late, never came, or came first.
// button == nullptr: a sync not followed by a button, applied alone.
bool applyPointerSync(State& st, const jlh::InputEvent& sync, const jlh::InputEvent* button,
                      jlh::HeldInput::Owner owner) {
    std::lock_guard<std::mutex> g(st.pointerMutex);
    st.pointer.syncPointer(sync.seq);
    ++st.pointerSyncs;
    st.input.moveNormalized(sync.x, sync.y);
    return button ? st.input.apply(*button, owner) : true;
}

// Runs on its own thread holding one of st.controlSlots, taken by the
// listener; every return path closes the socket and gives the slot back.
void serveControl(State& st, SOCKET c, std::string peer) {
    struct Release {
        State& st;
        SOCKET c;
        bool established = false;
        ~Release() {
            if (established) --st.controlConnections;
            closesocket(c);
            st.controlSlots.release();
        }
    } guard{st, c};
    BOOL nodelay = TRUE;
    setsockopt(c, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));
    uint8_t h[jlh::kMrc1HeaderBytes];
    std::vector<uint8_t> payload;
    auto readFrame = [&](jlh::Mrc1Header& hdr, int64_t deadlineMs) {
        if (!recvExact(c, h, sizeof(h), deadlineMs)) return false;
        auto parsed = jlh::parseMrc1Header(h);
        if (!parsed) return false;
        hdr = *parsed;
        payload.resize(hdr.length);
        return hdr.length == 0 || recvExact(c, payload.data(), hdr.length, deadlineMs);
    };

    jlh::Mrc1Header hdr;
    if (!readFrame(hdr, msSinceStart() + kHandshakeMs) || !jlh::isTransitionProbe(hdr, payload.data())) {
        logf("control.refused peer=%s reason=no_transition_probe", peer.c_str());
        return;
    }
    const uint8_t open = jlh::kAuthOpenIpOnly;
    if (!sendAll(c, jlh::mrc1Frame(jlh::kMsgAuthResult, &open, 1))) return;
    const DWORD noTimeout = 0;  // the viewer keeps idle channels open
    if (setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&noTimeout), sizeof(noTimeout)) != 0) {
        logf("control.closed peer=%s reason=rcvtimeo err=%d", peer.c_str(), WSAGetLastError());
        return;
    }
    ++st.controlConnections;
    guard.established = true;
    touch(st);
    const char* role = "control";
    bool first = true;
    bool hostInfoLogged = false, inputSeen = false;
    const jlh::HeldInput::Owner owner = st.nextInputOwner++;
    std::optional<jlh::InputEvent> pendingSync;  // a POINTER_SYNC waiting for its button
    while (st.running && readFrame(hdr, -1)) {
        if (first) {
            if (hdr.type == jlh::kMsgClipboardHello) role = "clipboard";
            else if (hdr.type == jlh::kMsgPing) role = "ping";
            logf("control.open peer=%s channel=%s auth=open_ip_only", peer.c_str(), role);
        }
        if (first && hdr.type == jlh::kMsgFileHello) {
            // No file transfer in H1: the viewer reads a close as refused.
            logf("control.file_refused peer=%s reason=not_in_h1", peer.c_str());
            break;
        }
        first = false;
        // Only frames this host handles count as viewer activity.
        switch (hdr.type) {
        case jlh::kMsgPing:
            if (!jlh::isValidPing(hdr)) break;  // like the Mac host: no reply to other sizes
            ++st.pings;
            touch(st);
            if (!sendAll(c, jlh::mrc1Frame(jlh::kMsgPong, payload))) goto done;
            break;
        case jlh::kMsgVideoConfig: {
            touch(st);
            const auto d = jlh::decideVideoConfig(payload.data(), payload.size(), st.bitrateMbps.load(),
                                                  st.streamW.load(), st.streamH.load());
            if (d.accepted && d.bitrateChanged) st.bitrateMbps = d.bitrateMbps;
            // HOST_INFO rides behind the ACK, in the same send, only when this
            // VIDEO_CONFIG said the viewer reads it (host_protocol.hpp says
            // why): an older viewer gets the ACK alone, as from H1.
            const int monitors = std::clamp(GetSystemMetrics(SM_CMONITORS), 0, 255);
            const auto out = jlh::videoConfigReply(
                d, jlh::hostInfoPayload(jlh::kPlatformWindows, kHostCaps, uint8_t(monitors), JERISLINK_VERSION_STRING));
            if (!sendAll(c, out)) goto done;
            logf("video.config peer=%s status=%u codec=h264 bitrate_mbps=%d flags=0x%02x size=%dx%d host_info=%s",
                 peer.c_str(), unsigned(d.ack[1]), d.bitrateMbps, unsigned(d.ack[3]), st.streamW.load(),
                 st.streamH.load(), d.hostInfo ? "sent" : "not_asked");
            if (d.hostInfo && !hostInfoLogged) {
                hostInfoLogged = true;
                logf("host.info peer=%s platform=windows caps=0x%02x monitors=%d version=%s", peer.c_str(),
                     unsigned(kHostCaps), monitors, JERISLINK_VERSION_STRING);
            }
            break;
        }
        case jlh::kMsgKey:
        case jlh::kMsgMouseMoveRel:
        case jlh::kMsgMouseButton:
        case jlh::kMsgMouseScroll:
        case jlh::kMsgMouseMoveAbs:
        case jlh::kMsgMouseMoveNorm:
        case jlh::kMsgMouseButtonExt:
        case jlh::kMsgPointerSync:
        case jlh::kMsgForceQuitOpen: {
            const auto e = jlh::decodeInput(hdr, payload.data());
            if (!e) {
                ++st.inputMalformed;  // wrong length or button: dropped whole, like the Mac host
                break;
            }
            touch(st);
            if (!inputSeen) {
                inputSeen = true;
                logf("input.open peer=%s channel=%s", peer.c_str(), role);
            }
            // What was typed is never logged; only counts, in the stats line.
            const bool ok = jlh::stepInput(
                pendingSync, *e,
                [&](const jlh::InputEvent& s, const jlh::InputEvent* button) {
                    return applyPointerSync(st, s, button, owner);
                },
                [&](const jlh::InputEvent& ev) { return st.input.apply(ev, owner); });
            if (e->kind == jlh::InputEvent::Kind::TaskManager)
                logf("input.task_manager peer=%s sent=%s err=%lu", peer.c_str(), ok ? "yes" : "no",
                     ok ? 0ul : st.input.lastError());
            break;
        }
        default:
            break;  // clipboard data etc.: not yet
        }
    }
done:
    {
        // This connection went away: nothing it pressed stays down on this
        // PC, unless another connection of the viewer holds it too (Pepper's
        // H2 review, item 2). An up Windows refused earlier is tried again.
        const size_t n = st.input.releaseOwned(owner);
        if (inputSeen || n)
            logf("input.released peer=%s channel=%s released=%zu still_held=%s", peer.c_str(), role, n,
                 st.input.anyHeld() ? "yes" : "no");
    }
    logf("control.closed peer=%s channel=%s", peer.c_str(), role);
}

void controlListener(State& st, SOCKET ls) {
    while (st.running) {
        sockaddr_in from{};
        int len = sizeof(from);
        SOCKET c = accept(ls, reinterpret_cast<sockaddr*>(&from), &len);
        if (c == INVALID_SOCKET) {
            if (!st.running) break;
            continue;
        }
        if (from.sin_addr.s_addr != st.allowAddr.s_addr) {
            ++st.rejected;
            logf("control.rejected peer=%s reason=not_allowed", ipString(from.sin_addr).c_str());
            closesocket(c);
            continue;
        }
        if (!st.controlSlots.tryAcquire()) {
            logf("control.rejected peer=%s reason=too_many", ipString(from.sin_addr).c_str());
            closesocket(c);
            continue;
        }
        try {
            std::thread(serveControl, std::ref(st), c, ipString(from.sin_addr)).detach();
        } catch (const std::exception&) {
            logf("control.rejected peer=%s reason=no_thread", ipString(from.sin_addr).c_str());
            closesocket(c);
            st.controlSlots.release();
        }
    }
}

// --------------------------------------------------------------------- MRM1

void mrm1Listener(State& st, SOCKET u) {
    uint8_t b[2048];
    uint64_t lastLoggedKfr = 0;
    while (st.running) {
        sockaddr_in from{};
        int len = sizeof(from);
        const int n = recvfrom(u, reinterpret_cast<char*>(b), sizeof(b), 0, reinterpret_cast<sockaddr*>(&from), &len);
        if (n <= 0) continue;
        if (from.sin_addr.s_addr != st.allowAddr.s_addr) { ++st.rejected; continue; }
        const auto m = jlh::parseMrm1(b, size_t(n));
        if (!m) continue;  // only a valid 0x24, 0x40 or 0x43 counts as viewer activity
        touch(st);
        bool newSession;
        {
            std::lock_guard<std::mutex> g(st.pointerMutex);
            newSession = st.pointer.note(from.sin_addr.s_addr, from.sin_port);
        }
        if (newSession) {
            // A viewer socket not seen before: a new MRM1 session. Pointer
            // order starts over and the cursor loop sends the shape there.
            {
                std::lock_guard<std::mutex> g(st.mrm1PeerMutex);
                st.mrm1Peer = from;
                st.haveMrm1Peer = true;
                ++st.mrm1Generation;
            }
            logf("mrm1.session peer=%s:%u", ipString(from.sin_addr).c_str(), unsigned(ntohs(from.sin_port)));
        }
        if (m->type == jlh::kMrm1Pointer) {
            // Only the newest move counts; a late datagram, or one older than
            // the last POINTER_SYNC, is dropped.
            std::lock_guard<std::mutex> g(st.pointerMutex);
            if (st.pointer.takePointer(m->seq)) {
                ++st.pointerUdp;
                st.input.moveNormalized(m->nx, m->ny);
            } else {
                ++st.pointerUdpStale;
            }
        } else if (m->type == jlh::kMrm1KeyframeRequest) {
            st.keyframeRequested = true;
            const uint64_t k = ++st.keyframeRequests;
            if (k <= 3 || k - lastLoggedKfr >= 50) {
                logf("mrm1.keyframe_request seq=%u total=%llu", m->seq, (unsigned long long)k);
                lastLoggedKfr = k;
            }
        } else if (m->type == jlh::kMrm1Ping) {
            const auto pong = jlh::mrm1Pong(b, size_t(n));
            sendto(u, reinterpret_cast<const char*>(pong.data()), int(pong.size()), 0,
                   reinterpret_cast<const sockaddr*>(&from), len);
        }
        // 0x41 NACK, 0x42 receiver report, 0x45 audio: not yet, dropped by
        // parseMrm1.
    }
}

// ------------------------------------------------------------------- cursor

// Sends the cursor shape (MRM1 0x31) to the newest MRM1 session while a
// viewer is present: on a change at once, otherwise once a second so a lost
// datagram is repaired. Each session's seq starts from the tick count, so a
// viewer that outlives a host restart does not take the new packets for
// old ones.
void cursorLoop(State& st) {
    uint32_t gen = 0, seq = 0;
    bool haveShape = false;
    jlh::CursorShape last = jlh::CursorShape::Arrow;
    auto lastSent = Clock::now();
    uint64_t changesLogged = 0;
    while (st.running) {
        Sleep(kCursorPollMs);
        const bool active = st.controlConnections.load() > 0 ||
                            msSinceStart() - st.lastActivityMs.load() < kActiveGraceMs;
        if (!active) continue;
        sockaddr_in peer{};
        uint32_t g = 0;
        {
            std::lock_guard<std::mutex> lk(st.mrm1PeerMutex);
            if (!st.haveMrm1Peer) continue;
            peer = st.mrm1Peer;
            g = st.mrm1Generation;
        }
        if (g != gen) {
            gen = g;
            seq = uint32_t(GetTickCount64());
            haveShape = false;
        }
        const jlh::CursorShape shape = jlh::currentCursorShape();
        const auto now = Clock::now();
        const bool changed = !haveShape || shape != last;
        if (!changed && now - lastSent < std::chrono::milliseconds(kCursorResendMs)) continue;
        const auto pkt = jlh::mrm1Cursor(seq++, shape);
        if (sendto(st.mrm1Sock, reinterpret_cast<const char*>(pkt.data()), int(pkt.size()), 0,
                   reinterpret_cast<const sockaddr*>(&peer), sizeof(peer)) == int(pkt.size()))
            ++st.cursorSent;
        else
            ++st.cursorSendFail;
        if (changed && haveShape) {
            ++st.cursorChanges;
            if (changesLogged < 20) {
                ++changesLogged;
                logf("cursor.shape code=%u", unsigned(shape));
            }
        }
        last = shape;
        haveShape = true;
        lastSent = now;
    }
}

// -------------------------------------------------------------------- probe

int runProbe(const Options& o) {
    int failures = 0;
    jlh::ScreenCapture cap;
    std::string err;
    jlh::CapturedFrame f;
    if (!cap.open(o.capture, err)) {
        logf("probe.capture FAIL %s", err.c_str());
        return 2;
    }
    logf("probe.capture backend=%s %s", cap.backend(), cap.describe().c_str());
    // Up to 2 s for a frame. An acquire error reopens capture, as the
    // stream loop does, so Auto can move to GDI within the same probe
    // (e.g. after DDA fails to remake its staging texture).
    int r = 0;
    std::string lastErr;
    const auto deadline = Clock::now() + std::chrono::seconds(2);
    while (r != 1 && Clock::now() < deadline) {
        r = cap.acquire(100, f, err);
        if (r >= 0) continue;
        lastErr = err;
        logf("probe.capture lost %s; reopening", err.c_str());
        Sleep(100);
        if (!cap.open(o.capture, err)) {
            logf("probe.capture FAIL %s", err.c_str());
            return 2;
        }
        logf("probe.capture backend=%s %s", cap.backend(), cap.describe().c_str());
    }
    if (r != 1) {
        logf("probe.capture FAIL no frame in 2 s (%s)", lastErr.empty() ? "timeout" : lastErr.c_str());
        return 2;
    }
    logf("probe.capture OK size=%dx%d stride=%zu", f.width, f.height, f.stride);
    const jlh::DesktopRect dr = cap.desktopRect();
    logf("probe.desktop rect=%d,%d %dx%d virtual=%d,%d %dx%d monitors=%d cursor_shape=%u", dr.left, dr.top, dr.width,
         dr.height, GetSystemMetrics(SM_XVIRTUALSCREEN), GetSystemMetrics(SM_YVIRTUALSCREEN),
         GetSystemMetrics(SM_CXVIRTUALSCREEN), GetSystemMetrics(SM_CYVIRTUALSCREEN), GetSystemMetrics(SM_CMONITORS),
         unsigned(jlh::currentCursorShape()));
    if (!o.snapshotPath.empty())
        logf("probe.snapshot %s %s", o.snapshotPath.c_str(), writeBmp(o.snapshotPath, f) ? "written" : "FAILED");

    int w = 0, h = 0;
    jlh::fitEven(f.width, f.height, o.maxW, o.maxH, w, h);
    std::vector<uint8_t> nv12(size_t(w) * h * 3 / 2);
    auto t0 = Clock::now();
    jlh::bgraToNv12(f.bgra, f.width, f.height, f.stride, nv12.data(), w, h);
    const double convMs = std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
    jlh::MfH264Encoder enc;
    jlh::EncoderConfig ec{w, h, o.fps, o.bitrateMbps, o.fps};
    if (!enc.open(ec, err)) {
        logf("probe.encoder FAIL %s", err.c_str());
        return 3;
    }
    std::vector<uint8_t> au;
    bool key = false;
    double encMs = 0;
    size_t bytes = 0;
    int keys = 0, outputs = 0;
    for (int i = 0; i < 10; ++i) {
        t0 = Clock::now();
        if (!enc.encode(nv12.data(), int64_t(i) * 10'000'000 / o.fps, i == 0, au, key, err)) {
            logf("probe.encoder FAIL frame=%d %s", i, err.c_str());
            return 3;
        }
        encMs += std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
        if (!au.empty()) ++outputs;
        bytes += au.size();
        if (key) {
            ++keys;
            const auto types = jlh::annexBNalTypes(au.data(), au.size());
            std::string t;
            for (int x : types) t += std::to_string(x) + ",";
            logf("probe.encoder keyframe frame=%d bytes=%zu nal_types=%s", i, au.size(), t.c_str());
        }
    }
    if (outputs < 10 || keys < 1) ++failures;
    logf("probe.encoder %s size=%dx%d outputs=%d keyframes=%d bytes=%zu enc_ms_avg=%.1f nv12_ms=%.1f",
         failures ? "FAIL" : "OK", w, h, outputs, keys, bytes, encMs / 10, convMs);
    return failures ? 3 : 0;
}

// -------------------------------------------------------------------- video

class VideoSender {
public:
    explicit VideoSender(State& st) : pacer_(st.bitrateMbps) {
        s_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr = st.bindAddr;  // the viewer checks the source is the host it connected to
        bind(s_, reinterpret_cast<sockaddr*>(&a), sizeof(a));
        int sndbuf = 4 << 20;
        setsockopt(s_, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char*>(&sndbuf), sizeof(sndbuf));
        to_.sin_family = AF_INET;
        to_.sin_addr = st.allowAddr;
        to_.sin_port = htons(kVideoPort);
    }
    ~VideoSender() { closesocket(s_); }
    void setBitrate(int mbps) { pacer_.setBitrate(mbps); }

    // Returns packets sent; a datagram the socket refused is counted in
    // takeFailed() (design §8.4: H1 counted only what went out).
    size_t send(const std::vector<uint8_t>& au, bool key) {
        const auto packets = jlh::packetizeMr02(nextFrameId_++, au.data(), au.size(), key);
        size_t sent = 0;
        for (const auto& p : packets) {
            int64_t now = nowUs();
            int64_t wait = pacer_.waitUs(now, p.size());
            if (wait > 0) {
                spinUntil(now + wait);
                now = nowUs();
            }
            pacer_.spend(now, p.size());
            if (sendto(s_, reinterpret_cast<const char*>(p.data()), int(p.size()), 0,
                       reinterpret_cast<const sockaddr*>(&to_), sizeof(to_)) == int(p.size())) {
                ++sent;
                bytes_ += p.size();
            } else {
                ++failed_;
                lastError_ = WSAGetLastError();
            }
        }
        return sent;
    }
    uint64_t takeBytes() { const uint64_t b = bytes_; bytes_ = 0; return b; }
    uint64_t takeFailed() { const uint64_t f = failed_; failed_ = 0; return f; }
    int lastError() const { return lastError_; }

private:
    static int64_t nowUs() {
        return std::chrono::duration_cast<std::chrono::microseconds>(Clock::now().time_since_epoch()).count();
    }
    static void spinUntil(int64_t us) {
        while (nowUs() < us) {
            if (us - nowUs() > 2000) Sleep(1);
            else std::this_thread::yield();
        }
    }
    jlh::Pacer pacer_;
    SOCKET s_ = INVALID_SOCKET;
    sockaddr_in to_{};
    uint64_t nextFrameId_ = 1;
    uint64_t bytes_ = 0;
    uint64_t failed_ = 0;
    int lastError_ = 0;
};

void videoLoop(State& st) {
    const Options& o = st.opt;
    VideoSender sender(st);
    jlh::ScreenCapture cap;
    jlh::MfH264Encoder enc;
    std::string err;
    std::vector<uint8_t> nv12, au;
    int srcW = 0, srcH = 0;
    bool haveFrame = false, streaming = false, needKey = true, snapshotDone = o.snapshotPath.empty();
    int encodedBitrate = 0;
    const auto interval = std::chrono::microseconds(1'000'000 / o.fps);
    auto nextTick = Clock::now();
    auto lastSend = Clock::now() - std::chrono::hours(1), lastKey = lastSend;
    auto statsAt = Clock::now() + std::chrono::seconds(1);
    auto streamStart = Clock::now();
    uint64_t frameIndex = 0, nCaptured = 0, nEncoded = 0, nKeys = 0, nPackets = 0;
    uint64_t sendFailTotal = 0;
    double encMsSum = 0;
    jlh::DesktopRect desktop{};

    while (st.running) {
        if (o.seconds > 0 && msSinceStart() > int64_t(o.seconds) * 1000) break;
        const bool active = st.controlConnections.load() > 0 ||
                            msSinceStart() - st.lastActivityMs.load() < kActiveGraceMs;
        if (!active) {
            if (streaming) {
                logf("stream.idle reason=no_viewer_traffic");
                streaming = false;
                cap.close();
                enc.close();
                haveFrame = false;
            }
            Sleep(100);
            continue;
        }
        if (!streaming) {
            streaming = true;
            needKey = true;
            streamStart = Clock::now();
            logf("stream.start viewer=%s:%u", o.allowIp.c_str(), unsigned(kVideoPort));
        }
        if (std::strcmp(cap.backend(), "none") == 0) {
            if (!cap.open(o.capture, err)) {
                logf("capture.open FAIL %s; retry in 1 s", err.c_str());
                Sleep(1000);
                continue;
            }
            logf("capture.open backend=%s %s", cap.backend(), cap.describe().c_str());
            needKey = true;
        }

        // Cap the rate: wait for the next tick, then take the newest desktop
        // image (duplication accumulates changes) or wait for one.
        const auto now0 = Clock::now();
        if (now0 < nextTick) std::this_thread::sleep_until(nextTick);
        jlh::CapturedFrame f;
        const int r = cap.acquire(int(std::max<int64_t>(1, interval.count() / 1000)), f, err);
        if (r < 0) {
            logf("capture.lost %s; reopening", err.c_str());
            cap.close();
            Sleep(100);
            continue;
        }
        if (r == 1) {
            ++nCaptured;
            const jlh::DesktopRect dr = cap.desktopRect();
            if (dr.left != desktop.left || dr.top != desktop.top || dr.width != desktop.width ||
                dr.height != desktop.height) {
                desktop = dr;
                st.input.setDesktop(dr);  // the pointer lands on the monitor the viewer sees
                logf("input.desktop rect=%d,%d %dx%d", dr.left, dr.top, dr.width, dr.height);
            }
            if (f.width != srcW || f.height != srcH) {
                srcW = f.width;
                srcH = f.height;
                enc.close();
            }
            int w = 0, h = 0;
            jlh::fitEven(srcW, srcH, o.maxW, o.maxH, w, h);
            nv12.resize(size_t(w) * h * 3 / 2);
            jlh::bgraToNv12(f.bgra, f.width, f.height, f.stride, nv12.data(), w, h);
            haveFrame = true;
            st.streamW = w;
            st.streamH = h;
            if (!snapshotDone && Clock::now() - streamStart > std::chrono::seconds(10)) {
                snapshotDone = true;
                logf("stream.snapshot %s %s size=%dx%d", o.snapshotPath.c_str(),
                     writeBmp(o.snapshotPath, f) ? "written" : "FAILED", f.width, f.height);
            }
        }
        if (!haveFrame) continue;
        const auto now = Clock::now();
        const bool keyAsked = st.keyframeRequested.load() && now - lastKey >= std::chrono::milliseconds(kKeyframeMinGapMs);
        const bool stale = now - lastSend >= std::chrono::milliseconds(kStaticRefreshMs);
        if (r != 1 && !keyAsked && !stale && !needKey) continue;

        const int bitrate = st.bitrateMbps.load();
        if (!enc.isOpen() || encodedBitrate != bitrate) {
            int w = 0, h = 0;
            jlh::fitEven(srcW, srcH, o.maxW, o.maxH, w, h);
            jlh::EncoderConfig ec{w, h, o.fps, bitrate, o.fps};
            if (!enc.open(ec, err)) {
                logf("encoder.open FAIL %s", err.c_str());
                Sleep(1000);
                continue;
            }
            encodedBitrate = bitrate;
            sender.setBitrate(bitrate);
            needKey = true;
            logf("encoder.open mf_software_h264 size=%dx%d (source %dx%d) fps=%d bitrate_mbps=%d gop=%d", w, h, srcW,
                 srcH, o.fps, bitrate, o.fps);
        }
        bool forceKey = needKey || keyAsked;
        if (keyAsked) st.keyframeRequested = false;
        bool key = false;
        const auto t0 = Clock::now();
        if (!enc.encode(nv12.data(), int64_t(frameIndex++) * 10'000'000 / o.fps, forceKey, au, key, err)) {
            logf("encoder.error %s; reopening", err.c_str());
            enc.close();
            Sleep(100);
            continue;
        }
        encMsSum += std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
        nextTick = t0 + interval;
        if (au.empty()) continue;
        if (key) { ++nKeys; lastKey = Clock::now(); needKey = false; }
        else if (needKey) continue;  // nothing but a keyframe may start a stream
        nPackets += sender.send(au, key);
        ++nEncoded;
        lastSend = Clock::now();

        if (Clock::now() >= statsAt) {
            const double secs = 1.0 + std::chrono::duration<double>(Clock::now() - statsAt).count();
            statsAt = Clock::now() + std::chrono::seconds(1);
            const uint64_t sendFail = sender.takeFailed();
            sendFailTotal += sendFail;
            logf("stats size=%dx%d source=%dx%d capture_fps=%.1f sent_fps=%.1f mbps=%.2f keyframes=%llu "
                 "keyframe_requests=%llu enc_ms_avg=%.1f packets=%llu send_fail=%llu send_fail_total=%llu "
                 "send_err=%d control_conns=%d pings=%llu input=%llu input_fail=%llu input_ignored=%llu "
                 "input_malformed=%llu input_err=%lu pointer_udp=%llu pointer_udp_stale=%llu pointer_sync=%llu cursor_sent=%llu "
                 "cursor_fail=%llu cursor_changes=%llu backend=%s",
                 st.streamW.load(), st.streamH.load(), srcW, srcH, nCaptured / secs, nEncoded / secs,
                 sender.takeBytes() * 8.0 / 1e6 / secs, (unsigned long long)nKeys,
                 (unsigned long long)st.keyframeRequests.load(), nEncoded ? encMsSum / nEncoded : 0.0,
                 (unsigned long long)nPackets, (unsigned long long)sendFail, (unsigned long long)sendFailTotal,
                 sendFail ? sender.lastError() : 0, st.controlConnections.load(), (unsigned long long)st.pings.load(),
                 (unsigned long long)st.input.injected(), (unsigned long long)st.input.failed(),
                 (unsigned long long)st.input.ignored(), (unsigned long long)st.inputMalformed.load(),
                 st.input.lastError(), (unsigned long long)st.pointerUdp.load(),
                 (unsigned long long)st.pointerUdpStale.load(), (unsigned long long)st.pointerSyncs.load(),
                 (unsigned long long)st.cursorSent.load(),
                 (unsigned long long)st.cursorSendFail.load(), (unsigned long long)st.cursorChanges.load(),
                 cap.backend());
            nCaptured = nEncoded = nKeys = nPackets = 0;
            encMsSum = 0;
        }
    }
    enc.close();
    cap.close();
}

SOCKET listenOn(const in_addr& addr, uint16_t port, int type) {
    SOCKET s = socket(AF_INET, type, type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP);
    if (s == INVALID_SOCKET) return s;
    BOOL excl = TRUE;
    setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&excl), sizeof(excl));
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr = addr;
    a.sin_port = htons(port);
    if (bind(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0 || (type == SOCK_STREAM && listen(s, 16) != 0)) {
        logf("net.bind FAIL %s:%u err=%d", ipString(addr).c_str(), unsigned(port), WSAGetLastError());
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

}  // namespace

int main(int argc, char** argv) {
    Options o;
    std::string err;
    if (!parseArgs(argc, argv, o, err)) {
        std::fprintf(stderr, "JerisLinkHost: %s\n", err.c_str());
        std::fprintf(stderr,
                     "usage: JerisLinkHost --dev-no-password --bind <host ip> --allow <viewer ip> [--fps N] "
                     "[--bitrate Mbps] [--max-size WxH] [--capture auto|dda|gdi] [--log file] [--seconds N] "
                     "[--snapshot file.bmp]\n       JerisLinkHost --probe [--capture ...] [--snapshot file.bmp]\n");
        return 64;
    }
    if (!o.logPath.empty()) gLogFile = std::fopen(o.logPath.c_str(), "a");
    // Physical pixels on HiDPI screens: duplication and GDI see the real mode.
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    if (FAILED(CoInitializeEx(nullptr, COINIT_MULTITHREADED)) || FAILED(MFStartup(MF_VERSION, MFSTARTUP_LITE))) {
        logf("init FAIL com/mf");
        return 1;
    }
    logf("JerisLinkHost %s (H2: capture + MF software H.264 + MR02 + SendInput + cursor shape)",
         JERISLINK_VERSION_STRING);
    if (o.probe) {
        const int rc = runProbe(o);
        MFShutdown();
        return rc;
    }

    WSADATA wsa{};
    WSAStartup(MAKEWORD(2, 2), &wsa);
    static State st;
    gState = &st;
    st.opt = o;
    st.bitrateMbps = o.bitrateMbps;
    parseIpv4(o.bindIp, st.bindAddr);
    parseIpv4(o.allowIp, st.allowAddr);
    SetConsoleCtrlHandler(onConsoleCtrl, TRUE);
    logf("WARNING dev mode: no password; only %s may connect", o.allowIp.c_str());

    SOCKET ctl = listenOn(st.bindAddr, kControlPort, SOCK_STREAM);
    SOCKET mrm1 = listenOn(st.bindAddr, kMrm1Port, SOCK_DGRAM);
    if (ctl == INVALID_SOCKET || mrm1 == INVALID_SOCKET) return 2;
    st.mrm1Sock = mrm1;
    logf("listening control=tcp:%s:%u mrm1=udp:%s:%u video_to=%s:%u fps=%d bitrate_mbps=%d max=%dx%d",
         o.bindIp.c_str(), unsigned(kControlPort), o.bindIp.c_str(), unsigned(kMrm1Port), o.allowIp.c_str(),
         unsigned(kVideoPort), o.fps, o.bitrateMbps, o.maxW, o.maxH);
    std::thread(controlListener, std::ref(st), ctl).detach();
    std::thread(mrm1Listener, std::ref(st), mrm1).detach();
    std::thread(cursorLoop, std::ref(st)).detach();
    videoLoop(st);
    st.running = false;
    closesocket(ctl);
    closesocket(mrm1);
    logf("exit");
    MFShutdown();
    // Connection threads are detached and may sit in recv(): leave now.
    std::fflush(nullptr);
    ExitProcess(0);
}
