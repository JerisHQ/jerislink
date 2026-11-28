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
#include <mstcpip.h>
#include <windows.h>
#include "control_read.hpp"  // after the Winsock headers it uses
#ifndef TCP_MAXRT
#define TCP_MAXRT 5  // ws2ipdef.h, Windows Vista and later
#endif
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
// TCP limits on control connections (serveControl): keep-alive's first
// probe after this much silence, then one a second, and Windows gives up
// after 10 unanswered probes (about 13 s in all); data the viewer has not
// acknowledged for kMaxRetransmitS seconds closes the connection too.
constexpr ULONG kKeepAliveIdleMs = 3'000;
constexpr ULONG kKeepAliveIntervalMs = 1'000;
constexpr DWORD kMaxRetransmitS = 13;
// How often an up Windows did not take is tried again (InputClaims::retry),
// and how often the input owner's liveness is checked (InputClaims::expire).
constexpr int kUpRetryMs = 250;
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
    // but over more than one control connection at a time (a reconnect, or
    // a second viewer), so each connection gets its own owner number
    // (InputClaims::open), and only the input owner's frames go in (r8).
    jlh::InputInjector input;
    // Who the input owner is and what it holds down. Its lock comes first:
    // then pointerMutex, then the injector's own.
    jlh::InputClaims claims;
    std::atomic<uint64_t> inputTakeovers{0}, inputDropped{0}, inputUpRetried{0};
    // r9: owners that went quiet (expire), frames dropped while an up was
    // owed, UDP moves from another socket than the owner's or while an up
    // was owed.
    std::atomic<uint64_t> inputSilenced{0}, inputUpPending{0}, pointerUdpNotOwner{0}, pointerUdpUpPending{0};
    // r11: UDP moves dropped while the legacy rule was off.
    std::atomic<uint64_t> pointerUdpLegacyOff{0};
    // MRM1 pointer order. A UDP move and a POINTER_SYNC (control thread) both
    // take this, then the injector's own lock, in that order.
    std::mutex pointerMutex;
    jlh::Mrm1Session pointer;  // guarded by pointerMutex
    std::atomic<uint64_t> inputMalformed{0}, pointerUdp{0}, pointerUdpStale{0}, pointerSyncs{0};
    std::atomic<uint64_t> cursorSent{0}, cursorSendFail{0}, cursorChanges{0};
    // The MRM1 socket. The cursor shape goes from it (port 38412, the
    // viewer checks both) to the viewer socket the host takes pointer
    // moves from (r10: InputClaims::cursorPeer, Pepper's review of
    // f919167, item 3), never to whichever socket was heard from last.
    SOCKET mrm1Sock = INVALID_SOCKET;
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
// The seq belongs to the viewer's MRM1 socket (peerAddr, sync.port), which
// the host may not have heard from yet (Pepper's review of 8f8a33b, item
// 5a; Mrm1Session::syncPointer).
// button == nullptr: a sync not followed by a button, applied alone. Runs
// inside InputClaims::frame (its lock, then this one).
bool applyPointerSync(State& st, uint32_t peerAddr, const jlh::InputEvent& sync, const jlh::InputEvent* button,
                      jlh::HeldInput::Owner owner, jlh::HeldInput& held) {
    std::lock_guard<std::mutex> g(st.pointerMutex);
    st.pointer.syncPointer(peerAddr, sync.port, sync.seq, msSinceStart());
    ++st.pointerSyncs;
    st.input.moveNormalized(sync.x, sync.y);
    return button ? st.input.apply(*button, owner, held) : true;
}

// Runs on its own thread holding one of st.controlSlots, taken by the
// listener; every return path closes the socket and gives the slot back.
// r12 (Pepper's review of 9f803c6, item 2): the listener opened owner in
// InputClaims at accept, so the connection counts for its address from
// then; every return path closes it there too (done: below, or the guard).
void serveControl(State& st, SOCKET c, std::string peer, uint32_t peerAddr, jlh::HeldInput::Owner owner) {
    auto upKey = [&st](uint16_t v) { return st.input.upKey(v); };
    auto upButton = [&st](uint8_t b) { return st.input.upButton(b); };
    struct Release {
        State& st;
        SOCKET c;
        jlh::HeldInput::Owner owner;
        bool established = false;
        bool claimsClosed = false;
        ~Release() {
            if (!claimsClosed)  // before its first frame: it holds nothing
                st.claims.close(owner, [this](uint16_t v) { return st.input.upKey(v); },
                                [this](uint8_t b) { return st.input.upButton(b); });
            if (established) --st.controlConnections;
            closesocket(c);
            st.controlSlots.release();
        }
    } guard{st, c, owner};
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
    // Limits on a dead connection. The host writes to an idle control
    // connection only to answer a ping, so without them a dropped network
    // would keep the connection and its slot open, and for the input owner
    // what it holds down, until a newer connection takes over or the host
    // restarts. (r9: an owner that pings loses what it holds about 5 s
    // after its pings stop, InputClaims::expire; these limits still close
    // the connection.)
    // - TCP keep-alive: a connection the host has heard nothing on for 3 s
    //   is probed once a second, and closed after 10 unanswered probes,
    //   about 13 s after the last thing the host got from it, or at once
    //   when the viewer's side answers with a reset (its socket is gone).
    // - TCP_MAXRT: while something the host sent (a pong, a VIDEO_CONFIG
    //   ACK) is not acknowledged, keep-alive does not probe; that data going
    //   unacknowledged for 13 s closes the connection instead of Windows'
    //   own, longer retransmission limit.
    // r8 (InputClaims): a connection where either cannot be set is closed
    // here, before it can send anything, so it is never the input owner and
    // every owner has both limits.
    tcp_keepalive ka{1, kKeepAliveIdleMs, kKeepAliveIntervalMs};
    DWORD kaBytes = 0;
    if (WSAIoctl(c, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), nullptr, 0, &kaBytes, nullptr, nullptr) != 0) {
        logf("control.closed peer=%s reason=keepalive err=%d", peer.c_str(), WSAGetLastError());
        return;
    }
    const DWORD maxRt = kMaxRetransmitS;
    if (setsockopt(c, IPPROTO_TCP, TCP_MAXRT, reinterpret_cast<const char*>(&maxRt), sizeof(maxRt)) != 0) {
        logf("control.closed peer=%s reason=maxrt err=%d", peer.c_str(), WSAGetLastError());
        return;
    }
    ++st.controlConnections;
    guard.established = true;
    touch(st);
    const char* role = "control";
    bool first = true;
    bool hostInfoLogged = false, inputSeen = false, droppedLogged = false, upPending = false;
    std::optional<jlh::InputEvent> pendingSync;  // a POINTER_SYNC waiting for its button
    // r10 (Pepper's review of f919167, item 1): the connection is read in
    // short slices (control_read.hpp), and reading stops as soon as it
    // loses ownership for going quiet (InputClaims::expire, run by
    // inputRetryLoop): it is closed then, its slot comes back, and nothing
    // it sends afterwards is read. Not only at its next frame, which a hung
    // viewer never sends.
    const auto stopReading = [&] { return jlh::stopLiveRead(st.running.load(), st.claims, owner); };
    for (;;) {
        const jlh::ReadResult rr = jlh::readMrc1FrameUntil(c, hdr, payload, jlh::kReadSliceMs, stopReading);
        if (rr == jlh::ReadResult::Stopped && st.running) {
            logf("control.silenced_closed peer=%s channel=%s reason=liveness_timeout", peer.c_str(), role);
            goto done;
        }
        if (rr != jlh::ReadResult::Ok) break;
        // r11 (InputClaims::heard, Pepper's review of 5880264, items 1 and
        // 2): the first frame says what this connection is (a control
        // connection is counted for its address), and a ping after it is a
        // liveness ping.
        const jlh::InputClaims::Heard heard = st.claims.heard(owner, hdr, msSinceStart());
        if (first) {
            if (hdr.type == jlh::kMsgClipboardHello) role = "clipboard";
            else if (hdr.type == jlh::kMsgPing) role = "ping";
            logf("control.open peer=%s channel=%s auth=open_ip_only", peer.c_str(), role);
            if (heard.controls > 1)
                logf("control.shared_address peer=%s channel=%s controls=%zu legacy_udp=off", peer.c_str(), role,
                     heard.controls);
        }
        if (heard.refuse) {
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
            // r9 (InputClaims): a ping after the first frame is the viewer
            // UI's liveness signal; the first one arms this connection (r11:
            // nothing else does). One that lost ownership for going quiet is
            // closed, with no pong.
            if (heard.silenced) {
                logf("control.silenced_closed peer=%s channel=%s", peer.c_str(), role);
                goto done;
            }
            if (heard.armed)
                logf("input.liveness peer=%s channel=%s timeout_ms=%lld from=ping input_seen=%s", peer.c_str(), role,
                     (long long)jlh::kLivenessTimeoutMs, inputSeen ? "yes" : "no");
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
            // r11 (Pepper's review of 5880264, item 1): asking for HOST_INFO
            // no longer arms the connection (r10 did): H2 r1 to r8 viewers
            // ask and never ping. Only a liveness ping does (above).
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
                // r11: liveness=on: this connection pinged before its first
                // input (this viewer always does with a Windows host).
                logf("input.open peer=%s channel=%s liveness=%s", peer.c_str(), role,
                     st.claims.armed(owner) ? "on" : "off");
            }
            // r8 (InputClaims): only the input owner's frames go in. This
            // connection's first input makes it the owner when it opened
            // after every owner before it; the old owner's claims end first,
            // and its frames are dropped from then on. Admission, takeover
            // and injection are one step under the claims lock (Pepper's
            // review of 6175b5e, item 3). What was typed is never logged;
            // only counts, in the stats line.
            // r9: an owner that went quiet is closed; while an up is owed
            // only ups go in; a POINTER_SYNC names the owner's MRM1 socket.
            const auto f = st.claims.frame(
                owner, peerAddr, *e,
                [&](jlh::HeldInput& held) {
                    return jlh::stepInput(
                        pendingSync, *e,
                        [&](const jlh::InputEvent& s, const jlh::InputEvent* button) {
                            return applyPointerSync(st, peerAddr, s, button, owner, held);
                        },
                        [&](const jlh::InputEvent& ev) { return st.input.apply(ev, owner, held); });
                },
                upKey, upButton);
            if (f.tookOver) {
                st.inputTakeovers += f.replaced;
                logf("input.owner peer=%s channel=%s replaced=%zu released=%zu still_held=%s", peer.c_str(), role,
                     f.replaced, f.released, st.claims.anyHeld() ? "yes" : "no");
            }
            if (f.silenced) {
                ++st.inputDropped;
                logf("control.silenced_closed peer=%s channel=%s", peer.c_str(), role);
                goto done;
            }
            if (!f.admitted) {
                ++st.inputDropped;
                if (!droppedLogged) {
                    droppedLogged = true;
                    logf("input.dropped peer=%s channel=%s reason=not_owner", peer.c_str(), role);
                }
                break;
            }
            if (f.blocked) {
                // Never kept: a POINTER_SYNC waiting for its button goes too.
                pendingSync.reset();
                ++st.inputUpPending;
                if (!upPending) {
                    upPending = true;
                    logf("input.dropped peer=%s channel=%s reason=up_pending", peer.c_str(), role);
                }
                break;
            }
            upPending = false;
            if (e->kind == jlh::InputEvent::Kind::TaskManager)
                logf("input.task_manager peer=%s sent=%s err=%lu", peer.c_str(), f.injected ? "yes" : "no",
                     f.injected ? 0ul : st.input.lastError());
            break;
        }
        default:
            break;  // clipboard data etc.: not yet
        }
    }
done:
    {
        // This connection went away: nothing it pressed stays down on this
        // PC (Pepper's H2 review, item 2). It lets go of its own claims only
        // (review of f97ad11, item 1); a replaced connection has none left.
        // An up Windows refused earlier is tried again.
        const size_t n = st.claims.close(owner, upKey, upButton);
        guard.claimsClosed = true;
        if (inputSeen || n)
            logf("input.released peer=%s channel=%s released=%zu still_held=%s", peer.c_str(), role, n,
                 st.claims.anyHeld() ? "yes" : "no");
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
        // r12 (Pepper's review of 9f803c6, item 2): counted for its address
        // from now, before its handshake and first frame (InputClaims).
        const jlh::HeldInput::Owner owner = st.claims.open(uint32_t(from.sin_addr.s_addr));
        try {
            std::thread(serveControl, std::ref(st), c, ipString(from.sin_addr), uint32_t(from.sin_addr.s_addr), owner)
                .detach();
        } catch (const std::exception&) {
            logf("control.rejected peer=%s reason=no_thread", ipString(from.sin_addr).c_str());
            st.claims.close(owner, [&st](uint16_t v) { return st.input.upKey(v); },
                            [&st](uint8_t b) { return st.input.upButton(b); });
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
            newSession = st.pointer.note(from.sin_addr.s_addr, ntohs(from.sin_port), msSinceStart());
        }
        if (newSession) {
            // Another viewer socket than the last one heard (a new one, or
            // an older one whose datagram came late). Pointer order is that
            // socket's own and is kept across the switch (Mrm1Session,
            // Pepper's review of f97ad11, item 3). r10 (Pepper's review of
            // f919167, item 3): the cursor shape no longer follows it; it
            // goes where InputClaims takes moves from (cursorLoop).
            logf("mrm1.session peer=%s:%u", ipString(from.sin_addr).c_str(), unsigned(ntohs(from.sin_port)));
        }
        if (m->type == jlh::kMrm1Pointer) {
            // r9 (InputClaims::udpMove, Pepper's review of 0d74abe, item 2):
            // only from the input owner's own MRM1 socket, the one its
            // POINTER_SYNC named, and not while an up is owed. Then only the
            // newest move counts; a late datagram, or one older than the
            // last POINTER_SYNC, is dropped. r10 (item 2): a 0.4.x owner,
            // which names none, and a 0.4.x viewer hovering before its first
            // click, by the legacy rule (host_protocol.hpp).
            const auto r = st.claims.udpMove(from.sin_addr.s_addr, ntohs(from.sin_port), [&] {
                std::lock_guard<std::mutex> g(st.pointerMutex);
                if (!st.pointer.takePointer(m->seq)) return false;
                st.input.moveNormalized(m->nx, m->ny);
                return true;
            });
            switch (r) {
            case jlh::InputClaims::Udp::Moved: ++st.pointerUdp; break;
            case jlh::InputClaims::Udp::Stale: ++st.pointerUdpStale; break;
            case jlh::InputClaims::Udp::NotOwner: ++st.pointerUdpNotOwner; break;
            case jlh::InputClaims::Udp::UpPending: ++st.pointerUdpUpPending; break;
            case jlh::InputClaims::Udp::LegacyOff: {
                // r11 (Pepper's review of 5880264, item 2): not one viewer
                // alone on its address, or a second socket of it.
                const uint64_t k = ++st.pointerUdpLegacyOff;
                if (k <= 3 || k % 500 == 0)
                    logf("mrm1.legacy_off peer=%s:%u total=%llu", ipString(from.sin_addr).c_str(),
                         unsigned(ntohs(from.sin_port)), (unsigned long long)k);
                break;
            }
            }
        } else if (m->type == jlh::kMrm1KeyframeRequest) {
            // r12: InputClaims notes every socket it hears (Sock::with).
            st.claims.udpHeard(from.sin_addr.s_addr, ntohs(from.sin_port));
            st.keyframeRequested = true;
            const uint64_t k = ++st.keyframeRequests;
            if (k <= 3 || k - lastLoggedKfr >= 50) {
                logf("mrm1.keyframe_request seq=%u total=%llu", m->seq, (unsigned long long)k);
                lastLoggedKfr = k;
            }
        } else if (m->type == jlh::kMrm1Ping) {
            st.claims.udpHeard(from.sin_addr.s_addr, ntohs(from.sin_port));
            const auto pong = jlh::mrm1Pong(b, size_t(n));
            sendto(u, reinterpret_cast<const char*>(pong.data()), int(pong.size()), 0,
                   reinterpret_cast<const sockaddr*>(&from), len);
        }
        // 0x41 NACK, 0x42 receiver report, 0x45 audio: not yet, dropped by
        // parseMrm1.
    }
}

// r8 (Pepper's review of 6175b5e, item 4): an up Windows did not take (on a
// takeover, a close, the owner's own up, Task Manager) stays recorded with
// no owner, and is sent again every kUpRetryMs until Windows takes it.
// What a connection still holds is not touched: nothing is let go for
// being still.
// r9 (Pepper's review of 0d74abe, item 1): an owner whose liveness pings
// stopped for more than kLivenessTimeoutMs (host_protocol.hpp) loses
// ownership here, and what it holds is let go (InputClaims::expire). One
// that never pinged (an older viewer) is not touched.
// r10 (Pepper's review of f919167, item 1): the expired connection's reader
// stops within kReadSliceMs and closes it, giving its slot back
// (serveControl). r11: only a connection that sent a liveness ping counts
// (InputClaims::heard); asking for HOST_INFO no longer does.
void inputRetryLoop(State& st) {
    auto upKey = [&st](uint16_t v) { return st.input.upKey(v); };
    auto upButton = [&st](uint8_t b) { return st.input.upButton(b); };
    while (st.running) {
        Sleep(kUpRetryMs);
        const auto x = st.claims.expire(msSinceStart(), jlh::kLivenessTimeoutMs, upKey, upButton);
        if (x.owner) {
            ++st.inputSilenced;
            logf("input.owner_silent owner=%llu silent_ms=%lld released=%zu still_held=%s",
                 (unsigned long long)x.owner, (long long)x.silentMs, x.released, st.claims.anyHeld() ? "yes" : "no");
        }
        const size_t n = st.claims.retry(upKey, upButton);
        if (n) {
            st.inputUpRetried += n;
            logf("input.up_retried released=%zu still_held=%s", n, st.claims.anyHeld() ? "yes" : "no");
        }
    }
}

// ------------------------------------------------------------------- cursor

// Sends the cursor shape (MRM1 0x31) while a viewer is present: on a change
// at once, otherwise once a second so a lost datagram is repaired. Each
// destination's seq starts from the tick count, so a viewer that outlives a
// host restart does not take the new packets for old ones.
// r10 (Pepper's review of f919167, item 3): the destination is the viewer
// socket the host takes pointer moves from (InputClaims::cursorPeer: the
// owner's own socket, or a 0.4.x viewer's by the legacy rule), never the
// socket heard from last, so a replaced viewer's late datagram cannot take
// the cursor shape from the new owner. None: nothing is sent.
void cursorLoop(State& st) {
    uint64_t gen = 0;
    uint32_t seq = 0;
    bool haveShape = false;
    jlh::CursorShape last = jlh::CursorShape::Arrow;
    auto lastSent = Clock::now();
    uint64_t changesLogged = 0;
    while (st.running) {
        Sleep(kCursorPollMs);
        const bool active = st.controlConnections.load() > 0 ||
                            msSinceStart() - st.lastActivityMs.load() < kActiveGraceMs;
        if (!active) continue;
        const jlh::InputClaims::CursorPeer to = st.claims.cursorPeer();
        if (!to.named) continue;
        sockaddr_in peer{};
        peer.sin_family = AF_INET;
        peer.sin_addr.s_addr = to.ip;  // as recvfrom gave it: network order
        peer.sin_port = htons(to.port);
        if (to.gen != gen) {
            gen = to.gen;
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
                 "send_err=%d control_conns=%d pings=%llu input=%llu input_fail=%llu input_ignored=%llu input_up_held=%llu "
                 "input_takeover=%llu input_dropped=%llu input_up_retry=%llu input_silenced=%llu input_up_pending=%llu "
                 "input_malformed=%llu input_err=%lu pointer_udp=%llu pointer_udp_stale=%llu pointer_udp_not_owner=%llu "
                 "pointer_udp_up_pending=%llu pointer_udp_legacy_off=%llu pointer_sync=%llu cursor_sent=%llu "
                 "cursor_fail=%llu cursor_changes=%llu backend=%s",
                 st.streamW.load(), st.streamH.load(), srcW, srcH, nCaptured / secs, nEncoded / secs,
                 sender.takeBytes() * 8.0 / 1e6 / secs, (unsigned long long)nKeys,
                 (unsigned long long)st.keyframeRequests.load(), nEncoded ? encMsSum / nEncoded : 0.0,
                 (unsigned long long)nPackets, (unsigned long long)sendFail, (unsigned long long)sendFailTotal,
                 sendFail ? sender.lastError() : 0, st.controlConnections.load(), (unsigned long long)st.pings.load(),
                 (unsigned long long)st.input.injected(), (unsigned long long)st.input.failed(),
                 (unsigned long long)st.input.ignored(), (unsigned long long)st.input.upsHeld(),
                 (unsigned long long)st.inputTakeovers.load(), (unsigned long long)st.inputDropped.load(),
                 (unsigned long long)st.inputUpRetried.load(), (unsigned long long)st.inputSilenced.load(),
                 (unsigned long long)st.inputUpPending.load(), (unsigned long long)st.inputMalformed.load(),
                 st.input.lastError(), (unsigned long long)st.pointerUdp.load(),
                 (unsigned long long)st.pointerUdpStale.load(), (unsigned long long)st.pointerUdpNotOwner.load(),
                 (unsigned long long)st.pointerUdpUpPending.load(), (unsigned long long)st.pointerUdpLegacyOff.load(),
                 (unsigned long long)st.pointerSyncs.load(),
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
    std::thread(inputRetryLoop, std::ref(st)).detach();
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
