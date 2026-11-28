// JerisLink Windows host, H3 (design doc 2026-11-27, phases H1 to H3).
//
// H1: captures the screen, encodes H.264 with the Media Foundation software
// encoder and sends it as MR02 to one viewer, so the existing viewer shows
// the picture.
// H2: the viewer's keyboard and mouse (MRC1 0x10, 0x20-0x25, MRM1 0x24) go
// in with SendInput, the Force Quit button (MRC1 0x60) opens Task Manager,
// the cursor shape goes back as MRM1 0x31, and MRC1 0x06 HOST_INFO tells a
// new viewer it talks to Windows.
// H3: the connection password, as the macOS host v0.4.0 (PR-C) does it
// (host_auth.hpp, host_auth_conn.hpp): every TCP connection authenticates
// (0x05 CHALLENGE, 0x03 RESPONSE, 0x04 RESULT), the newest manual control
// login takes over and every older connection is void at once, failures
// lock the address and the 20th blacklists it, and every UDP datagram both
// ways carries an 8-byte tag under the session key. The settings live in
// HKLM\SOFTWARE\Jeris\JerisLinkHost (host_config_win.hpp; the key under
// DPAPI); the connection settings window (settings_window.cpp) sets them.
// There is no mode without a password (D9): with none set the host does not
// listen.
// No audio, clipboard, files, NACK or ABR yet.
//
//   JerisLinkHost.exe [--bind <tailnet ip>] [--fps 30] [--bitrate 25]
//                     [--max-size 1920x1080] [--capture auto|dda|gdi]
//                     [--log file] [--seconds N] [--snapshot file.bmp]
//   JerisLinkHost.exe --connection-settings
//   JerisLinkHost.exe --probe [--capture ...] [--snapshot file.bmp]
//
// Runs elevated (the key is readable by SYSTEM and Administrators only).
// Ports as the macOS host: control TCP 38400, MRM1 UDP 38412 on the bind
// address (--bind, else the registry's BindIP, else this PC's lowest
// tailnet IPv4; never another interface); video to the session viewer's
// 38402 from the bind address.
// Exit codes: 64 bad arguments, 77 not elevated, 78 no password (or the
// settings do not read, or the registry's listen settings are wrong). With
// no tailnet address up yet the host waits for one.

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
#include "host_auth_conn.hpp"
#include "host_config_win.hpp"
#include "settings_window.hpp"
#include <mfapi.h>
#include <objbase.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <exception>
#include <fstream>
#include <memory>
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
constexpr int kCursorPollMs = 16;           // cursor shape check
constexpr int kCursorResendMs = 1000;       // unchanged shape re-sent this often (UDP loss repair)
constexpr uint32_t kHostCaps = jlh::kHostCapKeyboard | jlh::kHostCapPointer | jlh::kHostCapCursorShape |
                               jlh::kHostCapTaskManager | jlh::kHostCapPointerSync;

struct Options {
    bool probe = false;
    bool connectionSettings = false;
    std::string bindIp, logPath, snapshotPath;
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
    char msg[2048];
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    SYSTEMTIME st;
    GetLocalTime(&st);
    char line[2200];
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
        if (k == "--dev-no-password" || k == "--allow") {
            // H3 (D9): no mode without a password, no single allowed IP.
            err = k + " was removed in H3: set a password with --connection-settings";
            return false;
        }
        else if (k == "--probe") o.probe = true;
        else if (k == "--connection-settings") o.connectionSettings = true;
        else if (k == "--bind") { if (!val(o.bindIp)) return false; }
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
    if (o.probe && o.connectionSettings) {
        err = "--probe and --connection-settings do not go together";
        return false;
    }
    if (o.probe || o.connectionSettings) return true;
    // D11: only a tailnet address, never 0.0.0.0 or another interface.
    if (!o.bindIp.empty() && !jlh::auth::isTailnetIpv4(o.bindIp)) {
        err = "--bind must be a tailnet IPv4 on this PC (100.64.0.0/10), got " + o.bindIp;
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
    in_addr bindAddr{};
    std::string bindIp;
    // H3: the password (main() builds these before anything listens). The
    // broker says which viewer the UDP paths serve and under which key
    // (SessionBroker::current); nobody else is sent to or heard.
    jlh::auth::AuthEnv* auth = nullptr;
    jlh::auth::SessionBroker* broker = nullptr;
    jlh::auth::AuthGuard* guard = nullptr;
    jlh::auth::BadTagLog* mrm1BadTag = nullptr;
    // UDP counters (the Mac's mouse_udp_* names, in the stats line).
    std::atomic<uint64_t> udpNoSession{0}, udpRejected{0}, udpBad{0}, udpReplay{0}, udpStale{0}, udpLateOk{0};
    std::atomic<uint64_t> pongDrops{0};
    std::atomic<bool> running{true};
    std::atomic<int> controlConnections{0};  // past the handshake: these keep the stream active
    jlh::ConnectionSlots controlSlots;  // H3 r2: handshakes capped in all and per address
    std::atomic<bool> keyframeRequested{false};
    std::atomic<int> bitrateMbps{25};
    std::atomic<int> streamW{0}, streamH{0};
    // counters, read by the stats line
    std::atomic<uint64_t> keyframeRequests{0}, pings{0};
    // H2 input. One injector for every connection. More than one control
    // connection can be open at a time (a reconnect, a takeover in flight),
    // so each gets its own owner number, H3: its broker token
    // (InputClaims::openAs), and only the input owner's frames go in (r8).
    jlh::InputInjector input;
    // Who the input owner is and what it holds down. Its lock comes first:
    // then pointerMutex, then the injector's own.
    jlh::InputClaims claims;
    std::atomic<uint64_t> inputTakeovers{0}, inputDropped{0}, inputUpRetried{0};
    // H3: input owners retired because the broker voided them.
    std::atomic<uint64_t> inputOwnerVoided{0};
    // r9: owners that went quiet (expire), frames dropped while an up was
    // owed, UDP moves from another socket than the owner's or while an up
    // was owed.
    std::atomic<uint64_t> inputSilenced{0}, inputUpPending{0}, pointerUdpNotOwner{0}, pointerUdpUpPending{0};
    // r14: UDP moves dropped because the owner named no socket (a 0.4.x
    // viewer run without --mouse-move-transport tcp).
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

BOOL WINAPI onConsoleCtrl(DWORD) {
    if (gState) gState->running = false;
    return TRUE;
}

std::string ipString(const in_addr& a) {
    char b[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &a, b, sizeof(b));
    return b;
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
// listener; every return path closes the socket and gives the place back.
// H3 r2: the handshake place goes back as soon as the password matched.
// H3: the connection authenticates first (AuthConn, the Mac's
// ControlServer). Only an admitted connection opens its owner in
// InputClaims, numbered by its broker token (InputClaims::openAs), counts
// as a viewer and is read from; every frame goes through admitMessage (the
// policy, the blacklist, the channel) and every frame back through
// sendChecked. A takeover, a password or whitelist change, a block or the
// journal lockdown voids it in the broker; its reader stops within one
// read slice, and a control line replaced by a newer login gets REPLACED
// (AuthConn::finish).
void serveControl(State& st, SOCKET c, std::string peer, uint32_t peerAddr) {
    auto upKey = [&st](uint16_t v) { return st.input.upKey(v); };
    auto upButton = [&st](uint8_t b) { return st.input.upButton(b); };
    jlh::auth::AuthConn ac(*st.auth, c, peer);
    struct Release {
        State& st;
        SOCKET c;
        const jlh::auth::AuthConn& ac;
        uint32_t source;
        jlh::HeldInput::Owner owner = 0;  // 0: never admitted, no claims opened
        bool established = false;
        bool claimsClosed = false;
        bool inHandshake = true;
        ~Release() {
            if (owner && !claimsClosed)  // before its first frame: it holds nothing
                st.claims.close(owner, [this](uint16_t v) { return st.input.upKey(v); },
                                [this](uint8_t b) { return st.input.upButton(b); });
            if (established) --st.controlConnections;
            jlh::auth::finishSocket(c, ac.resetRequested());
            st.controlSlots.release(source, inHandshake);
        }
    } guard{st, c, ac, peerAddr};
    // H3 (the Mac r12): the listener made the socket non-blocking
    // (acceptStep); every wait is a select() slice that asks whether the
    // connection was voided first.
    BOOL nodelay = TRUE;
    setsockopt(c, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));
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
    // every owner has both limits. H3: set before the password, so nothing
    // after it can fail this way.
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

    const auto ok = ac.authenticate();  // refusals are answered and logged there
    if (!ok) return;
    st.controlSlots.authenticated(peerAddr);
    guard.inHandshake = false;
    const auto life = std::make_shared<jlh::auth::ConnLife>();
    const auto token = ac.admit(*ok, life);  // a control login takes over here
    if (!token) return;
    const jlh::HeldInput::Owner owner = *token;
    st.claims.openAs(owner);
    guard.owner = owner;
    const bool isControl = ok->channel == jlh::auth::Channel::Control;
    const char* role = jlh::auth::channelName(ok->channel);
    ++st.controlConnections;
    guard.established = true;
    logf("control.open peer=%s channel=%s auth=password session=%s", peer.c_str(), role,
         isControl ? jlh::auth::hex(ok->sessionId).c_str() : "-");

    jlh::Mrc1Header hdr;
    std::vector<uint8_t> payload;
    bool first = true;
    bool hostInfoLogged = false, inputSeen = false, droppedLogged = false, upPending = false;
    std::optional<jlh::InputEvent> pendingSync;  // a POINTER_SYNC waiting for its button
    // r10 (Pepper's review of f919167, item 1): the connection is read in
    // short slices (control_read.hpp), and reading stops as soon as it
    // loses ownership for going quiet (InputClaims::expire, run by
    // inputRetryLoop): it is closed then, its slot comes back, and nothing
    // it sends afterwards is read. Not only at its next frame, which a hung
    // viewer never sends. H3: also as soon as the broker voided it.
    const auto stopReading = [&] {
        return life->revoked() || jlh::stopLiveRead(st.running.load(), st.claims, owner);
    };
    // A pong or a VIDEO_CONFIG reply. A control line voided by a takeover is
    // kept for its REPLACED notice; anything else refused is reset.
    const auto reply = [&](const char* kind, const std::vector<uint8_t>& framed) {
        return ac.sendCheckedFramed(life.get(), kind, framed, -1, isControl) == jlh::auth::CheckedSend::Sent;
    };
    for (;;) {
        const jlh::ReadResult rr = jlh::readMrc1FrameUntil(c, hdr, payload, jlh::kReadSliceMs, stopReading);
        if (rr == jlh::ReadResult::Stopped && st.running && !life->revoked()) {
            logf("control.silenced_closed peer=%s channel=%s reason=liveness_timeout", peer.c_str(), role);
            goto done;
        }
        if (rr != jlh::ReadResult::Ok) break;
        // H3 (the Mac serveAdmitted): nothing a voided connection read is
        // acted on, a blocked peer is reset, and a channel takes only the
        // messages it authenticated for.
        if (!ac.admitMessage(*ok, *life, hdr.type, first)) break;
        // r11 (InputClaims::heard, Pepper's review of 5880264, item 1): a
        // ping after the first frame is a liveness ping; a FILE_HELLO first
        // is refused.
        const jlh::InputClaims::Heard heard = st.claims.heard(owner, hdr, msSinceStart());
        if (heard.refuse) {
            // No file transfer yet: the viewer reads a close as refused.
            logf("control.file_refused peer=%s reason=not_in_h3", peer.c_str());
            break;
        }
        first = false;
        // H3: input and VIDEO_CONFIG only on the control channel.
        switch (hdr.type) {
        case jlh::kMsgPing:
            if (!jlh::isValidPing(hdr)) break;  // like the Mac host: no reply to other sizes
            ++st.pings;
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
            if (!reply("ping", jlh::mrc1Frame(jlh::kMsgPong, payload))) goto done;
            break;
        case jlh::kMsgVideoConfig: {
            if (!isControl) break;
            const auto d = jlh::decideVideoConfig(payload.data(), payload.size(), st.bitrateMbps.load(),
                                                  st.streamW.load(), st.streamH.load());
            if (d.accepted && d.bitrateChanged) st.bitrateMbps = d.bitrateMbps;
            // HOST_INFO rides behind the ACK, in the same send, only when this
            // VIDEO_CONFIG said the viewer reads it (host_protocol.hpp says
            // why): an older viewer gets the ACK alone, as from H1.
            const int monitors = std::clamp(GetSystemMetrics(SM_CMONITORS), 0, 255);
            const auto out = jlh::videoConfigReply(
                d, jlh::hostInfoPayload(jlh::kPlatformWindows, kHostCaps, uint8_t(monitors), JERISLINK_VERSION_STRING));
            if (!reply("video_config", out)) goto done;
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
            if (!isControl) break;
            const auto e = jlh::decodeInput(hdr, payload.data());
            if (!e) {
                ++st.inputMalformed;  // wrong length or button: dropped whole, like the Mac host
                break;
            }
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
            // H3: the epoch is asked again under the claims lock, which a
            // void takes (SessionBroker::onVoid, InputClaims::retire): a
            // frame read before a takeover goes in before the new viewer's
            // AUTH_OK, or not at all (the Mac r11 whileLive rule).
            const auto f = st.claims.frameIfLive(
                owner, peerAddr, *e, [&] { return !life->revoked(); },
                [&](jlh::HeldInput& held) {
                    return jlh::stepInput(
                        pendingSync, *e,
                        [&](const jlh::InputEvent& s, const jlh::InputEvent* button) {
                            return applyPointerSync(st, peerAddr, s, button, owner, held);
                        },
                        [&](const jlh::InputEvent& ev) { return st.input.apply(ev, owner, held); });
                },
                upKey, upButton);
            if (f.revoked) {
                ++st.inputDropped;
                logf("input.dropped peer=%s channel=%s reason=voided; connection closing", peer.c_str(), role);
                goto done;
            }
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
    // REPLACED for a control line a newer login took over; then it leaves
    // the broker.
    const auto why = life->kickReason();
    ac.finish(*ok, *token, *life);
    logf("control.closed peer=%s channel=%s reason=%s", peer.c_str(), role,
         why ? jlh::auth::closeReasonName(*why) : "closed");
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
        // H3 r2 (Pepper's review r1, item 1): an address the guard refuses
        // (blacklist, whitelist, its wait, the host-wide wait, a lockdown)
        // is answered and closed here, before a worker or a place; the
        // rest take a place, with handshakes capped in all and per address
        // (the AUTH timeout, 5 s, bounds each, and counts as a failure).
        const std::string peer = ipString(from.sin_addr);
        const uint32_t source = uint32_t(from.sin_addr.s_addr);
        if (jlh::auth::acceptStep(*st.auth, st.controlSlots, c, peer, source) != jlh::auth::AcceptVerdict::Serve) {
            closesocket(c);
            continue;
        }
        try {
            std::thread(serveControl, std::ref(st), c, peer, source).detach();
        } catch (const std::exception&) {
            logf("control.rejected peer=%s reason=no_thread", peer.c_str());
            closesocket(c);
            st.controlSlots.release(source, true);
        }
    }
}

// --------------------------------------------------------------------- MRM1

// The viewer the UDP paths serve (SessionBroker::current), looked up again
// only when the broker's generation moved: one atomic load per datagram
// while it holds.
struct SessionView {
    uint64_t gen = UINT64_MAX;  // never a real generation: the first look fetches
    std::shared_ptr<const jlh::auth::UdpSession> s;  // nullptr: no viewer
    in_addr addr{};

    void refresh(jlh::auth::SessionBroker& b) {
        const uint64_t g = b.generation();
        if (g == gen) return;
        s = b.current();
        gen = s ? s->generation : g;
        addr = in_addr{};
        if (s && !parseIpv4(s->peerIp, addr)) s.reset();
    }
};

// One datagram to `to`, sealed with the session's h2v tag (flag 0x80 on
// byte 4, 8 bytes appended). False: not sent (no taggers, too long, or the
// socket refused it). H3 r2: callers send under the broker's send gate
// (SessionBroker::sendIfCurrent), so no datagram goes out under a session
// that was voided before it started.
bool sendSealed(SOCKET s, const jlh::auth::UdpSession& sess, const uint8_t* p, size_t n, const sockaddr_in& to) {
    if (!sess.tags) return false;
    uint8_t out[2048];
    if (n + jlh::auth::kTagBytes > sizeof(out)) return false;
    const size_t m = sess.tags->seal(p, n, out);
    if (!m) return false;
    return sendto(s, reinterpret_cast<const char*>(out), int(m), 0, reinterpret_cast<const sockaddr*>(&to),
                  sizeof(to)) == int(m);
}

// H3 (the Mac MouseMoveUDPServer, PR-C): a datagram counts only when it
// comes from the session's viewer address with a good v2h tag; then the tag
// comes off and the datagram is checked for format and against a 64-packet
// anti-replay window, fresh for each session generation (a new AUTH). Only
// after all three does anything move: the pointer, the socket, keyframe
// requests, pongs. A forged, replayed or malformed datagram changes nothing
// and is never answered (bad tags: one log line per 10 s, BadTagLog).
// A port change within one generation (NAT rebinding) keeps the window, so
// a recorded datagram cannot be replayed from another port.
void mrm1Listener(State& st, SOCKET u) {
    uint8_t b[2048];
    uint64_t lastLoggedKfr = 0;
    SessionView sv;
    uint64_t windowGen = 0;  // the generation `window` belongs to (0: none yet)
    jlh::auth::SeqReplayWindow window;
    while (st.running) {
        sockaddr_in from{};
        int len = sizeof(from);
        int n = recvfrom(u, reinterpret_cast<char*>(b), sizeof(b), 0, reinterpret_cast<sockaddr*>(&from), &len);
        if (n <= 0) continue;
        sv.refresh(*st.broker);
        if (!sv.s) {
            ++st.udpNoSession;
            continue;
        }
        if (from.sin_addr.s_addr != sv.addr.s_addr) {
            ++st.udpRejected;
            continue;
        }
        const std::string& peer = sv.s->peerIp;
        if (!sv.s->tags || !sv.s->tags->verify(b, size_t(n))) {
            st.mrm1BadTag->drop(peer, sv.s->tags ? jlh::auth::badTagReason(b, size_t(n)) : "no_taggers");
            continue;
        }
        n -= int(jlh::auth::kTagBytes);
        b[jlh::auth::kUdpVersionByte] &= uint8_t(~jlh::auth::kUdpTagFlag);
        const bool newGen = sv.s->generation != windowGen;
        const auto m = jlh::parseMrm1(b, size_t(n));
        if (!m) {
            // 0x41 NACK, 0x42 receiver report, 0x45 audio: not yet, not
            // counted. Anything else is malformed.
            const bool known = n >= 10 && std::memcmp(b, "MRM1", 4) == 0 && b[4] == 1 &&
                               (b[5] == 0x41 || b[5] == 0x42 || b[5] == 0x45);
            if (!known) ++st.udpBad;
            continue;
        }
        jlh::auth::SeqReplayWindow w = newGen ? jlh::auth::SeqReplayWindow{} : window;
        switch (w.check(m->seq)) {
        case jlh::auth::SeqReplayWindow::Verdict::Newest:
            break;
        case jlh::auth::SeqReplayWindow::Verdict::Late:
            w.mark(m->seq);
            if (m->type == jlh::kMrm1Pointer) {
                // A move sets the pointer: only the newest counts.
                window = w;
                ++st.udpStale;
                continue;
            }
            ++st.udpLateOk;
            break;
        case jlh::auth::SeqReplayWindow::Verdict::Duplicate:
            ++st.udpReplay;
            continue;
        case jlh::auth::SeqReplayWindow::Verdict::TooOld:
            ++st.udpStale;
            continue;
        }
        // Accepted: now the state moves.
        window = w;
        if (newGen) {
            windowGen = sv.s->generation;
            logf("mrm1.session gen=%llu peer=%s:%u", (unsigned long long)windowGen, peer.c_str(),
                 unsigned(ntohs(from.sin_port)));
        }
        bool newSocket;
        {
            std::lock_guard<std::mutex> g(st.pointerMutex);
            newSocket = st.pointer.note(from.sin_addr.s_addr, ntohs(from.sin_port), msSinceStart());
        }
        if (newSocket && !newGen) {
            // Another viewer socket than the last one heard. Pointer order
            // is that socket's own and is kept across the switch
            // (Mrm1Session, Pepper's review of f97ad11, item 3). r10
            // (Pepper's review of f919167, item 3): the cursor shape does
            // not follow it; it goes where InputClaims takes moves from
            // (cursorLoop).
            logf("mrm1.socket peer=%s:%u gen=%llu", peer.c_str(), unsigned(ntohs(from.sin_port)),
                 (unsigned long long)windowGen);
        }
        if (m->type == jlh::kMrm1Pointer) {
            // r9 (InputClaims::udpMove, Pepper's review of 0d74abe, item 2):
            // only from the input owner's own MRM1 socket, the one its
            // POINTER_SYNC named, and not while an up is owed. Then only the
            // newest move counts; a late datagram, or one older than the
            // last POINTER_SYNC, is dropped. r14 (Pepper's review of
            // 524e4d1): a 0.4.x owner names none, so none of its UDP moves
            // goes in (LegacyOff); it runs with --mouse-move-transport tcp.
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
                // r14: the owner never sent a POINTER_SYNC (0.4.x without
                // --mouse-move-transport tcp).
                const uint64_t k = ++st.pointerUdpLegacyOff;
                if (k <= 3 || k % 500 == 0)
                    logf("mrm1.legacy_off peer=%s:%u total=%llu", peer.c_str(), unsigned(ntohs(from.sin_port)),
                         (unsigned long long)k);
                break;
            }
            }
        } else if (m->type == jlh::kMrm1KeyframeRequest) {
            st.keyframeRequested = true;
            const uint64_t k = ++st.keyframeRequests;
            if (k <= 3 || k - lastLoggedKfr >= 50) {
                logf("mrm1.keyframe_request seq=%u total=%llu", m->seq, (unsigned long long)k);
                lastLoggedKfr = k;
            }
        } else if (m->type == jlh::kMrm1Ping) {
            // The Mac r9: a blocked viewer (or a journal lockdown) gets no
            // pong. The pong goes only while the session it came in is
            // still the current one, sealed with its key (H3 r2: checked
            // and sent under the broker's send gate).
            if (st.guard->inputRefusal(peer)) {
                ++st.pongDrops;
                continue;
            }
            const auto pong = jlh::mrm1Pong(b, size_t(n));
            bool sent = false;
            if (!st.broker->sendIfCurrent(sv.s->generation,
                                          [&] { sent = sendSealed(u, *sv.s, pong.data(), pong.size(), from); }) ||
                !sent)
                ++st.pongDrops;
        }
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
// socket the owner named in its POINTER_SYNC), never the socket heard from
// last, so a replaced viewer's late datagram cannot take the cursor shape
// from the new owner. None (r14: a 0.4.x owner, or no owner): nothing is
// sent.
// H3: only while there is a session, only to its viewer's address, sealed
// with its key; a new session starts the seq again.
void cursorLoop(State& st) {
    uint64_t gen = 0, sessionGen = 0;
    uint32_t seq = 0;
    bool haveShape = false;
    jlh::CursorShape last = jlh::CursorShape::Arrow;
    auto lastSent = Clock::now();
    uint64_t changesLogged = 0;
    SessionView sv;
    while (st.running) {
        Sleep(kCursorPollMs);
        sv.refresh(*st.broker);
        if (!sv.s) continue;
        const jlh::InputClaims::CursorPeer to = st.claims.cursorPeer();
        if (!to.named || to.ip != sv.addr.s_addr) continue;
        sockaddr_in peer{};
        peer.sin_family = AF_INET;
        peer.sin_addr.s_addr = to.ip;  // as recvfrom gave it: network order
        peer.sin_port = htons(to.port);
        if (to.gen != gen || sv.s->generation != sessionGen) {
            gen = to.gen;
            sessionGen = sv.s->generation;
            seq = uint32_t(GetTickCount64());
            haveShape = false;
        }
        const jlh::CursorShape shape = jlh::currentCursorShape();
        const auto now = Clock::now();
        const bool changed = !haveShape || shape != last;
        if (!changed && now - lastSent < std::chrono::milliseconds(kCursorResendMs)) continue;
        const auto pkt = jlh::mrm1Cursor(seq++, shape);
        bool sent = false;
        if (!st.broker->sendIfCurrent(sv.s->generation,
                                      [&] { sent = sendSealed(st.mrm1Sock, *sv.s, pkt.data(), pkt.size(), peer); }))
            continue;  // the session moved: the next poll starts over for the new one
        if (sent)
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
        to_.sin_port = htons(kVideoPort);
    }
    ~VideoSender() { closesocket(s_); }
    void setBitrate(int mbps) { pacer_.setBitrate(mbps); }

    // A datagram the socket refused is counted in takeFailed() (design
    // §8.4: H1 counted only what went out). H3: to the session's viewer,
    // sealed with its key (the Mac UDPFrameSender: 1200-byte packets plus
    // the 8-byte tag). H3 r2 (Pepper's review r1, item 2): every packet is
    // checked against the session and sent under the broker's send gate;
    // a session change mid-frame ends the frame (cut).
    jlh::auth::FrameSend send(const std::vector<uint8_t>& au, bool key, jlh::auth::SessionBroker& broker,
                              const jlh::auth::UdpSession& sess, const in_addr& viewer) {
        to_.sin_addr = viewer;
        const auto packets = jlh::packetizeMr02(nextFrameId_++, au.data(), au.size(), key);
        const auto r = jlh::auth::sendFrameWhileCurrent(
            broker, sess.generation, packets.size(),
            [&](size_t i) {
                const size_t n = packets[i].size();
                int64_t now = nowUs();
                const int64_t wait = pacer_.waitUs(now, n);
                if (wait > 0) {
                    spinUntil(now + wait);
                    now = nowUs();
                }
                pacer_.spend(now, n + jlh::auth::kTagBytes);
            },
            [&](size_t i) {
                const auto& p = packets[i];
                if (sendSealed(s_, sess, p.data(), p.size(), to_)) {
                    bytes_ += p.size() + jlh::auth::kTagBytes;
                    return true;
                }
                lastError_ = WSAGetLastError();
                return false;
            });
        failed_ += r.failed;
        return r;
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
    SessionView sv;
    uint64_t streamGen = 0, nSessionDrops = 0;

    while (st.running) {
        if (o.seconds > 0 && msSinceStart() > int64_t(o.seconds) * 1000) break;
        // H3: the stream runs while a control connection holds the session
        // (SessionBroker::current), and goes only to that viewer.
        sv.refresh(*st.broker);
        const bool active = sv.s != nullptr;
        if (!active) {
            if (streaming) {
                logf("stream.idle reason=no_session");
                streaming = false;
                cap.close();
                enc.close();
                haveFrame = false;
            }
            Sleep(100);
            continue;
        }
        if (!streaming || sv.s->generation != streamGen) {
            // A new session (a new AUTH, a takeover): the viewer gets a
            // fresh IDR before anything else (the Mac newSessionHandler).
            if (!streaming) streamStart = Clock::now();
            streaming = true;
            needKey = true;
            streamGen = sv.s->generation;
            logf("stream.start viewer=%s:%u gen=%llu udp=%s", sv.s->peerIp.c_str(), unsigned(kVideoPort),
                 (unsigned long long)streamGen, sv.s->tags ? "tagged" : "no_taggers");
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
        // Not to a session that ended while this frame was encoded: the
        // next one starts with its own IDR (top of the loop).
        sv.refresh(*st.broker);
        if (!sv.s || sv.s->generation != streamGen) {
            ++nSessionDrops;
            continue;
        }
        const auto frameSent = sender.send(au, key, *st.broker, *sv.s, sv.addr);
        nPackets += frameSent.sent;
        if (frameSent.cut) {
            // H3 r2: the session moved mid-frame; the rest was not sent.
            ++nSessionDrops;
            continue;
        }
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
                 "input_takeover=%llu input_owner_voided=%llu input_dropped=%llu input_up_retry=%llu input_silenced=%llu input_up_pending=%llu "
                 "input_malformed=%llu input_err=%lu pointer_udp=%llu pointer_udp_stale=%llu pointer_udp_not_owner=%llu "
                 "pointer_udp_up_pending=%llu pointer_udp_legacy_off=%llu pointer_sync=%llu cursor_sent=%llu "
                 "cursor_fail=%llu cursor_changes=%llu auth_fail=%llu auth_rejected=%llu auth_old_viewer=%llu "
                 "auth_resume_refused=%llu replaced=%llu udp_no_session=%llu udp_rejected=%llu udp_bad_tag=%llu "
                 "udp_bad=%llu udp_replay=%llu udp_stale=%llu udp_late_ok=%llu pong_drops=%llu session_drops=%llu "
                 "backend=%s",
                 st.streamW.load(), st.streamH.load(), srcW, srcH, nCaptured / secs, nEncoded / secs,
                 sender.takeBytes() * 8.0 / 1e6 / secs, (unsigned long long)nKeys,
                 (unsigned long long)st.keyframeRequests.load(), nEncoded ? encMsSum / nEncoded : 0.0,
                 (unsigned long long)nPackets, (unsigned long long)sendFail, (unsigned long long)sendFailTotal,
                 sendFail ? sender.lastError() : 0, st.controlConnections.load(), (unsigned long long)st.pings.load(),
                 (unsigned long long)st.input.injected(), (unsigned long long)st.input.failed(),
                 (unsigned long long)st.input.ignored(), (unsigned long long)st.input.upsHeld(),
                 (unsigned long long)st.inputTakeovers.load(), (unsigned long long)st.inputOwnerVoided.load(),
                 (unsigned long long)st.inputDropped.load(), (unsigned long long)st.inputUpRetried.load(), (unsigned long long)st.inputSilenced.load(),
                 (unsigned long long)st.inputUpPending.load(), (unsigned long long)st.inputMalformed.load(),
                 st.input.lastError(), (unsigned long long)st.pointerUdp.load(),
                 (unsigned long long)st.pointerUdpStale.load(), (unsigned long long)st.pointerUdpNotOwner.load(),
                 (unsigned long long)st.pointerUdpUpPending.load(), (unsigned long long)st.pointerUdpLegacyOff.load(),
                 (unsigned long long)st.pointerSyncs.load(),
                 (unsigned long long)st.cursorSent.load(),
                 (unsigned long long)st.cursorSendFail.load(), (unsigned long long)st.cursorChanges.load(),
                 (unsigned long long)st.auth->counters->failures.load(),
                 (unsigned long long)st.auth->counters->rejected.load(),
                 (unsigned long long)st.auth->counters->oldViewers.load(),
                 (unsigned long long)st.broker->resumesRefused(), (unsigned long long)st.broker->replaced(),
                 (unsigned long long)st.udpNoSession.load(), (unsigned long long)st.udpRejected.load(),
                 (unsigned long long)st.mrm1BadTag->total(), (unsigned long long)st.udpBad.load(),
                 (unsigned long long)st.udpReplay.load(), (unsigned long long)st.udpStale.load(),
                 (unsigned long long)st.udpLateOk.load(), (unsigned long long)st.pongDrops.load(),
                 (unsigned long long)nSessionDrops, cap.backend());
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

// H3: the connection settings window. Not elevated: this exe again with one
// UAC prompt, and this process ends. Started from Explorer or a shortcut
// (a console of its own, nothing else on it): the console goes away.
int runSettings() {
    if (!jlh::config::isElevated()) {
        if (jlh::config::relaunchElevated(L"--connection-settings")) return 0;
        std::fprintf(stderr, "JerisLinkHost: the connection settings need administrator rights (UAC refused, "
                             "error %lu)\n", GetLastError());
        return 77;
    }
    DWORD pids[2];
    if (GetConsoleProcessList(pids, 2) == 1) FreeConsole();
    return jlh::settingsui::runConnectionSettings(jlh::config::Location{});
}

}  // namespace

int main(int argc, char** argv) {
    Options o;
    std::string err;
    if (!parseArgs(argc, argv, o, err)) {
        std::fprintf(stderr, "JerisLinkHost: %s\n", err.c_str());
        std::fprintf(stderr,
                     "usage: JerisLinkHost [--bind <tailnet ip>] [--fps N] [--bitrate Mbps] [--max-size WxH] "
                     "[--capture auto|dda|gdi] [--log file] [--seconds N] [--snapshot file.bmp]\n"
                     "       JerisLinkHost --connection-settings\n"
                     "       JerisLinkHost --probe [--capture ...] [--snapshot file.bmp]\n");
        return 64;
    }
    if (o.connectionSettings) return runSettings();
    if (!o.logPath.empty()) gLogFile = std::fopen(o.logPath.c_str(), "a");
    // Physical pixels on HiDPI screens: duplication and GDI see the real mode.
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    if (FAILED(CoInitializeEx(nullptr, COINIT_MULTITHREADED)) || FAILED(MFStartup(MF_VERSION, MFSTARTUP_LITE))) {
        logf("init FAIL com/mf");
        return 1;
    }
    logf("JerisLinkHost %s (H3: capture + MF software H.264 + MR02 + SendInput + cursor shape + password)",
         JERISLINK_VERSION_STRING);
    if (o.probe) {
        const int rc = runProbe(o);
        MFShutdown();
        return rc;
    }

    // H3: the password key is readable by SYSTEM and Administrators only.
    if (!jlh::config::isElevated()) {
        logf("host.not_elevated: run JerisLinkHost as administrator; nothing listens");
        MFShutdown();
        return 77;
    }
    const jlh::config::Location loc;
    const jlh::config::Settings settings = jlh::config::readSettings(loc);
    if (!gLogFile && !settings.logPath.empty()) {
        gLogFile = std::fopen(settings.logPath.c_str(), "a");
        if (!gLogFile) logf("host.log_open FAIL path=%s errno=%d", settings.logPath.c_str(), errno);
    }
    if (!settings.problem.empty()) logf("host.settings_problem %s (defaults used)", settings.problem.c_str());

    WSADATA wsa{};
    WSAStartup(MAKEWORD(2, 2), &wsa);
    static State st;
    gState = &st;
    st.opt = o;
    st.bitrateMbps = o.bitrateMbps;
    const auto logLine = [](const std::string& s) { logf("%s", s.c_str()); };
    const auto monoSeconds = [] {
        return std::chrono::duration<double>(Clock::now().time_since_epoch()).count();
    };

    // The password, the whitelist and the blacklist (registry), before
    // anything listens (D9: no password, no listening).
    static jlh::config::RegistryBlocklist blocklist(loc);
    static jlh::config::RegistryPendingBlocks journal(loc);
    static jlh::config::RegistryFailureLog failureStore(loc);
    static jlh::config::RegistryPolicySource policySource(loc);
    static jlh::auth::AuthGuard guard({}, blocklist, &journal, jlh::auth::AuthGuard::defaultHooks(logLine));
    static jlh::auth::SessionBroker broker(jlh::auth::win::tagsFactory(), logLine);
    static jlh::auth::AuthLogThrottle throttle(monoSeconds, logLine);
    static jlh::auth::AuthFailureLog failureLog(failureStore);
    static jlh::auth::AuthCounters counters;
    static jlh::auth::BadTagLog mrm1BadTag("mrm1", monoSeconds, logLine);
    static jlh::settings::PolicyHolder holder(policySource, guard, broker, logLine);
    holder.load();
    if (!holder.passwordSet()) {
        logf("auth.no_password: set one with JerisLinkHost --connection-settings; nothing listens");
        MFShutdown();
        return 78;
    }

    // Where to listen (D11): --bind, else the registry's BindIP, else this
    // PC's lowest tailnet IPv4; with none up yet, wait for one.
    jlh::settings::ListenPlan plan;
    for (bool waitLogged = false;;) {
        if (!o.bindIp.empty()) {
            plan = jlh::settings::resolveListen("tailnet", o.bindIp, jlh::config::localIpv4());
        } else {
            plan = jlh::settings::resolveListen(settings.listenMode, settings.bindIp, jlh::config::localIpv4());
        }
        if (plan.kind == jlh::settings::ListenPlan::NotConfigured) {
            logf("net.listen_not_configured %s; nothing listens", plan.why.c_str());
            MFShutdown();
            return 78;
        }
        if (plan.kind == jlh::settings::ListenPlan::Ready) break;
        if (!waitLogged) {
            waitLogged = true;
            logf("net.waiting %s; trying again every 2 s", plan.why.c_str());
        }
        Sleep(2000);
    }
    st.bindIp = plan.bindIp;
    parseIpv4(st.bindIp, st.bindAddr);

    static jlh::auth::AuthEnv env;
    env.hmac = jlh::auth::win::hmac;
    env.random = jlh::auth::win::random;
    env.guard = &guard;
    env.broker = &broker;
    env.failureLog = &failureLog;
    env.authLog = &throttle;
    env.counters = &counters;
    env.log = logLine;
    env.wallNow = [] { return int64_t(std::time(nullptr)); };
    env.stopping = [] { return !gState->running.load(); };
    env.policy = [] { return holder.snapshot(); };
    env.refreshPolicy = [] { holder.refresh(false); };
    env.endpoint = st.bindIp + ":" + std::to_string(kControlPort);
    st.auth = &env;
    st.broker = &broker;
    // A void (a takeover, a password or whitelist change, a block) retires
    // a voided input owner at once: its keys and buttons go up, its MRM1
    // socket is unbound, and an injection of it already past its check
    // finishes before the void returns (InputClaims::retire).
    broker.onVoid([] {
        bool retired = false;
        const size_t n = st.claims.retire([](uint64_t o) { return st.broker->live(o); },
                                          [](uint16_t v) { return st.input.upKey(v); },
                                          [](uint8_t b) { return st.input.upButton(b); }, &retired);
        if (retired) {
            ++st.inputOwnerVoided;
            logf("input.owner_voided released=%zu still_held=%s", n, st.claims.anyHeld() ? "yes" : "no");
        }
    });
    st.guard = &guard;
    st.mrm1BadTag = &mrm1BadTag;
    SetConsoleCtrlHandler(onConsoleCtrl, TRUE);

    SOCKET ctl = listenOn(st.bindAddr, kControlPort, SOCK_STREAM);
    SOCKET mrm1 = listenOn(st.bindAddr, kMrm1Port, SOCK_DGRAM);
    if (ctl == INVALID_SOCKET || mrm1 == INVALID_SOCKET) return 2;
    st.mrm1Sock = mrm1;
    // Settings changes (the window, regedit): the password or whitelist
    // voids every connection, a blacklisted address loses its own at once.
    static jlh::config::PolicyWatcher watcher(loc, [] { holder.tick(); });
    logf("listening control=tcp:%s:%u mrm1=udp:%s:%u video_to=<session viewer>:%u mode=%s auth=password "
         "whitelist=%zu fps=%d bitrate_mbps=%d max=%dx%d",
         st.bindIp.c_str(), unsigned(kControlPort), st.bindIp.c_str(), unsigned(kMrm1Port), unsigned(kVideoPort),
         plan.mode.c_str(), settings.whitelist.size(), o.fps, o.bitrateMbps, o.maxW, o.maxH);
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
