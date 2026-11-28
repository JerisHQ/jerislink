// JerisLink Windows host: the connection password on one TCP connection.
//
// ControlServer.swift (Mac host v0.4.0, PR-C) ported: `authenticate` and
// its refusals, the broker step after it (the takeover), checked sends to
// an admitted viewer, and the REPLACED notice at the end. Log lines are the
// Mac host's, with the registry in place of listen.plist.
//
// Portable (Winsock or POSIX), so auth_test runs it over real loopback
// sockets on Linux and Windows. Viewer sockets are non-blocking (the Mac
// r12): a send never waits in the kernel, and every wait for room is cut
// into kSendSliceMs slices that ask `revoked` first.
//
// Windows differences (the Mac restarts its control service instead):
// - a takeover, a password or whitelist change, a blocked address and the
//   journal lockdown all void connections through the broker; the handler
//   asks the broker why (`voidReason`), and only a takeover gets REPLACED;
// - a kicked connection is not shut down from another thread: its reader
//   asks `ConnLife::revoked` before every read slice (kReadSliceMs) and
//   every send slice, so it stops within one slice.
#pragma once

#include "control_read.hpp"
#include "host_auth.hpp"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <atomic>
#include <chrono>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>

namespace jlh::auth {

// ------------------------------------------------------------------ sockets

inline int64_t monoMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

inline int sockError() {
#ifdef _WIN32
    return WSAGetLastError();
#else
    return errno;
#endif
}
inline bool sockWouldBlock(int e) {
#ifdef _WIN32
    return e == WSAEWOULDBLOCK;
#else
    return e == EAGAIN || e == EWOULDBLOCK;
#endif
}
inline bool sockInterrupted(int e) {
#ifdef _WIN32
    return e == WSAEINTR;
#else
    return e == EINTR;
#endif
}

// r12 (Mac): O_NONBLOCK on a viewer socket. False: the accept loop closes
// the connection instead of serving it.
inline bool setNonBlocking(SocketHandle s) {
#ifdef _WIN32
    u_long on = 1;
    return ioctlsocket(s, FIONBIO, &on) == 0;
#else
    const int f = fcntl(s, F_GETFL);
    return f >= 0 && fcntl(s, F_SETFL, f | O_NONBLOCK) == 0;
#endif
}

inline long rawSend(SocketHandle s, const uint8_t* p, size_t n) {
#ifdef _WIN32
    return send(s, reinterpret_cast<const char*>(p), int(std::min<size_t>(n, INT_MAX)), 0);
#else
    return long(send(s, p, n, MSG_NOSIGNAL));
#endif
}
inline long rawRecv(SocketHandle s, uint8_t* p, size_t n) {
#ifdef _WIN32
    return recv(s, reinterpret_cast<char*>(p), int(std::min<size_t>(n, INT_MAX)), 0);
#else
    return long(recv(s, p, n, 0));
#endif
}
inline void shutdownWrite(SocketHandle s) {
#ifdef _WIN32
    shutdown(s, SD_SEND);
#else
    shutdown(s, SHUT_WR);
#endif
}
inline void closeSocketHandle(SocketHandle s) {
#ifdef _WIN32
    closesocket(s);
#else
    close(s);
#endif
}

// 1: ready; 0: nothing within `ms` (or a signal); -1: the socket failed.
inline int waitSocket(SocketHandle s, bool forWrite, int ms) {
    fd_set set;
    FD_ZERO(&set);
    FD_SET(s, &set);
    timeval tv{};
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
#ifdef _WIN32
    const int n = select(0, forWrite ? nullptr : &set, forWrite ? &set : nullptr, nullptr, &tv);
#else
    const int n = select(s + 1, forWrite ? nullptr : &set, forWrite ? &set : nullptr, nullptr, &tv);
    if (n < 0 && errno == EINTR) return 0;
#endif
    if (n < 0) return -1;
    return n > 0 ? 1 : 0;
}

// r10 (Mac resetPeer): SO_LINGER {1, 0}, so the close sends an RST: what
// the kernel still holds for a refused viewer is dropped, not delivered.
inline void setResetOnClose(SocketHandle s) {
    linger l{};
    l.l_onoff = 1;
    l.l_linger = 0;
    setsockopt(s, SOL_SOCKET, SO_LINGER, reinterpret_cast<const char*>(&l), sizeof(l));
}

// Mac settleBeforeReset: before the RST close, two smoothed RTTs (20 to
// 200 ms) so the segment in flight is acknowledged first (RFC 5961: an RST
// while data is in flight gets a challenge ACK instead).
inline void settleBeforeReset(SocketHandle s) {
    long rttMs = 0;
#if defined(_WIN32) && defined(SIO_TCP_INFO)
    DWORD version = 0, got = 0;
    TCP_INFO_v0 info{};
    if (WSAIoctl(s, SIO_TCP_INFO, &version, sizeof(version), &info, sizeof(info), &got, nullptr, nullptr) == 0)
        rttMs = long(info.RttUs / 1000);
#elif defined(TCP_INFO) && !defined(_WIN32)
    tcp_info info{};
    socklen_t len = sizeof(info);
    if (getsockopt(s, IPPROTO_TCP, TCP_INFO, &info, &len) == 0) rttMs = long(info.tcpi_rtt / 1000);
#else
    (void)s;
#endif
    std::this_thread::sleep_for(std::chrono::milliseconds(std::min(200L, std::max(20L, 2 * rttMs))));
}

// The handler closes its socket once: with an RST (after the settle) when
// something asked for a reset, else a plain close.
inline void finishSocket(SocketHandle s, bool reset) {
    if (reset) settleBeforeReset(s);
    closeSocketHandle(s);
}

// ---------------------------------------------------------- one connection

// Mac KickHandle, minus the descriptor: the broker's close (any thread)
// only marks this object, which lives as long as either side holds it, so
// no socket number is ever touched after its handler closed it.
class ConnLife {
public:
    // r12: set once the connection is in the broker, on its own thread.
    void bind(std::function<bool()> live) {
        std::lock_guard<std::mutex> g(m_);
        live_ = std::move(live);
    }
    // r12: a newer login took over, or the connection left the broker for
    // another reason. Asked before every side effect.
    bool revoked() const {
        if (kicked_.load()) return true;
        std::function<bool()> live;
        {
            std::lock_guard<std::mutex> g(m_);
            live = live_;
        }
        return live && !live();
    }
    void kick(CloseReason why) {
        std::lock_guard<std::mutex> g(m_);
        if (kicked_.load()) return;
        why_ = why;
        kickedAt_ = monoMs();
        kicked_.store(true);
    }
    bool kicked() const { return kicked_.load(); }
    std::optional<CloseReason> kickReason() const {
        std::lock_guard<std::mutex> g(m_);
        if (!kicked_.load()) return std::nullopt;
        return why_;
    }
    // Mac hardCloseAfter: what is left of the 2 s a kicked connection may
    // still use (the notice and its linger), from now.
    int hardCloseLeftMs(int hardCloseMs) const {
        std::lock_guard<std::mutex> g(m_);
        if (!kicked_.load()) return hardCloseMs;
        return int(std::max<int64_t>(0, kickedAt_ + hardCloseMs - monoMs()));
    }
    // r14: a frame went out only in part; nothing may follow it.
    void notePartial() { partial_.store(true); }
    bool partial() const { return partial_.load(); }

private:
    mutable std::mutex m_;
    std::function<bool()> live_;
    std::atomic<bool> kicked_{false}, partial_{false};
    CloseReason why_ = CloseReason::Replaced;
    int64_t kickedAt_ = 0;
};

constexpr int kHardCloseMs = 2000;  // Mac KickHandle.hardCloseAfter

struct SendOpts {
    int limitMs = -1;                  // the whole frame's time; -1: see sendFrame
    std::function<bool()> revoked;     // asked after every wake; true stops the send
    std::function<bool()> stopping;    // the host is shutting down
    std::function<void()> partial;     // gave up after some of the frame went out
};

// One MRC1 frame on a non-blocking socket (Mac sendPacket, r12). The wait
// for room is select() in kSendSliceMs slices; after every wake `revoked`
// is asked first, then the deadline, then `stopping`, and only then is the
// rest written. Without `revoked` (handshake frames) the deadline is
// kHandshakeSendMs; with it there is none unless `limitMs` sets one.
// Bytes already framed (one MRC1 frame or several back to back, such as
// VIDEO_CONFIG_ACK with HOST_INFO behind it), under sendFrame's rules.
inline bool sendBytes(SocketHandle s, const Bytes& b, const SendOpts& o) {
    const int64_t start = monoMs();
    const int64_t deadline = o.limitMs >= 0 ? start + o.limitMs : (o.revoked ? INT64_MAX : start + kHandshakeSendMs);
    size_t off = 0;
    const auto cut = [&] {
        if (off > 0 && o.partial) o.partial();
        return false;
    };
    while (off < b.size()) {
        const int ready = waitSocket(s, true, kSendSliceMs);
        if (ready < 0) return cut();
        if (o.revoked && o.revoked()) return cut();
        if (monoMs() > deadline) return cut();
        if (o.stopping && o.stopping()) return cut();
        if (ready == 0) continue;
        const long r = rawSend(s, b.data() + off, b.size() - off);
        if (r > 0) {
            off += size_t(r);
            continue;
        }
        if (r < 0) {
            const int e = sockError();
            if (sockWouldBlock(e) || sockInterrupted(e)) continue;
        }
        return cut();
    }
    return true;
}
inline bool sendFrame(SocketHandle s, uint8_t type, const uint8_t* payload, size_t n, const SendOpts& o) {
    if (n > 0xFFFF) return false;
    Bytes b{'M', 'R', 'C', '1', 1, type, uint8_t(n >> 8), uint8_t(n)};
    if (n) b.insert(b.end(), payload, payload + n);
    return sendBytes(s, b, o);
}
inline bool sendFrame(SocketHandle s, uint8_t type, const Bytes& payload, const SendOpts& o) {
    return sendFrame(s, type, payload.data(), payload.size(), o);
}

enum class RecvOutcome { Ok, Timeout, Closed, Error };

// Exactly n bytes before `deadlineMs` (monotonic). `stop` is asked at
// least every 200 ms (the host shutting down reads as Closed).
inline RecvOutcome recvExactBy(SocketHandle s, uint8_t* p, size_t n, int64_t deadlineMs, int& err,
                               const std::function<bool()>& stop = {}) {
    while (n) {
        if (stop && stop()) return RecvOutcome::Closed;
        const int64_t left = deadlineMs - monoMs();
        if (left <= 0) return RecvOutcome::Timeout;
        const int w = waitSocket(s, false, int(std::min<int64_t>(left, 200)));
        if (w < 0) {
            err = sockError();
            return RecvOutcome::Error;
        }
        if (w == 0) continue;
        const long r = rawRecv(s, p, n);
        if (r == 0) return RecvOutcome::Closed;
        if (r < 0) {
            const int e = sockError();
            if (sockWouldBlock(e) || sockInterrupted(e)) continue;
            err = e;
            return RecvOutcome::Error;
        }
        p += r;
        n -= size_t(r);
    }
    return RecvOutcome::Ok;
}

// r4 (Mac drainAfterNotice): after the notice and FIN, read and drop what
// the viewer still sends until it closes, for at most `lingerMs`. Closing
// with input unread sends an RST, and Windows may then throw away a notice
// the viewer has not read yet.
inline void drainAfterNotice(SocketHandle s, int lingerMs) {
    const int64_t deadline = monoMs() + lingerMs;
    uint8_t scratch[4096];
    for (;;) {
        const int64_t left = deadline - monoMs();
        if (left <= 0) return;
        const int w = waitSocket(s, false, int(std::max<int64_t>(1, left)));
        if (w < 0) return;
        if (w == 0) continue;  // the loop re-checks the deadline
        const long r = rawRecv(s, scratch, sizeof(scratch));
        if (r < 0) {
            const int e = sockError();
            if (sockWouldBlock(e) || sockInterrupted(e)) continue;
        }
        if (r <= 0) return;
    }
}

// Mac OncePerInterval.
class OncePerInterval {
public:
    explicit OncePerInterval(int64_t ms) : ms_(ms) {}
    bool due() {
        std::lock_guard<std::mutex> g(m_);
        const int64_t t = monoMs();
        if (have_ && t - last_ < ms_) return false;
        have_ = true;
        last_ = t;
        return true;
    }

private:
    std::mutex m_;
    const int64_t ms_;
    int64_t last_ = 0;
    bool have_ = false;
};

// ------------------------------------------------------------------ policy

// What the registry holds for the password (D7/D8): K, never the password.
struct AuthSecret {
    Key key{};
    Salt salt{};
    uint32_t iterations = kIterations;
    HostId hostId{};
    AuthSecret() = default;
    AuthSecret(const AuthSecret&) = default;
    AuthSecret& operator=(const AuthSecret&) = default;
    ~AuthSecret() { wipe(key.data(), key.size()); }
};

// The secret and the broker's policy generation, read together (one lock
// on the settings side): an AUTH that ran under an older policy is refused
// at admit.
struct PolicySnapshot {
    std::shared_ptr<const AuthSecret> secret;  // nullptr: no password set (D9: nobody gets in)
    uint64_t generation = 0;
    std::string noSecretReason = "no_password";  // the reject line's reason when secret is nullptr
};

struct AuthCounters {
    std::atomic<uint64_t> failures{0}, oldViewers{0}, probes{0}, resumesRefused{0}, rejected{0};
};

// An authenticated connection (Mac AuthOK).
struct AuthOK {
    Channel channel = Channel::Control;
    Key sessionKey{};                  // K_s (used on the control channel only)
    SessionId sessionId{};             // r4: sent in OK
    std::optional<SessionId> resume;   // the control session another channel named (nullopt on control)
    bool isAuto = false;               // r14: a control AUTH flagged "auto" (never takes over)
    Mac macH{};                        // r5: for the OK sent after admit
    uint64_t policy = 0;               // the policy generation it ran under
    AuthOK() = default;
    AuthOK(const AuthOK&) = default;
    AuthOK& operator=(const AuthOK&) = default;
    ~AuthOK() { wipe(sessionKey.data(), sessionKey.size()); }
};

// Everything one listener shares between its connections.
struct AuthEnv {
    HmacFn hmac = nullptr;
    std::function<bool(uint8_t*, size_t)> random;
    AuthGuard* guard = nullptr;
    SessionBroker* broker = nullptr;
    AuthFailureLog* failureLog = nullptr;   // optional: the settings window's failure list
    AuthLogThrottle* authLog = nullptr;
    AuthCounters* counters = nullptr;
    std::function<void(const std::string&)> log;
    std::function<int64_t()> wallNow;
    std::function<bool()> stopping;
    std::function<PolicySnapshot()> policy;
    // Asked before every message and send check: picks up a settings change
    // that has not been applied yet (it may void connections, this one too).
    std::function<void()> refreshPolicy;
    std::string endpoint;                   // "bind:port", for the reject lines
    int authTimeoutMs = kAuthTimeoutMs;
    int noticeLingerMs = kNoticeLingerMs;
    int hardCloseMs = kHardCloseMs;
    std::function<bool(const AuthOK&)> failAuthOKForTest;
    OncePerInterval peerRefusedOnce{1000};  // Mac peerCheck: one line a second
};

enum class CheckedSend { Sent, Refused, Failed };

inline std::string hexByte(uint8_t v) {
    char b[8];
    std::snprintf(b, sizeof(b), "%x", unsigned(v));
    return b;
}

// Addresses that joined the blacklist (a 20th failure, the settings
// window, the journal) lose their open connections at once (Windows; the
// Mac closes them at their next message).
inline void kickNewlyBlocked(AuthGuard& guard, SessionBroker& broker) {
    for (const auto& ip : guard.takeNewlyBlocked()) broker.kickPeer(ip, CloseReason::Blocked);
}

// One TCP connection's password handshake and its life in the broker.
class AuthConn {
public:
    AuthConn(AuthEnv& env, SocketHandle s, std::string peerIp) : env_(env), s_(s), ip_(std::move(peerIp)) {}

    // The socket wants an RST close (setResetOnClose was called).
    bool resetRequested() const { return reset_; }
    const std::string& peer() const { return ip_; }

    // Mac authenticate: admission, CHALLENGE, RESPONSE, MAC, under the
    // guard's limits. nullopt: refused, answered and logged; the caller
    // closes the connection.
    std::optional<AuthOK> authenticate() {
        const PolicySnapshot pol = env_.policy ? env_.policy() : PolicySnapshot{};
        if (!pol.secret) {
            // D9: the Windows host has no transition mode. Without a
            // password nobody gets a challenge.
            reject("Control reject peer=" + ip_ + " reason=" + pol.noSecretReason + " on " + env_.endpoint +
                   "; connection closed");
            return std::nullopt;
        }
        const AuthSecret& secret = *pol.secret;
        const AuthGuard::Admission admission = env_.guard->admit(ip_);
        if (admission.kind != AuthGuard::Admission::Challenge) {
            refuse(admission, false);
            return std::nullopt;
        }
        Nonce hostNonce{};
        if (!env_.random(hostNonce.data(), hostNonce.size())) {
            log("auth.random_failed peer=" + ip_ + "; connection closed");
            return std::nullopt;
        }
        if (!sendHandshake(kMsgChallenge, challengePayload(hostNonce, secret.salt, secret.iterations, secret.hostId)))
            return std::nullopt;

        const int64_t deadline = monoMs() + env_.authTimeoutMs;
        uint8_t header[8];
        int err = 0;
        switch (recvExactBy(s_, header, sizeof(header), deadline, err, env_.stopping)) {
        case RecvOutcome::Ok: break;
        case RecvOutcome::Timeout: settleFailure("timeout"); return std::nullopt;
        case RecvOutcome::Closed: noteNoResponse(false, 0); return std::nullopt;
        case RecvOutcome::Error: noteNoResponse(true, err); return std::nullopt;
        }
        const uint8_t type = header[5];
        const size_t length = size_t(uint16_t(header[6]) << 8 | header[7]);
        const bool isMrc1 = header[0] == 'M' && header[1] == 'R' && header[2] == 'C' && header[3] == '1' && header[4] == 1;
        if (isMrc1 && type != kMsgResponse && isLegacyFirstHeader(type, length)) {
            // r2/r3 (Pepper's PR-C review, items 8 and 4): a 0.3.x viewer's
            // own first header, exact length: no password was tried, not
            // counted.
            if (env_.counters) ++env_.counters->oldViewers;
            sendHandshake(kMsgResult, resultStatus(Status::AuthRequired));
            authLog("auth.old_viewer", "auth.old_viewer peer=" + ip_ + " type=0x" + hexByte(type) + " counted=0");
            return std::nullopt;
        }
        if (!isMrc1 || type != kMsgResponse) {
            settleFailure("bad_header");
            return std::nullopt;
        }
        if (length != kResponseBytes && length != kResumeResponseBytes) {
            settleFailure("bad_response");
            return std::nullopt;
        }
        uint8_t body[kResumeResponseBytes];
        switch (recvExactBy(s_, body, length, deadline, err, env_.stopping)) {
        case RecvOutcome::Ok: break;
        case RecvOutcome::Timeout: settleFailure("timeout"); return std::nullopt;
        case RecvOutcome::Closed: noteNoResponse(false, 0); return std::nullopt;
        case RecvOutcome::Error: noteNoResponse(true, err); return std::nullopt;
        }
        const auto response = decodeResponse(body, length);
        if (!response) {
            settleFailure("bad_response");
            return std::nullopt;
        }
        if (response->zeroMac()) {
            // PR-C item 5: a transition probe that crossed the CHALLENGE.
            const AuthGuard::ProbeAnswer p = env_.guard->probe(ip_);
            if (p.refused) {
                refuse(p.admission, true);
            } else {
                if (env_.counters) ++env_.counters->probes;
                sendHandshake(kMsgResult, resultFail(p.triesLeft));
                authLog("auth.probe_race",
                        "auth.probe_race peer=" + ip_ + " tries=" + std::to_string(p.triesLeft) + " counted=0");
            }
            return std::nullopt;
        }
        std::optional<Channel> matched;
        const AuthGuard::Settlement settlement = env_.guard->settle(ip_, [&] {
            matched = matchChannel(env_.hmac, secret.key, hostNonce, *response, secret.hostId);
            return matched.has_value();
        });
        if (settlement.kind != AuthGuard::Settlement::Ok || !matched) {
            finishFailure(settlement, "wrong_password");
            return std::nullopt;
        }
        // r14 (Pepper's r13 review, item 4): takeover is never automatic.
        const bool isAuto = *matched == Channel::Control && response->hasResume;
        if (isAuto && env_.broker->autoRefused(true)) {
            refuseResume(Channel::Control, "auth");
            return std::nullopt;
        }
        AuthOK ok;
        ok.channel = *matched;
        ok.isAuto = isAuto;
        ok.policy = pol.generation;
        if (*matched != Channel::Control && response->hasResume) ok.resume = response->resume;
        if (!env_.random(ok.sessionId.data(), ok.sessionId.size()) ||
            !macHost(env_.hmac, secret.key, hostNonce, response->clientNonce, *matched, ok.macH) ||
            !sessionKey(env_.hmac, secret.key, hostNonce, response->clientNonce, ok.sessionId, ok.sessionKey)) {
            log("auth.crypto_failed peer=" + ip_ + " chan=" + channelName(*matched) + "; connection closed");
            return std::nullopt;
        }
        // r5 (Pepper's r4 review, item 2): OK goes out from `admit`, once
        // the broker took the session.
        return ok;
    }

    // The broker step (Mac handleClient after authenticate): admit (a
    // control AUTH takes over here, r12), bind the connection's life to
    // its epoch, then OK. nullopt: refused or OK unsent, answered and
    // logged; the caller closes the connection.
    std::optional<uint64_t> admit(const AuthOK& ok, const std::shared_ptr<ConnLife>& life) {
        const bool control = ok.channel == Channel::Control;
        const SessionBroker::Admitted a = env_.broker->admit(
            ip_, ok.channel, control ? std::optional<Key>(ok.sessionKey) : std::nullopt,
            control ? std::optional<SessionId>(ok.sessionId) : std::nullopt, ok.resume, ok.isAuto, ok.policy,
            [life](CloseReason why) { life->kick(why); });
        if (a.refused == SessionBroker::Refusal::Policy) {
            // The password or the whitelist changed while this AUTH ran.
            reject("Control reject peer=" + ip_ + " reason=policy_revoked; connection closed");
            return std::nullopt;
        }
        if (a.refused == SessionBroker::Refusal::Resume) {
            if (control) {
                // r4: the reconnect check again, atomically with the takeover.
                refuseResume(Channel::Control, "admit");
            } else {
                authLog("auth.channel_unadmitted", "auth.channel_unadmitted peer=" + ip_ + " chan=" +
                                                       channelName(ok.channel) + " resume=" +
                                                       (ok.resume ? hex(*ok.resume) : std::string("-")) +
                                                       " counted=0; closed, no REPLACED");
            }
            return std::nullopt;
        }
        SessionBroker* broker = env_.broker;
        const uint64_t token = a.token;
        life->bind([broker, token] { return broker->live(token); });
        // r9: a control OK that did not go out drops its session id.
        if (!sendAuthOK(ok, *life)) {
            if (control) {
                env_.broker->abandon(token);
                log("auth.ok_unsent peer=" + ip_ + " chan=control; session dropped, the viewer reconnects");
            } else {
                env_.broker->end(token);
            }
            return std::nullopt;
        }
        return token;
    }

    // Before a message is acted on (Mac serveAdmitted): nothing a voided
    // connection read is acted on; a peer the blacklist or the journal
    // lockdown refuses is reset; the channel holds the connection to the
    // messages it authenticated for. False: stop serving.
    bool admitMessage(const AuthOK& ok, const ConnLife& life, uint8_t type, bool first) {
        if (env_.refreshPolicy) env_.refreshPolicy();
        if (life.revoked()) return false;
        if (peerRefused()) {
            reject("Control reject peer=" + ip_ + " reason=peer_refused type=0x" + hexByte(type) + " on " +
                   env_.endpoint + "; open connection closed");
            resetPeer();
            return false;
        }
        if (!channelAllows(ok.channel, type, first)) {
            log("auth.channel_mismatch peer=" + ip_ + " chan=" + channelName(ok.channel) + " type=0x" + hexByte(type) +
                "; connection closed");
            return false;
        }
        return true;
    }

    // r10 (Mac sendChecked): the one way a frame reaches an admitted
    // viewer. The connection's epoch and this peer's block are asked right
    // before the frame and after every wait for room. A refusal resets the
    // socket, except a voided control line kept for its REPLACED notice.
    CheckedSend sendChecked(const ConnLife* life, const char* kind, uint8_t type, const Bytes& payload,
                            int limitMs = -1, bool keepForNotice = false) {
        if (payload.size() > 0xFFFF) return CheckedSend::Failed;
        Bytes b{'M', 'R', 'C', '1', 1, type, uint8_t(payload.size() >> 8), uint8_t(payload.size())};
        b.insert(b.end(), payload.begin(), payload.end());
        return sendCheckedFramed(life, kind, b, limitMs, keepForNotice);
    }
    // The same for bytes already framed (sendBytes).
    CheckedSend sendCheckedFramed(const ConnLife* life, const char* kind, const Bytes& framed, int limitMs = -1,
                                  bool keepForNotice = false) {
        bool refused = false;
        SendOpts o;
        o.limitMs = limitMs;
        o.revoked = [&] {
            if ((life && life->revoked()) || sessionRevoked(kind)) refused = true;
            return refused;
        };
        o.stopping = env_.stopping;
        o.partial = [life] {
            if (life) const_cast<ConnLife*>(life)->notePartial();
        };
        const bool ok = sendBytes(s_, framed, o);
        if (refused) {
            if (!(keepForNotice && life && life->revoked())) resetPeer();
            return CheckedSend::Refused;
        }
        return ok ? CheckedSend::Sent : CheckedSend::Failed;
    }

    // After the message loop (Mac handleClient's end): a control line a
    // takeover voided gets REPLACED, then FIN and a short drain; one with a
    // frame cut off part way is reset instead (r14). Windows: a line voided
    // for another reason (policy, blocked, lockdown) gets no notice; a
    // blocked or locked-down one is reset. Then the connection leaves the
    // broker.
    void finish(const AuthOK& ok, uint64_t token, const ConnLife& life) {
        const bool voided = life.revoked();
        std::optional<CloseReason> why = life.kickReason();
        if (!why && voided) why = env_.broker->voidReason(token);
        if (ok.channel == Channel::Control && voided && why == CloseReason::Replaced) {
            if (life.partial()) {
                resetPeer();
                log("auth.replaced_notice peer=" + ip_ + " sent=0 skipped=partial_frame; connection reset");
            } else {
                const int left = life.hardCloseLeftMs(env_.hardCloseMs);
                SendOpts o;
                o.limitMs = std::min(left, kHandshakeSendMs);
                o.stopping = env_.stopping;
                const Bytes notice = resultStatus(Status::Replaced);
                const bool sent = left > 0 && sendFrame(s_, kMsgResult, notice, o);
                log("auth.replaced_notice peer=" + ip_ + " sent=" + (sent ? "1" : "0"));
                if (sent) {
                    shutdownWrite(s_);
                    drainAfterNotice(s_, std::min(env_.noticeLingerMs, life.hardCloseLeftMs(env_.hardCloseMs)));
                }
            }
        } else if (voided && why && (*why == CloseReason::Blocked || *why == CloseReason::Lockdown)) {
            resetPeer();
        }
        env_.broker->end(token);
    }

    void resetPeer() {
        setResetOnClose(s_);
        reset_ = true;
    }

private:
    void log(const std::string& line) {
        if (env_.log) env_.log(line);
    }
    void authLog(const std::string& event, const std::string& line) {
        if (env_.authLog) env_.authLog->log(event, ip_, line);
        else log(line);
    }
    void reject(const std::string& line) {
        if (env_.counters) ++env_.counters->rejected;
        log(line);
    }

    // A handshake frame: no revocation check, kHandshakeSendMs at most.
    bool sendHandshake(uint8_t type, const Bytes& payload) {
        SendOpts o;
        o.stopping = env_.stopping;
        return sendFrame(s_, type, payload, o);
    }

    // Mac peerCheck (admitPeerMessage): the journal lockdown, then the
    // blacklist, asked with an open connection's peer on every message.
    bool peerRefused() {
        const auto why = env_.guard->inputRefusal(ip_);
        if (!why) return false;
        if (env_.peerRefusedOnce.due())
            log("auth.peer_refused peer=" + ip_ + " reason=" + *why + " entry=open_connection; closed");
        return true;
    }

    // Mac sessionRevoked, for sends (the policy part is the connection's
    // epoch on Windows: a change voids it in the broker).
    bool sessionRevoked(const char* kind) {
        if (env_.refreshPolicy) env_.refreshPolicy();
        if (!peerRefused()) return false;
        reject("Control reject peer=" + ip_ + " reason=peer_refused session=" + kind + " on " + env_.endpoint +
               "; open connection closed");
        return true;
    }

    bool sendAuthOK(const AuthOK& ok, const ConnLife& life) {
        if (env_.failAuthOKForTest && env_.failAuthOKForTest(ok)) return false;
        if (sendChecked(&life, "auth", kMsgResult, resultOk(ok.macH, ok.sessionId), kHandshakeSendMs) !=
            CheckedSend::Sent) {
            log("auth.ok_send_failed peer=" + ip_ + " chan=" + channelName(ok.channel) +
                " limit_s=" + std::to_string(kHandshakeSendMs / 1000));
            return false;
        }
        log("auth.ok peer=" + ip_ + " chan=" + channelName(ok.channel) + " session=" + hex(ok.sessionId));
        return true;
    }

    // r4: a refused reconnect gets REPLACED (the notice's status). Not a
    // failure: nothing counted.
    void refuseResume(Channel channel, const char* stage) {
        if (env_.counters) ++env_.counters->resumesRefused;
        const bool sent = sendHandshake(kMsgResult, resultStatus(Status::Replaced));
        authLog("auth.resume_refused", "auth.resume_refused peer=" + ip_ + " chan=" + channelName(channel) +
                                           " stage=" + stage + " reason=auto_while_connected sent=" +
                                           (sent ? "1" : "0") + " counted=0");
        if (sent) {
            shutdownWrite(s_);
            drainAfterNotice(s_, env_.noticeLingerMs);
        }
    }

    // No challenge, or an answer that came after a wait or the blacklist
    // started: the viewer learns why, nothing is counted.
    void refuse(const AuthGuard::Admission& a, bool afterChallenge) {
        const std::string note = afterChallenge ? " after_challenge=1 counted=0" : "";
        bool sent = false;
        switch (a.kind) {
        case AuthGuard::Admission::Blocked:
            sent = sendHandshake(kMsgResult, resultStatus(Status::Blocked));
            authLog("auth.blocked", "auth.blocked peer=" + ip_ + note + "; connection closed");
            break;
        case AuthGuard::Admission::NotAllowed:
            reject("Control reject peer=" + ip_ + " expected=whitelist on " + env_.endpoint + note +
                   "; connection closed");
            break;
        case AuthGuard::Admission::Locked:
            sent = sendHandshake(kMsgResult, resultLocked(a.retrySeconds));
            authLog("auth.locked", "auth.locked peer=" + ip_ + " retry_s=" + std::to_string(a.retrySeconds) +
                                       " stage=" + std::to_string(a.stage) + note + "; connection closed");
            break;
        case AuthGuard::Admission::GlobalLocked:
            sent = sendHandshake(kMsgResult, resultLocked(a.retrySeconds));
            authLog("auth.global_locked", "auth.global_locked peer=" + ip_ +
                                              " retry_s=" + std::to_string(a.retrySeconds) + note +
                                              "; connection closed");
            break;
        case AuthGuard::Admission::Challenge:
            break;
        }
        // After the challenge the viewer's answer may be partly unread.
        if (afterChallenge) lingerAfterNotice(sent);
    }

    // The viewer closed (or the socket failed) before answering: nothing
    // tried, nothing counted.
    void noteNoResponse(bool error, int code) {
        if (error)
            authLog("auth.no_response",
                    "auth.no_response peer=" + ip_ + " reason=read_error errno=" + std::to_string(code) + " counted=0");
        else
            authLog("auth.no_response", "auth.no_response peer=" + ip_ + " reason=closed counted=0");
    }

    // A timeout or a malformed answer: settled like a wrong password, so
    // the waits are checked again first.
    void settleFailure(const char* reason) {
        finishFailure(env_.guard->settle(ip_, [] { return false; }), reason);
    }

    void finishFailure(const AuthGuard::Settlement& s, const std::string& reason) {
        if (s.kind == AuthGuard::Settlement::Ok) return;
        if (s.kind == AuthGuard::Settlement::Refused) {
            refuse(s.admission, true);
            return;
        }
        const AuthGuard::Failure& f = s.failure;
        if (env_.counters) ++env_.counters->failures;
        if (env_.failureLog) env_.failureLog->record(ip_, reason, f.failures, env_.wallNow ? env_.wallNow() : 0);
        Bytes result;
        const std::string head =
            "auth.fail peer=" + ip_ + " chan=unknown reason=" + reason + " failures=" + std::to_string(f.failures);
        switch (f.outcome.kind) {
        case AuthGuard::FailureOutcome::Retry:
            result = resultFail(f.outcome.triesLeft);
            log(head + " tries=" + std::to_string(f.outcome.triesLeft));
            break;
        case AuthGuard::FailureOutcome::Locked:
            result = resultLocked(f.outcome.retrySeconds);
            log(head);
            log("auth.locked peer=" + ip_ + " retry_s=" + std::to_string(f.outcome.retrySeconds) +
                " stage=" + std::to_string(f.outcome.stage));
            break;
        case AuthGuard::FailureOutcome::Blacklisted:
            result = resultStatus(Status::Blocked);
            log(head);
            log(f.outcome.persisted ? "auth.blocked peer=" + ip_ + " failures=" + std::to_string(f.failures) +
                                          " persisted=registry"
                                    : "auth.blocked peer=" + ip_ + " failures=" + std::to_string(f.failures) +
                                          " persisted=no attempts=" + std::to_string(AuthGuard::kSaveAttempts) +
                                          " (blocked in memory until restart)");
            break;
        }
        if (f.globalTriggered) log("auth.global_locked retry_s=" + std::to_string(uint32_t(AuthGuard::kGlobalWait)));
        const bool sent = sendHandshake(kMsgResult, result);
        // Windows: its other open connections close now.
        if (f.outcome.kind == AuthGuard::FailureOutcome::Blacklisted) kickNewlyBlocked(*env_.guard, *env_.broker);
        lingerAfterNotice(sent);
    }

    // A failure answer can leave the viewer's input unread (a bad header or
    // length leaves its payload behind). A plain close then sends an RST,
    // and Windows may throw away the RESULT before the viewer reads it. So:
    // FIN, then read and drop until the viewer closes, at most
    // noticeLingerMs (the same drain as after REPLACED).
    void lingerAfterNotice(bool sent) {
        if (!sent) return;
        shutdownWrite(s_);
        drainAfterNotice(s_, env_.noticeLingerMs);
    }

    AuthEnv& env_;
    SocketHandle s_;
    std::string ip_;
    bool reset_ = false;
};

}  // namespace jlh::auth
