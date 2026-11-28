// JerisLink Windows host: reading a control connection with a way out.
//
// r10 (Pepper's review of f919167, item 1): a connection that loses input
// ownership for going quiet (InputClaims::expire) is closed then, not at
// its next frame: its reader waits for data in short slices and stops as
// soon as stop() says so, so serveControl closes the socket and gives the
// slot back. Portable (Winsock or POSIX) so host_test runs the same code
// on a real socket.
#pragma once

#include "host_protocol.hpp"

#ifdef _WIN32
#include <winsock2.h>
#else
#include <cerrno>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#endif

#include <cstddef>
#include <cstdint>
#include <vector>

namespace jlh {

#ifdef _WIN32
using SocketHandle = SOCKET;
#else
using SocketHandle = int;
#endif

// The reader checks stop() at least this often while nothing arrives.
constexpr int kReadSliceMs = 50;

// Why serveControl's reader of a live connection stops: the host is
// shutting down, or connection o lost input ownership for going quiet
// (InputClaims::expire). The connection is closed then.
inline bool stopLiveRead(bool running, const InputClaims& claims, InputClaims::Owner o) {
    return !running || claims.silenced(o);
}

enum class ReadResult {
    Ok,       // the bytes asked for arrived
    Closed,   // the peer closed, or the socket failed
    Stopped,  // stop() said so: the caller closes the connection
};

// Waits until s has something to read (or is closed), checking stop()
// before each wait of at most sliceMs and once more when data is there.
template <class Stop>
ReadResult waitReadable(SocketHandle s, int sliceMs, Stop&& stop) {
    for (;;) {
        if (stop()) return ReadResult::Stopped;
        fd_set r;
        FD_ZERO(&r);
        FD_SET(s, &r);
        timeval tv{};
        tv.tv_sec = sliceMs / 1000;
        tv.tv_usec = (sliceMs % 1000) * 1000;
#ifdef _WIN32
        const int n = select(0, &r, nullptr, nullptr, &tv);
#else
        const int n = select(s + 1, &r, nullptr, nullptr, &tv);
        if (n < 0 && errno == EINTR) continue;
#endif
        if (n < 0) return ReadResult::Closed;
        if (n > 0) return stop() ? ReadResult::Stopped : ReadResult::Ok;
    }
}

// A recv() that failed only because nothing was there yet (non-blocking
// socket, after select said readable) or a signal came: try again.
inline bool recvWouldRetry() {
#ifdef _WIN32
    const int e = WSAGetLastError();
    return e == WSAEWOULDBLOCK || e == WSAEINTR;
#else
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
#endif
}

// Exactly n bytes, or why not.
template <class Stop>
ReadResult recvExactUntil(SocketHandle s, uint8_t* p, size_t n, int sliceMs, Stop&& stop) {
    while (n) {
        const ReadResult w = waitReadable(s, sliceMs, stop);
        if (w != ReadResult::Ok) return w;
        const auto r = recv(s, reinterpret_cast<char*>(p), int(n), 0);
        if (r < 0 && recvWouldRetry()) continue;  // H3: viewer sockets are non-blocking
        if (r <= 0) return ReadResult::Closed;
        p += r;
        n -= size_t(r);
    }
    return ReadResult::Ok;
}

// One MRC1 frame: header, then its payload. A header that does not parse
// reads as Closed (serveControl closes the connection, as before).
template <class Stop>
ReadResult readMrc1FrameUntil(SocketHandle s, Mrc1Header& hdr, std::vector<uint8_t>& payload, int sliceMs,
                              Stop&& stop) {
    uint8_t h[kMrc1HeaderBytes];
    ReadResult r = recvExactUntil(s, h, sizeof(h), sliceMs, stop);
    if (r != ReadResult::Ok) return r;
    const auto parsed = parseMrc1Header(h);
    if (!parsed) return ReadResult::Closed;
    hdr = *parsed;
    payload.resize(hdr.length);
    if (hdr.length == 0) return ReadResult::Ok;
    return recvExactUntil(s, payload.data(), hdr.length, sliceMs, stop);
}

}  // namespace jlh
