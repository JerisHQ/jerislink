import Foundation
import Darwin

/// Connection to JerisLink Input Helper (MRI1 on 127.0.0.1:38410).
///
/// The helper serves one connection at a time: it handles a client until that
/// client disconnects, then accepts the next. A process must therefore use a
/// single InputHelperClient for every ControlServer it runs (see
/// `ControlService`); a second connection would sit in the helper's backlog and
/// its events would never be posted. All calls are serialised by `lock`, and
/// socket timeouts keep a busy or wedged helper from blocking a caller forever.
final class InputHelperClient: @unchecked Sendable {
    static let defaultPort: UInt16 = 38410
    private static let ioTimeoutSeconds = 2

    private let host = "127.0.0.1"
    private let port: UInt16
    private let lock = NSLock()
    private var fd: Int32 = -1
    /// Viewer input sessions this host has started (SESSION_START delivered)
    /// and not yet ended. Re-announced on every new MRI1 connection, so a
    /// helper that restarted or dropped the socket learns the live sessions
    /// again before the next event.
    private var announcedSessions: [UInt32] = []

    /// `port` nil: JERISLINK_INPUT_HELPER_PORT, else 38410.
    init(port: UInt16? = nil) {
        if let port {
            self.port = port
        } else if let raw = ProcessInfo.processInfo.environment["JERISLINK_INPUT_HELPER_PORT"],
                  let parsed = UInt16(raw), parsed > 0 {
            self.port = parsed
        } else {
            self.port = Self.defaultPort
        }
    }

    deinit { closeLocked() }

    func closeConnection() {
        lock.lock(); defer { lock.unlock() }
        closeLocked()
    }

    /// Send one packet, reconnecting once if the connection dropped.
    private func deliver(_ bytes: [UInt8]) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return deliverLocked(bytes)
    }

    private func deliverLocked(_ bytes: [UInt8]) -> Bool {
        dropIfPeerClosedLocked()
        if sendAll(bytes) { return true }
        closeLocked()
        return sendAll(bytes)
    }

    /// The helper never sends unsolicited data, so a readable socket means it
    /// closed its end. Without this check the first packet after a helper
    /// restart is written into a dead socket and lost (send only fails on the
    /// packet after it). One non-blocking peek, no wait.
    private func dropIfPeerClosedLocked() {
        guard fd >= 0 else { return }
        var b: UInt8 = 0
        let n = Darwin.recv(fd, &b, 1, MSG_PEEK | MSG_DONTWAIT)
        if n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) { closeLocked() }
    }

    private func closeLocked() {
        if fd >= 0 { Darwin.shutdown(fd, SHUT_RDWR); Darwin.close(fd); fd = -1 }
    }

    private func ensureConnected() -> Bool {
        if fd >= 0 { return true }
        let s = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard s >= 0 else { return false }
        var noSigPipe: Int32 = 1
        setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))
        var tv = timeval(tv_sec: Self.ioTimeoutSeconds, tv_usec: 0)
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        _ = host.withCString { inet_pton(AF_INET, $0, &addr.sin_addr) }
        let rc = withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard rc == 0 else { Darwin.close(s); return false }
        fd = s
        // A new MRI1 connection starts with an empty session set in the
        // helper: re-announce every live session before anything else.
        for id in announcedSessions {
            guard writeAll(packet(type: Self.sessionStartType, payload: Self.sessionIDBytes(id))) else { return false }
        }
        return true
    }

    private func packet(type: UInt8, payload: [UInt8]) -> [UInt8] {
        let n = UInt16(payload.count)
        return [0x4d,0x52,0x49,0x31,1,type,UInt8(n >> 8),UInt8(n & 0xff)] + payload
    }

    private func sendAll(_ bytes: [UInt8]) -> Bool {
        guard ensureConnected() else { return false }
        return writeAll(bytes)
    }

    /// Write on the current socket; closes it on failure.
    private func writeAll(_ bytes: [UInt8]) -> Bool {
        var off = 0
        while off < bytes.count {
            let n = bytes.withUnsafeBytes { raw in
                Darwin.send(fd, raw.baseAddress!.advanced(by: off), bytes.count - off, 0)
            }
            if n <= 0 { closeLocked(); return false }
            off += n
        }
        return true
    }

    private func recvExact(_ count: Int) -> [UInt8]? {
        var out = [UInt8](repeating: 0, count: count)
        var off = 0
        while off < count {
            let n = out.withUnsafeMutableBytes { raw in
                Darwin.recv(fd, raw.baseAddress!.advanced(by: off), count - off, 0)
            }
            if n <= 0 { closeLocked(); return nil }
            off += n
        }
        return out
    }

    func ping() -> Bool {
        lock.lock(); defer { lock.unlock() }
        let payload: [UInt8] = [0x12,0x34,0x56,0x78]
        guard sendAll(packet(type: 0x01, payload: payload)), let h = recvExact(8) else { return false }
        let len = Int(UInt16(h[6]) << 8 | UInt16(h[7]))
        guard h[0] == 0x4d, h[1] == 0x52, h[2] == 0x49, h[3] == 0x31, h[4] == 1, h[5] == 0x02,
              let p = recvExact(len) else { return false }
        return p == payload
    }

    /// MRI1 SESSION_START (0x50) and SESSION_END (0x51), payload: a 4-byte
    /// big-endian session id. Sent once per viewer input session by
    /// `ControlServer`, never per event. The helper keeps a set of live ids,
    /// checks post-event access on a new START and ignores an END for an id it
    /// does not know (a session from before a helper restart).
    static let sessionStartType: UInt8 = 0x50
    static let sessionEndType: UInt8 = 0x51

    static func sessionIDBytes(_ id: UInt32) -> [UInt8] {
        [UInt8(id >> 24), UInt8((id >> 16) & 0xff), UInt8((id >> 8) & 0xff), UInt8(id & 0xff)]
    }

    /// True when START reached the helper; only then is the session announced
    /// again after a reconnect.
    func sendSessionStart(id: UInt32) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard deliverLocked(packet(type: Self.sessionStartType, payload: Self.sessionIDBytes(id))) else { return false }
        if !announcedSessions.contains(id) { announcedSessions.append(id) }
        return true
    }

    func sendSessionEnd(id: UInt32) -> Bool {
        lock.lock(); defer { lock.unlock() }
        announcedSessions.removeAll { $0 == id }
        return deliverLocked(packet(type: Self.sessionEndType, payload: Self.sessionIDBytes(id)))
    }

    func sendKey(cgCode: UInt16, down: Bool) -> Bool {
        let payload: [UInt8] = [down ? 1 : 0, UInt8(cgCode >> 8), UInt8(cgCode & 0xff)]
        let bytes = packet(type: 0x10, payload: payload)
        return deliver(bytes)
    }


    private func int16Bytes(_ v: Int16) -> [UInt8] {
        let u = UInt16(bitPattern: v)
        return [UInt8(u >> 8), UInt8(u & 0xff)]
    }

    private func uint16Bytes(_ v: UInt16) -> [UInt8] {
        [UInt8(v >> 8), UInt8(v & 0xff)]
    }

    func sendMouseMove(dx: Int16, dy: Int16) -> Bool {
        let bytes = packet(type: 0x20, payload: int16Bytes(dx) + int16Bytes(dy))
        return deliver(bytes)
    }

    func sendMouseMoveAbsolute(x: UInt16, y: UInt16) -> Bool {
        let bytes = packet(type: 0x23, payload: uint16Bytes(x) + uint16Bytes(y))
        return deliver(bytes)
    }

    func sendMouseMoveNormalized(nx: UInt16, ny: UInt16) -> Bool {
        let bytes = packet(type: 0x24, payload: uint16Bytes(nx) + uint16Bytes(ny))
        return deliver(bytes)
    }

    func sendMouseButton(button: UInt8, down: Bool) -> Bool {
        let bytes = packet(type: 0x21, payload: [button, down ? 1 : 0])
        return deliver(bytes)
    }

    func sendMouseButtonExtended(button: UInt8, down: Bool, clickCount: UInt8) -> Bool {
        let bytes = packet(type: 0x25, payload: [button, down ? 1 : 0, max(1, clickCount)])
        return deliver(bytes)
    }

    func sendScroll(dx: Int16, dy: Int16) -> Bool {
        let bytes = packet(type: 0x22, payload: int16Bytes(dx) + int16Bytes(dy))
        return deliver(bytes)
    }
}
