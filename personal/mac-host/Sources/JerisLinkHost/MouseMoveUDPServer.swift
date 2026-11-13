import Foundation
import Darwin
import AppKit

private enum RemoteCursorShape: UInt8 {
    case arrow = 0
    case iBeam = 1
    case pointingHand = 2
    case resizeLeftRight = 3
    case resizeUpDown = 4
    case resizeNWSE = 5
    case resizeNESW = 6
    case crosshair = 7
    case openHand = 8
    case closedHand = 9
    case notAllowed = 10
    case verticalIBeam = 11
}

/// Reads the current macOS system cursor only when the remote pointer moves.
/// Most standard cursors can be identified cheaply by image size + hotspot;
/// image serialization is reserved for the two diagonal resize orientations.
private final class CursorShapeDetector {
    private let diagonalNWSESignature: Data?
    private let diagonalNESWSignature: Data?

    init() {
        if #available(macOS 15.0, *) {
            diagonalNWSESignature = NSCursor.frameResize(position: .topLeft, directions: .all)
                .image.tiffRepresentation
            diagonalNESWSignature = NSCursor.frameResize(position: .topRight, directions: .all)
                .image.tiffRepresentation
        } else {
            diagonalNWSESignature = nil
            diagonalNESWSignature = nil
        }
    }

    func currentShape() -> RemoteCursorShape {
        guard let cursor = NSCursor.currentSystem else { return .arrow }
        let size = cursor.image.size
        let hot = cursor.hotSpot
        let geometry = (
            Int(size.width.rounded()), Int(size.height.rounded()),
            Int(hot.x.rounded()), Int(hot.y.rounded())
        )

        switch geometry {
        case (23, 22, 12, 11): return .iBeam
        case (22, 21, 11, 10): return .verticalIBeam
        case (32, 32, 13, 8): return .pointingHand
        case (32, 32, 16, 17): return .openHand
        case (24, 24, 11, 11): return .crosshair
        case (30, 24, 15, 12): return .resizeLeftRight
        case (24, 28, 12, 14): return .resizeUpDown
        case (24, 24, 12, 12): return .resizeLeftRight
        case (24, 24, 12, 13), (24, 24, 12, 11): return .resizeUpDown
        case (22, 22, 11, 11):
            guard let current = cursor.image.tiffRepresentation else { return .resizeNWSE }
            if let diagonalNESWSignature, current == diagonalNESWSignature { return .resizeNESW }
            if let diagonalNWSESignature, current == diagonalNWSESignature { return .resizeNWSE }
            return .resizeNWSE
        default:
            return .arrow
        }
    }
}

/// The video service's mouse relay into the control service's loopback
/// listener (127.0.0.1:38411). Internal so the control self-test drives it.
final class LocalControlMouseClient {
    private let host = "127.0.0.1"
    private let port: UInt16
    private var fd: Int32 = -1

    init(port: UInt16 = 38411) { self.port = port }

    deinit { closeConnection() }

    func closeConnection() {
        if fd >= 0 {
            Darwin.shutdown(fd, SHUT_RDWR)
            Darwin.close(fd)
            fd = -1
        }
    }

    private func ensureConnected() -> Bool {
        if fd >= 0 { return true }
        let s = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard s >= 0 else { return false }

        var noSigPipe: Int32 = 1
        setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))

        var noDelay: Int32 = 1
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &noDelay, socklen_t(MemoryLayout<Int32>.size))

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
        guard rc == 0 else {
            Darwin.close(s)
            return false
        }
        fd = s
        return true
    }

    private func sendAll(_ bytes: [UInt8]) -> Bool {
        guard ensureConnected() else { return false }
        var offset = 0
        while offset < bytes.count {
            let n = bytes.withUnsafeBytes { raw in
                Darwin.send(fd, raw.baseAddress!.advanced(by: offset), bytes.count - offset, 0)
            }
            if n <= 0 {
                closeConnection()
                return false
            }
            offset += n
        }
        return true
    }

    func sendMouseMoveNormalized(nx: UInt16, ny: UInt16) -> Bool {
        let payload: [UInt8] = [
            UInt8(nx >> 8), UInt8(nx & 0xff),
            UInt8(ny >> 8), UInt8(ny & 0xff)
        ]
        let n = UInt16(payload.count)
        let packet: [UInt8] = [
            0x4d, 0x52, 0x43, 0x31, // MRC1
            1, 0x24,
            UInt8(n >> 8), UInt8(n & 0xff)
        ] + payload
        if sendAll(packet) { return true }
        closeConnection()
        return sendAll(packet)
    }
}

/// Low-latency UDP side-channel used for disposable mouse movement and
/// video-recovery feedback. Keyboard, buttons, scroll and clipboard remain
/// on the reliable TCP control path.
/// Common header:
///   0..3  "MRM1"
///   4     version = 1
///   5     type (0x24 mouse move, 0x31 cursor state, 0x40 request keyframe,
///         0x41 NACK, 0x43 ping, 0x44 pong)
///   6..9  sequence, big-endian UInt32
/// Mouse move appends nx/ny as two big-endian UInt16 values (14 bytes total).
/// Cursor state appends one RemoteCursorShape byte (11 bytes total, Mac->Windows).
/// Keyframe request is header-only (10 bytes total).
/// NACK appends frameID u64, count u8, then count x (start u16, count u16)
/// packet ranges (19 + 4*count bytes, count 1...32). (0, 0xFFFF) = whole frame.
/// Ping appends the viewer clock in microseconds (u64, 18 bytes total); the
/// host echoes the same 18 bytes back with type 0x44 so the viewer can
/// measure RTT on the live path.
final class MouseMoveUDPServer: @unchecked Sendable {
    private let bindIP: String
    private let allowedClientIP: String?
    private let port: UInt16
    private let queue = DispatchQueue(label: "JerisLink.MouseMoveUDP", qos: .userInteractive)
    private let cursorQueue = DispatchQueue(label: "JerisLink.CursorStateUDP", qos: .userInteractive)
    private let lock = NSLock()
    private let controlRelay = LocalControlMouseClient()
    private var cursorDetector: CursorShapeDetector?
    private var fd: Int32 = -1
    private var stopping = false
    private var lastSequence: UInt32?
    private var lastPeerPort: UInt16?
    private var keyframeRequestHandler: (() -> Void)?
    private var nackHandler: ((UInt64, [UDPFrameSender.NackRange]) -> Void)?
    private var newSessionHandler: (() -> Void)?
    private var lastPeerAddress: sockaddr_in?
    private var lastCursorShape: RemoteCursorShape?
    private var cursorSequence: UInt32 = 0
    private var cursorProbePending = false
    private var lastCursorProbeNs: UInt64 = 0

    private static let cursorProbeIntervalNs: UInt64 = 16_000_000
    private static let cursorSettleDelayNs: UInt64 = 8_000_000

    private(set) var received: UInt64 = 0
    private(set) var forwarded: UInt64 = 0
    private(set) var rejected: UInt64 = 0
    private(set) var staleDropped: UInt64 = 0
    private(set) var badPackets: UInt64 = 0
    private(set) var keyframeRequests: UInt64 = 0
    private(set) var cursorUpdates: UInt64 = 0
    private(set) var cursorUpdateDrops: UInt64 = 0
    private(set) var nackRx: UInt64 = 0
    private(set) var pingRx: UInt64 = 0
    private(set) var pongDrops: UInt64 = 0

    init(bindIP: String, allowedClientIP: String?, port: UInt16) {
        self.bindIP = bindIP
        self.allowedClientIP = allowedClientIP
        self.port = port
    }

    func start() throws {
        let s = Darwin.socket(AF_INET, SOCK_DGRAM, 0)
        guard s >= 0 else {
            throw NSError(domain: "JerisLink.MouseMoveUDP", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "mouse UDP socket failed errno=\(errno)"])
        }

        var yes: Int32 = 1
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        let pton = bindIP.withCString { inet_pton(AF_INET, $0, &addr.sin_addr) }
        guard pton == 1 else {
            Darwin.close(s)
            throw NSError(domain: "JerisLink.MouseMoveUDP", code: 2,
                          userInfo: [NSLocalizedDescriptionKey: "invalid mouse UDP bind IP \(bindIP)"])
        }

        let rc = withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard rc == 0 else {
            let e = errno
            Darwin.close(s)
            throw NSError(domain: "JerisLink.MouseMoveUDP", code: 3,
                          userInfo: [NSLocalizedDescriptionKey: "mouse UDP bind failed errno=\(e)"])
        }

        lock.lock()
        fd = s
        stopping = false
        lastSequence = nil
        lastPeerPort = nil
        lastPeerAddress = nil
        lastCursorShape = nil
        cursorSequence = 0
        cursorProbePending = false
        lastCursorProbeNs = 0
        lock.unlock()

        print("MouseMove UDP: \(bindIP):\(port), allowedClient=\(allowedClientIP ?? "any"), relay=127.0.0.1:38411, cursor_state=move-triggered")
        queue.async { [weak self] in self?.receiveLoop() }
    }

    /// Called when a new viewer session appears (first packet, or a new
    /// source port after the viewer restarted or reconnected).
    func setNewSessionHandler(_ handler: @escaping () -> Void) {
        lock.lock()
        newSessionHandler = handler
        lock.unlock()
    }

    func setKeyframeRequestHandler(_ handler: @escaping () -> Void) {
        lock.lock()
        keyframeRequestHandler = handler
        lock.unlock()
    }

    /// Called on the receive queue for each valid NACK packet.
    func setNackHandler(_ handler: @escaping (UInt64, [UDPFrameSender.NackRange]) -> Void) {
        lock.lock()
        nackHandler = handler
        lock.unlock()
    }

    func stop() {
        lock.lock()
        stopping = true
        let s = fd
        fd = -1
        keyframeRequestHandler = nil
        nackHandler = nil
        newSessionHandler = nil
        lastPeerAddress = nil
        cursorProbePending = false
        lock.unlock()
        if s >= 0 {
            Darwin.shutdown(s, SHUT_RDWR)
            Darwin.close(s)
        }
        controlRelay.closeConnection()
    }

    func statsLine() -> String {
        return "mouse_udp_rx=\(received) mouse_udp_forwarded=\(forwarded) mouse_udp_rejected=\(rejected) mouse_udp_stale=\(staleDropped) mouse_udp_bad=\(badPackets) keyframe_requests=\(keyframeRequests) cursor_updates=\(cursorUpdates) cursor_update_drops=\(cursorUpdateDrops) nack_rx=\(nackRx) ping_rx=\(pingRx) pong_drops=\(pongDrops)"
    }

    /// Coalesce cursor-shape checks onto a separate queue. There is no periodic
    /// AppKit timer: when the remote pointer is idle, cursor probing is idle too.
    private func scheduleCursorShapeProbe(peer: sockaddr_in) {
        let now = DispatchTime.now().uptimeNanoseconds
        lock.lock()
        guard !stopping, fd >= 0 else {
            lock.unlock()
            return
        }
        lastPeerAddress = peer
        if cursorProbePending {
            lock.unlock()
            return
        }
        let elapsed = now >= lastCursorProbeNs ? now - lastCursorProbeNs : Self.cursorProbeIntervalNs
        let rateDelay = elapsed >= Self.cursorProbeIntervalNs ? 0 : Self.cursorProbeIntervalNs - elapsed
        let delay = max(Self.cursorSettleDelayNs, rateDelay)
        cursorProbePending = true
        lock.unlock()

        cursorQueue.asyncAfter(deadline: .now() + .nanoseconds(Int(delay))) { [weak self] in
            self?.probeCursorShape()
        }
    }

    private func probeCursorShape() {
        lock.lock()
        guard !stopping, fd >= 0, let peer = lastPeerAddress else {
            cursorProbePending = false
            lock.unlock()
            return
        }
        lock.unlock()

        let detector: CursorShapeDetector
        if let existing = cursorDetector {
            detector = existing
        } else {
            let created = CursorShapeDetector()
            cursorDetector = created
            detector = created
        }
        let shape = detector.currentShape()
        let now = DispatchTime.now().uptimeNanoseconds

        lock.lock()
        cursorProbePending = false
        lastCursorProbeNs = now
        guard !stopping, fd >= 0 else {
            lock.unlock()
            return
        }
        if lastCursorShape == shape {
            lock.unlock()
            return
        }
        lastCursorShape = shape
        cursorSequence &+= 1
        let seq = cursorSequence
        let s = fd
        lock.unlock()

        let packet: [UInt8] = [
            0x4d, 0x52, 0x4d, 0x31,
            1, 0x31,
            UInt8(seq >> 24), UInt8((seq >> 16) & 0xff),
            UInt8((seq >> 8) & 0xff), UInt8(seq & 0xff),
            shape.rawValue
        ]
        var destination = peer
        let n = packet.withUnsafeBytes { raw -> Int in
            guard let base = raw.baseAddress else { return -1 }
            return withUnsafePointer(to: &destination) { p in
                p.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    Darwin.sendto(s, base, packet.count, 0, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        lock.lock()
        if n == packet.count {
            cursorUpdates &+= 1
        } else {
            cursorUpdateDrops &+= 1
            lastCursorShape = nil
        }
        lock.unlock()
    }

    private func receiveLoop() {
        var buffer = [UInt8](repeating: 0, count: 256)
        while true {
            lock.lock()
            let shouldStop = stopping
            let s = fd
            lock.unlock()
            if shouldStop || s < 0 { return }

            var peer = sockaddr_in()
            var peerLen = socklen_t(MemoryLayout<sockaddr_in>.size)
            let capacity = buffer.count
            let n = buffer.withUnsafeMutableBytes { raw -> Int in
                guard let base = raw.baseAddress else { return -1 }
                return withUnsafeMutablePointer(to: &peer) { p in
                    p.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                        Darwin.recvfrom(s, base, capacity, 0, sa, &peerLen)
                    }
                }
            }
            if n < 0 {
                lock.lock(); let nowStopping = stopping; lock.unlock()
                if nowStopping { return }
                continue
            }
            received &+= 1

            let peerIP = String(cString: inet_ntoa(peer.sin_addr))
            if let allowedClientIP, peerIP != allowedClientIP {
                rejected &+= 1
                continue
            }

            // A freshly launched Windows viewer creates a new UDP socket and
            // starts its packet sequence again at 1. Treat a source-port
            // change as a new mouse session so the new viewer is not mistaken
            // for stale/reordered traffic from the previous process.
            let peerPort = UInt16(bigEndian: peer.sin_port)
            if lastPeerPort != peerPort {
                lastPeerPort = peerPort
                lastSequence = nil
                lock.lock()
                lastPeerAddress = peer
                lastCursorShape = nil
                let sessionHandler = newSessionHandler
                lock.unlock()
                print("MouseMove UDP new session peer=\(peerIP):\(peerPort)")
                fflush(stdout)
                sessionHandler?()
            }
            guard n >= 10,
                  buffer[0] == 0x4d, buffer[1] == 0x52, buffer[2] == 0x4d, buffer[3] == 0x31,
                  buffer[4] == 1 else {
                badPackets &+= 1
                continue
            }

            let seq = UInt32(buffer[6]) << 24 |
                      UInt32(buffer[7]) << 16 |
                      UInt32(buffer[8]) << 8 |
                      UInt32(buffer[9])
            if let last = lastSequence, !Self.isNewer(seq, than: last) {
                staleDropped &+= 1
                continue
            }
            lastSequence = seq

            switch buffer[5] {
            case 0x24:
                guard n == 14 else {
                    badPackets &+= 1
                    continue
                }
                let nx = UInt16(buffer[10]) << 8 | UInt16(buffer[11])
                let ny = UInt16(buffer[12]) << 8 | UInt16(buffer[13])
                if controlRelay.sendMouseMoveNormalized(nx: nx, ny: ny) {
                    forwarded &+= 1
                    scheduleCursorShapeProbe(peer: peer)
                }
            case 0x40:
                guard n == 10 else {
                    badPackets &+= 1
                    continue
                }
                lock.lock()
                let handler = keyframeRequestHandler
                lock.unlock()
                keyframeRequests &+= 1
                print("video.keyframe_request_rx seq=\(seq) total=\(keyframeRequests)")
                fflush(stdout)
                handler?()
            case 0x41:
                guard let parsed = Self.parseNack(buffer, length: n) else {
                    badPackets &+= 1
                    continue
                }
                lock.lock()
                let handler = nackHandler
                lock.unlock()
                nackRx &+= 1
                handler?(parsed.0, parsed.1)
            case 0x43:
                guard n == 18 else {
                    badPackets &+= 1
                    continue
                }
                pingRx &+= 1
                var pong = Array(buffer[0..<18])
                pong[5] = 0x44
                var destination = peer
                let sent = pong.withUnsafeBytes { raw -> Int in
                    guard let base = raw.baseAddress else { return -1 }
                    return withUnsafePointer(to: &destination) { p in
                        p.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                            Darwin.sendto(s, base, 18, 0, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
                        }
                    }
                }
                if sent != 18 { pongDrops &+= 1 }
            default:
                badPackets &+= 1
            }
        }
    }

    /// Sequence order that survives the UInt32 wrap (RFC 1982 style): `seq` is
    /// newer when it is less than 2^31 steps ahead of `last`.
    static func isNewer(_ seq: UInt32, than last: UInt32) -> Bool {
        Int32(bitPattern: seq &- last) > 0
    }

    /// Parses an MRM1 0x41 NACK. Returns nil unless the length matches the
    /// declared range count exactly and every range is well formed.
    static func parseNack(_ b: [UInt8], length n: Int) -> (UInt64, [UDPFrameSender.NackRange])? {
        guard n >= 19, n <= b.count, b[5] == 0x41 else { return nil }
        let count = Int(b[18])
        guard count >= 1, count <= 32, n == 19 + 4 * count else { return nil }
        var frameID: UInt64 = 0
        for i in 10..<18 { frameID = frameID << 8 | UInt64(b[i]) }
        var ranges: [UDPFrameSender.NackRange] = []
        ranges.reserveCapacity(count)
        for r in 0..<count {
            let o = 19 + 4 * r
            let start = UInt16(b[o]) << 8 | UInt16(b[o + 1])
            let len = UInt16(b[o + 2]) << 8 | UInt16(b[o + 3])
            if len == 0 { return nil }
            ranges.append(UDPFrameSender.NackRange(start: start, count: len))
        }
        return (frameID, ranges)
    }
}
