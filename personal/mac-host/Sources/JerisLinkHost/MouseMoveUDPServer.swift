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
///         0x41 NACK, 0x43 ping, 0x44 pong, 0x45 audio request)
///   6..9  sequence, big-endian UInt32
/// Mouse move appends nx/ny as two big-endian UInt16 values (14 bytes total).
/// Cursor state appends one RemoteCursorShape byte (11 bytes total, Mac->Windows).
/// Keyframe request is header-only (10 bytes total).
/// NACK appends frameID u64, count u8, then count x (start u16, count u16)
/// packet ranges (19 + 4*count bytes, count 1...32). (0, 0xFFFF) = whole frame.
/// Ping appends the viewer clock in microseconds (u64, 18 bytes total); the
/// host echoes the same 18 bytes back with type 0x44 so the viewer can
/// measure RTT on the live path.
/// Audio request (13 bytes) appends flags u8 (0x01 = send audio, 0x02 = the
/// viewer decodes Opus, so send MRA1 v2; A1 viewers leave it clear and get
/// v1 PCM) and the viewer UDP port u16 for MRA1. The viewer repeats it every second; the host
/// stops audio 10 s after the last one, or at once on flags 0.
final class MouseMoveUDPServer: @unchecked Sendable {
    private let bindIP: String
    private let allowedClientIP: String?
    private let port: UInt16
    private let queue = DispatchQueue(label: "JerisLink.MouseMoveUDP", qos: .userInteractive)
    private let cursorQueue = DispatchQueue(label: "JerisLink.CursorStateUDP", qos: .userInteractive)
    private let lock = NSLock()
    private let controlRelay: LocalControlMouseClient
    private let relayPort: UInt16
    private var cursorDetector: CursorShapeDetector?
    private var fd: Int32 = -1
    private var stopping = false
    private var replayWindow = SeqReplayWindow()
    private var lastPeerPort: UInt16?
    private var keyframeRequestHandler: (() -> Void)?
    private var nackHandler: ((UInt64, [UDPFrameSender.NackRange]) -> Void)?
    private var newSessionHandler: (() -> Void)?
    private var receiverReportHandler: ((ReceiverReport) -> Void)?
    private var audioRequestHandler: ((Bool, UInt16, Bool, UDPPeerSession.ID?) -> Void)?
    private var lastPeerAddress: sockaddr_in?
    private var lastCursorShape: RemoteCursorShape?
    private var cursorSequence: UInt32 = 0
    private var cursorProbePending = false
    private var lastCursorProbeNs: UInt64 = 0
    /// PR-C: the session link's view of the viewer (nil: the fixed
    /// allowedClientIP, as 0.3). With it, only the session peer is heard,
    /// and in password mode only datagrams with a valid v2h tag; replies
    /// are sealed with the h2v tagger. No session: everything is dropped.
    private let udpSession: UDPSessionState?
    /// Receive loop only.
    private var lastGeneration: UDPPeerSession.ID?
    let badTags = BadTagLog(entry: "mrm1")
    private(set) var noSession: UInt64 = 0

    private static let cursorProbeIntervalNs: UInt64 = 16_000_000
    private static let cursorSettleDelayNs: UInt64 = 8_000_000

    private(set) var received: UInt64 = 0
    private(set) var forwarded: UInt64 = 0
    private(set) var rejected: UInt64 = 0
    private(set) var staleDropped: UInt64 = 0
    /// r2 item 7: unseen late datagrams taken (NACK, receiver report...).
    private(set) var lateAccepted: UInt64 = 0
    /// r2 item 7: a seq already seen inside the window (replay or duplicate).
    private(set) var replayDropped: UInt64 = 0
    private(set) var badPackets: UInt64 = 0
    private(set) var keyframeRequests: UInt64 = 0
    private(set) var cursorUpdates: UInt64 = 0
    private(set) var cursorUpdateDrops: UInt64 = 0
    private(set) var nackRx: UInt64 = 0
    private(set) var pingRx: UInt64 = 0
    private(set) var receiverReportRx: UInt64 = 0
    private(set) var receiverReportRejected: UInt64 = 0  // short or inconsistent 0x42
    private(set) var pongDrops: UInt64 = 0
    private(set) var audioRequestRx: UInt64 = 0
    /// 0x24 moves dropped because input is off (password mode).
    private(set) var inputDropped: UInt64 = 0

    /// False in password mode: UDP input is only IP-checked, so it stays off
    /// until it is bound to an authenticated session (PR-C). Presence,
    /// keyframe, NACK, receiver report, ping and audio still work.
    /// Asked for every 0x24 datagram (LegacyAuthWatch.check in the video
    /// host: one stat while listen.plist is unchanged, a read when it moved),
    /// so a password set between two polls drops the very next move.
    private let inputAllowed: @Sendable () -> Bool
    /// r9: the viewer's block (listen.plist `blockedIPs`, the pending
    /// journal). Asked before each pong and cursor-shape datagram: nothing
    /// goes back to a blocked viewer, while password mode (input off) still
    /// answers pings.
    private let outputAllowed: @Sendable () -> Bool
    /// Set once by `revokeInput`; never cleared (a restart reopens input).
    private var inputRevoked = false
    var inputEnabled: Bool {
        lock.lock(); let revoked = inputRevoked; lock.unlock()
        return !revoked && inputAllowed()
    }

    /// The legacy entries closed (password set or listen.plist unknown): no
    /// UDP input from now on, and the relay connection to the control
    /// service is dropped by the receive loop on the next datagram (the
    /// control service also refuses it on its next message).
    func revokeInput(reason: String) {
        lock.lock(); let first = !inputRevoked; inputRevoked = true; lock.unlock()
        if first {
            print("MouseMove UDP input.revoked reason=\(reason) (relay closed, 0x24 dropped until restart)")
            fflush(stdout)
        }
    }

    /// Told about every valid datagram from the allowed client (video
    /// service: capture runs only while a viewer is heard).
    private let presence: ViewerPresence?
    /// A new source port not yet passed to `presence` (receive loop only).
    private var presenceNewSession = false

    init(bindIP: String, allowedClientIP: String?, port: UInt16, presence: ViewerPresence? = nil,
         relayPort: UInt16 = 38411,
         inputAllowed: @escaping @Sendable () -> Bool = { true },
         outputAllowed: @escaping @Sendable () -> Bool = { true },
         udpSession: UDPSessionState? = nil) {
        self.udpSession = udpSession
        self.relayPort = relayPort
        self.controlRelay = LocalControlMouseClient(port: relayPort)
        self.presence = presence
        self.inputAllowed = inputAllowed
        self.outputAllowed = outputAllowed
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
        replayWindow = SeqReplayWindow()
        lastPeerPort = nil
        lastPeerAddress = nil
        lastCursorShape = nil
        cursorSequence = 0
        cursorProbePending = false
        lastCursorProbeNs = 0
        lock.unlock()

        print("MouseMove UDP: \(bindIP):\(port), allowedClient=\(udpSession != nil ? "session" : allowedClientIP ?? "any"), relay=\(inputEnabled ? "127.0.0.1:\(relayPort)" : "off (password mode)"), cursor_state=move-triggered")
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

    /// Called on the receive queue for each MRM1 0x42 receiver report (ABR).
    func setReceiverReportHandler(_ handler: @escaping (ReceiverReport) -> Void) {
        lock.lock()
        receiverReportHandler = handler
        lock.unlock()
    }

    /// Called on the receive queue for each valid MRM1 0x45 audio request
    /// (enable, viewer audio port, opus, session generation). The peer IP
    /// was already checked. r3 (Pepper's PR-C r2 review, item 5): the
    /// generation is the session the request came in (nil without a session
    /// link), so audio for it never goes to the next viewer.
    func setAudioRequestHandler(_ handler: @escaping (Bool, UInt16, Bool, UDPPeerSession.ID?) -> Void) {
        lock.lock()
        audioRequestHandler = handler
        lock.unlock()
    }

    /// r3 self-test: the source port replies go to (nil: none yet).
    var replyPortForTest: UInt16? {
        lock.lock(); defer { lock.unlock() }
        return lastPeerAddress.map { UInt16(bigEndian: $0.sin_port) }
    }

    func stop() {
        lock.lock()
        stopping = true
        let s = fd
        fd = -1
        keyframeRequestHandler = nil
        nackHandler = nil
        receiverReportHandler = nil
        newSessionHandler = nil
        audioRequestHandler = nil
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
        return "mouse_udp_rx=\(received) mouse_udp_forwarded=\(forwarded) mouse_udp_rejected=\(rejected) mouse_udp_no_session=\(noSession) mouse_udp_bad_tag=\(badTags.total) mouse_udp_stale=\(staleDropped) mouse_udp_late_ok=\(lateAccepted) mouse_udp_replay=\(replayDropped) mouse_udp_bad=\(badPackets) keyframe_requests=\(keyframeRequests) cursor_updates=\(cursorUpdates) cursor_update_drops=\(cursorUpdateDrops) nack_rx=\(nackRx) ping_rx=\(pingRx) pong_drops=\(pongDrops) abr_reports_rx=\(receiverReportRx) abr_reports_rejected=\(receiverReportRejected) audio_requests_rx=\(audioRequestRx)"
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
        // r9: no cursor shape to a blocked viewer.
        guard outputAllowed() else {
            lock.lock(); lastCursorShape = nil; lock.unlock()
            return
        }
        let n = reply(packet, to: peer, socket: s)
        lock.lock()
        if n {
            cursorUpdates &+= 1
        } else {
            cursorUpdateDrops &+= 1
            lastCursorShape = nil
        }
        lock.unlock()
    }

    /// Sends a reply datagram to `peer`, sealed when the session is
    /// tagged. Nothing goes out when the session ended or moved to another
    /// peer since the datagram that asked for it. True when it all went.
    private func reply(_ packet: [UInt8], to peer: sockaddr_in, socket s: Int32) -> Bool {
        var destination = peer
        var tagger: UDPTagger?
        if let udpSession {
            guard let snap = udpSession.snapshot, snap.address.s_addr == peer.sin_addr.s_addr else { return false }
            tagger = snap.send
        }
        return packet.withUnsafeBytes { raw -> Bool in
            withUnsafePointer(to: &destination) { p in
                p.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa -> Bool in
                    let len = socklen_t(MemoryLayout<sockaddr_in>.size)
                    if let tagger {
                        return tagger.withSealed(raw) { Darwin.sendto(s, $0.baseAddress!, $0.count, 0, sa, len) == $0.count }
                    }
                    return Darwin.sendto(s, raw.baseAddress!, raw.count, 0, sa, len) == raw.count
                }
            }
        }
    }

    private func receiveLoop() {
        // 256 bytes of MRM1 plus a tag.
        var buffer = [UInt8](repeating: 0, count: 256 + UDPTag.bytes)
        while true {
            lock.lock()
            let shouldStop = stopping
            let s = fd
            lock.unlock()
            if shouldStop || s < 0 { return }

            var peer = sockaddr_in()
            var peerLen = socklen_t(MemoryLayout<sockaddr_in>.size)
            let capacity = buffer.count
            let got = buffer.withUnsafeMutableBytes { raw -> Int in
                guard let base = raw.baseAddress else { return -1 }
                return withUnsafeMutablePointer(to: &peer) { p in
                    p.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                        Darwin.recvfrom(s, base, capacity, 0, sa, &peerLen)
                    }
                }
            }
            if got < 0 {
                lock.lock(); let nowStopping = stopping; lock.unlock()
                if nowStopping { return }
                continue
            }
            var n = got
            received &+= 1

            let peerIP = String(cString: inet_ntoa(peer.sin_addr))
            var tagged = false
            var generationMoved: UDPPeerSession.ID?
            if let udpSession {
                // PR-C: only the session peer, and nothing with no session.
                guard let snap = udpSession.snapshot else { noSession &+= 1; continue }
                guard snap.address.s_addr == peer.sin_addr.s_addr else { rejected &+= 1; continue }
                if let rx = snap.receive {
                    // Password mode: verify before anything else (no new
                    // session, no presence, no reply for a forged datagram).
                    let ok = buffer.withUnsafeBytes { rx.verify($0.baseAddress!, n) }
                    guard ok else {
                        let reason: String
                        if n <= UDPTag.bytes + UDPTag.versionByte { reason = "short" }
                        else if buffer[UDPTag.versionByte] & UDPTag.flag == 0 { reason = "no_tag" }
                        else { reason = "bad_tag" }
                        badTags.drop(peer: peerIP, reason: reason)
                        continue
                    }
                    n -= UDPTag.bytes
                    buffer[UDPTag.versionByte] &= ~UDPTag.flag
                    tagged = true
                }
                // A new session (new AUTH, new key or another viewer):
                // sequence starts over and the viewer gets a fresh IDR.
                // r3: noted here, applied only once the datagram passed the
                // format and anti-replay checks below.
                if lastGeneration != snap.session.id {
                    generationMoved = snap.session.id
                }
            } else if let allowedClientIP, peerIP != allowedClientIP {
                rejected &+= 1
                continue
            }

            // A freshly launched Windows viewer creates a new UDP socket and
            // starts its packet sequence again at 1. Treat a source-port
            // change as a new mouse session so the new viewer is not mistaken
            // for stale/reordered traffic from the previous process.
            // PR-C tagged: a new viewer process means a new AUTH, so the
            // generation check above starts the session; a port change alone
            // (NAT rebinding) only moves the reply address, and the sequence
            // goes on, so a recorded datagram cannot be replayed from
            // another port.
            let peerPort = UInt16(bigEndian: peer.sin_port)
            let knownPort: UInt16? = generationMoved != nil ? nil : lastPeerPort
            let portMoved = tagged && knownPort != nil && knownPort != peerPort
            let newSession = !portMoved && knownPort != peerPort
            // r3 (Pepper's PR-C r2 review, item 3): format and anti-replay
            // first. A malformed, replayed or too-old datagram changes
            // nothing: not the reply address, not presence, not the session.
            guard n >= 10,
                  buffer[0] == 0x4d, buffer[1] == 0x52, buffer[2] == 0x4d, buffer[3] == 0x31,
                  buffer[4] == 1, Self.wellFormed(buffer, length: n) else {
                badPackets &+= 1
                if n >= 10, buffer[5] == 0x42 { receiverReportRejected &+= 1 }
                continue
            }
            let seq = UInt32(buffer[6]) << 24 |
                      UInt32(buffer[7]) << 16 |
                      UInt32(buffer[8]) << 8 |
                      UInt32(buffer[9])
            // r2 (Pepper's PR-C review, item 7; design §5.1): a 64-packet
            // anti-replay window. A seq seen before, or more than 63 behind
            // the newest, is dropped. One that arrives late but was never
            // seen is taken (a reordered NACK or receiver report still
            // matters), except a pointer move or an audio request: those
            // set state, so only the newest counts, as before. A new session
            // is checked against a fresh window, kept only if it passes.
            var window = newSession ? SeqReplayWindow() : replayWindow
            switch window.check(seq) {
            case .newest:
                break
            case .late:
                window.mark(seq)
                if buffer[5] == 0x24 || buffer[5] == 0x45 {
                    replayWindow = window
                    staleDropped &+= 1
                    continue
                }
                lateAccepted &+= 1
            case .duplicate:
                replayDropped &+= 1
                continue
            case .tooOld:
                staleDropped &+= 1
                continue
            }

            // Accepted: now the state moves.
            replayWindow = window
            if let generationMoved { lastGeneration = generationMoved }
            if portMoved {
                lastPeerPort = peerPort
                lock.lock(); lastPeerAddress = peer; lock.unlock()
                print("MouseMove UDP peer port moved peer=\(peerIP):\(peerPort) (same session)")
                fflush(stdout)
            } else if newSession {
                presenceNewSession = true
                lastPeerPort = peerPort
                lock.lock()
                lastPeerAddress = peer
                lastCursorShape = nil
                let sessionHandler = newSessionHandler
                lock.unlock()
                print("MouseMove UDP new session peer=\(peerIP):\(peerPort)")
                fflush(stdout)
                sessionHandler?()
            }
            presence?.heard(type: buffer[5], newSession: presenceNewSession)
            presenceNewSession = false

            switch buffer[5] {
            case 0x24:
                guard n == 14 else {
                    badPackets &+= 1
                    continue
                }
                guard inputEnabled else {
                    inputDropped &+= 1
                    // Receive loop only: the relay client is not thread-safe.
                    controlRelay.closeConnection()
                    if inputDropped == 1 {
                        print("MouseMove UDP input.dropped reason=password_mode_or_unknown peer=\(peerIP) (logged once)")
                        fflush(stdout)
                    }
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
            case 0x42:
                guard let report = ReceiverReport.parse(Array(buffer[0..<n])) else {
                    badPackets &+= 1
                    receiverReportRejected &+= 1
                    continue
                }
                lock.lock()
                let handler = receiverReportHandler
                lock.unlock()
                receiverReportRx &+= 1
                handler?(report)
            case 0x43:
                guard n == 18 else {
                    badPackets &+= 1
                    continue
                }
                pingRx &+= 1
                // r9: a blocked viewer gets no pong.
                guard outputAllowed() else { pongDrops &+= 1; continue }
                var pong = Array(buffer[0..<18])
                pong[5] = 0x44
                if !reply(pong, to: peer, socket: s) { pongDrops &+= 1 }
            case 0x45:
                guard let req = Self.parseAudioRequest(buffer, length: n) else {
                    badPackets &+= 1
                    continue
                }
                lock.lock()
                let handler = audioRequestHandler
                lock.unlock()
                audioRequestRx &+= 1
                handler?(req.enable, req.port, req.opus, udpSession == nil ? nil : lastGeneration)
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

    /// r3: the per-type length and layout checks, run before a datagram may
    /// move any state (reply address, presence, anti-replay window).
    static func wellFormed(_ b: [UInt8], length n: Int) -> Bool {
        guard n >= 10, n <= b.count else { return false }
        switch b[5] {
        case 0x24: return n == 14
        case 0x40: return n == 10
        case 0x41: return parseNack(b, length: n) != nil
        case 0x42: return ReceiverReport.parse(Array(b[0..<n])) != nil
        case 0x43: return n == 18
        case 0x45: return parseAudioRequest(b, length: n) != nil
        default: return false
        }
    }

    /// Parses an MRM1 0x45 audio request: flags u8, port u16 (13 bytes).
    /// Unknown flag bits are ignored, as an A1 host ignores 0x02.
    static func parseAudioRequest(_ b: [UInt8], length n: Int) -> (enable: Bool, port: UInt16, opus: Bool)? {
        guard n == 13, n <= b.count, b[5] == 0x45 else { return nil }
        let enable = b[10] & 0x01 != 0
        let opus = b[10] & 0x02 != 0
        let port = UInt16(b[11]) << 8 | UInt16(b[12])
        if enable && port == 0 { return nil }
        return (enable, port, opus)
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

/// r2 (Pepper's PR-C review, item 7; design §5.1 "seq 滑動窗口（64）"): the
/// newest seq seen and a bitmap of the 64 before it (bit i = newest - i),
/// RFC 4303 §3.4.3 style. Order survives the UInt32 wrap (isNewer).
struct SeqReplayWindow: Equatable {
    static let size: UInt32 = 64

    enum Verdict: Equatable {
        /// Newer than anything seen: the window moved to it.
        case newest
        /// Inside the window and not seen yet; `mark` records it.
        case late
        /// Inside the window and seen before.
        case duplicate
        /// Behind the window: cannot tell, dropped.
        case tooOld
    }

    private(set) var highest: UInt32?
    private(set) var bits: UInt64 = 0

    mutating func check(_ seq: UInt32) -> Verdict {
        guard let top = highest else {
            highest = seq
            bits = 1
            return .newest
        }
        if MouseMoveUDPServer.isNewer(seq, than: top) {
            let shift = seq &- top
            bits = shift >= Self.size ? 1 : (bits << UInt64(shift)) | 1
            highest = seq
            return .newest
        }
        let back = top &- seq
        guard back < Self.size else { return .tooOld }
        return bits & (UInt64(1) << UInt64(back)) != 0 ? .duplicate : .late
    }

    mutating func mark(_ seq: UInt32) {
        guard let top = highest else { return }
        let back = top &- seq
        if back < Self.size { bits |= UInt64(1) << UInt64(back) }
    }
}
