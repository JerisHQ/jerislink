import Foundation
import Darwin
import Carbon
import AppKit

final class ControlServer: @unchecked Sendable {
    private let bindIP: String
    private let allowedClientIP: String?
    private let port: UInt16
    private let injectRequested: Bool
    private let queue = DispatchQueue(label: "JerisLink.ControlServer")
    private let lock = NSLock()
    private var serverFD: Int32 = -1
    private var clientFDs: Set<Int32> = []
    private var stopping = false
    private var inputHelper: InputHelperClient?
    private let videoSettings = VideoSettingsController()
    private var shiftDown = false
    private var capsAlphaMode = false
    private var capsTemporaryInputSourceID: String?
    private static let usInputSourceID = "com.apple.keylayout.US"

    private(set) var messages: UInt64 = 0
    private(set) var keyEvents: UInt64 = 0
    private(set) var mouseEvents: UInt64 = 0
    /// Input helper send failures: counted, and logged at most once per 10 s.
    private var sendFailures = LogRateLimiter()
    private let sendFailuresLock = NSLock()
    private(set) var clipboardSent: UInt64 = 0
    private(set) var clipboardReceived: UInt64 = 0
    private(set) var rejectedClients: UInt64 = 0
    private(set) var settingsRejected: UInt64 = 0
    private(set) var fileSessions: UInt64 = 0
    private(set) var fileRefused: UInt64 = 0
    private(set) var fileUploads: UInt64 = 0
    private(set) var fileUploadsFailed: UInt64 = 0
    private(set) var fileRxBytes: UInt64 = 0
    private var fileAnnounces: UInt64 = 0
    private var filePulls: UInt64 = 0
    private var fileTxBytes: UInt64 = 0
    private var filePushes: UInt64 = 0
    /// Open file sessions that announce Finder copies (F3). While one is
    /// open the text clipboard session leaves file copies alone, so the
    /// filename text Finder also puts on the pasteboard does not replace the
    /// file object on the Windows clipboard.
    private var announceSessions = 0
    private let fileStatsLock = NSLock()
    /// When a Mac->Windows paste last pulled bytes (systemUptime seconds).
    /// While that is recent, pasteboard changes wait: a Mac copy made
    /// mid-paste must not cancel the announce Explorer is reading, nor
    /// replace the Windows clipboard under it (F3 r3). 0: never.
    private var lastPullServe: TimeInterval = 0
    /// How long a paste counts as running after its last REQUEST. Explorer
    /// asks again within milliseconds while it copies, so this only bridges
    /// the gap between files; the waiting copy syncs once it has passed.
    static let pullHoldSeconds: TimeInterval = 3
    /// Uploads (paste or Send to) running in this server's file sessions.
    private var uploadsActive = 0
    /// Open file sessions whose viewer shows NOTICE (caps notice).
    private var noticeSessions = 0
    /// Bumped for each refused Cmd+V; every notice session sends one NOTICE
    /// per bump on its next poll (it owns its socket, so no cross-thread send).
    private var noticeSeq: UInt64 = 0
    private var finderPastesRefused: UInt64 = 0
    /// Cmd+V to Finder while a transfer runs (FinderPasteGate).
    private var pasteGate = FinderPasteGate()
    /// The frontmost Mac app (a fake in the self-test).
    private let frontmostApp: () -> String?
    /// The viewer allowed to change video settings (JERISLINK_CLIENT_IP),
    /// read for every request so a network.conf change applies at once.
    private let settingsClientIP: () -> String?
    /// Read PROXY headers from loopback peers (legacy `tailscale serve`
    /// forward). Off for `--service control`, whose sockets see real peers.
    private let acceptProxy: Bool
    /// Tell the input helper when a viewer input session starts and ends
    /// (MRI1 SESSION_START / SESSION_END). On for viewer-facing listeners;
    /// off for the loopback relay, whose client is the long-lived video
    /// service.
    private let announceInputSessions: Bool
    /// Answer FILE_HELLO (0x50). Only the viewer-facing direct listener;
    /// the loopback relay and the legacy listeners refuse it (design D13).
    private let allowFileSessions: Bool
    /// Where paste uploads are staged (a temp folder in the self-test).
    private let fileStagingRoot: URL
    /// Where drops land and what REVEAL opens (a temp folder in the self-test).
    private let fileSendFolder: FileSendFolder
    private static let maxClipboardBytes = 60 * 1024
    /// Pasteboard access for clipboard sessions (a fake in the self-test).
    private let clipboard: ClipboardBackend
    /// Current keyboard input source, cached from the system notification so
    /// the per-key Caps check never asks TIS on the main thread.
    private let inputSources: InputSourceCache
    /// Finder "Send to JerisLink" jobs for file sessions (F5b).
    private let pushBroker: PushBroker

    init(bindIP: String, allowedClientIP: String?, port: UInt16, inject: Bool,
         settingsClientIP: @escaping () -> String? = { ListenConfig.configuredClientIP() },
         acceptProxy: Bool = true,
         inputHelper: InputHelperClient? = nil,
         announceInputSessions: Bool = true,
         allowFileSessions: Bool = false,
         fileStagingRoot: URL = FileUploadReceiver.defaultRoot,
         fileSendFolder: FileSendFolder = .shared,
         clipboard: ClipboardBackend = SystemClipboard.shared,
         inputSources: InputSourceCache = .shared,
         pushBroker: PushBroker = .shared,
         frontmostApp: @escaping () -> String? = { FrontmostApp.bundleID() }) {
        self.bindIP = bindIP
        self.clipboard = clipboard
        self.inputSources = inputSources
        self.pushBroker = pushBroker
        self.frontmostApp = frontmostApp
        self.announceInputSessions = announceInputSessions
        self.allowFileSessions = allowFileSessions
        self.fileStagingRoot = fileStagingRoot
        self.fileSendFolder = fileSendFolder
        self.inputHelper = inputHelper
        self.acceptProxy = acceptProxy
        self.allowedClientIP = allowedClientIP
        self.port = port
        self.injectRequested = inject
        self.settingsClientIP = settingsClientIP
    }

    func start() throws {
        let fd = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw NSError(domain: "JerisLink.Control", code: 1, userInfo: [NSLocalizedDescriptionKey: "control socket failed errno=\(errno)"]) }

        var yes: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))

        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        let pton = bindIP.withCString { inet_pton(AF_INET, $0, &addr.sin_addr) }
        guard pton == 1 else {
            Darwin.close(fd)
            throw NSError(domain: "JerisLink.Control", code: 2, userInfo: [NSLocalizedDescriptionKey: "invalid control bind IP \(bindIP)"])
        }

        let rc = withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard rc == 0 else {
            let e = errno
            Darwin.close(fd)
            throw NSError(domain: "JerisLink.Control", code: 3, userInfo: [NSLocalizedDescriptionKey: "control bind failed errno=\(e)"])
        }
        guard Darwin.listen(fd, 4) == 0 else {
            let e = errno
            Darwin.close(fd)
            throw NSError(domain: "JerisLink.Control", code: 4, userInfo: [NSLocalizedDescriptionKey: "control listen failed errno=\(e)"])
        }

        lock.lock()
        serverFD = fd
        stopping = false
        lock.unlock()

        inputSources.start()

        var helperOK = false
        if injectRequested {
            // Keep the client object even when the Helper is not reachable yet.
            // InputHelperClient reconnects lazily on send, which removes the
            // boot-order dependency where the Host had to start after the app.
            // A caller running several servers passes one shared client: the
            // helper serves a single connection at a time.
            let helper = inputHelper ?? InputHelperClient()
            inputHelper = helper
            helperOK = helper.ping()
        }
        let info = Bundle.main.infoDictionary
        let version = info?["CFBundleShortVersionString"] as? String ?? "dev"
        let build = info?["JLBuildSHA"] as? String ?? "dev"
        print("Control MRC1: version=\(version) build=\(build) \(bindIP):\(port), allowedClient=\(allowedClientIP ?? "any"), inject=\(injectRequested ? "requested" : "off"), inputHelper=\(helperOK ? "ready" : "unavailable")")
        if injectRequested && !helperOK {
            print("Control warning: JerisLink Input Helper is not reachable yet; input will reconnect lazily when the next event arrives.")
        }

        queue.async { [weak self] in self?.acceptLoop() }
    }

    func stop() {
        lock.lock()
        stopping = true
        let s = serverFD
        let clients = Array(clientFDs)
        serverFD = -1
        lock.unlock()

        // Client handlers own close(); shutdown is enough to wake any blocked
        // recv/poll without risking a descriptor being closed twice.
        for c in clients { Darwin.shutdown(c, SHUT_RDWR) }
        if s >= 0 { Darwin.shutdown(s, SHUT_RDWR); Darwin.close(s) }
    }

    private var helperSendFailures: UInt64 {
        sendFailuresLock.lock(); defer { sendFailuresLock.unlock() }
        return sendFailures.total
    }

    /// One send failure per input event is possible while the helper is
    /// down, so log the first and then at most one per 10 s.
    private func warnSendFailed(_ what: String) {
        sendFailuresLock.lock()
        let folded = sendFailures.record(nowNs: DispatchTime.now().uptimeNanoseconds)
        sendFailuresLock.unlock()
        guard let folded else { return }
        print("Control warning: input helper \(what) send failed" + (folded > 0 ? " (\(folded) more since the last warning)" : ""))
    }

    func statsLine() -> String {
        "control_messages=\(messages) control_key_events=\(keyEvents) control_mouse_events=\(mouseEvents) clipboard_tx=\(clipboardSent) clipboard_rx=\(clipboardReceived) control_rejected_clients=\(rejectedClients) settings_rejected=\(settingsRejected) file_sessions=\(fileSessions) file_refused=\(fileRefused) \(fileStatsText()) helper_send_failures=\(helperSendFailures) main_hops=\(MainThreadHops.total)"
    }

    private func acceptLoop() {
        while true {
            lock.lock()
            let shouldStop = stopping
            let s = serverFD
            lock.unlock()
            if shouldStop || s < 0 { break }

            var peer = sockaddr_in()
            var peerLen = socklen_t(MemoryLayout<sockaddr_in>.size)
            let c = withUnsafeMutablePointer(to: &peer) { p -> Int32 in
                p.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.accept(s, $0, &peerLen)
                }
            }
            if c < 0 {
                lock.lock(); let nowStopping = stopping; lock.unlock()
                if nowStopping { break }
                continue
            }

            var noSigPipe: Int32 = 1
            setsockopt(c, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))

            let peerIP = String(cString: inet_ntoa(peer.sin_addr))
            if let allowedClientIP, peerIP != allowedClientIP {
                rejectedClients += 1
                print("Control reject peer=\(peerIP) expected=\(allowedClientIP) on \(bindIP):\(port); connection closed")
                Darwin.close(c)
                continue
            }

            lock.lock(); clientFDs.insert(c); lock.unlock()
            let peerPort = UInt16(bigEndian: peer.sin_port)
            print("Control client connected: \(peerIP):\(peerPort)")
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                guard let self else {
                    Darwin.close(c)
                    return
                }
                self.handleClient(c, tcpPeerIP: peerIP)
                self.lock.lock()
                self.clientFDs.remove(c)
                self.lock.unlock()
                Darwin.close(c)
                print("Control client disconnected: \(peerIP):\(peerPort)")
            }
        }
    }

    private func handleClient(_ fd: Int32, tcpPeerIP: String) {
        guard var pending = recvExact(fd, count: 8) else { return }
        var peer = ControlPeer(ip: tcpPeerIP, verified: !ControlPeer.isLoopback(tcpPeerIP))
        // Only a local forwarder (tailscale serve --proxy-protocol) may name
        // another address; a remote client cannot claim one.
        if acceptProxy && ControlPeer.isLoopback(tcpPeerIP) {
            switch ProxyProtocol.parse(first: pending, read: { self.recvExact(fd, count: $0) }) {
            case .notProxy:
                break
            case .proxy(let source):
                if let source { peer = ControlPeer(ip: source, verified: true) }
                print("Control PROXY peer=\(source ?? "local") via=\(tcpPeerIP)")
                guard let next = recvExact(fd, count: 8) else { return }
                pending = next
            case .invalid(let reason):
                print("Control bad PROXY header (\(reason)) via=\(tcpPeerIP)")
                return
            }
        }
        // A connection is an input session only once it sends its first key
        // or mouse message; clipboard, PING and VIDEO_CONFIG sessions never
        // are. One bool test per message, one helper message per session edge.
        // A START that did not reach the helper (helper down) is retried on
        // the next input message, and the input message that failed it is
        // dropped: input reaches the helper only inside a session it knows.
        // END is sent only for a started session. The relay listener has no
        // lifecycle and forwards as before.
        let sessionID = Self.sessionIDs.next()
        var sessionStarted = false
        defer { if sessionStarted { endInputSession(sessionID) } }
        var firstHeader: [UInt8]? = pending
        var connectionMessages = 0
        while true {
            let next: [UInt8]?
            if let firstHeader { next = firstHeader } else { next = recvExact(fd, count: 8) }
            firstHeader = nil
            guard let header = next else { return }
            guard header[0] == 0x4d, header[1] == 0x52, header[2] == 0x43, header[3] == 0x31, header[4] == 1 else {
                print("Control bad header")
                return
            }
            let type = header[5]
            let length = Int(UInt16(header[6]) << 8 | UInt16(header[7]))
            guard length <= Self.maxClipboardBytes, let payload = recvExact(fd, count: length) else { return }
            messages += 1
            connectionMessages += 1
            if !sessionStarted && announceInputSessions && Self.isInputMessage(type) {
                pasteGate = FinderPasteGate()  // no Cmd held over from an earlier viewer
                sessionStarted = startInputSession(sessionID)
                if !sessionStarted { continue }
            }

            switch type {
            case FileProto.MsgType.hello: // FILE_HELLO: dedicate this TCP session to file transfer.
                // Only as the first message, and only on the direct listener.
                guard allowFileSessions, connectionMessages == 1,
                      case .hello(let proto, let peerCaps)? = FileProto.decode(type: type, payload: payload), proto >= 1 else {
                    fileRefused += 1
                    print("file.session=refused")
                    return
                }
                handleFileSession(fd, peerCaps: peerCaps)
                return
            case 0x30: // CLIPBOARD_HELLO: dedicate this TCP session to clipboard sync.
                guard payload.isEmpty else { return }
                print("Clipboard session connected")
                handleClipboardSession(fd)
                print("Clipboard session ended")
                return
            case 0x01: // PING
                if payload.count == 4 {
                    _ = sendPacket(fd, type: 0x02, payload: payload)
                }
            case 0x40: // VIDEO_CONFIG_SET v1
                let clientIP = settingsClientIP()
                let ack: VideoSettingsAck
                switch SettingsAuthority.check(peer: peer, clientIP: clientIP) {
                case .allow:
                    ack = videoSettings.apply(request: payload)
                case .reject(let reason):
                    settingsRejected += 1
                    print("Video config reject peer=\(peer.ip) verified=\(peer.verified) expected=\(clientIP ?? "unset") reason=\(reason); settings unchanged")
                    ack = videoSettings.currentAck(ignored: true)
                }
                _ = sendPacket(fd, type: 0x41, payload: ack.payload)
                print("Video config ACK status=\(ack.status) codec=\(ack.codec) bitrate_mbps=\(ack.bitrateMbps) flags=0x\(String(ack.flags, radix: 16)) remote_size=\(ack.framebufferWidth)x\(ack.framebufferHeight)")
            case 0x10: // KEY
                if payload.count == 3 {
                    let down = payload[0] != 0
                    let semantic = UInt16(payload[1]) << 8 | UInt16(payload[2])
                    handleKey(semantic: semantic, down: down)
                }
            case 0x20: // MOUSE_MOVE_REL
                if payload.count == 4 {
                    let dx = Int16(bitPattern: UInt16(payload[0]) << 8 | UInt16(payload[1]))
                    let dy = Int16(bitPattern: UInt16(payload[2]) << 8 | UInt16(payload[3]))
                    handleMouseMove(dx: dx, dy: dy)
                }
            case 0x21: // MOUSE_BUTTON
                if payload.count == 2 {
                    handleMouseButton(button: payload[0], down: payload[1] != 0)
                }
            case 0x25: // MOUSE_BUTTON_EXT (button, down, clickCount)
                if payload.count == 3 {
                    handleMouseButtonExtended(button: payload[0], down: payload[1] != 0, clickCount: payload[2])
                }
            case 0x22: // MOUSE_SCROLL
                if payload.count == 4 {
                    let dx = Int16(bitPattern: UInt16(payload[0]) << 8 | UInt16(payload[1]))
                    let dy = Int16(bitPattern: UInt16(payload[2]) << 8 | UInt16(payload[3]))
                    handleScroll(dx: dx, dy: dy)
                }
            case 0x23: // MOUSE_MOVE_ABS (legacy pixel coordinates)
                if payload.count == 4 {
                    let x = UInt16(payload[0]) << 8 | UInt16(payload[1])
                    let y = UInt16(payload[2]) << 8 | UInt16(payload[3])
                    handleMouseMoveAbsolute(x: x, y: y)
                }
            case 0x24: // MOUSE_MOVE_ABS_NORM (0...65535)
                if payload.count == 4 {
                    let nx = UInt16(payload[0]) << 8 | UInt16(payload[1])
                    let ny = UInt16(payload[2]) << 8 | UInt16(payload[3])
                    handleMouseMoveNormalized(nx: nx, ny: ny)
                }
            default:
                print("Control unknown type=\(type) len=\(length)")
            }
        }
    }

    private static func isInputMessage(_ type: UInt8) -> Bool {
        switch type {
        case 0x10, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25: return true
        default: return false
        }
    }

    /// Returns true when SESSION_START reached the helper, so SESSION_END is
    /// sent only for a session the helper knows about.
    private func startInputSession(_ id: UInt32) -> Bool {
        guard announceInputSessions, injectRequested, let helper = inputHelper else { return false }
        return helper.sendSessionStart(id: id)
    }

    private func endInputSession(_ id: UInt32) {
        guard let helper = inputHelper else { return }
        _ = helper.sendSessionEnd(id: id)
    }

    /// Input session ids, unique per process (shared by every listener, as
    /// is the one helper connection). 0 is never used.
    private final class SessionIDCounter: @unchecked Sendable {
        private let lock = NSLock()
        private var last: UInt32 = 0
        func next() -> UInt32 {
            lock.lock(); defer { lock.unlock() }
            last &+= 1
            if last == 0 { last = 1 }
            return last
        }
    }
    private static let sessionIDs = SessionIDCounter()

    private func announceSessionsOpen() -> Bool {
        fileStatsLock.lock(); defer { fileStatsLock.unlock() }
        return announceSessions > 0
    }

    private func notePullServe() {
        fileStatsLock.lock(); lastPullServe = ProcessInfo.processInfo.systemUptime; fileStatsLock.unlock()
    }

    /// A paste is pulling now: leave the pasteboard change for later.
    private func pullHeld() -> Bool {
        fileStatsLock.lock(); defer { fileStatsLock.unlock() }
        return lastPullServe > 0 && ProcessInfo.processInfo.systemUptime - lastPullServe < Self.pullHoldSeconds
    }

    /// Keep `uploadsActive` in step with one session's receiver.
    private func noteUpload(_ was: inout Bool, active: Bool) {
        guard was != active else { return }
        was = active
        fileStatsLock.lock(); uploadsActive += active ? 1 : -1; fileStatsLock.unlock()
    }

    /// A Cmd+V for Finder now would land mid-transfer: an upload is running
    /// or a paste is pulling, a viewer can show the notice (so nothing is
    /// eaten silently), and Finder is frontmost (checked last: a main-thread
    /// hop).
    private func finderPasteBlocked() -> Bool {
        fileStatsLock.lock()
        let running = uploadsActive > 0 || (lastPullServe > 0 &&
            ProcessInfo.processInfo.systemUptime - lastPullServe < Self.pullHoldSeconds)
        let canNotify = noticeSessions > 0
        fileStatsLock.unlock()
        guard running, canNotify else { return false }
        return frontmostApp() == FinderPasteGate.finderBundleID
    }

    private func requestPasteBusyNotice() {
        fileStatsLock.lock(); noticeSeq &+= 1; finderPastesRefused += 1; fileStatsLock.unlock()
    }

    private func currentNoticeSeq() -> UInt64 {
        fileStatsLock.lock(); defer { fileStatsLock.unlock() }
        return noticeSeq
    }

    private func fileStatsText() -> String {
        fileStatsLock.lock(); defer { fileStatsLock.unlock() }
        return "file_uploads=\(fileUploads) file_upload_failed=\(fileUploadsFailed) file_rx_bytes=\(fileRxBytes) file_announces=\(fileAnnounces) file_pulls=\(filePulls) file_tx_bytes=\(fileTxBytes) file_pushes=\(filePushes) finder_paste_refused=\(finderPastesRefused)"
    }

    /// A file session: HELLO_ACK with this build's caps, PING echo, paste
    /// and send uploads through `FileUploadReceiver` (F2, F4), REVEAL (F4,
    /// no reply), and REJECT `denied` for every other request until F5
    /// implements them. A viewer whose HELLO
    /// carries caps `announce` gets Finder copies announced on this session
    /// and pulls their bytes with REQUEST (F3, `FileAnnouncer`); the
    /// pasteboard is checked on each 100 ms poll by its change count only. Any malformed or
    /// unexpected message closes the session, and a session that ends with
    /// an upload running removes its partial files. Runs on this client's own
    /// thread; only the final pasteboard write hops to the main thread. Logs
    /// carry no file names (D15): only open/closed and counts.
    private func handleFileSession(_ fd: Int32, peerCaps: UInt16) {
        fileSessions += 1
        let receiver = FileUploadReceiver(root: fileStagingRoot, clipboard: clipboard, sendFolder: fileSendFolder)
        let announcer: FileAnnouncer? = (peerCaps & FileProto.Caps.announce) != 0 ? FileAnnouncer() : nil
        // A copy made before the session opened is not announced: the viewer
        // connecting must not replace what the Windows clipboard holds.
        var lastChangeCount = clipboard.changeCount()
        if announcer != nil {
            fileStatsLock.lock(); announceSessions += 1; fileStatsLock.unlock()
        }
        let ack = FileProto.Message.helloAck(proto: FileProto.version, caps: FileProto.Caps.host,
                                             maxChunk: FileProto.maxChunk, maxTotal: FileProto.maxTotalBytes)
        guard let ackBytes = ack.encode(), sendPacket(fd, type: ack.type, payload: ackBytes) else { return }
        print("file.session=open caps=0x\(String(FileProto.Caps.host, radix: 16)) peer_caps=0x\(String(peerCaps, radix: 16))")
        func sendAll(_ msgs: [FileProto.Message]) -> Bool {
            for out in msgs {
                guard let bytes = out.encode(), sendPacket(fd, type: out.type, payload: bytes) else { return false }
            }
            return true
        }
        // r3: this viewer shows NOTICE; refused Finder pastes are told here.
        let showsNotice = (peerCaps & FileProto.Caps.notice) != 0
        var lastNotice: UInt64 = 0
        if showsNotice {
            fileStatsLock.lock(); noticeSessions += 1; lastNotice = noticeSeq; fileStatsLock.unlock()
        }
        var uploading = false
        var received = 0
        var refused = 0
        var reason = "peer_closed"
        // F5b: Finder pushes go to the newest session; one at a time.
        let pushSession = pushBroker.register(peerCaps: peerCaps)
        var push: PushSender?
        func endPush() {
            guard let p = push else { return }
            p.close()
            fileStatsLock.lock(); filePushes += 1; fileTxBytes += p.bytesOut; fileStatsLock.unlock()
            pushBroker.finished(p.job)
            push = nil
        }
        defer {
            endPush()
            pushBroker.unregister(pushSession)
            receiver.abort(reason: reason)
            noteUpload(&uploading, active: false)
            if showsNotice { fileStatsLock.lock(); noticeSessions -= 1; fileStatsLock.unlock() }
            announcer?.close()
            fileStatsLock.lock()
            fileUploads += receiver.completed
            fileUploadsFailed += receiver.failed
            fileRxBytes += receiver.bytesIn
            if let announcer {
                announceSessions -= 1
                fileAnnounces += announcer.announces
                filePulls += announcer.filesServed
                fileTxBytes += announcer.bytesOut
            }
            fileStatsLock.unlock()
            print("file.session=closed reason=\(reason) messages=\(received) refused=\(refused)")
        }
        var lastMessage = Date()

        while true {
            lock.lock(); let shouldStop = stopping; lock.unlock()
            if shouldStop { reason = "stopping"; return }
            if Date().timeIntervalSince(lastMessage) > FileProto.idleTimeoutSeconds { reason = "idle"; return }
            if showsNotice {
                let seq = currentNoticeSeq()
                if seq != lastNotice {
                    lastNotice = seq
                    guard sendAll([.notice(code: FileProto.Notice.pasteBusy)]) else { reason = "send_failed"; return }
                }
            }
            if let p = push, p.ended { endPush() }
            if let p = push, !p.accepted, p.job.isAbandoned {
                guard sendAll(p.abandon()) else { reason = "send_failed"; return }
                endPush()
            }
            if push == nil, let job = pushBroker.take(session: pushSession) {
                let p = PushSender(job: job)
                push = p
                guard sendAll(p.start()) else { reason = "send_failed"; return }
            }
            if let announcer {
                let changeCount = clipboard.changeCount()
                // Mid-paste the change waits (lastChangeCount stays), so the
                // announce Explorer is reading stays served.
                if changeCount != lastChangeCount, !pullHeld() {
                    lastChangeCount = changeCount
                    // This host's own F2 paste holds staging files Windows
                    // already has: never announce them back.
                    let urls = clipboard.ownFileWriteChangeCount() == changeCount ? nil : clipboard.readFileURLs()
                    guard sendAll(announcer.announce(urls: urls)) else { reason = "send_failed"; return }
                }
            }

            var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let ready = Darwin.poll(&pfd, 1, 100)
            if ready < 0 {
                if errno == EINTR { continue }
                reason = "poll_error"; return
            }
            if ready == 0 { continue }
            if (pfd.revents & Int16(POLLERR | POLLNVAL)) != 0 { reason = "socket_error"; return }

            guard let header = recvExact(fd, count: 8) else { return }
            guard header[0] == 0x4d, header[1] == 0x52, header[2] == 0x43, header[3] == 0x31, header[4] == 1 else {
                reason = "bad_header"; return
            }
            let type = header[5]
            let length = Int(UInt16(header[6]) << 8 | UInt16(header[7]))
            guard length <= FileProto.maxPayload else { reason = "too_long"; return }
            guard let payload = recvExact(fd, count: length) else { return }
            received += 1
            lastMessage = Date()
            pushBroker.heard(pushSession)

            guard let msg = FileProto.decode(type: type, payload: payload) else { reason = "malformed"; return }
            switch msg {
            case .ping:
                guard sendPacket(fd, type: type, payload: payload) else { reason = "send_failed"; return }
            case .request(let t, let index, let offset, let length) where push != nil && t == push?.transfer:
                guard let p = push, p.serve(index: index, offset: offset, length: length,
                                            send: { m in m.encode().map { sendPacket(fd, type: m.type, payload: $0) } ?? false }) else {
                    reason = "send_failed"; return
                }
                lastMessage = Date()
            case .reply(let t, let status) where push != nil && t == push?.transfer:
                push?.reply(status)
            case .result(let t, let status, let filesOK) where push != nil && t == push?.transfer:
                push?.result(status: status, filesOK: filesOK)
            case .cancel(let t, _) where push != nil && t == push?.transfer:
                push?.cancelled()
            case .request(let t, let index, let offset, let length):
                guard let announcer else {
                    refused += 1
                    guard sendAll([.reply(transfer: t, status: FileProto.Status.denied)]) else { reason = "send_failed"; return }
                    continue
                }
                if t == announcer.current { notePullServe() }
                guard announcer.serve(transfer: t, index: index, offset: offset, length: length,
                                      send: { m in m.encode().map { sendPacket(fd, type: m.type, payload: $0) } ?? false }) else {
                    reason = "send_failed"; return
                }
                // Serving can take a while on a slow link; it is activity.
                lastMessage = Date()
            case .cancel(let t, _) where announcer != nil && t == announcer?.current,
                 .reply(let t, _) where announcer != nil && t == announcer?.current:
                // The viewer dropped the announce (cleared, or names Windows
                // cannot take).
                announcer?.cancel(t)
            case .offer(_, FileProto.Purpose.paste, _, _), .offer(_, FileProto.Purpose.send, _, _),
                 .entry, .data, .fileEnd, .cancel:
                let step = receiver.handle(msg)
                noteUpload(&uploading, active: receiver.isActive)
                for out in step.send {
                    guard let bytes = out.encode(), sendPacket(fd, type: out.type, payload: bytes) else {
                        reason = "send_failed"; return
                    }
                }
                if let why = step.close { reason = why; return }
            case .reveal(let transfer):
                // F4: Finder opens the folder that send went to. No reply.
                receiver.reveal(transfer)
            case .offer(let transfer, _, _, _):
                refused += 1
                let reply = FileProto.Message.reply(transfer: transfer, status: FileProto.Status.denied)
                guard let bytes = reply.encode(), sendPacket(fd, type: reply.type, payload: bytes) else {
                    reason = "send_failed"; return
                }
            case .hello, .helloAck, .notice:
                reason = "unexpected"; return
            case .reply, .result, .progress:
                // Host-to-viewer messages: nothing to answer.
                break
            }
        }
    }

    private func handleClipboardSession(_ fd: Int32) {
        // Each 100 ms poll reads only the change count, on this thread. The
        // contents are read (on the main thread) only when the count moved.
        var lastChangeCount = clipboard.changeCount()
        var lastSentText = clipboard.readText()
        var lastRemoteApplied: String?

        while true {
            lock.lock(); let shouldStop = stopping; lock.unlock()
            if shouldStop { return }

            var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let ready = Darwin.poll(&pfd, 1, 100)
            if ready < 0 {
                if errno == EINTR { continue }
                return
            }
            if ready > 0 {
                if (pfd.revents & Int16(POLLERR | POLLHUP | POLLNVAL)) != 0 { return }
                if (pfd.revents & Int16(POLLIN)) != 0 {
                    guard let header = recvExact(fd, count: 8) else { return }
                    guard header[0] == 0x4d, header[1] == 0x52, header[2] == 0x43,
                          header[3] == 0x31, header[4] == 1 else { return }
                    let type = header[5]
                    let length = Int(UInt16(header[6]) << 8 | UInt16(header[7]))
                    guard length <= Self.maxClipboardBytes,
                          let payload = recvExact(fd, count: length) else { return }

                    if type == 0x31 {
                        guard let text = String(data: Data(payload), encoding: .utf8) else {
                            print("Clipboard rejected invalid UTF-8")
                            continue
                        }
                        if clipboard.readText() != text {
                            guard let updated = clipboard.writeText(text) else {
                                print("Clipboard remote apply failed")
                                continue
                            }
                            lastChangeCount = updated
                        } else {
                            lastChangeCount = clipboard.changeCount()
                        }
                        lastRemoteApplied = text
                        lastSentText = text
                        clipboardReceived += 1
                        print("Clipboard RX bytes=\(payload.count)")
                    } else if type == 0x01, payload.count == 4 {
                        _ = sendPacket(fd, type: 0x02, payload: payload)
                    }
                }
            }

            let changeCount = clipboard.changeCount()
            if changeCount == lastChangeCount { continue }
            // Mid-paste, Windows keeps the file object Explorer is reading;
            // this copy syncs once the paste is quiet.
            if pullHeld() { continue }
            lastChangeCount = changeCount
            // Our own file-URL write (Windows->Mac paste): Windows already
            // holds those files; never send the staging path back as text.
            if clipboard.ownFileWriteChangeCount() == changeCount { continue }
            // A Finder copy goes to Windows as files on the file session
            // (F3); its filename text must not overwrite them there.
            if announceSessionsOpen(), clipboard.readFileURLs() != nil { continue }
            let text = clipboard.readText()
            let settled = clipboard.changeCount()
            if clipboard.ownFileWriteChangeCount() == settled { lastChangeCount = settled; continue }
            guard let text else { continue }
            let payload = Array(text.utf8)
            if payload.count > Self.maxClipboardBytes {
                print("Clipboard skip oversize bytes=\(payload.count)")
                continue
            }
            if text == lastRemoteApplied {
                lastRemoteApplied = nil
                lastSentText = text
                continue
            }
            if text == lastSentText { continue }
            guard sendPacket(fd, type: 0x31, payload: payload) else { return }
            lastSentText = text
            clipboardSent += 1
            print("Clipboard TX bytes=\(payload.count)")
        }
    }

    private func handleCapsLock(down: Bool) {
        // Caps Lock is a latch/status key, so one key-down toggles the remote
        // state and the matching key-up carries no additional action.
        guard down else { return }
        // One fresh TIS read per Caps press (not per key); it also refreshes
        // the cache in case the change notification has not arrived yet.
        let backend = inputSources.backend
        let current = backend.currentID()
        inputSources.store(current)

        if let saved = capsTemporaryInputSourceID {
            if current == Self.usInputSourceID && backend.select(id: saved) {
                inputSources.store(saved)
                capsTemporaryInputSourceID = nil
                capsAlphaMode = false
                return
            }
            // The user changed input source through another shortcut while in
            // temporary ABC mode; discard the stale restore target.
            capsTemporaryInputSourceID = nil
        }

        if let current, current != Self.usInputSourceID {
            if backend.select(id: Self.usInputSourceID) {
                inputSources.store(Self.usInputSourceID)
                capsTemporaryInputSourceID = current
                capsAlphaMode = false
                return
            }
        }

        capsAlphaMode.toggle()
    }

    private func handleKey(semantic: UInt16, down: Bool) {
        // Keys are never logged (privacy): only keyEvents counts them.
        keyEvents += 1

        switch pasteGate.key(semantic: semantic, down: down, refuse: { finderPasteBlocked() }) {
        case .pass:
            break
        case .refused:
            // Finder would save the text clipboard as a .textClipping file.
            print("file.paste=refused reason=busy_finder")
            requestPasteBusyNotice()
            return
        case .swallow:
            return
        }

        if semantic == 20 { // Windows VK_CAPITAL / Caps Lock.
            handleCapsLock(down: down)
            return
        }

        // If an external shortcut changed away from U.S. while alpha Caps mode
        // was active, do not leak synthetic Shift into an input method. The
        // cache follows the system's input-source notification; no TIS call
        // and no main-thread hop per key.
        if capsAlphaMode, inputSources.current != Self.usInputSourceID {
            capsAlphaMode = false
        }

        let cg = Self.macKeyCode(semantic)

        if semantic == 4 { shiftDown = down }
        guard injectRequested, let cg, let helper = inputHelper else { return }

        if capsAlphaMode && (65...90).contains(semantic) {
            // Real Caps Lock is Shift XOR Caps for letters. Temporarily invert
            // the Shift state for this key event, then restore the physical
            // remote Shift state immediately afterwards.
            let preOK = helper.sendKey(cgCode: 56, down: !shiftDown)
            let keyOK = helper.sendKey(cgCode: UInt16(cg), down: down)
            let postOK = helper.sendKey(cgCode: 56, down: shiftDown)
            if !(preOK && keyOK && postOK) {
                warnSendFailed("caps-aware key")
            }
            return
        }

        if !helper.sendKey(cgCode: UInt16(cg), down: down) {
            warnSendFailed("key")
        }
    }



    private func handleMouseMove(dx: Int16, dy: Int16) {
        mouseEvents += 1
        guard injectRequested, let helper = inputHelper else { return }
        if !helper.sendMouseMove(dx: dx, dy: dy) {
            warnSendFailed("mouse-move")
        }
    }

    private func handleMouseMoveAbsolute(x: UInt16, y: UInt16) {
        mouseEvents += 1
        guard injectRequested, let helper = inputHelper else { return }
        if !helper.sendMouseMoveAbsolute(x: x, y: y) {
            warnSendFailed("absolute mouse-move")
        }
    }

    private func handleMouseMoveNormalized(nx: UInt16, ny: UInt16) {
        mouseEvents += 1
        guard injectRequested, let helper = inputHelper else { return }
        if !helper.sendMouseMoveNormalized(nx: nx, ny: ny) {
            warnSendFailed("normalized mouse-move")
        }
    }

    private func handleMouseButton(button: UInt8, down: Bool) {
        mouseEvents += 1
        guard injectRequested, let helper = inputHelper else { return }
        if !helper.sendMouseButton(button: button, down: down) {
            warnSendFailed("mouse-button")
        }
    }

    private func handleMouseButtonExtended(button: UInt8, down: Bool, clickCount: UInt8) {
        mouseEvents += 1
        guard injectRequested, let helper = inputHelper else { return }
        if !helper.sendMouseButtonExtended(button: button, down: down, clickCount: clickCount) {
            warnSendFailed("extended mouse-button")
        }
    }

    private func handleScroll(dx: Int16, dy: Int16) {
        mouseEvents += 1
        guard injectRequested, let helper = inputHelper else { return }
        if !helper.sendScroll(dx: dx, dy: dy) {
            warnSendFailed("scroll")
        }
    }

    private func recvExact(_ fd: Int32, count: Int) -> [UInt8]? {
        if count == 0 { return [] }
        var out = [UInt8](repeating: 0, count: count)
        var offset = 0
        while offset < count {
            let n = out.withUnsafeMutableBytes { raw -> Int in
                Darwin.recv(fd, raw.baseAddress!.advanced(by: offset), count - offset, 0)
            }
            if n <= 0 { return nil }
            offset += n
        }
        return out
    }

    private func sendPacket(_ fd: Int32, type: UInt8, payload: [UInt8]) -> Bool {
        let length = UInt16(payload.count)
        let bytes: [UInt8] = [0x4d, 0x52, 0x43, 0x31, 1, type, UInt8(length >> 8), UInt8(length & 0xff)] + payload
        var offset = 0
        while offset < bytes.count {
            let n = bytes.withUnsafeBytes { raw -> Int in
                Darwin.send(fd, raw.baseAddress!.advanced(by: offset), bytes.count - offset, 0)
            }
            if n <= 0 { return false }
            offset += n
        }
        return true
    }

    private static func macKeyCode(_ code: UInt16) -> UInt16? {
        switch code {
        // Modifiers / status keys.
        case 1: return 59; case 2: return 58; case 3: return 55; case 4: return 56
        case 20: return 57      // Caps Lock (handled contextually above)

        // Letters A-Z.
        case 65: return 0;  case 66: return 11; case 67: return 8;  case 68: return 2
        case 69: return 14; case 70: return 3;  case 71: return 5;  case 72: return 4
        case 73: return 34; case 74: return 38; case 75: return 40; case 76: return 37
        case 77: return 46; case 78: return 45; case 79: return 31; case 80: return 35
        case 81: return 12; case 82: return 15; case 83: return 1;  case 84: return 17
        case 85: return 32; case 86: return 9;  case 87: return 13; case 88: return 7
        case 89: return 16; case 90: return 6

        // Number row 0-9.
        case 48: return 29; case 49: return 18; case 50: return 19; case 51: return 20
        case 52: return 21; case 53: return 23; case 54: return 22; case 55: return 26
        case 56: return 28; case 57: return 25

        // Editing/navigation.
        case 8: return 51       // Backspace -> Mac Delete
        case 9: return 48       // Tab
        case 13: return 36      // Return
        case 27: return 53      // Escape
        case 32: return 49      // Space
        case 33: return 116     // Page Up
        case 34: return 121     // Page Down
        case 35: return 119     // End
        case 36: return 115     // Home
        case 37: return 123     // Left
        case 38: return 126     // Up
        case 39: return 124     // Right
        case 40: return 125     // Down
        case 45: return 114     // Insert -> Help/Insert-style key
        case 46: return 117     // Forward Delete

        // US/HK punctuation physical keys (Windows VK_OEM_* semantics).
        case 186: return 41     // ; :
        case 187: return 24     // = +
        case 188: return 43     // , <
        case 189: return 27     // - _
        case 190: return 47     // . >
        case 191: return 44     // / ?
        case 192: return 50     // ` ~
        case 219: return 33     // [ {
        case 220: return 42     // \\ |
        case 221: return 30     // ] }
        case 222: return 39     // ' "

        // Numpad 0-9 and operators.
        case 96: return 82; case 97: return 83; case 98: return 84; case 99: return 85
        case 100: return 86; case 101: return 87; case 102: return 88; case 103: return 89
        case 104: return 91; case 105: return 92
        case 106: return 67     // *
        case 107: return 69     // +
        case 109: return 78     // -
        case 110: return 65     // .
        case 111: return 75     // /

        // Function keys F1-F12.
        case 112: return 122; case 113: return 120; case 114: return 99;  case 115: return 118
        case 116: return 96;  case 117: return 97;  case 118: return 98;  case 119: return 100
        case 120: return 101; case 121: return 109; case 122: return 103; case 123: return 111

        default: return nil
        }
    }
}
