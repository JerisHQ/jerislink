import Foundation
import Darwin
import Security

/// F5b: the control agent's end of the send socket (see `SendWire`).
///
/// Only this user's "JerisLink Send.app" may talk to it: the peer must have
/// this process's uid (getpeereid) and its code signature, read from the
/// peer's audit token, must be the helper's bundle id signed by this team.
/// Any other peer is closed with no reply. A trusted peer's batch becomes a
/// `PushJob` for `PushBroker`; the reply line tells the helper what to show.
final class SendSocketServer: @unchecked Sendable {  // listenFD and counters behind `lock`
    typealias PeerCheck = @Sendable (Int32) -> Bool

    let path: String
    private let broker: PushBroker
    private let peerCheck: PeerCheck
    private var listenFD: Int32 = -1
    private let lock = NSLock()
    private(set) var refusedPeers: UInt64 = 0
    private(set) var requests: UInt64 = 0

    init(path: String = SendWire.socketPath, broker: PushBroker = .shared,
         peerCheck: @escaping PeerCheck = { SendSocketServer.isTrustedHelper($0) }) {
        self.path = path
        self.broker = broker
        self.peerCheck = peerCheck
    }

    func start() throws {
        let dir = (path as NSString).deletingLastPathComponent
        try Self.prepareDirectory(dir)
        // A socket left by an earlier agent: remove it (never anything else).
        var st = stat()
        if lstat(path, &st) == 0 {
            guard (st.st_mode & S_IFMT) == S_IFSOCK else { throw Self.error("send socket path is not a socket") }
            unlink(path)
        }
        let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw Self.error("send socket failed errno=\(errno)") }
        _ = fcntl(fd, F_SETFD, FD_CLOEXEC)
        guard var addr = SendWire.address(path) else { Darwin.close(fd); throw Self.error("send socket path too long") }
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        // The folder is 0700, so the moment before chmod is not reachable by others.
        guard rc == 0, chmod(path, 0o600) == 0, Darwin.listen(fd, 8) == 0 else {
            let e = errno
            Darwin.close(fd)
            throw Self.error("send socket bind/listen failed errno=\(e)")
        }
        lock.lock(); listenFD = fd; lock.unlock()
        // Strong: the agent keeps the listener for its whole life.
        let t = Thread { self.acceptLoop(fd) }
        t.name = "JerisLink.SendSocket"
        t.start()
        print("file.push_socket=listening")
    }

    func stop() {
        lock.lock(); let fd = listenFD; listenFD = -1; lock.unlock()
        if fd >= 0 {
            Darwin.shutdown(fd, SHUT_RDWR)
            Darwin.close(fd)
            unlink(path)
        }
    }

    /// The folder must be ours and a real folder; it is made 0700.
    static func prepareDirectory(_ dir: String) throws {
        if mkdir(dir, 0o700) != 0 && errno != EEXIST { throw error("send socket folder failed errno=\(errno)") }
        var st = stat()
        guard lstat(dir, &st) == 0, (st.st_mode & S_IFMT) == S_IFDIR, st.st_uid == getuid() else {
            throw error("send socket folder is not this user's folder")
        }
        guard chmod(dir, 0o700) == 0 else { throw error("send socket folder chmod failed errno=\(errno)") }
    }

    private func acceptLoop(_ fd: Int32) {
        while true {
            let c = Darwin.accept(fd, nil, nil)
            if c < 0 {
                if errno == EINTR || errno == ECONNABORTED { continue }
                lock.lock(); let open = listenFD == fd; lock.unlock()
                if !open { return }
                usleep(100_000)
                continue
            }
            _ = fcntl(c, F_SETFD, FD_CLOEXEC)
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                guard let self else { Darwin.close(c); return }
                self.handle(c)
                Darwin.close(c)
            }
        }
    }

    /// One helper request on `sock`. The caller closes `sock`.
    func handle(_ sock: Int32) {
        SendWire.setTimeouts(sock, seconds: 5)
        var uid: uid_t = 0
        var gid: gid_t = 0
        guard getpeereid(sock, &uid, &gid) == 0, uid == getuid(), peerCheck(sock) else {
            lock.lock(); refusedPeers += 1; lock.unlock()
            print("file.push_socket peer=refused")
            return
        }
        lock.lock(); requests += 1; lock.unlock()
        let reply = receive(sock)
        _ = SendWire.send(sock, Array((reply.rawValue + "\n").utf8))
        print("file.push_socket reply=\(reply.rawValue)")
    }

    /// Reads the batch, checks it, hands it to the broker.
    private func receive(_ sock: Int32) -> SendWire.Reply {
        var fds: [Int32] = []        // received, not yet in `files`
        var files: [PushFile] = []
        var handedOff = false
        defer {
            for fd in fds { Darwin.close(fd) }
            if !handedOff { for f in files { Darwin.close(f.fd) } }
        }
        guard let head = SendWire.receive(sock, 8, fds: &fds), Array(head[0..<4]) == SendWire.magic, fds.isEmpty else {
            return .failed
        }
        let declared = SendWire.u32(head, 4)
        guard declared >= 1 else { return .failed }
        guard declared <= SendWire.maxFiles else { return .tooBig }
        var total: UInt64 = 0
        var badName = false
        while true {
            guard let kind = SendWire.receive(sock, 1, fds: &fds) else { return .failed }
            if kind[0] == UInt8(ascii: "E") {
                guard fds.isEmpty, files.count == declared else { return .failed }
                break
            }
            guard kind[0] == UInt8(ascii: "F"), let fh = SendWire.receive(sock, 6, fds: &fds) else { return .failed }
            let n = SendWire.u16(fh, 0)
            let len = SendWire.u32(fh, 2)
            guard n >= 1, n <= SendWire.batch, files.count + n <= declared,
                  len <= n * (2 + SendWire.maxNameBytes),
                  let body = SendWire.receive(sock, len, fds: &fds),
                  let names = SendWire.names(body, count: n), fds.count == n else { return .failed }
            for (name, fd) in zip(names, fds) {
                var st = stat()
                guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else {
                    badName = true
                    Darwin.close(fd)
                    continue
                }
                guard case .ok(let nfc) = FilePathSafety.validate(name), !nfc.contains("/") else {
                    badName = true
                    Darwin.close(fd)
                    continue
                }
                let size = UInt64(st.st_size)
                total += size
                files.append(PushFile(name: Array(nfc.utf8), fd: fd, size: size, mtime: Int64(st.st_mtimespec.tv_sec)))
            }
            fds.removeAll()
            if badName { return .badName }
        }
        guard total <= FileProto.maxTotalBytes else { return .tooBig }
        handedOff = true
        return broker.submit(PushJob(files: files))
    }

    // MARK: Peer check

    static let requirement = "anchor apple generic and identifier \"\(SendWire.helperBundleID)\" "
        + "and certificate leaf[subject.OU] = \"\(SendWire.teamID)\""

    /// LOCAL_PEERTOKEN (sys/un.h), not imported into Swift.
    private static let localPeerToken: Int32 = 6
    private static let solLocal: Int32 = 0

    /// True when the process at the other end of `sock` is the signed
    /// Service helper: its code, found by audit token (not pid, which can be
    /// reused), satisfies `requirement`.
    static func isTrustedHelper(_ sock: Int32) -> Bool {
        var token = audit_token_t()
        var len = socklen_t(MemoryLayout<audit_token_t>.size)
        guard getsockopt(sock, solLocal, localPeerToken, &token, &len) == 0,
              Int(len) == MemoryLayout<audit_token_t>.size else { return false }
        let tokenData = withUnsafeBytes(of: &token) { Data($0) }
        let attrs = [kSecGuestAttributeAudit: tokenData] as CFDictionary
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attrs, SecCSFlags(), &code) == errSecSuccess, let code else { return false }
        var req: SecRequirement?
        guard SecRequirementCreateWithString(requirement as CFString, SecCSFlags(), &req) == errSecSuccess, let req else {
            return false
        }
        return SecCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), req) == errSecSuccess
    }

    private static func error(_ s: String) -> NSError {
        NSError(domain: "JerisLink.SendSocket", code: 1, userInfo: [NSLocalizedDescriptionKey: s])
    }
}
