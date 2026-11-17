import Foundation
import Darwin

/// F5b: the local socket between "JerisLink Send.app" (the Finder Service)
/// and the control agent. Shared by both: the helper is built from this file
/// plus SendHelper/JerisLinkSend.swift, the host compiles it in its target.
///
/// The helper opens each file the user picked and passes the open
/// descriptors with SCM_RIGHTS, so the agent never needs Desktop/Documents
/// access for them. Unix stream socket at
/// ~/Library/Caches/org.jeris.jerislink/send.sock (folder 0700, socket 0600).
///
/// Helper -> agent, all integers big-endian:
///   "JLS1" files:u32                         once, no descriptors
///   'F' n:u16 len:u32 n*(nameLen:u16 name)    a batch of n descriptors (SCM_RIGHTS on this frame)
///   'E'                                       end
/// Agent -> helper: one reply line ("ok\n", "not_connected\n", ...), then close.
/// A peer the agent does not trust gets no reply at all.
enum SendWire {
    static let magic: [UInt8] = Array("JLS1".utf8)
    /// Same limit as the viewer (file_push.hpp kMaxFiles).
    static let maxFiles = 1000
    /// Descriptors per frame; macOS limits one control message.
    static let batch = 64
    static let maxNameBytes = 255
    static let helperBundleID = "org.jeris.jerislink.send"
    static let teamID = "DD6947X9AG"

    enum Reply: String, CaseIterable {
        case ok
        case notConnected = "not_connected"
        case busy
        case oldViewer = "old_viewer"
        case tooBig = "too_big"
        case badName = "bad_name"
        case noSpace = "no_space"
        case refused
        case failed
    }

    static var socketDirectory: String {
        NSHomeDirectory() + "/Library/Caches/org.jeris.jerislink"
    }
    static var socketPath: String { socketDirectory + "/send.sock" }

    // MARK: Frames

    static func header(files: Int) -> [UInt8] { magic + be32(UInt32(files)) }

    static func batchFrame(names: [[UInt8]]) -> [UInt8] {
        var body: [UInt8] = []
        for n in names { body += be16(UInt16(n.count)) + n }
        return [UInt8(ascii: "F")] + be16(UInt16(names.count)) + be32(UInt32(body.count)) + body
    }

    static let endFrame: [UInt8] = [UInt8(ascii: "E")]

    /// Splits a batch body into names. nil when it does not add up.
    static func names(_ body: [UInt8], count: Int) -> [[UInt8]]? {
        var out: [[UInt8]] = []
        var i = 0
        while i < body.count {
            guard i + 2 <= body.count else { return nil }
            let n = Int(body[i]) << 8 | Int(body[i + 1])
            i += 2
            guard n > 0, n <= maxNameBytes, i + n <= body.count else { return nil }
            out.append(Array(body[i..<(i + n)]))
            i += n
        }
        return out.count == count ? out : nil
    }

    static func be16(_ v: UInt16) -> [UInt8] { [UInt8(v >> 8), UInt8(v & 0xff)] }
    static func be32(_ v: UInt32) -> [UInt8] { [UInt8(v >> 24), UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)] }
    static func u16(_ b: [UInt8], _ i: Int) -> Int { Int(b[i]) << 8 | Int(b[i + 1]) }
    static func u32(_ b: [UInt8], _ i: Int) -> Int { Int(b[i]) << 24 | Int(b[i + 1]) << 16 | Int(b[i + 2]) << 8 | Int(b[i + 3]) }

    // MARK: Socket I/O

    /// cmsghdr is 12 bytes on Darwin, aligned to 4.
    private static let cmsgHeader = 12
    private static func align4(_ n: Int) -> Int { (n + 3) & ~3 }

    /// Sends `bytes` in full; `fds` ride on the first sendmsg.
    static func send(_ sock: Int32, _ bytes: [UInt8], fds: [Int32] = []) -> Bool {
        guard !bytes.isEmpty else { return true }
        var sent = 0
        if !fds.isEmpty {
            let fdBytes = fds.count * MemoryLayout<Int32>.size
            var control = [UInt8](repeating: 0, count: cmsgHeader + align4(fdBytes))
            control.withUnsafeMutableBytes { raw in
                raw.storeBytes(of: UInt32(cmsgHeader + fdBytes), toByteOffset: 0, as: UInt32.self)
                raw.storeBytes(of: SOL_SOCKET, toByteOffset: 4, as: Int32.self)
                raw.storeBytes(of: SCM_RIGHTS, toByteOffset: 8, as: Int32.self)
                for (i, fd) in fds.enumerated() {
                    raw.storeBytes(of: fd, toByteOffset: cmsgHeader + i * 4, as: Int32.self)
                }
            }
            var data = bytes
            let n = data.withUnsafeMutableBytes { dataRaw -> Int in
                control.withUnsafeMutableBytes { ctlRaw -> Int in
                    var iov = iovec(iov_base: dataRaw.baseAddress, iov_len: dataRaw.count)
                    return withUnsafeMutablePointer(to: &iov) { iovp -> Int in
                        var msg = msghdr()
                        msg.msg_iov = iovp
                        msg.msg_iovlen = 1
                        msg.msg_control = ctlRaw.baseAddress
                        msg.msg_controllen = socklen_t(ctlRaw.count)
                        return Darwin.sendmsg(sock, &msg, 0)
                    }
                }
            }
            if n <= 0 { return false }
            sent = n
        }
        while sent < bytes.count {
            let n = bytes.withUnsafeBytes { Darwin.send(sock, $0.baseAddress!.advanced(by: sent), bytes.count - sent, 0) }
            if n <= 0 { return false }
            sent += n
        }
        return true
    }

    /// Reads exactly `count` bytes. Descriptors that arrive on the way are
    /// appended to `fds` (marked close-on-exec); a truncated control message
    /// fails the read, and every descriptor received is still handed back
    /// so the caller closes it.
    static func receive(_ sock: Int32, _ count: Int, fds: inout [Int32]) -> [UInt8]? {
        var out = [UInt8](repeating: 0, count: count)
        var got = 0
        let controlSize = cmsgHeader + batch * 4 + 64
        while got < count {
            var control = [UInt8](repeating: 0, count: controlSize)
            var flags: Int32 = 0
            var controlLen = 0
            let n = out.withUnsafeMutableBytes { dataRaw -> Int in
                control.withUnsafeMutableBytes { ctlRaw -> Int in
                    var iov = iovec(iov_base: dataRaw.baseAddress!.advanced(by: got), iov_len: count - got)
                    return withUnsafeMutablePointer(to: &iov) { iovp -> Int in
                        var msg = msghdr()
                        msg.msg_iov = iovp
                        msg.msg_iovlen = 1
                        msg.msg_control = ctlRaw.baseAddress
                        msg.msg_controllen = socklen_t(ctlRaw.count)
                        let r = Darwin.recvmsg(sock, &msg, 0)
                        flags = msg.msg_flags
                        controlLen = Int(msg.msg_controllen)
                        return r
                    }
                }
            }
            if n < 0, errno == EINTR { continue }
            // Pick up descriptors first, even from a read that then fails.
            var off = 0
            while off + cmsgHeader <= controlLen {
                let len = control.withUnsafeBytes { Int($0.load(fromByteOffset: off, as: UInt32.self)) }
                let level = control.withUnsafeBytes { $0.load(fromByteOffset: off + 4, as: Int32.self) }
                let type = control.withUnsafeBytes { $0.load(fromByteOffset: off + 8, as: Int32.self) }
                guard len >= cmsgHeader, off + len <= controlLen else { break }
                if level == SOL_SOCKET && type == SCM_RIGHTS {
                    for k in 0..<((len - cmsgHeader) / 4) {
                        let fd = control.withUnsafeBytes { $0.load(fromByteOffset: off + cmsgHeader + k * 4, as: Int32.self) }
                        _ = fcntl(fd, F_SETFD, FD_CLOEXEC)
                        fds.append(fd)
                    }
                }
                off += align4(len)
            }
            if n <= 0 || (flags & MSG_CTRUNC) != 0 { return nil }
            got += n
        }
        return out
    }

    /// One reply line, at most 64 bytes.
    static func readLine(_ sock: Int32) -> String? {
        var line: [UInt8] = []
        var byte: UInt8 = 0
        while line.count < 64 {
            let n = Darwin.read(sock, &byte, 1)
            if n < 0, errno == EINTR { continue }
            if n <= 0 { break }
            if byte == UInt8(ascii: "\n") { return String(decoding: line, as: UTF8.self) }
            line.append(byte)
        }
        return nil
    }

    static func setTimeouts(_ sock: Int32, seconds: Int) {
        var tv = timeval(tv_sec: seconds, tv_usec: 0)
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var one: Int32 = 1
        setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
    }

    static func address(_ path: String) -> sockaddr_un? {
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: addr.sun_path) else { return nil }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            for (i, b) in bytes.enumerated() { raw[i] = b }
            raw[bytes.count] = 0
        }
        addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        return addr
    }

    /// Helper side: sends the files (name, open descriptor) and returns the
    /// agent's reply, or nil when the agent is not there or said nothing.
    static func submit(_ files: [(name: [UInt8], fd: Int32)], path: String = socketPath, timeout: Int = 20) -> String? {
        let sock = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard sock >= 0 else { return nil }
        defer { Darwin.close(sock) }
        setTimeouts(sock, seconds: timeout)
        guard var addr = address(path) else { return nil }
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(sock, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard rc == 0 else { return nil }
        guard send(sock, header(files: files.count)) else { return nil }
        var i = 0
        while i < files.count {
            let part = Array(files[i..<min(files.count, i + batch)])
            guard send(sock, batchFrame(names: part.map(\.name)), fds: part.map(\.fd)) else { return nil }
            i += part.count
        }
        guard send(sock, endFrame) else { return nil }
        return readLine(sock)
    }
}
