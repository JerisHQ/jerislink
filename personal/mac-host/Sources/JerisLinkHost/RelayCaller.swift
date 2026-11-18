import Darwin
import Foundation

/// Who is on the other end of a loopback relay connection (#58 r2).
///
/// The relay (127.0.0.1:38411) exists for one client: the video service's
/// mouse relay (LocalControlMouseClient), which is this same executable
/// started as `--service video`. Every relay peer is 127.0.0.1, so the
/// address proves nothing. Instead find the process that owns the client end
/// of the TCP connection and accept it only when it runs our own executable.
/// Processes of other users (root's tailscaled behind an old `tailscale
/// serve` forward, for one) are not visible to us, so they are refused too.
enum RelayCaller {
    enum Decision: Equatable {
        case allow(pid: pid_t)
        case reject(String)
    }

    /// What the decision looks up about processes, swappable so the
    /// self-test can play a shared socket or a reused pid (#60 r3).
    struct Lookup {
        /// Every pid holding a TCP socket with local port `clientPort` and
        /// remote port `serverPort`.
        var holders: (_ clientPort: UInt16, _ serverPort: UInt16) -> [pid_t]
        /// A process's start time, which changes when its pid is reused.
        var startTime: (_ pid: pid_t) -> UInt64?
        var path: (_ pid: pid_t) -> String?
        var selfPath: () -> String?

        static var live: Lookup { Lookup(
            holders: { RelayCaller.holderPIDs(clientPort: $0, serverPort: $1) },
            startTime: { RelayCaller.startTime($0) },
            path: { RelayCaller.executablePath($0) },
            selfPath: { RelayCaller.executablePath(getpid()) }) }
    }

    static func check(clientPort: UInt16, serverPort: UInt16) -> Decision {
        decide(clientPort: clientPort, serverPort: serverPort, lookup: .live)
    }

    static func decide(clientPort: UInt16, serverPort: UInt16, lookup: Lookup) -> Decision {
        guard let me = lookup.selfPath() else { return .reject("no-self-path") }
        guard let pid = lookup.holders(clientPort, serverPort).first else { return .reject("no-owner") }
        guard let path = lookup.path(pid) else { return .reject("no-owner-path") }
        return path == me ? .allow(pid: pid) : .reject("other-executable")
    }

    /// When `pid` started (seconds and microseconds since 1970), or nil.
    static func startTime(_ pid: pid_t) -> UInt64? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else { return nil }
        return UInt64(info.pbi_start_tvsec) &* 1_000_000 &+ UInt64(info.pbi_start_tvusec)
    }

    static func executablePath(_ pid: pid_t) -> String? {
        var buf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN)) // PROC_PIDPATHINFO_MAXSIZE
        guard proc_pidpath(pid, &buf, UInt32(buf.count)) > 0 else { return nil }
        return URL(fileURLWithPath: String(cString: buf)).resolvingSymlinksInPath().path
    }

    /// Every pid we can see holding a TCP socket whose local port is
    /// `clientPort` and whose remote port is `serverPort` (the client end of
    /// the relay connection). More than one when the socket is shared.
    static func holderPIDs(clientPort: UInt16, serverPort: UInt16) -> [pid_t] {
        let count = proc_listallpids(nil, 0)
        guard count > 0 else { return [] }
        var pids = [pid_t](repeating: 0, count: Int(count) + 64)
        let got = pids.withUnsafeMutableBytes { proc_listallpids($0.baseAddress, Int32($0.count)) }
        guard got > 0 else { return [] }
        return pids.prefix(Int(got)).filter {
            $0 > 0 && holdsClientSocket(pid: $0, clientPort: clientPort, serverPort: serverPort)
        }
    }

    static func holdsClientSocket(pid: pid_t, clientPort: UInt16, serverPort: UInt16) -> Bool {
        holdsSocket(pid: pid, clientPort: clientPort, serverPort: serverPort)
    }

    private static func holdsSocket(pid: pid_t, clientPort: UInt16, serverPort: UInt16) -> Bool {
        let fdSize = MemoryLayout<proc_fdinfo>.stride
        let bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        guard bytes > 0 else { return false }
        var fds = [proc_fdinfo](repeating: proc_fdinfo(), count: Int(bytes) / fdSize + 16)
        let used = fds.withUnsafeMutableBytes { proc_pidinfo(pid, PROC_PIDLISTFDS, 0, $0.baseAddress, Int32($0.count)) }
        guard used > 0 else { return false }
        let infoSize = Int32(MemoryLayout<socket_fdinfo>.size)
        for fd in fds.prefix(Int(used) / fdSize) where fd.proc_fdtype == UInt32(PROX_FDTYPE_SOCKET) {
            var info = socket_fdinfo()
            guard proc_pidfdinfo(pid, fd.proc_fd, PROC_PIDFDSOCKETINFO, &info, infoSize) == infoSize,
                  info.psi.soi_kind == Int32(SOCKINFO_TCP) else { continue }
            let ini = info.psi.soi_proto.pri_tcp.tcpsi_ini
            let lport = UInt16(bigEndian: UInt16(truncatingIfNeeded: ini.insi_lport))
            let fport = UInt16(bigEndian: UInt16(truncatingIfNeeded: ini.insi_fport))
            if lport == clientPort && fport == serverPort { return true }
        }
        return false
    }
}
