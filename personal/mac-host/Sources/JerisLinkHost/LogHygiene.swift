import Foundation
import Darwin

/// Rate limit for a warning that can repeat per input event: the first one is
/// logged, then at most one per `intervalNs`, carrying how many were folded
/// into it. Pure, so the self-test drives it with fixed times.
struct LogRateLimiter {
    let intervalNs: UInt64
    private var lastNs: UInt64? = nil
    private var folded: UInt64 = 0
    private(set) var total: UInt64 = 0

    init(intervalNs: UInt64 = 10_000_000_000) {
        self.intervalNs = intervalNs
    }

    /// Counts one event. Returns the number of events folded since the last
    /// logged one when this one should be logged, nil when it is folded.
    mutating func record(nowNs: UInt64) -> UInt64? {
        total &+= 1
        if let last = lastNs, nowNs &- last < intervalNs {
            folded &+= 1
            return nil
        }
        lastNs = nowNs
        defer { folded = 0 }
        return folded
    }
}

/// When the periodic encoder stats line is due: every `intervalNs` (10 s)
/// instead of every 120 frames.
struct StatsTicker {
    let intervalNs: UInt64
    private var lastNs: UInt64

    init(intervalNs: UInt64 = 10_000_000_000, nowNs: UInt64 = DispatchTime.now().uptimeNanoseconds) {
        self.intervalNs = intervalNs
        self.lastNs = nowNs
    }

    mutating func due(nowNs: UInt64) -> Bool {
        guard nowNs &- lastNs >= intervalNs else { return false }
        lastNs = nowNs
        return true
    }
}

/// The service logs are launchd's StandardOutPath/StandardErrorPath files in
/// /tmp. Keep them readable by the owner only and below a size cap.
enum LogFiles {
    static let defaultMaxBytes: off_t = 10 * 1024 * 1024
    nonisolated(unsafe) private static var timer: DispatchSourceTimer?

    /// Sets mode 0600 on `fd` when it is a regular file and empties it when it
    /// is larger than `maxBytes`. Returns true when it emptied the file.
    @discardableResult
    static func secure(fd: Int32, maxBytes: off_t) -> Bool {
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else { return false }
        if st.st_mode & 0o777 != 0o600 { _ = fchmod(fd, 0o600) }
        guard st.st_size > maxBytes else { return false }
        guard ftruncate(fd, 0) == 0 else { return false }
        // launchd may open the file without O_APPEND: rewind as well.
        _ = lseek(fd, 0, SEEK_SET)
        let note = "log emptied at \(st.st_size) bytes (cap \(maxBytes))\n"
        _ = note.withCString { Darwin.write(fd, $0, strlen($0)) }
        return true
    }

    static func secureStdio(maxBytes: off_t = defaultMaxBytes) {
        fflush(stdout)
        fflush(stderr)
        secure(fd: STDOUT_FILENO, maxBytes: maxBytes)
        secure(fd: STDERR_FILENO, maxBytes: maxBytes)
    }

    /// Checks now and then every `everySeconds` for the life of the process.
    static func startCapping(everySeconds: Int = 300, maxBytes: off_t = defaultMaxBytes) {
        secureStdio(maxBytes: maxBytes)
        guard timer == nil else { return }
        let t = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
        t.schedule(deadline: .now() + .seconds(everySeconds), repeating: .seconds(everySeconds))
        t.setEventHandler { secureStdio(maxBytes: maxBytes) }
        t.resume()
        timer = t
    }
}

/// `JerisLinkHost --self-test` part for the log hygiene pieces.
enum LogHygieneSelfTest {
    static func run() -> Int32 {
        var failures = 0
        func expect(_ ok: Bool, _ name: String) {
            print("\(ok ? "PASS" : "FAIL") \(name)")
            if !ok { failures += 1 }
        }

        var limiter = LogRateLimiter(intervalNs: 10_000_000_000)
        expect(limiter.record(nowNs: 1_000) == 0, "log: first warning is logged")
        var logged = 0
        for i in 1...999 where limiter.record(nowNs: 1_000 + UInt64(i) * 1_000_000) != nil { logged += 1 }
        expect(logged == 0, "log: 999 warnings within 10 s are folded")
        expect(limiter.record(nowNs: 1_000 + 10_000_000_000) == 999, "log: next warning after 10 s reports 999 folded")
        expect(limiter.total == 1_001, "log: limiter counts every warning")

        var ticker = StatsTicker(intervalNs: 10_000_000_000, nowNs: 0)
        var ticks = 0
        for frame in 0..<(60 * 30) where ticker.due(nowNs: UInt64(frame) * 16_666_667) { ticks += 1 }
        expect(ticks == 2, "log: stats line every 10 s (2 in 30 s at 60 fps, was 15)")

        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("jerislink-loghygiene-\(getpid())", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let big = dir.appendingPathComponent("big.log")
        let small = dir.appendingPathComponent("small.log")
        FileManager.default.createFile(atPath: big.path, contents: Data(repeating: 0x41, count: 4096),
                                       attributes: [.posixPermissions: 0o644])
        FileManager.default.createFile(atPath: small.path, contents: Data(repeating: 0x41, count: 100),
                                       attributes: [.posixPermissions: 0o644])
        func check(_ url: URL) -> (emptied: Bool, mode: Int, size: Int) {
            let fd = open(url.path, O_WRONLY | O_APPEND)
            defer { close(fd) }
            let emptied = LogFiles.secure(fd: fd, maxBytes: 1024)
            let a = try? FileManager.default.attributesOfItem(atPath: url.path)
            return (emptied, (a?[.posixPermissions] as? Int) ?? -1, (a?[.size] as? Int) ?? -1)
        }
        let b = check(big)
        expect(b.emptied && b.mode == 0o600 && b.size > 0 && b.size < 100, "log: file over the cap is emptied and set to 0600")
        let s = check(small)
        expect(!s.emptied && s.mode == 0o600 && s.size == 100, "log: file under the cap is kept and set to 0600")
        var fds: [Int32] = [0, 0]
        if pipe(&fds) == 0 {
            expect(!LogFiles.secure(fd: fds[1], maxBytes: 0), "log: a pipe is left alone")
            close(fds[0]); close(fds[1])
        }

        expect(H264AnnexBWriter.discards(URL(fileURLWithPath: "/dev/null")), "log: no Annex B writer for /dev/null")
        expect(!H264AnnexBWriter.discards(big), "log: Annex B writer for a real output file")

        print(failures == 0 ? "LOG SELFTEST OK" : "LOG SELFTEST FAILED failures=\(failures)")
        return Int32(failures)
    }
}
