import Foundation
import Darwin
import CoreGraphics

/// Decides when the status file may be rewritten: on connect/disconnect
/// (`force`) and otherwise at most once per `minInterval`. Pure, so the
/// self-test drives it with fixed times.
struct StatusThrottle {
    let minIntervalNs: UInt64
    private(set) var lastWriteNs: UInt64? = nil
    private(set) var dirty = false

    init(minIntervalNs: UInt64 = 1_000_000_000) {
        self.minIntervalNs = minIntervalNs
    }

    /// Marks the status changed and returns true when it should be written now.
    mutating func shouldWrite(nowNs: UInt64, force: Bool = false) -> Bool {
        dirty = true
        if !force, let last = lastWriteNs, nowNs &- last < minIntervalNs { return false }
        lastWriteNs = nowNs
        dirty = false
        return true
    }
}

/// Main display bounds, re-read at most every `maxAgeNs` and on every viewer
/// connect, instead of a WindowServer query per mouse event. A display mode
/// change takes effect within `maxAgeNs`.
struct DisplayBoundsCache {
    let maxAgeNs: UInt64
    private var bounds = CGRect.zero
    private var readAtNs: UInt64? = nil

    init(maxAgeNs: UInt64 = 500_000_000) {
        self.maxAgeNs = maxAgeNs
    }

    mutating func invalidate() { readAtNs = nil }

    mutating func get(nowNs: UInt64, read: () -> CGRect) -> CGRect {
        if let at = readAtNs, nowNs &- at < maxAgeNs { return bounds }
        bounds = read()
        readAtNs = nowNs
        return bounds
    }
}

@inline(__always) private func monotonicNs() -> UInt64 {
    DispatchTime.now().uptimeNanoseconds
}

private let statusDirURL: URL = {
    let dir = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/JerisLink", isDirectory: true)
    try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    return dir
}()

final class InputHelper {
    private let host = "127.0.0.1"
    private let port: UInt16 = 38410
    private var listenFD: Int32 = -1
    private var keyEvents: UInt64 = 0
    private var mouseEvents: UInt64 = 0
    private var leftDown = false
    private var rightDown = false
    private var middleDown = false
    private var controlDown = false
    private var optionDown = false
    private var commandDown = false
    private var shiftDown = false
    /// Post-event access as checked when the current viewer connected. Events
    /// are always posted: without access macOS drops them, and posting
    /// unconditionally means a grant made mid-session works at once.
    private var postEventAccess = false
    private var statusThrottle = StatusThrottle()
    private var displayBounds = DisplayBoundsCache()

    // Created once (the directory is made when this is first used).
    private let statusURL = statusDirURL.appendingPathComponent("input-helper-status.txt")

    private func currentFlags() -> CGEventFlags {
        var f: CGEventFlags = []
        if controlDown { f.insert(.maskControl) }
        if optionDown { f.insert(.maskAlternate) }
        if commandDown { f.insert(.maskCommand) }
        if shiftDown { f.insert(.maskShift) }
        return f
    }

    /// Rewrites the status file on connect/disconnect (`force`) and otherwise
    /// at most once a second. It holds counters only, never key codes.
    private func updateStatus(extra: @autoclosure () -> String? = nil, force: Bool = false) {
        guard statusThrottle.shouldWrite(nowNs: monotonicNs(), force: force) else { return }
        var s = "listening 127.0.0.1:38410 postEvent=\(postEventAccess) keyEvents=\(keyEvents) mouseEvents=\(mouseEvents)"
        s += " flags=0x\(String(currentFlags().rawValue, radix: 16))"
        if let extra = extra() { s += " \(extra)" }
        s += "\n"
        try? s.write(to: statusURL, atomically: true, encoding: .utf8)
    }

    /// One permission check per viewer connection (not per event).
    private func checkAccessOnConnect() {
        postEventAccess = CGPreflightPostEventAccess()
        if !postEventAccess {
            FileHandle.standardError.write(Data("input helper: post-event (Accessibility) access is not granted; input from the viewer is dropped by macOS until it is\n".utf8))
        }
        displayBounds.invalidate()
        updateStatus(extra: postEventAccess ? "clientConnected=true" : "clientConnected=true postEventDenied=true", force: true)
    }

    private func mainDisplayBounds() -> CGRect {
        displayBounds.get(nowNs: monotonicNs()) { CGDisplayBounds(CGMainDisplayID()) }
    }

    private func packet(type: UInt8, payload: [UInt8]) -> [UInt8] {
        let n = UInt16(payload.count)
        return [0x4d,0x52,0x49,0x31,1,type,UInt8(n >> 8),UInt8(n & 0xff)] + payload
    }

    private func sendAll(_ fd: Int32, _ bytes: [UInt8]) -> Bool {
        var off = 0
        while off < bytes.count {
            let n = bytes.withUnsafeBytes { raw -> Int in
                Darwin.send(fd, raw.baseAddress!.advanced(by: off), bytes.count - off, 0)
            }
            if n <= 0 { return false }
            off += n
        }
        return true
    }

    private func recvExact(_ fd: Int32, _ count: Int) -> [UInt8]? {
        if count == 0 { return [] }
        var out = [UInt8](repeating: 0, count: count)
        var off = 0
        while off < count {
            let n = out.withUnsafeMutableBytes { raw -> Int in
                Darwin.recv(fd, raw.baseAddress!.advanced(by: off), count - off, 0)
            }
            if n <= 0 { return nil }
            off += n
        }
        return out
    }

    private func isModifier(_ cg: UInt16) -> Bool {
        cg == 59 || cg == 58 || cg == 55 || cg == 56
    }

    private func setModifier(_ cg: UInt16, down: Bool) {
        switch cg {
        case 59: controlDown = down
        case 58: optionDown = down
        case 55: commandDown = down
        case 56: shiftDown = down
        default: break
        }
    }

    private func postKey(cg: UInt16, down: Bool) {
        keyEvents += 1

        if isModifier(cg) {
            setModifier(cg, down: down)
        }
        let flags = currentFlags()

        if let e = CGEvent(keyboardEventSource: nil,
                           virtualKey: CGKeyCode(cg),
                           keyDown: down) {
            e.flags = flags
            e.post(tap: .cghidEventTap)
        }

        updateStatus()
    }



    private func decodeInt16(_ p: [UInt8], _ i: Int) -> Int16 {
        Int16(bitPattern: UInt16(p[i]) << 8 | UInt16(p[i + 1]))
    }

    private func postMouseMove(dx: Int16, dy: Int16) {
        mouseEvents += 1
        guard let base = CGEvent(source: nil)?.location else {
            updateStatus(extra: "mouseLocationUnavailable=true")
            return
        }
        let target = CGPoint(x: base.x + CGFloat(dx), y: base.y + CGFloat(dy))
        postMouseMoveEvent(target: target)
        updateStatus()
    }

    private func postMouseMoveAbsolute(x: UInt16, y: UInt16) {
        mouseEvents += 1
        let bounds = mainDisplayBounds()
        let tx = min(max(CGFloat(x), bounds.minX), bounds.maxX - 1)
        let ty = min(max(CGFloat(y), bounds.minY), bounds.maxY - 1)
        let target = CGPoint(x: tx, y: ty)
        postMouseMoveEvent(target: target)
        updateStatus()
    }

    private func postMouseMoveNormalized(nx: UInt16, ny: UInt16) {
        mouseEvents += 1
        let bounds = mainDisplayBounds()
        let fx = CGFloat(nx) / 65535.0
        let fy = CGFloat(ny) / 65535.0
        let tx = bounds.minX + fx * max(0, bounds.width - 1)
        let ty = bounds.minY + fy * max(0, bounds.height - 1)
        let target = CGPoint(x: tx, y: ty)
        postMouseMoveEvent(target: target)
        updateStatus(extra: "bounds=\(Int(bounds.width))x\(Int(bounds.height))")
    }

    private func postMouseMoveEvent(target: CGPoint) {
        let type: CGEventType
        let button: CGMouseButton
        if leftDown { type = .leftMouseDragged; button = .left }
        else if rightDown { type = .rightMouseDragged; button = .right }
        else { type = .mouseMoved; button = .left }
        if let e = CGEvent(mouseEventSource: nil, mouseType: type, mouseCursorPosition: target, mouseButton: button) {
            e.post(tap: .cghidEventTap)
        }
    }

    private func postMouseButton(button code: UInt8, down: Bool, clickCount: UInt8 = 1) {
        mouseEvents += 1
        guard let pos = CGEvent(source: nil)?.location else { return }
        let type: CGEventType
        let button: CGMouseButton
        switch code {
        case 0:
            leftDown = down; type = down ? .leftMouseDown : .leftMouseUp; button = .left
        case 1:
            rightDown = down; type = down ? .rightMouseDown : .rightMouseUp; button = .right
        case 2:
            middleDown = down; type = down ? .otherMouseDown : .otherMouseUp; button = .center
        default:
            updateStatus(extra: "badMouseButton=\(code)")
            return
        }
        if let e = CGEvent(mouseEventSource: nil, mouseType: type, mouseCursorPosition: pos, mouseButton: button) {
            e.setIntegerValueField(.mouseEventClickState, value: Int64(max(1, clickCount)))
            e.post(tap: .cghidEventTap)
        }
        updateStatus()
    }

    private func postScroll(dx: Int16, dy: Int16) {
        mouseEvents += 1
        if let e = CGEvent(scrollWheelEvent2Source: nil,
                           units: .pixel,
                           wheelCount: 2,
                           wheel1: Int32(dy),
                           wheel2: Int32(dx),
                           wheel3: 0) {
            e.post(tap: .cghidEventTap)
        }
        updateStatus()
    }


    private func handleClient(_ fd: Int32) {
        while true {
            guard let h = recvExact(fd, 8) else { return }
            guard h[0] == 0x4d, h[1] == 0x52, h[2] == 0x49, h[3] == 0x31, h[4] == 1 else { return }
            let type = h[5]
            let len = Int(UInt16(h[6]) << 8 | UInt16(h[7]))
            guard len <= 4096, let p = recvExact(fd, len) else { return }
            switch type {
            case 0x01:
                _ = sendAll(fd, packet(type: 0x02, payload: p))
            case 0x10:
                guard p.count == 3 else { continue }
                let down = p[0] != 0
                let cg = UInt16(p[1]) << 8 | UInt16(p[2])
                postKey(cg: cg, down: down)
            case 0x20:
                guard p.count == 4 else { continue }
                postMouseMove(dx: decodeInt16(p, 0), dy: decodeInt16(p, 2))
            case 0x21:
                guard p.count == 2 else { continue }
                postMouseButton(button: p[0], down: p[1] != 0)
            case 0x25:
                guard p.count == 3 else { continue }
                postMouseButton(button: p[0], down: p[1] != 0, clickCount: p[2])
            case 0x22:
                guard p.count == 4 else { continue }
                postScroll(dx: decodeInt16(p, 0), dy: decodeInt16(p, 2))
            case 0x23:
                guard p.count == 4 else { continue }
                let x = UInt16(p[0]) << 8 | UInt16(p[1])
                let y = UInt16(p[2]) << 8 | UInt16(p[3])
                postMouseMoveAbsolute(x: x, y: y)
            case 0x24:
                guard p.count == 4 else { continue }
                let nx = UInt16(p[0]) << 8 | UInt16(p[1])
                let ny = UInt16(p[2]) << 8 | UInt16(p[3])
                postMouseMoveNormalized(nx: nx, ny: ny)
            default:
                continue
            }
        }
    }

    func run() throws {
        let s = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard s >= 0 else { throw NSError(domain: "MRI1", code: 1) }
        var yes: Int32 = 1
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        _ = host.withCString { inet_pton(AF_INET, $0, &addr.sin_addr) }
        let brc = withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard brc == 0 else { Darwin.close(s); throw NSError(domain: "MRI1", code: 2) }
        guard Darwin.listen(s, 4) == 0 else { Darwin.close(s); throw NSError(domain: "MRI1", code: 3) }
        listenFD = s
        postEventAccess = CGPreflightPostEventAccess()
        updateStatus(force: true)

        while true {
            let c = Darwin.accept(s, nil, nil)
            if c < 0 { continue }
            var noSigPipe: Int32 = 1
            setsockopt(c, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))
            checkAccessOnConnect()
            handleClient(c)
            Darwin.close(c)
            controlDown = false
            optionDown = false
            commandDown = false
            shiftDown = false
            leftDown = false
            rightDown = false
            middleDown = false
            updateStatus(extra: "clientClosed=true", force: true)
        }
    }
}

/// `JerisLinkInputHelper --self-test`: status throttle and display bounds
/// cache. Pure; posts no events and writes no files.
func inputHelperSelfTest() -> Bool {
    var ok = true
    func check(_ cond: Bool, _ what: String) {
        if !cond { ok = false; print("FAIL \(what)") }
    }
    let s = 1_000_000_000 as UInt64
    var t = StatusThrottle(minIntervalNs: s)
    check(t.shouldWrite(nowNs: 10 * s), "first write goes through")
    check(!t.shouldWrite(nowNs: 10 * s + 1), "second write within 1 s is held")
    check(t.dirty, "held write leaves the status dirty")
    check(!t.shouldWrite(nowNs: 11 * s - 1), "still held just under 1 s")
    check(t.shouldWrite(nowNs: 11 * s), "write allowed at 1 s")
    check(!t.dirty, "write clears dirty")
    check(t.shouldWrite(nowNs: 11 * s + 5, force: true), "forced write (connect/disconnect) always goes through")
    check(!t.shouldWrite(nowNs: 11 * s + 6), "throttle restarts after a forced write")
    var held = 0
    for i in 0..<10_000 where !t.shouldWrite(nowNs: 12 * s + UInt64(i) * 100_000) { held += 1 }
    check(held == 9_999, "10k events in 1 s write once (held \(held))")

    var c = DisplayBoundsCache(maxAgeNs: 500_000_000)
    var reads = 0
    let a = CGRect(x: 0, y: 0, width: 1920, height: 1080)
    let b = CGRect(x: 0, y: 0, width: 3840, height: 2160)
    var current = a
    check(c.get(nowNs: s, read: { reads += 1; return current }) == a, "first read")
    current = b
    check(c.get(nowNs: s + 100, read: { reads += 1; return current }) == a, "cached within max age")
    check(reads == 1, "one read while cached")
    check(c.get(nowNs: s + 500_000_000, read: { reads += 1; return current }) == b, "re-read after max age")
    c.invalidate()
    current = a
    check(c.get(nowNs: s + 500_000_001, read: { reads += 1; return current }) == a, "invalidate forces a re-read")
    check(reads == 3, "three reads in total (got \(reads))")
    print(ok ? "input helper self-test: ok" : "input helper self-test: FAILED")
    return ok
}

if CommandLine.arguments.contains("--self-test") {
    exit(inputHelperSelfTest() ? 0 : 1)
}

if CommandLine.arguments.contains("--version") {
    let version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "dev"
    print("JerisLink Input Helper v\(version)")
    exit(0)
}

if CommandLine.arguments.contains("--release-modifiers") {
    let modifiers: [CGKeyCode] = [59, 58, 55, 56]
    let allowed = CGPreflightPostEventAccess()
    if allowed {
        for key in modifiers {
            if let e = CGEvent(keyboardEventSource: nil, virtualKey: key, keyDown: false) {
                e.flags = []
                e.post(tap: .cghidEventTap)
            }
        }
        usleep(100_000)
    }
    let flags = CGEventSource.flagsState(.combinedSessionState)
    print("releaseModifiers postEvent=\(allowed) flags=0x\(String(flags.rawValue, radix: 16)) control=\(CGEventSource.keyState(.combinedSessionState, key: 59))")
    exit(allowed ? 0 : 5)
}

if CommandLine.arguments.contains("--request-post-event-access") {
    let before = CGPreflightPostEventAccess()
    let result = CGRequestPostEventAccess()
    let after = CGPreflightPostEventAccess()
    let dir = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/JerisLink", isDirectory: true)
    try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    let line = "request before=\(before) result=\(result) after=\(after)\n"
    try? line.write(to: dir.appendingPathComponent("input-helper-request.txt"), atomically: true, encoding: .utf8)
    print(line, terminator: "")
    exit(result ? 0 : 4)
}

// The helper is its own launchd agent, so this request is attributed to the
// helper's code identity (Accessibility), not to JerisLink.app.
if !CGPreflightPostEventAccess() {
    _ = CGRequestPostEventAccess()
}

do {
    try InputHelper().run()
} catch {
    try? "fatal=\(error)\n".write(to: statusDirURL.appendingPathComponent("input-helper-status.txt"), atomically: true, encoding: .utf8)
    exit(1)
}
