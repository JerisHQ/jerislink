import Foundation
import Darwin
import CoreGraphics

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
    private var lastCG: UInt16 = 0
    private var lastDown = false

    private var statusURL: URL {
        let dir = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/JerisLink", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("input-helper-status.txt")
    }

    private func currentFlags() -> CGEventFlags {
        var f: CGEventFlags = []
        if controlDown { f.insert(.maskControl) }
        if optionDown { f.insert(.maskAlternate) }
        if commandDown { f.insert(.maskCommand) }
        if shiftDown { f.insert(.maskShift) }
        return f
    }

    private func updateStatus(extra: String? = nil) {
        var s = "listening 127.0.0.1:38410 postEvent=\(CGPreflightPostEventAccess()) keyEvents=\(keyEvents) mouseEvents=\(mouseEvents)"
        if keyEvents > 0 { s += " lastCG=\(lastCG) down=\(lastDown)" }
        s += " flags=0x\(String(currentFlags().rawValue, radix: 16))"
        if let extra { s += " \(extra)" }
        s += "\n"
        try? s.write(to: statusURL, atomically: true, encoding: .utf8)
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
        lastCG = cg
        lastDown = down

        if isModifier(cg) {
            setModifier(cg, down: down)
        }
        let flags = currentFlags()

        if CGPreflightPostEventAccess(), let e = CGEvent(keyboardEventSource: nil,
                                                        virtualKey: CGKeyCode(cg),
                                                        keyDown: down) {
            e.flags = flags
            e.post(tap: .cghidEventTap)
        }

        updateStatus(extra: "eventFlags=0x\(String(flags.rawValue, radix: 16))")
    }



    private func decodeInt16(_ p: [UInt8], _ i: Int) -> Int16 {
        Int16(bitPattern: UInt16(p[i]) << 8 | UInt16(p[i + 1]))
    }

    private func postMouseMove(dx: Int16, dy: Int16) {
        mouseEvents += 1
        guard CGPreflightPostEventAccess(), let base = CGEvent(source: nil)?.location else {
            updateStatus(extra: "mouseMoveDenied=true")
            return
        }
        let target = CGPoint(x: base.x + CGFloat(dx), y: base.y + CGFloat(dy))
        postMouseMoveEvent(target: target)
        updateStatus(extra: "mouseMove=\(dx),\(dy)")
    }

    private func postMouseMoveAbsolute(x: UInt16, y: UInt16) {
        mouseEvents += 1
        guard CGPreflightPostEventAccess() else {
            updateStatus(extra: "mouseMoveAbsDenied=true")
            return
        }
        let bounds = CGDisplayBounds(CGMainDisplayID())
        let tx = min(max(CGFloat(x), bounds.minX), bounds.maxX - 1)
        let ty = min(max(CGFloat(y), bounds.minY), bounds.maxY - 1)
        let target = CGPoint(x: tx, y: ty)
        postMouseMoveEvent(target: target)
        updateStatus(extra: "mouseMoveAbs=\(x),\(y)")
    }

    private func postMouseMoveNormalized(nx: UInt16, ny: UInt16) {
        mouseEvents += 1
        guard CGPreflightPostEventAccess() else {
            updateStatus(extra: "mouseMoveNormDenied=true")
            return
        }
        let bounds = CGDisplayBounds(CGMainDisplayID())
        let fx = CGFloat(nx) / 65535.0
        let fy = CGFloat(ny) / 65535.0
        let tx = bounds.minX + fx * max(0, bounds.width - 1)
        let ty = bounds.minY + fy * max(0, bounds.height - 1)
        let target = CGPoint(x: tx, y: ty)
        postMouseMoveEvent(target: target)
        updateStatus(extra: "mouseMoveNorm=\(nx),\(ny) bounds=\(Int(bounds.width))x\(Int(bounds.height))")
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
        if CGPreflightPostEventAccess(), let e = CGEvent(mouseEventSource: nil, mouseType: type, mouseCursorPosition: pos, mouseButton: button) {
            e.setIntegerValueField(.mouseEventClickState, value: Int64(max(1, clickCount)))
            e.post(tap: .cghidEventTap)
        }
        updateStatus(extra: "mouseButton=\(code) down=\(down) clicks=\(max(1, clickCount))")
    }

    private func postScroll(dx: Int16, dy: Int16) {
        mouseEvents += 1
        if CGPreflightPostEventAccess(), let e = CGEvent(scrollWheelEvent2Source: nil,
                                                         units: .pixel,
                                                         wheelCount: 2,
                                                         wheel1: Int32(dy),
                                                         wheel2: Int32(dx),
                                                         wheel3: 0) {
            e.post(tap: .cghidEventTap)
        }
        updateStatus(extra: "scroll=\(dx),\(dy)")
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
        updateStatus()

        while true {
            let c = Darwin.accept(s, nil, nil)
            if c < 0 { continue }
            var noSigPipe: Int32 = 1
            setsockopt(c, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))
            handleClient(c)
            Darwin.close(c)
            controlDown = false
            optionDown = false
            commandDown = false
            shiftDown = false
            leftDown = false
            rightDown = false
            middleDown = false
            updateStatus(extra: "clientClosed=true")
        }
    }
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
    let dir = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/JerisLink", isDirectory: true)
    try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    try? "fatal=\(error)\n".write(to: dir.appendingPathComponent("input-helper-status.txt"), atomically: true, encoding: .utf8)
    exit(1)
}
