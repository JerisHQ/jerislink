import Foundation
import Darwin

final class InputHelperClient: @unchecked Sendable {
    private let host = "127.0.0.1"
    private let port: UInt16 = 38410
    private var fd: Int32 = -1

    deinit { closeConnection() }

    func closeConnection() {
        if fd >= 0 { Darwin.shutdown(fd, SHUT_RDWR); Darwin.close(fd); fd = -1 }
    }

    private func ensureConnected() -> Bool {
        if fd >= 0 { return true }
        let s = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard s >= 0 else { return false }
        var noSigPipe: Int32 = 1
        setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))
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
        return true
    }

    private func packet(type: UInt8, payload: [UInt8]) -> [UInt8] {
        let n = UInt16(payload.count)
        return [0x4d,0x52,0x49,0x31,1,type,UInt8(n >> 8),UInt8(n & 0xff)] + payload
    }

    private func sendAll(_ bytes: [UInt8]) -> Bool {
        guard ensureConnected() else { return false }
        var off = 0
        while off < bytes.count {
            let n = bytes.withUnsafeBytes { raw in
                Darwin.send(fd, raw.baseAddress!.advanced(by: off), bytes.count - off, 0)
            }
            if n <= 0 { closeConnection(); return false }
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
            if n <= 0 { closeConnection(); return nil }
            off += n
        }
        return out
    }

    func ping() -> Bool {
        let payload: [UInt8] = [0x12,0x34,0x56,0x78]
        guard sendAll(packet(type: 0x01, payload: payload)), let h = recvExact(8) else { return false }
        let len = Int(UInt16(h[6]) << 8 | UInt16(h[7]))
        guard h[0] == 0x4d, h[1] == 0x52, h[2] == 0x49, h[3] == 0x31, h[4] == 1, h[5] == 0x02,
              let p = recvExact(len) else { return false }
        return p == payload
    }

    func sendKey(cgCode: UInt16, down: Bool) -> Bool {
        let payload: [UInt8] = [down ? 1 : 0, UInt8(cgCode >> 8), UInt8(cgCode & 0xff)]
        let bytes = packet(type: 0x10, payload: payload)
        if sendAll(bytes) { return true }
        closeConnection()
        return sendAll(bytes)
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
        if sendAll(bytes) { return true }
        closeConnection()
        return sendAll(bytes)
    }

    func sendMouseMoveAbsolute(x: UInt16, y: UInt16) -> Bool {
        let bytes = packet(type: 0x23, payload: uint16Bytes(x) + uint16Bytes(y))
        if sendAll(bytes) { return true }
        closeConnection()
        return sendAll(bytes)
    }

    func sendMouseMoveNormalized(nx: UInt16, ny: UInt16) -> Bool {
        let bytes = packet(type: 0x24, payload: uint16Bytes(nx) + uint16Bytes(ny))
        if sendAll(bytes) { return true }
        closeConnection()
        return sendAll(bytes)
    }

    func sendMouseButton(button: UInt8, down: Bool) -> Bool {
        let bytes = packet(type: 0x21, payload: [button, down ? 1 : 0])
        if sendAll(bytes) { return true }
        closeConnection()
        return sendAll(bytes)
    }

    func sendMouseButtonExtended(button: UInt8, down: Bool, clickCount: UInt8) -> Bool {
        let bytes = packet(type: 0x25, payload: [button, down ? 1 : 0, max(1, clickCount)])
        if sendAll(bytes) { return true }
        closeConnection()
        return sendAll(bytes)
    }

    func sendScroll(dx: Int16, dy: Int16) -> Bool {
        let bytes = packet(type: 0x22, payload: int16Bytes(dx) + int16Bytes(dy))
        if sendAll(bytes) { return true }
        closeConnection()
        return sendAll(bytes)
    }
}
