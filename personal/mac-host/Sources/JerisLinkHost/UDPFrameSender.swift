import Foundation
import Darwin

final class UDPFrameSender {
    private let socketFD: Int32
    private var destination = sockaddr_in()
    private let packetBytes: Int
    private let headerBytes = 20
    private let lock = NSLock()
    /// Pacing rate for each frame's packets in bits/s; 0 keeps the old
    /// 50us-per-8-packets smoothing. A path with a short queue (a relay, a
    /// congested link) drops much of a 270-packet IDR sent in ~1 ms.
    private let paceBitsPerSecond: Double
    private var paceWaitNanos: UInt64 = 0
    private var maxFrameSendNanos: UInt64 = 0

    private var sentFrames: UInt64 = 0
    private var sentPackets: UInt64 = 0
    private var sentBytes: UInt64 = 0
    private var sendErrors: UInt64 = 0
    private var maxPacketsPerFrame: UInt64 = 0
    private var maxFrameBytes: UInt64 = 0
    private var keyFrames: UInt64 = 0

    init(bindIP: String, clientIP: String, clientPort: UInt16, packetBytes: Int,
         paceMbps: Int = 0) throws {
        self.paceBitsPerSecond = Double(max(0, paceMbps)) * 1_000_000
        guard packetBytes > headerBytes + 64 && packetBytes <= 1400 else {
            throw NSError(domain: "JerisLink.UDP", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "packetBytes must be between 85 and 1400"])
        }
        self.packetBytes = packetBytes

        socketFD = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard socketFD >= 0 else {
            throw Self.posixError("socket")
        }

        var local = sockaddr_in()
        local.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        local.sin_family = sa_family_t(AF_INET)
        local.sin_port = 0
        guard inet_pton(AF_INET, bindIP, &local.sin_addr) == 1 else {
            close(socketFD)
            throw NSError(domain: "JerisLink.UDP", code: 2,
                          userInfo: [NSLocalizedDescriptionKey: "Invalid bind IP: \(bindIP)"])
        }

        let bindResult = withUnsafePointer(to: &local) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                Darwin.bind(socketFD, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0 else {
            let err = Self.posixError("bind \(bindIP)")
            close(socketFD)
            throw err
        }

        destination.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        destination.sin_family = sa_family_t(AF_INET)
        destination.sin_port = clientPort.bigEndian
        guard inet_pton(AF_INET, clientIP, &destination.sin_addr) == 1 else {
            close(socketFD)
            throw NSError(domain: "JerisLink.UDP", code: 3,
                          userInfo: [NSLocalizedDescriptionKey: "Invalid client IP: \(clientIP)"])
        }

        print("UDP sender: \(bindIP) -> \(clientIP):\(clientPort), packetBytes=\(packetBytes), pace=\(paceMbps > 0 ? "\(paceMbps) Mbps" : "off")")
    }

    deinit {
        close(socketFD)
    }

    func send(frameID: UInt64, data: Data, keyFrame: Bool) {
        let payloadCapacity = packetBytes - headerBytes
        guard payloadCapacity > 0, !data.isEmpty else { return }

        let packetCount = (data.count + payloadCapacity - 1) / payloadCapacity
        guard packetCount <= Int(UInt16.max) else {
            lock.lock(); sendErrors &+= 1; lock.unlock()
            return
        }

        lock.lock()
        maxPacketsPerFrame = max(maxPacketsPerFrame, UInt64(packetCount))
        maxFrameBytes = max(maxFrameBytes, UInt64(data.count))
        if keyFrame { keyFrames &+= 1 }
        lock.unlock()

        var frameHadError = false
        let frameStartNanos = DispatchTime.now().uptimeNanoseconds
        var frameBytesSent = 0
        var frameWaitNanos: UInt64 = 0
        for packetIndex in 0..<packetCount {
            let start = packetIndex * payloadCapacity
            let end = min(start + payloadCapacity, data.count)
            let payload = data.subdata(in: start..<end)
            var packet = Data(capacity: headerBytes + payload.count)
            packet.append(contentsOf: [0x4d, 0x52, 0x30, 0x32]) // MR02
            packet.append(1) // protocol version
            var flags: UInt8 = keyFrame ? 0x01 : 0x00
            if packetIndex == packetCount - 1 { flags |= 0x02 }
            packet.append(flags)
            packet.appendBE(frameID)
            packet.appendBE(UInt16(packetIndex))
            packet.appendBE(UInt16(packetCount))
            packet.appendBE(UInt16(payload.count))
            packet.append(payload)

            let result: ssize_t = packet.withUnsafeBytes { raw in
                guard let base = raw.baseAddress else { return -1 }
                return withUnsafePointer(to: &destination) { ptr in
                    ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                        Darwin.sendto(socketFD, base, packet.count, 0, sa,
                                      socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
            }

            lock.lock()
            if result == packet.count {
                sentPackets &+= 1
                sentBytes &+= UInt64(packet.count)
            } else {
                sendErrors &+= 1
                frameHadError = true
            }
            lock.unlock()

            frameBytesSent += packet.count
            if paceBitsPerSecond > 0 {
                // Keep this frame at or under the pace rate. Sleep only when at
                // least 2 ms ahead: macOS sleeps overshoot by several ms, so a
                // small frame (under ~20 KB at 80 Mbps) goes out without a wait,
                // and the due time is from the frame start so overshoot is
                // absorbed by the following packets.
                let dueNanos = frameStartNanos
                    + UInt64(Double(frameBytesSent) * 8 / paceBitsPerSecond * 1_000_000_000)
                let now = DispatchTime.now().uptimeNanoseconds
                if dueNanos > now + 2_000_000 {
                    usleep(UInt32((dueNanos - now) / 1000))
                    frameWaitNanos &+= dueNanos - now
                }
            } else if packetCount > 24 && packetIndex % 8 == 7 {
                // Old behaviour: 50us every 8 packets for large frames.
                usleep(50)
            }
        }
        let frameSendNanos = DispatchTime.now().uptimeNanoseconds &- frameStartNanos
        lock.lock()
        paceWaitNanos &+= frameWaitNanos
        maxFrameSendNanos = max(maxFrameSendNanos, frameSendNanos)
        lock.unlock()

        if !frameHadError {
            lock.lock(); sentFrames &+= 1; lock.unlock()
        }
    }

    func statsLine() -> String {
        lock.lock(); defer { lock.unlock() }
        return "udp_frames=\(sentFrames) udp_packets=\(sentPackets) udp_bytes=\(sentBytes) udp_errors=\(sendErrors) keyframes=\(keyFrames) max_packets_per_frame=\(maxPacketsPerFrame) max_frame_bytes=\(maxFrameBytes) pace_wait_total_ms=\(paceWaitNanos / 1_000_000) max_frame_send_ms=\(String(format: "%.2f", Double(maxFrameSendNanos) / 1_000_000))"
    }

    private static func posixError(_ operation: String) -> NSError {
        let code = errno
        return NSError(domain: NSPOSIXErrorDomain, code: Int(code),
                       userInfo: [NSLocalizedDescriptionKey: "\(operation) failed: \(String(cString: strerror(code)))"])
    }
}

private extension Data {
    mutating func appendBE<T: FixedWidthInteger>(_ value: T) {
        var v = value.bigEndian
        Swift.withUnsafeBytes(of: &v) { append(contentsOf: $0) }
    }
}
