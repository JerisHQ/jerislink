import Foundation
import Darwin

/// Host send pacing for the MR02 video packets. Wire format is unchanged.
///
/// Off (mbps == 0): the old behaviour, packets go out inline from the encoder
/// callback with 50us every 8 packets for frames over 24 packets.
/// On: frames go to one serial send queue and a token bucket limits the rate
/// to `mbps`, with up to `burstBytes` allowed at line rate. A small P frame
/// still leaves at once; a large frame (an IDR) is spread out instead of
/// leaving in about 1 ms, which a short router or relay queue would drop.
struct UDPPacing: Equatable {
    var mbps: Int
    var burstBytes: Int

    static let off = UDPPacing(mbps: 0, burstBytes: 0)
    static let defaultBurstKB = 32

    var enabled: Bool { mbps > 0 }

    /// Rate used when video-settings.plist has no udpPaceMbps: 4x the video
    /// bitrate, at least 40 and at most 400 Mbps (18 Mbps HEVC -> 72 Mbps).
    static func autoMbps(bitrateMbps: Int) -> Int {
        min(400, max(40, bitrateMbps * 4))
    }

    var summary: String {
        enabled ? "pace=\(mbps)Mbps burst=\(burstBytes / 1024)KB" : "pace=off"
    }
}

/// State is guarded by `lock`; the token bucket is only used on `sendQueue`.
final class UDPFrameSender: @unchecked Sendable {
    private let socketFD: Int32
    private var destination = sockaddr_in()
    private let packetBytes: Int
    private let headerBytes = 20
    private let lock = NSLock()
    private let pacing: UDPPacing
    private let sendQueue = DispatchQueue(label: "jerislink.udp.send", qos: .userInteractive)

    private var sentFrames: UInt64 = 0
    private var sentPackets: UInt64 = 0
    private var sentBytes: UInt64 = 0
    private var sendErrors: UInt64 = 0
    private var maxPacketsPerFrame: UInt64 = 0
    private var maxFrameBytes: UInt64 = 0
    private var keyFrames: UInt64 = 0

    // Send-time and burst stats (both modes), guarded by `lock`.
    private var frameSendSumNanos: UInt64 = 0
    private var frameSendMaxNanos: UInt64 = 0
    private var frameSendCount: UInt64 = 0
    private var paceWaits: UInt64 = 0
    private var paceWaitNanos: UInt64 = 0
    private var queuedFrames = 0
    private var maxQueuedFrames = 0
    private var queueOverflowFrames: UInt64 = 0
    // Sliding 1 ms window over sent packets: the most bytes that left within
    // any 1 ms, i.e. the worst burst the network queue had to absorb.
    private var windowTimes = [UInt64](repeating: 0, count: 1024)
    private var windowSizes = [Int](repeating: 0, count: 1024)
    private var windowHead = 0
    private var windowCount = 0
    private var windowBytes = 0
    private var maxBytesPer1ms = 0

    // Token bucket, touched only on `sendQueue`.
    private var tokens: Double = 0
    private var lastRefillNanos: UInt64 = 0

    /// A frame that would wait behind this many queued frames goes out without
    /// pacing, so a too-low rate cannot build latency without bound.
    private let maxQueuedBeforeFlush = 4

    init(bindIP: String, clientIP: String, clientPort: UInt16, packetBytes: Int,
         pacing: UDPPacing = .off) throws {
        guard packetBytes > headerBytes + 64 && packetBytes <= 1400 else {
            throw NSError(domain: "JerisLink.UDP", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "packetBytes must be between 85 and 1400"])
        }
        self.packetBytes = packetBytes
        var p = pacing
        if p.enabled { p.burstBytes = max(p.burstBytes, packetBytes) }
        self.pacing = p
        self.tokens = Double(p.burstBytes)
        self.lastRefillNanos = DispatchTime.now().uptimeNanoseconds

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

        print("UDP sender: \(bindIP) -> \(clientIP):\(clientPort), packetBytes=\(packetBytes), \(self.pacing.summary)")
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

        let enqueuedNanos = DispatchTime.now().uptimeNanoseconds
        guard pacing.enabled else {
            sendFrame(frameID: frameID, data: data, keyFrame: keyFrame,
                      packetCount: packetCount, enqueuedNanos: enqueuedNanos, paced: false)
            return
        }

        lock.lock()
        let flush = queuedFrames >= maxQueuedBeforeFlush
        if flush { queueOverflowFrames &+= 1 }
        queuedFrames += 1
        maxQueuedFrames = max(maxQueuedFrames, queuedFrames)
        lock.unlock()

        sendQueue.async { [self] in
            sendFrame(frameID: frameID, data: data, keyFrame: keyFrame,
                      packetCount: packetCount, enqueuedNanos: enqueuedNanos, paced: !flush)
            lock.lock(); queuedFrames -= 1; lock.unlock()
        }
    }

    private func sendFrame(frameID: UInt64, data: Data, keyFrame: Bool, packetCount: Int,
                           enqueuedNanos: UInt64, paced: Bool) {
        let payloadCapacity = packetBytes - headerBytes
        var frameHadError = false
        var frameWaits: UInt64 = 0
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

            if paced {
                let waited = takeTokens(packet.count)
                if waited > 0 {
                    frameWaits &+= 1
                    frameWaitNanos &+= waited
                }
            }

            let result: ssize_t = packet.withUnsafeBytes { raw in
                guard let base = raw.baseAddress else { return -1 }
                return withUnsafePointer(to: &destination) { ptr in
                    ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                        Darwin.sendto(socketFD, base, packet.count, 0, sa,
                                      socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
            }
            let sentNanos = DispatchTime.now().uptimeNanoseconds

            lock.lock()
            if result == packet.count {
                sentPackets &+= 1
                sentBytes &+= UInt64(packet.count)
                recordBurst(at: sentNanos, bytes: packet.count)
            } else {
                sendErrors &+= 1
                frameHadError = true
            }
            lock.unlock()

            // Old behaviour when pacing is off: 50us every 8 packets for large
            // frames. Also skipped for a flushed (overflow) frame.
            if !pacing.enabled && packetCount > 24 && packetIndex % 8 == 7 {
                usleep(50)
            }
        }

        let sendNanos = DispatchTime.now().uptimeNanoseconds &- enqueuedNanos
        lock.lock()
        frameSendSumNanos &+= sendNanos
        frameSendMaxNanos = max(frameSendMaxNanos, sendNanos)
        frameSendCount &+= 1
        paceWaits &+= frameWaits
        paceWaitNanos &+= frameWaitNanos
        if !frameHadError { sentFrames &+= 1 }
        lock.unlock()
    }

    /// Token bucket: refill at the pace rate up to the burst size, then wait
    /// until `bytes` are available. Returns the nanoseconds slept (0 = none).
    /// Sleep overshoot only adds tokens, so the next packets catch up.
    private func takeTokens(_ bytes: Int) -> UInt64 {
        let bytesPerNano = Double(pacing.mbps) * 1_000_000 / 8 / 1_000_000_000
        var now = DispatchTime.now().uptimeNanoseconds
        tokens = min(Double(pacing.burstBytes), tokens + Double(now &- lastRefillNanos) * bytesPerNano)
        lastRefillNanos = now
        var slept: UInt64 = 0
        if tokens < Double(bytes) {
            let waitNanos = UInt64((Double(bytes) - tokens) / bytesPerNano)
            var ts = timespec(tv_sec: Int(waitNanos / 1_000_000_000), tv_nsec: Int(waitNanos % 1_000_000_000))
            nanosleep(&ts, nil)
            let after = DispatchTime.now().uptimeNanoseconds
            slept = max(1, after &- now)
            now = after
            tokens = min(Double(pacing.burstBytes), tokens + Double(now &- lastRefillNanos) * bytesPerNano)
            lastRefillNanos = now
        }
        tokens -= Double(bytes)
        return slept
    }

    /// Caller holds `lock`.
    private func recordBurst(at nanos: UInt64, bytes: Int) {
        let capacity = windowTimes.count
        while windowCount > 0 && nanos &- windowTimes[windowHead] > 1_000_000 {
            windowBytes -= windowSizes[windowHead]
            windowHead = (windowHead + 1) % capacity
            windowCount -= 1
        }
        if windowCount == capacity {
            windowBytes -= windowSizes[windowHead]
            windowHead = (windowHead + 1) % capacity
            windowCount -= 1
        }
        let tail = (windowHead + windowCount) % capacity
        windowTimes[tail] = nanos
        windowSizes[tail] = bytes
        windowCount += 1
        windowBytes += bytes
        maxBytesPer1ms = max(maxBytesPer1ms, windowBytes)
    }

    func statsLine() -> String {
        lock.lock(); defer { lock.unlock() }
        let sendAvgMS = frameSendCount > 0 ? Double(frameSendSumNanos) / Double(frameSendCount) / 1_000_000 : 0
        // frame_send_*: from the encoder handing the frame over to its last
        // packet leaving (includes queue wait and pacing). max_kb_per_1ms: the
        // most bytes sent within any 1 ms (cumulative max).
        return "udp_frames=\(sentFrames) udp_packets=\(sentPackets) udp_bytes=\(sentBytes) udp_errors=\(sendErrors) keyframes=\(keyFrames) max_packets_per_frame=\(maxPacketsPerFrame) max_frame_bytes=\(maxFrameBytes) "
            + "\(pacing.summary) "
            + String(format: "frame_send_avg=%.2fms frame_send_max=%.2fms ", sendAvgMS, Double(frameSendMaxNanos) / 1_000_000)
            + "pace_waits=\(paceWaits) pace_wait_total_ms=\(paceWaitNanos / 1_000_000) "
            + "send_queue_max=\(maxQueuedFrames) pace_overflow=\(queueOverflowFrames) "
            + "max_kb_per_1ms=\(maxBytesPer1ms / 1024)"
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
