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

/// Frames kept for NACK retransmit (MRM1 0x41). A frame leaves the cache when
/// it is older than 250 ms, or when the cache holds more than 4 MiB or 32
/// frames (oldest first). A frameID that goes backwards means the encoder
/// restarted, so the old frames are dropped.
struct RetransmitFrameCache {
    struct Entry {
        let frameID: UInt64
        let data: Data
        let keyFrame: Bool
        let packetCount: Int
        let insertedNanos: UInt64
    }

    static let maxAgeNanos: UInt64 = 250_000_000
    static let maxBytes = 4 * 1024 * 1024
    static let maxFrames = 32

    private(set) var entries: [Entry] = [] // oldest first
    private(set) var bytes = 0
    private(set) var resets: UInt64 = 0

    mutating func insert(frameID: UInt64, data: Data, keyFrame: Bool, packetCount: Int, now: UInt64) {
        if let last = entries.last, frameID <= last.frameID {
            removeAll()
            resets &+= 1
        }
        entries.append(Entry(frameID: frameID, data: data, keyFrame: keyFrame,
                             packetCount: packetCount, insertedNanos: now))
        bytes += data.count
        evict(now: now)
    }

    mutating func evict(now: UInt64) {
        while let first = entries.first,
              entries.count > Self.maxFrames || bytes > Self.maxBytes || Self.expired(first, now: now) {
            bytes -= first.data.count
            entries.removeFirst()
        }
    }

    func lookup(frameID: UInt64, now: UInt64) -> Entry? {
        guard let entry = entries.last(where: { $0.frameID == frameID }), !Self.expired(entry, now: now) else {
            return nil
        }
        return entry
    }

    mutating func removeAll() {
        entries.removeAll(keepingCapacity: true)
        bytes = 0
    }

    private static func expired(_ entry: Entry, now: UInt64) -> Bool {
        now > entry.insertedNanos && now - entry.insertedNanos > maxAgeNanos
    }
}

/// Retransmit budget: at most 20% of the video bitrate in any 100 ms window
/// (sliding: every send stays counted for 100 ms after it went out). A NACK
/// that does not fit is dropped whole (counted as nack_over_budget) and the
/// caller falls back to a gated keyframe.
struct RetransmitBudget {
    static let windowNanos: UInt64 = 100_000_000
    private(set) var bytesPerWindow: Int
    private var sends: [(at: UInt64, bytes: Int)] = []
    private var head = 0
    private(set) var used = 0

    init(videoBitrateMbps: Int) {
        // bitrate/8 bytes per second, /10 per 100 ms, 20% of that.
        bytesPerWindow = max(1, videoBitrateMbps) * 1_000_000 / 8 / 10 / 5
    }

    /// ABR: the budget follows the live bitrate (same 20% per 100 ms).
    mutating func setVideoBitrate(kbps: Int) {
        bytesPerWindow = max(1, max(1, kbps) * 1000 / 8 / 10 / 5)
    }

    mutating func take(_ bytes: Int, now: UInt64) -> Bool {
        // Drop sends that left the window. A clock that went backwards empties it.
        while head < sends.count, now < sends[head].at || now - sends[head].at >= Self.windowNanos {
            used -= sends[head].bytes
            head += 1
        }
        if head > 64, head * 2 > sends.count {
            sends.removeFirst(head)
            head = 0
        }
        guard used + bytes <= bytesPerWindow else { return false }
        sends.append((now, bytes))
        used += bytes
        return true
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
    private var paceMbpsLive: Int = 0
    private var tokens: Double = 0
    private var lastRefillNanos: UInt64 = 0

    /// One NACK range: `count` packets from `start`. (0, 0xFFFF) = whole frame.
    struct NackRange: Equatable {
        var start: UInt16
        var count: UInt16
        static let wholeFrame = NackRange(start: 0, count: 0xFFFF)
    }

    enum RetransmitResult: Equatable {
        case sent(packets: Int)
        case miss        // frame no longer cached (or never was)
        case overBudget  // would pass 20% of the bitrate in this 100 ms
        case disabled
    }

    // NACK retransmit (design doc section 1), guarded by `lock`.
    let retransmitEnabled: Bool
    private var cache = RetransmitFrameCache()
    private var budget: RetransmitBudget
    /// Paced mode: retransmit packets wait here and leave before the next
    /// packet of any new frame, through the same token bucket.
    private var pendingRetransmit: [Data] = []
    private var nackRequests: UInt64 = 0
    private var nackPacketsResent: UInt64 = 0
    private var nackBytes: UInt64 = 0
    private var nackMiss: UInt64 = 0
    private var nackOverBudget: UInt64 = 0
    // ABR window: send queue max since the last abrWindow() call (lock).
    private var abrWindowQueueMax = 0
    // Send-cadence slope since the last abrWindow() call (lock).
    private var sendSlope: ArrivalSlope
    private var abrPaceMbps = 0
    private var statsSuffix: (() -> String)?

    /// A frame that would wait behind this many queued frames goes out without
    /// pacing, so a too-low rate cannot build latency without bound.
    private let maxQueuedBeforeFlush = 4

    init(bindIP: String, clientIP: String, clientPort: UInt16, packetBytes: Int,
         pacing: UDPPacing = .off, retransmit: Bool = false, videoBitrateMbps: Int = 20,
         nominalFps: Int = 60) throws {
        guard packetBytes > headerBytes + 64 && packetBytes <= 1400 else {
            throw NSError(domain: "JerisLink.UDP", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "packetBytes must be between 85 and 1400"])
        }
        self.packetBytes = packetBytes
        var p = pacing
        if p.enabled { p.burstBytes = max(p.burstBytes, packetBytes) }
        self.pacing = p
        self.paceMbpsLive = p.mbps
        self.tokens = Double(p.burstBytes)
        self.lastRefillNanos = DispatchTime.now().uptimeNanoseconds
        self.retransmitEnabled = retransmit
        self.budget = RetransmitBudget(videoBitrateMbps: videoBitrateMbps)
        self.sendSlope = ArrivalSlope(nominalFrameMs: 1000.0 / Double(max(1, nominalFps)))

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

        print("UDP sender: \(bindIP) -> \(clientIP):\(clientPort), packetBytes=\(packetBytes), \(self.pacing.summary) nack=\(retransmit ? "on budget=\(budget.bytesPerWindow)B/100ms" : "off")")
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

        noteFrameCadence(frameID, nowMs: Double(DispatchTime.now().uptimeNanoseconds) / 1_000_000)
        lock.lock()
        maxPacketsPerFrame = max(maxPacketsPerFrame, UInt64(packetCount))
        maxFrameBytes = max(maxFrameBytes, UInt64(data.count))
        if keyFrame { keyFrames &+= 1 }
        if retransmitEnabled {
            cache.insert(frameID: frameID, data: data, keyFrame: keyFrame, packetCount: packetCount,
                         now: DispatchTime.now().uptimeNanoseconds)
        }
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
        abrWindowQueueMax = max(abrWindowQueueMax, queuedFrames)
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
            if paced { drainRetransmits(paced: true) }
            let packet = Self.makePacket(frameID: frameID, data: data, keyFrame: keyFrame,
                                         packetIndex: packetIndex, packetCount: packetCount,
                                         payloadCapacity: payloadCapacity, retransmit: false)

            if paced {
                let waited = takeTokens(packet.count)
                if waited > 0 {
                    frameWaits &+= 1
                    frameWaitNanos &+= waited
                }
            }

            if !sendCounted(packet) { frameHadError = true }

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

    /// Resend the packets a viewer NACKed (MRM1 0x41). Called on the mouse UDP
    /// receive queue. Retransmitted packets are byte-identical to the
    /// originals except for MR02 flag 0x04.
    func retransmit(frameID: UInt64, ranges: [NackRange]) -> RetransmitResult {
        guard retransmitEnabled else { return .disabled }
        let now = DispatchTime.now().uptimeNanoseconds
        let payloadCapacity = packetBytes - headerBytes
        lock.lock()
        nackRequests &+= 1
        cache.evict(now: now)
        guard let entry = cache.lookup(frameID: frameID, now: now) else {
            nackMiss &+= 1
            lock.unlock()
            return .miss
        }
        let indices = Self.packetIndices(for: ranges, packetCount: entry.packetCount)
        let packets = indices.map {
            Self.makePacket(frameID: entry.frameID, data: entry.data, keyFrame: entry.keyFrame,
                            packetIndex: $0, packetCount: entry.packetCount,
                            payloadCapacity: payloadCapacity, retransmit: true)
        }
        let bytes = packets.reduce(0) { $0 + $1.count }
        guard budget.take(bytes, now: now) else {
            nackOverBudget &+= 1
            lock.unlock()
            return .overBudget
        }
        nackPacketsResent &+= UInt64(packets.count)
        nackBytes &+= UInt64(bytes)
        if pacing.enabled { pendingRetransmit.append(contentsOf: packets) }
        lock.unlock()

        if pacing.enabled {
            sendQueue.async { [self] in drainRetransmits(paced: true) }
        } else {
            for packet in packets { _ = sendCounted(packet) }
        }
        return .sent(packets: packets.count)
    }

    /// Extra fields at the end of statsLine() (the ABR state).
    func setStatsSuffix(_ suffix: @escaping () -> String) {
        lock.lock(); statsSuffix = suffix; lock.unlock()
    }

    /// ABR input for one receiver report: the most frames queued at the pacer
    /// since the previous call (then reset to the current depth), the
    /// cumulative NACK over-budget count, and the send-cadence slope since
    /// the previous call (frames as the encoder handed them over).
    func abrWindow() -> (queueMax: Int, overBudgetTotal: UInt64, sendSlope: ArrivalSlope.Window) {
        lock.lock(); defer { lock.unlock() }
        let q = abrWindowQueueMax
        abrWindowQueueMax = queuedFrames
        return (q, nackOverBudget, sendSlope.take())
    }

    /// ABR changed the encoder bitrate: the NACK budget follows it, and so
    /// does the pace rate when it is automatic (UDPPacing.autoMbps).
    func setVideoBitrate(kbps: Int, paceFollows: Bool) {
        lock.lock()
        budget.setVideoBitrate(kbps: kbps)
        let mbps = paceFollows && pacing.enabled ? UDPPacing.autoMbps(bitrateMbps: max(1, (kbps + 999) / 1000)) : 0
        if mbps > 0 { abrPaceMbps = mbps }
        lock.unlock()
        if mbps > 0 { sendQueue.async { [self] in paceMbpsLive = mbps } }
    }

    /// New viewer session: old frames can no longer be asked for.
    func clearRetransmitCache() {
        lock.lock()
        cache.removeAll()
        pendingRetransmit.removeAll()
        lock.unlock()
    }

    /// Capture restart (display change): the new capture numbers frames from
    /// 1 again. Clear the cache as for a new session, and start the
    /// send-cadence slope again, so the first frames of the new capture are
    /// measured instead of ignored as "old" ids (ABR v1 review P3).
    func captureRestarted() {
        lock.lock()
        cache.removeAll()
        pendingRetransmit.removeAll()
        sendSlope.reset()
        lock.unlock()
    }

    /// The encoder handed over frame `frameID` at `nowMs` (send() calls it;
    /// self-tests call it with fixed times).
    func noteFrameCadence(_ frameID: UInt64, nowMs: Double) {
        lock.lock()
        sendSlope.onFrame(frameID, nowMs: nowMs)
        lock.unlock()
    }

    /// Packet indices for NACK ranges, sorted and without duplicates; ranges
    /// past the end of the frame are clipped.
    static func packetIndices(for ranges: [NackRange], packetCount: Int) -> [Int] {
        guard packetCount > 0 else { return [] }
        var wanted = [Bool](repeating: false, count: packetCount)
        for range in ranges {
            if range == .wholeFrame {
                return Array(0..<packetCount)
            }
            let start = Int(range.start)
            let end = min(start + Int(range.count), packetCount)
            if start < end {
                for i in start..<end { wanted[i] = true }
            }
        }
        return wanted.indices.filter { wanted[$0] }
    }

    static func makePacket(frameID: UInt64, data: Data, keyFrame: Bool, packetIndex: Int,
                           packetCount: Int, payloadCapacity: Int, retransmit: Bool) -> Data {
        let start = data.startIndex + packetIndex * payloadCapacity
        let end = min(start + payloadCapacity, data.endIndex)
        let payload = data.subdata(in: start..<end)
        var packet = Data(capacity: 20 + payload.count)
        packet.append(contentsOf: [0x4d, 0x52, 0x30, 0x32]) // MR02
        packet.append(1) // protocol version
        var flags: UInt8 = keyFrame ? 0x01 : 0x00
        if packetIndex == packetCount - 1 { flags |= 0x02 }
        if retransmit { flags |= 0x04 }
        packet.append(flags)
        packet.appendBE(frameID)
        packet.appendBE(UInt16(packetIndex))
        packet.appendBE(UInt16(packetCount))
        packet.appendBE(UInt16(payload.count))
        packet.append(payload)
        return packet
    }

    /// On `sendQueue` only (paced mode).
    private func drainRetransmits(paced: Bool) {
        while true {
            lock.lock()
            guard !pendingRetransmit.isEmpty else {
                lock.unlock()
                return
            }
            let packet = pendingRetransmit.removeFirst()
            lock.unlock()
            if paced { _ = takeTokens(packet.count) }
            _ = sendCounted(packet)
        }
    }

    /// Send one packet and count it. Returns false on a send error.
    private func sendCounted(_ packet: Data) -> Bool {
        var dest = destination
        let result: ssize_t = packet.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return -1 }
            return withUnsafePointer(to: &dest) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                    Darwin.sendto(socketFD, base, packet.count, 0, sa,
                                  socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        let sentNanos = DispatchTime.now().uptimeNanoseconds
        lock.lock()
        defer { lock.unlock() }
        if result == packet.count {
            sentPackets &+= 1
            sentBytes &+= UInt64(packet.count)
            recordBurst(at: sentNanos, bytes: packet.count)
            return true
        }
        sendErrors &+= 1
        return false
    }

    /// Token bucket: refill at the pace rate up to the burst size, then wait
    /// until `bytes` are available. Returns the nanoseconds slept (0 = none).
    /// Sleep overshoot only adds tokens, so the next packets catch up.
    private func takeTokens(_ bytes: Int) -> UInt64 {
        let bytesPerNano = Double(paceMbpsLive) * 1_000_000 / 8 / 1_000_000_000
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
            + "\(pacing.summary)\(abrPaceMbps > 0 ? " pace_live=\(abrPaceMbps)Mbps" : "") "
            + String(format: "frame_send_avg=%.2fms frame_send_max=%.2fms ", sendAvgMS, Double(frameSendMaxNanos) / 1_000_000)
            + "pace_waits=\(paceWaits) pace_wait_total_ms=\(paceWaitNanos / 1_000_000) "
            + "send_queue_max=\(maxQueuedFrames) pace_overflow=\(queueOverflowFrames) "
            + "max_kb_per_1ms=\(maxBytesPer1ms / 1024) "
            + "nack=\(retransmitEnabled ? "on" : "off") nack_rx=\(nackRequests) nack_packets_resent=\(nackPacketsResent) "
            + "nack_bytes=\(nackBytes) nack_miss=\(nackMiss) nack_over_budget=\(nackOverBudget) "
            + "cache_frames=\(cache.entries.count) cache_bytes=\(cache.bytes) cache_resets=\(cache.resets)"
            + (statsSuffix.map { " " + $0() } ?? "")
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
