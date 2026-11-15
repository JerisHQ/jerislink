import Foundation
import CoreMedia
import CoreAudio
@preconcurrency import ScreenCaptureKit

/// MRA1: Mac -> viewer audio, one datagram per 5 ms of 48 kHz stereo PCM.
///   0..3   "MRA1"
///   4      version = 1
///   5      flags (0x01 = first packet after the capture (re)started)
///   6..9   sequence, big-endian UInt32 (one per packet, wraps)
///   10..17 host capture time of the first frame, microseconds, big-endian UInt64
///   18..19 frame count, big-endian UInt16 (240)
///   20...  frames x 2 channels x Int16 little-endian, interleaved L R
/// The packet goes out of the video UDP socket to the viewer's IP and the
/// port its MRM1 0x45 audio request named. Audio never touches the Mac's
/// output device: it is captured from the system mix by ScreenCaptureKit.
enum MRA1 {
    static let headerBytes = 20
    static let sampleRate = 48_000
    static let channels = 2
    static let framesPerPacket = 240  // 5 ms
    static let flagRestart: UInt8 = 0x01

    static func packet(seq: UInt32, captureMicros: UInt64, flags: UInt8, samples: ArraySlice<Int16>) -> Data {
        let frames = samples.count / channels
        var p = Data(capacity: headerBytes + samples.count * 2)
        p.append(contentsOf: [0x4d, 0x52, 0x41, 0x31, 1, flags])
        p.append(contentsOf: [UInt8(seq >> 24), UInt8((seq >> 16) & 0xff), UInt8((seq >> 8) & 0xff), UInt8(seq & 0xff)])
        for i in 0..<8 { p.append(UInt8((captureMicros >> UInt64(56 - 8 * i)) & 0xff)) }
        p.append(contentsOf: [UInt8(frames >> 8), UInt8(frames & 0xff)])
        for s in samples {
            let u = UInt16(bitPattern: s)
            p.append(UInt8(u & 0xff))
            p.append(UInt8(u >> 8))
        }
        return p
    }

    /// For tests: (seq, captureMicros, flags, samples) or nil when malformed.
    static func parse(_ b: [UInt8]) -> (seq: UInt32, micros: UInt64, flags: UInt8, samples: [Int16])? {
        guard b.count >= headerBytes, b[0] == 0x4d, b[1] == 0x52, b[2] == 0x41, b[3] == 0x31, b[4] == 1 else { return nil }
        let seq = UInt32(b[6]) << 24 | UInt32(b[7]) << 16 | UInt32(b[8]) << 8 | UInt32(b[9])
        var micros: UInt64 = 0
        for i in 10..<18 { micros = micros << 8 | UInt64(b[i]) }
        let frames = Int(b[18]) << 8 | Int(b[19])
        guard frames > 0, b.count == headerBytes + frames * channels * 2 else { return nil }
        var samples: [Int16] = []
        samples.reserveCapacity(frames * channels)
        var o = headerBytes
        while o < b.count {
            samples.append(Int16(bitPattern: UInt16(b[o]) | UInt16(b[o + 1]) << 8))
            o += 2
        }
        return (seq, micros, b[5], samples)
    }
}

/// Collects interleaved stereo Int16 frames and cuts them into 5 ms packets.
/// Pure, so the self-test can drive it.
struct AudioChunker {
    private(set) var pending: [Int16] = []
    private var pendingStartMicros: UInt64 = 0

    /// Appends `samples` (interleaved stereo) captured starting at `micros`
    /// and returns the complete 240-frame chunks with their start times.
    mutating func append(_ samples: [Int16], micros: UInt64) -> [(micros: UInt64, samples: ArraySlice<Int16>)] {
        if pending.isEmpty { pendingStartMicros = micros }
        pending.append(contentsOf: samples)
        let chunk = MRA1.framesPerPacket * MRA1.channels
        var out: [(UInt64, ArraySlice<Int16>)] = []
        var offset = 0
        while pending.count - offset >= chunk {
            let start = pendingStartMicros + UInt64(offset / MRA1.channels) * 1_000_000 / UInt64(MRA1.sampleRate)
            out.append((start, ArraySlice(pending[offset..<(offset + chunk)])))
            offset += chunk
        }
        if offset > 0 {
            pending.removeFirst(offset)
            pendingStartMicros += UInt64(offset / MRA1.channels) * 1_000_000 / UInt64(MRA1.sampleRate)
        }
        return out
    }

    mutating func reset() { pending.removeAll(keepingCapacity: true) }
}

/// RMS / peak of the captured signal over one log window, in dBFS.
struct AudioLevelMeter {
    private(set) var frames: UInt64 = 0
    private var sumSquares: Double = 0
    private var peak: Double = 0

    mutating func add(_ samples: [Int16]) {
        for s in samples {
            let v = Double(s) / 32768.0
            sumSquares += v * v
            peak = max(peak, abs(v))
        }
        frames += UInt64(samples.count / MRA1.channels)
    }

    static func dbfs(_ linear: Double) -> Double { linear > 0 ? max(-120, 20 * log10(linear)) : -120 }

    /// (rms dBFS, peak dBFS, frames) for the window, then starts a new one.
    mutating func take() -> (rms: Double, peak: Double, frames: UInt64) {
        let n = Double(frames) * Double(MRA1.channels)
        let rms = n > 0 ? (sumSquares / n).squareRoot() : 0
        let r = (Self.dbfs(rms), Self.dbfs(peak), frames)
        frames = 0; sumSquares = 0; peak = 0
        return r
    }
}

/// Converts one ScreenCaptureKit audio buffer list to interleaved stereo
/// Int16. Handles Float32 / Int16, interleaved or not, mono or stereo.
enum AudioConvert {
    static func toStereoInt16(_ abl: UnsafeMutableAudioBufferListPointer, asbd: AudioStreamBasicDescription) -> [Int16]? {
        let isFloat = asbd.mFormatFlags & kAudioFormatFlagIsFloat != 0
        let nonInterleaved = asbd.mFormatFlags & kAudioFormatFlagIsNonInterleaved != 0
        let bits = Int(asbd.mBitsPerChannel)
        let chans = Int(asbd.mChannelsPerFrame)
        guard chans >= 1, (isFloat && bits == 32) || (!isFloat && bits == 16) else { return nil }

        func sample(_ buffer: AudioBuffer, _ index: Int) -> Int16 {
            guard let data = buffer.mData else { return 0 }
            if isFloat {
                let v = data.assumingMemoryBound(to: Float.self)[index]
                let c = max(-1, min(1, v.isFinite ? v : 0))
                return Int16((c * 32767).rounded())
            }
            return data.assumingMemoryBound(to: Int16.self)[index]
        }

        var frames: Int
        if nonInterleaved {
            guard abl.count >= 1 else { return nil }
            frames = Int(abl[0].mDataByteSize) / (bits / 8)
            for b in abl { frames = min(frames, Int(b.mDataByteSize) / (bits / 8)) }
        } else {
            guard abl.count >= 1 else { return nil }
            frames = Int(abl[0].mDataByteSize) / (bits / 8 * chans)
        }
        var out = [Int16](repeating: 0, count: frames * 2)
        for f in 0..<frames {
            let l: Int16, r: Int16
            if nonInterleaved {
                l = sample(abl[0], f)
                r = abl.count > 1 ? sample(abl[1], f) : l
            } else {
                l = sample(abl[0], f * chans)
                r = chans > 1 ? sample(abl[0], f * chans + 1) : l
            }
            out[2 * f] = l
            out[2 * f + 1] = r
        }
        return out
    }
}

/// Audio-only ScreenCaptureKit stream, separate from the video stream, that
/// runs only while a viewer asks for audio (MRM1 0x45 at least every 10 s;
/// the viewer sends one per second, the slack covers a viewer main loop held
/// up by a long window drag)./// It never selects or changes a Mac output device.
final class AudioStreamer: NSObject, SCStreamOutput, SCStreamDelegate, @unchecked Sendable {
    static let requestTimeoutNs: UInt64 = 10_000_000_000
    static let logIntervalNs: UInt64 = 5_000_000_000

    private let send: (Data, UInt16) -> Bool
    private let state = DispatchQueue(label: "JerisLink.AudioState", qos: .userInitiated)
    private let sampleQueue = DispatchQueue(label: "JerisLink.AudioCapture", qos: .userInteractive)
    private let lock = NSLock()

    // `state` queue only.
    private var stream: SCStream?
    private var starting = false
    private var requestedUntilNs: UInt64 = 0
    private var lastStartAttemptNs: UInt64 = 0
    private var timer: DispatchSourceTimer?
    private var lastLogNs: UInt64 = 0

    // `lock`.
    private var port: UInt16 = 0
    private var chunker = AudioChunker()
    private var meter = AudioLevelMeter()
    private var seq: UInt32 = 0
    private var nextFlags: UInt8 = MRA1.flagRestart
    private var buffers: UInt64 = 0
    private var packetsSent: UInt64 = 0
    private var sendErrors: UInt64 = 0
    private var formatErrors: UInt64 = 0
    private var formatLogged = false

    private(set) var requests: UInt64 = 0
    private var starts: UInt64 = 0
    private var stops: UInt64 = 0
    private var startFailures: UInt64 = 0

    init(send: @escaping (Data, UInt16) -> Bool) {
        self.send = send
        super.init()
    }

    static func log(_ message: String) {
        print("audio: \(message)")
        fflush(stdout)
    }

    /// MRM1 0x45 from the allowed viewer. enable=false stops at once.
    func noteRequest(enable: Bool, port: UInt16) {
        state.async { [self] in
            requests &+= 1
            if !enable || port == 0 {
                requestedUntilNs = 0
                stopStream()
                return
            }
            lock.lock()
            let portChanged = self.port != port
            self.port = port
            lock.unlock()
            if portChanged { Self.log("viewer audio port=\(port)") }
            requestedUntilNs = DispatchTime.now().uptimeNanoseconds + Self.requestTimeoutNs
            ensureTimer()
            startIfNeeded()
        }
    }

    func shutdown() {
        state.sync { [self] in
            requestedUntilNs = 0
            timer?.cancel(); timer = nil
            stopStream()
        }
    }

    private func ensureTimer() {
        guard timer == nil else { return }
        let t = DispatchSource.makeTimerSource(queue: state)
        t.schedule(deadline: .now() + 1, repeating: 1)
        t.setEventHandler { [weak self] in self?.tick() }
        t.resume()
        timer = t
    }

    private func tick() {
        let now = DispatchTime.now().uptimeNanoseconds
        if stream != nil || starting {
            if now > requestedUntilNs {
                Self.log("viewer stopped asking for audio; stopping capture")
                stopStream()
            } else if now - lastLogNs >= Self.logIntervalNs {
                lastLogNs = now
                logLevels()
            }
        } else if now <= requestedUntilNs {
            startIfNeeded()  // retry after a failed start or a stream error
        } else {
            timer?.cancel(); timer = nil
        }
    }

    private func logLevels() {
        lock.lock()
        let level = meter.take()
        let line = String(format: "rms_dbfs=%.1f peak_dbfs=%.1f frames=%llu buffers=%llu packets_sent=%llu send_errors=%llu format_errors=%llu port=%u",
                          level.rms, level.peak, level.frames, buffers, packetsSent, sendErrors, formatErrors, UInt32(port))
        lock.unlock()
        Self.log(line + (level.frames == 0 ? " (no audio buffers from ScreenCaptureKit in this window)" : ""))
    }

    private func startIfNeeded() {
        guard stream == nil, !starting else { return }
        let now = DispatchTime.now().uptimeNanoseconds
        if lastStartAttemptNs != 0 && now - lastStartAttemptNs < 2_000_000_000 { return }
        lastStartAttemptNs = now
        starting = true
        lock.lock()
        chunker.reset()
        nextFlags = MRA1.flagRestart
        lock.unlock()
        Task { [self] in
            do {
                let content = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: true)
                guard let display = content.displays.first else {
                    throw NSError(domain: "JerisLink.Audio", code: 1,
                                  userInfo: [NSLocalizedDescriptionKey: "no display for the audio content filter"])
                }
                let filter = SCContentFilter(display: display, excludingApplications: [], exceptingWindows: [])
                let config = SCStreamConfiguration()
                config.capturesAudio = true
                config.excludesCurrentProcessAudio = true
                config.sampleRate = MRA1.sampleRate
                config.channelCount = MRA1.channels
                // The video side of this stream is a 2x2 frame once a second;
                // the real video comes from the separate video stream.
                config.width = 2
                config.height = 2
                config.minimumFrameInterval = CMTime(value: 1, timescale: 1)
                config.showsCursor = false
                let s = SCStream(filter: filter, configuration: config, delegate: self)
                try s.addStreamOutput(self, type: .audio, sampleHandlerQueue: sampleQueue)
                try s.addStreamOutput(self, type: .screen, sampleHandlerQueue: sampleQueue)
                try await s.startCapture()
                state.async { [self] in
                    starting = false
                    starts &+= 1
                    if DispatchTime.now().uptimeNanoseconds > requestedUntilNs {
                        Task { try? await s.stopCapture() }
                        return
                    }
                    stream = s
                    lastLogNs = DispatchTime.now().uptimeNanoseconds
                    Self.log("capture started (ScreenCaptureKit system audio, 48 kHz stereo, own process excluded; output device untouched)")
                }
            } catch {
                state.async { [self] in
                    starting = false
                    startFailures &+= 1
                    Self.log("capture start failed: \(error.localizedDescription)")
                }
            }
        }
    }

    private func stopStream() {
        guard let s = stream else { return }
        stream = nil
        stops &+= 1
        logLevels()
        Task { try? await s.stopCapture() }
        Self.log("capture stopped \(statsLine())")
    }

    func statsLine() -> String {
        lock.lock(); defer { lock.unlock() }
        return "audio_requests=\(requests) audio_starts=\(starts) audio_stops=\(stops) audio_start_failures=\(startFailures) audio_packets_sent=\(packetsSent) audio_send_errors=\(sendErrors) audio_format_errors=\(formatErrors)"
    }

    // MARK: SCStreamDelegate

    func stream(_ stream: SCStream, didStopWithError error: Error) {
        state.async { [self] in
            guard self.stream === stream else { return }
            self.stream = nil
            lastStartAttemptNs = 0
            Self.log("capture stopped by ScreenCaptureKit: \(error.localizedDescription); restarting while the viewer asks")
        }
    }

    // MARK: SCStreamOutput

    func stream(_ stream: SCStream, didOutputSampleBuffer sampleBuffer: CMSampleBuffer, of type: SCStreamOutputType) {
        guard type == .audio, CMSampleBufferIsValid(sampleBuffer),
              let fd = CMSampleBufferGetFormatDescription(sampleBuffer),
              let asbdPtr = CMAudioFormatDescriptionGetStreamBasicDescription(fd) else { return }
        let asbd = asbdPtr.pointee
        let pts = CMSampleBufferGetPresentationTimeStamp(sampleBuffer)
        let micros = pts.isValid ? UInt64(max(0, CMTimeGetSeconds(pts)) * 1_000_000) : UInt64(DispatchTime.now().uptimeNanoseconds / 1000)

        var converted: [Int16]?
        if Int(asbd.mSampleRate) == MRA1.sampleRate {
            try? sampleBuffer.withAudioBufferList { abl, _ in
                converted = AudioConvert.toStereoInt16(abl, asbd: asbd)
            }
        }
        lock.lock()
        buffers &+= 1
        guard let samples = converted else {
            formatErrors &+= 1
            let first = !formatLogged
            formatLogged = true
            lock.unlock()
            if first {
                Self.log("unsupported audio format rate=\(asbd.mSampleRate) bits=\(asbd.mBitsPerChannel) channels=\(asbd.mChannelsPerFrame) flags=\(asbd.mFormatFlags)")
            }
            return
        }
        meter.add(samples)
        let chunks = chunker.append(samples, micros: micros)
        let port = self.port
        var packets: [Data] = []
        for c in chunks {
            seq &+= 1
            packets.append(MRA1.packet(seq: seq, captureMicros: c.micros, flags: nextFlags, samples: c.samples))
            nextFlags = 0
        }
        lock.unlock()
        var sent: UInt64 = 0, errors: UInt64 = 0
        for p in packets {
            if send(p, port) { sent &+= 1 } else { errors &+= 1 }
        }
        if !packets.isEmpty {
            lock.lock(); packetsSent &+= sent; sendErrors &+= errors; lock.unlock()
        }
    }
}

/// `JerisLinkHost --self-test` part for audio: MRA1 layout, 5 ms chunking,
/// Float32 conversion, the level meter and the MRM1 0x45 parser.
enum AudioSelfTest {
    static func run() -> Int32 {
        var failures = 0
        func expect(_ ok: Bool, _ name: String) {
            print("\(ok ? "PASS" : "FAIL") \(name)")
            if !ok { failures += 1 }
        }

        let samples: [Int16] = (0..<480).map { Int16(truncatingIfNeeded: $0 * 61 - 14000) }
        let p = MRA1.packet(seq: 0xfffffffe, captureMicros: 0x0102030405060708, flags: MRA1.flagRestart, samples: samples[...])
        expect(p.count == 20 + 960, "mra1: 5 ms packet is 980 bytes")
        expect(Array(p.prefix(6)) == [0x4d, 0x52, 0x41, 0x31, 1, 1], "mra1: magic, version, flags")
        let parsed = MRA1.parse(Array(p))
        expect(parsed?.seq == 0xfffffffe && parsed?.micros == 0x0102030405060708 && parsed?.samples == samples,
               "mra1: round trip")
        expect(Array(p[18..<22]) == [0, 240, UInt8(UInt16(bitPattern: samples[0]) & 0xff), UInt8(UInt16(bitPattern: samples[0]) >> 8)],
               "mra1: frame count big-endian, samples little-endian")
        var bad = Array(p); bad.removeLast()
        expect(MRA1.parse(bad) == nil, "mra1: length must match frame count")

        var c = AudioChunker()
        let a = c.append([Int16](repeating: 1, count: 2 * 100), micros: 1_000_000)
        expect(a.isEmpty && c.pending.count == 200, "chunker: holds a partial packet")
        let b = c.append([Int16](repeating: 2, count: 2 * 400), micros: 1_002_083)
        expect(b.count == 2 && b[0].micros == 1_000_000 && b[1].micros == 1_005_000 && c.pending.count == 2 * 20,
               "chunker: 500 frames -> two 240-frame packets, 20 left, 5 ms apart")
        expect(b[0].samples.count == 480 && b[0].samples.first == 1 && b[0].samples.last == 2, "chunker: keeps frame order")

        // Float32 non-interleaved stereo, as ScreenCaptureKit delivers it.
        var left: [Float] = [0, 0.5, -1, 2]
        var right: [Float] = [1, -0.5, 0.25, -2]
        var asbd = AudioStreamBasicDescription(mSampleRate: 48000, mFormatID: kAudioFormatLinearPCM,
                                               mFormatFlags: kAudioFormatFlagIsFloat | kAudioFormatFlagIsNonInterleaved | kAudioFormatFlagIsPacked,
                                               mBytesPerPacket: 4, mFramesPerPacket: 1, mBytesPerFrame: 4,
                                               mChannelsPerFrame: 2, mBitsPerChannel: 32, mReserved: 0)
        let abl = AudioBufferList.allocate(maximumBuffers: 2)
        defer { free(abl.unsafeMutablePointer) }
        let out = left.withUnsafeMutableBytes { l in
            right.withUnsafeMutableBytes { r -> [Int16]? in
                abl[0] = AudioBuffer(mNumberChannels: 1, mDataByteSize: UInt32(l.count), mData: l.baseAddress)
                abl[1] = AudioBuffer(mNumberChannels: 1, mDataByteSize: UInt32(r.count), mData: r.baseAddress)
                return AudioConvert.toStereoInt16(abl, asbd: asbd)
            }
        }
        expect(out == [0, 32767, 16384, -16384, -32767, 8192, 32767, -32767],
               "convert: float32 planar -> s16 interleaved, clipped")
        asbd.mBitsPerChannel = 24
        expect(AudioConvert.toStereoInt16(abl, asbd: asbd) == nil, "convert: unsupported format refused")

        var m = AudioLevelMeter()
        m.add([Int16](repeating: 16384, count: 480))
        let lv = m.take()
        expect(abs(lv.rms - (-6.02)) < 0.1 && abs(lv.peak - (-6.02)) < 0.1 && lv.frames == 240, "meter: half scale = -6 dBFS")
        expect(m.take().rms == -120, "meter: silence after reset is -120 dBFS")

        expect(MouseMoveUDPServer.parseAudioRequest([0x4d, 0x52, 0x4d, 0x31, 1, 0x45, 0, 0, 0, 9, 1, 0x95, 0x02], length: 13)?.port == 38146,
               "mrm1 0x45: enable + port parsed")
        expect(MouseMoveUDPServer.parseAudioRequest([0x4d, 0x52, 0x4d, 0x31, 1, 0x45, 0, 0, 0, 9, 1, 0x95], length: 12) == nil,
               "mrm1 0x45: wrong length refused")
        expect(MouseMoveUDPServer.parseAudioRequest([0x4d, 0x52, 0x4d, 0x31, 1, 0x45, 0, 0, 0, 9, 0, 0, 0], length: 13)?.enable == false,
               "mrm1 0x45: stop request")
        return failures == 0 ? 0 : 1
    }
}
