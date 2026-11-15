import Foundation
import CoreMedia
import CoreAudio
@preconcurrency import ScreenCaptureKit
import COpus
import COpusShim

/// MRA1: Mac -> viewer audio, one datagram per packet of 48 kHz stereo.
///   0..3   "MRA1"
///   4      version: 1 = PCM, 2 = Opus
///   5      flags (0x01 = first packet after the capture (re)started)
///   6..9   sequence, big-endian UInt32 (one per packet, wraps)
///   10..17 host capture time of the first frame, microseconds, big-endian UInt64
///   18..19 frame count, big-endian UInt16 (v1: 240 = 5 ms, v2: 480 = 10 ms)
///   20...  v1: frames x 2 channels x Int16 little-endian, interleaved L R
///          v2: one Opus packet (48 kHz stereo, decodes to `frame count` frames)
/// The host sends v2 only to a viewer whose MRM1 0x45 request sets flag 0x02
/// ("I decode Opus"); every other viewer gets v1 as before. The packet goes
/// out of the video UDP socket to the viewer's IP and the port its MRM1 0x45
/// audio request named. Audio never touches the Mac's output device: it is
/// captured from the system mix by ScreenCaptureKit.
enum MRA1 {
    static let headerBytes = 20
    static let sampleRate = 48_000
    static let channels = 2
    static let framesPerPacket = 240      // v1 PCM: 5 ms
    static let opusFramesPerPacket = 480  // v2 Opus: 10 ms
    static let versionPCM: UInt8 = 1
    static let versionOpus: UInt8 = 2
    static let flagRestart: UInt8 = 0x01
    /// Opus: 128 kbps target (constrained VBR), in-band FEC flag on.
    static let opusBitrate = 128_000
    /// What the video budget gives up while Opus audio streams: the Opus
    /// bitrate plus MRA1 + UDP/IPv4 headers at 100 packets/s
    /// (128 + 48 B x 8 x 100 / 1000 = 166.4 kbps), rounded up.
    static let opusReserveKbps = 170
    static let maxOpusPayload = 1275

    static func header(version: UInt8, seq: UInt32, captureMicros: UInt64, flags: UInt8, frames: Int) -> Data {
        var p = Data(capacity: headerBytes)
        p.append(contentsOf: [0x4d, 0x52, 0x41, 0x31, version, flags])
        p.append(contentsOf: [UInt8(seq >> 24), UInt8((seq >> 16) & 0xff), UInt8((seq >> 8) & 0xff), UInt8(seq & 0xff)])
        for i in 0..<8 { p.append(UInt8((captureMicros >> UInt64(56 - 8 * i)) & 0xff)) }
        p.append(contentsOf: [UInt8(frames >> 8), UInt8(frames & 0xff)])
        return p
    }

    static func packet(seq: UInt32, captureMicros: UInt64, flags: UInt8, samples: ArraySlice<Int16>) -> Data {
        var p = header(version: versionPCM, seq: seq, captureMicros: captureMicros, flags: flags, frames: samples.count / channels)
        p.reserveCapacity(headerBytes + samples.count * 2)
        for s in samples {
            let u = UInt16(bitPattern: s)
            p.append(UInt8(u & 0xff))
            p.append(UInt8(u >> 8))
        }
        return p
    }

    static func opusPacket(seq: UInt32, captureMicros: UInt64, flags: UInt8, frames: Int, payload: [UInt8]) -> Data {
        var p = header(version: versionOpus, seq: seq, captureMicros: captureMicros, flags: flags, frames: frames)
        p.append(contentsOf: payload)
        return p
    }

    /// For tests: (seq, captureMicros, flags, samples) or nil when malformed.
    static func parse(_ b: [UInt8]) -> (seq: UInt32, micros: UInt64, flags: UInt8, samples: [Int16])? {
        guard b.count >= headerBytes, b[0] == 0x4d, b[1] == 0x52, b[2] == 0x41, b[3] == 0x31, b[4] == versionPCM else { return nil }
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

    /// For tests: v2 (seq, frames, Opus payload) or nil when malformed.
    static func parseOpus(_ b: [UInt8]) -> (seq: UInt32, frames: Int, payload: [UInt8])? {
        guard b.count > headerBytes, b.count <= headerBytes + maxOpusPayload,
              b[0] == 0x4d, b[1] == 0x52, b[2] == 0x41, b[3] == 0x31, b[4] == versionOpus else { return nil }
        let seq = UInt32(b[6]) << 24 | UInt32(b[7]) << 16 | UInt32(b[8]) << 8 | UInt32(b[9])
        let frames = Int(b[18]) << 8 | Int(b[19])
        guard frames > 0 else { return nil }
        return (seq, frames, Array(b[headerBytes...]))
    }
}

/// libopus encoder for MRA1 v2: 48 kHz stereo, 10 ms frames, 128 kbps,
/// OPUS_APPLICATION_AUDIO, in-band FEC flag on. Not thread-safe; the
/// streamer uses it under its lock.
final class OpusAudioEncoder {
    private let enc: OpaquePointer
    let lookaheadFrames: Int
    private var out = [UInt8](repeating: 0, count: MRA1.maxOpusPayload)

    /// packetLossPercent 0: libopus stays in CELT-only mode at 128 kbps
    /// stereo, where it codes no FEC (see the PR notes); PLC on the viewer
    /// covers loss.
    init?(bitrate: Int = MRA1.opusBitrate, inbandFEC: Bool = true, packetLossPercent: Int = 0) {
        var err: Int32 = 0
        guard let e = jl_opus_encoder_create(Int32(bitrate), inbandFEC ? 1 : 0, Int32(packetLossPercent), &err) else { return nil }
        enc = e
        lookaheadFrames = Int(jl_opus_encoder_lookahead(e))
    }

    deinit { opus_encoder_destroy(enc) }

    /// `samples`: exactly 480 interleaved stereo frames. nil on encoder error.
    func encode(_ samples: ArraySlice<Int16>) -> [UInt8]? {
        guard samples.count == MRA1.opusFramesPerPacket * MRA1.channels else { return nil }
        let n = samples.withContiguousStorageIfAvailable { pcm in
            out.withUnsafeMutableBufferPointer { o in
                opus_encode(enc, pcm.baseAddress, Int32(MRA1.opusFramesPerPacket), o.baseAddress, Int32(o.count))
            }
        } ?? Array(samples).withUnsafeBufferPointer { pcm in
            out.withUnsafeMutableBufferPointer { o in
                opus_encode(enc, pcm.baseAddress, Int32(MRA1.opusFramesPerPacket), o.baseAddress, Int32(o.count))
            }
        }
        guard n > 0 else { return nil }
        return Array(out[0..<Int(n)])
    }
}

/// Collects interleaved stereo Int16 frames and cuts them into fixed-size
/// packets (240 frames for PCM, 480 for Opus). Pure, so the self-test can
/// drive it.
struct AudioChunker {
    let framesPerPacket: Int
    private(set) var pending: [Int16] = []
    private var pendingStartMicros: UInt64 = 0

    init(framesPerPacket: Int = MRA1.framesPerPacket) {
        self.framesPerPacket = framesPerPacket
    }

    /// Appends `samples` (interleaved stereo) captured starting at `micros`
    /// and returns the complete chunks with their start times.
    mutating func append(_ samples: [Int16], micros: UInt64) -> [(micros: UInt64, samples: ArraySlice<Int16>)] {
        if pending.isEmpty { pendingStartMicros = micros }
        pending.append(contentsOf: samples)
        let chunk = framesPerPacket * MRA1.channels
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
/// up by a long window drag). It never selects or changes a Mac output device.
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
    private var opus = false
    private var encoder: OpusAudioEncoder?
    private var chunker = AudioChunker()
    private var meter = AudioLevelMeter()
    private var seq: UInt32 = 0
    private var nextFlags: UInt8 = MRA1.flagRestart
    private var buffers: UInt64 = 0
    private var packetsSent: UInt64 = 0
    private var sendErrors: UInt64 = 0
    private var formatErrors: UInt64 = 0
    private var encodeErrors: UInt64 = 0
    private var payloadBytes: UInt64 = 0
    private var windowPayloadBytes: UInt64 = 0
    private var windowStartNs: UInt64 = DispatchTime.now().uptimeNanoseconds
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
    /// opus: the viewer decodes MRA1 v2 (request flag 0x02).
    func noteRequest(enable: Bool, port: UInt16, opus: Bool = false) {
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
            let codecChanged = self.opus != opus || (opus && encoder == nil)
            var encoderFailed = false
            if codecChanged {
                // New packet size: drop the partial chunk and tell the viewer
                // to resynchronise.
                self.opus = opus
                encoder = nil
                if opus {
                    encoder = OpusAudioEncoder()
                    encoderFailed = encoder == nil
                    if encoderFailed { self.opus = false }
                }
                chunker = AudioChunker(framesPerPacket: self.opus ? MRA1.opusFramesPerPacket : MRA1.framesPerPacket)
                nextFlags = MRA1.flagRestart
            }
            let codec = self.codecSummaryLocked()
            lock.unlock()
            if portChanged { Self.log("viewer audio port=\(port)") }
            if encoderFailed { Self.log("opus encoder init failed; sending PCM") }
            if codecChanged { Self.log("viewer audio codec=\(codec)") }
            requestedUntilNs = DispatchTime.now().uptimeNanoseconds + Self.requestTimeoutNs
            ensureTimer()
            startIfNeeded()
        }
    }

    /// `lock` held.
    private func codecSummaryLocked() -> String {
        if opus, let e = encoder {
            return "opus bitrate_target=\(MRA1.opusBitrate / 1000)kbps frame_ms=10 fec=on lookahead_ms=\(String(format: "%.1f", Double(e.lookaheadFrames) / 48))"
        }
        return "pcm s16 frame_ms=5"
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
        let now = DispatchTime.now().uptimeNanoseconds
        lock.lock()
        let level = meter.take()
        let seconds = Double(now &- windowStartNs) / 1e9
        let kbps = seconds > 0 ? Double(windowPayloadBytes) * 8 / seconds / 1000 : 0
        windowPayloadBytes = 0
        windowStartNs = now
        let line = String(format: "rms_dbfs=%.1f peak_dbfs=%.1f frames=%llu buffers=%llu packets_sent=%llu send_errors=%llu format_errors=%llu encode_errors=%llu codec=%@ payload_kbps=%.1f port=%u",
                          level.rms, level.peak, level.frames, buffers, packetsSent, sendErrors, formatErrors, encodeErrors,
                          opus ? "opus" : "pcm", kbps, UInt32(port))
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
        return "audio_requests=\(requests) audio_starts=\(starts) audio_stops=\(stops) audio_start_failures=\(startFailures) audio_packets_sent=\(packetsSent) audio_send_errors=\(sendErrors) audio_format_errors=\(formatErrors) audio_codec=\(opus ? "opus" : "pcm") audio_encode_errors=\(encodeErrors) audio_payload_bytes=\(payloadBytes)"
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
            let p: Data
            if opus, let encoder {
                // Opus is about 0.1 ms per 10 ms frame here; fine under the lock.
                guard let payload = encoder.encode(c.samples) else {
                    encodeErrors &+= 1
                    continue  // the viewer conceals the gap (PLC)
                }
                seq &+= 1
                p = MRA1.opusPacket(seq: seq, captureMicros: c.micros, flags: nextFlags,
                                    frames: MRA1.opusFramesPerPacket, payload: payload)
                payloadBytes &+= UInt64(payload.count)
                windowPayloadBytes &+= UInt64(payload.count)
            } else {
                seq &+= 1
                p = MRA1.packet(seq: seq, captureMicros: c.micros, flags: nextFlags, samples: c.samples)
                payloadBytes &+= UInt64(c.samples.count * 2)
                windowPayloadBytes &+= UInt64(c.samples.count * 2)
            }
            packets.append(p)
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

/// `JerisLinkHost --self-test` part for audio: MRA1 v1/v2 layout, chunking,
/// Float32 conversion, the level meter, the Opus round trip and the MRM1
/// 0x45 parser.
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
        var c10 = AudioChunker(framesPerPacket: MRA1.opusFramesPerPacket)
        let d = c10.append([Int16](repeating: 3, count: 2 * 960), micros: 2_000_000)
        expect(d.count == 2 && d[1].micros == 2_010_000 && d[0].samples.count == 960 && c10.pending.isEmpty,
               "chunker: one 20 ms ScreenCaptureKit buffer -> two 10 ms Opus frames")

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

        opusRoundTrip(expect)

        expect(MouseMoveUDPServer.parseAudioRequest([0x4d, 0x52, 0x4d, 0x31, 1, 0x45, 0, 0, 0, 9, 1, 0x95, 0x02], length: 13).map { $0.port == 38146 && !$0.opus } == true,
               "mrm1 0x45: enable + port parsed, A1 viewer gets PCM")
        expect(MouseMoveUDPServer.parseAudioRequest([0x4d, 0x52, 0x4d, 0x31, 1, 0x45, 0, 0, 0, 9, 3, 0x95, 0x02], length: 13).map { $0.enable && $0.opus } == true,
               "mrm1 0x45: flag 0x02 asks for Opus")
        expect(MouseMoveUDPServer.parseAudioRequest([0x4d, 0x52, 0x4d, 0x31, 1, 0x45, 0, 0, 0, 9, 1, 0x95], length: 12) == nil,
               "mrm1 0x45: wrong length refused")
        expect(MouseMoveUDPServer.parseAudioRequest([0x4d, 0x52, 0x4d, 0x31, 1, 0x45, 0, 0, 0, 9, 0, 0, 0], length: 13)?.enable == false,
               "mrm1 0x45: stop request")
        return failures == 0 ? 0 : 1
    }

    /// Encodes 1 s of a two-tone stereo signal, checks the MRA1 v2 layout and
    /// the bitrate, decodes it and compares with the input (aligned by the
    /// encoder lookahead).
    private static func opusRoundTrip(_ expect: (Bool, String) -> Void) {
        guard let enc = OpusAudioEncoder() else {
            expect(false, "opus: encoder init")
            return
        }
        expect(enc.lookaheadFrames > 0 && enc.lookaheadFrames <= 48 * 7, "opus: lookahead \(enc.lookaheadFrames) frames <= 7 ms")
        var err: Int32 = 0
        guard let dec = opus_decoder_create(48000, 2, &err) else {
            expect(false, "opus: decoder init")
            return
        }
        defer { opus_decoder_destroy(dec) }
        let frames = MRA1.opusFramesPerPacket
        let packets = 100
        var input = [Int16](repeating: 0, count: frames * 2 * packets)
        for i in 0..<(frames * packets) {
            let t = Double(i) / 48000
            input[2 * i] = Int16(9000 * sin(2 * .pi * 440 * t) + 3000 * sin(2 * .pi * 3000 * t))
            input[2 * i + 1] = Int16(9000 * sin(2 * .pi * 660 * t))
        }
        var decoded: [Int16] = []
        var bytes = 0
        var layoutOK = true
        var pcm = [Int16](repeating: 0, count: frames * 2)
        for k in 0..<packets {
            guard let payload = enc.encode(input[(k * frames * 2)..<((k + 1) * frames * 2)]) else {
                expect(false, "opus: encode packet \(k)")
                return
            }
            bytes += payload.count
            let pkt = MRA1.opusPacket(seq: UInt32(k), captureMicros: UInt64(k) * 10_000, flags: k == 0 ? MRA1.flagRestart : 0,
                                      frames: frames, payload: payload)
            guard let back = MRA1.parseOpus(Array(pkt)), back.seq == UInt32(k), back.frames == frames, back.payload == payload,
                  pkt[4] == MRA1.versionOpus, MRA1.parse(Array(pkt)) == nil else {
                layoutOK = false
                continue
            }
            let n = back.payload.withUnsafeBufferPointer { p in
                pcm.withUnsafeMutableBufferPointer { o in
                    opus_decode(dec, p.baseAddress, Int32(p.count), o.baseAddress, Int32(frames), 0)
                }
            }
            if n != Int32(frames) { layoutOK = false; continue }
            decoded.append(contentsOf: pcm)
        }
        expect(layoutOK, "opus: MRA1 v2 layout, v1 parser refuses it, 480 frames per packet")
        let kbps = Double(bytes) * 8 / 1.0 / 1000
        expect(kbps > 100 && kbps < 140, "opus: \(String(format: "%.1f", kbps)) kbps for a 128 kbps target")
        // SNR over the second half, decoded output delayed by the lookahead.
        let lag = enc.lookaheadFrames
        var sig = 0.0, noise = 0.0
        for i in (frames * packets / 2)..<(frames * packets - lag) {
            for ch in 0..<2 {
                let x = Double(input[2 * i + ch]), y = Double(decoded[2 * (i + lag) + ch])
                sig += x * x
                noise += (x - y) * (x - y)
            }
        }
        let snr = noise > 0 ? 10 * log10(sig / noise) : 99
        expect(snr > 20, "opus: round trip SNR \(String(format: "%.1f", snr)) dB > 20 dB")
    }
}
