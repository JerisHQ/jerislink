import Foundation
import CoreMedia
import CoreVideo
import VideoToolbox
import Darwin

private final class HEVCFrameContext {
    let frameID: UInt64
    let submitNanos: UInt64
    let forcedKeyframeRequested: Bool

    init(frameID: UInt64, submitNanos: UInt64, forcedKeyframeRequested: Bool) {
        self.frameID = frameID
        self.submitNanos = submitNanos
        self.forcedKeyframeRequested = forcedKeyframeRequested
    }
}

final class HEVCEncoder: FrameEncoder {
    private var session: VTCompressionSession?
    private let writer: HEVCAnnexBWriter
    private let fps: Int32
    private let udpSender: UDPFrameSender?
    private var frameID: UInt64 = 0
    private var encodedFrames: UInt64 = 0
    private var latencySumMS: Double = 0
    private var latencyMaxMS: Double = 0
    private var callbackLatencySumMS: Double = 0
    private var callbackLatencyMaxMS: Double = 0
    private var sendLatencySumMS: Double = 0
    private var sendLatencyMaxMS: Double = 0
    private let statsLock = NSLock()
    private let keyframeRequestLock = NSLock()
    private var forceKeyframePending = false
    private var forceKeyframeRequests: UInt64 = 0
    private var forceKeyframesEmitted: UInt64 = 0

    init(width: Int32, height: Int32, fps: Int32, bitrate: Int,
         keyframeInterval: Int32? = nil,
         outputURL: URL, udpSender: UDPFrameSender? = nil) throws {
        self.fps = fps
        self.udpSender = udpSender
        self.writer = try HEVCAnnexBWriter(url: outputURL)

        var createdSession: VTCompressionSession?
        let encoderSpecification = [
            kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder: true as CFBoolean,
            kVTVideoEncoderSpecification_EnableLowLatencyRateControl: true as CFBoolean
        ] as CFDictionary

        let status = VTCompressionSessionCreate(
            allocator: kCFAllocatorDefault,
            width: width,
            height: height,
            codecType: kCMVideoCodecType_HEVC,
            encoderSpecification: encoderSpecification,
            imageBufferAttributes: nil,
            compressedDataAllocator: nil,
            outputCallback: { outputCallbackRefCon, sourceFrameRefCon, status, infoFlags, sampleBuffer in
                guard let outputCallbackRefCon else { return }
                let encoder = Unmanaged<HEVCEncoder>
                    .fromOpaque(outputCallbackRefCon)
                    .takeUnretainedValue()
                encoder.handleEncodedFrame(
                    sourceFrameRefCon: sourceFrameRefCon,
                    status: status,
                    infoFlags: infoFlags,
                    sampleBuffer: sampleBuffer
                )
            },
            refcon: Unmanaged.passUnretained(self).toOpaque(),
            compressionSessionOut: &createdSession
        )

        guard status == noErr, let createdSession else {
            throw NSError(
                domain: "JerisLink.HEVCEncoder",
                code: Int(status),
                userInfo: [NSLocalizedDescriptionKey: "HEVC VTCompressionSessionCreate failed: \(status)"]
            )
        }

        self.session = createdSession

        try setProperty(kVTCompressionPropertyKey_RealTime, kCFBooleanTrue)
        try setProperty(kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanFalse)
        try setProperty(kVTCompressionPropertyKey_ExpectedFrameRate, fps as CFNumber)
        try setProperty(kVTCompressionPropertyKey_AverageBitRate, bitrate as CFNumber)
        let effectiveKeyframeInterval = max(1, keyframeInterval ?? fps)
        try setProperty(kVTCompressionPropertyKey_MaxKeyFrameInterval,
                        effectiveKeyframeInterval as CFNumber)
        print("encoder.keyframe_interval=\(effectiveKeyframeInterval)")
        try setProperty(kVTCompressionPropertyKey_ProfileLevel, kVTProfileLevel_HEVC_Main_AutoLevel)

        let prepareStatus = VTCompressionSessionPrepareToEncodeFrames(createdSession)
        guard prepareStatus == noErr else {
            throw NSError(
                domain: "JerisLink.HEVCEncoder",
                code: Int(prepareStatus),
                userInfo: [NSLocalizedDescriptionKey: "HEVC VTCompressionSessionPrepareToEncodeFrames failed: \(prepareStatus)"]
            )
        }

        print("encoder.codec=hevc")
        print("encoder.hardware=required")
    }

    deinit {
        finish()
    }

    func requestKeyframe() {
        keyframeRequestLock.lock()
        forceKeyframePending = true
        forceKeyframeRequests &+= 1
        let total = forceKeyframeRequests
        keyframeRequestLock.unlock()
        print("encoder.hevc_force_keyframe_requested total=\(total)")
        fflush(stdout)
    }

    func encode(pixelBuffer: CVPixelBuffer, presentationTimeStamp: CMTime) {
        guard let session else { return }

        keyframeRequestLock.lock()
        let forceKeyframe = forceKeyframePending
        if forceKeyframe { forceKeyframePending = false }
        keyframeRequestLock.unlock()

        frameID &+= 1
        let context = HEVCFrameContext(
            frameID: frameID,
            submitNanos: DispatchTime.now().uptimeNanoseconds,
            forcedKeyframeRequested: forceKeyframe
        )
        let contextPointer = Unmanaged.passRetained(context).toOpaque()

        let frameProperties: CFDictionary? = forceKeyframe
            ? [kVTEncodeFrameOptionKey_ForceKeyFrame: kCFBooleanTrue] as CFDictionary
            : nil
        var infoFlags = VTEncodeInfoFlags()
        let duration = CMTime(value: 1, timescale: fps)
        let status = VTCompressionSessionEncodeFrame(
            session,
            imageBuffer: pixelBuffer,
            presentationTimeStamp: presentationTimeStamp,
            duration: duration,
            frameProperties: frameProperties,
            sourceFrameRefcon: contextPointer,
            infoFlagsOut: &infoFlags
        )

        if status != noErr {
            _ = Unmanaged<HEVCFrameContext>.fromOpaque(contextPointer).takeRetainedValue()
            if forceKeyframe {
                keyframeRequestLock.lock()
                forceKeyframePending = true
                keyframeRequestLock.unlock()
            }
            fputs("HEVC encode failed: \(status)\n", stderr)
        }
    }

    func finish() {
        guard let session else { return }
        VTCompressionSessionCompleteFrames(session, untilPresentationTimeStamp: .invalid)
        writer.synchronize()
        VTCompressionSessionInvalidate(session)
        self.session = nil
    }

    func statsLine() -> String {
        statsLock.lock()
        defer { statsLock.unlock() }
        guard encodedFrames > 0 else { return "codec=hevc encoded=0" }
        // avg_encode runs from submit to the end of the UDP send (as before);
        // callback_avg is the hardware encoder alone, udp_send_avg the send.
        let n = Double(encodedFrames)
        let base = String(format: "codec=hevc encoded=%llu avg_encode=%.2fms max_encode=%.2fms callback_avg=%.2fms callback_max=%.2fms udp_send_avg=%.2fms udp_send_max=%.2fms",
                          encodedFrames, latencySumMS / n, latencyMaxMS,
                          callbackLatencySumMS / n, callbackLatencyMaxMS,
                          sendLatencySumMS / n, sendLatencyMaxMS)
        if let udpSender { return base + " " + udpSender.statsLine() }
        return base
    }

    private func setProperty(_ key: CFString, _ value: CFTypeRef) throws {
        guard let session else { return }
        let status = VTSessionSetProperty(session, key: key, value: value)
        guard status == noErr else {
            throw NSError(
                domain: "JerisLink.HEVCEncoder",
                code: Int(status),
                userInfo: [NSLocalizedDescriptionKey: "HEVC VTSessionSetProperty failed for \(key): \(status)"]
            )
        }
    }

    private func handleEncodedFrame(
        sourceFrameRefCon: UnsafeMutableRawPointer?,
        status: OSStatus,
        infoFlags: VTEncodeInfoFlags,
        sampleBuffer: CMSampleBuffer?
    ) {
        let callbackNanos = DispatchTime.now().uptimeNanoseconds
        let context: HEVCFrameContext? = sourceFrameRefCon.map {
            Unmanaged<HEVCFrameContext>.fromOpaque($0).takeRetainedValue()
        }

        guard status == noErr,
              !infoFlags.contains(.frameDropped),
              let sampleBuffer,
              CMSampleBufferDataIsReady(sampleBuffer)
        else {
            return
        }

        guard let encoded = writer.annexBFrame(sampleBuffer: sampleBuffer) else { return }
        if let context, context.forcedKeyframeRequested {
            if encoded.keyFrame {
                keyframeRequestLock.lock()
                forceKeyframesEmitted &+= 1
                let total = forceKeyframesEmitted
                keyframeRequestLock.unlock()
                print("encoder.hevc_force_keyframe_emitted frame=\(context.frameID) total=\(total)")
            } else {
                print("encoder.hevc_force_keyframe_missed frame=\(context.frameID)")
            }
            fflush(stdout)
        }
        writer.write(data: encoded.data)
        if let context {
            let sendStartNanos = DispatchTime.now().uptimeNanoseconds
            udpSender?.send(frameID: context.frameID, data: encoded.data, keyFrame: encoded.keyFrame)
            let now = DispatchTime.now().uptimeNanoseconds
            let latencyMS = Double(now - context.submitNanos) / 1_000_000.0
            let callbackLatencyMS = Double(callbackNanos &- context.submitNanos) / 1_000_000.0
            let sendLatencyMS = Double(now - sendStartNanos) / 1_000_000.0

            statsLock.lock()
            encodedFrames &+= 1
            latencySumMS += latencyMS
            latencyMaxMS = max(latencyMaxMS, latencyMS)
            callbackLatencySumMS += callbackLatencyMS
            callbackLatencyMaxMS = max(callbackLatencyMaxMS, callbackLatencyMS)
            sendLatencySumMS += sendLatencyMS
            sendLatencyMaxMS = max(sendLatencyMaxMS, sendLatencyMS)
            let shouldPrint = encodedFrames % 120 == 0
            statsLock.unlock()

            if shouldPrint {
                print("[frame \(context.frameID)] \(statsLine())")
            }
        }
    }
}
