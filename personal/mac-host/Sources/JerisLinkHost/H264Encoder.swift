import Foundation
import CoreMedia
import CoreVideo
import VideoToolbox
import Darwin

private final class FrameContext {
    let frameID: UInt64
    let submitNanos: UInt64
    let forcedKeyframeRequested: Bool

    init(frameID: UInt64, submitNanos: UInt64, forcedKeyframeRequested: Bool) {
        self.frameID = frameID
        self.submitNanos = submitNanos
        self.forcedKeyframeRequested = forcedKeyframeRequested
    }
}

final class H264Encoder: FrameEncoder {
    private var session: VTCompressionSession?
    private let writer: H264AnnexBWriter
    private let fps: Int32
    private let udpSender: UDPFrameSender?
    private var frameID: UInt64 = 0
    private var encodedFrames: UInt64 = 0
    private var callbackLatencySumMS: Double = 0
    private var callbackLatencyMaxMS: Double = 0
    private var prepLatencySumMS: Double = 0
    private var sendLatencySumMS: Double = 0
    private var sendLatencyMaxMS: Double = 0
    private var totalLatencySumMS: Double = 0
    private var totalLatencyMaxMS: Double = 0
    private let statsLock = NSLock()
    private let keyframeRequestLock = NSLock()
    private var forceKeyframePending = false
    private var forceKeyframeRequests: UInt64 = 0
    private var forceKeyframesEmitted: UInt64 = 0

    init(width: Int32, height: Int32, fps: Int32, bitrate: Int,
         keyframeInterval: Int32? = nil,
         requestedMaxEncoderLatency: Double? = nil,
         inputQueueMaxCount: Int? = nil,
         maxFrameDelayCount: Int? = nil,
         profile: String = "constrained-high",
         outputURL: URL, udpSender: UDPFrameSender? = nil) throws {
        self.fps = fps
        self.udpSender = udpSender
        self.writer = try H264AnnexBWriter(url: outputURL)

        var createdSession: VTCompressionSession?
        let encoderSpecification = [
            kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder: true as CFBoolean,
            kVTVideoEncoderSpecification_EnableLowLatencyRateControl: true as CFBoolean
        ] as CFDictionary

        let status = VTCompressionSessionCreate(
            allocator: kCFAllocatorDefault,
            width: width,
            height: height,
            codecType: kCMVideoCodecType_H264,
            encoderSpecification: encoderSpecification,
            imageBufferAttributes: nil,
            compressedDataAllocator: nil,
            outputCallback: { outputCallbackRefCon, sourceFrameRefCon, status, infoFlags, sampleBuffer in
                guard let outputCallbackRefCon else { return }
                let encoder = Unmanaged<H264Encoder>
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
                domain: "JerisLink.H264Encoder",
                code: Int(status),
                userInfo: [NSLocalizedDescriptionKey: "VTCompressionSessionCreate failed: \(status)"]
            )
        }

        self.session = createdSession

        // Low-latency rate control already disables frame reordering and look-ahead.
        // MaxFrameDelayCount is not supported by every hardware encoder, so do not
        // make it a required property for this build.
        try setProperty(kVTCompressionPropertyKey_RealTime, kCFBooleanTrue)
        try setProperty(kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanFalse)
        try setProperty(kVTCompressionPropertyKey_ExpectedFrameRate, fps as CFNumber)
        try setProperty(kVTCompressionPropertyKey_AverageBitRate, bitrate as CFNumber)
        if let requestedMaxEncoderLatency {
            // This key is advertised by VTSessionCopySupportedPropertyDictionary
            // on the Apple M4 hardware H.264 encoder used by this host.
            try setProperty("RequestedMaxEncoderLatency" as CFString,
                            NSNumber(value: requestedMaxEncoderLatency))
            print("encoder.requested_max_latency=\(requestedMaxEncoderLatency)")
        }
        if let inputQueueMaxCount {
            try setProperty("InputQueueMaxCount" as CFString,
                            NSNumber(value: inputQueueMaxCount))
            print("encoder.input_queue_max_count=\(inputQueueMaxCount)")
        }
        if let maxFrameDelayCount {
            let status = VTSessionSetProperty(createdSession,
                                              key: "MaxFrameDelayCount" as CFString,
                                              value: NSNumber(value: maxFrameDelayCount))
            print("encoder.max_frame_delay_count=\(maxFrameDelayCount) status=\(status)")
        }
        // Default remains one IDR about once per second. Tests may shorten the
        // interval without changing the production/default behavior.
        let effectiveKeyframeInterval = max(1, keyframeInterval ?? fps)
        try setProperty(kVTCompressionPropertyKey_MaxKeyFrameInterval,
                        effectiveKeyframeInterval as CFNumber)
        print("encoder.keyframe_interval=\(effectiveKeyframeInterval)")
        let profileLevel: CFString
        switch profile {
        case "constrained-baseline":
            profileLevel = kVTProfileLevel_H264_ConstrainedBaseline_AutoLevel
        case "main":
            profileLevel = kVTProfileLevel_H264_Main_AutoLevel
        case "high":
            profileLevel = kVTProfileLevel_H264_High_AutoLevel
        default:
            profileLevel = kVTProfileLevel_H264_ConstrainedHigh_AutoLevel
        }
        try setProperty(kVTCompressionPropertyKey_ProfileLevel, profileLevel)
        print("encoder.h264_profile=\(profile)")

        let prepareStatus = VTCompressionSessionPrepareToEncodeFrames(createdSession)
        guard prepareStatus == noErr else {
            throw NSError(
                domain: "JerisLink.H264Encoder",
                code: Int(prepareStatus),
                userInfo: [NSLocalizedDescriptionKey: "VTCompressionSessionPrepareToEncodeFrames failed: \(prepareStatus)"]
            )
        }
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
        print("encoder.force_keyframe_requested total=\(total)")
        fflush(stdout)
    }

    func encode(pixelBuffer: CVPixelBuffer, presentationTimeStamp: CMTime) {
        guard let session else { return }

        keyframeRequestLock.lock()
        let forceKeyframe = forceKeyframePending
        if forceKeyframe { forceKeyframePending = false }
        keyframeRequestLock.unlock()

        frameID &+= 1
        let context = FrameContext(
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
            _ = Unmanaged<FrameContext>.fromOpaque(contextPointer).takeRetainedValue()
            if forceKeyframe {
                keyframeRequestLock.lock()
                forceKeyframePending = true
                keyframeRequestLock.unlock()
            }
            fputs("encode failed: \(status)\n", stderr)
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
        guard encodedFrames > 0 else { return "encoded=0" }
        let n = Double(encodedFrames)
        let base = String(
            format: "encoded=%llu callback_avg=%.2fms callback_max=%.2fms prep_avg=%.2fms udp_send_avg=%.2fms udp_send_max=%.2fms total_avg=%.2fms total_max=%.2fms",
            encodedFrames,
            callbackLatencySumMS / n,
            callbackLatencyMaxMS,
            prepLatencySumMS / n,
            sendLatencySumMS / n,
            sendLatencyMaxMS,
            totalLatencySumMS / n,
            totalLatencyMaxMS
        )
        if let udpSender { return base + " " + udpSender.statsLine() }
        return base
    }

    private func setProperty(_ key: CFString, _ value: CFTypeRef) throws {
        guard let session else { return }
        let status = VTSessionSetProperty(session, key: key, value: value)
        guard status == noErr else {
            throw NSError(
                domain: "JerisLink.H264Encoder",
                code: Int(status),
                userInfo: [NSLocalizedDescriptionKey: "VTSessionSetProperty failed for \(key): \(status)"]
            )
        }
    }

    private func copyNumberProperty(_ key: CFString) -> Int? {
        guard let session else { return nil }
        var value: CFTypeRef?
        let status = VTSessionCopyProperty(session,
                                           key: key,
                                           allocator: kCFAllocatorDefault,
                                           valueOut: &value)
        guard status == noErr, let number = value as? NSNumber else { return nil }
        return number.intValue
    }

    private func handleEncodedFrame(
        sourceFrameRefCon: UnsafeMutableRawPointer?,
        status: OSStatus,
        infoFlags: VTEncodeInfoFlags,
        sampleBuffer: CMSampleBuffer?
    ) {
        let context: FrameContext? = sourceFrameRefCon.map {
            Unmanaged<FrameContext>.fromOpaque($0).takeRetainedValue()
        }

        guard status == noErr,
              !infoFlags.contains(.frameDropped),
              let sampleBuffer,
              CMSampleBufferDataIsReady(sampleBuffer)
        else {
            return
        }

        guard let context else { return }
        let callbackNanos = DispatchTime.now().uptimeNanoseconds
        let callbackLatencyMS = Double(callbackNanos - context.submitNanos) / 1_000_000.0

        guard let encoded = writer.annexBFrame(sampleBuffer: sampleBuffer) else { return }
        if context.forcedKeyframeRequested {
            if encoded.keyFrame {
                keyframeRequestLock.lock()
                forceKeyframesEmitted &+= 1
                let total = forceKeyframesEmitted
                keyframeRequestLock.unlock()
                print("encoder.force_keyframe_emitted frame=\(context.frameID) total=\(total)")
            } else {
                print("encoder.force_keyframe_missed frame=\(context.frameID)")
            }
            fflush(stdout)
        }
        writer.write(data: encoded.data)
        let sendStartNanos = DispatchTime.now().uptimeNanoseconds
        let prepLatencyMS = Double(sendStartNanos - callbackNanos) / 1_000_000.0

        udpSender?.send(frameID: context.frameID, data: encoded.data, keyFrame: encoded.keyFrame)
        let sendEndNanos = DispatchTime.now().uptimeNanoseconds
        let sendLatencyMS = Double(sendEndNanos - sendStartNanos) / 1_000_000.0
        let totalLatencyMS = Double(sendEndNanos - context.submitNanos) / 1_000_000.0

        statsLock.lock()
        encodedFrames &+= 1
        callbackLatencySumMS += callbackLatencyMS
        callbackLatencyMaxMS = max(callbackLatencyMaxMS, callbackLatencyMS)
        prepLatencySumMS += prepLatencyMS
        sendLatencySumMS += sendLatencyMS
        sendLatencyMaxMS = max(sendLatencyMaxMS, sendLatencyMS)
        totalLatencySumMS += totalLatencyMS
        totalLatencyMaxMS = max(totalLatencyMaxMS, totalLatencyMS)
        let shouldPrint = encodedFrames % 120 == 0
        statsLock.unlock()

        if shouldPrint {
            let pending = copyNumberProperty("NumberOfPendingFrames" as CFString)
            let pendingText = pending.map(String.init) ?? "unknown"
            print("[frame \(context.frameID)] \(statsLine()) pending_frames=\(pendingText)")
            fflush(stdout)
        }
    }
}
