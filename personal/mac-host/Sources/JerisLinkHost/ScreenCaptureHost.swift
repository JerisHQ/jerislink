import Foundation
import CoreGraphics
import CoreMedia
import CoreVideo
@preconcurrency import ScreenCaptureKit

final class ScreenCaptureHost: NSObject, SCStreamOutput, SCStreamDelegate {
    private let encoder: any FrameEncoder
    private let queue = DispatchQueue(label: "jerislink.capture", qos: .userInteractive)
    private var stream: SCStream?
    private var receivedFrames: UInt64 = 0

    init(encoder: any FrameEncoder) {
        self.encoder = encoder
    }

    func start(displayID: CGDirectDisplayID,
               targetWidth: Int, targetHeight: Int, fps: Int32,
               fullRange: Bool, showsCursor: Bool = true, queueDepth: Int = 3) async throws {
        let content = try await SCShareableContent.excludingDesktopWindows(
            false,
            onScreenWindowsOnly: true
        )

        guard let display = content.displays.first(where: { $0.displayID == displayID }) ?? content.displays.first else {
            throw NSError(
                domain: "JerisLink.ScreenCapture",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "No captureable display found"]
            )
        }

        let filter = SCContentFilter(
            display: display,
            excludingApplications: [],
            exceptingWindows: []
        )

        let config = SCStreamConfiguration()
        config.width = targetWidth
        config.height = targetHeight
        config.minimumFrameInterval = CMTime(value: 1, timescale: fps)
        config.queueDepth = queueDepth
        config.pixelFormat = fullRange
            ? kCVPixelFormatType_420YpCbCr8BiPlanarFullRange
            : kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange
        config.showsCursor = showsCursor
        config.capturesAudio = false

        print("Display source: id=\(display.displayID) logical=\(display.width)x\(display.height)")
        print("Capture output: \(targetWidth)x\(targetHeight) @ \(fps) fps, \(fullRange ? "420f" : "420v"), cursor=\(showsCursor ? "on" : "off"), queueDepth=\(queueDepth)")

        let stream = SCStream(filter: filter, configuration: config, delegate: self)
        try stream.addStreamOutput(self, type: .screen, sampleHandlerQueue: queue)
        self.stream = stream
        try await stream.startCapture()
    }

    func stop() async {
        guard let stream else { return }
        try? await stream.stopCapture()
        self.stream = nil
        encoder.finish()
    }

    func stream(
        _ stream: SCStream,
        didOutputSampleBuffer sampleBuffer: CMSampleBuffer,
        of outputType: SCStreamOutputType
    ) {
        guard outputType == .screen,
              CMSampleBufferIsValid(sampleBuffer),
              let imageBuffer = CMSampleBufferGetImageBuffer(sampleBuffer)
        else {
            return
        }

        guard
            let attachmentsArray = CMSampleBufferGetSampleAttachmentsArray(
                sampleBuffer,
                createIfNecessary: false
            ) as? [[SCStreamFrameInfo: Any]],
            let attachments = attachmentsArray.first,
            let statusRawValue = attachments[.status] as? Int,
            SCFrameStatus(rawValue: statusRawValue) == .complete
        else {
            return
        }

        receivedFrames &+= 1
        let pts = CMSampleBufferGetPresentationTimeStamp(sampleBuffer)
        encoder.encode(pixelBuffer: imageBuffer, presentationTimeStamp: pts)
    }

    func stream(_ stream: SCStream, didStopWithError error: any Error) {
        fputs("ScreenCaptureKit stopped: \(error.localizedDescription)\n", stderr)
    }
}
