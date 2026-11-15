import Foundation
import CoreGraphics
import CoreMedia
import CoreVideo
import VideoToolbox

/// `JerisLinkHost --self-test` part for the capped-capture H.264 diagnosis:
/// SPS parsing (golden bytes), buffer geometry, the capture log budget, and an
/// H.264 encode -> decode round trip that checks the bottom rows of the frame.
/// `--h264-roundtrip-test hardware` runs only the round trip on the hardware
/// encoder, with the production session settings; it needs no screen capture.
enum VideoDiagSelfTest {
    static func run() -> Int32 {
        var failures = 0
        func expect(_ ok: Bool, _ name: String) {
            print("\(ok ? "PASS" : "FAIL") \(name)")
            if !ok { failures += 1 }
        }

        // Golden SPS NAL units from an independent bit writer (header 0x67,
        // emulation prevention applied). Name: profile, size.
        let golden: [(String, [UInt8], H264SPSInfo)] = [
            ("high 3840x2160 L5.2",
             [0x67, 0x64, 0x00, 0x34, 0xac, 0xda, 0x00, 0xf0, 0x01, 0x0f, 0x90],
             sps(100, 0, 52, 1, 240, 135, [0, 0, 0, 0])),
            ("constrained high 1920x1080 L4.2 (crop 4)",
             [0x67, 0x64, 0x0c, 0x2a, 0xac, 0xda, 0x01, 0xe0, 0x08, 0x9f, 0x95],
             sps(100, 0x0c, 42, 1, 120, 68, [0, 0, 0, 4])),
            ("high 3392x1904 L5.1",
             [0x67, 0x64, 0x00, 0x33, 0xac, 0xda, 0x00, 0xd4, 0x03, 0xbe, 0x40],
             sps(100, 0, 51, 1, 212, 119, [0, 0, 0, 0])),
            ("main 1920x1080 poc type 1",
             [0x67, 0x4d, 0x00, 0x28, 0xd1, 0x99, 0xa2, 0xa0, 0x1e, 0x00, 0x89, 0xf9, 0x50],
             sps(77, 0, 40, 1, 120, 68, [0, 0, 0, 4])),
            ("high 1280x720 with a scaling list",
             [0x67, 0x64, 0x00, 0x1f, 0xad, 0x84, 0x3f, 0xff, 0x80, 0xda, 0x01, 0x40, 0x16, 0xe4],
             sps(100, 0, 31, 1, 80, 45, [0, 0, 0, 0])),
            ("baseline 16x16",
             [0x67, 0x42, 0x00, 0x00, 0xed, 0x3c, 0x80],
             sps(66, 0, 0, 1, 1, 1, [0, 0, 0, 0])),
        ]
        let displays = [(3840, 2160), (1920, 1080), (3392, 1904), (1920, 1080), (1280, 720), (16, 16)]
        for (i, (name, bytes, want)) in golden.enumerated() {
            let got = H264SPSInfo.parse(bytes)
            expect(got == want && got?.displayWidth == displays[i].0 && got?.displayHeight == displays[i].1,
                   "sps: \(name) -> \(got?.line ?? "nil")")
        }
        expect(H264SPSInfo.parse([0x68, 0xce, 0x3c, 0x80, 0x00]) == nil, "sps: a PPS is rejected")
        expect(H264SPSInfo.parse([0x67, 0x64, 0x00]) == nil, "sps: a truncated SPS is rejected")
        expect(H264SPSInfo.unescape([0x00, 0x00, 0x03, 0x01, 0x00, 0x00, 0x03, 0x00, 0x03]) == [0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03],
               "sps: emulation prevention bytes are removed")

        // Geometry of buffers we create: a plain IOSurface 420f buffer has no
        // mismatch; extended pixels and a wrong target are reported.
        if let plain = makeBuffer(width: 3840, height: 2160, padded: false) {
            let g = PixelBufferGeometry(plain)
            expect(g.mismatches(targetWidth: 3840, targetHeight: 2160).isEmpty,
                   "geometry: plain 3840x2160 420f -> \(g.line(targetWidth: 3840, targetHeight: 2160))")
            expect(g.mismatches(targetWidth: 3840, targetHeight: 2176) == ["size"], "geometry: wrong target is reported")
        } else {
            expect(false, "geometry: create a 3840x2160 420f buffer")
        }
        if let padded = makeBuffer(width: 3840, height: 2160, padded: true) {
            let g = PixelBufferGeometry(padded)
            print("INFO geometry: padded buffer -> \(g.line(targetWidth: 3840, targetHeight: 2160))")
            expect(g.width == 3840 && g.height == 2160 && g.planes.count == 2,
                   "geometry: padded buffer keeps its size and two planes")
        } else {
            expect(false, "geometry: create a padded 3840x2160 420f buffer")
        }
        let synthetic = PixelBufferGeometry(
            width: 3840, height: 2160, pixelFormat: kCVPixelFormatType_420YpCbCr8BiPlanarFullRange,
            bytesPerRow: 0,
            planes: [.init(width: 3840, height: 2160, bytesPerRow: 3840), .init(width: 1920, height: 1088, bytesPerRow: 3840)],
            dataSize: 0, ioSurface: true, ioSurfaceWidth: 3840, ioSurfaceHeight: 2176, extended: [0, 0, 0, 16])
        expect(synthetic.mismatches(targetWidth: 3840, targetHeight: 2160) == ["chroma_plane", "extended", "iosurface_size"],
               "geometry: chroma plane, padding and surface size mismatches are listed")
        expect(PixelBufferGeometry.fourCC(kCVPixelFormatType_420YpCbCr8BiPlanarFullRange) == "420f", "geometry: fourCC 420f")

        // Capture log: one line per change, then quiet when the budget is used.
        let log = CaptureGeometryLog(targetWidth: 3840, targetHeight: 2160, maxLines: 2)
        let a = synthetic
        var b = synthetic
        b.extended = [0, 0, 0, 0]
        var c = synthetic
        c.width = 3392
        let info = CaptureGeometryLog.frameInfoText(contentRect: CGRect(x: 0, y: 0, width: 2432, height: 1368),
                                                    contentScale: 0.7895, scaleFactor: 2)
        let first = log.note(a, frameInfo: info)
        let same = log.note(a, frameInfo: info)
        let changed = log.note(b, frameInfo: info)
        let overBudget = log.note(c, frameInfo: info)
        expect(first?.hasPrefix("capture.buffer size=3840x2160") == true && first?.contains("content_rect=0,0,2432x1368") == true,
               "capture log: first frame is logged with the content rect")
        expect(same == nil && changed != nil && overBudget == nil && log.changes == 2 && log.lines == 2,
               "capture log: repeats are quiet, changes are counted, the line budget holds")

        failures += Int(roundTrip(hardware: false))
        print("video diag self-test: \(failures == 0 ? "ok" : "\(failures) failed")")
        return failures == 0 ? 0 : 1
    }

    private static func sps(_ profile: Int, _ constraint: Int, _ level: Int, _ chroma: Int,
                            _ w: Int, _ h: Int, _ crop: [Int]) -> H264SPSInfo {
        H264SPSInfo(profileIdc: profile, constraintFlags: constraint, levelIdc: level, chromaFormatIdc: chroma,
                    widthInMbs: w, heightInMapUnits: h, frameMbsOnly: true, crop: crop)
    }

    // MARK: - Round trip

    /// Sizes from the host log: native 1080p-class, the 1696x954 capped case,
    /// and the 3840x2160 cap. Returns the number of failures. A missing
    /// encoder or decoder is a SKIP in the self-test (CI runners may have no
    /// video hardware) and a failure with `hardware: true`.
    static func roundTrip(hardware: Bool) -> Int32 {
        var failures: Int32 = 0
        let sizes = [(1920, 1080), (3392, 1904), (3840, 2160)]
        for (w, h) in sizes {
            for padded in [false, true] {
                let name = "h264 round trip \(w)x\(h) \(padded ? "padded" : "plain") \(hardware ? "hardware" : "any-encoder")"
                switch roundTripOne(width: w, height: h, padded: padded, hardware: hardware) {
                case .pass(let detail):
                    print("PASS \(name): \(detail)")
                case .skip(let why):
                    if hardware {
                        print("FAIL \(name): \(why)")
                        failures += 1
                    } else {
                        print("SKIP \(name): \(why)")
                    }
                case .fail(let why):
                    print("FAIL \(name): \(why)")
                    failures += 1
                }
            }
        }
        return failures
    }

    private enum Outcome {
        case pass(String)
        case skip(String)
        case fail(String)
    }

    private final class Box: @unchecked Sendable {
        let lock = NSLock()
        var sample: CMSampleBuffer?
        var encodeStatus: OSStatus = noErr
        var image: CVImageBuffer?
        var decodeStatus: OSStatus = noErr
    }

    /// Luma rises with the row (16...235) so a wrong or missing bottom band
    /// shows; chroma is neutral (128), so green garbage (low U and V) shows.
    private static func lumaFor(row: Int, height: Int) -> UInt8 {
        UInt8(16 + (row * 219) / max(1, height - 1))
    }

    private static func makeBuffer(width: Int, height: Int, padded: Bool) -> CVPixelBuffer? {
        var attrs: [CFString: Any] = [kCVPixelBufferIOSurfacePropertiesKey: [CFString: Any]() as CFDictionary]
        if padded {
            attrs[kCVPixelBufferBytesPerRowAlignmentKey] = 256
            attrs[kCVPixelBufferExtendedPixelsBottomKey] = 16
            attrs[kCVPixelBufferExtendedPixelsRightKey] = 64
        }
        var buffer: CVPixelBuffer?
        let status = CVPixelBufferCreate(kCFAllocatorDefault, width, height,
                                         kCVPixelFormatType_420YpCbCr8BiPlanarFullRange,
                                         attrs as CFDictionary, &buffer)
        guard status == kCVReturnSuccess, let buffer else { return nil }
        CVPixelBufferLockBaseAddress(buffer, [])
        defer { CVPixelBufferUnlockBaseAddress(buffer, []) }
        guard let y = CVPixelBufferGetBaseAddressOfPlane(buffer, 0),
              let uv = CVPixelBufferGetBaseAddressOfPlane(buffer, 1) else { return nil }
        let yBpr = CVPixelBufferGetBytesPerRowOfPlane(buffer, 0)
        let uvBpr = CVPixelBufferGetBytesPerRowOfPlane(buffer, 1)
        for row in 0..<height {
            memset(y.advanced(by: row * yBpr), Int32(lumaFor(row: row, height: height)), width)
        }
        for row in 0..<CVPixelBufferGetHeightOfPlane(buffer, 1) {
            memset(uv.advanced(by: row * uvBpr), 128, CVPixelBufferGetWidthOfPlane(buffer, 1) * 2)
        }
        return buffer
    }

    /// Mean absolute luma error and mean U/V over rows [from, to).
    private static func measure(_ image: CVPixelBuffer, sourceHeight: Int, rows: Range<Int>) -> (luma: Double, u: Double, v: Double)? {
        CVPixelBufferLockBaseAddress(image, .readOnly)
        defer { CVPixelBufferUnlockBaseAddress(image, .readOnly) }
        guard CVPixelBufferGetPlaneCount(image) == 2,
              let y = CVPixelBufferGetBaseAddressOfPlane(image, 0)?.assumingMemoryBound(to: UInt8.self),
              let uv = CVPixelBufferGetBaseAddressOfPlane(image, 1)?.assumingMemoryBound(to: UInt8.self)
        else { return nil }
        let w = CVPixelBufferGetWidthOfPlane(image, 0)
        let yBpr = CVPixelBufferGetBytesPerRowOfPlane(image, 0)
        let uvBpr = CVPixelBufferGetBytesPerRowOfPlane(image, 1)
        var lumaErr = 0.0, uSum = 0.0, vSum = 0.0, n = 0.0, cn = 0.0
        for row in rows {
            let want = Double(lumaFor(row: row, height: sourceHeight))
            for x in stride(from: 0, to: w, by: 8) {
                lumaErr += abs(Double(y[row * yBpr + x]) - want)
                n += 1
            }
            if row % 2 == 0 {
                let crow = row / 2
                for x in stride(from: 0, to: w / 2, by: 8) {
                    uSum += Double(uv[crow * uvBpr + x * 2])
                    vSum += Double(uv[crow * uvBpr + x * 2 + 1])
                    cn += 1
                }
            }
        }
        guard n > 0, cn > 0 else { return nil }
        return (lumaErr / n, uSum / cn, vSum / cn)
    }

    private static func roundTripOne(width: Int, height: Int, padded: Bool, hardware: Bool) -> Outcome {
        guard let source = makeBuffer(width: width, height: height, padded: padded) else {
            return .fail("could not create the source buffer")
        }
        var spec: [CFString: Any] = [:]
        if hardware {
            spec[kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder] = true
            spec[kVTVideoEncoderSpecification_EnableLowLatencyRateControl] = true
        }
        var encoder: VTCompressionSession?
        let createStatus = VTCompressionSessionCreate(
            allocator: kCFAllocatorDefault, width: Int32(width), height: Int32(height),
            codecType: kCMVideoCodecType_H264, encoderSpecification: spec as CFDictionary,
            imageBufferAttributes: nil, compressedDataAllocator: nil,
            outputCallback: nil, refcon: nil, compressionSessionOut: &encoder)
        guard createStatus == noErr, let encoder else {
            return .skip("no H.264 encoder for this size (status \(createStatus))")
        }
        defer { VTCompressionSessionInvalidate(encoder) }
        // Production settings (H264Encoder); a key the encoder lacks is noted, not fatal.
        var unsupported: [String] = []
        let props: [(CFString, CFTypeRef)] = [
            (kVTCompressionPropertyKey_RealTime, kCFBooleanTrue),
            (kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanFalse),
            (kVTCompressionPropertyKey_ExpectedFrameRate, 60 as CFNumber),
            (kVTCompressionPropertyKey_AverageBitRate, 40_000_000 as CFNumber),
            (kVTCompressionPropertyKey_ProfileLevel, kVTProfileLevel_H264_ConstrainedHigh_AutoLevel),
        ]
        for (key, value) in props where VTSessionSetProperty(encoder, key: key, value: value) != noErr {
            unsupported.append(key as String)
        }
        VTCompressionSessionPrepareToEncodeFrames(encoder)

        let box = Box()
        var flags = VTEncodeInfoFlags()
        let encodeStatus = VTCompressionSessionEncodeFrame(
            encoder, imageBuffer: source, presentationTimeStamp: CMTime(value: 0, timescale: 60),
            duration: CMTime(value: 1, timescale: 60),
            frameProperties: [kVTEncodeFrameOptionKey_ForceKeyFrame: kCFBooleanTrue] as CFDictionary,
            infoFlagsOut: &flags
        ) { status, _, sample in
            box.lock.lock()
            box.encodeStatus = status
            box.sample = sample
            box.lock.unlock()
        }
        guard encodeStatus == noErr else { return .fail("encode failed: \(encodeStatus)") }
        VTCompressionSessionCompleteFrames(encoder, untilPresentationTimeStamp: .invalid)
        box.lock.lock()
        let sample = box.sample
        let outStatus = box.encodeStatus
        box.lock.unlock()
        guard outStatus == noErr, let sample, let format = CMSampleBufferGetFormatDescription(sample) else {
            return .fail("no encoded frame (status \(outStatus))")
        }
        guard let spsBytes = H264SPSInfo.firstSPS(format), let info = H264SPSInfo.parse(spsBytes) else {
            return .fail("SPS missing or not parsed")
        }
        guard info.displayWidth == width, info.displayHeight == height else {
            return .fail("SPS display \(info.displayWidth)x\(info.displayHeight): \(info.line)")
        }

        let decoderAttrs: [CFString: Any] = [
            kCVPixelBufferPixelFormatTypeKey: kCVPixelFormatType_420YpCbCr8BiPlanarFullRange,
            kCVPixelBufferIOSurfacePropertiesKey: [CFString: Any]() as CFDictionary,
        ]
        var decoder: VTDecompressionSession?
        let decCreate = VTDecompressionSessionCreate(
            allocator: kCFAllocatorDefault, formatDescription: format, decoderSpecification: nil,
            imageBufferAttributes: decoderAttrs as CFDictionary, outputCallback: nil, decompressionSessionOut: &decoder)
        guard decCreate == noErr, let decoder else {
            return .skip("no H.264 decoder (status \(decCreate)); encoder SPS ok: \(info.line)")
        }
        defer { VTDecompressionSessionInvalidate(decoder) }
        var decodeFlags = VTDecodeInfoFlags()
        let decStatus = VTDecompressionSessionDecodeFrame(
            decoder, sampleBuffer: sample, flags: [], infoFlagsOut: &decodeFlags
        ) { status, _, image, _, _ in
            box.lock.lock()
            box.decodeStatus = status
            box.image = image
            box.lock.unlock()
        }
        guard decStatus == noErr else { return .fail("decode failed: \(decStatus)") }
        VTDecompressionSessionWaitForAsynchronousFrames(decoder)
        box.lock.lock()
        let image = box.image
        let imageStatus = box.decodeStatus
        box.lock.unlock()
        guard imageStatus == noErr, let image else { return .fail("no decoded image (status \(imageStatus))") }
        let dw = CVPixelBufferGetWidth(image), dh = CVPixelBufferGetHeight(image)
        guard dw == width, dh == height else { return .fail("decoded size \(dw)x\(dh)") }
        guard let middle = measure(image, sourceHeight: height, rows: (height / 2 - 8)..<(height / 2 + 8)),
              let bottom = measure(image, sourceHeight: height, rows: (height - 16)..<height)
        else { return .fail("decoded image is not 4:2:0 bi-planar") }
        let detail = String(format: "sps %@; middle luma_err=%.1f u=%.0f v=%.0f; bottom16 luma_err=%.1f u=%.0f v=%.0f; frame_bytes=%d%@",
                            info.line, middle.luma, middle.u, middle.v, bottom.luma, bottom.u, bottom.v,
                            CMSampleBufferGetTotalSampleSize(sample),
                            unsupported.isEmpty ? "" : "; unsupported=" + unsupported.joined(separator: ","))
        let neutral = { (x: Double) in abs(x - 128) <= 12 }
        guard middle.luma <= 10, bottom.luma <= 10, neutral(middle.u), neutral(middle.v),
              neutral(bottom.u), neutral(bottom.v)
        else { return .fail(detail) }
        return .pass(detail)
    }
}
