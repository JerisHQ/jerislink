import Foundation
import CoreGraphics
import CoreMedia
import CoreVideo
import IOSurface

// Diagnostics for green rows at the bottom of H.264 frames when the capture is
// capped (ScreenCaptureKit scales a display larger than 3840x2160 down).
// Native 3840x2160 capture and HEVC are fine. These helpers only describe
// buffers and parameter sets; they change nothing in the stream.

/// Size and memory layout of one CVPixelBuffer.
struct PixelBufferGeometry: Equatable {
    struct Plane: Equatable {
        var width: Int
        var height: Int
        var bytesPerRow: Int
    }

    var width: Int
    var height: Int
    var pixelFormat: OSType
    var bytesPerRow: Int
    var planes: [Plane]
    var dataSize: Int
    var ioSurface: Bool
    var ioSurfaceWidth: Int
    var ioSurfaceHeight: Int
    /// Extended (padding) pixels: left, right, top, bottom.
    var extended: [Int]

    init(width: Int, height: Int, pixelFormat: OSType, bytesPerRow: Int, planes: [Plane],
         dataSize: Int, ioSurface: Bool, ioSurfaceWidth: Int = 0, ioSurfaceHeight: Int = 0,
         extended: [Int] = [0, 0, 0, 0]) {
        self.width = width
        self.height = height
        self.pixelFormat = pixelFormat
        self.bytesPerRow = bytesPerRow
        self.planes = planes
        self.dataSize = dataSize
        self.ioSurface = ioSurface
        self.ioSurfaceWidth = ioSurfaceWidth
        self.ioSurfaceHeight = ioSurfaceHeight
        self.extended = extended
    }

    init(_ buffer: CVPixelBuffer) {
        var planes: [Plane] = []
        let count = CVPixelBufferGetPlaneCount(buffer)
        for i in 0..<count {
            planes.append(Plane(width: CVPixelBufferGetWidthOfPlane(buffer, i),
                                height: CVPixelBufferGetHeightOfPlane(buffer, i),
                                bytesPerRow: CVPixelBufferGetBytesPerRowOfPlane(buffer, i)))
        }
        var l = 0, r = 0, t = 0, b = 0
        CVPixelBufferGetExtendedPixels(buffer, &l, &r, &t, &b)
        var surfaceW = 0, surfaceH = 0
        let surface = CVPixelBufferGetIOSurface(buffer)?.takeUnretainedValue()
        if let surface {
            surfaceW = IOSurfaceGetWidth(surface)
            surfaceH = IOSurfaceGetHeight(surface)
        }
        self.init(width: CVPixelBufferGetWidth(buffer),
                  height: CVPixelBufferGetHeight(buffer),
                  pixelFormat: CVPixelBufferGetPixelFormatType(buffer),
                  bytesPerRow: CVPixelBufferGetBytesPerRow(buffer),
                  planes: planes,
                  dataSize: CVPixelBufferGetDataSize(buffer),
                  ioSurface: surface != nil,
                  ioSurfaceWidth: surfaceW,
                  ioSurfaceHeight: surfaceH,
                  extended: [l, r, t, b])
    }

    static func fourCC(_ v: OSType) -> String {
        let bytes = [UInt8((v >> 24) & 0xff), UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)]
        if bytes.allSatisfy({ $0 >= 0x20 && $0 < 0x7f }) {
            return String(decoding: bytes, as: UTF8.self)
        }
        return String(format: "0x%08x", v)
    }

    /// What differs from a plain width x height 4:2:0 bi-planar buffer, or
    /// "none". Row padding (bytesPerRow > width) is normal and not listed.
    func mismatches(targetWidth: Int, targetHeight: Int) -> [String] {
        var out: [String] = []
        if width != targetWidth || height != targetHeight { out.append("size") }
        if planes.count != 2 {
            out.append("planes")
        } else {
            if planes[0].width != width || planes[0].height != height { out.append("luma_plane") }
            if planes[1].width != (width + 1) / 2 || planes[1].height != (height + 1) / 2 { out.append("chroma_plane") }
            if planes[0].bytesPerRow < width || planes[1].bytesPerRow < planes[1].width * 2 { out.append("short_rows") }
        }
        if extended != [0, 0, 0, 0] { out.append("extended") }
        if ioSurface && (ioSurfaceWidth != width || ioSurfaceHeight != height) { out.append("iosurface_size") }
        return out
    }

    func line(targetWidth: Int, targetHeight: Int) -> String {
        let planeText = planes.enumerated()
            .map { "p\($0.offset)=\($0.element.width)x\($0.element.height)/\($0.element.bytesPerRow)" }
            .joined(separator: " ")
        let bad = mismatches(targetWidth: targetWidth, targetHeight: targetHeight)
        return "size=\(width)x\(height) target=\(targetWidth)x\(targetHeight) fmt=\(Self.fourCC(pixelFormat)) "
            + "bpr=\(bytesPerRow) \(planeText) data=\(dataSize) "
            + "iosurface=\(ioSurface ? "\(ioSurfaceWidth)x\(ioSurfaceHeight)" : "none") "
            + "ext=\(extended.map(String.init).joined(separator: ",")) "
            + "mismatch=\(bad.isEmpty ? "none" : bad.joined(separator: ","))"
    }
}

/// Logs the captured buffer geometry and the SCK frame info (content rect and
/// scale) on the first frame and whenever it changes, at most `maxLines`
/// times per capture session. Used on the capture queue only.
final class CaptureGeometryLog {
    private let targetWidth: Int
    private let targetHeight: Int
    private let maxLines: Int
    private var last: String?
    private(set) var lines = 0
    private(set) var changes = 0

    init(targetWidth: Int, targetHeight: Int, maxLines: Int = 8) {
        self.targetWidth = targetWidth
        self.targetHeight = targetHeight
        self.maxLines = maxLines
    }

    /// Returns the line to print, or nil when nothing changed or the budget is used.
    func note(_ geometry: PixelBufferGeometry, frameInfo: String) -> String? {
        let text = geometry.line(targetWidth: targetWidth, targetHeight: targetHeight) + " " + frameInfo
        guard text != last else { return nil }
        if last != nil { changes += 1 }
        last = text
        guard lines < maxLines else { return nil }
        lines += 1
        return "capture.buffer \(text)"
    }

    /// SCStreamFrameInfo fields that tell whether SCK scaled or letterboxed.
    static func frameInfoText(contentRect: CGRect?, contentScale: Double?, scaleFactor: Double?) -> String {
        let rect = contentRect.map {
            String(format: "%.0f,%.0f,%.0fx%.0f", $0.origin.x, $0.origin.y, $0.size.width, $0.size.height)
        } ?? "na"
        let cs = contentScale.map { String(format: "%.4f", $0) } ?? "na"
        let sf = scaleFactor.map { String(format: "%.2f", $0) } ?? "na"
        return "content_rect=\(rect) content_scale=\(cs) scale_factor=\(sf)"
    }
}

/// The parts of an H.264 sequence parameter set that decide the coded and
/// displayed frame size. Parsing stops before the VUI.
struct H264SPSInfo: Equatable {
    var profileIdc: Int
    var constraintFlags: Int
    var levelIdc: Int
    var chromaFormatIdc: Int
    var widthInMbs: Int
    var heightInMapUnits: Int
    var frameMbsOnly: Bool
    /// frame_crop_left/right/top/bottom_offset as coded (crop units).
    var crop: [Int]

    var codedWidth: Int { widthInMbs * 16 }
    var codedHeight: Int { heightInMapUnits * 16 * (frameMbsOnly ? 1 : 2) }

    private var cropUnitX: Int { chromaFormatIdc == 0 || chromaFormatIdc == 3 ? 1 : 2 }
    private var cropUnitY: Int {
        let sub = chromaFormatIdc == 1 ? 2 : 1
        return (chromaFormatIdc == 0 ? 1 : sub) * (frameMbsOnly ? 1 : 2)
    }
    var displayWidth: Int { codedWidth - cropUnitX * (crop[0] + crop[1]) }
    var displayHeight: Int { codedHeight - cropUnitY * (crop[2] + crop[3]) }

    var line: String {
        "profile=\(profileIdc) constraint=0x\(String(constraintFlags, radix: 16)) level=\(levelIdc) "
            + "chroma=\(chromaFormatIdc) mbs=\(widthInMbs)x\(heightInMapUnits) frame_mbs_only=\(frameMbsOnly ? 1 : 0) "
            + "coded=\(codedWidth)x\(codedHeight) crop=\(crop.map(String.init).joined(separator: ",")) "
            + "display=\(displayWidth)x\(displayHeight)"
    }

    /// Removes emulation-prevention bytes (00 00 03 -> 00 00).
    static func unescape(_ nal: [UInt8]) -> [UInt8] {
        var out: [UInt8] = []
        out.reserveCapacity(nal.count)
        var zeros = 0
        for byte in nal {
            if zeros >= 2 && byte == 3 {
                zeros = 0
                continue
            }
            out.append(byte)
            zeros = byte == 0 ? zeros + 1 : 0
        }
        return out
    }

    private struct BitReader {
        let bytes: [UInt8]
        var pos = 0

        mutating func bit() -> Int? {
            guard pos < bytes.count * 8 else { return nil }
            let v = Int(bytes[pos >> 3] >> (7 - UInt8(pos & 7))) & 1
            pos += 1
            return v
        }

        mutating func u(_ n: Int) -> Int? {
            var v = 0
            for _ in 0..<n {
                guard let b = bit() else { return nil }
                v = (v << 1) | b
            }
            return v
        }

        mutating func ue() -> Int? {
            var zeros = 0
            while true {
                guard let b = bit() else { return nil }
                if b == 1 { break }
                zeros += 1
                if zeros > 31 { return nil }
            }
            guard let rest = u(zeros) else { return nil }
            return (1 << zeros) - 1 + rest
        }

        mutating func se() -> Int? {
            guard let k = ue() else { return nil }
            return k & 1 == 1 ? (k + 1) / 2 : -(k / 2)
        }
    }

    /// `nal` is one SPS NAL unit including its one-byte header (type 7).
    static func parse(_ nal: [UInt8]) -> H264SPSInfo? {
        guard nal.count > 4, nal[0] & 0x1f == 7 else { return nil }
        var r = BitReader(bytes: unescape(Array(nal.dropFirst())))
        guard let profile = r.u(8), let constraint = r.u(8), let level = r.u(8), r.ue() != nil else { return nil }
        var chroma = 1
        if [100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135].contains(profile) {
            guard let c = r.ue() else { return nil }
            chroma = c
            if chroma == 3 { guard r.u(1) != nil else { return nil } }
            guard r.ue() != nil, r.ue() != nil, r.u(1) != nil, let scaling = r.u(1) else { return nil }
            if scaling == 1 {
                for i in 0..<(chroma == 3 ? 12 : 8) {
                    guard let present = r.u(1) else { return nil }
                    guard present == 1 else { continue }
                    var lastScale = 8, nextScale = 8
                    for _ in 0..<(i < 6 ? 16 : 64) {
                        if nextScale != 0 {
                            guard let delta = r.se() else { return nil }
                            nextScale = (lastScale + delta + 256) % 256
                        }
                        lastScale = nextScale == 0 ? lastScale : nextScale
                    }
                }
            }
        }
        guard r.ue() != nil, let pocType = r.ue() else { return nil }
        if pocType == 0 {
            guard r.ue() != nil else { return nil }
        } else if pocType == 1 {
            guard r.u(1) != nil, r.se() != nil, r.se() != nil, let n = r.ue(), n < 256 else { return nil }
            for _ in 0..<n { guard r.se() != nil else { return nil } }
        }
        guard r.ue() != nil, r.u(1) != nil,
              let wMinus1 = r.ue(), let hMinus1 = r.ue(), let fmo = r.u(1) else { return nil }
        if fmo == 0 { guard r.u(1) != nil else { return nil } }
        guard r.u(1) != nil, let cropping = r.u(1) else { return nil }
        var crop = [0, 0, 0, 0]
        if cropping == 1 {
            for i in 0..<4 {
                guard let c = r.ue() else { return nil }
                crop[i] = c
            }
        }
        return H264SPSInfo(profileIdc: profile, constraintFlags: constraint, levelIdc: level,
                           chromaFormatIdc: chroma, widthInMbs: wMinus1 + 1, heightInMapUnits: hMinus1 + 1,
                           frameMbsOnly: fmo == 1, crop: crop)
    }

    /// The first SPS of an H.264 format description.
    static func firstSPS(_ format: CMFormatDescription) -> [UInt8]? {
        var ptr: UnsafePointer<UInt8>?
        var size = 0
        var count = 0
        var headerLength: Int32 = 0
        let status = CMVideoFormatDescriptionGetH264ParameterSetAtIndex(
            format, parameterSetIndex: 0,
            parameterSetPointerOut: &ptr, parameterSetSizeOut: &size,
            parameterSetCountOut: &count, nalUnitHeaderLengthOut: &headerLength)
        guard status == noErr, let ptr, size > 0 else { return nil }
        return Array(UnsafeBufferPointer(start: ptr, count: size))
    }
}

/// Logs the encoder's output format (and, for H.264, the parsed SPS) on the
/// first keyframe and whenever it changes. Thread-safe; at most `maxLines`.
final class EncodedFormatLog: @unchecked Sendable {
    private let lock = NSLock()
    private let codec: String
    private let sessionWidth: Int
    private let sessionHeight: Int
    private let maxLines: Int
    private var last: String?
    private var lines = 0

    init(codec: String, sessionWidth: Int, sessionHeight: Int, maxLines: Int = 4) {
        self.codec = codec
        self.sessionWidth = sessionWidth
        self.sessionHeight = sessionHeight
        self.maxLines = maxLines
    }

    static func text(codec: String, sessionWidth: Int, sessionHeight: Int, format: CMFormatDescription) -> String {
        let dims = CMVideoFormatDescriptionGetDimensions(format)
        var text = "codec=\(codec) session=\(sessionWidth)x\(sessionHeight) format=\(dims.width)x\(dims.height)"
        if codec == "h264" {
            if let sps = H264SPSInfo.firstSPS(format), let info = H264SPSInfo.parse(sps) {
                text += " sps " + info.line
                text += " display_matches=\(info.displayWidth == sessionWidth && info.displayHeight == sessionHeight ? 1 : 0)"
            } else {
                text += " sps=unparsed"
            }
        }
        return text
    }

    func noteKeyframe(_ sampleBuffer: CMSampleBuffer) {
        guard let format = CMSampleBufferGetFormatDescription(sampleBuffer) else { return }
        let text = Self.text(codec: codec, sessionWidth: sessionWidth, sessionHeight: sessionHeight, format: format)
        lock.lock()
        let changed = text != last && lines < maxLines
        if changed {
            last = text
            lines += 1
        }
        lock.unlock()
        if changed {
            print("encoder.format \(text)")
            fflush(stdout)
        }
    }
}
