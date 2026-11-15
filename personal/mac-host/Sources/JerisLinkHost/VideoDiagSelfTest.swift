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

        // Slice/NAL summary: golden slice headers (first_mb_in_slice, slice_type).
        let sps: [UInt8] = [0x67, 0x64, 0x00, 0x34, 0xac, 0xda, 0x00, 0xf0, 0x01, 0x0f, 0x90]
        let pps: [UInt8] = [0x68, 0xce, 0x3c, 0x80]
        let idr0: [UInt8] = [0x65, 0x88, 0xc0, 0x11, 0x22]
        let idr4080: [UInt8] = [0x65, 0x00, 0x1f, 0xe2, 0x23, 0x44]
        let p0: [UInt8] = [0x41, 0x9b, 0x10]
        let p25440: [UInt8] = [0x41, 0x00, 0x03, 0x1b, 0x0f]
        func avcc(_ nals: [[UInt8]]) -> [UInt8] {
            nals.flatMap { n in [UInt8(n.count >> 24 & 0xff), UInt8(n.count >> 16 & 0xff), UInt8(n.count >> 8 & 0xff), UInt8(n.count & 0xff)] + n }
        }
        let key = H264FrameSummary.parseAVCC(avcc([sps, pps, idr0, idr4080]))
        var keyOk = key?.nalTypes == [7, 8, 5, 5]
        keyOk = keyOk && key?.slices.map(\.firstMb) == [0, 4080]
        keyOk = keyOk && key?.slices.map(\.sliceType) == [2, 2]
        keyOk = keyOk && key?.frameType == "IDR"
        keyOk = keyOk && key?.slice(containing: 4079) == 0
        keyOk = keyOk && key?.slice(containing: 4080) == 1
        expect(keyOk, "slices: two-slice IDR -> \(key?.line ?? "nil")")
        let p = H264FrameSummary.parseAVCC(avcc([p0, p25440]))
        var pOk = p?.slices.map(\.firstMb) == [0, 25440]
        pOk = pOk && p?.frameType == "P"
        pOk = pOk && p?.totalBytes == 8
        expect(pOk,
               "slices: two-slice P frame -> \(p?.line ?? "nil")")
        let start4: [UInt8] = [0, 0, 0, 1]
        let start3: [UInt8] = [0, 0, 1]
        var annexB = start4 + sps
        annexB += start3 + pps
        annexB += start4 + idr0
        let viaAnnexB = H264FrameSummary.parseAnnexB(annexB)
        var annexOk = viaAnnexB.nalTypes == [7, 8, 5]
        annexOk = annexOk && viaAnnexB.nalSizes == [sps.count, pps.count, idr0.count]
        annexOk = annexOk && viaAnnexB.slices.first?.firstMb == 0
        expect(annexOk,
               "slices: Annex B start codes (3 and 4 bytes) -> \(viaAnnexB.line)")
        expect(H264FrameSummary.parseAVCC([0, 0, 0, 9, 0x65]) == nil, "slices: a truncated NAL is rejected")
        let sliceLog = H264SliceLog(initialFrames: 2, interval: 1.0, maxLines: 4)
        let one = H264FrameSummary.parseAVCC(avcc([p0]))!
        let two = p!
        let l1 = sliceLog.note(one, frameID: 1, keyFrame: false, now: 0.0)
        let l2 = sliceLog.note(one, frameID: 2, keyFrame: false, now: 0.01)
        let quiet = sliceLog.note(one, frameID: 3, keyFrame: false, now: 0.02)
        let layout = sliceLog.note(two, frameID: 4, keyFrame: false, now: 0.03)
        let budget = sliceLog.note(key!, frameID: 5, keyFrame: true, now: 5.0)
        let over = sliceLog.note(key!, frameID: 6, keyFrame: true, now: 9.0)
        var logOk = l1 != nil && l2 != nil && quiet == nil
        logOk = logOk && layout?.contains("layout_changed=1 skipped=1") == true
        logOk = logOk && budget?.hasPrefix("h264.slices fid=5 type=IDR") == true
        logOk = logOk && over == nil && sliceLog.suppressed == 2
        expect(logOk,
               "slice log: first frames, layout change and keyframes are logged; budget holds")

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

    /// Test pictures. Each moves a little from frame to frame, so the P-frames
    /// carry real motion and residual, not only skipped macroblocks.
    enum Pattern: String, CaseIterable {
        /// Luma rises with the row; chroma neutral (128). Green garbage shows as low U/V.
        case ramp
        /// Colour bars in the top half, U/V gradients in the bottom half.
        case chroma
        /// Text-like glyphs on a light background, a noise band at the bottom,
        /// a smooth chroma gradient.
        case detail
    }

    static let roundTripFrames = 6  // one IDR, then P-frames

    /// Sizes from the host log: native 1080p-class, the 1696x954 capped case,
    /// and the 3840x2160 cap. Returns the number of failures. A missing
    /// encoder or decoder is a SKIP in the self-test (CI runners may have no
    /// video hardware) and a failure with `hardware: true`.
    static func roundTrip(hardware: Bool) -> Int32 {
        var failures: Int32 = 0
        let sizes = [(1920, 1080), (3392, 1904), (3840, 2160)]
        for (w, h) in sizes {
            for padded in [false, true] {
                for pattern in Pattern.allCases {
                    let name = "h264 round trip \(w)x\(h) \(padded ? "padded" : "plain") \(pattern.rawValue) "
                        + (hardware ? "hardware" : "any-encoder")
                    switch roundTripOne(width: w, height: h, padded: padded, pattern: pattern, hardware: hardware) {
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
        var samples: [CMSampleBuffer] = []
        var encodeStatus: OSStatus = noErr
        var image: CVImageBuffer?
        var decodeStatus: OSStatus = noErr
    }

    /// Luma rises with the row (16...235).
    private static func lumaFor(row: Int, height: Int) -> UInt8 {
        UInt8(16 + (row * 219) / max(1, height - 1))
    }

    @inline(__always)
    private static func hash(_ a: Int, _ b: Int, _ c: Int = 0) -> UInt32 {
        var h = UInt32(truncatingIfNeeded: a) &* 0x9E37_79B1
        h ^= UInt32(truncatingIfNeeded: b) &* 0x85EB_CA77
        h ^= UInt32(truncatingIfNeeded: c) &* 0xC2B2_AE3D
        h ^= h >> 15
        h &*= 0x2C1B_3C6D
        h ^= h >> 13
        return h
    }

    private static let barUV: [(UInt8, UInt8)] = [
        (128, 128), (16, 146), (166, 16), (54, 34), (202, 222), (90, 240), (240, 110), (110, 202),
    ]

    /// Fills a 4:2:0 bi-planar buffer with `pattern` at motion step `frame`.
    private static func fill(_ buffer: CVPixelBuffer, pattern: Pattern, frame: Int) -> Bool {
        CVPixelBufferLockBaseAddress(buffer, [])
        defer { CVPixelBufferUnlockBaseAddress(buffer, []) }
        guard let yBase = CVPixelBufferGetBaseAddressOfPlane(buffer, 0)?.assumingMemoryBound(to: UInt8.self),
              let uvBase = CVPixelBufferGetBaseAddressOfPlane(buffer, 1)?.assumingMemoryBound(to: UInt8.self)
        else { return false }
        let w = CVPixelBufferGetWidth(buffer), h = CVPixelBufferGetHeight(buffer)
        let yBpr = CVPixelBufferGetBytesPerRowOfPlane(buffer, 0)
        let uvBpr = CVPixelBufferGetBytesPerRowOfPlane(buffer, 1)
        let cw = CVPixelBufferGetWidthOfPlane(buffer, 1), ch = CVPixelBufferGetHeightOfPlane(buffer, 1)
        let dx = 4 * frame, dy = 2 * frame
        switch pattern {
        case .ramp:
            for row in 0..<h {
                memset(yBase.advanced(by: row * yBpr), Int32(lumaFor(row: (row + dy) % h, height: h)), w)
            }
            for row in 0..<ch { memset(uvBase.advanced(by: row * uvBpr), 128, cw * 2) }
        case .chroma:
            for row in 0..<h {
                let line = yBase.advanced(by: row * yBpr)
                for x in 0..<w {
                    let sx = (x + dx) % w
                    line[x] = row < h / 2 ? UInt8(96 + (sx * 8 / w) * 16) : UInt8(64 + (sx * 128) / w)
                }
            }
            for crow in 0..<ch {
                let line = uvBase.advanced(by: crow * uvBpr)
                let row = crow * 2
                for cx in 0..<cw {
                    let sx = (cx * 2 + dx) % w
                    let u: UInt8, v: UInt8
                    if row < h / 2 {
                        (u, v) = barUV[min(7, sx * 8 / w)]
                    } else {
                        u = UInt8((sx * 255) / max(1, w - 1))
                        v = UInt8(255 - (row * 255) / max(1, h - 1))
                    }
                    line[cx * 2] = u
                    line[cx * 2 + 1] = v
                }
            }
        case .detail:
            let noiseFrom = h * 3 / 4
            for row in 0..<h {
                let line = yBase.advanced(by: row * yBpr)
                let sy = row + dy
                if row >= noiseFrom {
                    for x in 0..<w {
                        line[x] = UInt8(112 + Int(hash(x + dx, sy, 7) % 33))
                    }
                    continue
                }
                let cellY = sy / 16, py = sy % 16
                for x in 0..<w {
                    let sx = x + dx
                    let cellX = sx / 8, px = sx % 8
                    let glyph = Int(hash(cellX, cellY) % 64)
                    let ink = glyph >= 13 && px >= 1 && px <= 6 && py >= 3 && py <= 12
                        && hash(glyph, px, py) % 100 < 45
                    line[x] = ink ? 24 : 230
                }
            }
            for crow in 0..<ch {
                let line = uvBase.advanced(by: crow * uvBpr)
                for cx in 0..<cw {
                    line[cx * 2] = UInt8(96 + (cx * 64) / max(1, cw))
                    line[cx * 2 + 1] = UInt8(160 - (crow * 64) / max(1, ch))
                }
            }
        }
        return true
    }

    private static func makeBuffer(width: Int, height: Int, padded: Bool,
                                   pattern: Pattern = .ramp, frame: Int = 0) -> CVPixelBuffer? {
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
        guard status == kCVReturnSuccess, let buffer, fill(buffer, pattern: pattern, frame: frame) else { return nil }
        return buffer
    }

    /// Per-plane comparison of a decoded frame with its source, in
    /// macroblocks (16x16 luma, 8x8 chroma per plane).
    struct PlaneCompare {
        var name: String
        var sumErr = 0.0
        var samples = 0.0
        var worst = 0.0
        var worstMB = (x: 0, y: 0)
        /// Mean error over the last macroblock row.
        var lastRow = 0.0
        var mean: Double { samples > 0 ? sumErr / samples : 0 }
    }

    struct FrameCompare {
        var planes: [PlaneCompare]
        /// First macroblock in raster order over the limit: plane, mb x/y, error.
        var firstBad: (plane: String, mbX: Int, mbY: Int, err: Double)?
        var badMBs = 0
    }

    /// Compares `decoded` with `source`. A macroblock is bad when its mean
    /// absolute error is above `lumaBad` (Y) or `chromaBad` (U or V).
    static func compare(source: CVPixelBuffer, decoded: CVPixelBuffer,
                        lumaBad: Double, chromaBad: Double) -> FrameCompare? {
        CVPixelBufferLockBaseAddress(source, .readOnly)
        CVPixelBufferLockBaseAddress(decoded, .readOnly)
        defer {
            CVPixelBufferUnlockBaseAddress(decoded, .readOnly)
            CVPixelBufferUnlockBaseAddress(source, .readOnly)
        }
        guard CVPixelBufferGetPlaneCount(decoded) == 2,
              CVPixelBufferGetWidth(decoded) == CVPixelBufferGetWidth(source),
              CVPixelBufferGetHeight(decoded) == CVPixelBufferGetHeight(source),
              let sy = CVPixelBufferGetBaseAddressOfPlane(source, 0)?.assumingMemoryBound(to: UInt8.self),
              let suv = CVPixelBufferGetBaseAddressOfPlane(source, 1)?.assumingMemoryBound(to: UInt8.self),
              let dy = CVPixelBufferGetBaseAddressOfPlane(decoded, 0)?.assumingMemoryBound(to: UInt8.self),
              let duv = CVPixelBufferGetBaseAddressOfPlane(decoded, 1)?.assumingMemoryBound(to: UInt8.self)
        else { return nil }
        let w = CVPixelBufferGetWidth(source), h = CVPixelBufferGetHeight(source)
        let syBpr = CVPixelBufferGetBytesPerRowOfPlane(source, 0)
        let suvBpr = CVPixelBufferGetBytesPerRowOfPlane(source, 1)
        let dyBpr = CVPixelBufferGetBytesPerRowOfPlane(decoded, 0)
        let duvBpr = CVPixelBufferGetBytesPerRowOfPlane(decoded, 1)
        let mbW = (w + 15) / 16, mbH = (h + 15) / 16
        let cw = (w + 1) / 2, ch = (h + 1) / 2
        var planes = [PlaneCompare(name: "Y"), PlaneCompare(name: "U"), PlaneCompare(name: "V")]
        var result = FrameCompare(planes: [])
        for mby in 0..<mbH {
            for mbx in 0..<mbW {
                // Luma
                var e = 0, n = 0
                for row in (mby * 16)..<min(h, mby * 16 + 16) {
                    let s = sy.advanced(by: row * syBpr), d = dy.advanced(by: row * dyBpr)
                    for x in (mbx * 16)..<min(w, mbx * 16 + 16) {
                        e += abs(Int(s[x]) - Int(d[x]))
                        n += 1
                    }
                }
                // Chroma (U at even bytes, V at odd bytes)
                var eu = 0, ev = 0, cn = 0
                for crow in (mby * 8)..<min(ch, mby * 8 + 8) {
                    let s = suv.advanced(by: crow * suvBpr), d = duv.advanced(by: crow * duvBpr)
                    for cx in (mbx * 8)..<min(cw, mbx * 8 + 8) {
                        eu += abs(Int(s[cx * 2]) - Int(d[cx * 2]))
                        ev += abs(Int(s[cx * 2 + 1]) - Int(d[cx * 2 + 1]))
                        cn += 1
                    }
                }
                let errs = [(e, n), (eu, cn), (ev, cn)]
                for (i, (err, count)) in errs.enumerated() where count > 0 {
                    let mean = Double(err) / Double(count)
                    planes[i].sumErr += Double(err)
                    planes[i].samples += Double(count)
                    if mean > planes[i].worst {
                        planes[i].worst = mean
                        planes[i].worstMB = (mbx, mby)
                    }
                    if mby == mbH - 1 { planes[i].lastRow += mean / Double(mbW) }
                    if mean > (i == 0 ? lumaBad : chromaBad) {
                        result.badMBs += 1
                        if result.firstBad == nil { result.firstBad = (planes[i].name, mbx, mby, mean) }
                    }
                }
            }
        }
        result.planes = planes
        return result
    }

    /// Limits per pattern: (frame mean Y, frame mean U/V, bad MB Y, bad MB U/V).
    /// Smooth pictures must come back nearly exact; the detail picture is
    /// lossy at the production bit rate, so only gross errors count there.
    private static func limits(_ pattern: Pattern) -> (Double, Double, Double, Double) {
        switch pattern {
        case .ramp, .chroma: return (6, 6, 24, 24)
        case .detail: return (40, 8, 110, 40)
        }
    }

    private static func roundTripOne(width: Int, height: Int, padded: Bool, pattern: Pattern,
                                     hardware: Bool) -> Outcome {
        var sources: [CVPixelBuffer] = []
        for k in 0..<roundTripFrames {
            guard let s = makeBuffer(width: width, height: height, padded: padded, pattern: pattern, frame: k) else {
                return .fail("could not create source buffer \(k)")
            }
            sources.append(s)
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
            (kVTCompressionPropertyKey_MaxKeyFrameInterval, 60 as CFNumber),
            (kVTCompressionPropertyKey_ProfileLevel, kVTProfileLevel_H264_ConstrainedHigh_AutoLevel),
        ]
        for (key, value) in props where VTSessionSetProperty(encoder, key: key, value: value) != noErr {
            unsupported.append(key as String)
        }
        VTCompressionSessionPrepareToEncodeFrames(encoder)

        let box = Box()
        for (k, source) in sources.enumerated() {
            var flags = VTEncodeInfoFlags()
            let frameProps: CFDictionary? = k == 0
                ? [kVTEncodeFrameOptionKey_ForceKeyFrame: kCFBooleanTrue] as CFDictionary : nil
            let encodeStatus = VTCompressionSessionEncodeFrame(
                encoder, imageBuffer: source, presentationTimeStamp: CMTime(value: Int64(k), timescale: 60),
                duration: CMTime(value: 1, timescale: 60), frameProperties: frameProps, infoFlagsOut: &flags
            ) { status, _, sample in
                box.lock.lock()
                if status != noErr { box.encodeStatus = status }
                if let sample { box.samples.append(sample) }
                box.lock.unlock()
            }
            guard encodeStatus == noErr else { return .fail("encode frame \(k) failed: \(encodeStatus)") }
        }
        VTCompressionSessionCompleteFrames(encoder, untilPresentationTimeStamp: .invalid)
        box.lock.lock()
        let samples = box.samples.sorted {
            CMSampleBufferGetPresentationTimeStamp($0).value < CMSampleBufferGetPresentationTimeStamp($1).value
        }
        let outStatus = box.encodeStatus
        box.lock.unlock()
        guard outStatus == noErr, samples.count == roundTripFrames,
              let format = CMSampleBufferGetFormatDescription(samples[0]) else {
            return .fail("encoded \(samples.count)/\(roundTripFrames) frames (status \(outStatus))")
        }
        guard let spsBytes = H264SPSInfo.firstSPS(format), let info = H264SPSInfo.parse(spsBytes) else {
            return .fail("SPS missing or not parsed")
        }
        guard info.displayWidth == width, info.displayHeight == height else {
            return .fail("SPS display \(info.displayWidth)x\(info.displayHeight): \(info.line)")
        }
        let summaries = samples.map { H264FrameSummary.from($0) }
        let frameTypes = summaries.map { $0?.frameType ?? "unparsed" }
        let sliceText = summaries.first.flatMap { $0?.layout } ?? "slices=?"
        let layouts = Set(summaries.compactMap { $0?.layout })
        let bytesText = samples.map { String(CMSampleBufferGetTotalSampleSize($0)) }.joined(separator: ",")
        var header = "sps \(info.line); frames=\(frameTypes.joined(separator: ",")) \(sliceText)"
            + (layouts.count > 1 ? " layouts=\(layouts.count)" : "") + " bytes=\(bytesText)"
        if !unsupported.isEmpty { header += "; unsupported=" + unsupported.joined(separator: ",") }
        guard frameTypes.first == "IDR" else { return .fail("first frame is not an IDR; \(header)") }
        let pCount = frameTypes.dropFirst().filter { $0 == "P" }.count

        let decoderAttrs: [CFString: Any] = [
            kCVPixelBufferPixelFormatTypeKey: kCVPixelFormatType_420YpCbCr8BiPlanarFullRange,
            kCVPixelBufferIOSurfacePropertiesKey: [CFString: Any]() as CFDictionary,
        ]
        var decoder: VTDecompressionSession?
        let decCreate = VTDecompressionSessionCreate(
            allocator: kCFAllocatorDefault, formatDescription: format, decoderSpecification: nil,
            imageBufferAttributes: decoderAttrs as CFDictionary, outputCallback: nil, decompressionSessionOut: &decoder)
        guard decCreate == noErr, let decoder else {
            return .skip("no H.264 decoder (status \(decCreate)); \(header)")
        }
        defer { VTDecompressionSessionInvalidate(decoder) }

        let (meanY, meanC, badY, badC) = limits(pattern)
        var worstMean = [0.0, 0.0, 0.0]
        var worstMB = [(0.0, 0, 0, 0), (0.0, 0, 0, 0), (0.0, 0, 0, 0)]  // err, frame, mb x, mb y
        var lastRow = [0.0, 0.0, 0.0]
        var firstError: String?
        for (k, sample) in samples.enumerated() {
            box.lock.lock()
            box.image = nil
            box.decodeStatus = noErr
            box.lock.unlock()
            var decodeFlags = VTDecodeInfoFlags()
            let decStatus = VTDecompressionSessionDecodeFrame(
                decoder, sampleBuffer: sample, flags: [], infoFlagsOut: &decodeFlags
            ) { status, _, image, _, _ in
                box.lock.lock()
                box.decodeStatus = status
                box.image = image
                box.lock.unlock()
            }
            guard decStatus == noErr else { return .fail("decode frame \(k) failed: \(decStatus); \(header)") }
            VTDecompressionSessionWaitForAsynchronousFrames(decoder)
            box.lock.lock()
            let image = box.image
            let imageStatus = box.decodeStatus
            box.lock.unlock()
            guard imageStatus == noErr, let image else {
                return .fail("no decoded image for frame \(k) (status \(imageStatus)); \(header)")
            }
            let dw = CVPixelBufferGetWidth(image), dh = CVPixelBufferGetHeight(image)
            guard dw == width, dh == height else { return .fail("frame \(k) decoded size \(dw)x\(dh); \(header)") }
            guard let cmp = compare(source: sources[k], decoded: image, lumaBad: badY, chromaBad: badC) else {
                return .fail("frame \(k): decoded image is not 4:2:0 bi-planar; \(header)")
            }
            for (i, p) in cmp.planes.enumerated() {
                worstMean[i] = max(worstMean[i], p.mean)
                lastRow[i] = max(lastRow[i], p.lastRow)
                if p.worst > worstMB[i].0 { worstMB[i] = (p.worst, k, p.worstMB.x, p.worstMB.y) }
                if firstError == nil, p.mean > (i == 0 ? meanY : meanC) {
                    firstError = String(format: "frame %d (%@) plane %@ mean error %.1f over %.0f",
                                        k, frameTypes[k], p.name, p.mean, i == 0 ? meanY : meanC)
                }
            }
            if firstError == nil, let bad = cmp.firstBad {
                let mb = bad.mbY * ((width + 15) / 16) + bad.mbX
                let slice = summaries[k]?.slice(containing: mb).map(String.init) ?? "?"
                firstError = String(format: "frame %d (%@) first bad MB plane %@ mb=(%d,%d) px=(%d,%d) slice=%@ err=%.1f bad_mbs=%d",
                                    k, frameTypes[k], bad.plane, bad.mbX, bad.mbY, bad.mbX * 16, bad.mbY * 16,
                                    slice, bad.err, cmp.badMBs)
            }
        }
        let names = ["Y", "U", "V"]
        let stats = (0..<3).map { i in
            String(format: "%@ mean=%.1f last_mb_row=%.1f worst_mb=%.1f@f%d(%d,%d)", names[i], worstMean[i], lastRow[i],
                   worstMB[i].0, worstMB[i].1, worstMB[i].2, worstMB[i].3)
        }.joined(separator: " ")
        let detail = "\(header); p_frames=\(pCount); \(stats)"
        if let firstError { return .fail("\(firstError); \(detail)") }
        return .pass(detail)
    }
}
