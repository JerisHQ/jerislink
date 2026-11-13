import CoreMedia
import Darwin
import CoreVideo
import Foundation
import VideoToolbox

enum VideoCodec: String {
    case h264
    case hevc
}

protocol FrameEncoder: AnyObject {
    /// captureNanos: when the frame was captured, in DispatchTime uptime nanoseconds (0 = unknown).
    func encode(pixelBuffer: CVPixelBuffer, presentationTimeStamp: CMTime, captureNanos: UInt64)
    func requestKeyframe()
    func finish()
    func statsLine() -> String
    /// ABR: new average bitrate, applied on the encode thread before the next
    /// frame. idrCapFrames > 0 also sets DataRateLimits so one frame (an IDR)
    /// is at most that many times the average frame size.
    func setRateTarget(bitrateBps: Int, idrCapFrames: Int)
}

extension FrameEncoder {
    func requestKeyframe() {}
    func setRateTarget(bitrateBps: Int, idrCapFrames: Int) {}
}

/// Pending ABR rate change for a VT session (set from any thread, applied on
/// the encode thread). A failed VTSessionSetProperty is logged and counted,
/// never fatal: the stream keeps the previous rate.
final class EncoderRateTarget: @unchecked Sendable {
    private let lock = NSLock()
    private var pending: (bps: Int, cap: Int)?
    private var applied: UInt64 = 0
    private var errors: UInt64 = 0

    func request(bitrateBps: Int, idrCapFrames: Int) {
        lock.lock(); pending = (bitrateBps, idrCapFrames); lock.unlock()
    }

    func applyPending(to session: VTCompressionSession, fps: Int32) {
        lock.lock()
        let p = pending
        pending = nil
        lock.unlock()
        guard let p else { return }
        let rateStatus = VTSessionSetProperty(session, key: kVTCompressionPropertyKey_AverageBitRate,
                                              value: p.bps as CFNumber)
        var limitStatus: OSStatus = noErr
        var capBytes = 0
        if p.cap > 0 {
            let frameSeconds = 1.0 / Double(max(1, fps))
            capBytes = max(1, p.bps / 8 / Int(max(1, fps))) * p.cap
            let limits = [NSNumber(value: capBytes), NSNumber(value: frameSeconds)] as CFArray
            limitStatus = VTSessionSetProperty(session, key: kVTCompressionPropertyKey_DataRateLimits, value: limits)
        }
        lock.lock()
        if rateStatus == noErr && limitStatus == noErr { applied &+= 1 } else { errors &+= 1 }
        lock.unlock()
        print("encoder.rate bitrate=\(p.bps) frame_cap_bytes=\(capBytes) status=\(rateStatus) limit_status=\(limitStatus)")
        fflush(stdout)
    }

    var statsFields: String {
        lock.lock(); defer { lock.unlock() }
        return "rate_set=\(applied) rate_set_errors=\(errors)"
    }
}

/// Capture-to-encoded latency in 0.1 ms buckets up to 200 ms (one overflow
/// bucket above). Fixed memory, so it can run for a whole session; the
/// percentile is the upper edge of the bucket that holds the rank.
struct LatencyHistogram {
    static let bucketMS = 0.1
    static let bucketCount = 2000
    private(set) var counts = [UInt32](repeating: 0, count: LatencyHistogram.bucketCount + 1)
    private(set) var samples: UInt64 = 0
    private(set) var maxMS: Double = 0

    mutating func add(_ ms: Double) {
        let v = ms.isFinite ? max(0, ms) : 0
        let i = min(Int(v / Self.bucketMS), Self.bucketCount)
        counts[i] &+= 1
        samples &+= 1
        maxMS = max(maxMS, v)
    }

    func percentile(_ p: Double) -> Double {
        guard samples > 0 else { return 0 }
        let rank = max(1, UInt64((p * Double(samples)).rounded(.up)))
        var seen: UInt64 = 0
        for (i, c) in counts.enumerated() {
            seen += UInt64(c)
            if seen >= rank {
                return i == Self.bucketCount ? maxMS : min(maxMS, Double(i + 1) * Self.bucketMS)
            }
        }
        return maxMS
    }

    mutating func reset() { self = LatencyHistogram() }

    func fields(_ name: String) -> String {
        let f = { (v: Double) in String(format: "%.1fms", v) }
        return "\(name)_p50=\(f(percentile(0.50))) \(name)_p95=\(f(percentile(0.95))) \(name)_max=\(f(maxMS))"
    }
}

/// SCStreamFrameInfo.displayTime is mach_absolute_time ticks; DispatchTime
/// uptimeNanoseconds is the same clock in nanoseconds.
enum CaptureClock {
    private static let timebase: mach_timebase_info_data_t = {
        var info = mach_timebase_info_data_t()
        mach_timebase_info(&info)
        return info
    }()

    static func nanos(fromMachTicks ticks: UInt64) -> UInt64 {
        let tb = timebase
        guard tb.denom != 0 else { return ticks }
        return UInt64((Double(ticks) * Double(tb.numer) / Double(tb.denom)).rounded())
    }

    /// Milliseconds from capture to `now`; 0 when the capture time is missing
    /// or later than `now`.
    static func elapsedMS(since captureNanos: UInt64, now: UInt64) -> Double {
        guard captureNanos > 0, now > captureNanos else { return 0 }
        return Double(now - captureNanos) / 1_000_000.0
    }
}
