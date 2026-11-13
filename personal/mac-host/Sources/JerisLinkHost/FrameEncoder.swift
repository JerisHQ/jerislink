import CoreMedia
import Darwin
import CoreVideo

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
}

extension FrameEncoder {
    func requestKeyframe() {}
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
