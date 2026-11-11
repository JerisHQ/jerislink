import CoreMedia
import CoreVideo

enum VideoCodec: String {
    case h264
    case hevc
}

protocol FrameEncoder: AnyObject {
    func encode(pixelBuffer: CVPixelBuffer, presentationTimeStamp: CMTime)
    func requestKeyframe()
    func finish()
    func statsLine() -> String
}

extension FrameEncoder {
    func requestKeyframe() {}
}
