import Foundation
import CoreMedia
import VideoToolbox

final class HEVCAnnexBWriter {
    private let handle: FileHandle
    private let lock = NSLock()
    private let startCode = Data([0x00, 0x00, 0x00, 0x01])
    private var nalUnitHeaderLength = 4

    init(url: URL) throws {
        FileManager.default.createFile(atPath: url.path, contents: nil)
        self.handle = try FileHandle(forWritingTo: url)
    }

    deinit { try? handle.close() }

    func annexBFrame(sampleBuffer: CMSampleBuffer) -> (data: Data, keyFrame: Bool)? {
        let isKeyFrame: Bool = {
            guard let attachments = CMSampleBufferGetSampleAttachmentsArray(sampleBuffer, createIfNecessary: false) as? [[CFString: Any]],
                  let first = attachments.first else { return true }
            return (first[kCMSampleAttachmentKey_NotSync] as? Bool) != true
        }()

        var output = Data()
        if isKeyFrame, let format = CMSampleBufferGetFormatDescription(sampleBuffer) {
            appendParameterSets(formatDescription: format, to: &output)
        }

        guard let blockBuffer = CMSampleBufferGetDataBuffer(sampleBuffer) else { return nil }
        var totalLength = 0
        var lengthAtOffset = 0
        var dataPointer: UnsafeMutablePointer<Int8>?
        let status = CMBlockBufferGetDataPointer(blockBuffer, atOffset: 0,
                                                 lengthAtOffsetOut: &lengthAtOffset,
                                                 totalLengthOut: &totalLength,
                                                 dataPointerOut: &dataPointer)
        guard status == kCMBlockBufferNoErr, let dataPointer else { return nil }

        let headerLength = max(1, min(4, nalUnitHeaderLength))
        var offset = 0
        while offset + headerLength <= totalLength {
            var nalLength = 0
            for i in 0..<headerLength {
                nalLength = (nalLength << 8) | Int(UInt8(bitPattern: dataPointer[offset + i]))
            }
            offset += headerLength
            guard nalLength > 0, offset + nalLength <= totalLength else { break }
            output.append(startCode)
            output.append(Data(bytes: UnsafeRawPointer(dataPointer.advanced(by: offset)), count: nalLength))
            offset += nalLength
        }
        return output.isEmpty ? nil : (output, isKeyFrame)
    }

    func write(data: Data) {
        lock.lock(); defer { lock.unlock() }
        handle.write(data)
    }

    func synchronize() {
        lock.lock(); defer { lock.unlock() }
        try? handle.synchronize()
    }

    private func appendParameterSets(formatDescription: CMFormatDescription, to output: inout Data) {
        var headerLength: Int32 = 4
        for index in 0..<3 {
            var ptr: UnsafePointer<UInt8>?
            var size = 0
            var count = 0
            let status = CMVideoFormatDescriptionGetHEVCParameterSetAtIndex(
                formatDescription,
                parameterSetIndex: index,
                parameterSetPointerOut: &ptr,
                parameterSetSizeOut: &size,
                parameterSetCountOut: &count,
                nalUnitHeaderLengthOut: &headerLength)
            guard status == noErr, let ptr, size > 0 else { continue }
            output.append(startCode)
            output.append(Data(bytes: ptr, count: size))
        }
        if (1...4).contains(Int(headerLength)) {
            nalUnitHeaderLength = Int(headerLength)
        }
    }
}
