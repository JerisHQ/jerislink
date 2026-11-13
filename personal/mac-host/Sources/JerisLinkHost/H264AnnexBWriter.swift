import Foundation
import CoreMedia
import VideoToolbox

final class H264AnnexBWriter {
    /// nil when the output is /dev/null (the video service): no file and no
    /// write per frame.
    private let handle: FileHandle?
    private let lock = NSLock()
    private let startCode = Data([0x00, 0x00, 0x00, 0x01])

    static func discards(_ url: URL) -> Bool {
        url.standardizedFileURL.path == "/dev/null"
    }

    init(url: URL) throws {
        if Self.discards(url) {
            self.handle = nil
            return
        }
        FileManager.default.createFile(atPath: url.path, contents: nil)
        self.handle = try FileHandle(forWritingTo: url)
    }

    deinit { try? handle?.close() }

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

        var offset = 0
        while offset + 4 <= totalLength {
            var nalLengthBE: UInt32 = 0
            memcpy(&nalLengthBE, dataPointer.advanced(by: offset), 4)
            let nalLength = Int(UInt32(bigEndian: nalLengthBE))
            offset += 4
            guard nalLength > 0, offset + nalLength <= totalLength else { break }
            output.append(startCode)
            output.append(Data(bytes: UnsafeRawPointer(dataPointer.advanced(by: offset)), count: nalLength))
            offset += nalLength
        }
        return output.isEmpty ? nil : (output, isKeyFrame)
    }

    func write(data: Data) {
        guard let handle else { return }
        lock.lock(); defer { lock.unlock() }
        handle.write(data)
    }

    func synchronize() {
        guard let handle else { return }
        lock.lock(); defer { lock.unlock() }
        try? handle.synchronize()
    }

    private func appendParameterSets(formatDescription: CMFormatDescription, to output: inout Data) {
        var nalUnitHeaderLength: Int32 = 0
        for index in 0..<2 {
            var ptr: UnsafePointer<UInt8>?
            var size = 0
            var count = 0
            let status = CMVideoFormatDescriptionGetH264ParameterSetAtIndex(
                formatDescription,
                parameterSetIndex: index,
                parameterSetPointerOut: &ptr,
                parameterSetSizeOut: &size,
                parameterSetCountOut: &count,
                nalUnitHeaderLengthOut: &nalUnitHeaderLength)
            guard status == noErr, let ptr, size > 0 else { continue }
            output.append(startCode)
            output.append(Data(bytes: ptr, count: size))
        }
    }
}
