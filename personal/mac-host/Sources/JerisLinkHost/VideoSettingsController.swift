import Foundation
import Darwin

struct VideoSettingsAck {
    let status: UInt8
    let codec: UInt8
    let flags: UInt8
    let bitrateMbps: UInt16
    let framebufferWidth: UInt16
    let framebufferHeight: UInt16

    init(status: UInt8, codec: UInt8, flags: UInt8, bitrateMbps: UInt16,
         framebufferWidth: UInt16 = 0, framebufferHeight: UInt16 = 0) {
        self.status = status
        self.codec = codec
        self.flags = flags
        self.bitrateMbps = bitrateMbps
        self.framebufferWidth = framebufferWidth
        self.framebufferHeight = framebufferHeight
    }

    var payload: [UInt8] {
        [
            1,
            status,
            codec,
            flags,
            UInt8(bitrateMbps >> 8),
            UInt8(bitrateMbps & 0xff),
            UInt8(framebufferWidth >> 8),
            UInt8(framebufferWidth & 0xff),
            UInt8(framebufferHeight >> 8),
            UInt8(framebufferHeight & 0xff)
        ]
    }
}

final class VideoSettingsController: @unchecked Sendable {
    private let lock = NSLock()
    private let fileURL: URL
    private let hostExecutablePattern: String

    init() {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let support = home
            .appendingPathComponent("Library/Application Support/JerisLink", isDirectory: true)
        self.fileURL = support.appendingPathComponent("video-settings.plist")
        self.hostExecutablePattern =
            "^" + home.path + "/Applications/JerisLink Host.app/Contents/MacOS/JerisLinkHost --duration 86400( |$)"
    }

    func apply(request payload: [UInt8]) -> VideoSettingsAck {
        guard payload.count == 6, payload[0] == 1 else {
            return VideoSettingsAck(status: 1, codec: 1, flags: 0, bitrateMbps: 25)
        }

        let requestedCodec = payload[1]
        let clientCaps = payload[2]
        let requestedBitrate = UInt16(payload[4]) << 8 | UInt16(payload[5])

        let clientH264 = (clientCaps & 0x01) != 0
        let clientHEVC = (clientCaps & 0x02) != 0
        guard clientH264 else {
            return VideoSettingsAck(status: 1, codec: 1, flags: 0, bitrateMbps: 25)
        }
        guard requestedCodec <= 2 else {
            return VideoSettingsAck(status: 1, codec: 1, flags: 0, bitrateMbps: 25)
        }
        if requestedBitrate != 0 && !(4...100).contains(requestedBitrate) {
            return VideoSettingsAck(status: 1, codec: 1, flags: 0, bitrateMbps: 25)
        }

        // v0.0.9.x Phase 1: the current JerisLink macOS Host has verified
        // VideoToolbox H.264 and HEVC encode paths. Client decoder capability
        // determines whether Auto may select HEVC.
        let hostHEVC = true
        let selectedCodec: UInt8
        var fallback = false
        switch requestedCodec {
        case 0: // Auto
            selectedCodec = (hostHEVC && clientHEVC) ? 2 : 1
        case 1: // H.264
            selectedCodec = 1
        case 2: // HEVC
            if hostHEVC && clientHEVC {
                selectedCodec = 2
            } else {
                selectedCodec = 1
                fallback = true
            }
        default:
            selectedCodec = 1
        }

        let selectedBitrate: UInt16
        if requestedBitrate == 0 {
            selectedBitrate = selectedCodec == 2 ? 18 : 25
        } else {
            selectedBitrate = requestedBitrate
        }

        let codecName = selectedCodec == 2 ? "hevc" : "h264"
        let displayMode = try? DisplayModeResolver.currentMainDisplay()
        let framebufferWidth = UInt16(displayMode?.pixelWidth ?? 0)
        let framebufferHeight = UInt16(displayMode?.pixelHeight ?? 0)

        lock.lock()
        defer { lock.unlock() }

        do {
            let old = readCurrent()
            let changed = old.codec != codecName || old.bitrateMbps != Int(selectedBitrate)
            if changed {
                try persist(codec: codecName, bitrateMbps: Int(selectedBitrate))
            }

            var flags: UInt8 = 0
            if changed { flags |= 0x01 }
            if hostHEVC { flags |= 0x02 }
            if fallback { flags |= 0x04 }
            if framebufferWidth > 0 && framebufferHeight > 0 { flags |= 0x08 }

            if changed {
                requestVideoRestart()
            }

            return VideoSettingsAck(
                status: 0,
                codec: selectedCodec,
                flags: flags,
                bitrateMbps: selectedBitrate,
                framebufferWidth: framebufferWidth,
                framebufferHeight: framebufferHeight
            )
        } catch {
            print("Video settings apply failed: \(error)")
            return VideoSettingsAck(status: 2, codec: 1, flags: hostHEVC ? 0x02 : 0, bitrateMbps: 25)
        }
    }

    private func readCurrent() -> (codec: String, bitrateMbps: Int) {
        guard let data = try? Data(contentsOf: fileURL),
              let object = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
              let dict = object as? [String: Any],
              let codec = dict["codec"] as? String,
              let bitrate = dict["bitrateMbps"] as? Int
        else {
            return ("h264", 25)
        }
        return (codec, bitrate)
    }

    private func persist(codec: String, bitrateMbps: Int) throws {
        let directory = fileURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        let object: [String: Any] = [
            "version": 1,
            "codec": codec,
            "bitrateMbps": bitrateMbps
        ]
        let data = try PropertyListSerialization.data(
            fromPropertyList: object,
            format: .xml,
            options: 0
        )
        try data.write(to: fileURL, options: .atomic)
        print("Video settings persisted codec=\(codec) bitrate_mbps=\(bitrateMbps)")
    }

    private func requestVideoRestart() {
        let pattern = hostExecutablePattern
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
        process.arguments = ["-TERM", "-f", pattern]
        do {
            try process.run()
            process.waitUntilExit()
            if process.terminationStatus == 0 {
                print("Video settings stopped current Host before ACK")
            } else {
                print("Video settings found no running Host to stop")
            }
        } catch {
            print("Video settings restart request failed: \(error)")
        }
    }
}
