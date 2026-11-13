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

/// Everything the video service reads from video-settings.plist. Each key falls
/// back to its default on its own, as the old video-watchdog.zsh did.
struct PersistedVideoSettings: Equatable {
    var codec = "h264"
    var bitrateMbps = 25
    var fps: Int32 = 60
    var keepDisplayAwake = false
    /// udpPaceMbps: missing = auto (UDPPacing.autoMbps), 0 = off, 1...1000 = Mbps.
    var udpPaceMbps: Int?
    var udpPaceBurstKB = UDPPacing.defaultBurstKB

    /// Apple's ScreenCaptureKit 60 fps sample uses queueDepth 5. With depth 2 a
    /// BetterDisplay 4K virtual screen stops delivering frames after the first
    /// few (macOS 27.2). 30 fps keeps the low-latency depth 2.
    var captureQueueDepth: Int { fps == 60 ? 5 : 2 }

    init() {}

    init(dictionary dict: [String: Any]) {
        if let codec = dict["codec"] as? String, codec == "h264" || codec == "hevc" { self.codec = codec }
        if let bitrate = Self.int(dict["bitrateMbps"]), (4...100).contains(bitrate) { bitrateMbps = bitrate }
        if let fps = Self.int(dict["fps"]), fps == 30 || fps == 60 { self.fps = Int32(fps) }
        keepDisplayAwake = Self.bool(dict["keepDisplayAwake"]) ?? false
        if let pace = Self.int(dict["udpPaceMbps"]), (0...1000).contains(pace) { udpPaceMbps = pace }
        if let burst = Self.int(dict["udpPaceBurstKB"]), (2...1024).contains(burst) { udpPaceBurstKB = burst }
    }

    var pacing: UDPPacing {
        UDPPacing(mbps: udpPaceMbps ?? UDPPacing.autoMbps(bitrateMbps: bitrateMbps),
                  burstBytes: udpPaceBurstKB * 1024)
    }

    static func load(from url: URL) -> PersistedVideoSettings {
        guard let data = try? Data(contentsOf: url),
              let object = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil),
              let dict = object as? [String: Any]
        else { return PersistedVideoSettings() }
        return PersistedVideoSettings(dictionary: dict)
    }

    var summary: String {
        "codec=\(codec) bitrate=\(bitrateMbps) Mbps fps=\(fps) captureQueueDepth=\(captureQueueDepth) keepDisplayAwake=\(keepDisplayAwake) \(pacing.summary)"
    }

    private static func isBool(_ n: NSNumber) -> Bool { CFGetTypeID(n) == CFBooleanGetTypeID() }

    private static func int(_ value: Any?) -> Int? {
        if let n = value as? NSNumber, !isBool(n) { return n.intValue }
        if let s = value as? String { return Int(s.trimmingCharacters(in: .whitespaces)) }
        return nil
    }

    /// `<true/>`, `1`, "true" or "1" mean true, like the old watchdog.
    private static func bool(_ value: Any?) -> Bool? {
        if let n = value as? NSNumber { return isBool(n) ? n.boolValue : n.intValue == 1 }
        if let s = value as? String { return s == "true" || s == "1" }
        return nil
    }
}

final class VideoSettingsController: @unchecked Sendable {
    private let lock = NSLock()
    private let fileURL: URL
    private let hostExecutablePattern: String
    private let restartOverride: (() -> Void)?

    static var defaultFileURL: URL {
        if let path = ProcessInfo.processInfo.environment["JERISLINK_VIDEO_SETTINGS"], !path.isEmpty {
            return URL(fileURLWithPath: path)
        }
        return FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/JerisLink", isDirectory: true)
            .appendingPathComponent("video-settings.plist")
    }

    /// `restart` replaces the launchd restart (self-test). Setting
    /// JERISLINK_NO_VIDEO_RESTART=1 logs instead of restarting (private test hosts).
    init(fileURL: URL = VideoSettingsController.defaultFileURL, restart: (() -> Void)? = nil) {
        self.fileURL = fileURL
        self.restartOverride = restart
        // Fallback for a video host started by hand from this executable.
        let executable = Bundle.main.executablePath ?? CommandLine.arguments[0]
        self.hostExecutablePattern = "^" + Self.extendedRegexEscaped(executable) + " --duration 86400( |$)"
    }

    /// ACK for a request that was not applied (not the configured viewer): the
    /// current persisted settings, status 0, flag 0x10 = ignored. Nothing is
    /// written and nothing restarts.
    func currentAck(ignored: Bool) -> VideoSettingsAck {
        let current: (codec: String, bitrateMbps: Int)
        lock.lock()
        current = readCurrent()
        lock.unlock()
        let displayMode = try? DisplayModeResolver.currentMainDisplay()
        let framebufferWidth = UInt16(displayMode?.pixelWidth ?? 0)
        let framebufferHeight = UInt16(displayMode?.pixelHeight ?? 0)
        var flags: UInt8 = 0x02 // host HEVC
        if framebufferWidth > 0 && framebufferHeight > 0 { flags |= 0x08 }
        if ignored { flags |= 0x10 }
        return VideoSettingsAck(
            status: 0,
            codec: current.codec == "hevc" ? 2 : 1,
            flags: flags,
            bitrateMbps: UInt16(current.bitrateMbps),
            framebufferWidth: framebufferWidth,
            framebufferHeight: framebufferHeight
        )
    }

    static func extendedRegexEscaped(_ text: String) -> String {
        var out = ""
        for ch in text {
            if "\\.[]()*+?{}|^$".contains(ch) { out.append("\\") }
            out.append(ch)
        }
        return out
    }

    /// Codec and bitrate persisted by the control service; h264 / 25 Mbps by default.
    static func readPersisted(from url: URL = defaultFileURL) -> (codec: String, bitrateMbps: Int) {
        let settings = PersistedVideoSettings.load(from: url)
        return (settings.codec, settings.bitrateMbps)
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
            } else {
                print("Video settings unchanged codec=\(codecName) bitrate_mbps=\(selectedBitrate); no restart")
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
        Self.readPersisted(from: fileURL)
    }

    private func persist(codec: String, bitrateMbps: Int) throws {
        let directory = fileURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        // Keep keys this controller does not own (fps, keepDisplayAwake).
        var object: [String: Any] = [:]
        if let data = try? Data(contentsOf: fileURL),
           let existing = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any] {
            object = existing
        }
        object["version"] = 1
        object["codec"] = codec
        object["bitrateMbps"] = bitrateMbps
        let data = try PropertyListSerialization.data(
            fromPropertyList: object,
            format: .xml,
            options: 0
        )
        try data.write(to: fileURL, options: .atomic)
        print("Video settings persisted codec=\(codec) bitrate_mbps=\(bitrateMbps)")
    }

    /// Restarts the video host so it picks up the new settings. The video host
    /// normally runs as the launchd agent org.jeris.jerislink.agent.video, so
    /// `launchctl kickstart -k` stops it and launchd starts it again at once.
    /// A video host started by hand is stopped with pkill instead.
    private func requestVideoRestart() {
        if let restartOverride {
            restartOverride()
            return
        }
        if ProcessInfo.processInfo.environment["JERISLINK_NO_VIDEO_RESTART"] == "1" {
            print("Video settings restart skipped (JERISLINK_NO_VIDEO_RESTART=1)")
            return
        }
        let kickstart = Process()
        kickstart.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        kickstart.arguments = ["kickstart", "-k", "gui/\(getuid())/\(JerisLinkAgents.videoLabel)"]
        kickstart.standardOutput = FileHandle.nullDevice
        kickstart.standardError = FileHandle.nullDevice
        if (try? kickstart.run()) != nil {
            kickstart.waitUntilExit()
            if kickstart.terminationStatus == 0 {
                print("Video settings restarted the video agent before ACK")
                return
            }
        }
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
