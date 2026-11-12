import CoreGraphics
@preconcurrency import ScreenCaptureKit
import Foundation

struct ActiveDisplayMode: Equatable {
    let displayID: CGDirectDisplayID
    let logicalWidth: Int
    let logicalHeight: Int
    let pixelWidth: Int
    let pixelHeight: Int
    let refreshRate: Double
}

enum DisplayModeResolver {
    static func currentMainDisplay() throws -> ActiveDisplayMode {
        let displayID = CGMainDisplayID()
        guard let mode = CGDisplayCopyDisplayMode(displayID) else {
            throw NSError(
                domain: "JerisLink.DisplayMode",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Unable to read the active main display mode"]
            )
        }

        let bounds = CGDisplayBounds(displayID)
        let pixelWidth = mode.pixelWidth
        let pixelHeight = mode.pixelHeight
        guard pixelWidth > 0, pixelHeight > 0,
              pixelWidth <= Int(UInt16.max), pixelHeight <= Int(UInt16.max)
        else {
            throw NSError(
                domain: "JerisLink.DisplayMode",
                code: 2,
                userInfo: [NSLocalizedDescriptionKey: "Invalid framebuffer size \(pixelWidth)x\(pixelHeight)"]
            )
        }

        return ActiveDisplayMode(
            displayID: displayID,
            logicalWidth: Int(bounds.width.rounded()),
            logicalHeight: Int(bounds.height.rounded()),
            pixelWidth: pixelWidth,
            pixelHeight: pixelHeight,
            refreshRate: mode.refreshRate
        )
    }
}

/// The display a capture session uses, sized from ScreenCaptureKit.
///
/// A long-running process cannot trust `CGDisplayCopyDisplayMode` for a display
/// that appeared after it started: on macOS 27.2 it keeps returning no mode
/// (0x0) for that display for the life of the process, while a fresh process
/// reads the real one. ScreenCaptureKit queries the window server on every call,
/// so the capture size comes from the SCDisplay itself (points x pointPixelScale).
struct CaptureTarget {
    let display: SCDisplay
    let logicalWidth: Int
    let logicalHeight: Int
    let pixelWidth: Int
    let pixelHeight: Int
    let scale: Double
    let refreshRate: Double

    var displayID: CGDirectDisplayID { display.displayID }

    func sameCapture(as other: CaptureTarget) -> Bool {
        displayID == other.displayID && pixelWidth == other.pixelWidth && pixelHeight == other.pixelHeight
    }

    var summary: String {
        "display=\(displayID) logical=\(logicalWidth)x\(logicalHeight) framebuffer=\(pixelWidth)x\(pixelHeight) scale=\(scale)"
    }
}

/// Cheap CoreGraphics view of the display layout, polled often. These values
/// stay current in a long-running process (the display mode does not), so a
/// change here triggers a fresh ScreenCaptureKit lookup.
struct DisplayLayoutFingerprint: Equatable {
    let mainDisplayID: CGDirectDisplayID
    let onlineDisplayIDs: [CGDirectDisplayID]
    let bounds: [CGRect]
    let modePixels: [Int]

    static func current() -> DisplayLayoutFingerprint {
        var count: UInt32 = 0
        var ids = [CGDirectDisplayID](repeating: 0, count: 32)
        if CGGetOnlineDisplayList(UInt32(ids.count), &ids, &count) != .success { count = 0 }
        let online = Array(ids.prefix(Int(count))).sorted()
        return DisplayLayoutFingerprint(
            mainDisplayID: CGMainDisplayID(),
            onlineDisplayIDs: online,
            bounds: online.map { CGDisplayBounds($0) },
            modePixels: online.flatMap { id -> [Int] in
                let mode = CGDisplayCopyDisplayMode(id)
                return [mode?.pixelWidth ?? 0, mode?.pixelHeight ?? 0]
            }
        )
    }
}

extension DisplayModeResolver {
    /// Picks the display to capture and its native framebuffer size.
    /// `pinnedDisplayID` (diagnostics, `--display-id`) wins when that display
    /// exists; otherwise the main display: the CoreGraphics main display if
    /// ScreenCaptureKit has it, else the display at the global origin.
    static func captureTarget(pinnedDisplayID: CGDirectDisplayID? = nil) async throws -> CaptureTarget {
        let content = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: true)
        let displays = content.displays
        let mainID = CGMainDisplayID()
        guard let display = displays.first(where: { pinnedDisplayID != nil && $0.displayID == pinnedDisplayID })
            ?? displays.first(where: { $0.displayID == mainID })
            ?? displays.first(where: { $0.frame.origin == .zero })
            ?? displays.first
        else {
            throw NSError(domain: "JerisLink.ScreenCapture", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "No captureable display found"])
        }

        // Prefer the real mode. CoreGraphics caches modes per process, so a
        // display that appeared or changed after launch can report no mode (or
        // a stale one) here; a fresh process always reads the current one.
        var mode = ProbedDisplayMode(CGDisplayCopyDisplayMode(display.displayID))
        if mode?.matches(display) != true {
            mode = probeModeInFreshProcess(display.displayID)
        }
        let rawWidth: Double
        let rawHeight: Double
        if let mode, mode.matches(display) {
            rawWidth = Double(mode.pixelWidth)
            rawHeight = Double(mode.pixelHeight)
        } else {
            let info = SCShareableContent.info(for: SCContentFilter(display: display, excludingWindows: []))
            let fallbackScale = Double(info.pointPixelScale) > 0 ? Double(info.pointPixelScale) : 1
            rawWidth = Double(display.width) * fallbackScale
            rawHeight = Double(display.height) * fallbackScale
        }
        // Even sizes keep 4:2:0 encoders happy.
        let pixelWidth = Int(rawWidth.rounded()) & ~1
        let pixelHeight = Int(rawHeight.rounded()) & ~1
        let scale = display.width > 0 ? rawWidth / Double(display.width) : 1
        guard pixelWidth > 0, pixelHeight > 0,
              pixelWidth <= Int(UInt16.max), pixelHeight <= Int(UInt16.max)
        else {
            throw NSError(domain: "JerisLink.DisplayMode", code: 2,
                          userInfo: [NSLocalizedDescriptionKey: "Invalid framebuffer size \(pixelWidth)x\(pixelHeight) for display \(display.displayID)"])
        }
        return CaptureTarget(
            display: display,
            logicalWidth: display.width,
            logicalHeight: display.height,
            pixelWidth: pixelWidth,
            pixelHeight: pixelHeight,
            scale: scale,
            refreshRate: mode?.refreshRate ?? 0
        )
    }

    static let probeModeFlag = "--probe-display-mode"

    /// Child side of `probeModeInFreshProcess`: print the current mode and exit.
    static func runModeProbe(_ argument: String) -> Never {
        guard let id = CGDirectDisplayID(argument),
              let mode = ProbedDisplayMode(CGDisplayCopyDisplayMode(id))
        else { exit(1) }
        print("\(mode.pixelWidth) \(mode.pixelHeight) \(mode.logicalWidth) \(mode.logicalHeight) \(mode.refreshRate)")
        exit(0)
    }

    static func probeModeInFreshProcess(_ id: CGDirectDisplayID) -> ProbedDisplayMode? {
        guard let executable = Bundle.main.executableURL else { return nil }
        let process = Process()
        let output = Pipe()
        process.executableURL = executable
        process.arguments = [probeModeFlag, String(id)]
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        do { try process.run() } catch { return nil }
        DispatchQueue.global().asyncAfter(deadline: .now() + 3) {
            if process.isRunning { process.terminate() }
        }
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationReason == .exit, process.terminationStatus == 0,
              let text = String(data: data, encoding: .utf8)
        else { return nil }
        let parts = text.split(whereSeparator: { $0 == " " || $0 == "\n" })
        guard parts.count == 5,
              let pw = Int(parts[0]), let ph = Int(parts[1]),
              let lw = Int(parts[2]), let lh = Int(parts[3]),
              let refresh = Double(parts[4])
        else { return nil }
        return ProbedDisplayMode(pixelWidth: pw, pixelHeight: ph,
                                 logicalWidth: lw, logicalHeight: lh, refreshRate: refresh)
    }
}

struct ProbedDisplayMode {
    let pixelWidth: Int
    let pixelHeight: Int
    let logicalWidth: Int
    let logicalHeight: Int
    let refreshRate: Double

    init(pixelWidth: Int, pixelHeight: Int, logicalWidth: Int, logicalHeight: Int, refreshRate: Double) {
        self.pixelWidth = pixelWidth
        self.pixelHeight = pixelHeight
        self.logicalWidth = logicalWidth
        self.logicalHeight = logicalHeight
        self.refreshRate = refreshRate
    }

    init?(_ mode: CGDisplayMode?) {
        guard let mode, mode.pixelWidth > 0, mode.pixelHeight > 0 else { return nil }
        self.init(pixelWidth: mode.pixelWidth, pixelHeight: mode.pixelHeight,
                  logicalWidth: mode.width, logicalHeight: mode.height, refreshRate: mode.refreshRate)
    }

    /// A cached mode is only trusted when it agrees with ScreenCaptureKit's point size.
    func matches(_ display: SCDisplay) -> Bool {
        logicalWidth == display.width && logicalHeight == display.height
    }
}
