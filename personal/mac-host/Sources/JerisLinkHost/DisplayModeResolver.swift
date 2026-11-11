import CoreGraphics
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
