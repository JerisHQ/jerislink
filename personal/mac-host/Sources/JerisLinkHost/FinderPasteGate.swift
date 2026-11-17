import Foundation
import AppKit

/// Cmd+V from the viewer while a file transfer runs and Finder is the
/// frontmost Mac app. Finder turns a text clipboard pasted into a folder into
/// a "Pasted <date>.textClipping" file, so a Cmd+V meant for the viewer's own
/// file paste (refused as busy) or a text copy synced from Windows mid-
/// transfer left stray clipping files. The host swallows that V down, its
/// repeats and its V up, logs `file.paste=refused reason=busy_finder`, and
/// asks the viewer to show its busy notice (NOTICE 0x5D). Every other key, and
/// Cmd+V in any other app or with no transfer running, passes unchanged.
///
/// `refuse` is asked only on a Cmd+V down, so the frontmost-app check (a main
/// thread hop) never runs per key. No key is ever logged.
struct FinderPasteGate {
    static let finderBundleID = "com.apple.finder"
    /// Wire semantics (keymap.hpp): 3 Command, 86 'V'.
    static let commandSemantic: UInt16 = 3
    static let vSemantic: UInt16 = 86

    enum Verdict: Equatable {
        case pass       // forward the key as usual
        case refused    // a new Cmd+V refused: log it and notify the viewer
        case swallow    // a repeat or the V up of a refused Cmd+V
    }

    private enum VKey { case up, passed, swallowed }
    private var commandDown = false
    private var vKey = VKey.up

    mutating func key(semantic: UInt16, down: Bool, refuse: () -> Bool) -> Verdict {
        if semantic == Self.commandSemantic {
            commandDown = down
            return .pass
        }
        guard semantic == Self.vSemantic else { return .pass }
        if !down {
            // A V up follows its V down: swallowed with it, so Finder never
            // sees a lone key up, or passed with it, so no key sticks.
            defer { vKey = .up }
            return vKey == .swallowed ? .swallow : .pass
        }
        switch vKey {
        case .swallowed: return .swallow  // auto-repeat of a refused V
        case .passed: return .pass        // auto-repeat of a forwarded V
        case .up: break
        }
        guard commandDown, refuse() else { vKey = .passed; return .pass }
        vKey = .swallowed
        return .refused
    }
}

/// The frontmost Mac app's bundle id. One main-thread hop; called only for a
/// Cmd+V while a transfer runs.
enum FrontmostApp {
    static func bundleID() -> String? {
        MainThreadHops.sync { NSWorkspace.shared.frontmostApplication?.bundleIdentifier }
    }
}
