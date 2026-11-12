import AppKit
import CoreGraphics
import Foundation
import ServiceManagement

/// launchd agents shipped inside JerisLink.app (Contents/Library/LaunchAgents) and
/// registered by the app itself through SMAppService (macOS 13+).
///
/// Each agent is its own process with KeepAlive, so a crash in one of them
/// (video host, control service, input helper) does not take down the others,
/// and launchd restarts it. This replaces the old zsh watchdog LaunchAgents.
enum JerisLinkAgents {
    static let launcherBundleIdentifier = "org.jeris.jerislink.host"

    static let inputHelperLabel = "org.jeris.jerislink.agent.input-helper"
    static let controlLabel = "org.jeris.jerislink.agent.control"
    static let videoLabel = "org.jeris.jerislink.agent.video"

    /// Registration order: input helper first, then control, then video.
    static let labels = [inputHelperLabel, controlLabel, videoLabel]

    static func service(_ label: String) -> SMAppService {
        SMAppService.agent(plistName: label + ".plist")
    }

    static func statusName(_ status: SMAppService.Status) -> String {
        switch status {
        case .notRegistered: return "notRegistered"
        case .enabled: return "enabled"
        case .requiresApproval: return "requiresApproval"
        case .notFound: return "notFound"
        @unknown default: return "unknown(\(status.rawValue))"
        }
    }

    static func statusLines() -> [String] {
        labels.map { "\($0): \(statusName(service($0).status))" }
    }

    static var needsUserApproval: Bool {
        labels.contains { service($0).status == .requiresApproval }
    }

    static var allEnabled: Bool {
        labels.allSatisfy { service($0).status == .enabled }
    }

    /// Registers every agent that is not enabled yet. Returns error lines.
    /// An agent waiting for the user's approval in Login Items is not an error.
    static func registerAll() -> [String] {
        var errors: [String] = []
        for label in labels {
            let agent = service(label)
            if agent.status == .enabled { continue }
            do {
                try agent.register()
            } catch {
                if agent.status == .requiresApproval { continue }
                errors.append("\(label): \(error.localizedDescription)")
            }
        }
        return errors
    }

    /// Unregisters every agent. Returns error lines.
    static func unregisterAll() -> [String] {
        var errors: [String] = []
        for label in labels.reversed() {
            let agent = service(label)
            if agent.status == .notRegistered || agent.status == .notFound { continue }
            do {
                try agent.unregister()
            } catch {
                errors.append("\(label): \(error.localizedDescription)")
            }
        }
        return errors
    }
}

/// What happens when the user opens JerisLink.app from Finder (no arguments):
/// register the background agents, ask for Screen Recording for this app, and
/// show one dialog with the result. The app then quits; the agents keep running.
@MainActor
enum JerisLinkLauncher {
    static func run() {
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)

        let errors = JerisLinkAgents.registerAll()
        let screenRecording = CGPreflightScreenCaptureAccess() || CGRequestScreenCaptureAccess()
        let needsApproval = JerisLinkAgents.needsUserApproval

        var lines: [String] = []
        if JerisLinkAgents.allEnabled {
            lines.append("JerisLink background services are running and start at login.")
        } else if needsApproval {
            lines.append("Allow JerisLink in System Settings > General > Login Items & Extensions so its background services can run.")
        }
        lines.append("Screen Recording for JerisLink: \(screenRecording ? "allowed" : "not allowed yet")")
        lines.append("Accessibility for JerisLink Input Helper is asked for by the helper itself the first time it runs.")
        if !errors.isEmpty {
            lines.append("")
            lines.append("Errors:")
            lines.append(contentsOf: errors)
        }
        lines.append("")
        lines.append(contentsOf: JerisLinkAgents.statusLines())
        print(lines.joined(separator: "\n"))

        let alert = NSAlert()
        alert.messageText = "JerisLink"
        alert.informativeText = lines.joined(separator: "\n")
        alert.addButton(withTitle: "OK")
        if needsApproval {
            alert.addButton(withTitle: "Open Login Items Settings")
        } else if !screenRecording {
            alert.addButton(withTitle: "Open Screen Recording Settings")
        }
        app.activate(ignoringOtherApps: true)
        let response = alert.runModal()
        guard response == .alertSecondButtonReturn else { return }
        if needsApproval {
            SMAppService.openSystemSettingsLoginItems()
        } else if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture") {
            NSWorkspace.shared.open(url)
        }
    }
}
