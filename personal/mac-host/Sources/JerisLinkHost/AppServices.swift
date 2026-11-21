import AppKit
import CoreGraphics
import CoreServices
import Foundation
import ServiceManagement

/// launchd agents shipped inside JerisLink.app (Contents/Library/LaunchAgents) and
/// registered by the app itself through SMAppService (macOS 13+).
///
/// Each agent is its own process with KeepAlive, so a crash in one of them
/// (video host, control service, input helper) does not take down the others,
/// and launchd restarts it. This replaces the old zsh watchdog LaunchAgents.
/// Where this process runs from. The video and control agents run from a
/// nested copy of the host, JerisLink Service.app, with the same bundle id and
/// signature (so Screen Recording and the defaults domain stay the same).
///
/// Why: ScreenCaptureKit and the HIServices calls check those agents in with
/// Launch Services as UIElement apps that never answer Apple events. Launch
/// Services matches a running app by bundle path, so while they ran from
/// JerisLink.app itself, opening the app from Spotlight, Finder or the Dock
/// was routed to them and failed with "The application is not open anymore".
/// Running them from another path leaves JerisLink.app free to start the
/// launcher.
enum JerisLinkBundle {
    static let serviceHelperPath = "Contents/Library/Helpers/JerisLink Service.app"

    /// True when this process is JerisLink Service.app inside JerisLink.app.
    static var isServiceHelper: Bool { isServiceHelper(Bundle.main.bundleURL) }

    static func isServiceHelper(_ bundleURL: URL) -> Bool {
        let parts = bundleURL.standardizedFileURL.pathComponents
        guard parts.count >= 5 else { return false }
        return parts.suffix(4).dropLast().elementsEqual(["Contents", "Library", "Helpers"])
            && parts[parts.count - 5].hasSuffix(".app")
            && parts.last == (serviceHelperPath as NSString).lastPathComponent
    }

    /// JerisLink.app: this bundle, or the app that contains the service helper.
    static var appURL: URL { appURL(for: Bundle.main.bundleURL) }

    static func appURL(for bundleURL: URL) -> URL {
        guard isServiceHelper(bundleURL) else { return bundleURL }
        return bundleURL.standardizedFileURL
            .deletingLastPathComponent()  // Helpers
            .deletingLastPathComponent()  // Library
            .deletingLastPathComponent()  // Contents
            .deletingLastPathComponent()  // JerisLink.app
    }

    /// The service helper was opened with no arguments (Finder, `open`):
    /// open JerisLink.app instead so the launcher runs there.
    static func openApp() {
        let open = Process()
        open.executableURL = URL(fileURLWithPath: "/usr/bin/open")
        open.arguments = [appURL.path]
        try? open.run()
        open.waitUntilExit()
    }

    static func selfTest() -> Int32 {
        var failures: Int32 = 0
        func check(_ ok: Bool, _ name: String) {
            print("\(ok ? "ok" : "FAIL"): bundle \(name)")
            if !ok { failures += 1 }
        }
        let app = URL(fileURLWithPath: "/Users/x/Applications/JerisLink.app")
        let helper = app.appendingPathComponent(serviceHelperPath)
        let send = app.appendingPathComponent("Contents/Library/Helpers/JerisLink Send.app")
        check(!isServiceHelper(app), "app is not the service helper")
        check(isServiceHelper(helper), "service helper detected")
        check(appURL(for: helper).path == app.path, "service helper resolves the app")
        check(appURL(for: app).path == app.path, "app resolves itself")
        check(!isServiceHelper(send), "send helper is not the service helper")
        check(!isServiceHelper(URL(fileURLWithPath: "/tmp/Helpers/X.app")), "loose Helpers dir ignored")
        return failures
    }
}

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

/// F5b: the Finder Service helper (JerisLink Send.app) inside this app.
///
/// The control agent calls this at every start, so the Finder item appears
/// after an install without opening the app. The control agent runs from
/// JerisLink Service.app, so the path is taken from JerisLink.app.
enum JerisLinkSendService {
    static var helperURL: URL {
        JerisLinkBundle.appURL.appendingPathComponent("Contents/Library/Helpers/JerisLink Send.app")
    }

    /// nil: this build has no helper. Otherwise whether Launch Services knows
    /// the helper at this app's path.
    static func ensureRegistered() -> Bool? {
        let helper = helperURL
        guard FileManager.default.fileExists(atPath: helper.path) else { return nil }
        let known = NSWorkspace.shared.urlForApplication(withBundleIdentifier: SendWire.helperBundleID)
        if known?.standardizedFileURL.path == helper.standardizedFileURL.path { return true }
        return LSRegisterURL(helper as CFURL, true) == noErr
    }

    /// Asks pbs to rebuild the Services menu from Launch Services. For the
    /// control agent, which has no AppKit app to call NSUpdateDynamicServices.
    /// Returns pbs's exit status, or nil if it could not run or took over 20 s.
    static func refreshServicesMenu() -> Int32? {
        let pbs = Process()
        pbs.executableURL = URL(fileURLWithPath: "/System/Library/CoreServices/pbs")
        pbs.arguments = ["-update"]
        pbs.standardOutput = FileHandle.nullDevice
        pbs.standardError = FileHandle.nullDevice
        do { try pbs.run() } catch { return nil }
        let deadline = Date().addingTimeInterval(20)
        while pbs.isRunning && Date() < deadline { usleep(100_000) }
        if pbs.isRunning { pbs.terminate(); return nil }
        return pbs.terminationStatus
    }
}

/// What happens when the user opens JerisLink.app from Finder (no arguments):
/// register the background agents, ask for Screen Recording for this app, and
/// show one dialog with the result. The app then quits; the agents keep running.
@MainActor
enum JerisLinkLauncher {
    /// F5b: makes sure Launch Services knows the Finder Service helper
    /// inside this app, then refreshes the Services menu. Returns a status
    /// line, or nil when there is no helper (a development build).
    static func registerSendService() -> String? {
        guard let registered = JerisLinkSendService.ensureRegistered() else { return nil }
        NSUpdateDynamicServices()
        return registered
            ? "Finder: right-click files > Quick Actions or Services > Send to JerisLink."
            : "Finder \"Send to JerisLink\" could not be registered."
    }

    static func run() {
        let app = NSApplication.shared
        app.setActivationPolicy(.accessory)

        let errors = JerisLinkAgents.registerAll()
        let sendService = registerSendService()
        let screenRecording = CGPreflightScreenCaptureAccess() || CGRequestScreenCaptureAccess()
        let needsApproval = JerisLinkAgents.needsUserApproval

        var lines: [String] = []
        if JerisLinkAgents.allEnabled {
            lines.append("JerisLink background services are running and start at login.")
        } else if needsApproval {
            lines.append("Allow JerisLink in System Settings > General > Login Items & Extensions so its background services can run.")
        }
        lines.append("Screen Recording for JerisLink: \(screenRecording ? "allowed" : "not allowed yet")")
        let conn = ConnectionSettings.state(url: ConnectionSettings.defaultURL)
        if conn.hasPlist && !conn.passwordSet {
            lines.append("⚠️ No connection password is set: viewers on the whitelist connect without one. Set it in 連線設定.")
        }
        lines.append("Accessibility for JerisLink Input Helper is asked for by the helper itself the first time it runs.")
        if let sendService { lines.append(sendService) }
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
        alert.addButton(withTitle: "連線設定…")
        if needsApproval {
            alert.addButton(withTitle: "Open Login Items Settings")
        } else if !screenRecording {
            alert.addButton(withTitle: "Open Screen Recording Settings")
        }
        app.activate(ignoringOtherApps: true)
        let response = alert.runModal()
        if response == .alertSecondButtonReturn {
            ConnectionSettingsWindow().runModal()
            return
        }
        guard response == .alertThirdButtonReturn else { return }
        if needsApproval {
            SMAppService.openSystemSettingsLoginItems()
        } else if let url = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture") {
            NSWorkspace.shared.open(url)
        }
    }
}
