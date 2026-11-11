import AppKit
import Foundation

private enum ScreenState {
    case starting
    case waiting(code: String)
    case incoming(code: String, supporter: String, capabilities: [String])
    case connected(supporter: String)
    case expired
    case ended
    case failed(String)
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var window: NSWindow!
    private let titleLabel = NSTextField(labelWithString: "JerisLink Support")
    private let subtitleLabel = NSTextField(labelWithString: "One-time remote support")
    private let codeCaption = NSTextField(labelWithString: "Support Code")
    private let codeLabel = NSTextField(labelWithString: "--- ---")
    private let statusLabel = NSTextField(wrappingLabelWithString: "Starting secure support session…")
    private let detailLabel = NSTextField(wrappingLabelWithString: "")
    private let primaryButton = NSButton(title: "", target: nil, action: nil)
    private let secondaryButton = NSButton(title: "", target: nil, action: nil)
    private var state: ScreenState = .starting
    private var runtime: JerisLinkSupportRuntime?
    private var lastCode = ""

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        buildWindow()
        startRuntime()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationWillTerminate(_ notification: Notification) {
        runtime?.shutdown()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    private func buildWindow() {
        window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 500, height: 390),
            styleMask: [.titled, .closable, .miniaturizable],
            backing: .buffered,
            defer: false
        )
        window.title = "JerisLink Support"
        window.center()
        window.isReleasedWhenClosed = false

        titleLabel.font = .systemFont(ofSize: 28, weight: .semibold)
        titleLabel.alignment = .center
        subtitleLabel.font = .systemFont(ofSize: 14, weight: .regular)
        subtitleLabel.textColor = .secondaryLabelColor
        subtitleLabel.alignment = .center

        codeCaption.font = .systemFont(ofSize: 12, weight: .medium)
        codeCaption.textColor = .secondaryLabelColor
        codeCaption.alignment = .center
        codeLabel.font = .monospacedDigitSystemFont(ofSize: 38, weight: .semibold)
        codeLabel.alignment = .center
        codeLabel.setContentCompressionResistancePriority(.required, for: .vertical)

        statusLabel.font = .systemFont(ofSize: 16, weight: .medium)
        statusLabel.alignment = .center
        detailLabel.font = .systemFont(ofSize: 13)
        detailLabel.textColor = .secondaryLabelColor
        detailLabel.alignment = .center

        primaryButton.bezelStyle = .rounded
        primaryButton.controlSize = .large
        primaryButton.target = self
        primaryButton.action = #selector(primaryPressed)

        secondaryButton.bezelStyle = .rounded
        secondaryButton.controlSize = .large
        secondaryButton.target = self
        secondaryButton.action = #selector(secondaryPressed)

        let buttonRow = NSStackView(views: [secondaryButton, primaryButton])
        buttonRow.orientation = .horizontal
        buttonRow.spacing = 12
        buttonRow.distribution = .fillEqually

        let spacer1 = NSView()
        spacer1.translatesAutoresizingMaskIntoConstraints = false
        spacer1.heightAnchor.constraint(equalToConstant: 8).isActive = true
        let spacer2 = NSView()
        spacer2.translatesAutoresizingMaskIntoConstraints = false
        spacer2.heightAnchor.constraint(equalToConstant: 10).isActive = true

        let stack = NSStackView(views: [
            titleLabel,
            subtitleLabel,
            spacer1,
            codeCaption,
            codeLabel,
            spacer2,
            statusLabel,
            detailLabel,
            buttonRow,
        ])
        stack.orientation = .vertical
        stack.spacing = 10
        stack.alignment = .centerX
        stack.translatesAutoresizingMaskIntoConstraints = false

        let content = NSView()
        content.addSubview(stack)
        window.contentView = content

        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: content.leadingAnchor, constant: 36),
            stack.trailingAnchor.constraint(equalTo: content.trailingAnchor, constant: -36),
            stack.centerYAnchor.constraint(equalTo: content.centerYAnchor),
            statusLabel.widthAnchor.constraint(equalTo: stack.widthAnchor),
            detailLabel.widthAnchor.constraint(equalTo: stack.widthAnchor),
            buttonRow.widthAnchor.constraint(equalToConstant: 360),
        ])

        render(.starting)
    }

    private func startRuntime() {
        let resources = Bundle.main.resourceURL ?? URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
        let environment = ProcessInfo.processInfo.environment
        let brokerURL = environment["JERIS_SUPPORT_BROKER_URL"] ?? "http://127.0.0.1:8781"
        let agentPath = environment["JERIS_SUPPORT_AGENT_BINARY"] ?? resources.appendingPathComponent("jeris-support-agent-darwin-arm64").path
        let transportPath = environment["JERIS_SUPPORT_TRANSPORT_BINARY"] ?? resources.appendingPathComponent("jeris-support-transport-darwin-arm64").path
        let bundledHost = resources.appendingPathComponent("JerisLinkHost").path
        let hostPath = environment["JERIS_SUPPORT_HOST_BINARY"] ?? bundledHost

        let config = JerisLinkSupportRuntime.Configuration(
            agentExecutable: agentPath,
            transportExecutable: transportPath,
            hostExecutable: hostPath,
            brokerURL: brokerURL,
            singletonAddress: "127.0.0.1:48771"
        )
        let runtime = JerisLinkSupportRuntime(configuration: config)
        self.runtime = runtime

        runtime.onCode = { [weak self] code in
            self?.lastCode = code
            self?.render(.waiting(code: code))
        }
        runtime.onIncoming = { [weak self] supporter, capabilities in
            guard let self else { return }
            self.render(.incoming(code: self.lastCode, supporter: supporter, capabilities: capabilities))
            NSApp.requestUserAttention(.criticalRequest)
        }
        runtime.onConnected = { [weak self] supporter in
            self?.render(.connected(supporter: supporter))
        }
        runtime.onExpired = { [weak self] in
            self?.render(.expired)
        }
        runtime.onEnded = { [weak self] in
            self?.render(.ended)
        }
        runtime.onError = { [weak self] message in
            self?.render(.failed(message))
        }

        do {
            try runtime.start()
        } catch {
            render(.failed(error.localizedDescription))
        }
    }

    @objc private func primaryPressed() {
        switch state {
        case .waiting:
            render(.starting)
            runtime?.generateNewCode()
        case .incoming:
            statusLabel.stringValue = "Approving support request…"
            primaryButton.isEnabled = false
            secondaryButton.isEnabled = false
            runtime?.approve()
        case .connected:
            statusLabel.stringValue = "Ending support session…"
            primaryButton.isEnabled = false
            runtime?.endSession()
        case .expired:
            render(.starting)
            runtime?.generateNewCode()
        case .ended, .failed:
            runtime?.shutdown()
            runtime = nil
            render(.starting)
            startRuntime()
        case .starting:
            break
        }
    }

    @objc private func secondaryPressed() {
        switch state {
        case .waiting:
            statusLabel.stringValue = "Ending support session…"
            secondaryButton.isEnabled = false
            primaryButton.isEnabled = false
            runtime?.endSession()
        case .incoming:
            statusLabel.stringValue = "Rejecting request…"
            secondaryButton.isEnabled = false
            primaryButton.isEnabled = false
            runtime?.reject()
        default:
            break
        }
    }

    private func render(_ newState: ScreenState) {
        state = newState
        primaryButton.isEnabled = true
        secondaryButton.isEnabled = true
        codeCaption.isHidden = false
        codeLabel.isHidden = false
        detailLabel.isHidden = false
        secondaryButton.isHidden = false

        switch newState {
        case .starting:
            codeLabel.stringValue = "--- ---"
            statusLabel.stringValue = "Starting secure support session…"
            detailLabel.stringValue = "Creating a fresh one-time Tailcat identity."
            primaryButton.title = "Starting…"
            primaryButton.isEnabled = false
            secondaryButton.isHidden = true
        case .waiting(let code):
            codeLabel.stringValue = code
            statusLabel.stringValue = "Waiting for supporter…"
            detailLabel.stringValue = "Share only this code. Remote control cannot start until you approve the request."
            primaryButton.title = "Generate New Code"
            secondaryButton.title = "End Session"
        case .incoming(let code, let supporter, let capabilities):
            codeLabel.stringValue = code
            statusLabel.stringValue = "Incoming request from \(supporter)"
            let caps = capabilities.isEmpty ? "No capabilities listed" : capabilities.joined(separator: " • ")
            detailLabel.stringValue = "Requested: \(caps)"
            primaryButton.title = "Approve"
            secondaryButton.title = "Reject"
        case .connected(let supporter):
            codeCaption.isHidden = true
            codeLabel.isHidden = true
            statusLabel.stringValue = "Connected to \(supporter)"
            detailLabel.stringValue = "Screen, keyboard/mouse and clipboard are available for this one-time session."
            primaryButton.title = "End Session"
            secondaryButton.isHidden = true
        case .expired:
            codeLabel.stringValue = "Expired"
            statusLabel.stringValue = "Support code expired"
            detailLabel.stringValue = "Generate a fresh code to continue."
            primaryButton.title = "Generate New Code"
            secondaryButton.isHidden = true
        case .ended:
            codeCaption.isHidden = true
            codeLabel.isHidden = true
            statusLabel.stringValue = "Support session ended"
            detailLabel.stringValue = "Temporary transport credentials have been destroyed."
            primaryButton.title = "Start New Session"
            secondaryButton.isHidden = true
        case .failed(let message):
            codeCaption.isHidden = true
            codeLabel.isHidden = true
            statusLabel.stringValue = "Unable to start support session"
            detailLabel.stringValue = message
            primaryButton.title = "Retry"
            secondaryButton.isHidden = true
        }
    }
}

func runOrchestrationSelfTest() -> Int32 {
    let fm = FileManager.default
    let dir = fm.temporaryDirectory.appendingPathComponent("jerislink-support-selftest-\(UUID().uuidString)")
    do {
        try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: dir) }

        let hostStarted = dir.appendingPathComponent("host-started")
        let hostStopped = dir.appendingPathComponent("host-stopped")
        let fakeAgent = dir.appendingPathComponent("fake-agent.sh")
        let fakeTransport = dir.appendingPathComponent("fake-transport.sh")
        let fakeHost = dir.appendingPathComponent("fake-host.sh")

        let agentScript = """
        #!/bin/sh
        echo 'Support Code: 123 456'
        (sleep 0.35; echo 'Incoming support request from Alice. Requested: view, input, clipboard') &
        while IFS= read -r line; do
          case "$line" in
            approve)
              echo 'Connected to Alice.'
              echo 'Command: end'
              ;;
            reject)
              echo 'Support request rejected.'
              echo 'Support Code: 123 456'
              ;;
            new)
              echo 'Support Code: 654 321'
              ;;
            end)
              echo 'Support session ended. Temporary transport credentials destroyed.'
              exit 0
              ;;
          esac
        done
        """
        let transportScript = "#!/bin/sh\nexit 0\n"
        let hostScript = """
        #!/bin/sh
        echo started > '\(hostStarted.path)'
        trap "echo stopped > '\(hostStopped.path)'; exit 0" TERM INT
        while true; do sleep 1; done
        """

        try agentScript.write(to: fakeAgent, atomically: true, encoding: .utf8)
        try transportScript.write(to: fakeTransport, atomically: true, encoding: .utf8)
        try hostScript.write(to: fakeHost, atomically: true, encoding: .utf8)
        try fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: fakeAgent.path)
        try fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: fakeTransport.path)
        try fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: fakeHost.path)

        let runtime = JerisLinkSupportRuntime(configuration: .init(
            agentExecutable: fakeAgent.path,
            transportExecutable: fakeTransport.path,
            hostExecutable: fakeHost.path,
            brokerURL: "http://127.0.0.1:8781",
            singletonAddress: "127.0.0.1:49771"
        ))

        let codeSem = DispatchSemaphore(value: 0)
        let incomingSem = DispatchSemaphore(value: 0)
        let connectedSem = DispatchSemaphore(value: 0)
        let endedSem = DispatchSemaphore(value: 0)
        var selfTestError: String?
        runtime.onCode = { _ in codeSem.signal() }
        runtime.onIncoming = { supporter, _ in
            if supporter != "Alice" { selfTestError = "wrong supporter" }
            incomingSem.signal()
        }
        runtime.onConnected = { supporter in
            if supporter != "Alice" { selfTestError = "wrong connected supporter" }
            connectedSem.signal()
        }
        runtime.onEnded = { endedSem.signal() }
        runtime.onError = { message in selfTestError = message }

        try runtime.start()
        guard wait(codeSem), wait(incomingSem) else {
            fputs("P2_SELFTEST_FAIL: waiting/incoming timeout\n", stderr)
            runtime.shutdown()
            return 1
        }
        if fm.fileExists(atPath: hostStarted.path) {
            fputs("P2_SELFTEST_FAIL: Host started before approval\n", stderr)
            runtime.shutdown()
            return 1
        }
        print("PRE_APPROVAL_HOST_NOT_STARTED_PASS")

        runtime.approve()
        guard wait(connectedSem) else {
            fputs("P2_SELFTEST_FAIL: connected timeout\n", stderr)
            runtime.shutdown()
            return 1
        }
        guard waitForFile(hostStarted.path, timeout: 2.0) else {
            fputs("P2_SELFTEST_FAIL: Host did not start after approval\n", stderr)
            runtime.shutdown()
            return 1
        }
        print("POST_APPROVAL_HOST_STARTED_PASS")

        runtime.endSession()
        guard wait(endedSem), waitForFile(hostStopped.path, timeout: 3.0) else {
            fputs("P2_SELFTEST_FAIL: End did not stop Host/session\n", stderr)
            runtime.shutdown()
            return 1
        }
        if let selfTestError {
            fputs("P2_SELFTEST_FAIL: \(selfTestError)\n", stderr)
            return 1
        }
        print("END_STOPS_HOST_PASS")
        print("QS_TC1_P2_ORCHESTRATION_PASS")
        return 0
    } catch {
        fputs("P2_SELFTEST_FAIL: \(error.localizedDescription)\n", stderr)
        return 1
    }
}

private func wait(_ semaphore: DispatchSemaphore, timeout: Double = 3.0) -> Bool {
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        if semaphore.wait(timeout: .now()) == .success { return true }
        RunLoop.main.run(until: Date().addingTimeInterval(0.02))
    }
    return false
}

private func waitForFile(_ path: String, timeout: Double) -> Bool {
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        if FileManager.default.fileExists(atPath: path) { return true }
        RunLoop.main.run(until: Date().addingTimeInterval(0.02))
    }
    return false
}

@main
struct JerisLinkSupportMain {
    static func main() {
        if CommandLine.arguments.contains("--self-test") {
            exit(runOrchestrationSelfTest())
        }

        let application = NSApplication.shared
        let delegate = AppDelegate()
        application.delegate = delegate
        application.run()
    }
}
