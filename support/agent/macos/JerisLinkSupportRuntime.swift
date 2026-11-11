import Foundation

final class JerisLinkSupportRuntime {
    struct Configuration {
        let agentExecutable: String
        let transportExecutable: String
        let hostExecutable: String
        let brokerURL: String
        let singletonAddress: String
    }

    var onCode: ((String) -> Void)?
    var onIncoming: ((String, [String]) -> Void)?
    var onConnected: ((String) -> Void)?
    var onExpired: (() -> Void)?
    var onEnded: (() -> Void)?
    var onError: ((String) -> Void)?

    private let configuration: Configuration
    private let queue = DispatchQueue(label: "org.jeris.jerislink.support.runtime")
    private var agentProcess: Process?
    private var agentInput: Pipe?
    private var hostProcess: Process?
    private var stdoutBuffer = ""
    private var expectedAgentExit = false
    private var currentSupporter = ""

    init(configuration: Configuration) {
        self.configuration = configuration
    }

    var isRunning: Bool {
        agentProcess?.isRunning == true
    }

    func start() throws {
        guard agentProcess?.isRunning != true else { return }
        guard FileManager.default.isExecutableFile(atPath: configuration.agentExecutable) else {
            throw RuntimeError("Support Agent executable missing: \(configuration.agentExecutable)")
        }
        guard FileManager.default.isExecutableFile(atPath: configuration.transportExecutable) else {
            throw RuntimeError("Transport executable missing: \(configuration.transportExecutable)")
        }

        expectedAgentExit = false
        stdoutBuffer = ""
        currentSupporter = ""

        let process = Process()
        process.executableURL = URL(fileURLWithPath: configuration.agentExecutable)
        process.arguments = [
            "--broker", configuration.brokerURL,
            "--transport-binary", configuration.transportExecutable,
            "--poll-every", "500ms",
            "--singleton-listen", configuration.singletonAddress,
        ]

        let input = Pipe()
        let output = Pipe()
        let error = Pipe()
        process.standardInput = input
        process.standardOutput = output
        process.standardError = error
        agentInput = input
        agentProcess = process

        output.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty, let chunk = String(data: data, encoding: .utf8) else { return }
            self?.queue.async { self?.consume(chunk) }
        }
        error.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty, let chunk = String(data: data, encoding: .utf8) else { return }
            self?.queue.async {
                let message = chunk.trimmingCharacters(in: .whitespacesAndNewlines)
                if !message.isEmpty {
                    self?.dispatchError(message)
                }
            }
        }
        process.terminationHandler = { [weak self] process in
            output.fileHandleForReading.readabilityHandler = nil
            error.fileHandleForReading.readabilityHandler = nil
            self?.queue.async {
                guard let self else { return }
                if !self.expectedAgentExit && process.terminationStatus != 0 {
                    self.dispatchError("Support Agent exited with status \(process.terminationStatus).")
                }
            }
        }

        try process.run()
    }

    func generateNewCode() {
        send("new")
    }

    func approve() {
        send("approve")
    }

    func reject() {
        send("reject")
    }

    func endSession() {
        stopHost()
        expectedAgentExit = true
        send("end")
    }

    func shutdown() {
        stopHost()
        guard let process = agentProcess else { return }
        if process.isRunning {
            expectedAgentExit = true
            send("end")
            DispatchQueue.global().asyncAfter(deadline: .now() + 1.5) {
                if process.isRunning {
                    process.terminate()
                }
            }
        }
    }

    private func send(_ command: String) {
        guard let input = agentInput else { return }
        guard let data = (command + "\n").data(using: .utf8) else { return }
        do {
            try input.fileHandleForWriting.write(contentsOf: data)
        } catch {
            dispatchError("Unable to send \(command) to Support Agent: \(error.localizedDescription)")
        }
    }

    private func consume(_ chunk: String) {
        stdoutBuffer += chunk
        while let newline = stdoutBuffer.firstIndex(of: "\n") {
            let line = String(stdoutBuffer[..<newline]).trimmingCharacters(in: .whitespacesAndNewlines)
            stdoutBuffer.removeSubrange(...newline)
            if !line.isEmpty {
                handleLine(line)
            }
        }
    }

    private func handleLine(_ line: String) {
        if line.hasPrefix("Support Code: ") {
            let code = String(line.dropFirst("Support Code: ".count))
            DispatchQueue.main.async { [weak self] in self?.onCode?(code) }
            return
        }

        if line.hasPrefix("Incoming support request from ") {
            let payload = String(line.dropFirst("Incoming support request from ".count))
            let separator = ". Requested: "
            if let range = payload.range(of: separator) {
                let name = String(payload[..<range.lowerBound])
                let rawCaps = String(payload[range.upperBound...])
                let caps = rawCaps.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
                currentSupporter = name
                DispatchQueue.main.async { [weak self] in self?.onIncoming?(name, caps) }
            }
            return
        }

        if line.hasPrefix("Connected to "), line.hasSuffix(".") {
            let start = line.index(line.startIndex, offsetBy: "Connected to ".count)
            let end = line.index(before: line.endIndex)
            let name = String(line[start..<end])
            currentSupporter = name
            do {
                try startHost()
                DispatchQueue.main.async { [weak self] in self?.onConnected?(name) }
            } catch {
                dispatchError("Approved, but JerisLink Host failed to start: \(error.localizedDescription)")
                stopHost()
                expectedAgentExit = true
                send("end")
            }
            return
        }

        if line == "Support code expired. Type: new" {
            DispatchQueue.main.async { [weak self] in self?.onExpired?() }
            return
        }

        if line.hasPrefix("Support session ended.") {
            stopHost()
            DispatchQueue.main.async { [weak self] in self?.onEnded?() }
            return
        }
    }

    private func startHost() throws {
        if hostProcess?.isRunning == true { return }
        guard FileManager.default.isExecutableFile(atPath: configuration.hostExecutable) else {
            throw RuntimeError("Bundled JerisLinkHost missing: \(configuration.hostExecutable)")
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: configuration.hostExecutable)
        process.arguments = [
            "--duration", "86400",
            "--fps", "60",
            "--bitrate-mbps", "20",
            "--codec", "hevc",
            "--range", "full",
            "--keyframe-interval", "60",
            "--capture-queue-depth", "2",
            "--bind-ip", "127.0.0.1",
            "--client-ip", "127.0.0.1",
            "--client-port", "48402",
            "--packet-bytes", "1200",
            "--control-port", "48411",
            "--mouse-udp-port", "48412",
            "--control-client-ip", "127.0.0.1",
            "--control-inject",
            "--hide-cursor",
            "--output", "/dev/null",
        ]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        process.terminationHandler = { [weak self] process in
            guard process.terminationStatus != 0 else { return }
            DispatchQueue.main.async {
                self?.onError?("JerisLink Host exited unexpectedly with status \(process.terminationStatus).")
            }
        }
        try process.run()
        hostProcess = process
    }

    private func stopHost() {
        guard let process = hostProcess else { return }
        hostProcess = nil
        if process.isRunning {
            process.terminationHandler = nil
            process.terminate()
            DispatchQueue.global().asyncAfter(deadline: .now() + 1.5) {
                if process.isRunning {
                    process.interrupt()
                }
            }
        }
    }

    private func dispatchError(_ message: String) {
        DispatchQueue.main.async { [weak self] in self?.onError?(message) }
    }
}

private struct RuntimeError: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}
