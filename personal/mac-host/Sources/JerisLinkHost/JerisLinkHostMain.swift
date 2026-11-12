import Foundation
import ApplicationServices

struct Options {
    var durationSeconds: Double = 10
    var width: Int32?
    var height: Int32?
    var fps: Int32 = 60
    var bitrateMbps: Int = 20
    var codec: VideoCodec = .h264
    var colorRange: String = "video"
    var keyframeInterval: Int32?
    var requestedMaxEncoderLatency: Double?
    var inputQueueMaxCount: Int?
    var maxFrameDelayCount: Int?
    var captureQueueDepth: Int = 3
    var h264Profile: String = "constrained-high"
    var outputPath: String = "output.h264"
    var bindIP: String?
    var clientIP: String?
    var clientPort: UInt16 = 38401
    var packetBytes: Int = 1200
    var controlPort: UInt16 = 38400
    var mouseUDPPort: UInt16?
    var controlClientIP: String?
    var controlInject = false
    var controlOnly = false
    var controlServerEnabled = true
    var requestPostEventAccess = false
    var requestScreenCaptureAccess = false
    var captureCursor = true
    var service: String?
    var showVersion = false
    var registerAgents = false
    var unregisterAgents = false
    var showAgentStatus = false

    static func parse() -> Options {
        var o = Options()
        let args = Array(CommandLine.arguments.dropFirst())
        var i = 0
        while i < args.count {
            let key = args[i]
            if key == "--control-inject" {
                o.controlInject = true
                i += 1
                continue
            }
            if key == "--control-only" {
                o.controlOnly = true
                i += 1
                continue
            }
            if key == "--no-control-server" {
                o.controlServerEnabled = false
                i += 1
                continue
            }
            if key == "--request-post-event-access" {
                o.requestPostEventAccess = true
                i += 1
                continue
            }
            if key == "--request-screen-capture-access" {
                o.requestScreenCaptureAccess = true
                i += 1
                continue
            }
            if key == "--version" {
                o.showVersion = true
                i += 1
                continue
            }
            if key == "--register" {
                o.registerAgents = true
                i += 1
                continue
            }
            if key == "--unregister" {
                o.unregisterAgents = true
                i += 1
                continue
            }
            if key == "--status" {
                o.showAgentStatus = true
                i += 1
                continue
            }
            if key == "--hide-cursor" {
                o.captureCursor = false
                i += 1
                continue
            }
            guard i + 1 < args.count else { break }
            let value = args[i + 1]
            switch key {
            case "--duration": o.durationSeconds = Double(value) ?? o.durationSeconds
            case "--width":
                if let parsed = Int32(value), parsed > 0 { o.width = parsed }
            case "--height":
                if let parsed = Int32(value), parsed > 0 { o.height = parsed }
            case "--fps": o.fps = Int32(value) ?? o.fps
            case "--bitrate-mbps": o.bitrateMbps = Int(value) ?? o.bitrateMbps
            case "--codec": o.codec = VideoCodec(rawValue: value.lowercased()) ?? o.codec
            case "--keyframe-interval":
                if let parsed = Int32(value), parsed > 0 { o.keyframeInterval = parsed }
            case "--requested-max-encoder-latency":
                if let parsed = Double(value), parsed >= 0 { o.requestedMaxEncoderLatency = parsed }
            case "--input-queue-max-count":
                if let parsed = Int(value), parsed > 0 { o.inputQueueMaxCount = parsed }
            case "--max-frame-delay-count":
                if let parsed = Int(value), parsed >= 0 { o.maxFrameDelayCount = parsed }
            case "--capture-queue-depth":
                if let parsed = Int(value), parsed >= 1 && parsed <= 8 { o.captureQueueDepth = parsed }
            case "--h264-profile":
                let normalized = value.lowercased()
                if ["constrained-high", "constrained-baseline", "main", "high"].contains(normalized) {
                    o.h264Profile = normalized
                }
            case "--range":
                let normalized = value.lowercased()
                if normalized == "video" || normalized == "full" {
                    o.colorRange = normalized
                }
            case "--output": o.outputPath = value
            case "--bind-ip": o.bindIP = value
            case "--client-ip": o.clientIP = value
            case "--client-port": o.clientPort = UInt16(value) ?? o.clientPort
            case "--packet-bytes": o.packetBytes = Int(value) ?? o.packetBytes
            case "--control-port": o.controlPort = UInt16(value) ?? o.controlPort
            case "--mouse-udp-port": o.mouseUDPPort = UInt16(value)
            case "--control-client-ip": o.controlClientIP = value
            case "--service": o.service = value
            default: break
            }
            i += 2
        }
        if o.codec == .hevc && o.outputPath == "output.h264" {
            o.outputPath = "output.hevc"
        }
        if o.controlClientIP == nil { o.controlClientIP = o.clientIP }
        return o
    }
}

@main
struct JerisLinkHostMain {
    static func main() async {
        var o = Options.parse()
        let hostVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "dev"
        if o.showVersion {
            print("JerisLink Host v\(hostVersion)")
            return
        }
        if o.registerAgents || o.unregisterAgents {
            let errors = o.registerAgents ? JerisLinkAgents.registerAll() : JerisLinkAgents.unregisterAll()
            JerisLinkAgents.statusLines().forEach { print($0) }
            if o.registerAgents && JerisLinkAgents.needsUserApproval {
                print("Allow JerisLink in System Settings > General > Login Items & Extensions.")
            }
            errors.forEach { fputs("Error: \($0)\n", stderr) }
            exit(errors.isEmpty ? 0 : 1)
        }
        if o.showAgentStatus {
            JerisLinkAgents.statusLines().forEach { print($0) }
            return
        }
        // Opened from Finder or at login as JerisLink.app with no arguments.
        if CommandLine.arguments.count == 1,
           Bundle.main.bundleIdentifier == JerisLinkAgents.launcherBundleIdentifier {
            await MainActor.run { JerisLinkLauncher.run() }
            return
        }
        if let service = o.service {
            guard service == "video" else {
                fputs("Fatal: unknown --service \(service) (expected video)\n", stderr)
                exit(2)
            }
            o = await VideoService.resolveOptions(base: o)
        }
        if o.requestPostEventAccess {
            let before = CGPreflightPostEventAccess()
            print("PostEvent permission before request: \(before)")
            let result = CGRequestPostEventAccess()
            let after = CGPreflightPostEventAccess()
            print("CGRequestPostEventAccess result: \(result)")
            print("PostEvent permission after request: \(after)")
            return
        }
        if o.requestScreenCaptureAccess {
            let before = CGPreflightScreenCaptureAccess()
            print("ScreenCapture permission before request: \(before)")
            let result = CGRequestScreenCaptureAccess()
            let after = CGPreflightScreenCaptureAccess()
            print("CGRequestScreenCaptureAccess result: \(result)")
            print("ScreenCapture permission after request: \(after)")
            return
        }
        if o.controlOnly {
            guard let bindIP = o.bindIP else {
                fputs("Fatal: --control-only requires --bind-ip\n", stderr)
                exit(2)
            }
            do {
                let control = ControlServer(bindIP: bindIP,
                                            allowedClientIP: o.controlClientIP,
                                            port: o.controlPort,
                                            inject: o.controlInject)
                try control.start()
                print("JerisLink control-only service")
                print("Control MRC1: \(bindIP):\(o.controlPort), allowedClient=\(o.controlClientIP ?? "any"), inject=\(o.controlInject ? "requested" : "off")")
                while true {
                    try await Task.sleep(for: .seconds(3600))
                }
            } catch {
                fputs("Fatal: \(error.localizedDescription)\n", stderr)
                exit(1)
            }
        }
        if (o.width == nil) != (o.height == nil) {
            fputs("Fatal: --width and --height must be provided together\n", stderr)
            exit(2)
        }
        let autoResolution = o.width == nil
        let outputURL = URL(fileURLWithPath: o.outputPath).standardizedFileURL
        print("JerisLink Host v\(hostVersion)")
        print("Output: \(outputURL.path)")
        if autoResolution {
            print("Resolution: auto-native framebuffer")
        } else {
            print("Resolution override: \(o.width!)x\(o.height!)")
        }
        print("Frame rate: \(o.fps) fps")
        print("Bitrate: \(o.bitrateMbps) Mbps")
        print("Codec: \(o.codec.rawValue)")
        print("Range: \(o.colorRange)")
        print("Keyframe interval: \(o.keyframeInterval ?? o.fps) frames")
        if let requested = o.requestedMaxEncoderLatency {
            print("Requested max encoder latency: \(requested)")
        }
        if let inputQueueMaxCount = o.inputQueueMaxCount {
            print("Input queue max count: \(inputQueueMaxCount)")
        }
        if let maxFrameDelayCount = o.maxFrameDelayCount {
            print("Max frame delay count: \(maxFrameDelayCount)")
        }
        print("Capture queue depth: \(o.captureQueueDepth)")
        print("H264 profile: \(o.h264Profile)")
        print("Duration: \(o.durationSeconds) s")

        do {
            var sender: UDPFrameSender?
            var control: ControlServer?
            var mouseUDP: MouseMoveUDPServer?
            if let bindIP = o.bindIP, let clientIP = o.clientIP {
                sender = try UDPFrameSender(bindIP: bindIP, clientIP: clientIP,
                                            clientPort: o.clientPort, packetBytes: o.packetBytes)
                if let mouseUDPPort = o.mouseUDPPort {
                    let server = MouseMoveUDPServer(bindIP: bindIP,
                                                    allowedClientIP: o.controlClientIP ?? clientIP,
                                                    port: mouseUDPPort)
                    try server.start()
                    mouseUDP = server
                }
                if o.controlServerEnabled {
                    control = ControlServer(bindIP: bindIP, allowedClientIP: o.controlClientIP,
                                            port: o.controlPort, inject: o.controlInject)
                    try control?.start()
                }
            }
            defer { control?.stop() }
            defer { mouseUDP?.stop() }

            let deadline = Date().addingTimeInterval(o.durationSeconds)
            var sessionIndex = 0
            while Date() < deadline {
                sessionIndex += 1
                let displayMode = try DisplayModeResolver.currentMainDisplay()
                let targetWidth = o.width ?? Int32(displayMode.pixelWidth)
                let targetHeight = o.height ?? Int32(displayMode.pixelHeight)

                print("Capture session \(sessionIndex): display=\(displayMode.displayID) logical=\(displayMode.logicalWidth)x\(displayMode.logicalHeight) framebuffer=\(displayMode.pixelWidth)x\(displayMode.pixelHeight) target=\(targetWidth)x\(targetHeight) refresh=\(String(format: "%.2f", displayMode.refreshRate))Hz")

                let encoder: any FrameEncoder
                switch o.codec {
                case .h264:
                    encoder = try H264Encoder(width: targetWidth, height: targetHeight, fps: o.fps,
                                              bitrate: o.bitrateMbps * 1_000_000,
                                              keyframeInterval: o.keyframeInterval ?? o.fps,
                                              requestedMaxEncoderLatency: o.requestedMaxEncoderLatency,
                                              inputQueueMaxCount: o.inputQueueMaxCount,
                                              maxFrameDelayCount: o.maxFrameDelayCount,
                                              profile: o.h264Profile,
                                              outputURL: outputURL, udpSender: sender)
                case .hevc:
                    encoder = try HEVCEncoder(width: targetWidth, height: targetHeight, fps: o.fps,
                                              bitrate: o.bitrateMbps * 1_000_000,
                                              keyframeInterval: o.keyframeInterval ?? o.fps,
                                              outputURL: outputURL, udpSender: sender)
                }

                let capture = ScreenCaptureHost(encoder: encoder)
                mouseUDP?.setKeyframeRequestHandler {
                    encoder.requestKeyframe()
                }
                try await capture.start(displayID: displayMode.displayID,
                                        targetWidth: Int(targetWidth), targetHeight: Int(targetHeight), fps: o.fps,
                                        fullRange: o.colorRange == "full", showsCursor: o.captureCursor,
                                        queueDepth: o.captureQueueDepth)
                print("Capture started. Move windows around to create motion.")

                var changedMode: ActiveDisplayMode?
                while Date() < deadline {
                    try await Task.sleep(for: .milliseconds(500))
                    if autoResolution,
                       let currentMode = try? DisplayModeResolver.currentMainDisplay(),
                       (currentMode.displayID != displayMode.displayID ||
                        currentMode.pixelWidth != displayMode.pixelWidth ||
                        currentMode.pixelHeight != displayMode.pixelHeight) {
                        changedMode = currentMode
                        break
                    }
                }

                await capture.stop()
                print("Capture session \(sessionIndex) complete: \(encoder.statsLine())")

                if let changedMode {
                    print("Display mode changed: \(displayMode.pixelWidth)x\(displayMode.pixelHeight) -> \(changedMode.pixelWidth)x\(changedMode.pixelHeight); restarting capture at native framebuffer size")
                    continue
                }
                break
            }
            if let control { print("Control complete: \(control.statsLine())") }
            if let mouseUDP { print("Mouse UDP complete: \(mouseUDP.statsLine())") }
            print("Wrote: \(outputURL.path)")
        } catch {
            fputs("Fatal: \(error.localizedDescription)\n", stderr)
            exit(1)
        }
    }
}
