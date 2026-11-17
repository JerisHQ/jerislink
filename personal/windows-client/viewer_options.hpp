#pragma once

// Viewer launch options: command line + saved settings -> one connection config.
// Pure C++ (no Win32), so the resolution rules can be unit-tested anywhere.
//
// Priority, per value:
//   host (Mac) IP : --source-ip  > saved HostIp > JERISLINK_SOURCE_IP
//   this PC's IP  : --bind-ip    > Auto: match the Mac address (tailnet or
//                   Tailcat, see bind_choices.hpp), falling back to the first
//                   active 100.64.0.0/10 address. A BindIp value saved by an
//                   older build is ignored.
//   codec/bitrate : --codec/--bitrate-mbps > saved > defaults (h264, 25)

#include "bind_choices.hpp"

#include <cstdint>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace jl {

struct SavedSettings {
    std::string hostIp;   // empty = not set
    std::string codec = "h264";
    uint16_t bitrateMbps = 25;
};

struct Options {
    std::string bindIp;
    std::string sourceIp;
    uint16_t port = 38402;
    uint16_t controlPort = 38400;
    uint16_t mouseUdpPort = 38412;
    bool controlEnabled = true;
    std::string mouseMoveTransport = "udp";
    double scrollScale = 1.0;
    std::string videoBackend = "auto";
    std::string codec = "h264";
    uint16_t bitrateMbps = 25;
    std::string presentMode = "waitable";  // max frame latency 2; "waitable1": latency 1 (G2 behaviour); "nowait": no frame-latency object
    std::string lossRecovery = "strict";
    std::string nack = "on";  // on: use NACK when the host supports it (strict only)
    std::string abr = "on";   // on: send MRM1 0x42 receiver reports when the host supports ABR
    std::string audio = "on";  // on: ask the host for audio (MRM1 0x45) and play it; Ctrl+Alt+M mutes locally
    int idleTimeoutMs = 8000;
    int startupTimeoutMs = 180000;
    uint32_t width = 3712;
    uint32_t height = 2088;
    bool widthExplicit = false;
    bool heightExplicit = false;
    uint32_t fps = 60;
    uint32_t windowWidth = 1280;
    uint32_t windowHeight = 720;
    bool startMaximized = true;
};

enum class LaunchStatus { Ok, NeedsSetup, NoTailnet, InvalidArgs };

struct LaunchRequest {
    LaunchStatus status = LaunchStatus::InvalidArgs;
    Options options;
    bool openSettings = false;       // --settings: show the settings dialog first
    std::string printConfigPath;     // --print-config PATH: write the result and exit
    std::string hostSource = "none"; // cli | saved | env | none
    std::string bindSource = "none"; // cli | auto | none
    std::string bindReason = "none"; // cli | auto-tailnet | auto-tailcat | fallback | none
    std::string error;
};

inline const char* statusName(LaunchStatus s) {
    switch (s) {
    case LaunchStatus::Ok: return "ok";
    case LaunchStatus::NeedsSetup: return "needs-setup";
    case LaunchStatus::NoTailnet: return "no-tailnet";
    case LaunchStatus::InvalidArgs: return "invalid-args";
    }
    return "unknown";
}

// args: command-line arguments without argv[0].
inline LaunchRequest resolveLaunch(const std::vector<std::string>& args,
                                   const SavedSettings& saved,
                                   const std::string& envSourceIp,
                                   const BindDetection& detected) {
    LaunchRequest r;
    Options& o = r.options;
    o.codec = saved.codec;
    o.bitrateMbps = saved.bitrateMbps;

    auto invalid = [&](const std::string& why) {
        r.status = LaunchStatus::InvalidArgs;
        r.error = why;
        return r;
    };

    try {
        for (size_t i = 0; i < args.size(); ++i) {
            const std::string& k = args[i];
            if (k == "--no-control") { o.controlEnabled = false; continue; }
            if (k == "--start-maximized") { o.startMaximized = true; continue; }
            if (k == "--settings") { r.openSettings = true; continue; }
            if (i + 1 >= args.size()) return invalid("missing value for " + k);
            const std::string& v = args[++i];
            if (k == "--bind-ip") { o.bindIp = v; r.bindSource = "cli"; }
            else if (k == "--source-ip") { o.sourceIp = v; r.hostSource = "cli"; }
            else if (k == "--print-config") r.printConfigPath = v;
            else if (k == "--port") o.port = static_cast<uint16_t>(std::stoi(v));
            else if (k == "--control-port") o.controlPort = static_cast<uint16_t>(std::stoi(v));
            else if (k == "--mouse-udp-port") o.mouseUdpPort = static_cast<uint16_t>(std::stoi(v));
            else if (k == "--idle-timeout-ms") o.idleTimeoutMs = std::stoi(v);
            else if (k == "--startup-timeout-ms") o.startupTimeoutMs = std::stoi(v);
            else if (k == "--width") { o.width = static_cast<uint32_t>(std::stoul(v)); o.widthExplicit = true; }
            else if (k == "--height") { o.height = static_cast<uint32_t>(std::stoul(v)); o.heightExplicit = true; }
            else if (k == "--fps") o.fps = static_cast<uint32_t>(std::stoul(v));
            else if (k == "--window-width") o.windowWidth = static_cast<uint32_t>(std::stoul(v));
            else if (k == "--window-height") o.windowHeight = static_cast<uint32_t>(std::stoul(v));
            else if (k == "--video-backend") o.videoBackend = v;
            else if (k == "--codec") o.codec = v;
            else if (k == "--bitrate-mbps") o.bitrateMbps = static_cast<uint16_t>(std::stoul(v));
            else if (k == "--present-mode") o.presentMode = v;
            else if (k == "--loss-recovery") o.lossRecovery = v;
            else if (k == "--nack") o.nack = v;
            else if (k == "--abr") o.abr = v;
            else if (k == "--audio") o.audio = v;
            else if (k == "--mouse-move-transport") o.mouseMoveTransport = v;
            else if (k == "--scroll-scale") o.scrollScale = std::stod(v);
            else return invalid("unknown argument " + k);
        }
    } catch (...) {
        return invalid("bad number in arguments");
    }

    if (o.presentMode != "waitable" && o.presentMode != "waitable1" && o.presentMode != "nowait")
        return invalid("bad --present-mode");
    if (o.videoBackend != "auto" && o.videoBackend != "hardware" && o.videoBackend != "cpu")
        return invalid("bad --video-backend");
    if (o.codec != "auto" && o.codec != "h264" && o.codec != "hevc") return invalid("bad --codec");
    if (o.bitrateMbps != 0 && (o.bitrateMbps < 4 || o.bitrateMbps > 100)) return invalid("bad --bitrate-mbps");
    if (o.lossRecovery != "legacy" && o.lossRecovery != "strict") return invalid("bad --loss-recovery");
    if (o.nack != "on" && o.nack != "off") return invalid("bad --nack");
    if (o.abr != "on" && o.abr != "off") return invalid("bad --abr");
    if (o.audio != "on" && o.audio != "off") return invalid("bad --audio");
    if (o.mouseMoveTransport != "tcp" && o.mouseMoveTransport != "udp") return invalid("bad --mouse-move-transport");
    if (o.scrollScale <= 0.0 || o.scrollScale > 8.0) return invalid("bad --scroll-scale");
    if (o.widthExplicit != o.heightExplicit) return invalid("--width and --height go together");

    if (o.sourceIp.empty() && isIPv4(saved.hostIp)) { o.sourceIp = saved.hostIp; r.hostSource = "saved"; }
    if (o.sourceIp.empty() && !envSourceIp.empty()) { o.sourceIp = envSourceIp; r.hostSource = "env"; }

    if (!o.bindIp.empty()) r.bindReason = "cli";
    if (o.bindIp.empty()) {
        const AutoBind a = autoBindFor(o.sourceIp, detected);
        if (!a.ip.empty()) {
            o.bindIp = a.ip;
            r.bindSource = "auto";
        }
        r.bindReason = a.reason;
    }

    if (o.sourceIp.empty()) r.status = LaunchStatus::NeedsSetup;
    else if (o.bindIp.empty()) r.status = LaunchStatus::NoTailnet;
    else r.status = LaunchStatus::Ok;
    return r;
}

// Tailnet detection only (no Tailcat bridge).
inline LaunchRequest resolveLaunch(const std::vector<std::string>& args,
                                   const SavedSettings& saved,
                                   const std::string& envSourceIp,
                                   const std::optional<std::string>& detectedTailnetIp) {
    return resolveLaunch(args, saved, envSourceIp, BindDetection{detectedTailnetIp, false});
}

inline std::string describeLaunch(const LaunchRequest& r) {
    std::ostringstream s;
    s << "status=" << statusName(r.status) << "\n"
      << "host=" << r.options.sourceIp << "\n"
      << "host_source=" << r.hostSource << "\n"
      << "bind=" << r.options.bindIp << "\n"
      << "bind_source=" << r.bindSource << "\n"
      << "bind_reason=" << r.bindReason << "\n"
      << "codec=" << r.options.codec << "\n"
      << "bitrate_mbps=" << r.options.bitrateMbps << "\n"
      << "open_settings=" << (r.openSettings ? 1 : 0) << "\n";
    if (!r.error.empty()) s << "error=" << r.error << "\n";
    return s.str();
}

// The launch screen shows first unless the Mac's address came on the command
// line (scripts, shortcuts with --source-ip); --settings or Shift held while
// starting shows it then too. Bad arguments never reach it.
inline bool showLaunchScreen(const LaunchRequest& r, bool shiftHeld) {
    if (r.status == LaunchStatus::InvalidArgs || !r.printConfigPath.empty()) return false;
    if (r.openSettings || shiftHeld) return true;
    return r.hostSource != "cli";
}

// After the launch screen the address typed there (saved as HostIp) is the
// one to use, so --source-ip and --settings are dropped from the arguments.
inline std::vector<std::string> argsAfterLaunchScreen(const std::vector<std::string>& args) {
    std::vector<std::string> out;
    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--settings") continue;
        if (args[i] == "--source-ip") {
            ++i;  // and its value
            continue;
        }
        out.push_back(args[i]);
    }
    return out;
}

// Arguments for the process that comes back to the launch screen after a
// session ends (Disconnect, lost stream, error): the same arguments plus
// --settings, once.
inline std::vector<std::string> argsForRelaunch(const std::vector<std::string>& args) {
    std::vector<std::string> out;
    for (const auto& a : args) {
        if (a != "--settings") out.push_back(a);
    }
    out.push_back("--settings");
    return out;
}

// Debug mode: JERISLINK_DEBUG=1 (exactly "1") turns on debug-only
// diagnostics, such as the CPU-decode first-frame BMP in %TEMP%. Unset or any
// other value: off.
inline bool debugModeEnabled(const std::string& envValue) {
    return envValue == "1";
}

}  // namespace jl
