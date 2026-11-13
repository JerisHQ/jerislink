#pragma once

// Viewer launch options: command line + saved settings -> one connection config.
// Pure C++ (no Win32), so the resolution rules can be unit-tested anywhere.
//
// Priority, per value:
//   host (Mac) IP : --source-ip  > saved HostIp > JERISLINK_SOURCE_IP
//   this PC's IP  : --bind-ip    > saved BindIp > first active 100.64.0.0/10 address
//   codec/bitrate : --codec/--bitrate-mbps > saved > defaults (h264, 25)

#include <cstdint>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace jl {

struct SavedSettings {
    std::string hostIp;   // empty = not set
    std::string bindIp;   // empty = detect automatically
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
    std::string presentMode = "nowait";
    std::string lossRecovery = "strict";
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
    std::string bindSource = "none"; // cli | saved | auto | none
    std::string error;
};

inline bool isIPv4(const std::string& s) {
    int parts = 0;
    size_t i = 0;
    while (i <= s.size()) {
        size_t j = i;
        while (j < s.size() && s[j] >= '0' && s[j] <= '9') ++j;
        const size_t len = j - i;
        if (len == 0 || len > 3) return false;
        if (len > 1 && s[i] == '0') return false;
        if (std::stoi(s.substr(i, len)) > 255) return false;
        ++parts;
        if (j == s.size()) break;
        if (s[j] != '.') return false;
        i = j + 1;
        if (i == s.size()) return false;
    }
    return parts == 4;
}

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
                                   const std::optional<std::string>& detectedBindIp) {
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
            else if (k == "--mouse-move-transport") o.mouseMoveTransport = v;
            else if (k == "--scroll-scale") o.scrollScale = std::stod(v);
            else return invalid("unknown argument " + k);
        }
    } catch (...) {
        return invalid("bad number in arguments");
    }

    if (o.presentMode != "waitable" && o.presentMode != "nowait") return invalid("bad --present-mode");
    if (o.videoBackend != "auto" && o.videoBackend != "hardware" && o.videoBackend != "cpu")
        return invalid("bad --video-backend");
    if (o.codec != "auto" && o.codec != "h264" && o.codec != "hevc") return invalid("bad --codec");
    if (o.bitrateMbps != 0 && (o.bitrateMbps < 4 || o.bitrateMbps > 100)) return invalid("bad --bitrate-mbps");
    if (o.lossRecovery != "legacy" && o.lossRecovery != "strict") return invalid("bad --loss-recovery");
    if (o.mouseMoveTransport != "tcp" && o.mouseMoveTransport != "udp") return invalid("bad --mouse-move-transport");
    if (o.scrollScale <= 0.0 || o.scrollScale > 8.0) return invalid("bad --scroll-scale");
    if (o.widthExplicit != o.heightExplicit) return invalid("--width and --height go together");

    if (o.sourceIp.empty() && isIPv4(saved.hostIp)) { o.sourceIp = saved.hostIp; r.hostSource = "saved"; }
    if (o.sourceIp.empty() && !envSourceIp.empty()) { o.sourceIp = envSourceIp; r.hostSource = "env"; }

    if (o.bindIp.empty() && isIPv4(saved.bindIp)) { o.bindIp = saved.bindIp; r.bindSource = "saved"; }
    if (o.bindIp.empty() && detectedBindIp && !detectedBindIp->empty()) {
        o.bindIp = *detectedBindIp;
        r.bindSource = "auto";
    }

    if (o.sourceIp.empty()) r.status = LaunchStatus::NeedsSetup;
    else if (o.bindIp.empty()) r.status = LaunchStatus::NoTailnet;
    else r.status = LaunchStatus::Ok;
    return r;
}

inline std::string describeLaunch(const LaunchRequest& r) {
    std::ostringstream s;
    s << "status=" << statusName(r.status) << "\n"
      << "host=" << r.options.sourceIp << "\n"
      << "host_source=" << r.hostSource << "\n"
      << "bind=" << r.options.bindIp << "\n"
      << "bind_source=" << r.bindSource << "\n"
      << "codec=" << r.options.codec << "\n"
      << "bitrate_mbps=" << r.options.bitrateMbps << "\n"
      << "open_settings=" << (r.openSettings ? 1 : 0) << "\n";
    if (!r.error.empty()) s << "error=" << r.error << "\n";
    return s.str();
}

}  // namespace jl
