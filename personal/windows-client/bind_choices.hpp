#pragma once

// "This PC's address": which local IPv4 the viewer binds to. It is always
// set automatically from the Mac address; there is no manual choice
// (--bind-ip on the command line still overrides it). Connection info shows
// the result. Pure C++ (no Win32), so the rules can be unit-tested anywhere.
//
// Detection (viewer.cpp):
//   tailnet : first active adapter IPv4 in 100.64.0.0/10 (Tailscale range)
//   Tailcat : Tailcat is a userspace library with no adapter or IP of its own.
//             jeris-support-transport bridges it to loopback on this PC, so
//             the Tailcat address is 127.0.0.1 on both sides: the viewer
//             sends to 127.0.0.1 (the Mac host address is then a 127.x
//             address) and binds 127.0.0.1. The bridge counts as present
//             while a TCP listener is open on 127.0.0.1:48400 (its control
//             port).
//
// Auto, from the Mac host address:
//   100.64.0.0/10 and a local tailnet IP   -> that IP     (auto-tailnet)
//   127.0.0.0/8   and the Tailcat bridge   -> 127.0.0.1   (auto-tailcat)
//   otherwise                              -> the local tailnet IP if any
//                                             (fallback, the old rule), else none

#include <cstdint>
#include <optional>
#include <string>

namespace jl {

inline bool parseIPv4(const std::string& s, uint32_t& out) {
    uint32_t value = 0;
    int parts = 0;
    size_t i = 0;
    while (i <= s.size()) {
        size_t j = i;
        while (j < s.size() && s[j] >= '0' && s[j] <= '9') ++j;
        const size_t len = j - i;
        if (len == 0 || len > 3) return false;
        if (len > 1 && s[i] == '0') return false;
        const int octet = std::stoi(s.substr(i, len));
        if (octet > 255) return false;
        value = (value << 8) | static_cast<uint32_t>(octet);
        ++parts;
        if (j == s.size()) break;
        if (s[j] != '.') return false;
        i = j + 1;
        if (i == s.size()) return false;
    }
    if (parts != 4) return false;
    out = value;
    return true;
}

inline bool isIPv4(const std::string& s) {
    uint32_t v = 0;
    return parseIPv4(s, v);
}

inline bool isTailnetIPv4(const std::string& s) {
    uint32_t v = 0;
    return parseIPv4(s, v) && (v & 0xFFC00000u) == 0x64400000u;
}

inline bool isTailcatIPv4(const std::string& s) {
    uint32_t v = 0;
    return parseIPv4(s, v) && (v & 0xFF000000u) == 0x7F000000u;
}

inline constexpr char kTailcatBindIp[] = "127.0.0.1";
inline constexpr unsigned short kTailcatControlPort = 48400;

struct BindDetection {
    std::optional<std::string> tailnetIp;  // 100.64.0.0/10 address, if any
    bool tailcat = false;                  // bridge listening on 127.0.0.1:48400
};

struct AutoBind {
    std::string ip;            // empty: nothing to bind
    std::string reason;        // auto-tailnet | auto-tailcat | fallback | none
};

inline AutoBind autoBindFor(const std::string& macHost, const BindDetection& d) {
    const bool haveTailnet = d.tailnetIp && !d.tailnetIp->empty();
    if (isTailnetIPv4(macHost) && haveTailnet) return {*d.tailnetIp, "auto-tailnet"};
    if (isTailcatIPv4(macHost) && d.tailcat) return {kTailcatBindIp, "auto-tailcat"};
    if (haveTailnet) return {*d.tailnetIp, "fallback"};
    return {"", "none"};
}

}  // namespace jl
