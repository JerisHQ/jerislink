#pragma once

// "This PC's address": which local IPv4 the viewer binds to.
// Pure C++ (no Win32), so the rules can be unit-tested anywhere.
//
// Saved in HKCU ...\Jerislink\BindIp (REG_SZ, same format as before):
//   empty      Auto (match the Mac address), the default
//   an IPv4    manual choice, used as is
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
#include <vector>

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

enum class BindKind { Auto, Tailnet, Tailcat, Saved };

struct BindChoice {
    BindKind kind;
    std::string ip;          // shown to the user (empty for Auto)
    std::string savedValue;  // written to BindIp when chosen
};

// Auto first, then each detected local IP as a manual choice. A saved manual
// IP that is not detected now stays in the list, so saving keeps it.
inline std::vector<BindChoice> bindChoices(const BindDetection& d, const std::string& savedBind) {
    std::vector<BindChoice> out;
    out.push_back({BindKind::Auto, "", ""});
    if (d.tailnetIp && !d.tailnetIp->empty()) {
        out.push_back({BindKind::Tailnet, *d.tailnetIp, *d.tailnetIp});
    }
    if (d.tailcat) out.push_back({BindKind::Tailcat, kTailcatBindIp, kTailcatBindIp});
    if (isIPv4(savedBind)) {
        bool listed = false;
        for (const auto& c : out) listed = listed || c.savedValue == savedBind;
        if (!listed) out.push_back({BindKind::Saved, savedBind, savedBind});
    }
    return out;
}

// The entry that matches what is saved; Auto when nothing matches.
inline int initialBindChoice(const std::vector<BindChoice>& choices, const std::string& savedBind) {
    for (size_t i = 0; i < choices.size(); ++i) {
        if (choices[i].savedValue == savedBind) return static_cast<int>(i);
    }
    return 0;
}

// Value to save. No valid pick: keep what was saved.
inline std::string bindValueToSave(const std::vector<BindChoice>& choices, int index,
                                   const std::string& savedBind) {
    if (index < 0 || static_cast<size_t>(index) >= choices.size()) return savedBind;
    return choices[static_cast<size_t>(index)].savedValue;
}

}  // namespace jl
