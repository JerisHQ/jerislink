#pragma once
// r3 (Pepper's r2 review, item 2): which parts of the MRM1 UDP channel a
// viewer runs. A read-only view (--no-control) still needs the channel for
// picture and sound: the keep-alive PING (0x43) keeps the Mac's presence
// up, so it starts and keeps capturing, keyframe requests and NACKs repair
// the video, and the 0x45 audio request starts the sound. Only input
// (0x24 pointer moves) is switched off.
#include <string>

namespace jl::viewer {

struct UdpPlan {
    bool channel = false;    // open the MRM1 socket at all
    bool input = false;      // pointer moves (0x24) go over it
    bool keepAlive = false;  // PING (0x43) every second
    bool audio = false;      // start the player and send 0x45
};

inline UdpPlan udpPlan(bool controlEnabled, const std::string& moveTransport, bool hostSupportsNack,
                       bool audioRequested, bool hostSupportsAudio) {
    UdpPlan p;
    p.channel = !controlEnabled || moveTransport == "udp";
    p.input = controlEnabled && moveTransport == "udp";
    // A read-only view sends nothing else, so it pings even when the Mac
    // has no NACK support: the ping is what keeps its presence up.
    p.keepAlive = p.channel && (hostSupportsNack || !controlEnabled);
    p.audio = p.channel && audioRequested && hostSupportsAudio;
    return p;
}

}  // namespace jl::viewer
