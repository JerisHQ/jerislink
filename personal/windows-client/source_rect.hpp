#pragma once

#include <algorithm>
#include <cmath>
#include <cstdint>

// Picks the part of a decoded surface that holds the remote picture.
//
// The Mac host (since candidate 4) encodes at a 16-aligned size, for example
// 1920x1080 -> 1920x1088, and ScreenCaptureKit (preservesAspectRatio) centres
// the picture inside that frame with thin black bars. The host reports its
// native framebuffer size in the VIDEO_CONFIG ACK. Showing the whole 1088-row
// surface would scale every pixel by 1080/1088 on a 1080p window; cropping
// rows 0..1079 would show the top bar and lose the bottom rows.
struct JerisSourceRect {
    uint32_t x = 0;
    uint32_t y = 0;
    uint32_t w = 0;
    uint32_t h = 0;
};

// codedW/codedH: decoder output frame size (MF_MT_FRAME_SIZE).
// aperture*: decoder display aperture, or haveAperture=false.
// remoteW/remoteH: host framebuffer size from the ACK (0 if unknown).
inline JerisSourceRect jerisPickSourceRect(uint32_t codedW, uint32_t codedH,
                                           bool haveAperture,
                                           uint32_t apertureX, uint32_t apertureY,
                                           uint32_t apertureW, uint32_t apertureH,
                                           uint32_t remoteW, uint32_t remoteH) {
    JerisSourceRect full{0, 0, codedW, codedH};
    if (codedW == 0 || codedH == 0) return full;

    // A real conformance-window crop from the bitstream wins.
    if (haveAperture && apertureW > 0 && apertureH > 0 &&
        apertureX + apertureW <= codedW && apertureY + apertureH <= codedH &&
        (apertureW < codedW || apertureH < codedH)) {
        return JerisSourceRect{apertureX, apertureY, apertureW, apertureH};
    }
    if (remoteW == 0 || remoteH == 0) return full;

    // Aspect-fit the host framebuffer into the coded frame, centred, the same
    // way ScreenCaptureKit letterboxes. Only trust it for a small alignment
    // pad; anything larger means the sizes do not describe the same picture.
    const double scale = std::min(static_cast<double>(codedW) / remoteW,
                                  static_cast<double>(codedH) / remoteH);
    const uint32_t w = std::min<uint32_t>(
        codedW, static_cast<uint32_t>(std::llround(remoteW * scale)));
    const uint32_t h = std::min<uint32_t>(
        codedH, static_cast<uint32_t>(std::llround(remoteH * scale)));
    if (w == 0 || h == 0) return full;
    if (codedW - w > 16 || codedH - h > 16) return full;
    return JerisSourceRect{(codedW - w) / 2, (codedH - h) / 2, w, h};
}
