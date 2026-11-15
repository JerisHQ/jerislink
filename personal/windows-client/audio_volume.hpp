// Viewer audio volume: the saved setting and its mapping to the WASAPI
// session level. Pure helpers, shared by the viewer and the console test.
#pragma once

#include <cstdint>

namespace jl::audio {

constexpr int kDefaultVolumePercent = 100;

inline int clampVolumePercent(int pct) {
    return pct < 0 ? 0 : (pct > 100 ? 100 : pct);
}

// HKCU\Software\Jeris\Jerislink\AudioVolumePercent (REG_DWORD). A missing or
// unreadable value (wrong type or size) means 100%; values above 100 clamp.
inline int volumePercentFromSaved(bool readOk, uint32_t raw) {
    if (!readOk) return kDefaultVolumePercent;
    return raw > 100 ? 100 : static_cast<int>(raw);
}

// ISimpleAudioVolume::SetMasterVolume level, 0.0-1.0. Linear, so the slider
// reads the same as the viewer's row in the Windows volume mixer.
inline float volumeScalar(int pct) {
    return static_cast<float>(clampVolumePercent(pct)) / 100.0f;
}

}  // namespace jl::audio
