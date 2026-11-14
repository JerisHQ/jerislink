#pragma once

#include <cstdint>

// Remembers which mouse buttons the viewer has sent down to the host, so that
// every down sent gets exactly one up, even when the matching WM_*BUTTONUP
// never reaches the viewer (focus moved, capture taken by another window).
// Pure: the viewer passes a sender, the unit test passes a recorder.
class RemoteButtons {
public:
    static constexpr uint8_t kCount = 3;  // 0 = left, 1 = right, 2 = middle

    void down(uint8_t button) {
        if (button < kCount) held_[button] = true;
    }

    // True when a down was sent for this button and the up must be sent now.
    bool up(uint8_t button) {
        if (button >= kCount || !held_[button]) return false;
        held_[button] = false;
        return true;
    }

    bool held(uint8_t button) const { return button < kCount && held_[button]; }

    bool anyHeld() const {
        for (bool h : held_) if (h) return true;
        return false;
    }

    // Sends an up for every button still held. Returns a bit mask of the
    // buttons released (bit 0 = left), 0 when nothing was held.
    template <typename SendUp>
    uint8_t releaseAll(SendUp&& sendUp) {
        uint8_t mask = 0;
        for (uint8_t b = 0; b < kCount; ++b) {
            if (!held_[b]) continue;
            held_[b] = false;
            mask |= static_cast<uint8_t>(1u << b);
            sendUp(b);
        }
        return mask;
    }

private:
    bool held_[kCount] = {false, false, false};
};
