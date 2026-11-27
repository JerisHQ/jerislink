#pragma once

#include <bitset>
#include <cstdint>
#include <utility>

namespace jl::holdback {

// H2 (Pepper's H2 review, item 4): until a VIDEO_CONFIG ACK says what the
// host is, the viewer does not know which keymap applies, so keys are held
// back (not sent), their ups too, and the host never gets a down without
// its up.
//
// Pepper's review of 8f8a33b, item 4a: a chord must not cross the moment
// the ACK arrives. If Ctrl was held back and C is pressed after the ACK,
// sending C alone would give the host a plain C. So while any key held back
// is still down (the chord is open), every new key down, the Windows key,
// the hook's Win+C / Win+Space / Caps Lock and mouse button downs are held
// back too, ACK or not. The chord ends when the last of its keys is up;
// what follows goes out as usual. Nothing held back is replayed later.
//
// Pure: the viewer passes the key state (isDown: is this virtual key down
// now?), the unit test passes its own.
enum class Reason : uint8_t {
    None,             // send it
    PlatformUnknown,  // no ACK yet
    ChordOpen,        // a key held back is still down
};

class KeyHoldBack {
public:
    // A key down (WM_KEYDOWN / WM_SYSKEYDOWN). known: an ACK was read.
    template <class IsDown>
    Reason keyDown(uint32_t vk, bool repeat, bool known, IsDown&& isDown) {
        if (vk < 256 && keys_.test(vk)) {
            // Auto-repeat of a key held back stays held back. A fresh press
            // means its up went elsewhere (focus moved): it starts over.
            if (repeat) return Reason::ChordOpen;
            keys_.reset(vk);
        }
        const Reason r = reason(known, isDown);
        if (r != Reason::None) {
            if (vk < 256) keys_.set(vk);
            ++count_;
        }
        return r;
    }
    // A key up: true when its down was held back, so its up is not sent
    // either.
    bool keyUp(uint32_t vk) {
        if (vk >= 256 || !keys_.test(vk)) return false;
        keys_.reset(vk);
        return true;
    }
    // The Windows key, from the low-level hook (WM_MR_WIN_DOWN / _UP).
    // The hook posts a down only for a fresh press, after it posted the
    // up or was reset, so a Windows key still held back here is one whose
    // up never came: it starts over, as a fresh key press does.
    template <class IsDown>
    Reason winDown(bool known, IsDown&& isDown) {
        win_ = false;
        const Reason r = reason(known, isDown);
        if (r != Reason::None) {
            win_ = true;
            ++count_;
        }
        return r;
    }
    bool winUp() { return std::exchange(win_, false); }
    // Win+C, Win+Space and Caps Lock from the hook: held back like a key
    // down. They come as one tap, so nothing is left to release.
    template <class IsDown>
    Reason hookTap(bool known, IsDown&& isDown) {
        const Reason r = reason(known, isDown);
        if (r != Reason::None) ++count_;
        return r;
    }
    // A mouse button down: the pointer does not depend on the keymap, so
    // only an open chord holds it back (Ctrl+click must not land as a plain
    // click). Its up is then not sent either (the viewer never noted the
    // down).
    template <class IsDown>
    Reason buttonDown(IsDown&& isDown) {
        if (!chordOpen(isDown)) return Reason::None;
        ++count_;
        return Reason::ChordOpen;
    }
    // A key held back is down now. A key whose up never came here (focus
    // moved) and is no longer down does not keep the chord open.
    template <class IsDown>
    bool chordOpen(IsDown&& isDown) const {
        if (win_) return true;
        for (uint32_t k = 0; k < 256; ++k)
            if (keys_.test(k) && isDown(k)) return true;
        return false;
    }
    // The hook forgot the Windows key (resetHook below), so its up will
    // not come. Keys stay noted, so an up that still comes here is not sent
    // alone.
    void hookReset() { win_ = false; }
    // A new session.
    void reset() {
        keys_.reset();
        win_ = false;
        count_ = 0;
    }
    uint64_t heldBack() const { return count_; }

private:
    template <class IsDown>
    Reason reason(bool known, IsDown&& isDown) const {
        if (!known) return Reason::PlatformUnknown;
        return chordOpen(isDown) ? Reason::ChordOpen : Reason::None;
    }
    std::bitset<256> keys_;  // keys whose down was held back: their up is not sent
    bool win_ = false;       // the Windows key's down was held back
    uint64_t count_ = 0;     // everything held back this session
};

// Every reset of the viewer's low-level hook state goes through here
// (Pepper's review of f97ad11, item 2): focus left, the Files panel or the
// disconnect confirm opened. The reset hook does not post the Windows
// key's up, so a Windows key held back is forgotten in the same step;
// otherwise the open chord would hold back every key and click after it.
template <class Hook>
void resetHook(Hook& hook, KeyHoldBack& h) {
    hook.reset();
    h.hookReset();
}

}  // namespace jl::holdback
