#pragma once

#include <cstdint>
#include <string>
#include <vector>

// Windows keyboard -> remote Mac key events. Pure: no Win32 calls, so the
// console test (keymap_test.cpp) can drive it with recorded key sequences.
//
// The viewer's window procedure and low-level keyboard hook read the
// physical state (GetKeyState, KBDLLHOOKSTRUCT) and pass it in; this file
// decides which semantic key events go on the wire (control_channel.hpp
// sendKey: MRC1 type 0x10, [down, semantic_hi, semantic_lo]).
//
// Today's layout is positional: Ctrl -> Control, Alt -> Option,
// Win -> Command, plus the Ctrl+A/C/V/Z -> Command compat shortcuts and the
// Win+C / Win+Space escapes. A preset parameter is added in a later change;
// Translator is the one place it will plug in.
namespace jl::keymap {

// Wire semantics for modifiers (the host maps 1 Control, 2 Option,
// 3 Command, 4 Shift). Every other key uses its Windows VK value.
inline constexpr uint16_t kCtrl = 1;
inline constexpr uint16_t kAlt = 2;
inline constexpr uint16_t kWin = 3;
inline constexpr uint16_t kShift = 4;

// Windows virtual-key codes used here, so this header needs no <windows.h>.
// viewer.cpp static_asserts each one against the real VK_* value.
namespace vk {
inline constexpr uint32_t Back = 0x08, Tab = 0x09, Return = 0x0D;
inline constexpr uint32_t Shift = 0x10, Control = 0x11, Menu = 0x12;
inline constexpr uint32_t Capital = 0x14, Escape = 0x1B, Space = 0x20;
inline constexpr uint32_t Prior = 0x21, Next = 0x22, End = 0x23, Home = 0x24;
inline constexpr uint32_t Left = 0x25, Up = 0x26, Right = 0x27, Down = 0x28;
inline constexpr uint32_t Insert = 0x2D, Delete = 0x2E;
inline constexpr uint32_t LWin = 0x5B, RWin = 0x5C;
inline constexpr uint32_t Numpad0 = 0x60, Numpad9 = 0x69;
inline constexpr uint32_t Multiply = 0x6A, Add = 0x6B, Subtract = 0x6D, Decimal = 0x6E, Divide = 0x6F;
inline constexpr uint32_t F1 = 0x70, F12 = 0x7B;
inline constexpr uint32_t LShift = 0xA0, RShift = 0xA1, LControl = 0xA2, RControl = 0xA3;
inline constexpr uint32_t LMenu = 0xA4, RMenu = 0xA5;
inline constexpr uint32_t Oem1 = 0xBA, OemPlus = 0xBB, OemComma = 0xBC, OemMinus = 0xBD;
inline constexpr uint32_t OemPeriod = 0xBE, Oem2 = 0xBF, Oem3 = 0xC0;
inline constexpr uint32_t Oem4 = 0xDB, Oem5 = 0xDC, Oem6 = 0xDD, Oem7 = 0xDE;
}  // namespace vk

struct KeyEvent {
    bool down;
    uint16_t semantic;
    bool operator==(const KeyEvent& o) const { return down == o.down && semantic == o.semantic; }
};

// Physical modifier state at the time of the key message.
struct Held {
    bool ctrl = false;
    bool alt = false;
    bool win = false;
};

struct Output {
    // true: the viewer consumed the key (window procedure returns 0).
    // false: not ours, let DefWindowProc see it.
    bool handled = false;
    std::vector<KeyEvent> events;
    // Shortcut name for the log. The viewer writes it only with
    // JERISLINK_DEBUG=1; empty for ordinary keys, which are never logged.
    std::string debugTag;
};

// Semantic wire code for a Windows VK; 0 = not forwarded.
inline uint16_t semanticKey(uint32_t key) {
    switch (key) {
    case vk::Control: case vk::LControl: case vk::RControl: return kCtrl;
    case vk::Menu: case vk::LMenu: case vk::RMenu: return kAlt;
    case vk::LWin: case vk::RWin: return kWin;
    case vk::Shift: case vk::LShift: case vk::RShift: return kShift;
    case vk::Capital: return static_cast<uint16_t>(vk::Capital);

    // Editing/navigation keys. For non-modifiers the Windows VK value is the
    // semantic code; the Mac side maps that semantic to a CGKeyCode.
    case vk::Back: case vk::Tab: case vk::Return: case vk::Escape: case vk::Space:
    case vk::Prior: case vk::Next: case vk::End: case vk::Home:
    case vk::Left: case vk::Up: case vk::Right: case vk::Down:
    case vk::Insert: case vk::Delete:

    // Number pad operators (digits are a range below).
    case vk::Multiply: case vk::Add: case vk::Subtract: case vk::Decimal: case vk::Divide:

    // US/HK physical punctuation keys. Shift state is carried separately, so
    // these naturally produce ! @ # ... and other shifted symbols.
    case vk::Oem1: case vk::OemPlus: case vk::OemComma: case vk::OemMinus:
    case vk::OemPeriod: case vk::Oem2: case vk::Oem3: case vk::Oem4:
    case vk::Oem5: case vk::Oem6: case vk::Oem7:
        return static_cast<uint16_t>(key);
    default:
        if ((key >= 'A' && key <= 'Z') || (key >= '0' && key <= '9') ||
            (key >= vk::Numpad0 && key <= vk::Numpad9) || (key >= vk::F1 && key <= vk::F12)) {
            return static_cast<uint16_t>(key);
        }
        return 0;
    }
}

// Ctrl+letter shortcuts sent as Command+letter in the positional layout.
inline bool isWindowsCtrlCompatShortcut(uint32_t key) {
    return key == 'A' || key == 'C' || key == 'V' || key == 'Z';
}

// Physical Ctrl+Alt+O (overlay), M (mute), V (volume) stay on the viewer.
inline bool isViewerHotkey(uint32_t key, const Held& held) {
    return (key == 'O' || key == 'M' || key == 'V') && held.ctrl && held.alt;
}

inline void appendChord(std::vector<KeyEvent>& out, uint16_t modifier, uint16_t key) {
    out.push_back({true, modifier});
    out.push_back({true, key});
    out.push_back({false, key});
    out.push_back({false, modifier});
}

// Key-ups for every modifier (focus loss, disconnect, close).
inline std::vector<KeyEvent> releaseAllModifiers() {
    return {{false, kCtrl}, {false, kAlt}, {false, kWin}, {false, kShift}};
}

// Window-message side: WM_KEYDOWN/WM_SYSKEYDOWN, WM_KEYUP/WM_SYSKEYUP and the
// messages the low-level hook posts. Keeps the "key owned by a remapped
// shortcut until its physical key-up" state.
class Translator {
public:
    // The key went to a viewer hotkey: swallow its repeats and key-up. Ctrl
    // and Alt were already sent as plain modifier downs and release normally.
    void suppressUntilUp(uint32_t key) {
        suppressedKey_ = key;
        releasedModifier_ = 0;
    }

    void reset() {
        suppressedKey_ = 0;
        releasedModifier_ = 0;
    }

    uint32_t suppressedKey() const { return suppressedKey_; }
    uint16_t releasedModifier() const { return releasedModifier_; }

    // WM_KEYDOWN / WM_SYSKEYDOWN, after the viewer hotkey and overlay checks.
    Output keyDown(uint32_t key, bool repeat, const Held& held) {
        Output out;
        // Windows+Space is native macOS Control+Space (input source switch),
        // Windows+C is a true Control+C. Win normally maps to Command, so
        // release it remotely before the Control chord.
        if (!repeat && held.win && (key == vk::Space || key == 'C')) {
            out.handled = true;
            out.events.push_back({false, kWin});
            appendChord(out.events, kCtrl, static_cast<uint16_t>(key));
            suppressedKey_ = key;
            releasedModifier_ = kWin;
            out.debugTag = key == vk::Space ? "shortcut.win_space=control_space"
                                            : "shortcut.win_c=control_c";
            return out;
        }

        // Windows editing muscle memory: Ctrl+A/C/V/Z become Command+A/C/V/Z.
        // The physical Ctrl was already forwarded as Control, so release it
        // remotely while emitting the Command chord.
        if (!repeat && held.ctrl && isWindowsCtrlCompatShortcut(key)) {
            out.handled = true;
            out.events.push_back({false, kCtrl});
            appendChord(out.events, kWin, static_cast<uint16_t>(key));
            suppressedKey_ = key;
            releasedModifier_ = kCtrl;
            out.debugTag = std::string("shortcut.ctrl_") +
                           static_cast<char>(key - 'A' + 'a') + "=command";
            return out;
        }

        // Repeats of ordinary keys are forwarded (native key repeat on the
        // Mac). A key owned by a remapped shortcut stays suppressed until its
        // physical key-up, or holding Ctrl+C would leak the letter.
        if (repeat && suppressedKey_ != 0 && key == suppressedKey_) {
            out.handled = true;
            return out;
        }

        const uint16_t sem = semanticKey(key);
        if (!sem) return out;
        out.handled = true;
        out.events.push_back({true, sem});
        return out;
    }

    // WM_KEYUP / WM_SYSKEYUP.
    Output keyUp(uint32_t key, const Held& held) {
        Output out;
        if (suppressedKey_ != 0 && key == suppressedKey_) {
            out.handled = true;
            if (releasedModifier_ == kCtrl && held.ctrl) {
                out.events.push_back({true, kCtrl});
            } else if (releasedModifier_ == kWin && held.win) {
                out.events.push_back({true, kWin});
            }
            reset();
            return out;
        }
        const uint16_t sem = semanticKey(key);
        if (!sem) return out;
        out.handled = true;
        out.events.push_back({false, sem});
        return out;
    }

    // Messages posted by the low-level hook, which owns the Windows key and
    // Caps Lock while the viewer is focused.
    static Output hookWinDown() {
        return {true, {{true, kWin}}, "shortcut.win_hook=command_down"};
    }
    static Output hookWinUp() {
        return {true, {{false, kWin}}, "shortcut.win_hook=command_up"};
    }
    // Momentarily release remote Command, emit true Control+C / Control+Space,
    // then restore Command while the Windows key is still held.
    static Output hookWinC(bool winStillHeld) { return hookWinChord('C', winStillHeld, "shortcut.win_c_hook=control_c"); }
    static Output hookWinSpace(bool winStillHeld) {
        return hookWinChord(static_cast<uint16_t>(vk::Space), winStillHeld, "shortcut.win_space_hook=control_space");
    }
    static Output hookCapsLock() {
        return {true,
                {{true, static_cast<uint16_t>(vk::Capital)}, {false, static_cast<uint16_t>(vk::Capital)}},
                "key.caps_lock=remote_only"};
    }

private:
    static Output hookWinChord(uint16_t key, bool winStillHeld, const char* tag) {
        Output out{true, {{false, kWin}}, tag};
        appendChord(out.events, kCtrl, key);
        if (winStillHeld) out.events.push_back({true, kWin});
        return out;
    }

    uint32_t suppressedKey_ = 0;
    uint16_t releasedModifier_ = 0;
};

// The low-level keyboard hook's own state: which keys it swallows while the
// viewer has focus, and which message it posts to the window procedure.
// Everything else (Alt+Tab, Ctrl+Esc, ...) still goes to Windows.
class HookFilter {
public:
    enum class Post { None, CapsLock, WinDown, WinUp, WinC, WinSpace };
    struct Decision {
        bool swallow = false;
        Post post = Post::None;
    };

    bool winDown() const { return winDown_; }
    void reset() { *this = HookFilter{}; }

    Decision onKey(uint32_t key, bool keyDown, bool keyUp) {
        if (key == vk::Capital) {
            Decision d{true, Post::None};
            if (keyDown && !capsDown_) {
                capsDown_ = true;
                d.post = Post::CapsLock;
            } else if (keyUp) {
                capsDown_ = false;
            }
            return d;
        }
        if (key == vk::LWin || key == vk::RWin) {
            Decision d{true, Post::None};
            if (keyDown && !winDown_) {
                winDown_ = true;
                d.post = Post::WinDown;
            } else if (keyUp && winDown_) {
                winDown_ = false;
                d.post = Post::WinUp;
            }
            return d;
        }
        if (key == 'C' && winDown_) {
            if (auto d = intercept(interceptingWinC_, Post::WinC, keyDown, keyUp); d.swallow) return d;
        }
        if (key == vk::Space && winDown_) {
            if (auto d = intercept(interceptingWinSpace_, Post::WinSpace, keyDown, keyUp); d.swallow) return d;
        }
        return {};
    }

private:
    static Decision intercept(bool& active, Post post, bool keyDown, bool keyUp) {
        if (keyDown) {
            Decision d{true, Post::None};
            if (!active) {
                active = true;
                d.post = post;
            }
            return d;
        }
        if (keyUp && active) {
            active = false;
            return {true, Post::None};
        }
        return {};
    }

    bool winDown_ = false;
    bool interceptingWinC_ = false;
    bool interceptingWinSpace_ = false;
    bool capsDown_ = false;
};

}  // namespace jl::keymap
