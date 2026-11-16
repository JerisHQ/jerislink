// Golden tests for keymap.hpp: lock today's Windows -> Mac key events exactly
// (positional layout, Ctrl+A/C/V/Z compat, Win+C / Win+Space escapes, viewer
// hotkeys, focus-loss release) before presets are added.
#include "keymap.hpp"

#include <cstdio>
#include <set>
#include <string>
#include <vector>

using namespace jl::keymap;

namespace {

int gPass = 0;
int gFail = 0;

void expect(bool cond, const std::string& what) {
    if (cond) { ++gPass; std::printf("PASS %s\n", what.c_str()); }
    else { ++gFail; std::printf("FAIL %s\n", what.c_str()); }
}

std::string show(const std::vector<KeyEvent>& ev) {
    std::string s;
    for (const auto& e : ev) {
        if (!s.empty()) s += ' ';
        s += (e.down ? "+" : "-") + std::to_string(e.semantic);
    }
    return s.empty() ? "(none)" : s;
}

void expectEvents(const std::vector<KeyEvent>& got, const std::vector<KeyEvent>& want, const std::string& what) {
    const bool ok = got == want;
    expect(ok, what + (ok ? "" : "  got [" + show(got) + "] want [" + show(want) + "]"));
}

KeyEvent D(uint16_t s) { return {true, s}; }
KeyEvent U(uint16_t s) { return {false, s}; }

constexpr uint16_t SP = static_cast<uint16_t>(vk::Space);
constexpr uint16_t CAPS = static_cast<uint16_t>(vk::Capital);

// What the viewer's window procedure and hook do, minus Win32: physical
// modifier state, the viewer-hotkey check that runs before forwarding, the
// hook's swallow/post decisions, and the wire it would write.
struct Viewer {
    Translator keys;
    HookFilter hook;
    Held held;
    bool useHook = false;  // true: the LL hook owns Win and Caps Lock
    std::vector<KeyEvent> wire;
    std::vector<std::string> tags;
    int passedToWindows = 0;

    void emit(const Output& o) {
        wire.insert(wire.end(), o.events.begin(), o.events.end());
        if (!o.debugTag.empty()) tags.push_back(o.debugTag);
    }

    void setHeld(uint32_t key, bool down) {
        if (key == vk::Control || key == vk::LControl || key == vk::RControl) held.ctrl = down;
        if (key == vk::Menu || key == vk::LMenu || key == vk::RMenu) held.alt = down;
        if (key == vk::LWin || key == vk::RWin) held.win = down;
    }

    // Returns true when the hook swallowed the key (no window message).
    bool runHook(uint32_t key, bool down) {
        if (!useHook) return false;
        const auto d = hook.onKey(key, down, !down);
        switch (d.post) {
        case HookFilter::Post::CapsLock: emit(Translator::hookCapsLock()); break;
        case HookFilter::Post::WinDown: emit(Translator::hookWinDown()); break;
        case HookFilter::Post::WinUp: emit(Translator::hookWinUp()); break;
        case HookFilter::Post::WinC: emit(Translator::hookWinC(hook.winDown())); break;
        case HookFilter::Post::WinSpace: emit(Translator::hookWinSpace(hook.winDown())); break;
        case HookFilter::Post::None: break;
        }
        return d.swallow;
    }

    void down(uint32_t key, bool repeat = false) {
        if (runHook(key, true)) return;  // swallowed keys never update GetKeyState
        setHeld(key, true);
        if (isViewerHotkey(key, held)) {
            keys.suppressUntilUp(key);
            return;
        }
        const auto o = keys.keyDown(key, repeat, held);
        if (!o.handled) { ++passedToWindows; return; }
        emit(o);
    }

    void up(uint32_t key) {
        if (runHook(key, false)) return;
        setHeld(key, false);
        const auto o = keys.keyUp(key, held);
        if (!o.handled) { ++passedToWindows; return; }
        emit(o);
    }

    void focusKill() {
        hook.reset();
        keys.reset();
        emit({true, releaseAllModifiers(), ""});
    }

    void tap(uint32_t key) { down(key); up(key); }
};

void testSemantics() {
    expect(kCtrl == 1 && kAlt == 2 && kWin == 3 && kShift == 4, "modifier semantics are 1 Ctrl, 2 Alt, 3 Win, 4 Shift");
    for (uint32_t k : {vk::Control, vk::LControl, vk::RControl})
        expect(semanticKey(k) == 1, "Ctrl VK " + std::to_string(k) + " -> 1");
    for (uint32_t k : {vk::Menu, vk::LMenu, vk::RMenu})
        expect(semanticKey(k) == 2, "Alt VK " + std::to_string(k) + " -> 2 (right Alt / AltGr too)");
    for (uint32_t k : {vk::LWin, vk::RWin})
        expect(semanticKey(k) == 3, "Win VK " + std::to_string(k) + " -> 3");
    for (uint32_t k : {vk::Shift, vk::LShift, vk::RShift})
        expect(semanticKey(k) == 4, "Shift VK " + std::to_string(k) + " -> 4");

    // Every VK 0..255 against the forwarded set as it is today.
    std::set<uint32_t> fwd = {0x08, 0x09, 0x0D, 0x14, 0x1B, 0x20, 0x21, 0x22, 0x23, 0x24,
                              0x25, 0x26, 0x27, 0x28, 0x2D, 0x2E, 0x6A, 0x6B, 0x6D, 0x6E, 0x6F,
                              0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xDB, 0xDC, 0xDD, 0xDE};
    for (uint32_t k = '0'; k <= '9'; ++k) fwd.insert(k);
    for (uint32_t k = 'A'; k <= 'Z'; ++k) fwd.insert(k);
    for (uint32_t k = 0x60; k <= 0x69; ++k) fwd.insert(k);  // numpad 0-9
    for (uint32_t k = 0x70; k <= 0x7B; ++k) fwd.insert(k);  // F1-F12
    const std::set<uint32_t> mods = {0x10, 0x11, 0x12, 0x5B, 0x5C, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5};
    int wrong = 0;
    for (uint32_t k = 0; k < 256; ++k) {
        const uint16_t s = semanticKey(k);
        if (mods.count(k)) continue;
        const uint16_t want = fwd.count(k) ? static_cast<uint16_t>(k) : 0;
        if (s != want) { ++wrong; std::printf("  vk 0x%02X -> %u want %u\n", k, s, want); }
    }
    expect(wrong == 0, "VK 0..255: forwarded keys keep their VK value, the rest send nothing");
    expect(semanticKey(0x7C) == 0 && semanticKey(0x5D) == 0 && semanticKey(0xE2) == 0 &&
               semanticKey(0x2C) == 0 && semanticKey(0x90) == 0 && semanticKey(0xAD) == 0,
           "F13, Apps, ISO extra key, PrintScreen, NumLock, media keys are not forwarded");
}

void testCtrlCompat() {
    for (char c : {'A', 'C', 'V', 'Z'}) {
        Viewer v;
        v.down(vk::LControl);
        v.down(static_cast<uint32_t>(c));
        v.up(static_cast<uint32_t>(c));
        v.up(vk::LControl);
        const uint16_t k = static_cast<uint16_t>(c);
        expectEvents(v.wire, {D(1), U(1), D(3), D(k), U(k), U(3), D(1), U(1)},
                     std::string("Ctrl+") + c + " -> Command+" + c + ", Control restored while Ctrl held");
        expect(v.tags.size() == 1 && v.tags[0] == std::string("shortcut.ctrl_") + char(c - 'A' + 'a') + "=command",
               std::string("Ctrl+") + c + " debug tag");
    }
    {
        Viewer v;
        v.down(vk::LControl);
        v.down('C');
        v.up(vk::LControl);  // Ctrl released before C
        v.up('C');
        expectEvents(v.wire, {D(1), U(1), D(3), D('C'), U('C'), U(3), U(1)},
                     "Ctrl released before C: Control not restored, plain Ctrl up still sent");
    }
    {
        Viewer v;
        v.down(vk::LControl);
        v.down('C');
        v.down('C', true);
        v.down('C', true);
        v.up('C');
        v.up(vk::LControl);
        expectEvents(v.wire, {D(1), U(1), D(3), D('C'), U('C'), U(3), D(1), U(1)},
                     "held Ctrl+C: repeats suppressed, letter never leaks");
    }
    for (char c : {'X', 'S', 'F', 'Y'}) {
        Viewer v;
        v.down(vk::LControl);
        v.tap(static_cast<uint32_t>(c));
        v.up(vk::LControl);
        const uint16_t k = static_cast<uint16_t>(c);
        expectEvents(v.wire, {D(1), D(k), U(k), U(1)},
                     std::string("Ctrl+") + c + " stays Control+" + c + " (today's gap)");
        expect(v.tags.empty(), std::string("Ctrl+") + c + " has no debug tag");
    }
    {
        Viewer v;
        v.down(vk::RControl);
        v.tap('V');
        v.up(vk::RControl);
        expectEvents(v.wire, {D(1), U(1), D(3), D('V'), U('V'), U(3), D(1), U(1)}, "right Ctrl+V -> Command+V");
    }
}

void testWinWithoutHook() {
    // Window-message path (hook not installed): Win arrives as a normal key.
    {
        Viewer v;
        v.down(vk::LWin);
        v.tap('C');
        v.up(vk::LWin);
        expectEvents(v.wire, {D(3), U(3), D(1), D('C'), U('C'), U(1), D(3), U(3)},
                     "Win+C -> Control+C, Command restored while Win held");
        expect(v.tags.size() == 1 && v.tags[0] == "shortcut.win_c=control_c", "Win+C debug tag");
    }
    {
        Viewer v;
        v.down(vk::LWin);
        v.tap(vk::Space);
        v.up(vk::LWin);
        expectEvents(v.wire, {D(3), U(3), D(1), D(SP), U(SP), U(1), D(3), U(3)},
                     "Win+Space -> Control+Space (input source), Command restored");
        expect(v.tags.size() == 1 && v.tags[0] == "shortcut.win_space=control_space", "Win+Space debug tag");
    }
    {
        Viewer v;
        v.down(vk::LWin);
        v.tap('T');
        v.up(vk::LWin);
        expectEvents(v.wire, {D(3), D('T'), U('T'), U(3)}, "Win+T stays Command+T");
    }
    {
        Viewer v;
        v.down(vk::LControl);
        v.down(vk::LWin);
        v.tap('C');
        v.up(vk::LWin);
        v.up(vk::LControl);
        expectEvents(v.wire, {D(1), D(3), U(3), D(1), D('C'), U('C'), U(1), D(3), U(3), U(1)},
                     "Ctrl+Win+C: the Win escape wins over Ctrl compat");
    }
}

void testWinWithHook() {
    {
        Viewer v;
        v.useHook = true;
        v.down(vk::LWin);
        v.down('C');
        v.down('C', true);  // auto-repeat seen by the hook
        v.up('C');
        v.up(vk::LWin);
        expectEvents(v.wire, {D(3), U(3), D(1), D('C'), U('C'), U(1), D(3), U(3)},
                     "hook Win+C -> Control+C once, Command restored, Command up on Win release");
        expect(v.tags == std::vector<std::string>{"shortcut.win_hook=command_down", "shortcut.win_c_hook=control_c",
                                                  "shortcut.win_hook=command_up"},
               "hook Win+C debug tags");
        expect(v.passedToWindows == 0, "hook Win+C: nothing reaches Windows");
    }
    {
        Viewer v;
        v.useHook = true;
        v.down(vk::RWin);
        v.tap(vk::Space);
        v.up(vk::RWin);
        expectEvents(v.wire, {D(3), U(3), D(1), D(SP), U(SP), U(1), D(3), U(3)},
                     "hook Win+Space -> Control+Space, Command restored");
    }
    {
        Viewer v;
        v.useHook = true;
        v.down(vk::LWin);
        v.tap('L');
        v.up(vk::LWin);
        expectEvents(v.wire, {D(3), D('L'), U('L'), U(3)}, "hook Win+L -> Command+L (L itself not hooked)");
    }
    {
        Viewer v;
        v.useHook = true;
        v.down(vk::Capital);
        v.down(vk::Capital, true);
        v.up(vk::Capital);
        expectEvents(v.wire, {D(CAPS), U(CAPS)}, "hook Caps Lock: one tap sent on press, repeat and release swallowed");
        expect(v.tags == std::vector<std::string>{"key.caps_lock=remote_only"}, "Caps Lock debug tag");
    }
    {
        HookFilter h;
        const auto d = h.onKey(vk::Tab, true, false);
        expect(!d.swallow && d.post == HookFilter::Post::None, "hook leaves Alt+Tab / Tab to Windows");
        const auto e = h.onKey(vk::Escape, true, false);
        expect(!e.swallow, "hook leaves Ctrl+Esc to Windows");
        const auto c = h.onKey('C', true, false);
        expect(!c.swallow, "hook leaves C alone when Win is not held");
    }
}

void testViewerHotkeys() {
    for (char c : {'O', 'M', 'V'}) {
        Viewer v;
        v.down(vk::LControl);
        v.down(vk::LMenu);
        v.down(static_cast<uint32_t>(c));
        v.down(static_cast<uint32_t>(c), true);
        v.up(static_cast<uint32_t>(c));
        v.up(vk::LMenu);
        v.up(vk::LControl);
        expectEvents(v.wire, {D(1), D(2), U(2), U(1)},
                     std::string("Ctrl+Alt+") + c + " stays on the viewer: only plain modifier downs/ups reach the Mac");
        expect(v.tags.empty(), std::string("Ctrl+Alt+") + c + " has no debug tag");
    }
    expect(!isViewerHotkey('O', {true, false, false}) && !isViewerHotkey('O', {false, true, false}) &&
               !isViewerHotkey('P', {true, true, false}),
           "hotkeys need both Ctrl and Alt and only O/M/V");
    {
        Viewer v;
        v.down(vk::LControl);
        v.down(vk::LMenu);
        v.tap('V');  // volume hotkey wins over Ctrl+V compat
        v.up(vk::LMenu);
        v.up(vk::LControl);
        expectEvents(v.wire, {D(1), D(2), U(2), U(1)}, "Ctrl+Alt+V is the volume hotkey, not Command+V");
    }
}

void testPlainKeysAndRelease() {
    {
        Viewer v;
        v.down(vk::LShift);
        v.tap('1');
        v.down(vk::Back);
        v.down(vk::Back, true);
        v.down(vk::Back, true);
        v.up(vk::Back);
        v.up(vk::LShift);
        expectEvents(v.wire, {D(4), D('1'), U('1'), D(8), D(8), D(8), U(8), U(4)},
                     "plain keys and their repeats are forwarded as-is");
        expect(v.tags.empty(), "plain keys produce no debug tag");
    }
    {
        Viewer v;
        v.tap(0x7C);  // F13
        expect(v.wire.empty() && v.passedToWindows == 2, "unmapped key: nothing sent, left to Windows");
    }
    {
        Viewer v;
        v.down(vk::LControl);
        v.down('C');
        v.focusKill();
        expect(v.keys.suppressedKey() == 0 && v.keys.releasedModifier() == 0, "focus kill clears shortcut state");
        expectEvents(v.wire, {D(1), U(1), D(3), D('C'), U('C'), U(3), U(1), U(2), U(3), U(4)},
                     "focus kill releases modifiers 1-4");
    }
    {
        Viewer v;
        v.useHook = true;
        v.down(vk::LWin);
        v.focusKill();
        expect(!v.hook.winDown(), "focus kill clears the hook's Win state");
    }
    expectEvents(releaseAllModifiers(), {U(1), U(2), U(3), U(4)}, "releaseAllModifiers sends ups for 1-4");
}

}  // namespace

int main() {
    testSemantics();
    testCtrlCompat();
    testWinWithoutHook();
    testWinWithHook();
    testViewerHotkeys();
    testPlainKeysAndRelease();
    std::printf("keymap: %d passed, %d failed\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
