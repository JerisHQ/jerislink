// Down/up parity for remote mouse buttons: every down the viewer sends gets
// exactly one up, whatever order the window messages arrive in.
#include "mouse_buttons.hpp"

#include <cstdio>
#include <vector>

namespace {

int gPass = 0;
int gFail = 0;

void expect(bool cond, const char* what) {
    if (cond) { ++gPass; std::printf("PASS %s\n", what); }
    else { ++gFail; std::printf("FAIL %s\n", what); }
}

struct Wire {
    std::vector<int> downs = std::vector<int>(RemoteButtons::kCount, 0);
    std::vector<int> ups = std::vector<int>(RemoteButtons::kCount, 0);
    bool balanced() const {
        for (size_t b = 0; b < downs.size(); ++b) if (downs[b] != ups[b]) return false;
        return true;
    }
};

// What the viewer's window procedure does, minus Win32.
struct Viewer {
    RemoteButtons buttons;
    Wire wire;
    void buttonDown(uint8_t b) { ++wire.downs[b]; buttons.down(b); }
    void buttonUp(uint8_t b) { if (buttons.up(b)) ++wire.ups[b]; }
    uint8_t lostCapture() { return buttons.releaseAll([&](uint8_t b) { ++wire.ups[b]; }); }
    uint8_t focusKill() { return lostCapture(); }
};

}  // namespace

int main() {
    {
        Viewer v;
        v.buttonDown(0); v.buttonUp(0);
        expect(v.wire.balanced() && v.wire.ups[0] == 1, "plain left click: one down, one up");
    }
    {
        Viewer v;
        v.buttonDown(0);
        uint8_t mask = v.focusKill();
        expect(mask == 0x1 && v.wire.balanced(), "focus kill while left held sends the left up");
        v.buttonUp(0);  // the late WM_LBUTTONUP, if it still arrives
        expect(v.wire.ups[0] == 1, "late WM_LBUTTONUP after focus kill sends no second up");
    }
    {
        Viewer v;
        v.buttonDown(0);
        expect(v.lostCapture() == 0x1 && v.wire.balanced(), "capture taken while left held sends the left up");
    }
    {
        Viewer v;
        v.buttonDown(0); v.buttonDown(1); v.buttonDown(2);
        expect(v.focusKill() == 0x7 && v.wire.balanced(), "focus kill releases left, right and middle");
        expect(!v.buttons.anyHeld(), "nothing held after focus kill");
    }
    {
        Viewer v;
        v.buttonUp(1);
        expect(v.wire.ups[1] == 0, "up with no down sent sends nothing");
        expect(v.focusKill() == 0, "focus kill with nothing held sends nothing");
    }
    {
        Viewer v;
        v.buttonDown(0); v.buttonDown(1); v.buttonUp(1);
        expect(v.buttons.held(0) && !v.buttons.held(1), "right released while left held: left stays held");
        v.buttonUp(0);
        expect(v.wire.balanced(), "overlapping left and right clicks balance");
    }
    {
        Viewer v;
        v.buttonDown(0); v.buttonUp(0);     // double click: down, up,
        v.buttonDown(0); v.buttonUp(0);     // WM_LBUTTONDBLCLK, up
        expect(v.wire.downs[0] == 2 && v.wire.balanced(), "double click balances");
    }
    {
        // Mixed random-ish sequence: every interleaving ends balanced after a
        // final focus kill.
        Viewer v;
        const int ops[] = {0, 10, 1, 21, 11, 2, 99, 12, 0, 10, 0, 98, 10, 1, 2, 11, 99, 12};
        for (int op : ops) {
            if (op < 10) v.buttonDown(static_cast<uint8_t>(op));
            else if (op < 20) v.buttonUp(static_cast<uint8_t>(op - 10));
            else if (op == 98) v.lostCapture();
            else if (op == 99) v.focusKill();
            else v.buttonUp(static_cast<uint8_t>(op - 20));
        }
        v.focusKill();
        expect(v.wire.balanced(), "mixed sequence balanced after focus kill");
    }
    {
        // A second down while held (the first up was lost upstream): the host
        // keeps one boolean per button, so one up clears it.
        RemoteButtons b;
        b.down(0); b.down(0);
        expect(b.up(0) && !b.anyHeld() && !b.up(0), "repeated down is cleared by one up");
    }
    {
        RemoteButtons b;
        b.down(7);
        expect(!b.anyHeld() && !b.up(7), "out-of-range button is ignored");
    }
    std::printf("MouseButtonsTest %d PASS / %d FAIL\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
