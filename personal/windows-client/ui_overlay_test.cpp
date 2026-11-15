// In-session overlay maths (ui_overlay.hpp): layout, hit-test, keyboard
// focus order, slider, hover dwell, top-centre zone and placement.
#include "ui_overlay.hpp"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <iterator>

namespace {

int gPass = 0;
int gFail = 0;

void expect(bool cond, const char* what) {
    if (cond) { ++gPass; std::printf("PASS %s\n", what); }
    else { ++gFail; std::printf("FAIL %s\n", what); }
}

using namespace jl::overlay;

bool inside(const Rect& outer, const Rect& inner) {
    return inner.left >= outer.left && inner.right <= outer.right && inner.top >= outer.top &&
           inner.bottom <= outer.bottom;
}

void layoutTests() {
    for (unsigned dpi : {96u, 120u, 144u, 192u}) {
        const Layout l = layoutFor(dpi);
        const Rect items[] = {l.status, l.mute, l.volumeLabel, l.slider, l.info, l.settings,
                              l.disconnect};
        bool allInBar = true, ordered = true;
        for (size_t i = 0; i < std::size(items); ++i) {
            allInBar = allInBar && inside(l.bar, items[i]) && items[i].width() > 0;
            if (i > 0) ordered = ordered && items[i - 1].right <= items[i].left;
        }
        expect(allInBar, "every item lies inside the bar");
        expect(ordered, "items run left to right without overlap");
        expect(l.sep1 > l.status.right && l.sep1 < l.mute.left, "first separator between status and mute");
        expect(l.sep2 > l.slider.right && l.sep2 < l.info.left, "second separator between slider and Info");
        expect(inside(l.size, l.hint) && l.hint.top >= l.bar.bottom, "hint row under the bar");
        expect(l.size.width() == scale(648, dpi), "width scales with dpi");
    }
}

void hitTests() {
    const Layout l = layoutFor(96);
    const auto mid = [](const Rect& r) { return std::array<int, 2>{(r.left + r.right) / 2, (r.top + r.bottom) / 2}; };
    auto c = mid(l.mute);
    expect(hitTest(l, c[0], c[1]) == Item::Mute, "hit mute");
    c = mid(l.slider);
    expect(hitTest(l, c[0], c[1]) == Item::Volume, "hit slider = volume");
    c = mid(l.volumeLabel);
    expect(hitTest(l, c[0], c[1]) == Item::Volume, "hit volume label = volume");
    c = mid(l.info);
    expect(hitTest(l, c[0], c[1]) == Item::Info, "hit Info");
    c = mid(l.settings);
    expect(hitTest(l, c[0], c[1]) == Item::Settings, "hit Settings");
    c = mid(l.disconnect);
    expect(hitTest(l, c[0], c[1]) == Item::Disconnect, "hit Disconnect");
    c = mid(l.status);
    expect(hitTest(l, c[0], c[1]) == Item::None, "status is not a button");
    c = mid(l.hint);
    expect(hitTest(l, c[0], c[1]) == Item::None, "hint is not a button");
    expect(hitTest(l, l.sep1, l.bar.bottom / 2) == Item::None, "separator is not a button");
}

void focusTests() {
    expect(nextFocus(Item::None, 1) == Item::Mute, "Tab from nothing starts at mute");
    expect(nextFocus(Item::None, -1) == Item::Disconnect, "Shift+Tab from nothing starts at Disconnect");
    expect(nextFocus(Item::Mute, 1) == Item::Volume, "mute -> volume");
    expect(nextFocus(Item::Settings, 1) == Item::Disconnect, "Settings -> Disconnect");
    expect(nextFocus(Item::Disconnect, 1) == Item::Mute, "wraps forward");
    expect(nextFocus(Item::Mute, -1) == Item::Disconnect, "wraps back");
    // A full lap visits every item once.
    Item it = Item::None;
    int seen = 0;
    for (size_t i = 0; i < kFocusOrder.size(); ++i) {
        it = nextFocus(it, 1);
        seen |= 1 << static_cast<int>(it);
    }
    expect(seen == ((1 << int(Item::Mute)) | (1 << int(Item::Volume)) | (1 << int(Item::Info)) |
                    (1 << int(Item::Settings)) | (1 << int(Item::Disconnect))),
           "one lap visits all five items");
}

void sliderTests() {
    for (unsigned dpi : {96u, 144u}) {
        const Layout l = layoutFor(dpi);
        const Rect s = l.slider;
        expect(sliderValueAt(s, s.left - 50, dpi) == 0, "left of the track clamps to 0");
        expect(sliderValueAt(s, s.right + 50, dpi) == 100, "right of the track clamps to 100");
        bool roundTrip = true;
        for (int v = 0; v <= 100; v += 5) {
            roundTrip = roundTrip && std::abs(sliderValueAt(s, sliderKnobX(s, v, dpi), dpi) - v) <= 1;
        }
        expect(roundTrip, "knob x -> value round trip within 1%");
        expect(sliderKnobX(s, 0, dpi) - sliderKnobRadius(dpi) >= s.left &&
                   sliderKnobX(s, 100, dpi) + sliderKnobRadius(dpi) <= s.right,
               "knob stays inside the slider");
    }
    expect(volumeStep(70, 1) == 75 && volumeStep(70, -1) == 65, "arrow keys step 5%");
    expect(volumeStep(98, 1) == 100 && volumeStep(2, -1) == 0, "steps clamp");
}

void dwellTests() {
    Dwell d(2000);
    expect(!d.update(true, 0), "dwell: not yet at start");
    expect(!d.update(true, 1999), "dwell: not before 2 s");
    expect(d.update(true, 2000), "dwell: fires at 2 s");
    expect(!d.update(true, 5000), "dwell: fires once while held");
    expect(!d.update(false, 5100), "dwell: release resets");
    expect(!d.update(true, 5200), "dwell: restarts");
    expect(!d.update(false, 6000), "dwell: a break before 2 s cancels");
    expect(!d.update(true, 6100) && !d.update(true, 8000) && d.update(true, 8100),
           "dwell: needs a full unbroken 2 s");
}

void zoneTests() {
    // 1280 wide: the zone is x 560..719, y 0..23.
    expect(inTopCentreZone(640, 0, 1280, 720, 160, 24), "top-centre pixel is in the zone");
    expect(inTopCentreZone(560, 23, 1280, 720, 160, 24) &&
               inTopCentreZone(719, 23, 1280, 720, 160, 24),
           "zone edges are in");
    expect(!inTopCentreZone(559, 5, 1280, 720, 160, 24) &&
               !inTopCentreZone(720, 5, 1280, 720, 160, 24),
           "left and right of the zone are out");
    expect(!inTopCentreZone(640, 24, 1280, 720, 160, 24), "below the zone is out");
    expect(!inTopCentreZone(640, -1, 1280, 720, 160, 24), "outside the client area is out");
    expect(!inTopCentreZone(0, 0, 1280, 720, 160, 24) &&
               !inTopCentreZone(0, 719, 1280, 720, 160, 24),
           "the old bottom-left corner is no longer a zone");
    expect(inTopCentreZone(0, 0, 100, 720, 160, 24) && inTopCentreZone(99, 0, 100, 720, 160, 24),
           "narrow client: the zone spans its width");
}

void placementTests() {
    const Rect client{100, 50, 1380, 770};
    Point p = placeInClient(client, 648, 78, 16);
    expect(p.x == 100 + (1280 - 648) / 2 && p.y == 50 + 16, "top centre with margin");
    p = placeInClient(Rect{0, 0, 300, 60}, 648, 78, 16);
    expect(p.x == 0 && p.y == 0, "tiny client: pinned to its top-left");
    p = placeInClient(Rect{0, 0, 648, 400}, 648, 78, 16);
    expect(p.x == 0 && p.y == 16, "client exactly as wide: flush left, margin on top");
}

}  // namespace

int main() {
    layoutTests();
    hitTests();
    focusTests();
    sliderTests();
    dwellTests();
    zoneTests();
    placementTests();
    std::printf("%d passed, %d failed\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
