// In-session overlay maths (ui_overlay.hpp): layout, hit-test, keyboard
// focus order, slider, hover dwell, corner zone, opacity token, placement,
// the hover zone on any monitor and the offset below the remote menu bar.
#include "ui_overlay.hpp"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <iterator>
#include <string>

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
                              l.files, l.forceQuit, l.disconnect};
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
        expect(l.size.width() == scale(804, dpi), "width scales with dpi");
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
    c = mid(l.files);
    expect(hitTest(l, c[0], c[1]) == Item::Files, "hit Files");
    c = mid(l.forceQuit);
    expect(hitTest(l, c[0], c[1]) == Item::ForceQuit, "hit Force Quit");
    c = mid(l.disconnect);
    expect(hitTest(l, c[0], c[1]) == Item::Disconnect, "hit Disconnect");
    expect(hitTest(l, l.forceQuit.right + 1, c[1]) == Item::None, "gap between Force Quit and Disconnect");
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
    expect(nextFocus(Item::Settings, 1) == Item::Files, "Settings -> Files");
    expect(nextFocus(Item::Files, 1) == Item::ForceQuit, "Files -> Force Quit");
    expect(nextFocus(Item::ForceQuit, 1) == Item::Disconnect, "Force Quit -> Disconnect");
    expect(nextFocus(Item::Disconnect, -1) == Item::ForceQuit, "Disconnect <- Force Quit");
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
                    (1 << int(Item::Settings)) | (1 << int(Item::Files)) | (1 << int(Item::ForceQuit)) |
                    (1 << int(Item::Disconnect))),
           "one lap visits all seven items");
    expect(tooltipFor(Item::ForceQuit) != nullptr &&
               std::wstring(tooltipFor(Item::ForceQuit)) == L"Force Quit Mac apps (Cmd+Option+Esc)",
           "Force Quit tooltip names the chord");
    expect(tooltipFor(Item::Disconnect) == nullptr && tooltipFor(Item::Files) == nullptr,
           "other items have no tooltip");
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
    expect(inCornerZone(0, 719, 1280, 720, 48), "corner pixel is in the zone");
    expect(inCornerZone(47, 672, 1280, 720, 48), "zone edge is in");
    expect(!inCornerZone(48, 700, 1280, 720, 48), "right of the zone is out");
    expect(!inCornerZone(10, 671, 1280, 720, 48), "above the zone is out");
    expect(!inCornerZone(-1, 700, 1280, 720, 48) && !inCornerZone(10, 720, 1280, 720, 48),
           "outside the client area is out");
    expect(!inCornerZone(640, 0, 1280, 720, 48), "the top centre is not a zone");
    expect(kSessionUiAlpha >= 179 && kSessionUiAlpha <= 204, "session UI alpha is about 75%");
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

bool same(const Rect& a, const Rect& b) {
    return a.left == b.left && a.top == b.top && a.right == b.right && a.bottom == b.bottom;
}

// Bug: the hover zone never fired with the viewer on an external monitor.
// The zone is now built in screen coordinates from the viewer's client
// area and its monitor's work area, so any origin and any dpi work.
void hoverZoneTests() {
    // External monitor left of the primary (negative x, above: negative y),
    // viewer maximized: client under the caption, down to the taskbar.
    const Rect leftWork{-2560, -200, 0, 1200};
    const Rect leftClient{-2560, -169, 0, 1200};
    Rect z = hoverZone(leftClient, leftWork, 48);
    expect(same(z, Rect{-2560, 1152, -2512, 1200}), "negative origin: zone at the client bottom-left");
    expect(z.contains(-2560, 1199) && z.contains(-2513, 1152), "negative origin: corner and zone edge are in");
    expect(!z.contains(-2512, 1180) && !z.contains(-2540, 1151), "negative origin: right of and above the zone are out");
    expect(!z.contains(0, 1199) && !z.contains(10, 700), "negative origin: points on the primary are out");

    // Monitor above the primary (negative y only).
    z = hoverZone(Rect{0, -1049, 1920, -40}, Rect{0, -1080, 1920, -40}, 48);
    expect(same(z, Rect{0, -88, 48, -40}), "monitor above the primary: zone in negative y");

    // Different dpi on the external monitor: the zone is sized for it.
    z = hoverZone(Rect{-1920, 31, 0, 1032}, Rect{-1920, 0, 0, 1032}, scale(kHoverZone, 144));
    expect(z.width() == 72 && z.height() == 72 && z.left == -1920 && z.bottom == 1032,
           "150% monitor: 72 px zone at its corner");

    // Windowed and fully on the external monitor: the client corner itself.
    z = hoverZone(Rect{2700, 200, 3980, 920}, Rect{2560, 0, 4480, 1040}, 48);
    expect(same(z, Rect{2700, 872, 2748, 920}), "windowed on the external monitor: client corner");

    // A window sized for a bigger panel, moved to a 1920x1080 external
    // monitor: its client bottom-left is off-screen. The zone moves to the
    // visible corner, above the taskbar.
    const Rect smallWork{2560, 0, 4480, 1040};
    z = hoverZone(Rect{2600, 100, 5160, 1540}, smallWork, 48);
    expect(same(z, Rect{2600, 992, 2648, 1040}), "window larger than the monitor: visible corner");
    expect(z.bottom <= smallWork.bottom && z.left >= smallWork.left, "zone stays reachable on that monitor");

    // Client bottom behind the taskbar.
    z = hoverZone(Rect{0, 0, 1920, 1080}, Rect{0, 0, 1920, 1032}, 48);
    expect(same(z, Rect{0, 984, 48, 1032}), "client under the taskbar: zone above it");

    // Nothing of the client on the monitor, or a tiny client.
    z = hoverZone(Rect{5000, 0, 6000, 500}, smallWork, 48);
    expect(z.width() <= 0 || z.height() <= 0, "client off the monitor: empty zone");
    z = hoverZone(Rect{0, 0, 30, 20}, Rect{0, 0, 1920, 1040}, 48);
    expect(same(z, Rect{0, 0, 30, 20}), "client smaller than the zone: the whole client");
}

// Hand test r1: on a wide external monitor the zone sat in the left black
// bar. It is now the bottom-left corner of the drawn video (remote picture).
void videoHoverZoneTests() {
    // Pillarboxed: maximized 1920-wide client, 1001 rows, 16:9 stream. The
    // video is 1779 wide, starting 70 px in.
    const Rect extWork{1920, 0, 3840, 1032};
    Rect z = videoHoverZone(Rect{1920, 31, 3840, 1032}, 3840, 2160, extWork, 48);
    expect(same(z, Rect{1990, 984, 2038, 1032}), "pillarboxed: zone starts at the video left edge");
    expect(z.contains(1995, 1000), "pillarboxed: Mac picture bottom-left is in");
    expect(!z.contains(1950, 1000) && !z.contains(1920, 1031), "pillarboxed: left black bar is out");

    // Same on a monitor left of the primary (negative origin).
    z = videoHoverZone(Rect{-1920, 31, 0, 1032}, 3840, 2160, Rect{-1920, 0, 0, 1032}, 48);
    expect(same(z, Rect{-1850, 984, -1802, 1032}), "pillarboxed, negative origin: video corner");

    // 150% dpi: 72 px zone, still at the video edge.
    z = videoHoverZone(Rect{1920, 31, 3840, 1032}, 3840, 2160, extWork, scale(kHoverZone, 144));
    expect(z.left == 1990 && z.width() == 72 && z.height() == 72 && z.bottom == 1032,
           "pillarboxed, 150% dpi: 72 px zone at the video corner");

    // Letterboxed: 16:10 client, 16:9 stream. Zone bottom is the video
    // bottom (1140), not the window bottom (1200).
    z = videoHoverZone(Rect{0, 0, 1920, 1200}, 3840, 2160, Rect{0, 0, 1920, 1200}, 48);
    expect(same(z, Rect{0, 1092, 48, 1140}), "letterboxed: zone bottom is the video bottom");
    expect(!z.contains(10, 1150) && !z.contains(10, 1199), "letterboxed: bottom black bar is out");

    // Letterboxed with the taskbar over the video bottom: zone above it.
    z = videoHoverZone(Rect{0, 0, 1920, 1200}, 3840, 2160, Rect{0, 0, 1920, 1100}, 48);
    expect(same(z, Rect{0, 1052, 48, 1100}), "letterboxed under the taskbar: zone above it");

    // Video partly off-screen: client hangs off the monitor's left edge; the
    // video's left part is off-screen, so the zone is at the visible part.
    z = videoHoverZone(Rect{-1000, 0, 1560, 1000}, 1920, 1080, Rect{0, 0, 1920, 1040}, 48);
    expect(same(z, Rect{0, 952, 48, 1000}), "video partly off-screen: visible video corner");

    // Window larger than the monitor, exact 16:9: the r1 visible corner.
    z = videoHoverZone(Rect{2600, 100, 5160, 1540}, 3840, 2160, Rect{2560, 0, 4480, 1040}, 48);
    expect(same(z, Rect{2600, 992, 2648, 1040}), "window larger than the monitor: visible corner");

    // No visible video at all (only black bar on the monitor): fall back to
    // the visible client corner.
    z = videoHoverZone(Rect{-3000, 0, 1000, 500}, 1920, 1080, Rect{0, 0, 1920, 1040}, 48);
    expect(same(z, Rect{0, 452, 48, 500}), "no visible video: visible client corner");

    // Unknown stream size: the whole client is the video.
    const Rect c{100, 100, 1380, 820}, w{0, 0, 1920, 1040};
    expect(same(videoHoverZone(c, 0, 0, w, 48), hoverZone(c, w, 48)), "no stream size: client corner");

    // Stream size change moves the zone (16:9 to 4:3 in a 16:9 client).
    z = videoHoverZone(Rect{0, 0, 1920, 1080}, 1024, 768, Rect{0, 0, 1920, 1080}, 48);
    expect(same(z, Rect{240, 1032, 288, 1080}), "4:3 stream in a 16:9 window: zone moves to video left");
}

// Bug: the bar covered the Mac menu bar. The top offset is the remote menu
// bar mapped into client pixels plus a gap; it never falls short of the
// real bar (24 pt x scale) at any size below.
void menuBarOffsetTests() {
    expect(same(fitVideo(1920, 1200, 3840, 2160), Rect{0, 60, 1920, 1140}), "16:10 window: letterboxed fit");
    expect(same(fitVideo(2560, 1080, 1920, 1080), Rect{320, 0, 2240, 1080}), "wide window: pillarboxed fit");
    expect(same(fitVideo(1920, 1080, 1920, 1080), Rect{0, 0, 1920, 1080}), "exact fit");

    expect(remoteMenuBarStreamPx(1080) == 24 && remoteMenuBarStreamPx(1440) == 24,
           "1080 and 1440 row streams: 1x menu bar (24 rows)");
    expect(remoteMenuBarStreamPx(2160) == 48 && remoteMenuBarStreamPx(1600) == 48,
           "1600 and 2160 row streams: 2x menu bar (48 rows)");

    const int gap = scale(kMenuBarGap, 96);
    expect(gap == 6, "gap is 6 px at 96 dpi");
    // 1920x1080 stream shown 1:1.
    expect(overlayTopOffset(1920, 1080, 1920, 1080, gap) == 24 + 6, "1920x1080 1:1: 24 + gap");
    // 2560x1440 stream in a 1920x1080 client: 24 x 1080/1440 = 18.
    expect(overlayTopOffset(1920, 1080, 2560, 1440, gap) == 18 + 6, "2560x1440 in 1920x1080: 18 + gap");
    expect(overlayTopOffset(2560, 1440, 2560, 1440, gap) == 24 + 6, "2560x1440 1:1: 24 + gap");
    // 3840x2160 (4K, 2x): 48 rows.
    expect(overlayTopOffset(3840, 2160, 3840, 2160, scale(kMenuBarGap, 192)) == 48 + 12,
           "3840x2160 1:1 at 200%: 48 + gap");
    expect(overlayTopOffset(1920, 1080, 3840, 2160, gap) == 24 + 6, "3840x2160 in 1920x1080: 24 + gap");
    // 4352x2448 capped to 3840x2160: the real bar is 24 x 2 x 3840/4352 =
    // 42.4 stream rows, 21.2 client rows at 1920x1080. The 2x estimate (24)
    // clears it.
    const int capped = overlayTopOffset(1920, 1080, 3840, 2160, gap);
    expect(capped - gap >= 22, "4352x2448 capped to 3840x2160: clears the real 21.2 px bar");
    expect(overlayTopOffset(3840, 2160, 3840, 2160, 0) >= 43, "capped stream 1:1: clears the real 42.4 row bar");
    // Letterboxed: 16:10 window, black bars of 60 above and below.
    expect(overlayTopOffset(1920, 1200, 3840, 2160, gap) == 60 + 24 + 6, "letterboxed 1920x1200: bar top + 24 + gap");
    // Pillarboxed: no bar on top.
    expect(overlayTopOffset(2560, 1080, 1920, 1080, gap) == 24 + 6, "pillarboxed 2560x1080: 24 + gap");
    // Small window: follows the resize.
    expect(overlayTopOffset(1280, 720, 3840, 2160, gap) == 16 + 6, "3840x2160 in 1280x720: 16 + gap");
    expect(overlayTopOffset(1280, 720, 1920, 1080, gap) == 16 + 6, "1920x1080 in 1280x720: 16 + gap");
    // No stream size yet: just the gap.
    expect(overlayTopOffset(1280, 720, 0, 0, gap) == gap, "unknown stream size: gap only");

    // Placed with the offset: below the menu bar, still centred.
    const Point p = placeInClient(Rect{-2560, -169, 0, 1200}, 648, 78,
                                  overlayTopOffset(2560, 1369, 3840, 2160, gap));
    expect(p.x == -2560 + (2560 - 648) / 2, "negative-origin client: centred");
    expect(p.y > -169 + 24, "negative-origin client: below the remote menu bar");
}

}  // namespace

void belowOverlayTests() {
    const Rect bar{558, 40, 1362, 118};  // 804x78 at 96 dpi, centred on 1920
    // Files panel centred under the menu bar, same top as the bar: moves under it.
    expect(topBelowOverlay({660, 40, 1260, 520}, bar, 8, 1040) == 126, "panel at bar top moves 8 px under the bar");
    // Already below: unchanged.
    expect(topBelowOverlay({660, 200, 1260, 680}, bar, 8, 1040) == 200, "panel already below stays");
    // Other columns (Volume top right on a wide window): unchanged.
    expect(topBelowOverlay({1500, 60, 1880, 260}, bar, 8, 1040) == 60, "window beside the bar stays");
    // Overlapping columns on a narrow window: moves under.
    expect(topBelowOverlay({1200, 60, 1580, 260}, bar, 8, 1040) == 126, "volume over the bar's right end moves under");
    // Window above the bar entirely: unchanged.
    expect(topBelowOverlay({660, 0, 1260, 30}, bar, 8, 1040) == 0, "window above the bar stays");
    // Not enough room: as low as the work area allows, never above its own top.
    expect(topBelowOverlay({660, 40, 1260, 1000}, bar, 8, 1040) == 80, "tall window stops at the work area bottom");
    expect(topBelowOverlay({660, 100, 1260, 1100}, bar, 8, 1040) == 100, "never moved up");
}

int main() {
    layoutTests();
    hitTests();
    focusTests();
    sliderTests();
    dwellTests();
    zoneTests();
    placementTests();
    hoverZoneTests();
    videoHoverZoneTests();
    menuBarOffsetTests();
    belowOverlayTests();
    std::printf("%d passed, %d failed\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
