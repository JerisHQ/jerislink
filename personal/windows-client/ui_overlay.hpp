#pragma once

// In-session overlay (B1): a thin translucent bar at the top centre of the
// viewer with the connection status, mute, volume, Info, Settings and Disconnect.
// Layout, hit-testing, keyboard focus order, slider maths and the hover
// fallback live here without Win32 so ui_overlay_test.cpp can check them.
// viewer.cpp paints and drives the real window.

#include <algorithm>
#include <array>

namespace jl::overlay {

enum class Item { None, Status, Mute, Volume, Info, Settings, Disconnect };

struct Rect {
    int left = 0, top = 0, right = 0, bottom = 0;
    int width() const { return right - left; }
    int height() const { return bottom - top; }
    bool contains(int x, int y) const { return x >= left && x < right && y >= top && y < bottom; }
};

// Logical pixels (96 dpi) scaled to the window's dpi, rounded.
inline int scale(int logical, unsigned dpi) {
    return (logical * static_cast<int>(dpi) + 48) / 96;
}

// Window coordinates of every part, for one dpi. The window is exactly
// `size`; the bar is its top part and the hint row sits under the bar
// inside the same rounded panel.
struct Layout {
    Rect size;
    Rect bar;
    Rect status, mute, volumeLabel, slider, info, settings, disconnect;
    Rect hint;
    int sep1 = 0, sep2 = 0;  // x of the two vertical separators
};

inline Layout layoutFor(unsigned dpi) {
    const auto s = [dpi](int v) { return scale(v, dpi); };
    Layout l;
    const int barH = s(56), hintH = s(22), w = s(648);
    l.size = {0, 0, w, barH + hintH};
    l.bar = {0, 0, w, barH};
    const int top = s(8), bottom = barH - s(8);
    l.status = {s(16), top, s(148), bottom};
    l.sep1 = s(160);
    const int muteTop = (barH - s(32)) / 2;
    l.mute = {s(172), muteTop, s(204), muteTop + s(32)};
    l.volumeLabel = {s(210), top, s(270), bottom};
    l.slider = {s(276), top, s(380), bottom};
    l.sep2 = s(396);
    l.info = {s(408), top, s(472), bottom};
    l.settings = {s(476), top, s(548), bottom};
    l.disconnect = {s(552), top, s(636), bottom};
    l.hint = {s(16), barH, w - s(16), barH + hintH - s(4)};
    return l;
}

// Interactive item under a point (window coordinates); None elsewhere.
// The volume label and the slider are one item.
inline Item hitTest(const Layout& l, int x, int y) {
    if (l.mute.contains(x, y)) return Item::Mute;
    if (l.slider.contains(x, y) || l.volumeLabel.contains(x, y)) return Item::Volume;
    if (l.info.contains(x, y)) return Item::Info;
    if (l.settings.contains(x, y)) return Item::Settings;
    if (l.disconnect.contains(x, y)) return Item::Disconnect;
    return Item::None;
}

// Tab / arrow order of the interactive items.
constexpr std::array<Item, 5> kFocusOrder{Item::Mute, Item::Volume, Item::Info, Item::Settings,
                                          Item::Disconnect};

// Next item in kFocusOrder (dir +1) or previous (dir -1), wrapping. From
// None, +1 starts at the first item and -1 at the last.
inline Item nextFocus(Item current, int dir) {
    const int n = static_cast<int>(kFocusOrder.size());
    int at = -1;
    for (int i = 0; i < n; ++i) {
        if (kFocusOrder[static_cast<size_t>(i)] == current) at = i;
    }
    if (at < 0) return dir >= 0 ? kFocusOrder.front() : kFocusOrder.back();
    return kFocusOrder[static_cast<size_t>(((at + dir) % n + n) % n)];
}

// The slider track runs between the knob centres at 0% and 100%; the knob
// radius keeps it inside the slider rectangle.
inline int sliderKnobRadius(unsigned dpi) { return scale(7, dpi); }

inline int sliderValueAt(const Rect& slider, int x, unsigned dpi) {
    const int r = sliderKnobRadius(dpi);
    const int x0 = slider.left + r, x1 = slider.right - r;
    if (x1 <= x0) return 0;
    const int v = ((x - x0) * 100 + (x1 - x0) / 2) / (x1 - x0);
    return std::clamp(v, 0, 100);
}

inline int sliderKnobX(const Rect& slider, int value, unsigned dpi) {
    const int r = sliderKnobRadius(dpi);
    const int x0 = slider.left + r, x1 = slider.right - r;
    return x0 + (x1 - x0) * std::clamp(value, 0, 100) / 100;
}

// Left / Right on the focused volume item: 5% steps, clamped.
inline int volumeStep(int value, int dir) { return std::clamp(value + 5 * dir, 0, 100); }

// Hover fallback: the pointer rests in a small zone at the middle of the
// top edge of the viewer's client area (zoneW wide, zoneH tall, centred).
inline bool inTopCentreZone(int x, int y, int clientW, int clientH, int zoneW, int zoneH) {
    const int w = std::min(zoneW, clientW);
    const int left = (clientW - w) / 2;
    return x >= left && x < left + w && y >= 0 && y < std::min(zoneH, clientH);
}

// Hover zone size in logical pixels (scaled with the dpi).
constexpr int kHoverZoneW = 160;
constexpr int kHoverZoneH = 24;

// Whole-window opacity of the overlay (layered window, LWA_ALPHA): 224/255
// is about 88%, so the video shows through while text stays readable.
constexpr unsigned char kOverlayAlpha = 224;

// Fires once when `on` has held for `ms` without a break; resets when it
// stops holding.
class Dwell {
public:
    explicit Dwell(double ms) : ms_(ms) {}
    bool update(bool on, double nowMs) {
        if (!on) {
            holding_ = false;
            fired_ = false;
            return false;
        }
        if (!holding_) {
            holding_ = true;
            sinceMs_ = nowMs;
        }
        if (fired_ || nowMs - sinceMs_ < ms_) return false;
        fired_ = true;
        return true;
    }
    void reset() {
        holding_ = false;
        fired_ = false;
    }
    void setMs(double ms) { ms_ = ms; }

private:
    double ms_;
    double sinceMs_ = 0.0;
    bool holding_ = false;
    bool fired_ = false;
};

// Top-left of the overlay in screen coordinates: horizontally centred in the
// viewer's client area, `margin` below its top edge, kept inside the client
// area when it is small (then pinned to the left).
struct Point {
    int x = 0, y = 0;
};

inline Point placeInClient(const Rect& client, int w, int h, int margin) {
    Point p{client.left + (client.width() - w) / 2, client.top + margin};
    p.x = std::max(client.left, std::min(p.x, client.right - w));
    p.y = std::max(client.top, std::min(p.y, client.bottom - h));
    return p;
}

}  // namespace jl::overlay
