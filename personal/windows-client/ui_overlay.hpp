#pragma once

// In-session overlay (B1): a thin translucent bar at the top centre of the
// viewer, just below the remote Mac menu bar, with the connection status, mute, volume, Info, Settings and Disconnect.
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

// Hover fallback in client coordinates: the bottom-left corner of a cw x ch
// client area (zone x zone pixels). The viewer uses videoHoverZone() below,
// which anchors the corner to the remote picture and keeps it on screen. The overlay itself opens at the top centre.
inline bool inCornerZone(int x, int y, int clientW, int clientH, int zone) {
    return x >= 0 && y < clientH && x < std::min(zone, clientW) && y >= clientH - zone;
}

// Hover zone size in logical pixels (scaled with the dpi).
constexpr int kHoverZone = 48;

// One opacity token for every in-session surface: the overlay and the Info,
// Settings and Volume windows opened while connected (layered windows,
// LWA_ALPHA). 191/255 is about 75%, so the video shows through; primary text
// keeps at least 7:1 contrast over any backdrop, hints at least 4.3:1.
// A later user setting (Settings > overlay opacity) only has to change this.
constexpr unsigned char kSessionUiAlpha = 191;

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

// ---- Hover zone on any monitor ---------------------------------------------
// Part of `a` that is also in `b`; empty (width or height <= 0) when apart.
inline Rect intersect(const Rect& a, const Rect& b) {
    Rect r{std::max(a.left, b.left), std::max(a.top, b.top), std::min(a.right, b.right),
           std::min(a.bottom, b.bottom)};
    if (r.right < r.left) r.right = r.left;
    if (r.bottom < r.top) r.bottom = r.top;
    return r;
}

// Bottom-left hover zone in screen coordinates. `clientScreen` is the
// viewer's client area in screen coordinates (any monitor, negative origins
// included); `workArea` is the work area of the monitor the viewer is on.
// The zone is the bottom-left corner of the part of the client area that is
// actually on that monitor and not under its taskbar, so it can always be
// reached: a window larger than the monitor, or one whose bottom edge is
// off-screen or behind the taskbar, still gets a reachable corner. Empty
// when no part of the client area is visible.
inline Rect hoverZone(const Rect& clientScreen, const Rect& workArea, int zone) {
    const Rect v = intersect(clientScreen, workArea);
    if (v.width() <= 0 || v.height() <= 0 || zone <= 0) return {};
    return {v.left, std::max(v.top, v.bottom - zone), std::min(v.right, v.left + zone), v.bottom};
}

// ---- Overlay below the remote menu bar -------------------------------------
// Where the stream is drawn in a cw x ch client area: aspect fit, centred,
// black bars on the long side (same maths as the CPU and D3D paths).
inline Rect fitVideo(int cw, int ch, unsigned streamW, unsigned streamH) {
    cw = std::max(1, cw);
    ch = std::max(1, ch);
    if (streamW == 0 || streamH == 0) return {0, 0, cw, ch};
    const double srcAspect = static_cast<double>(streamW) / streamH;
    int dw = cw, dh = ch, dx = 0, dy = 0;
    if (static_cast<double>(cw) / ch > srcAspect) {
        dw = std::max(1, static_cast<int>(ch * srcAspect));
        dx = (cw - dw) / 2;
    } else {
        dh = std::max(1, static_cast<int>(cw / srcAspect));
        dy = (ch - dh) / 2;
    }
    return {dx, dy, dx + dw, dy + dh};
}

// macOS menu bar: 24 pt on displays without a notch (taller, about 37 pt,
// on notch displays). The host does not send its menu bar height or backing
// scale, so the viewer estimates it from the stream height: streams of 1500
// rows or more come from a Retina / HiDPI (2x) mode, smaller ones from a 1x
// mode. For a capped stream (4352x2448 sent as 3840x2160) 2x gives 48 rows
// where the true bar is about 42, so the overlay sits a little lower and stays
// clear. A 1x guess for a stream that is really 2x (under 1500 rows) would be
// too small; the host sending its real menu bar height would fix that, which
// needs a wire change.
constexpr int kMacMenuBarPt = 24;
constexpr unsigned kHiDpiStreamRows = 1500;

inline int remoteMenuBarStreamPx(unsigned streamH) {
    return kMacMenuBarPt * (streamH >= kHiDpiStreamRows ? 2 : 1);
}

// Gap between the remote menu bar and the overlay, logical pixels.
constexpr int kMenuBarGap = 6;

// Distance from the client top to the overlay top: the top of the drawn
// video, plus the remote menu bar mapped into client pixels (menu bar rows
// x displayed video height / stream height, rounded up), plus `gapPx`.
inline int overlayTopOffset(int cw, int ch, unsigned streamW, unsigned streamH, int gapPx) {
    const Rect v = fitVideo(cw, ch, streamW, streamH);
    if (streamH == 0) return gapPx;
    const long long bar = static_cast<long long>(remoteMenuBarStreamPx(streamH)) * v.height();
    const int barPx = static_cast<int>((bar + streamH - 1) / streamH);
    return v.top + barPx + gapPx;
}

// Bottom-left hover zone on the remote picture, in screen coordinates: the
// bottom-left corner of (displayed video rect, same aspect fit as the
// renderer) and client area and monitor work area. On a pillarboxed or
// letterboxed window it starts at the video's left edge and ends at the
// video's bottom edge, never in the black bars. Only when no part of the
// video is visible does it fall back to the visible client corner.
inline Rect videoHoverZone(const Rect& clientScreen, unsigned streamW, unsigned streamH,
                           const Rect& workArea, int zone) {
    const Rect fit = fitVideo(clientScreen.width(), clientScreen.height(), streamW, streamH);
    const Rect video{clientScreen.left + fit.left, clientScreen.top + fit.top,
                     clientScreen.left + fit.right, clientScreen.top + fit.bottom};
    const Rect z = hoverZone(intersect(video, clientScreen), workArea, zone);
    if (z.width() > 0 && z.height() > 0) return z;
    return hoverZone(clientScreen, workArea, zone);
}

}  // namespace jl::overlay
