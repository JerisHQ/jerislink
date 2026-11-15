#pragma once

// Dark theme shared by the viewer window and its dialogs (settings, volume).
// Plain Win32 + GDI + DWM: no UI framework, no extra runtime dependency.
//
// The palette starts from the viewer's title bar (caption #0C1424, border
// #2B4463, caption text #F4F8FF) so a dialog's body reads as one surface
// with its title bar. Text pairs are at least 4.5:1 (WCAG AA):
//   text   #F4F8FF on body 16.2, on field 17.7, on footer 17.3
//   muted  #A3B1C6 on body 7.9, on footer 8.5
//   accent #4C9AFF on body 6.0
//   text   #F4F8FF on primary button #2563EB 4.9

#include <windows.h>
#include <commctrl.h>
#include <dwmapi.h>

#include <algorithm>
#include <initializer_list>
#include <iterator>

namespace jl::ui {

namespace color {
constexpr COLORREF kCaption = RGB(0x0C, 0x14, 0x24);       // title bar, footer band
constexpr COLORREF kBody = RGB(0x11, 0x1B, 0x2E);          // dialog body, one step lighter
constexpr COLORREF kField = RGB(0x0A, 0x11, 0x20);         // inputs, drop-down list
constexpr COLORREF kBorder = RGB(0x2B, 0x44, 0x63);        // window border, inputs, dividers
constexpr COLORREF kText = RGB(0xF4, 0xF8, 0xFF);          // primary text, caption text
constexpr COLORREF kMuted = RGB(0xA3, 0xB1, 0xC6);         // hints, secondary text
constexpr COLORREF kDisabled = RGB(0x5D, 0x6B, 0x80);      // disabled slider and text
constexpr COLORREF kAccent = RGB(0x4C, 0x9A, 0xFF);        // section headers, slider fill, focus
constexpr COLORREF kFocusRing = RGB(0x8D, 0xBB, 0xFF);     // keyboard focus ring
constexpr COLORREF kPrimary = RGB(0x25, 0x63, 0xEB);       // Save / Connect button
constexpr COLORREF kPrimaryDown = RGB(0x1D, 0x4F, 0xC4);
constexpr COLORREF kSecondary = RGB(0x18, 0x24, 0x3A);     // Cancel / Close button
constexpr COLORREF kSecondaryDown = RGB(0x22, 0x31, 0x4C);
constexpr COLORREF kListSelected = RGB(0x1E, 0x3A, 0x66);  // highlighted drop-down item
}  // namespace color

// The viewer's title-bar look, for any top-level window of the viewer.
// Best effort: older Windows builds ignore attributes they do not know.
inline void applyWindowChrome(HWND hwnd) {
    BOOL dark = TRUE;
    (void)DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark, sizeof(dark));
    const COLORREF caption = color::kCaption;
    const COLORREF border = color::kBorder;
    const COLORREF text = color::kText;
    (void)DwmSetWindowAttribute(hwnd, DWMWA_CAPTION_COLOR, &caption, sizeof(caption));
    (void)DwmSetWindowAttribute(hwnd, DWMWA_BORDER_COLOR, &border, sizeof(border));
    (void)DwmSetWindowAttribute(hwnd, DWMWA_TEXT_COLOR, &text, sizeof(text));
    DWM_WINDOW_CORNER_PREFERENCE corners = DWMWCP_ROUND;
    (void)DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &corners, sizeof(corners));
}

inline UINT windowDpi(HWND hwnd) {
    const UINT dpi = hwnd ? GetDpiForWindow(hwnd) : 0;
    return dpi ? dpi : 96;
}

inline int px(UINT dpi, int logical) { return MulDiv(logical, static_cast<int>(dpi), 96); }

inline void fillRect(HDC dc, const RECT& r, COLORREF c) {
    SetDCBrushColor(dc, c);
    FillRect(dc, &r, static_cast<HBRUSH>(GetStockObject(DC_BRUSH)));
}

// Rounded rectangle with a 1-device-pixel-per-96-dpi border.
inline void roundRect(HDC dc, const RECT& r, int radius, COLORREF fill, COLORREF border,
                      int borderWidth = 1) {
    HPEN pen = CreatePen(PS_INSIDEFRAME, std::max(1, borderWidth), border);
    HGDIOBJ oldPen = SelectObject(dc, pen);
    SetDCBrushColor(dc, fill);
    HGDIOBJ oldBrush = SelectObject(dc, GetStockObject(DC_BRUSH));
    RoundRect(dc, r.left, r.top, r.right, r.bottom, radius, radius);
    SelectObject(dc, oldBrush);
    SelectObject(dc, oldPen);
    DeleteObject(pen);
}

inline void ellipse(HDC dc, const RECT& r, COLORREF fill, COLORREF border, int borderWidth = 1) {
    HPEN pen = CreatePen(PS_INSIDEFRAME, std::max(1, borderWidth), border);
    HGDIOBJ oldPen = SelectObject(dc, pen);
    SetDCBrushColor(dc, fill);
    HGDIOBJ oldBrush = SelectObject(dc, GetStockObject(DC_BRUSH));
    Ellipse(dc, r.left, r.top, r.right, r.bottom);
    SelectObject(dc, oldBrush);
    SelectObject(dc, oldPen);
    DeleteObject(pen);
}

inline void line(HDC dc, int x0, int y0, int x1, int y1, COLORREF c, int width) {
    HPEN pen = CreatePen(PS_SOLID, std::max(1, width), c);
    HGDIOBJ old = SelectObject(dc, pen);
    MoveToEx(dc, x0, y0, nullptr);
    LineTo(dc, x1, y1);
    SelectObject(dc, old);
    DeleteObject(pen);
}

// Fonts and brushes for one dialog at one DPI. Rebuilt on WM_DPICHANGED.
struct DialogTheme {
    UINT dpi = 96;
    HBRUSH body = nullptr;
    HBRUSH footer = nullptr;
    HBRUSH field = nullptr;
    HFONT title = nullptr;    // "Settings"
    HFONT section = nullptr;  // CONNECTION / VIDEO / AUDIO
    HFONT label = nullptr;    // field labels, values
    HFONT text = nullptr;     // inputs, buttons, checkboxes
    HFONT small = nullptr;    // hints, footer note

    void build(HWND dlg, int titlePt) {
        release();
        dpi = windowDpi(dlg);
        body = CreateSolidBrush(color::kBody);
        footer = CreateSolidBrush(color::kCaption);
        field = CreateSolidBrush(color::kField);
        title = makeFont(titlePt, FW_SEMIBOLD);
        section = makeFont(8, FW_BOLD);
        label = makeFont(9, FW_SEMIBOLD);
        text = makeFont(9, FW_NORMAL);
        small = makeFont(8, FW_NORMAL);
    }

    void release() {
        for (HGDIOBJ* o : {reinterpret_cast<HGDIOBJ*>(&body), reinterpret_cast<HGDIOBJ*>(&footer),
                           reinterpret_cast<HGDIOBJ*>(&field), reinterpret_cast<HGDIOBJ*>(&title),
                           reinterpret_cast<HGDIOBJ*>(&section), reinterpret_cast<HGDIOBJ*>(&label),
                           reinterpret_cast<HGDIOBJ*>(&text), reinterpret_cast<HGDIOBJ*>(&small)}) {
            if (*o) DeleteObject(*o);
            *o = nullptr;
        }
    }

    ~DialogTheme() { release(); }

private:
    HFONT makeFont(int pt, int weight) const {
        return CreateFontW(-MulDiv(pt, static_cast<int>(dpi), 72), 0, 0, 0, weight, FALSE, FALSE,
                           FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                           CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    }
};

// Child rectangle in the parent's client coordinates.
inline RECT childRect(HWND parent, int id) {
    RECT r{};
    HWND child = GetDlgItem(parent, id);
    if (!child) return r;
    GetWindowRect(child, &r);
    MapWindowPoints(nullptr, parent, reinterpret_cast<POINT*>(&r), 2);
    return r;
}

// Owner-drawn check boxes keep their state in GWLP_USERDATA.
inline bool ownerChecked(HWND dlg, int id) {
    HWND b = GetDlgItem(dlg, id);
    return b && GetWindowLongPtrW(b, GWLP_USERDATA) != 0;
}

inline void setOwnerChecked(HWND dlg, int id, bool on) {
    HWND b = GetDlgItem(dlg, id);
    if (!b) return;
    if ((GetWindowLongPtrW(b, GWLP_USERDATA) != 0) == on) return;
    SetWindowLongPtrW(b, GWLP_USERDATA, on ? 1 : 0);
    InvalidateRect(b, nullptr, FALSE);
}

// Push button: primary (filled blue) or secondary (outlined).
inline void drawButton(const DRAWITEMSTRUCT& di, const DialogTheme& t, bool primary,
                       COLORREF behind) {
    HDC dc = di.hDC;
    const RECT r = di.rcItem;
    fillRect(dc, r, behind);
    const bool down = (di.itemState & ODS_SELECTED) != 0;
    const bool focus = (di.itemState & ODS_FOCUS) && !(di.itemState & ODS_NOFOCUSRECT);
    const COLORREF fill = primary ? (down ? color::kPrimaryDown : color::kPrimary)
                                  : (down ? color::kSecondaryDown : color::kSecondary);
    const COLORREF edge = focus ? color::kFocusRing : (primary ? fill : color::kBorder);
    roundRect(dc, r, px(t.dpi, 8), fill, edge, focus ? px(t.dpi, 2) : px(t.dpi, 1));
    wchar_t text[64]{};
    GetWindowTextW(di.hwndItem, text, static_cast<int>(std::size(text)));
    HGDIOBJ oldFont = SelectObject(dc, primary ? t.label : t.text);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, color::kText);
    RECT tr = r;
    DrawTextW(dc, text, -1, &tr, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_HIDEPREFIX);
    SelectObject(dc, oldFont);
}

// Check box: rounded box with a tick, label to the right.
inline void drawCheckBox(const DRAWITEMSTRUCT& di, const DialogTheme& t, bool checked,
                         COLORREF behind) {
    HDC dc = di.hDC;
    const RECT r = di.rcItem;
    fillRect(dc, r, behind);
    const bool focus = (di.itemState & ODS_FOCUS) && !(di.itemState & ODS_NOFOCUSRECT);
    const int box = px(t.dpi, 16);
    const int top = r.top + (r.bottom - r.top - box) / 2;
    const RECT b{r.left + px(t.dpi, 1), top, r.left + px(t.dpi, 1) + box, top + box};
    roundRect(dc, b, px(t.dpi, 5), checked ? color::kPrimary : color::kField,
              focus ? color::kFocusRing : (checked ? color::kPrimary : color::kBorder),
              focus ? px(t.dpi, 2) : px(t.dpi, 1));
    if (checked) {
        const int w = std::max(1, px(t.dpi, 2));
        const int x0 = b.left + box * 4 / 16, y0 = b.top + box * 8 / 16;
        const int x1 = b.left + box * 7 / 16, y1 = b.top + box * 11 / 16;
        const int x2 = b.left + box * 12 / 16, y2 = b.top + box * 5 / 16;
        line(dc, x0, y0, x1, y1, color::kText, w);
        line(dc, x1, y1, x2, y2, color::kText, w);
    }
    wchar_t text[64]{};
    GetWindowTextW(di.hwndItem, text, static_cast<int>(std::size(text)));
    HGDIOBJ oldFont = SelectObject(dc, t.text);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, IsWindowEnabled(di.hwndItem) ? color::kText : color::kDisabled);
    RECT tr = r;
    tr.left = b.right + px(t.dpi, 8);
    DrawTextW(dc, text, -1, &tr, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_HIDEPREFIX);
    SelectObject(dc, oldFont);
}

// Trackbar custom draw (WM_NOTIFY / NM_CUSTOMDRAW). Paints the whole control
// at CDDS_PREPAINT and skips the default drawing (so no dotted focus box):
// flat track, blue fill up to the thumb, round thumb, a ring when focused.
inline LRESULT drawSlider(const NMCUSTOMDRAW& cd, const DialogTheme& t) {
    if (cd.dwDrawStage != CDDS_PREPAINT) return CDRF_DODEFAULT;
    HWND slider = cd.hdr.hwndFrom;
    const bool enabled = IsWindowEnabled(slider) != FALSE;
    const bool focus = GetFocus() == slider &&
        !(SendMessageW(slider, WM_QUERYUISTATE, 0, 0) & UISF_HIDEFOCUS);
    RECT client{}, channel{}, thumb{};
    GetClientRect(slider, &client);
    SendMessageW(slider, TBM_GETCHANNELRECT, 0, reinterpret_cast<LPARAM>(&channel));
    SendMessageW(slider, TBM_GETTHUMBRECT, 0, reinterpret_cast<LPARAM>(&thumb));
    fillRect(cd.hdc, client, color::kBody);
    const int cx = (thumb.left + thumb.right) / 2;
    const int cy = (client.top + client.bottom) / 2;
    const int h = std::max(2, px(t.dpi, 4));
    RECT track{channel.left, cy - h / 2, channel.right, cy - h / 2 + h};
    roundRect(cd.hdc, track, h, color::kBorder, color::kBorder);
    if (enabled && cx > track.left) {
        RECT filled = track;
        filled.right = cx;
        roundRect(cd.hdc, filled, h, color::kAccent, color::kAccent);
    }
    const int d = px(t.dpi, 16);
    RECT dot{cx - d / 2, cy - d / 2, cx - d / 2 + d, cy - d / 2 + d};
    if (focus) {
        const int g = px(t.dpi, 3);
        RECT ring{dot.left - g, dot.top - g, dot.right + g, dot.bottom + g};
        ellipse(cd.hdc, ring, color::kBody, color::kFocusRing, px(t.dpi, 2));
    }
    ellipse(cd.hdc, dot, enabled ? color::kAccent : color::kDisabled,
            enabled ? color::kText : color::kDisabled, px(t.dpi, 2));
    return CDRF_SKIPDEFAULT;
}

}  // namespace jl::ui
