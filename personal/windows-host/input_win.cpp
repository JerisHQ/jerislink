#include "input_win.hpp"

#include <windows.h>

#include <algorithm>

namespace jlh {

static_assert(vk::Back == VK_BACK && vk::Tab == VK_TAB && vk::Return == VK_RETURN && vk::Capital == VK_CAPITAL &&
                  vk::Escape == VK_ESCAPE && vk::Space == VK_SPACE && vk::Prior == VK_PRIOR && vk::Next == VK_NEXT &&
                  vk::End == VK_END && vk::Home == VK_HOME && vk::Left == VK_LEFT && vk::Up == VK_UP &&
                  vk::Right == VK_RIGHT && vk::Down == VK_DOWN && vk::Insert == VK_INSERT && vk::Delete == VK_DELETE,
              "host_protocol.hpp VK constants");
static_assert(vk::LWin == VK_LWIN && vk::RWin == VK_RWIN && vk::Numpad0 == VK_NUMPAD0 && vk::Numpad9 == VK_NUMPAD9 &&
                  vk::Multiply == VK_MULTIPLY && vk::Add == VK_ADD && vk::Subtract == VK_SUBTRACT &&
                  vk::Decimal == VK_DECIMAL && vk::Divide == VK_DIVIDE && vk::F1 == VK_F1 && vk::F12 == VK_F12 &&
                  vk::LShift == VK_LSHIFT && vk::LControl == VK_LCONTROL && vk::RControl == VK_RCONTROL &&
                  vk::LMenu == VK_LMENU && vk::RMenu == VK_RMENU,
              "host_protocol.hpp VK constants");
static_assert(vk::Oem1 == VK_OEM_1 && vk::OemPlus == VK_OEM_PLUS && vk::OemComma == VK_OEM_COMMA &&
                  vk::OemMinus == VK_OEM_MINUS && vk::OemPeriod == VK_OEM_PERIOD && vk::Oem2 == VK_OEM_2 &&
                  vk::Oem3 == VK_OEM_3 && vk::Oem4 == VK_OEM_4 && vk::Oem5 == VK_OEM_5 && vk::Oem6 == VK_OEM_6 &&
                  vk::Oem7 == VK_OEM_7,
              "host_protocol.hpp VK constants");

namespace {

bool sendInputs(INPUT* in, UINT n, std::atomic<unsigned long>& lastError) {
    if (SendInput(n, in, sizeof(INPUT)) == n) return true;
    lastError = GetLastError();
    return false;
}

INPUT mouseInput(DWORD flags, LONG dx = 0, LONG dy = 0, DWORD data = 0) {
    INPUT in{};
    in.type = INPUT_MOUSE;
    in.mi.dx = dx;
    in.mi.dy = dy;
    in.mi.mouseData = data;
    in.mi.dwFlags = flags;
    return in;
}

}  // namespace

void InputInjector::setDesktop(const DesktopRect& r) {
    if (r.width <= 0 || r.height <= 0) return;
    std::lock_guard<std::mutex> g(m_);
    desktop_ = r;
    haveDesktop_ = true;
}

DesktopRect InputInjector::desktopLocked() const {
    if (haveDesktop_) return desktop_;
    return DesktopRect{0, 0, GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)};
}

bool InputInjector::apply(const InputEvent& e, HeldInput::Owner owner) {
    switch (e.kind) {
    case InputEvent::Kind::Key: return key(e.semantic, e.down, owner);
    case InputEvent::Kind::Button: return button(e.button, e.down, owner);
    case InputEvent::Kind::MoveNorm:
    case InputEvent::Kind::PointerSync: return moveNormalized(e.x, e.y);
    case InputEvent::Kind::MoveAbsPixels: {
        DesktopRect r;
        {
            std::lock_guard<std::mutex> g(m_);
            r = desktopLocked();
        }
        return movePixel(r.left + std::min(e.x, std::max(0, r.width - 1)),
                         r.top + std::min(e.y, std::max(0, r.height - 1)));
    }
    case InputEvent::Kind::MoveRel: return moveRelative(e.x, e.y);
    case InputEvent::Kind::Scroll: return scroll(e.x, e.y);
    case InputEvent::Kind::TaskManager: return taskManager();
    }
    return false;
}

bool InputInjector::moveNormalized(int nx, int ny) {
    DesktopRect r;
    {
        std::lock_guard<std::mutex> g(m_);
        r = desktopLocked();
    }
    int px = 0, py = 0;
    normToDesktop(nx, ny, r, px, py);
    return movePixel(px, py);
}

bool InputInjector::movePixel(int x, int y) {
    const int vl = GetSystemMetrics(SM_XVIRTUALSCREEN), vt = GetSystemMetrics(SM_YVIRTUALSCREEN);
    const int vw = GetSystemMetrics(SM_CXVIRTUALSCREEN), vh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    INPUT in = mouseInput(MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK, toAbsolute(x, vl, vw),
                          toAbsolute(y, vt, vh));
    if (!sendInputs(&in, 1, lastError_)) { ++failed_; return false; }
    ++injected_;
    return true;
}

bool InputInjector::moveRelative(int dx, int dy) {
    INPUT in = mouseInput(MOUSEEVENTF_MOVE, dx, dy);
    if (!sendInputs(&in, 1, lastError_)) { ++failed_; return false; }
    ++injected_;
    return true;
}

bool InputInjector::scroll(int dx, int dy) {
    // The viewer sends WM_MOUSEWHEEL / WM_MOUSEHWHEEL deltas (120 a notch at
    // its default --scroll-scale 1), same signs as Windows: through as is.
    INPUT in[2];
    UINT n = 0;
    if (dy) in[n++] = mouseInput(MOUSEEVENTF_WHEEL, 0, 0, DWORD(dy));
    if (dx) in[n++] = mouseInput(MOUSEEVENTF_HWHEEL, 0, 0, DWORD(dx));
    if (!n) { ++ignored_; return false; }
    if (!sendInputs(in, n, lastError_)) { ++failed_; return false; }
    ++injected_;
    return true;
}

bool InputInjector::sendButton(uint8_t b, bool down) {
    static const DWORD kDown[3] = {MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_RIGHTDOWN, MOUSEEVENTF_MIDDLEDOWN};
    static const DWORD kUp[3] = {MOUSEEVENTF_LEFTUP, MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_MIDDLEUP};
    INPUT in = mouseInput(down ? kDown[b] : kUp[b]);
    return sendInputs(&in, 1, lastError_);
}

// An up frame, by HeldInput's rule (Pepper's reviews of 8f8a33b, item 2,
// of f97ad11, item 1, of 04622f0 and of c397898, item 1): it ends the
// sender's own claim only, and goes to Windows only when no other
// connection still holds it.
bool InputInjector::countUp(HeldInput::Up r) {
    switch (r) {
    case HeldInput::Up::Sent: ++injected_; return true;
    case HeldInput::Up::Held: ++upsHeld_; return true;
    case HeldInput::Up::Failed: break;
    }
    ++failed_;
    return false;
}

bool InputInjector::button(uint8_t b, bool down, HeldInput::Owner owner) {
    if (b > 2) { ++ignored_; return false; }
    std::lock_guard<std::mutex> g(m_);
    if (!down)
        return countUp(claims_.held().releaseButton(b, owner, [this](uint8_t x) { return sendButton(x, false); }));
    if (!sendButton(b, true)) {
        ++failed_;
        return false;
    }
    claims_.held().pressButton(b, owner);
    ++injected_;
    return true;
}

bool InputInjector::sendKeyVk(uint16_t v, bool down) {
    INPUT in{};
    in.type = INPUT_KEYBOARD;
    const UINT scan = MapVirtualKeyW(v, MAPVK_VK_TO_VSC);
    if (scan) {
        in.ki.wScan = WORD(scan);
        in.ki.dwFlags = KEYEVENTF_SCANCODE;
    } else {
        in.ki.wVk = v;  // no scan code in this layout: by VK
    }
    if (isExtendedVk(v)) in.ki.dwFlags |= KEYEVENTF_EXTENDEDKEY;
    if (!down) in.ki.dwFlags |= KEYEVENTF_KEYUP;
    return sendInputs(&in, 1, lastError_);
}

bool InputInjector::key(uint16_t semantic, bool down, HeldInput::Owner owner) {
    const uint16_t v = semanticToVk(semantic);
    if (!v) { ++ignored_; return false; }
    std::lock_guard<std::mutex> g(m_);
    // Caps Lock comes as a tap (down, up); it toggles, nothing stays held.
    if (!down) return countUp(claims_.held().releaseKey(v, owner, [this](uint16_t x) { return sendKeyVk(x, false); }));
    if (!sendKeyVk(v, true)) {
        ++failed_;
        return false;
    }
    claims_.held().pressKey(v, owner);
    ++injected_;
    return true;
}

bool InputInjector::taskManager() {
    // MRC1 0x60, the viewer's Force Quit button: on Windows, Ctrl+Shift+Esc.
    // Held keys are released first so the chord is clean. Buttons stay as
    // they are (Pepper's H2 review, item 3): no up goes to Windows for them,
    // so their records stay too, and a later up or close releases them. A
    // key whose up Windows did not take stays recorded as well.
    std::lock_guard<std::mutex> g(m_);
    claims_.held().releaseKeys([this](uint16_t v) { return sendKeyVk(v, false); });
    const uint16_t seq[] = {vk::LControl, vk::LShift, vk::Escape};
    bool ok = true;
    for (uint16_t v : seq) ok = sendKeyVk(v, true) && ok;
    for (int i = 2; i >= 0; --i) ok = sendKeyVk(seq[i], false) && ok;
    if (!ok) { ++failed_; return false; }
    ++injected_;
    return true;
}

HeldInput::Owner InputInjector::open(int64_t nowMs) {
    std::lock_guard<std::mutex> g(m_);
    return claims_.open(nowMs);
}

void InputInjector::heard(HeldInput::Owner owner, int64_t nowMs) {
    std::lock_guard<std::mutex> g(m_);
    claims_.heard(owner, nowMs);
}

void InputInjector::heardPointer(int64_t nowMs) {
    std::lock_guard<std::mutex> g(m_);
    claims_.heardPointer(nowMs);
}

InputClaims::Admit InputInjector::admitInput(HeldInput::Owner owner) {
    std::lock_guard<std::mutex> g(m_);
    const auto r = claims_.admitInput(owner, [this](uint16_t v) { return sendKeyVk(v, false); },
                                      [this](uint8_t b) { return sendButton(b, false); });
    if (!r.ok) ++replacedDropped_;
    replaced_ += r.replaced;
    return r;
}

size_t InputInjector::close(HeldInput::Owner owner) {
    std::lock_guard<std::mutex> g(m_);
    return claims_.close(owner, [this](uint16_t v) { return sendKeyVk(v, false); },
                         [this](uint8_t b) { return sendButton(b, false); });
}

InputClaims::Quiet InputInjector::releaseQuiet(int64_t nowMs) {
    std::lock_guard<std::mutex> g(m_);
    const auto r = claims_.releaseQuiet(nowMs, [this](uint16_t v) { return sendKeyVk(v, false); },
                                        [this](uint8_t b) { return sendButton(b, false); });
    quietReleases_ += r.connections;
    return r;
}

bool InputInjector::anyHeld() const {
    std::lock_guard<std::mutex> g(m_);
    return claims_.held().anyHeld();
}

CursorShape currentCursorShape() {
    CURSORINFO ci{};
    ci.cbSize = sizeof(ci);
    if (!GetCursorInfo(&ci) || !(ci.flags & CURSOR_SHOWING) || !ci.hCursor) return CursorShape::Arrow;
    // System cursors are shared handles: the one in CURSORINFO is the one
    // LoadCursor hands out, in any process.
    static const struct {
        LPCWSTR id;
        CursorShape shape;
    } kMap[] = {
        {IDC_IBEAM, CursorShape::IBeam},          {IDC_HAND, CursorShape::PointingHand},
        {IDC_SIZEWE, CursorShape::ResizeLeftRight}, {IDC_SIZENS, CursorShape::ResizeUpDown},
        {IDC_SIZENWSE, CursorShape::ResizeNwse},  {IDC_SIZENESW, CursorShape::ResizeNesw},
        {IDC_CROSS, CursorShape::Crosshair},      {IDC_NO, CursorShape::NotAllowed},
        {IDC_WAIT, CursorShape::Wait},            {IDC_APPSTARTING, CursorShape::AppStarting},
        {IDC_SIZEALL, CursorShape::Move},
    };
    for (const auto& m : kMap)
        if (ci.hCursor == LoadCursorW(nullptr, m.id)) return m.shape;
    return CursorShape::Arrow;
}

}  // namespace jlh
