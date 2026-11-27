// JerisLink Windows host, H2: viewer input -> SendInput, and the cursor
// shape the viewer draws.
//
// Keys go in as scan codes (KEYEVENTF_SCANCODE), so the host's own keyboard
// layout turns them into characters, as a local keyboard would. The pointer
// is placed on the captured monitor with absolute virtual-desktop
// coordinates. Only the input owner's frames go in, and everything it
// pressed is released when it closes or a newer connection takes over
// (InputClaims, r8); a key or button held still stays down.
//
// SendInput reaches only the desktop this process runs on, and Windows
// (UIPI) drops input aimed at a window of a higher integrity level, such as
// an elevated Task Manager, when the host itself is not elevated. The
// secure desktop (UAC, lock screen) needs the service of design D1.
#pragma once

#include "host_protocol.hpp"

#include <atomic>
#include <cstdint>
#include <mutex>

namespace jlh {

class InputInjector {
public:
    // The monitor the stream shows (the capture's rect); before the first
    // capture, the primary monitor.
    void setDesktop(const DesktopRect& r);

    // One decoded MRC1 input frame from control connection `owner` (the
    // input owner), run inside InputClaims::frame with the HeldInput it
    // passes, so nothing else touches the claims meanwhile. False when
    // Windows took no input (the event is counted in failed()) or the event
    // was not one to inject (ignored()). A POINTER_SYNC only moves the
    // pointer here; its seq is for the host's Mrm1Session.
    bool apply(const InputEvent& e, HeldInput::Owner owner, HeldInput& held);
    // MRM1 0x24.
    bool moveNormalized(int nx, int ny);
    // An up straight to Windows, for InputClaims' releases (takeover,
    // close, retry). True when Windows took it.
    bool upKey(uint16_t vk);
    bool upButton(uint8_t b);

    uint64_t injected() const { return injected_.load(); }
    uint64_t failed() const { return failed_.load(); }
    uint64_t ignored() const { return ignored_.load(); }
    // Up frames not sent to Windows because another connection still holds
    // that key or button (HeldInput's rule).
    uint64_t upsHeld() const { return upsHeld_.load(); }
    // The GetLastError of the most recent SendInput that took nothing.
    unsigned long lastError() const { return lastError_.load(); }

private:
    bool key(uint16_t semantic, bool down, HeldInput::Owner owner, HeldInput& held);
    bool button(uint8_t b, bool down, HeldInput::Owner owner, HeldInput& held);
    bool movePixel(int x, int y);
    bool moveRelative(int dx, int dy);
    bool scroll(int dx, int dy);
    bool taskManager(HeldInput& held);
    bool sendKeyVk(uint16_t vk, bool down);
    bool sendButton(uint8_t b, bool down);
    bool countUp(HeldInput::Up r);
    DesktopRect desktopLocked() const;

    mutable std::mutex m_;  // the desktop rect; SendInput itself is thread-safe
    DesktopRect desktop_{};
    bool haveDesktop_ = false;
    std::atomic<uint64_t> injected_{0}, failed_{0}, ignored_{0}, upsHeld_{0};
    std::atomic<unsigned long> lastError_{0};
};

// The global cursor's shape as a viewer code: a standard system cursor maps
// to its code, anything else (an application's own cursor, none shown) to
// the arrow.
CursorShape currentCursorShape();

}  // namespace jlh
