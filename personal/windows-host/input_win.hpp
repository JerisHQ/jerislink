// JerisLink Windows host, H2: viewer input -> SendInput, and the cursor
// shape the viewer draws.
//
// Keys go in as scan codes (KEYEVENTF_SCANCODE), so the host's own keyboard
// layout turns them into characters, as a local keyboard would. The pointer
// is placed on the captured monitor with absolute virtual-desktop
// coordinates. Everything this host pressed is released when the viewer's
// control connection goes away.
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

    // One decoded MRC1 input frame. False when Windows took no input (the
    // event is counted in failed()) or the event was not one to inject
    // (ignored()).
    bool apply(const InputEvent& e);
    // MRM1 0x24.
    bool moveNormalized(int nx, int ny);
    // Releases every key and button this host pressed; returns how many.
    size_t releaseAll();

    uint64_t injected() const { return injected_.load(); }
    uint64_t failed() const { return failed_.load(); }
    uint64_t ignored() const { return ignored_.load(); }
    // The GetLastError of the most recent SendInput that took nothing.
    unsigned long lastError() const { return lastError_.load(); }

private:
    bool key(uint16_t semantic, bool down);
    bool button(uint8_t b, bool down);
    bool movePixel(int x, int y);
    bool moveRelative(int dx, int dy);
    bool scroll(int dx, int dy);
    bool taskManager();
    bool sendKeyVk(uint16_t vk, bool down);
    bool sendButton(uint8_t b, bool down);
    DesktopRect desktopLocked() const;

    mutable std::mutex m_;  // held state and the desktop rect; SendInput itself is thread-safe
    DesktopRect desktop_{};
    bool haveDesktop_ = false;
    HeldInput held_;
    std::atomic<uint64_t> injected_{0}, failed_{0}, ignored_{0};
    std::atomic<unsigned long> lastError_{0};
};

// The global cursor's shape as a viewer code: a standard system cursor maps
// to its code, anything else (an application's own cursor, none shown) to
// the arrow.
CursorShape currentCursorShape();

}  // namespace jlh
