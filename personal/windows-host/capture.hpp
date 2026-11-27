// JerisLink Windows host: screen capture (H1).
//
// DXGI Desktop Duplication on the first output of the first adapter that
// has one; GDI BitBlt of the primary screen as the fallback (and with
// --capture gdi), for a desktop where duplication is not available. Both
// hand back BGRA in CPU memory: H1 converts and encodes in software.
#pragma once

#include "host_protocol.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace jlh {

enum class CaptureMode { Auto, Dda, Gdi };

struct CapturedFrame {
    const uint8_t* bgra = nullptr;  // valid until the next acquire()
    int width = 0, height = 0;
    size_t stride = 0;
};

class ScreenCapture {
public:
    ScreenCapture();
    ~ScreenCapture();
    ScreenCapture(const ScreenCapture&) = delete;
    ScreenCapture& operator=(const ScreenCapture&) = delete;

    bool open(CaptureMode mode, std::string& error);
    void close();
    const char* backend() const;  // "dda", "gdi" or "none"
    std::string describe() const; // adapter / output, for the log
    // Where the captured monitor sits on the virtual desktop, in pixels (H2
    // places the pointer with it). Width and height follow the frames.
    DesktopRect desktopRect() const;

    // 1: a new frame; 0: nothing changed within timeoutMs; -1: error (call
    // open() again, e.g. after ACCESS_LOST or a desktop switch).
    int acquire(int timeoutMs, CapturedFrame& out, std::string& error);

private:
    struct Impl;
    Impl* impl_ = nullptr;
    // Set when DDA opens but cannot hand back frames we can use (staging
    // texture, pixel format). Reopening would hit it again, so Auto then
    // uses GDI for the rest of the process.
    std::string ddaUnusable_;
};

}  // namespace jlh
