// What the viewer's receive loop sleeps on when no video packet is waiting,
// and the timer resolution it sleeps with. Header-only so the console test
// (loop_wait_test.cpp) runs the same code as the viewer.
#pragma once

#include <winsock2.h>
#include <windows.h>
#include <timeapi.h>

#pragma comment(lib, "winmm.lib")

namespace jl {

// Handles the loop wakes on besides window messages: the video socket
// event, the swap chain latency object, the MRM1 socket event (pongs and
// cursor shapes). A null handle is skipped, so the mapping from wait result
// back to the source stays right whatever is present.
struct LoopWait {
    enum Wake { Timeout, Video, Present, Mrm1, Message, Failed };
    static constexpr DWORD kMax = 3;

    HANDLE handles[kMax]{};
    Wake kinds[kMax]{};
    DWORD count = 0;

    void add(HANDLE h, Wake kind) {
        if (!h || count >= kMax) return;
        handles[count] = h;
        kinds[count] = kind;
        ++count;
    }

    Wake wait(DWORD timeoutMs) const {
        const DWORD w = MsgWaitForMultipleObjects(count, count ? handles : nullptr,
                                                  FALSE, timeoutMs, QS_ALLINPUT);
        if (w == WAIT_TIMEOUT) return Timeout;
        if (w >= WAIT_OBJECT_0 && w < WAIT_OBJECT_0 + count) return kinds[w - WAIT_OBJECT_0];
        if (w == WAIT_OBJECT_0 + count) return Message;
        return Failed;
    }
};

// 1 ms system timer while a stream runs. Without it a 1 ms or 5 ms wait
// sleeps a whole default tick (about 15.6 ms), which delays the NACK
// reorder grace, the receiver hold timer and the present poll. Released
// when the stream ends, so the viewer only pays the power cost while
// streaming.
class ScopedTimerResolution {
public:
    explicit ScopedTimerResolution(UINT ms = 1)
        : ms_(ms), active_(timeBeginPeriod(ms) == TIMERR_NOERROR) {}
    ~ScopedTimerResolution() { if (active_) timeEndPeriod(ms_); }
    ScopedTimerResolution(const ScopedTimerResolution&) = delete;
    ScopedTimerResolution& operator=(const ScopedTimerResolution&) = delete;
    bool active() const { return active_; }
    UINT periodMs() const { return ms_; }

private:
    UINT ms_;
    bool active_;
};

} // namespace jl
