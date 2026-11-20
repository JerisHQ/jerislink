#pragma once
// Launch screen state for connection-password answers (design §7): one
// screen, red text, no modal, focus back to the password field. Pure logic
// (no Win32) so auth_ui_test.cpp can drive it with a fake clock.

#include "conn_auth.hpp"

#include <chrono>
#include <cstdint>
#include <cwchar>
#include <string>

namespace jl::auth::ui {

struct View {
    std::wstring text;           // red error line; empty = none
    bool connectEnabled = true;  // the Connect button
    bool focusPassword = false;  // put the caret back in the password field
    bool clearPassword = false;  // empty the password field (it was wrong)
};

inline std::wstring waitText(uint32_t seconds) {
    wchar_t buf[96];
    const uint32_t m = seconds / 60, s = seconds % 60;
    if (m > 0) std::swprintf(buf, 96, L"Too many wrong tries. Wait %u min %u s.", m, s);
    else std::swprintf(buf, 96, L"Too many wrong tries. Wait %u s.", s);
    return buf;
}

inline std::wstring failText(uint8_t triesLeft, bool savedKey) {
    if (savedKey) return L"The saved password no longer works. Enter the connection password.";
    if (triesLeft == 0) return L"Wrong password.";
    wchar_t buf[96];
    std::swprintf(buf, 96, L"Wrong password (%u %ls left).", unsigned(triesLeft), triesLeft == 1 ? L"try" : L"tries");
    return buf;
}

class LaunchState {
public:
    using Clock = std::chrono::steady_clock;

    // A new answer from the host. Returns true when it is one the launch
    // screen shows (terminal); false means carry on connecting.
    bool apply(const Report& r, Clock::time_point now) {
        lockedUntil_ = {};
        view_ = View{};
        switch (r.outcome) {
        case Outcome::Ok:
        case Outcome::Open:
        case Outcome::Network:
        case Outcome::Retry:
            return false;
        case Outcome::Fail:
            view_.text = failText(r.triesLeft, r.usedSavedKey);
            view_.clearPassword = true;
            break;
        case Outcome::Locked:
            lockedUntil_ = now + std::chrono::seconds(r.retrySeconds);
            view_.text = waitText(r.retrySeconds);
            view_.connectEnabled = r.retrySeconds == 0;
            view_.clearPassword = true;
            break;
        case Outcome::Blocked:
            view_.text = L"This PC is blocked by the Mac. Unblock it on the Mac to connect.";
            break;
        case Outcome::AuthRequired:
            view_.text = L"This Mac needs a connection password. Enter it and connect again.";
            break;
        case Outcome::HostMismatch:
            view_.text = L"Host identity does not match (mutual check failed). Nothing was saved.";
            view_.clearPassword = true;
            break;
        case Outcome::HostTooOld:
            view_.text = L"This Mac host is too old. Update it to v0.4.0.";
            break;
        case Outcome::NeedPassword:
            view_.text = L"Enter the connection password for this Mac.";
            break;
        }
        view_.focusPassword = true;
        return true;
    }

    // Once a second while counting down: the text and button follow the clock.
    View view(Clock::time_point now) const {
        View v = view_;
        if (lockedUntil_ != Clock::time_point{}) {
            const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(lockedUntil_ - now).count();
            if (left <= 0) {
                v.text.clear();
                v.connectEnabled = true;
            } else {
                v.text = waitText(uint32_t((left + 999) / 1000));
                v.connectEnabled = false;
            }
        }
        return v;
    }

    bool counting(Clock::time_point now) const {
        return lockedUntil_ != Clock::time_point{} && now < lockedUntil_;
    }

    // The countdown has run out: the screen goes back to normal.
    void expireIfDone(Clock::time_point now) {
        if (lockedUntil_ != Clock::time_point{} && now >= lockedUntil_) {
            lockedUntil_ = {};
            view_ = View{};
            view_.focusPassword = true;
        }
    }

    void clear() { lockedUntil_ = {}; view_ = View{}; }

private:
    View view_;
    Clock::time_point lockedUntil_{};
};

}  // namespace jl::auth::ui
