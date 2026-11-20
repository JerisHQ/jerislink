#pragma once
// Launch screen state for connection-password answers (design §7): one
// screen, red text, no modal, focus back to the password field. Pure logic
// (no Win32) so auth_ui_test.cpp can drive it with a fake clock.

#include "conn_auth.hpp"

#include <chrono>
#include <cstdint>
#include <cwchar>
#include <cwctype>
#include <optional>
#include <string>

namespace jl::auth::ui {

struct View {
    std::wstring text;           // red error line; empty = none
    bool connectEnabled = true;  // the Connect button
    bool focusPassword = false;  // put the caret back in the password field
    bool clearPassword = false;  // empty the password field (it was wrong)
    // Show "Retry without password": the only way a host known to want a
    // password is probed again (the user says the Mac dropped it).
    bool offerNoPassword = false;
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

inline std::wstring probeRaceText(uint8_t triesLeft) {
    wchar_t buf[128];
    std::swprintf(buf, 128, L"The Mac counted a connection check as a wrong try (%u %ls left). Connect again.",
                  unsigned(triesLeft), triesLeft == 1 ? L"try" : L"tries");
    return buf;
}

// A terminal answer handed from the session (a background channel, or the
// CLI preflight) back to the launch screen of the relaunched process, so it
// shows the same line, countdown and focus as an answer it got itself.
// "v1;o=<outcome>;t=<tries>;k=<saved key>;p=<probe race>;u=<locked until>"
// where u is a GetTickCount64 value (shared by every process on the PC).
inline std::wstring encodeHandoff(const Report& r, uint64_t nowTickMs) {
    if (!isTerminal(r.outcome)) return {};
    const uint64_t until = r.outcome == Outcome::Locked ? nowTickMs + uint64_t(r.retrySeconds) * 1000 : 0;
    wchar_t buf[128];
    std::swprintf(buf, 128, L"v1;o=%d;t=%u;k=%d;p=%d;u=%llu", int(r.outcome), unsigned(r.triesLeft),
                  r.usedSavedKey ? 1 : 0, r.probeRace ? 1 : 0, static_cast<unsigned long long>(until));
    return buf;
}

inline std::optional<Report> decodeHandoff(const std::wstring& text, uint64_t nowTickMs) {
    if (text.rfind(L"v1;", 0) != 0) return std::nullopt;
    long long o = -1, t = -1, k = -1, p = -1;
    unsigned long long u = 0;
    bool haveU = false;
    size_t pos = 3;
    while (pos < text.size()) {
        size_t end = text.find(L';', pos);
        if (end == std::wstring::npos) end = text.size();
        const std::wstring field = text.substr(pos, end - pos);
        pos = end + 1;
        if (field.size() < 3 || field[1] != L'=') return std::nullopt;
        const std::wstring value = field.substr(2);
        if (value.empty() || value.size() > 20) return std::nullopt;
        for (wchar_t c : value) if (!std::iswdigit(c)) return std::nullopt;
        const unsigned long long n = std::wcstoull(value.c_str(), nullptr, 10);
        switch (field[0]) {
        case L'o': o = static_cast<long long>(n); break;
        case L't': t = static_cast<long long>(n); break;
        case L'k': k = static_cast<long long>(n); break;
        case L'p': p = static_cast<long long>(n); break;
        case L'u': u = n; haveU = true; break;
        default: return std::nullopt;
        }
    }
    if (o < 0 || o > int(Outcome::Network) || t < 0 || t > 255 || k < 0 || k > 1 || p < 0 || p > 1 || !haveU)
        return std::nullopt;
    Report r;
    r.outcome = static_cast<Outcome>(o);
    if (!isTerminal(r.outcome)) return std::nullopt;
    r.triesLeft = static_cast<uint8_t>(t);
    r.usedSavedKey = k == 1;
    r.probeRace = p == 1;
    if (r.outcome == Outcome::Locked) {
        // Time spent relaunching counts; a lockout never exceeds a day.
        const uint64_t left = u > nowTickMs ? u - nowTickMs : 0;
        if (left > 24ull * 3600 * 1000) return std::nullopt;
        r.retrySeconds = static_cast<uint32_t>((left + 999) / 1000);
    }
    return r;
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
            if (r.probeRace) {
                // Not a wrong password: the probe (no password) was counted.
                view_.text = probeRaceText(r.triesLeft);
                break;
            }
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
        case Outcome::LocalError:
            view_.text = L"Windows could not compute the connection check. Nothing was sent; try again.";
            break;
        case Outcome::NoChallenge:
            // Known to want a password, but no challenge came: a slow line
            // or a busy Mac. Nothing was sent, no try spent, no probe.
            view_.text = L"This Mac wants a connection password but did not answer in time. Connect again, "
                         L"or use Retry without password if it no longer has one.";
            view_.offerNoPassword = true;
            break;
        case Outcome::RaceUnanswered:
            // The Mac switched to a password during our check and did not
            // say what it counted. No automatic retry; it is not probed again.
            view_.text = L"This Mac now needs a connection password. Enter it and connect again.";
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
