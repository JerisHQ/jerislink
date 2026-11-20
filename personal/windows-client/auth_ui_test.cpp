// Launch screen answers for the connection password (auth_ui.hpp): one
// screen, red text, no modal, focus back to the password field, tries left,
// the locked countdown with Connect greyed out, blocked, auth_required,
// host too old, mutual check failure; ok / open / retry carry on.
#include "auth_ui.hpp"

#include <cstdio>
#include <string>

namespace {

int gPass = 0;
int gFail = 0;

void expect(bool cond, const std::string& what) {
    if (cond) { ++gPass; std::printf("PASS %s\n", what.c_str()); }
    else { ++gFail; std::printf("FAIL %s\n", what.c_str()); }
}

using namespace jl::auth;
using namespace jl::auth::ui;
using Clock = LaunchState::Clock;

Report rep(Outcome o, uint8_t tries = 0, uint32_t retry = 0, bool saved = false) {
    Report r;
    r.outcome = o;
    r.triesLeft = tries;
    r.retrySeconds = retry;
    r.usedSavedKey = saved;
    return r;
}

void carryOnTests() {
    LaunchState s;
    const auto t0 = Clock::now();
    for (Outcome o : {Outcome::Ok, Outcome::Open, Outcome::Retry, Outcome::Network}) {
        expect(!s.apply(rep(o), t0), std::string("carry on, no error: ") + outcomeName(o));
        expect(s.view(t0).text.empty() && s.view(t0).connectEnabled, std::string("  screen clean after ") + outcomeName(o));
    }
}

void failTests() {
    LaunchState s;
    const auto t0 = Clock::now();
    expect(s.apply(rep(Outcome::Fail, 4), t0), "fail is shown");
    View v = s.view(t0);
    expect(v.text == L"Wrong password (4 tries left).", "fail: tries left in the text");
    expect(v.connectEnabled && v.focusPassword && v.clearPassword, "fail: Connect on, focus + clear password");
    s.apply(rep(Outcome::Fail, 1), t0);
    expect(s.view(t0).text == L"Wrong password (1 try left).", "fail: singular");
    s.apply(rep(Outcome::Fail, 0), t0);
    expect(s.view(t0).text == L"Wrong password.", "fail: no count when 0");
    s.apply(rep(Outcome::Fail, 3, 0, true), t0);
    expect(s.view(t0).text.find(L"saved password no longer works") != std::wstring::npos, "fail with saved key: asks for the password");
}

void lockedTests() {
    LaunchState s;
    const auto t0 = Clock::now();
    expect(s.apply(rep(Outcome::Locked, 0, 125), t0), "locked is shown");
    View v = s.view(t0);
    expect(v.text == L"Too many wrong tries. Wait 2 min 5 s.", "locked: M min S s");
    expect(!v.connectEnabled && v.focusPassword, "locked: Connect greyed out, focus on password");
    expect(s.counting(t0), "locked: counting");
    v = s.view(t0 + std::chrono::milliseconds(65500));
    expect(v.text == L"Too many wrong tries. Wait 1 min 0 s.", "locked: ticks down (65.5 s later)");
    v = s.view(t0 + std::chrono::seconds(124) + std::chrono::milliseconds(100));
    expect(v.text == L"Too many wrong tries. Wait 1 s." && !v.connectEnabled, "locked: last second");
    const auto end = t0 + std::chrono::seconds(125);
    v = s.view(end);
    expect(v.text.empty() && v.connectEnabled, "locked: Connect back at zero");
    expect(!s.counting(end), "locked: stops counting");
    s.expireIfDone(end);
    v = s.view(end);
    expect(v.text.empty() && v.connectEnabled && v.focusPassword, "locked: expire leaves a clean screen, focus on password");
    // A 0 s lock does not grey out Connect.
    s.apply(rep(Outcome::Locked, 0, 0), t0);
    expect(s.view(t0).connectEnabled, "locked 0 s: Connect on");
    // A new answer replaces the countdown.
    s.apply(rep(Outcome::Locked, 0, 300), t0);
    s.apply(rep(Outcome::Blocked), t0);
    expect(!s.counting(t0) && s.view(t0).connectEnabled, "new answer ends the countdown");
}

void otherTests() {
    LaunchState s;
    const auto t0 = Clock::now();
    struct Case { Outcome o; const wchar_t* needle; bool clear; };
    const Case cases[] = {
        {Outcome::Blocked, L"Unblock it on the Mac", false},
        {Outcome::AuthRequired, L"needs a connection password", false},
        {Outcome::HostMismatch, L"Host identity does not match", true},
        {Outcome::HostTooOld, L"too old", false},
        {Outcome::NeedPassword, L"Enter the connection password", false},
    };
    for (const Case& c : cases) {
        expect(s.apply(rep(c.o), t0), std::string("shown: ") + outcomeName(c.o));
        View v = s.view(t0);
        expect(v.text.find(c.needle) != std::wstring::npos, std::string("  text: ") + outcomeName(c.o));
        expect(v.connectEnabled && v.focusPassword, std::string("  Connect on, focus password: ") + outcomeName(c.o));
        expect(v.clearPassword == c.clear, std::string("  clear password: ") + outcomeName(c.o));
    }
    s.clear();
    expect(s.view(t0).text.empty(), "clear: no error");
    expect(waitText(59) == L"Too many wrong tries. Wait 59 s.", "wait text under a minute");
    expect(waitText(600) == L"Too many wrong tries. Wait 10 min 0 s.", "wait text 10 min");
}

}  // namespace

int main() {
    carryOnTests();
    failTests();
    lockedTests();
    otherTests();
    std::printf("%d passed, %d failed\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
