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
        {Outcome::LocalError, L"Nothing was sent", false},
        {Outcome::RaceUnanswered, L"now needs a connection password", false},
        {Outcome::NoChallenge, L"did not answer in time", false},
        {Outcome::Replaced, L"Another device is connected", false},  // r2 item 2; r14 item 4
        {Outcome::RetryCapped, L"within 2 minutes", false},  // r14 item 4
    };
    for (const Case& c : cases) {
        expect(s.apply(rep(c.o), t0), std::string("shown: ") + outcomeName(c.o));
        View v = s.view(t0);
        expect(v.text.find(c.needle) != std::wstring::npos, std::string("  text: ") + outcomeName(c.o));
        expect(v.connectEnabled && v.focusPassword, std::string("  Connect on, focus password: ") + outcomeName(c.o));
        expect(v.clearPassword == c.clear, std::string("  clear password: ") + outcomeName(c.o));
        // r4: "Retry without password" is offered for NoChallenge only.
        expect(v.offerNoPassword == (c.o == Outcome::NoChallenge),
               std::string("  retry without password offered: ") + (v.offerNoPassword ? "yes " : "no ") + outcomeName(c.o));
    }
    s.apply(rep(Outcome::NoChallenge), t0);
    s.clear();
    expect(!s.view(t0).offerNoPassword, "clear: retry without password hidden");
    s.clear();
    expect(s.view(t0).text.empty(), "clear: no error");
    expect(waitText(59) == L"Too many wrong tries. Wait 59 s.", "wait text under a minute");
    expect(waitText(600) == L"Too many wrong tries. Wait 10 min 0 s.", "wait text 10 min");
}

void probeRaceTests() {
    LaunchState s;
    const auto t0 = Clock::now();
    Report r = rep(Outcome::Fail, 3);
    r.probeRace = true;
    expect(s.apply(r, t0), "probe race fail is shown");
    const View v = s.view(t0);
    expect(v.text == L"The Mac counted a connection check as a wrong try (3 tries left). Connect again.",
           "probe race: says the check was counted, not a wrong password");
    expect(v.connectEnabled && v.focusPassword && !v.clearPassword, "probe race: Connect on, focus, not a wrong password");
}

// A session (background channel) or command-line start hands its answer to
// the relaunched launch screen, which must count down the same way.
void handoffTests() {
    const uint64_t tick0 = 5'000'000;
    Report locked = rep(Outcome::Locked, 0, 125);
    const std::wstring h = encodeHandoff(locked, tick0);
    expect(!h.empty() && h.rfind(L"v1;", 0) == 0, "handoff: encoded");
    // Relaunch took 3.2 s: 121.8 s left, shown as 122 s.
    auto back = decodeHandoff(h, tick0 + 3200);
    expect(back && back->outcome == Outcome::Locked && back->retrySeconds == 122, "handoff: locked keeps its deadline across the relaunch");
    LaunchState s;
    const auto t0 = Clock::now();
    expect(back && s.apply(*back, t0), "handoff: launch screen shows it");
    View v = s.view(t0);
    expect(v.text == L"Too many wrong tries. Wait 2 min 2 s." && !v.connectEnabled && v.focusPassword,
           "handoff: same countdown, Connect greyed out, focus on password");
    expect(s.counting(t0) && !s.counting(t0 + std::chrono::seconds(122)), "handoff: counts down to the original deadline");
    back = decodeHandoff(h, tick0 + 200'000);
    expect(back && back->retrySeconds == 0, "handoff: deadline already passed -> 0 s");
    expect(back && s.apply(*back, t0) && s.view(t0).connectEnabled, "handoff: passed deadline leaves Connect on");

    Report fail = rep(Outcome::Fail, 2, 0, true);
    fail.probeRace = true;
    back = decodeHandoff(encodeHandoff(fail, tick0), tick0);
    expect(back && back->outcome == Outcome::Fail && back->triesLeft == 2 && back->usedSavedKey && back->probeRace,
           "handoff: fail keeps tries, saved key, probe race");
    for (Outcome o : {Outcome::Blocked, Outcome::AuthRequired, Outcome::HostMismatch, Outcome::HostTooOld,
                      Outcome::NeedPassword, Outcome::LocalError, Outcome::RaceUnanswered, Outcome::NoChallenge,
                      Outcome::Replaced, Outcome::RetryCapped}) {
        back = decodeHandoff(encodeHandoff(rep(o), tick0), tick0);
        expect(back && back->outcome == o, std::string("handoff round trip: ") + outcomeName(o));
    }
    expect(encodeHandoff(rep(Outcome::Ok), tick0).empty() && encodeHandoff(rep(Outcome::Retry), tick0).empty(),
           "handoff: only terminal answers are handed over");
    for (const wchar_t* bad : {L"", L"v2;o=3;t=0;k=0;p=0;u=0", L"v1;o=3;t=0;k=0;p=0", L"v1;o=0;t=0;k=0;p=0;u=0",
                               L"v1;o=3;t=0;k=0;p=0;u=-1", L"v1;o=3;t=0;k=0;p=0;u=1;x=1", L"v1;o=99;t=0;k=0;p=0;u=0",
                               L"v1;o=3;t=300;k=0;p=0;u=0", L"v1;o=3;t=0;k=0;p=0;u=999999999999"}) {
        expect(!decodeHandoff(bad, tick0), std::string("handoff: rejects malformed #") + std::to_string(wcslen(bad)));
    }
}

}  // namespace

// Pepper's PR-B review r4, item 3: "Retry without password" belongs to the
// host (ip:port) that sent the NoChallenge.
void hostBindingTests() {
    LaunchState s;
    const auto t0 = Clock::now();
    const std::string a = "100.64.0.16:38400", b = "100.64.0.17:38400", aOtherPort = "100.64.0.16:47990";
    s.apply(rep(Outcome::NoChallenge), t0, a);
    expect(s.view(t0, a).offerNoPassword && s.noPasswordTarget(t0, a) == a,
           "r5 bound: offered for the host that sent NoChallenge, target is that ip:port");
    expect(!s.view(t0, b).offerNoPassword && s.noPasswordTarget(t0, b).empty(),
           "r5 bound: hidden and no target once the address is another Mac");
    expect(!s.view(t0, aOtherPort).offerNoPassword && s.noPasswordTarget(t0, aOtherPort).empty(),
           "r5 bound: same IP, other control port: hidden");
    expect(!s.view(t0, "").offerNoPassword, "r5 bound: address not valid: hidden");
    expect(s.view(t0, a).offerNoPassword, "r5 bound: back to the first address: shown again (same answer)");
    s.apply(rep(Outcome::NoChallenge), t0);
    expect(!s.view(t0, a).offerNoPassword && s.noPasswordTarget(t0, a).empty(),
           "r5 bound: answer with no known host: never offered");
    s.apply(rep(Outcome::NoChallenge), t0, a);
    s.apply(rep(Outcome::Fail, 3), t0, a);
    expect(s.noPasswordTarget(t0, a).empty(), "r5 bound: a later answer (not NoChallenge) drops the target");
    s.apply(rep(Outcome::NoChallenge), t0, a);
    s.clear();
    expect(s.noPasswordTarget(t0, a).empty() && s.answerHost().empty(), "r5 bound: clear drops the host");
    // Handed over to a relaunched launch screen with the host.
    const uint64_t tick0 = 5'000'000;
    const std::wstring h = encodeHandoff(rep(Outcome::NoChallenge), tick0, a);
    expect(h.find(L";h=100.64.0.16:38400") != std::wstring::npos, "r5 handoff: carries h=<ip:port>");
    std::string host;
    auto back = decodeHandoff(h, tick0, &host);
    expect(back && back->outcome == Outcome::NoChallenge && host == a, "r5 handoff: host round trip");
    expect(back && s.apply(*back, t0, host) && s.noPasswordTarget(t0, a) == a && s.noPasswordTarget(t0, b).empty(),
           "r5 handoff: relaunched screen offers it only for that host");
    back = decodeHandoff(encodeHandoff(rep(Outcome::NoChallenge), tick0), tick0, &host);
    expect(back && host.empty(), "r5 handoff: old form (no h) still decodes, host unknown");
    host = "stale";
    expect(!decodeHandoff(L"v1;o=3;t=0;k=0;p=0;u=0;h=1.2.3.4:5;h=1.2.3.4:5", tick0, &host) && host.empty(),
           "r5 handoff: rejects h twice");
    for (const wchar_t* bad : {L"v1;o=3;t=0;k=0;p=0;u=0;h=", L"v1;o=3;t=0;k=0;p=0;u=0;h=evil.example:1",
                               L"v1;o=3;t=0;k=0;p=0;u=0;h=100.64.0.16:38400:38400:1",
                               L"v1;o=3;t=0;k=0;p=0;u=0;h=1.2.3.4 5"}) {
        expect(!decodeHandoff(bad, tick0, &host), "r5 handoff: rejects bad host #" + std::to_string(wcslen(bad)));
    }
    expect(encodeHandoff(rep(Outcome::NoChallenge), tick0, "bad host").find(L";h=") == std::wstring::npos,
           "r5 handoff: an invalid host is not encoded");
}

// r5: the channel-paused notice fits the notice chip. Every combination
// was measured on win01 (Segoe UI Semibold 9 pt, 476 px text area); the
// longest is 80 characters and 410 px.
void channelPausedTests() {
    expect(channelPausedText(false, false, false).empty(), "r5 paused notice: nothing paused, no text");
    expect(channelPausedText(true, false, false) == "Mac not answering: input paused. Press a key to retry.",
           "r5 paused notice: input only names the retry key");
    expect(channelPausedText(false, true, false) == "Mac not answering: clipboard paused. Video keeps going.",
           "r5 paused notice: clipboard only says video keeps going");
    for (int m = 1; m < 8; ++m) {
        const std::string t = channelPausedText((m & 1) != 0, (m & 2) != 0, (m & 4) != 0);
        expect(!t.empty() && t.size() <= 80,
               "r5 paused notice: combination " + std::to_string(m) + " is " + std::to_string(t.size()) + " chars (<= 80)");
        expect(((m & 1) != 0) == (t.find("Press a key") != std::string::npos),
               "r5 paused notice: retry hint only when input paused, combination " + std::to_string(m));
    }
}

int main() {
    channelPausedTests();
    hostBindingTests();
    probeRaceTests();
    handoffTests();
    carryOnTests();
    failTests();
    lockedTests();
    otherTests();
    std::printf("%d passed, %d failed\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
