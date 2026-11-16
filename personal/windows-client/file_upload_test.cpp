// Tests for file_upload.hpp (F2 Windows->Mac paste): the Cmd+V hold in both
// keyboard presets, the 3 s paste window, the pacer, chip and confirm text,
// and the disconnect confirm keys.
#include "file_upload.hpp"

#include <cmath>
#include <cstdio>
#include <string>
#include <vector>

using namespace jl::fileup;
using jl::keymap::KeyEvent;
using jl::keymap::kCtrl;
using jl::keymap::kWin;
using jl::keymap::kShift;

namespace {

int gPass = 0;
int gFail = 0;

void expect(bool cond, const std::string& what) {
    if (cond) { ++gPass; std::printf("PASS %s\n", what.c_str()); }
    else { ++gFail; std::printf("FAIL %s\n", what.c_str()); }
}

std::string show(const std::vector<KeyEvent>& ev) {
    std::string s;
    for (const auto& e : ev) {
        if (!s.empty()) s += ' ';
        s += (e.down ? "+" : "-") + std::to_string(e.semantic);
    }
    return s.empty() ? "(none)" : s;
}

void expectEvents(const std::vector<KeyEvent>& got, const std::vector<KeyEvent>& want, const std::string& what) {
    const bool ok = got == want;
    expect(ok, what + (ok ? "" : "  got [" + show(got) + "] want [" + show(want) + "]"));
}

KeyEvent D(uint16_t s) { return {true, s}; }
KeyEvent U(uint16_t s) { return {false, s}; }
constexpr uint16_t V = 'V';

void macPresetChord() {
    PasteGate g;
    int asked = 0;
    auto yes = [&] { ++asked; return true; };
    // Physical Ctrl down goes out as Control.
    auto r = g.filter({D(kCtrl)}, 0, yes);
    expectEvents(r.events, {D(kCtrl)}, "mac: Ctrl down passes");
    expect(!r.startUpload && asked == 0, "mac: eligibility not asked for a modifier");
    // Keymap turns Ctrl+V into one output: release Control, Command chord.
    r = g.filter({U(kCtrl), D(kWin), D(V), U(V), U(kWin)}, 10, yes);
    expectEvents(r.events, {U(kCtrl), D(kWin), U(kWin)}, "mac: Ctrl+V chord held (V down and up swallowed)");
    expect(r.startUpload && asked == 1 && g.holding(), "mac: Ctrl+V starts the upload");
    // Translator re-sends Control after the physical V up.
    r = g.filter({D(kCtrl)}, 20, yes);
    expectEvents(r.events, {D(kCtrl)}, "mac: Control re-sent passes");
    // A second Ctrl+V while uploading is swallowed, eligibility not asked.
    r = g.filter({U(kCtrl), D(kWin), D(V), U(V), U(kWin)}, 30, yes);
    expectEvents(r.events, {U(kCtrl), D(kWin), U(kWin)}, "mac: second Ctrl+V while held is swallowed");
    expect(!r.startUpload && asked == 1, "mac: no second upload");
    r = g.filter({D(kCtrl)}, 35, yes);
    // Upload done in time: plain Cmd+V with Control lifted around it.
    const auto f = g.finish(true, 1200);
    expect(f.outcome == PasteGate::Outcome::Paste, "mac: finished within 3 s pastes");
    expectEvents(f.events, {U(kCtrl), D(kWin), D(V), U(V), U(kWin), D(kCtrl)}, "mac: paste chord lifts and restores Control");
    expect(!g.holding(), "mac: hold cleared");
}

void windowsPreset() {
    PasteGate g;
    auto yes = [] { return true; };
    auto r = g.filter({D(kWin)}, 0, yes);   // Ctrl = Command in this preset
    expectEvents(r.events, {D(kWin)}, "win: Command down passes");
    r = g.filter({D(V)}, 5, yes);
    expectEvents(r.events, {}, "win: V down held");
    expect(r.startUpload, "win: upload starts");
    r = g.filter({D(V)}, 30, yes);
    expectEvents(r.events, {}, "win: auto-repeat V swallowed");
    r = g.filter({U(V)}, 40, yes);
    expectEvents(r.events, {}, "win: V up swallowed");
    // Other keys still pass while held.
    r = g.filter({D(kShift), U(kShift)}, 50, yes);
    expectEvents(r.events, {D(kShift), U(kShift)}, "win: other keys pass while held");
    const auto f = g.finish(true, 2900);
    expect(f.outcome == PasteGate::Outcome::Paste, "win: 2.9 s still pastes");
    expectEvents(f.events, {D(V), U(V)}, "win: Command still held, only V is sent");
    r = g.filter({U(kWin)}, 3000, yes);
    expectEvents(r.events, {U(kWin)}, "win: Command up passes");
}

void notEligible() {
    PasteGate g;
    auto no = [] { return false; };
    auto r = g.filter({D(kWin), D(V), U(V), U(kWin)}, 0, no);
    expectEvents(r.events, {D(kWin), D(V), U(V), U(kWin)}, "not eligible (no files / old host): Cmd+V passes through");
    expect(!r.startUpload && !g.holding(), "not eligible: no upload");
    // V without Command never asks.
    int asked = 0;
    r = g.filter({D(V), U(V)}, 0, [&] { ++asked; return true; });
    expectEvents(r.events, {D(V), U(V)}, "plain V passes");
    expect(asked == 0, "plain V never asks eligibility");
    expect(g.finish(true, 0).outcome == PasteGate::Outcome::None, "finish without hold does nothing");
}

// A transfer is running (Send to / drop / paste upload, or a Mac->Windows
// pull): a Cmd+V with new copied files is eaten, never passed to the Mac
// (where it would paste a stale pasteboard) and never a second upload.
void busy() {
    auto yes = [] { return true; };
    auto no = [] { return false; };
    for (const char* kind : {"upload busy", "pull busy"}) {
        const std::string k = kind;
        PasteGate g;
        int busyAsked = 0;
        auto running = [&] { ++busyAsked; return true; };
        auto r = g.filter({D(kWin), D(V)}, 0, yes, running);
        expectEvents(r.events, {D(kWin)}, k + ": V down eaten");
        expect(r.refusedBusy && !r.startUpload && !g.holding() && busyAsked == 1,
               k + ": refused, no upload, no hold");
        r = g.filter({D(V)}, 30, yes, running);
        expectEvents(r.events, {}, k + ": auto-repeat V eaten");
        expect(!r.refusedBusy && busyAsked == 1, k + ": repeat refuses once only");
        r = g.filter({U(V), U(kWin)}, 40, yes, running);
        expectEvents(r.events, {U(kWin)}, k + ": V up eaten, Command up passes");
        expect(g.finish(true, 50).outcome == PasteGate::Outcome::None, k + ": nothing to finish");
        // The transfer ended: the same clipboard pastes normally.
        r = g.filter({D(kWin), D(V), U(V), U(kWin)}, 100, yes, no);
        expectEvents(r.events, {D(kWin), U(kWin)}, k + ": after it ends, Cmd+V is held for upload");
        expect(r.startUpload && !r.refusedBusy && g.holding(), k + ": after it ends, upload starts");
    }
    {
        PasteGate g;
        int busyAsked = 0;
        auto r = g.filter({D(kWin), D(V), U(V), U(kWin)}, 0, no, [&] { ++busyAsked; return true; });
        expectEvents(r.events, {D(kWin), D(V), U(V), U(kWin)},
                     "busy, no files (text) or old host: Cmd+V passes through");
        expect(!r.refusedBusy && !r.startUpload && busyAsked == 0, "busy, no files: busy never asked, no refusal");
    }
    {
        PasteGate g;
        auto r = g.filter({D(kWin), D(V), U(V), U(kWin)}, 0, yes, no);
        expectEvents(r.events, {D(kWin), U(kWin)}, "not busy: Cmd+V held as before");
        expect(r.startUpload && !r.refusedBusy, "not busy: upload starts as before");
    }
    {
        PasteGate g;
        g.filter({D(kWin), D(V)}, 0, yes, yes);
        g.modifiersReleased();  // focus left before V up
        auto r = g.filter({D(kWin), D(V), U(V), U(kWin)}, 500, yes, no);
        expect(r.startUpload, "refusal does not stick after focus loss");
    }
    expect(pasteBusy() == "A transfer is already running. Wait or cancel it in Files, then press Cmd+V again.",
           "text: busy notice");
}

void lateAndFailed() {
    auto yes = [] { return true; };
    {
        PasteGate g;
        g.filter({D(kWin), D(V), U(V), U(kWin)}, 1000, yes);
        const auto f = g.finish(true, 4001);
        expect(f.outcome == PasteGate::Outcome::Late && f.events.empty(), "late: over 3 s gives Ready, no keys");
        // Next Cmd+V asks again; the viewer answers no (same clipboard), so it passes.
        auto r = g.filter({D(kWin), D(V), U(V), U(kWin)}, 5000, [] { return false; });
        expectEvents(r.events, {D(kWin), D(V), U(V), U(kWin)}, "late: next Cmd+V goes to the Mac");
    }
    {
        PasteGate g;
        g.filter({D(kWin), D(V)}, 0, yes);
        g.abandon();
        g.modifiersReleased();
        const auto f = g.finish(true, 500);
        expect(f.outcome == PasteGate::Outcome::Late && f.events.empty(), "focus lost: never pastes, Ready instead");
        auto r = g.filter({U(V)}, 600, yes);
        expectEvents(r.events, {U(V)}, "after release a stray V up passes (harmless)");
    }
    {
        PasteGate g;
        g.filter({D(kWin), D(V), U(V), U(kWin)}, 0, yes);
        const auto f = g.finish(false, 100);
        expect(f.outcome == PasteGate::Outcome::Dropped && f.events.empty(), "failed upload: paste dropped");
    }
}

void pacer() {
    Pacer p(100);  // 12.5 MB/s = 12500 bytes/ms
    double t = 0;
    uint64_t sent = 0;
    for (int i = 0; i < 4000; ++i) {     // 4000 x 32 KiB = 131 MB
        const double d = p.delayMs(32768, t);
        t += d;
        sent += 32768;
    }
    const double mbps = sent * 8.0 / (t * 1000.0);
    expect(std::fabs(mbps - 100.0) < 2.0, "pacer: 100 Mbps cap holds (" + std::to_string(mbps) + ")");
    Pacer off(0);
    expect(off.delayMs(1 << 30, 0) == 0.0, "pacer: 0 means no cap");
    Pacer b(100);
    expect(b.delayMs(32768, 0) == 0.0, "pacer: first chunk immediate");
    // After a long idle, at most 50 ms of burst is credited.
    b.delayMs(32768, 10000);
    double burst = 0;
    int freeChunks = 0;
    for (int i = 0; i < 100 && burst == 0; ++i) {
        burst = b.delayMs(32768, 10000);
        if (burst == 0) ++freeChunks;
    }
    expect(freeChunks <= 21, "pacer: idle credit capped (" + std::to_string(freeChunks) + " free chunks)");
}

void text() {
    expect(formatBytes(0) == "0 B" && formatBytes(999) == "999 B", "bytes: under 1 KB");
    expect(formatBytes(1200000000) == "1.2 GB", "bytes: 1.2 GB");
    expect(formatBytes(85000000) == "85 MB", "bytes: 85 MB");
    expect(formatBytes(4000000000ull) == "4.0 GB", "bytes: 4.0 GB");
    expect(formatPair(1200000000, 4000000000ull) == "1.2 / 4.0 GB", "pair: 1.2 / 4.0 GB");
    expect(formatPair(5, 900) == "5 / 900 B", "pair: bytes");
    expect(chipText(3, 1200000000, 4000000000ull, 85000000) ==
               "\xE2\x86\x91 3 files \xC2\xB7 1.2 / 4.0 GB \xC2\xB7 85 MB/s",
           "chip: doc example");
    expect(chipText(1, 0, 70000, 0) == "\xE2\x86\x91 1 file \xC2\xB7 0 / 70 KB", "chip: one file, no rate yet");
    expect(confirmBody(2, 1200000000, 4000000000ull) ==
               "2 file(s) are still transferring (1.2 GB of 4.0 GB). If you disconnect now, the transfer "
               "stops and unfinished files are removed from the Mac. Files that already finished are kept.",
           "confirm: body text per doc");
    expect(confirmBodyPull(1, 70000, 4000000000ull) ==
               "1 file(s) are still being pasted into this PC (70 KB of 4.0 GB). If you disconnect now, the paste "
               "stops and Explorer reports the unfinished files. Files that already finished are kept.",
           "confirm: Mac->Windows paste variant");
}

void confirmKeys() {
    namespace vk = jl::keymap::vk;
    ConfirmKeys k;
    expect(k.focus() == ConfirmKeys::Button::Keep, "confirm: Keep is the default");
    expect(k.key(vk::Return) == ConfirmKeys::Action::Keep, "confirm: Enter keeps");
    expect(k.key(vk::Escape) == ConfirmKeys::Action::Keep, "confirm: Esc keeps");
    expect(k.key(vk::Space) == ConfirmKeys::Action::Keep, "confirm: Space on Keep keeps");
    expect(k.key(vk::Tab) == ConfirmKeys::Action::None && k.focus() == ConfirmKeys::Button::Disconnect,
           "confirm: Tab moves to Disconnect");
    expect(k.key(vk::Return) == ConfirmKeys::Action::Keep, "confirm: Enter keeps even on Disconnect");
    expect(k.key(vk::Space) == ConfirmKeys::Action::Disconnect, "confirm: Tab then Space disconnects");
    expect(k.key('A') == ConfirmKeys::Action::None, "confirm: other keys do nothing");
    k.reset();
    expect(k.focus() == ConfirmKeys::Button::Keep, "confirm: reset back to Keep");
}

}  // namespace

int main() {
    macPresetChord();
    windowsPreset();
    notEligible();
    busy();
    lateAndFailed();
    pacer();
    text();
    confirmKeys();
    std::printf("%d passed, %d failed\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
