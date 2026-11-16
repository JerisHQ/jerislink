// Tests for file_panel.hpp (F4 Files panel): host level from caps, the
// guide/tip/last texts, drop notices, buttons, layout and hit-test at
// several dpi, and the panel keys.
#include "file_panel.hpp"

#include <cstdio>
#include <string>
#include <utility>

using namespace jl::filepanel;
namespace caps = jl::file::caps;

namespace {

int gPass = 0;
int gFail = 0;

void expect(bool cond, const std::string& what) {
    if (cond) { ++gPass; std::printf("PASS %s\n", what.c_str()); }
    else { ++gFail; std::printf("FAIL %s\n", what.c_str()); }
}

void expectEq(const std::string& got, const std::string& want, const std::string& what) {
    expect(got == want, what + (got == want ? "" : "  got [" + got + "] want [" + want + "]"));
}

bool inside(const jl::overlay::Rect& inner, const jl::overlay::Rect& outer) {
    return inner.left >= outer.left && inner.top >= outer.top && inner.right <= outer.right &&
           inner.bottom <= outer.bottom && inner.width() > 0 && inner.height() > 0;
}

bool apart(const jl::overlay::Rect& a, const jl::overlay::Rect& b) {
    return a.right <= b.left || b.right <= a.left || a.bottom <= b.top || b.bottom <= a.top;
}

void hostLevels() {
    expect(hostFromCaps(false, false, 0) == Host::Unknown, "host: no answer yet is unknown");
    expect(hostFromCaps(true, false, 0) == Host::None, "host: old host (no HELLO_ACK) has no file transfer");
    expect(hostFromCaps(true, true, caps::kAnnounce) == Host::None, "host: announce only cannot receive");
    expect(hostFromCaps(true, true, caps::kUpload | caps::kAnnounce) == Host::PasteOnly, "host: F2/F3 host is paste only");
    expect(hostFromCaps(true, true, caps::kUpload | caps::kReveal | caps::kAnnounce) == Host::Full, "host: F4 host takes drops");
}

void texts() {
    expectEq(tipLine(Host::Full), "Tip: you can also drag files onto this window to send them to the Mac.", "tip: F4 host");
    expectEq(tipLine(Host::PasteOnly), "Update JerisLink on the Mac to drag files onto this window.", "tip: F3 host");
    expectEq(tipLine(Host::None), "The Mac's JerisLink has no file transfer. Update JerisLink on the Mac.", "tip: old host");
    expect(guideBody().find("Ctrl+C in Explorer, paste in Finder here.") != std::string::npos, "guide: PC to Mac line");
    expect(guideBody().find("Cmd+C in Finder here, Ctrl+V in Explorer.") != std::string::npos, "guide: Mac to PC line");

    expectEq(lastLine(Last{}), "", "last: nothing yet");
    expectEq(lastLine(lastFrom(2, true, 0, 3)), "Last: 3 files sent to the Mac", "last: drop of 3 files");
    expectEq(lastLine(lastFrom(2, true, 0, 1)), "Last: 1 file sent to the Mac", "last: drop of 1 file");
    expectEq(lastLine(lastFrom(2, false, 0, 3)), "Last: 3 files pasted in Finder", "last: paste of 3 files");
    expectEq(lastLine(lastFrom(3, true, jl::file::status::kFailed, 3)), "Last: sending to the Mac failed", "last: drop failed");
    expectEq(lastLine(lastFrom(3, false, jl::file::status::kNoSpace, 3)), "Last: paste to the Mac failed", "last: paste failed");
    expectEq(lastLine(lastFrom(4, true, jl::file::status::kCancelled, 2)), "Last: cancelled", "last: cancelled");
    expect(lastFrom(3, true, jl::file::status::kMacPermission, 1).kind == LastKind::MacPermission,
           "last: mac_permission is its own outcome");
    expect(lastLine(lastFrom(3, true, jl::file::status::kMacPermission, 1)).find("Allow") != std::string::npos,
           "last: mac_permission says click Allow");

    expect(dropRefused(Host::Full, true).find("already running") != std::string::npos, "drop: busy");
    expectEq(dropRefused(Host::PasteOnly, false), "Update JerisLink on the Mac to drag files onto this window",
             "drop: F3 host asks for an update");
    expect(dropRefused(Host::None, false).find("no file transfer") != std::string::npos, "drop: old host");
    expectEq(dropDone(2), "Sent 2 files to the Mac \xC2\xB7 Finder shows them", "drop: done");
    expectEq(dropMacPermission(), "Allow JerisLink on the Mac to use Downloads, then drop again", "drop: mac permission");
}

void buttonSets() {
    State s;
    expect(buttons(s).empty(), "buttons: idle panel has none");
    s.uploadRunning = true;
    expect(buttons(s) == std::vector<Button>{Button::Cancel}, "buttons: Cancel while uploading");
    s.uploadRunning = false;
    s.host = Host::Full;
    s.last = lastFrom(2, true, 0, 3);
    expect(buttons(s) == std::vector<Button>{Button::OpenFolder}, "buttons: Open folder after a drop");
    s.last = lastFrom(2, false, 0, 3);
    expect(buttons(s).empty(), "buttons: no Open folder after a paste");
    s.last = lastFrom(3, true, jl::file::status::kFailed, 3);
    expect(buttons(s).empty(), "buttons: no Open folder after a failed drop");
    s.host = Host::PasteOnly;
    s.last = lastFrom(2, true, 0, 3);
    expect(buttons(s).empty(), "buttons: no Open folder without reveal");
    s.host = Host::Full;
    s.uploadRunning = true;
    expect((buttons(s) == std::vector<Button>{Button::Cancel, Button::OpenFolder}), "buttons: Cancel then Open folder");
}

void layouts() {
    for (unsigned dpi : {96u, 120u, 144u, 192u, 288u}) {
        const Layout l = layoutFor(dpi);
        const jl::overlay::Rect win{0, 0, l.width, l.height};
        const std::string d = " @" + std::to_string(dpi);
        expect(inside(l.title, win) && inside(l.heading, win) && inside(l.guide, win) && inside(l.tip, win) &&
                   inside(l.progress, win) && inside(l.cancel, win) && inside(l.last, win) &&
                   inside(l.openFolder, win),
               "layout: every part inside the panel" + d);
        expect(apart(l.progress, l.cancel) && apart(l.last, l.openFolder) && apart(l.cancel, l.openFolder) &&
                   apart(l.guide, l.tip) && apart(l.tip, l.progress) && apart(l.progress, l.last),
               "layout: parts do not overlap" + d);
        State s;
        s.host = Host::Full;
        s.uploadRunning = true;
        s.last = lastFrom(2, true, 0, 1);
        const auto mid = [](const jl::overlay::Rect& r) { return std::pair{(r.left + r.right) / 2, (r.top + r.bottom) / 2}; };
        auto [cx, cy] = mid(l.cancel);
        auto [ox, oy] = mid(l.openFolder);
        expect(hit(l, s, cx, cy) == Button::Cancel && hit(l, s, ox, oy) == Button::OpenFolder &&
                   hit(l, s, 2, 2) == Button::None,
               "layout: hit Cancel, Open folder, nothing" + d);
        s.uploadRunning = false;
        expect(hit(l, s, cx, cy) == Button::None, "layout: hidden Cancel is not hit" + d);
    }
    expect(layoutFor(192).width == 2 * layoutFor(96).width, "layout: scales with dpi");
}

void keys() {
    State s;
    s.host = Host::Full;
    s.uploadRunning = true;
    s.last = lastFrom(2, true, 0, 1);
    Keys k;
    k.reset();
    expect(k.focus(s) == Button::None, "keys: no focus at first");
    expect(k.key(Keys::kSpace, s).action == Keys::Action::None, "keys: Space without focus does nothing");
    k.key(Keys::kTab, s);
    expect(k.focus(s) == Button::Cancel, "keys: Tab to Cancel");
    k.key(Keys::kTab, s);
    expect(k.focus(s) == Button::OpenFolder, "keys: Tab to Open folder");
    k.key(Keys::kTab, s);
    expect(k.focus(s) == Button::Cancel, "keys: Tab wraps");
    k.key(Keys::kTab, s, true);
    expect(k.focus(s) == Button::OpenFolder, "keys: Shift+Tab goes back");
    auto r = k.key(Keys::kEnter, s);
    expect(r.action == Keys::Action::Press && r.button == Button::OpenFolder, "keys: Enter presses the focused button");
    s.uploadRunning = false;  // Cancel went away: focus stays on a real button
    expect(k.focus(s) == Button::None || k.focus(s) == Button::OpenFolder, "keys: focus survives a button leaving");
    r = k.key(Keys::kSpace, s);
    expect(r.action == Keys::Action::Press && r.button == Button::OpenFolder, "keys: Space presses Open folder");
    expect(k.key(Keys::kEscape, s).action == Keys::Action::Close, "keys: Esc closes");
    expect(k.key('A', s).action == Keys::Action::None, "keys: letters are swallowed");
    State idle;
    Keys k2;
    expect(k2.key(Keys::kEnter, idle).action == Keys::Action::Close, "keys: Enter with no buttons closes");
    expect(k2.key(Keys::kTab, idle).action == Keys::Action::None && k2.focus(idle) == Button::None,
           "keys: Tab with no buttons is harmless");
}

}  // namespace

int main() {
    hostLevels();
    texts();
    buttonSets();
    layouts();
    keys();
    std::printf("file panel: %d passed, %d failed\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
