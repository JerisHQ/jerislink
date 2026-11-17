// Tests for file_panel.hpp (F4/F5a Files panel): host level from caps, the two cards,
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

void cards() {
    expectEq(title(), "Files", "card: panel title stays English");
    expectEq(guideHeading(), "\xE2\x91\xA0 Copy & Paste", "card 1: heading");
    expectEq(sendToHeading(), "\xE2\x91\xA1 Right-click \xE2\x80\xBA Send to JerisLink", "card 2: heading");
    const auto cp = copyPasteRows();
    expect(cp.size() == 2 && cp[0].label == "This PC \xE2\x86\x92 Mac" && cp[1].label == "Mac \xE2\x86\x92 This PC",
           "card 1: This PC -> Mac, then Mac -> This PC");
    expect(cp[0].text.find("Ctrl+C in Explorer, then paste in Finder here.") != std::string::npos && !cp[0].muted,
           "card 1: PC to Mac line");
    expect(cp[1].text.find("Cmd+C in Finder here, then Ctrl+V in Explorer.") != std::string::npos && !cp[1].muted,
           "card 1: Mac to PC line");

    auto st = sendToRows(SendToSetup::Installed);
    expect(st.size() == 2 && st[0].label == cp[0].label && st[1].label == cp[1].label, "card 2: same two directions");
    expectEq(st[0].text,
             "Right-click files \xE2\x80\xBA Send to \xE2\x80\xBA JerisLink (Windows 11: Show more options first). "
             "They go to Downloads/JerisLink on the Mac.",
             "card 2: installed, how to send");
    expect(!st[0].muted, "card 2: installed line is not grey");
    expectEq(st[1].text, "Right-click in Finder: coming with the next JerisLink update on the Mac.",
             "card 2: Mac -> This PC waits for F5b");
    expect(st[1].muted, "card 2: Mac -> This PC is grey");
    st = sendToRows(SendToSetup::NotInstalled);
    expectEq(st[0].text, "Not set up on this PC. Install JerisLink with its installer to add it.",
             "card 2: no shortcut (zip / deleted)");
    expect(st[0].muted, "card 2: not set up is grey");
    st = sendToRows(SendToSetup::StorePackage);
    expectEq(st[0].text, "Not in the Microsoft Store version yet. Drag files onto this window instead.",
             "card 2: Store build degrades to drag");
    expect(st[0].muted && st.size() == 2, "card 2: Store line is grey");
}

void texts() {
    expectEq(tipLine(Host::Full), "Tip: you can also drag files onto this window to send them to the Mac.", "tip: F4 host");
    expectEq(tipLine(Host::PasteOnly), "Update JerisLink on the Mac to drag files onto this window.", "tip: F3 host");
    expectEq(tipLine(Host::None), "The Mac's JerisLink has no file transfer. Update JerisLink on the Mac.", "tip: old host");

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
        expect(inside(l.title, win) && inside(l.copyPaste.box, win) && inside(l.sendTo.box, win) &&
                   inside(l.tip, win) && inside(l.progress, win) && inside(l.cancel, win) && inside(l.last, win) &&
                   inside(l.openFolder, win),
               "layout: every part inside the panel" + d);
        bool cardsOk = true;
        for (const Card* c : {&l.copyPaste, &l.sendTo}) {
            cardsOk = cardsOk && inside(c->heading, c->box);
            for (int i = 0; i < 2; ++i) {
                cardsOk = cardsOk && inside(c->label[i], c->box) && inside(c->text[i], c->box) &&
                          apart(c->heading, c->label[i]) && apart(c->label[i], c->text[i]);
                // room for four lines of the small font (about 16 px each at 96 dpi)
                cardsOk = cardsOk && c->text[i].height() >= jl::overlay::scale(64, dpi);
            }
            cardsOk = cardsOk && apart(c->text[0], c->label[1]) && apart(c->text[0], c->text[1]);
        }
        expect(cardsOk, "layout: card heading, labels and texts inside their card, no overlap" + d);
        expect(apart(l.copyPaste.box, l.sendTo.box) && l.copyPaste.box.right < l.sendTo.box.left &&
                   l.copyPaste.box.top == l.sendTo.box.top && l.copyPaste.box.width() == l.sendTo.box.width(),
               "layout: card 1 left, card 2 right, same size" + d);
        expect(apart(l.title, l.copyPaste.box) && apart(l.copyPaste.box, l.tip) && apart(l.sendTo.box, l.tip) &&
                   apart(l.progress, l.cancel) && apart(l.last, l.openFolder) && apart(l.cancel, l.openFolder) &&
                   apart(l.tip, l.progress) && apart(l.progress, l.last) && l.tip.top >= l.copyPaste.box.bottom &&
                   l.progress.top >= l.tip.bottom && l.last.top >= l.progress.bottom,
               "layout: title, cards, tip, progress, last in order without overlap" + d);
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

void chipRestore() {
    // Send to started while the viewer was minimised: no chip yet, but it must
    // come up once the viewer is restored (hand test, 2026-11-17).
    expect(!chipOnScreen(true, true, false), "chip: running bar stays hidden while minimised");
    expect(chipOnScreen(true, false, false), "chip: running bar shows after restore");
    expect(chipOnScreen(true, true, true), "chip: floating notice shows while minimised");
    expect(!chipOnScreen(false, false, false), "chip: hidden chip never shows on restore");
    expect(!chipOnScreen(false, true, true), "chip: hidden chip never floats");
}

}  // namespace

int main() {
    hostLevels();
    cards();
    texts();
    buttonSets();
    layouts();
    keys();
    chipRestore();
    std::printf("file panel: %d passed, %d failed\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
