#pragma once

// Files panel (F4, F5a): the overlay's Files button opens a small guide with
// two cards, (1) copy & paste and (2) right-click Send to JerisLink, the
// running transfer with Cancel, and the last transfer with Open folder
// (REVEAL) after a drop or Send to. Texts, layout, the buttons shown and the
// panel keys live here without Win32 so file_panel_test.cpp can check them;
// viewer.cpp paints and drives the real popup. No file names are shown or
// logged.

#include "file_proto.hpp"
#include "file_upload.hpp"
#include "ui_overlay.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace jl::filepanel {

namespace ov = jl::overlay;

// What the Mac's JerisLink can do, from its HELLO_ACK caps.
enum class Host { Unknown, None, PasteOnly, Full };

inline Host hostFromCaps(bool answered, bool capable, uint16_t caps) {
    if (!answered) return Host::Unknown;
    if (!capable || !(caps & jl::file::caps::kUpload)) return Host::None;
    return (caps & jl::file::caps::kReveal) ? Host::Full : Host::PasteOnly;
}

// The last Windows->Mac transfer of this session.
enum class LastKind { None, Done, Failed, Cancelled, MacPermission };
struct Last {
    LastKind kind = LastKind::None;
    bool send = false;    // a drop (purpose=send), else a Cmd+V paste
    uint64_t files = 0;
};

inline Last lastFrom(int state, bool send, uint8_t hostStatus, uint64_t files) {
    // state: FileSession::UploadState (2 Done, 3 Failed, 4 Cancelled).
    Last l;
    l.send = send;
    l.files = files;
    if (state == 2) l.kind = LastKind::Done;
    else if (state == 4) l.kind = LastKind::Cancelled;
    else if (state == 3) l.kind = hostStatus == jl::file::status::kMacPermission ? LastKind::MacPermission
                                                                                 : LastKind::Failed;
    return l;
}

inline const char* title() { return "Files"; }
inline const char* guideHeading() { return "\xE2\x91\xA0 Copy & Paste"; }  // (1)
inline const char* sendToHeading() { return "\xE2\x91\xA1 Right-click \xE2\x80\xBA Send to JerisLink"; }  // (2)

// One direction inside a card: a short label and up to four lines of text.
struct CardRow {
    std::string label;
    std::string text;
    bool muted = false;  // not usable here (yet): drawn grey
};

inline const char* pcToMac() { return "This PC \xE2\x86\x92 Mac"; }
inline const char* macToPc() { return "Mac \xE2\x86\x92 This PC"; }

inline std::vector<CardRow> copyPasteRows() {
    return {
        {pcToMac(), "Ctrl+C in Explorer, then paste in Finder here. Files go to the folder you paste into.", false},
        {macToPc(), "Cmd+C in Finder here, then Ctrl+V in Explorer. Files go to that folder.", false},
    };
}

// Whether Explorer's Send to menu has JerisLink on this PC.
enum class SendToSetup {
    NotInstalled,  // e.g. the bare exe from a zip, or the shortcut was deleted
    Installed,     // the installer's JerisLink shortcut is in the user's SendTo folder
    StorePackage,  // the Microsoft Store (MSIX) build on Windows older than 10 1809: no menu command
    StoreMenu,     // the Microsoft Store (MSIX) build: its own Explorer command (JerisLinkSendTo.dll)
};

// macPush: the Mac host has Finder's Send to JerisLink (HELLO_ACK caps
// push_service, F5b). Without it the Mac line is not shown at all.
inline std::vector<CardRow> sendToRows(SendToSetup setup, bool macPush = false) {
    std::vector<CardRow> rows;
    switch (setup) {
    case SendToSetup::Installed:
        rows.push_back({pcToMac(),
                        "Right-click files \xE2\x80\xBA Send to \xE2\x80\xBA JerisLink (Windows 11: Show more "
                        "options first). They go to Downloads/JerisLink on the Mac.",
                        false});
        break;
    case SendToSetup::StoreMenu:
        rows.push_back({pcToMac(),
                        "Right-click files \xE2\x80\xBA Send to JerisLink. They go to Downloads/JerisLink on the Mac.",
                        false});
        break;
    case SendToSetup::StorePackage:
        rows.push_back({pcToMac(), "Needs Windows 10 version 1809 or later. Drag files onto this window instead.", true});
        break;
    default:
        rows.push_back({pcToMac(), "Not set up on this PC. Install JerisLink with its installer to add it.", true});
        break;
    }
    if (macPush) {
        rows.push_back({macToPc(),
                        "Right-click files in Finder \xE2\x80\xBA Send to JerisLink (under Quick Actions or "
                        "Services). They go to Downloads\\JerisLink here.",
                        false});
    }
    return rows;
}

inline std::string tipLine(Host h) {
    switch (h) {
    case Host::Full: return "Tip: you can also drag files onto this window to send them to the Mac.";
    case Host::PasteOnly: return "Update JerisLink on the Mac to drag files onto this window.";
    case Host::None: return "The Mac's JerisLink has no file transfer. Update JerisLink on the Mac.";
    default: return "Checking what the Mac's JerisLink can do\xE2\x80\xA6";
    }
}

// "" when nothing ran yet in this session.
inline std::string lastLine(const Last& l) {
    const std::string n = jl::fileup::plural(l.files, "file", "files");
    switch (l.kind) {
    case LastKind::Done: return l.send ? "Last: " + n + " sent to the Mac" : "Last: " + n + " pasted in Finder";
    case LastKind::Failed: return l.send ? "Last: sending to the Mac failed" : "Last: paste to the Mac failed";
    case LastKind::Cancelled: return "Last: cancelled";
    case LastKind::MacPermission: return "Last: the Mac asked for access. Click Allow there, then drop again.";
    default: return "";
    }
}

// One-line chip notices about a drop (shown in the viewer, not the panel).
inline std::string dropRefused(Host h, bool busy) {
    if (busy) return "A transfer is already running \xE2\x80\x94 cancel it in Files to send more";
    if (h == Host::PasteOnly) return "Update JerisLink on the Mac to drag files onto this window";
    if (h == Host::Unknown) return "Still connecting to the Mac's file transfer \xE2\x80\x94 try again in a moment";
    return "The Mac's JerisLink has no file transfer. Update JerisLink on the Mac.";
}
inline std::string dropDone(uint64_t files) {
    return "Sent " + jl::fileup::plural(files, "file", "files") + " to the Mac \xC2\xB7 Finder shows them";
}
inline std::string dropMacPermission() {
    return "Allow JerisLink on the Mac to use Downloads, then drop again";
}
inline std::string dropFailed() { return "Sending to the Mac failed"; }

enum class Button { None, Cancel, OpenFolder };

struct State {
    Host host = Host::Unknown;
    bool uploadRunning = false;
    bool pullRunning = false;
    Last last;
};

// Buttons on the panel, in Tab order.
inline std::vector<Button> buttons(const State& s) {
    std::vector<Button> b;
    if (s.uploadRunning) b.push_back(Button::Cancel);
    if (s.host == Host::Full && s.last.send && s.last.kind == LastKind::Done) b.push_back(Button::OpenFolder);
    return b;
}

// A card: border box, heading, then two rows (label line, text block).
struct Card {
    ov::Rect box, heading;
    ov::Rect label[2], text[2];
};

struct Layout {
    int width = 0, height = 0;
    ov::Rect title;
    Card copyPaste, sendTo;  // side by side, (1) left and (2) right
    ov::Rect tip, progress, cancel, last, openFolder;
};

inline Layout layoutFor(unsigned dpi) {
    const auto s = [dpi](int v) { return ov::scale(v, dpi); };
    Layout l;
    l.width = s(720);
    l.height = s(400);
    const int x0 = s(20), x1 = l.width - s(20);
    l.title = {x0, s(14), x1, s(38)};
    const auto card = [&](int left, int right) {
        Card c;
        c.box = {left, s(46), right, s(264)};
        const int il = left + s(12), ir = right - s(12);
        c.heading = {il, s(56), ir, s(78)};
        for (int i = 0; i < 2; ++i) {
            const int y = s(84 + 88 * i);
            c.label[i] = {il, y, ir, y + s(18)};
            c.text[i] = {il, y + s(18), ir, y + s(82)};  // four lines of the small font
        }
        return c;
    };
    const int gap = s(12), cw = (x1 - x0 - gap) / 2;  // equal widths at every scale
    l.copyPaste = card(x0, x0 + cw);
    l.sendTo = card(x1 - cw, x1);
    l.tip = {x0, s(272), x1, s(306)};
    const int bw = s(110), bh = s(30);
    l.progress = {x0, s(314), x1 - bw - s(10), s(346)};
    l.cancel = {x1 - bw, s(315), x1, s(315) + bh};
    l.last = {x0, s(356), x1 - bw - s(10), s(388)};
    l.openFolder = {x1 - bw, s(357), x1, s(357) + bh};
    return l;
}

inline Button hit(const Layout& l, const State& s, int x, int y) {
    for (Button b : buttons(s)) {
        if (b == Button::Cancel && l.cancel.contains(x, y)) return b;
        if (b == Button::OpenFolder && l.openFolder.contains(x, y)) return b;
    }
    return Button::None;
}

// Keys while the panel is open. It owns every key: none reaches the Mac.
class Keys {
public:
    enum class Action { None, Close, Press };
    struct Result {
        Action action = Action::None;
        Button button = Button::None;
    };
    static constexpr uint32_t kTab = 0x09, kEnter = 0x0D, kEscape = 0x1B, kSpace = 0x20;

    void reset() { focus_ = -1; }
    Button focus(const State& s) const {
        const auto b = buttons(s);
        return focus_ >= 0 && focus_ < static_cast<int>(b.size()) ? b[focus_] : Button::None;
    }
    Result key(uint32_t vk, const State& s, bool shift = false) {
        const auto b = buttons(s);
        const int n = static_cast<int>(b.size());
        if (focus_ >= n) focus_ = n - 1;
        switch (vk) {
        case kEscape: return {Action::Close, Button::None};
        case kTab:
            if (n > 0) focus_ = focus_ < 0 ? (shift ? n - 1 : 0) : (focus_ + (shift ? n - 1 : 1)) % n;
            return {};
        case kEnter:
        case kSpace:
            if (focus_ >= 0 && focus_ < n) return {Action::Press, b[focus_]};
            return vk == kEnter ? Result{Action::Close, Button::None} : Result{};
        default: return {};
        }
    }

private:
    int focus_ = -1;
};

// Whether the transfer chip (progress bar or notice) belongs on screen. A chip
// started while the viewer was minimised (Send to from Explorer) was never
// shown; Windows restores only the owned popups it hid itself, so the viewer
// shows it on restore. A floating notice stays up even while minimised.
inline bool chipOnScreen(bool chipActive, bool viewerMinimised, bool floats) {
    return chipActive && (!viewerMinimised || floats);
}

}  // namespace jl::filepanel
