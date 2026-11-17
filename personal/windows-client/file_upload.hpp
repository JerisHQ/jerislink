#pragma once

// Windows->Mac paste (F2): the parts of the viewer side that need no Win32,
// so file_upload_test.cpp can lock them down.
//
// - PasteGate: watches the key events the viewer sends to the Mac. When a
//   Cmd+V goes out while the Windows clipboard holds files newer than the
//   last upload, it holds the V (the Mac sees no paste yet) and asks the
//   viewer to upload. When the upload ends within 3 s it gives back a Cmd+V
//   to send; later than that, or after focus left, the chip says "Ready,
//   press Cmd+V again" instead, so a late paste never lands elsewhere.
//   While any transfer runs, a Cmd+V with new files is eaten and the chip
//   says so (never a stale paste on the Mac, never a second transfer).
// - Pacer: token bucket for FileTransferMaxMbps (0 = no cap).
// - Text for the progress chip and the disconnect confirm.
// - ConfirmKeys: keyboard rules of the disconnect confirm.

#include "keymap.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <string>
#include <vector>

namespace jl::fileup {

inline constexpr double kPasteHoldMs = 3000.0;
inline constexpr uint16_t kKeyV = 'V';
inline constexpr uint32_t kDefaultMaxMbps = 100;
inline constexpr uint64_t kWindowBytes = 4ull * 1024 * 1024;  // max unacknowledged

class PasteGate {
public:
    struct Filtered {
        std::vector<keymap::KeyEvent> events;  // what to send to the Mac
        bool startUpload = false;              // a new hold began: start the upload now
        bool refusedBusy = false;              // Cmd+V eaten: files copied, but a transfer runs
    };
    enum class Outcome { None, Paste, Late, Dropped };
    struct Finished {
        Outcome outcome = Outcome::None;
        std::vector<keymap::KeyEvent> events;  // Cmd+V to send when outcome == Paste
    };

    // eligible() is asked only when a Cmd+V down is about to go out and no
    // hold is running: clipboard has files newer than the last upload and
    // the host can receive them. busy() is asked only after eligible() said
    // yes: a transfer (upload, Send to, Mac->Windows pull) is running. Then
    // the V is eaten, so the Mac never pastes its stale pasteboard, and
    // refusedBusy asks the viewer to say why. Without files (text) or with
    // an old host the Cmd+V passes through as before.
    Filtered filter(const std::vector<keymap::KeyEvent>& in, double nowMs,
                    const std::function<bool()>& eligible, const std::function<bool()>& busy = nullptr) {
        Filtered out;
        for (const auto& e : in) {
            if (e.semantic == keymap::kWin) cmd_ = e.down;
            else if (e.semantic == keymap::kCtrl) ctrl_ = e.down;
            if (e.semantic == kKeyV) {
                if (e.down && (holding_ || refusing_)) {  // repeat or a second press while held
                    swallowUp_ = true;
                    continue;
                }
                if (!e.down && refusing_) refusing_ = false;
                if (e.down && cmd_ && eligible && eligible()) {
                    if (busy && busy()) {
                        refusing_ = true;
                        swallowUp_ = true;
                        out.refusedBusy = true;
                        continue;
                    }
                    holding_ = true;
                    late_ = false;
                    startMs_ = nowMs;
                    swallowUp_ = true;
                    out.startUpload = true;
                    continue;
                }
                if (!e.down && swallowUp_) {
                    swallowUp_ = false;
                    continue;
                }
            }
            out.events.push_back(e);
        }
        return out;
    }

    // The upload ended. ok: the Mac pasteboard now holds the files.
    Finished finish(bool ok, double nowMs) {
        Finished f;
        if (!holding_) return f;
        holding_ = false;
        if (!ok) {
            f.outcome = Outcome::Dropped;
            return f;
        }
        if (late_ || nowMs - startMs_ > kPasteHoldMs) {
            f.outcome = Outcome::Late;
            return f;
        }
        f.outcome = Outcome::Paste;
        // Plain Cmd+V on the Mac: lift a held Control first (Mac preset
        // re-sends it after Ctrl+V) and put it back afterwards.
        if (ctrl_) f.events.push_back({false, keymap::kCtrl});
        if (!cmd_) f.events.push_back({true, keymap::kWin});
        f.events.push_back({true, kKeyV});
        f.events.push_back({false, kKeyV});
        if (!cmd_) f.events.push_back({false, keymap::kWin});
        if (ctrl_) f.events.push_back({true, keymap::kCtrl});
        return f;
    }

    // Focus left the viewer: never paste into whatever has the Mac's focus later.
    void abandon() {
        if (holding_) late_ = true;
    }
    // All modifiers were released on the Mac (focus loss, disconnect).
    void modifiersReleased() {
        cmd_ = false;
        ctrl_ = false;
        swallowUp_ = false;
        refusing_ = false;
    }
    bool holding() const { return holding_; }

private:
    bool cmd_ = false;
    bool ctrl_ = false;
    bool holding_ = false;
    bool refusing_ = false;  // a busy refusal ate this V down; eat its repeats too
    bool late_ = false;
    bool swallowUp_ = false;
    double startMs_ = 0.0;
};

// Token bucket: bytes per ms from Mbps, at most 50 ms of burst.
class Pacer {
public:
    explicit Pacer(uint32_t maxMbps = kDefaultMaxMbps) : mbps_(maxMbps) {}
    void setMbps(uint32_t mbps) { mbps_ = mbps; }
    uint32_t mbps() const { return mbps_; }
    // How long to wait before sending `bytes` at nowMs, then counts them as sent.
    double delayMs(uint64_t bytes, double nowMs) {
        if (mbps_ == 0) return 0.0;
        const double bytesPerMs = mbps_ * 1000.0 / 8.0;  // 1 Mbps = 125 bytes/ms
        if (!started_) {
            started_ = true;
            nextMs_ = nowMs;
        }
        nextMs_ = std::max(nextMs_, nowMs - kBurstMs);
        const double wait = std::max(0.0, nextMs_ - nowMs);
        nextMs_ += static_cast<double>(bytes) / bytesPerMs;
        return wait;
    }

private:
    static constexpr double kBurstMs = 50.0;
    uint32_t mbps_;
    bool started_ = false;
    double nextMs_ = 0.0;
};

// Decimal units, like Finder and Explorer's copy dialogs: "512 B", "12 KB",
// "85 MB", "1.2 GB" (one decimal under 10, none above).
inline std::string formatBytes(uint64_t n) {
    static const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    if (n < 1000) return std::to_string(n) + " B";
    double v = static_cast<double>(n);
    int u = 0;
    while (v >= 1000.0 && u < 4) {
        v /= 1000.0;
        ++u;
    }
    char buf[32];
    if (v < 9.95) std::snprintf(buf, sizeof(buf), "%.1f %s", v, units[u]);
    else std::snprintf(buf, sizeof(buf), "%.0f %s", v, units[u]);
    return buf;
}

// Same unit for both numbers: "1.2 / 4.0 GB".
inline std::string formatPair(uint64_t done, uint64_t total) {
    const std::string t = formatBytes(total);
    const auto space = t.find(' ');
    const std::string unit = t.substr(space + 1);
    static const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    double div = 1.0;
    for (const char* u : units) {
        if (unit == u) break;
        div *= 1000.0;
    }
    char buf[48];
    if (div == 1.0) {
        std::snprintf(buf, sizeof(buf), "%llu / %s", static_cast<unsigned long long>(done), t.c_str());
    } else {
        const double totalV = static_cast<double>(total) / div;
        const double doneV = std::min(static_cast<double>(done), static_cast<double>(total)) / div;
        if (totalV < 9.95) std::snprintf(buf, sizeof(buf), "%.1f / %s", doneV, t.c_str());
        else std::snprintf(buf, sizeof(buf), "%.0f / %s", doneV, t.c_str());
    }
    return buf;
}

inline std::string plural(uint64_t n, const char* one, const char* many) {
    return std::to_string(n) + " " + (n == 1 ? one : many);
}

// UTF-8 "↑ 3 files · 1.2 / 4.0 GB · 85 MB/s". Rate 0 is left out.
inline std::string chipText(uint64_t files, uint64_t done, uint64_t total, uint64_t bytesPerSec) {
    std::string s = "\xE2\x86\x91 " + plural(files, "file", "files") + " \xC2\xB7 " + formatPair(done, total);
    if (bytesPerSec > 0) s += " \xC2\xB7 " + formatBytes(bytesPerSec) + "/s";
    return s;
}

// Cmd+V with copied files while a transfer runs: nothing is pasted on the Mac.
inline std::string pasteBusy() {
    return "A transfer is already running. Wait or cancel it in Files, then press Cmd+V again.";
}

inline std::string confirmTitle() { return "File transfer in progress"; }

// {n} = files not finished; bytes like the chip. F2 has uploads only, so the
// destination is always the Mac.
inline std::string confirmBody(uint64_t filesLeft, uint64_t done, uint64_t total) {
    return std::to_string(filesLeft) + " file(s) are still transferring (" + formatBytes(std::min(done, total)) +
           " of " + formatBytes(total) +
           "). If you disconnect now, the transfer stops and unfinished files are removed from the Mac. "
           "Files that already finished are kept.";
}

// Same, while Explorer is pasting Mac files into this PC (F3). Explorer
// owns the files it writes; the viewer only stops feeding them.
inline std::string confirmBodyPull(uint64_t filesLeft, uint64_t done, uint64_t total) {
    return std::to_string(filesLeft) + " file(s) are still being pasted into this PC (" + formatBytes(std::min(done, total)) +
           " of " + formatBytes(total) +
           "). If you disconnect now, the paste stops and Explorer reports the unfinished files. "
           "Files that already finished are kept.";
}

// Disconnect confirm keys. Keep is the default; Esc and Enter keep;
// "Disconnect and remove" needs Tab (or an arrow) to it, then Space.
class ConfirmKeys {
public:
    enum class Button { Keep, Disconnect };
    enum class Action { None, Keep, Disconnect };
    void reset() { focus_ = Button::Keep; }
    Button focus() const { return focus_; }
    // vk: Windows virtual-key code (keymap::vk values).
    Action key(uint32_t vk) {
        switch (vk) {
        case keymap::vk::Escape:
        case keymap::vk::Return:
            return Action::Keep;
        case keymap::vk::Tab:
        case keymap::vk::Left:
        case keymap::vk::Right:
            focus_ = focus_ == Button::Keep ? Button::Disconnect : Button::Keep;
            return Action::None;
        case keymap::vk::Space:
            return focus_ == Button::Keep ? Action::Keep : Action::Disconnect;
        default:
            return Action::None;
        }
    }

private:
    Button focus_ = Button::Keep;
};

}  // namespace jl::fileup
