#pragma once

// F5a: Explorer > right-click > Send to > JerisLink.
//
// The installer puts a JerisLink shortcut in the user's SendTo folder that
// runs "Jerislink.exe --send-to <paths...>". The Microsoft Store (MSIX) build
// has no SendTo shortcut: its Explorer menu command (send_to_shell.cpp, in
// JerisLinkSendTo.dll) starts the same "--send-to" run instead, built with
// commandLine() below. That short-lived process never
// opens a viewer window: it hands the paths over a local named pipe to the
// running viewer of the same user and logon session, which sends them to the
// Mac exactly like a drop (purpose=send, ~/Downloads/JerisLink), and prints a
// dialog only when nothing was sent.
//
// This header has no Win32: argument handling, the pipe request / reply
// bytes, the viewer's decision and every user-facing text, so
// send_to_test.cpp can check them on any OS. send_to_win.hpp/.cpp is the
// Win32 pipe; viewer.cpp wires it to the session.

#include "file_panel.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace jl::sendto {

inline constexpr wchar_t kFlag[] = L"--send-to";
// The Explorer menu command's selection did not fit on one command line: the
// run only shows the "too many" dialog.
inline constexpr wchar_t kTooManyFlag[] = L"--send-to-too-many";

// Limits. Explorer passes Send to items on the command line (about 32k
// characters), so real requests are far smaller; the pipe enforces these
// anyway because any process of the user can write to it.
inline constexpr size_t kMaxItems = 1000;                    // design D7
inline constexpr size_t kMaxPathChars = 32767;               // longest Win32 path
inline constexpr size_t kMaxRequestBytes = 4u * 1024 * 1024;  // whole request
inline constexpr size_t kMaxCommandLineChars = 32766;         // CreateProcessW, without the NUL

// ---- command line ----

struct Args {
    bool sendTo = false;              // argv[1] is --send-to or --send-to-too-many
    bool tooMany = false;             // argv[1] is --send-to-too-many
    std::vector<std::wstring> items;  // what followed it, unchecked
};

// argv as CommandLineToArgvW returns it (argv[0] is the exe).
inline Args parseArgs(const std::vector<std::wstring>& argv) {
    Args a;
    if (argv.size() < 2) return a;
    if (argv[1] == kTooManyFlag) {
        a.sendTo = a.tooMany = true;
        return a;
    }
    if (argv[1] != kFlag) return a;
    a.sendTo = true;
    for (size_t i = 2; i < argv.size(); ++i) {
        if (!argv[i].empty()) a.items.push_back(argv[i]);
    }
    return a;
}

// One argument quoted so CommandLineToArgvW gives it back unchanged:
// backslashes are literal except before a quote, so a run of them before a
// quote (or before the closing quote, as in "C:\") is doubled.
inline std::wstring quoteArg(const std::wstring& s) {
    std::wstring out = L"\"";
    size_t slashes = 0;
    for (wchar_t c : s) {
        if (c == L'\\') {
            ++slashes;
            continue;
        }
        if (c == L'"') {
            out.append(slashes * 2 + 1, L'\\');
        } else {
            out.append(slashes, L'\\');
        }
        slashes = 0;
        out.push_back(c);
    }
    out.append(slashes * 2, L'\\');
    out.push_back(L'"');
    return out;
}

// The command line the Store build's Explorer command starts:
// "<exe>" --send-to "<item>"... When it would not fit in CreateProcessW's
// limit, "<exe>" --send-to-too-many instead, so the user still gets the
// "too many" dialog rather than a silently cut list.
inline std::wstring commandLine(const std::wstring& exe, const std::vector<std::wstring>& items) {
    std::wstring line = quoteArg(exe) + L" " + kFlag;
    for (const auto& p : items) {
        line += L" ";
        line += quoteArg(p);
        if (line.size() > kMaxCommandLineChars) return quoteArg(exe) + L" " + kTooManyFlag;
    }
    return line;
}

// A full local or UNC path: "C:\..." or "\\server\share\...". Explorer only
// passes these; anything else (relative, "C:x", device paths, embedded NUL)
// is refused before it reaches the viewer.
inline bool isAcceptablePath(const std::wstring& p) {
    if (p.size() < 3 || p.size() > kMaxPathChars) return false;
    for (wchar_t c : p) {
        if (c == L'\0') return false;
    }
    const auto sep = [](wchar_t c) { return c == L'\\' || c == L'/'; };
    const auto drive = [&](const std::wstring& s) {
        return s.size() >= 3 && ((s[0] >= L'A' && s[0] <= L'Z') || (s[0] >= L'a' && s[0] <= L'z')) && s[1] == L':' &&
               sep(s[2]);
    };
    const auto unc = [&](const std::wstring& s) {
        return s.size() >= 3 && sep(s[0]) && sep(s[1]) && s[2] != L'?' && s[2] != L'.' && !sep(s[2]);
    };
    // Long-path form Explorer may use: \\?\C:\... or \\?\UNC\server\share\...
    if (p.rfind(L"\\\\?\\", 0) == 0) {
        const std::wstring rest = p.substr(4);
        if (rest.rfind(L"UNC\\", 0) == 0) return rest.size() > 4 && !sep(rest[4]);
        return drive(rest);
    }
    return drive(p) || unc(p);
}

// ---- outcome ----

// What happened, from the viewer (over the pipe) or from the client itself.
enum class Reply : uint8_t {
    Started = 0,       // the viewer is sending; its chip shows progress
    NotConnected = 1,  // no viewer, or a viewer with no Mac session
    Busy = 2,          // a transfer is already running
    HostOld = 3,       // the Mac's JerisLink cannot take a send (pre-F4)
    Connecting = 4,    // session up, Mac file caps not known yet
    Failed = 5,        // the viewer could not start the send
    BadRequest = 6,    // malformed request or a path that is not a full path
    NothingSelected = 7,
    TooMany = 8,
    NotTrusted = 9,    // the pipe's server is not this user's process
};
inline constexpr uint8_t kReplyMax = 9;

// The viewer's answer to a valid request, from the same facts a drop uses.
inline Reply decide(bool session, jl::filepanel::Host host, bool busy, bool canSend) {
    using jl::filepanel::Host;
    if (!session) return Reply::NotConnected;
    if (busy) return Reply::Busy;
    if (host == Host::Unknown) return Reply::Connecting;
    if (host != Host::Full || !canSend) return Reply::HostOld;
    return Reply::Started;
}

// Dialog text when nothing was sent ("" for Started: no dialog).
inline std::string message(Reply r) {
    switch (r) {
    case Reply::Started: return "";
    case Reply::NotConnected: return "JerisLink is not connected. Connect to your Mac first, then try again.";
    case Reply::Busy: return "A transfer is already running. Cancel it in Files, or wait, then try again.";
    case Reply::HostOld: return "The Mac's JerisLink can't receive files yet. Update JerisLink on the Mac.";
    case Reply::Connecting: return "JerisLink is still connecting to the Mac. Try again in a moment.";
    case Reply::BadRequest: return "JerisLink couldn't read the selected items. Select files or folders, then try again.";
    case Reply::NothingSelected: return "Select files or folders first, then right-click \xE2\x80\xBA Send to \xE2\x80\xBA JerisLink.";
    case Reply::TooMany: return "Too many items. Send at most 1,000 at a time.";
    case Reply::NotTrusted: return "JerisLink couldn't reach the viewer safely. Close JerisLink, open it again, then try again.";
    default: return "Sending to the Mac failed. Try again.";
    }
}

// Process exit code of "Jerislink.exe --send-to": 0 when started.
inline int exitCode(Reply r) { return r == Reply::Started ? 0 : 20 + static_cast<int>(r); }

// Short log / test token.
inline const char* name(Reply r) {
    switch (r) {
    case Reply::Started: return "started";
    case Reply::NotConnected: return "not_connected";
    case Reply::Busy: return "busy";
    case Reply::HostOld: return "host_old";
    case Reply::Connecting: return "connecting";
    case Reply::BadRequest: return "bad_request";
    case Reply::NothingSelected: return "nothing_selected";
    case Reply::TooMany: return "too_many";
    case Reply::NotTrusted: return "not_trusted";
    default: return "failed";
    }
}

// Checks the client runs before it opens the pipe.
inline Reply checkItems(const std::vector<std::wstring>& items) {
    if (items.empty()) return Reply::NothingSelected;
    if (items.size() > kMaxItems) return Reply::TooMany;
    for (const auto& p : items) {
        if (!isAcceptablePath(p)) return Reply::BadRequest;
    }
    return Reply::Started;
}

// The same for a whole "--send-to" / "--send-to-too-many" run.
inline Reply checkArgs(const Args& a) { return a.tooMany ? Reply::TooMany : checkItems(a.items); }

// ---- pipe bytes ----
//
// Request: "JLS1", u32 count, then per item u32 length (UTF-16 code units)
// and the UTF-16LE path. Reply: "JLR1", u8 Reply. Little endian.

inline constexpr char kRequestMagic[4] = {'J', 'L', 'S', '1'};
inline constexpr char kReplyMagic[4] = {'J', 'L', 'R', '1'};

namespace detail {
inline void putU32(std::vector<uint8_t>& b, uint32_t v) {
    for (int i = 0; i < 4; ++i) b.push_back(static_cast<uint8_t>(v >> (8 * i)));
}
inline bool getU32(const uint8_t* p, size_t n, size_t& at, uint32_t& v) {
    if (n - at < 4) return false;
    v = 0;
    for (int i = 0; i < 4; ++i) v |= static_cast<uint32_t>(p[at + i]) << (8 * i);
    at += 4;
    return true;
}
}  // namespace detail

inline std::vector<uint8_t> encodeRequest(const std::vector<std::wstring>& items) {
    std::vector<uint8_t> b(kRequestMagic, kRequestMagic + 4);
    detail::putU32(b, static_cast<uint32_t>(items.size()));
    for (const auto& p : items) {
        detail::putU32(b, static_cast<uint32_t>(p.size()));
        for (wchar_t c : p) {
            const auto u = static_cast<uint16_t>(c);
            b.push_back(static_cast<uint8_t>(u & 0xFF));
            b.push_back(static_cast<uint8_t>(u >> 8));
        }
    }
    return b;
}

// Strict: exact length, count 1..kMaxItems, every path acceptable. On any
// failure returns false and leaves `out` empty.
inline bool decodeRequest(const uint8_t* p, size_t n, std::vector<std::wstring>& out) {
    out.clear();
    if (!p || n < 8 || n > kMaxRequestBytes) return false;
    for (int i = 0; i < 4; ++i) {
        if (p[i] != static_cast<uint8_t>(kRequestMagic[i])) return false;
    }
    size_t at = 4;
    uint32_t count = 0;
    if (!detail::getU32(p, n, at, count) || count == 0 || count > kMaxItems) return false;
    out.reserve(count);
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t len = 0;
        if (!detail::getU32(p, n, at, len) || len > kMaxPathChars || (n - at) / 2 < len) {
            out.clear();
            return false;
        }
        std::wstring s(len, L'\0');
        for (uint32_t k = 0; k < len; ++k) {
            s[k] = static_cast<wchar_t>(p[at] | (static_cast<uint16_t>(p[at + 1]) << 8));
            at += 2;
        }
        if (!isAcceptablePath(s)) {
            out.clear();
            return false;
        }
        out.push_back(std::move(s));
    }
    if (at != n) {
        out.clear();
        return false;
    }
    return true;
}

inline std::vector<uint8_t> encodeReply(Reply r) {
    std::vector<uint8_t> b(kReplyMagic, kReplyMagic + 4);
    b.push_back(static_cast<uint8_t>(r));
    return b;
}

inline bool decodeReply(const uint8_t* p, size_t n, Reply& r) {
    if (!p || n != 5) return false;
    for (int i = 0; i < 4; ++i) {
        if (p[i] != static_cast<uint8_t>(kReplyMagic[i])) return false;
    }
    if (p[4] > kReplyMax) return false;
    r = static_cast<Reply>(p[4]);
    return true;
}

// \\.\pipe\JerisLink.SendTo.<user SID>.<logon session id>: one viewer per
// user and session owns it (first instance), other users cannot open it.
inline std::wstring pipeName(const std::wstring& userSid, unsigned long sessionId) {
    return L"\\\\.\\pipe\\JerisLink.SendTo." + userSid + L"." + std::to_wstring(sessionId);
}

}  // namespace jl::sendto
