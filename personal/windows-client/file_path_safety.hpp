#pragma once

// Path rules for names received in a file session (design D14). The Mac
// side is FilePathSafety.swift; this one adds the Windows-only rules.
//
// A received path is relative, made of '/'-separated components, and is only
// ever joined under a destination folder the viewer chose. Anything that could
// leave that folder, or that Windows would read differently, is refused and
// never repaired: the sender gets REJECT bad_path.
//
// checkRules() and clashName() are pure UTF-8 code. validate() adds strict
// UTF-8 decoding and NFC through Win32 NormalizeString (link Normaliz).

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

namespace jl::file::path {

inline constexpr size_t kMaxComponentBytes = 255;
inline constexpr size_t kMaxPathBytes = 1024;
inline constexpr size_t kMaxDepth = 32;

enum class Rejection {
    None, NotUtf8, Empty, Absolute, Backslash, ControlChar, EmptyComponent, DotComponent,
    DriveLetter, ComponentTooLong, PathTooLong, TooDeep, ReservedChar, ReservedName,
    TrailingDotOrSpace, NormalizeFailed,
};

// Strict UTF-8: no overlong forms, no surrogates, nothing above U+10FFFF.
inline bool validUtf8(const std::string& s) {
    size_t i = 0;
    const size_t n = s.size();
    while (i < n) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (c < 0x80) { ++i; continue; }
        size_t len = 0;
        uint32_t cp = 0;
        uint32_t min = 0;
        if ((c & 0xE0) == 0xC0) { len = 2; cp = c & 0x1F; min = 0x80; }
        else if ((c & 0xF0) == 0xE0) { len = 3; cp = c & 0x0F; min = 0x800; }
        else if ((c & 0xF8) == 0xF0) { len = 4; cp = c & 0x07; min = 0x10000; }
        else return false;
        if (i + len > n) return false;
        for (size_t k = 1; k < len; ++k) {
            const unsigned char cc = static_cast<unsigned char>(s[i + k]);
            if ((cc & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (cc & 0x3F);
        }
        if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return false;
        i += len;
    }
    return true;
}

namespace detail {
inline bool isReservedName(const std::string& component) {
    // Windows reserves these device names with any extension and ignores
    // trailing spaces before the dot: "con.txt" and "NUL .log" are devices.
    std::string stem = component.substr(0, component.find('.'));
    while (!stem.empty() && stem.back() == ' ') stem.pop_back();
    for (char& ch : stem) if (ch >= 'a' && ch <= 'z') ch = char(ch - 'a' + 'A');
    static const char* const kNames[] = {"CON", "PRN", "AUX", "NUL"};
    for (const char* name : kNames) if (stem == name) return true;
    if (stem.size() >= 4 && (stem.compare(0, 3, "COM") == 0 || stem.compare(0, 3, "LPT") == 0)) {
        const std::string tail = stem.substr(3);
        if (tail.size() == 1 && tail[0] >= '1' && tail[0] <= '9') return true;
        // Superscript 1, 2, 3 (U+00B9, U+00B2, U+00B3) are devices too.
        if (tail == "\xC2\xB9" || tail == "\xC2\xB2" || tail == "\xC2\xB3") return true;
    }
    return false;
}
}  // namespace detail

// Rules on a path that is already valid UTF-8 and NFC. Same order as the
// Mac side, so both report the same reason for the shared rules.
inline Rejection checkRules(const std::string& path) {
    if (path.empty()) return Rejection::Empty;
    if (path.size() > kMaxPathBytes) return Rejection::PathTooLong;
    if (path[0] == '/') return Rejection::Absolute;
    for (unsigned char c : path) {
        if (c == '\\') return Rejection::Backslash;
        if (c < 0x20 || c == 0x7F) return Rejection::ControlChar;
    }
    std::vector<std::string> parts;
    size_t start = 0;
    while (true) {
        const size_t slash = path.find('/', start);
        parts.push_back(path.substr(start, slash == std::string::npos ? std::string::npos : slash - start));
        if (slash == std::string::npos) break;
        start = slash + 1;
    }
    if (parts.size() > kMaxDepth) return Rejection::TooDeep;
    for (size_t i = 0; i < parts.size(); ++i) {
        const std::string& part = parts[i];
        if (part.empty()) return Rejection::EmptyComponent;
        if (part == "." || part == "..") return Rejection::DotComponent;
        if (part.size() > kMaxComponentBytes) return Rejection::ComponentTooLong;
        if (i == 0 && part.size() >= 2 && part[1] == ':' &&
            ((part[0] >= 'A' && part[0] <= 'Z') || (part[0] >= 'a' && part[0] <= 'z'))) {
            return Rejection::DriveLetter;
        }
        // Windows-only from here.
        if (part.find_first_of(":*?\"<>|") != std::string::npos) return Rejection::ReservedChar;
        if (part.back() == '.' || part.back() == ' ') return Rejection::TrailingDotOrSpace;
        if (detail::isReservedName(part)) return Rejection::ReservedName;
    }
    return Rejection::None;
}

// F3 r2 (D14 revision): names a Mac allows but Windows cannot hold are
// mapped, not refused, when Mac files are pasted on Windows, so the copy
// still pastes. Only the Windows-only rules are mapped; every shared safety
// rule (absolute, "..", empty part, backslash, control chars) still refuses.
//   : * ? " < > |      -> _   (so a leading "C:" is "C_", not a drive)
//   trailing dots/spaces -> removed ("_" if nothing is left)
//   CON, NUL, COM1 ...   -> "_" after the device stem: CON.txt -> CON_.txt
// "." and ".." are left alone so checkRules() refuses them.
inline std::string windowsComponent(const std::string& part) {
    if (part == "." || part == "..") return part;
    std::string out = part;
    for (char& ch : out) {
        if (ch == ':' || ch == '*' || ch == '?' || ch == '"' || ch == '<' || ch == '>' || ch == '|') ch = '_';
    }
    while (!out.empty() && (out.back() == '.' || out.back() == ' ')) out.pop_back();
    if (out.empty()) return "_";
    if (detail::isReservedName(out)) {
        const size_t dot = out.find('.');
        out.insert(dot == std::string::npos ? out.size() : dot, "_");
    }
    return out;
}

// windowsComponent() on every '/'-separated part. Empty parts stay empty.
inline std::string windowsPath(const std::string& path) {
    std::string out;
    size_t start = 0;
    while (true) {
        const size_t slash = path.find('/', start);
        const std::string part = path.substr(start, slash == std::string::npos ? std::string::npos : slash - start);
        out += part.empty() ? part : windowsComponent(part);
        if (slash == std::string::npos) break;
        out += '/';
        start = slash + 1;
    }
    return out;
}

// Explorer-style name for the nth clash (n >= 2): "report (2).pdf",
// "notes (3)", ".profile (2)". The extension is what follows the last dot
// that is not the first character. The base is shortened on a code point
// boundary so the result stays within 255 bytes.
inline std::string clashName(const std::string& name, int n) {
    std::string base = name;
    std::string ext;
    const size_t dot = name.rfind('.');
    if (dot != std::string::npos && dot != 0) {
        base = name.substr(0, dot);
        ext = name.substr(dot);
    }
    const std::string suffix = " (" + std::to_string(n) + ")";
    while (!base.empty() && base.size() + suffix.size() + ext.size() > kMaxComponentBytes) {
        // Drop one whole code point: continuation bytes, then the lead byte.
        while (!base.empty() && (static_cast<unsigned char>(base.back()) & 0xC0) == 0x80) base.pop_back();
        if (!base.empty()) base.pop_back();
    }
    return base + suffix + ext;
}

#ifdef _WIN32
struct Verdict {
    Rejection why = Rejection::None;
    std::string utf8;    // NFC, '/'-separated (after mapping, if asked)
    std::wstring wide;   // NFC, '\\'-separated, ready to join under a folder
    std::string original;  // NFC as sent, before any mapping
    bool renamed = false;  // mapWindowsNames changed it
    bool ok() const { return why == Rejection::None; }
};

// Validate the raw UTF-8 bytes of an ENTRY path. mapWindowsNames (F3 Mac->
// Windows paste only) maps Windows-only name problems with windowsPath()
// instead of refusing them.
inline Verdict validate(const std::vector<uint8_t>& raw, bool mapWindowsNames = false) {
    Verdict v;
    const std::string in(raw.begin(), raw.end());
    if (in.empty()) { v.why = Rejection::Empty; return v; }
    if (!validUtf8(in)) { v.why = Rejection::NotUtf8; return v; }
    if (in.size() > 4 * kMaxPathBytes) { v.why = Rejection::PathTooLong; return v; }
    // Before NFC, so NormalizeString never sees NUL or a control character.
    for (unsigned char c : in) {
        if (c == '\\') { v.why = Rejection::Backslash; return v; }
        if (c < 0x20 || c == 0x7F) { v.why = Rejection::ControlChar; return v; }
    }
    const int wn = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, in.data(), int(in.size()), nullptr, 0);
    if (wn <= 0) { v.why = Rejection::NotUtf8; return v; }
    std::wstring w(size_t(wn), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, in.data(), int(in.size()), w.data(), wn);
    // NFC can grow a string; size by asking first, as the API documents.
    int nn = NormalizeString(NormalizationC, w.data(), int(w.size()), nullptr, 0);
    if (nn <= 0) { v.why = Rejection::NormalizeFailed; return v; }
    std::wstring nfc(size_t(nn), L'\0');
    nn = NormalizeString(NormalizationC, w.data(), int(w.size()), nfc.data(), nn);
    if (nn <= 0) { v.why = Rejection::NormalizeFailed; return v; }
    nfc.resize(size_t(nn));
    const int un = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, nfc.data(), int(nfc.size()), nullptr, 0, nullptr, nullptr);
    if (un <= 0) { v.why = Rejection::NotUtf8; return v; }
    v.utf8.assign(size_t(un), '\0');
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, nfc.data(), int(nfc.size()), v.utf8.data(), un, nullptr, nullptr);
    v.original = v.utf8;
    if (mapWindowsNames) {
        std::string mapped = windowsPath(v.utf8);
        if (mapped != v.utf8) {
            // ASCII-only edits: still NFC; rebuild the wide form from it.
            v.renamed = true;
            v.utf8 = std::move(mapped);
            const int mn = MultiByteToWideChar(CP_UTF8, 0, v.utf8.data(), int(v.utf8.size()), nullptr, 0);
            nfc.assign(size_t(mn > 0 ? mn : 0), L'\0');
            if (mn > 0) MultiByteToWideChar(CP_UTF8, 0, v.utf8.data(), int(v.utf8.size()), nfc.data(), mn);
        }
    }
    v.why = checkRules(v.utf8);
    if (!v.ok()) { v.utf8.clear(); v.renamed = false; return v; }
    v.wide = nfc;
    for (wchar_t& ch : v.wide) if (ch == L'/') ch = L'\\';
    return v;
}
#endif

}  // namespace jl::file::path
