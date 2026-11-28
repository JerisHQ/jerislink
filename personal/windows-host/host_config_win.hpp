// JerisLink Windows host, H3: the settings in the registry (design D7) and
// the password's key under DPAPI (D8).
//
// HKLM\SOFTWARE\Jeris\JerisLinkHost, 64-bit view. HKLM\SOFTWARE lets Users
// read and only Administrators and SYSTEM write, so every change needs an
// elevated process (the settings window asks UAC once).
//   ListenMode   REG_SZ        "tailnet" (default) or "loopback"
//   BindIP       REG_SZ        a tailnet IPv4 on this PC; absent or empty: the lowest one
//   AllowedIPs   REG_MULTI_SZ  the whitelist; empty: any address may try the password
//   BlockedIPs   REG_MULTI_SZ  the blacklist, "ip<TAB>unix seconds<TAB>reason" per row
//   PasswordSet  REG_DWORD     1 once a password is set (shown to Users; Secret decides)
//   Theme        REG_SZ        "green" (default) or "blue": the settings window
//   LogPath      REG_SZ        the host log when --log is not given
//   Serial       REG_QWORD     moved by every write JerisLink makes here (the change stamp)
//   Secret\Key   REG_BINARY    DPAPI, machine scope, of host_settings.hpp encodeSecret
//                              (K, salt, iterations, host id). Secret's DACL is
//                              SYSTEM and Administrators only, not inherited.
//   Journal\PendingBlocks REG_MULTI_SZ, Journal\Serial REG_QWORD (blocks not yet in BlockedIPs)
//   Failures\Records REG_MULTI_SZ, Failures\Times REG_BINARY (the window's failure list)
//
// Read-modify-writes (the blacklist, the password, the whitelist) run
// under the named mutex Global\JerisLinkHostConfig, which only SYSTEM and
// Administrators can open: the host adding a 20th-failure block and the
// window removing one cannot lose each other's change. The host reads
// without it: every value it serves from is one registry value, and
// Serial moves last, so a read that crossed a write is read again.
#pragma once

#include "host_crypto_win.hpp"
#include "host_settings.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#include <sddl.h>
#include <iphlpapi.h>
#include <shellapi.h>

#include <string>
#include <thread>
#include <vector>

namespace jlh::config {

using auth::BlockedEntry;
using auth::Bytes;
using auth::FailureRecord;
using auth::StoreStamp;
using settings::Outcome;

struct Location {
    HKEY hive = HKEY_LOCAL_MACHINE;
    std::wstring path = L"SOFTWARE\\Jeris\\JerisLinkHost";
    std::wstring mutexName = L"Global\\JerisLinkHostConfig";
    // Secret's DACL and the mutex's (false only for a test under HKCU
    // that runs without elevation).
    bool protect = true;
};

constexpr REGSAM kView = KEY_WOW64_64KEY;
constexpr wchar_t kSecretSddl[] = L"D:P(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)";
constexpr wchar_t kMutexSddl[] = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)";
constexpr DWORD kLockWaitMs = 2000;

// ------------------------------------------------------------- strings

inline std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), nullptr, 0);
    std::wstring w(size_t(std::max(n, 0)), L'\0');
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), &w[0], n);
    return w;
}
inline std::string narrow(const std::wstring& w) {
    if (w.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), int(w.size()), nullptr, 0, nullptr, nullptr);
    std::string s(size_t(std::max(n, 0)), '\0');
    if (n > 0) WideCharToMultiByte(CP_UTF8, 0, w.data(), int(w.size()), &s[0], n, nullptr, nullptr);
    return s;
}

// The password's NFC code points, for the strength rules. nullopt: it is
// not valid UTF-16 or did not normalize.
inline std::optional<std::u32string> nfcCodePoints(const std::wstring& pw) {
    if (pw.empty()) return std::u32string{};
    std::wstring nfc;
    int need = NormalizeString(NormalizationC, pw.c_str(), int(pw.size()), nullptr, 0);
    bool ok = false;
    for (int attempt = 0; attempt < 4 && need > 0; ++attempt) {
        nfc.assign(size_t(need), L'\0');
        const int got = NormalizeString(NormalizationC, pw.c_str(), int(pw.size()), &nfc[0], need);
        if (got > 0) {
            nfc.resize(size_t(got));
            ok = true;
            break;
        }
        SecureZeroMemory(&nfc[0], nfc.size() * sizeof(wchar_t));
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) break;
        need = -got;
    }
    if (!ok) return std::nullopt;
    std::u32string out;
    bool valid = true;
    for (size_t i = 0; i < nfc.size(); ++i) {
        const char32_t c = char32_t(nfc[i]);
        if (c >= 0xD800 && c <= 0xDBFF && i + 1 < nfc.size() && nfc[i + 1] >= 0xDC00 && nfc[i + 1] <= 0xDFFF) {
            out.push_back(0x10000 + ((c - 0xD800) << 10) + (char32_t(nfc[i + 1]) - 0xDC00));
            ++i;
        } else if (c >= 0xD800 && c <= 0xDFFF) {
            valid = false;
            break;
        } else {
            out.push_back(c);
        }
    }
    SecureZeroMemory(&nfc[0], nfc.size() * sizeof(wchar_t));
    if (!valid) {
        if (!out.empty()) SecureZeroMemory(&out[0], out.size() * sizeof(char32_t));
        return std::nullopt;
    }
    return out;
}

// ------------------------------------------------------------- registry

class Key {
public:
    Key() = default;
    ~Key() { close(); }
    Key(const Key&) = delete;
    Key& operator=(const Key&) = delete;

    HKEY get() const { return h_; }
    explicit operator bool() const { return h_ != nullptr; }
    LONG open(HKEY parent, const std::wstring& sub, REGSAM sam) {
        close();
        return RegOpenKeyExW(parent, sub.c_str(), 0, sam | kView, &h_);
    }
    LONG create(HKEY parent, const std::wstring& sub, REGSAM sam, SECURITY_ATTRIBUTES* sa = nullptr) {
        close();
        return RegCreateKeyExW(parent, sub.c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE, sam | kView, sa, &h_, nullptr);
    }
    void close() {
        if (h_) RegCloseKey(h_);
        h_ = nullptr;
    }

private:
    HKEY h_ = nullptr;
};

struct Raw {
    DWORD type = REG_NONE;
    Bytes data;
};

// ERROR_SUCCESS, ERROR_FILE_NOT_FOUND (no such value) or another error.
inline LONG queryValue(HKEY k, const wchar_t* name, Raw& out) {
    for (int attempt = 0; attempt < 4; ++attempt) {
        DWORD type = 0, size = 0;
        LONG r = RegQueryValueExW(k, name, nullptr, &type, nullptr, &size);
        if (r != ERROR_SUCCESS) return r;
        out.data.assign(size, 0);
        r = RegQueryValueExW(k, name, nullptr, &type, out.data.empty() ? nullptr : out.data.data(), &size);
        if (r == ERROR_MORE_DATA) continue;
        if (r != ERROR_SUCCESS) return r;
        out.data.resize(size);
        out.type = type;
        return ERROR_SUCCESS;
    }
    return ERROR_MORE_DATA;
}

inline std::wstring wideOf(const Bytes& b) {
    std::wstring w(b.size() / 2, L'\0');
    if (!w.empty()) std::memcpy(&w[0], b.data(), w.size() * 2);
    return w;
}
inline std::optional<std::string> asString(const Raw& r) {
    if (r.type != REG_SZ || r.data.size() % 2) return std::nullopt;
    std::wstring w = wideOf(r.data);
    while (!w.empty() && w.back() == L'\0') w.pop_back();
    if (w.find(L'\0') != std::wstring::npos) return std::nullopt;
    return narrow(w);
}
inline std::optional<std::vector<std::string>> asMulti(const Raw& r) {
    if (r.type != REG_MULTI_SZ || r.data.size() % 2) return std::nullopt;
    const std::wstring w = wideOf(r.data);
    std::vector<std::string> out;
    std::wstring cur;
    for (wchar_t c : w) {
        if (c == L'\0') {
            if (!cur.empty()) out.push_back(narrow(cur));
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) out.push_back(narrow(cur));
    return out;
}
inline std::optional<uint64_t> asQword(const Raw& r) {
    if (r.type != REG_QWORD || r.data.size() != 8) return std::nullopt;
    uint64_t v = 0;
    std::memcpy(&v, r.data.data(), 8);
    return v;
}
inline std::optional<uint32_t> asDword(const Raw& r) {
    if (r.type != REG_DWORD || r.data.size() != 4) return std::nullopt;
    uint32_t v = 0;
    std::memcpy(&v, r.data.data(), 4);
    return v;
}

inline LONG setString(HKEY k, const wchar_t* name, const std::string& v) {
    const std::wstring w = widen(v);
    return RegSetValueExW(k, name, 0, REG_SZ, reinterpret_cast<const BYTE*>(w.c_str()), DWORD((w.size() + 1) * 2));
}
inline LONG setMulti(HKEY k, const wchar_t* name, const std::vector<std::string>& v) {
    std::wstring b;
    for (const auto& s : v) {
        b += widen(s);
        b.push_back(L'\0');
    }
    b.push_back(L'\0');
    return RegSetValueExW(k, name, 0, REG_MULTI_SZ, reinterpret_cast<const BYTE*>(b.data()), DWORD(b.size() * 2));
}
inline LONG setDword(HKEY k, const wchar_t* name, uint32_t v) {
    return RegSetValueExW(k, name, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&v), 4);
}
inline LONG setQword(HKEY k, const wchar_t* name, uint64_t v) {
    return RegSetValueExW(k, name, 0, REG_QWORD, reinterpret_cast<const BYTE*>(&v), 8);
}
inline LONG setBinary(HKEY k, const wchar_t* name, const Bytes& v) {
    return RegSetValueExW(k, name, 0, REG_BINARY, v.empty() ? nullptr : v.data(), DWORD(v.size()));
}
inline LONG deleteValue(HKEY k, const wchar_t* name) {
    const LONG r = RegDeleteValueW(k, name);
    return r == ERROR_FILE_NOT_FOUND ? ERROR_SUCCESS : r;
}

// Serial + 1, the last write of a change (the stamp moves after the values).
inline LONG bumpSerial(HKEY k) {
    Raw r;
    uint64_t v = 0;
    if (queryValue(k, L"Serial", r) == ERROR_SUCCESS) v = asQword(r).value_or(0);
    return setQword(k, L"Serial", v + 1);
}

// {exists, last write time, Serial} of one key; nullopt when it could not
// be taken.
inline std::optional<StoreStamp> keyStamp(HKEY hive, const std::wstring& path) {
    Key k;
    const LONG r = k.open(hive, path, KEY_QUERY_VALUE);
    if (r == ERROR_FILE_NOT_FOUND) return StoreStamp{};
    if (r != ERROR_SUCCESS) return std::nullopt;
    FILETIME ft{};
    if (RegQueryInfoKeyW(k.get(), nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                         nullptr, &ft) != ERROR_SUCCESS)
        return std::nullopt;
    StoreStamp s;
    s.exists = true;
    s.a = (uint64_t(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    Raw raw;
    if (queryValue(k.get(), L"Serial", raw) == ERROR_SUCCESS) s.b = asQword(raw).value_or(0);
    return s;
}

inline std::wstring sub(const Location& loc, const wchar_t* name) { return loc.path + L"\\" + name; }

// ------------------------------------------------------------- the lock

class ConfigLock {
public:
    ConfigLock(const Location& loc, DWORD waitMs = kLockWaitMs) {
        PSECURITY_DESCRIPTOR sd = nullptr;
        SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, FALSE};
        if (loc.protect) {
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(kMutexSddl, SDDL_REVISION_1, &sd, nullptr)) return;
            sa.lpSecurityDescriptor = sd;
        }
        h_ = CreateMutexW(loc.protect ? &sa : nullptr, FALSE, loc.mutexName.c_str());
        if (sd) LocalFree(sd);
        if (!h_) return;
        const DWORD w = WaitForSingleObject(h_, waitMs);
        held_ = w == WAIT_OBJECT_0 || w == WAIT_ABANDONED;
    }
    ~ConfigLock() {
        if (held_) ReleaseMutex(h_);
        if (h_) CloseHandle(h_);
    }
    ConfigLock(const ConfigLock&) = delete;
    ConfigLock& operator=(const ConfigLock&) = delete;
    bool held() const { return held_; }

private:
    HANDLE h_ = nullptr;
    bool held_ = false;
};

// --------------------------------------------------------------- DPAPI

inline DATA_BLOB dpapiEntropy() {
    static const char kEntropy[] = "JerisLink host connection key v1";
    DATA_BLOB b{DWORD(sizeof(kEntropy) - 1), reinterpret_cast<BYTE*>(const_cast<char*>(kEntropy))};
    return b;
}
inline std::optional<Bytes> protect(const Bytes& plain) {
    DATA_BLOB in{DWORD(plain.size()), const_cast<BYTE*>(plain.data())};
    DATA_BLOB ent = dpapiEntropy();
    DATA_BLOB out{};
    if (!CryptProtectData(&in, L"JerisLink host key", &ent, nullptr, nullptr,
                          CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN, &out))
        return std::nullopt;
    Bytes b(out.pbData, out.pbData + out.cbData);
    LocalFree(out.pbData);
    return b;
}
inline std::optional<Bytes> unprotect(const Bytes& blob) {
    DATA_BLOB in{DWORD(blob.size()), const_cast<BYTE*>(blob.data())};
    DATA_BLOB ent = dpapiEntropy();
    DATA_BLOB out{};
    if (!CryptUnprotectData(&in, nullptr, &ent, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out))
        return std::nullopt;
    Bytes b(out.pbData, out.pbData + out.cbData);
    SecureZeroMemory(out.pbData, out.cbData);
    LocalFree(out.pbData);
    return b;
}

// ------------------------------------------------------------ reading

struct SecretRead {
    std::shared_ptr<const auth::AuthSecret> secret;  // nullptr: none (or problem)
    std::string problem;                             // non-empty: one exists but did not read
};

inline SecretRead readSecret(const Location& loc) {
    SecretRead out;
    Key k;
    LONG r = k.open(loc.hive, sub(loc, L"Secret"), KEY_QUERY_VALUE);
    if (r == ERROR_FILE_NOT_FOUND) return out;
    if (r != ERROR_SUCCESS) {
        out.problem = "secret_open_error_" + std::to_string(r);
        return out;
    }
    Raw raw;
    r = queryValue(k.get(), L"Key", raw);
    if (r == ERROR_FILE_NOT_FOUND) return out;
    if (r != ERROR_SUCCESS || raw.type != REG_BINARY) {
        out.problem = "secret_unreadable";
        return out;
    }
    auto plain = unprotect(raw.data);
    if (!plain) {
        out.problem = "secret_unprotect_failed_" + std::to_string(GetLastError());
        return out;
    }
    out.secret = settings::decodeSecret(*plain);
    auth::wipe(plain->data(), plain->size());
    if (!out.secret) out.problem = "secret_malformed";
    return out;
}

struct Settings {
    bool exists = false;
    std::string listenMode = "tailnet";
    std::string bindIp;
    std::vector<std::string> whitelist;
    bool passwordSet = false;
    std::string theme = "green";
    std::string logPath;
    std::string whitelistProblem;  // AllowedIPs did not read, or holds a non-tailnet address
    std::string problem;           // the first other value that did not read
};

inline Settings readSettings(const Location& loc) {
    Settings s;
    Key k;
    const LONG r = k.open(loc.hive, loc.path, KEY_QUERY_VALUE);
    if (r == ERROR_FILE_NOT_FOUND) return s;
    if (r != ERROR_SUCCESS) {
        s.problem = s.whitelistProblem = "settings_open_error_" + std::to_string(r);
        return s;
    }
    s.exists = true;
    auto str = [&](const wchar_t* name, std::string& out) {
        Raw raw;
        const LONG q = queryValue(k.get(), name, raw);
        if (q == ERROR_FILE_NOT_FOUND) return;
        const auto v = q == ERROR_SUCCESS ? asString(raw) : std::nullopt;
        if (!v) {
            if (s.problem.empty()) s.problem = narrow(name) + "_unreadable";
            return;
        }
        out = *v;
    };
    str(L"ListenMode", s.listenMode);
    str(L"BindIP", s.bindIp);
    str(L"Theme", s.theme);
    str(L"LogPath", s.logPath);
    {
        Raw raw;
        const LONG q = queryValue(k.get(), L"AllowedIPs", raw);
        if (q != ERROR_FILE_NOT_FOUND) {
            const auto v = q == ERROR_SUCCESS ? asMulti(raw) : std::nullopt;
            if (!v) {
                s.whitelistProblem = "AllowedIPs_unreadable";
            } else {
                for (const auto& ip : *v) {
                    if (!auth::isTailnetIpv4(ip)) {
                        s.whitelistProblem = "AllowedIPs_not_tailnet";
                        break;
                    }
                    if (std::find(s.whitelist.begin(), s.whitelist.end(), ip) == s.whitelist.end())
                        s.whitelist.push_back(ip);
                }
                if (!s.whitelistProblem.empty()) s.whitelist.clear();
            }
        }
    }
    {
        Raw raw;
        if (queryValue(k.get(), L"PasswordSet", raw) == ERROR_SUCCESS) s.passwordSet = asDword(raw).value_or(0) == 1;
    }
    return s;
}

// ------------------------------------------------------------- the stores

// BlockedIPs. A bare address is taken as a manual block (typed in
// regedit); a row that is neither is skipped.
inline std::optional<std::vector<BlockedEntry>> readBlocked(HKEY k) {
    Raw raw;
    const LONG q = queryValue(k, L"BlockedIPs", raw);
    if (q == ERROR_FILE_NOT_FOUND) return std::vector<BlockedEntry>{};
    if (q != ERROR_SUCCESS) return std::nullopt;
    const auto rows = asMulti(raw);
    if (!rows) return std::nullopt;
    std::vector<BlockedEntry> out;
    for (const auto& row : *rows) {
        std::optional<BlockedEntry> e = settings::parseBlocked(row);
        if (!e && auth::isIpv4(row)) e = BlockedEntry{row, 0, "manual"};
        if (e && std::none_of(out.begin(), out.end(), [&](const BlockedEntry& x) { return x.ip == e->ip; }))
            out.push_back(*e);
    }
    return out;
}

class RegistryBlocklist : public auth::BlocklistStore {
public:
    explicit RegistryBlocklist(Location loc) : loc_(std::move(loc)) {}

    std::optional<std::vector<BlockedEntry>> load() override {
        Key k;
        const LONG r = k.open(loc_.hive, loc_.path, KEY_QUERY_VALUE);
        if (r == ERROR_FILE_NOT_FOUND) return std::vector<BlockedEntry>{};
        if (r != ERROR_SUCCESS) return std::nullopt;
        return readBlocked(k.get());
    }
    std::optional<std::vector<BlockedEntry>> update(const std::vector<BlockedEntry>& adding,
                                                    const std::set<std::string>& removing) override {
        ConfigLock lock(loc_);
        if (!lock.held()) return std::nullopt;
        Key k;
        if (k.create(loc_.hive, loc_.path, KEY_QUERY_VALUE | KEY_SET_VALUE) != ERROR_SUCCESS) return std::nullopt;
        const auto current = readBlocked(k.get());
        if (!current) return std::nullopt;
        const auto merged = auth::mergedBlocklist(*current, adding, removing);
        std::vector<std::string> rows;
        for (const auto& e : merged) rows.push_back(settings::formatBlocked(e));
        if (setMulti(k.get(), L"BlockedIPs", rows) != ERROR_SUCCESS) return std::nullopt;
        if (bumpSerial(k.get()) != ERROR_SUCCESS) return std::nullopt;
        return merged;
    }
    std::optional<StoreStamp> probeStamp() override { return keyStamp(loc_.hive, loc_.path); }

private:
    Location loc_;
};

// Journal\PendingBlocks. A row that does not read makes the whole journal
// unreadable (the guard then admits nobody: fail closed).
class RegistryPendingBlocks : public auth::PendingBlockStore {
public:
    explicit RegistryPendingBlocks(Location loc) : loc_(std::move(loc)) {}

    std::optional<std::vector<BlockedEntry>> load() override {
        Key k;
        const LONG r = k.open(loc_.hive, sub(loc_, L"Journal"), KEY_QUERY_VALUE);
        if (r == ERROR_FILE_NOT_FOUND) return std::vector<BlockedEntry>{};
        if (r != ERROR_SUCCESS) return std::nullopt;
        Raw raw;
        const LONG q = queryValue(k.get(), L"PendingBlocks", raw);
        if (q == ERROR_FILE_NOT_FOUND) return std::vector<BlockedEntry>{};
        if (q != ERROR_SUCCESS) return std::nullopt;
        const auto rows = asMulti(raw);
        if (!rows) return std::nullopt;
        std::vector<BlockedEntry> out;
        for (const auto& row : *rows) {
            const auto e = settings::parseBlocked(row);
            if (!e) return std::nullopt;
            out.push_back(*e);
        }
        return out;
    }
    bool save(const std::vector<BlockedEntry>& entries) override {
        Key k;
        if (k.create(loc_.hive, sub(loc_, L"Journal"), KEY_QUERY_VALUE | KEY_SET_VALUE) != ERROR_SUCCESS) return false;
        LONG r;
        if (entries.empty()) {
            r = deleteValue(k.get(), L"PendingBlocks");
        } else {
            std::vector<std::string> rows;
            for (const auto& e : entries) rows.push_back(settings::formatBlocked(e));
            r = setMulti(k.get(), L"PendingBlocks", rows);
        }
        return r == ERROR_SUCCESS && bumpSerial(k.get()) == ERROR_SUCCESS;
    }
    std::optional<StoreStamp> probeStamp() override { return keyStamp(loc_.hive, sub(loc_, L"Journal")); }

private:
    Location loc_;
};

class RegistryFailureLog : public auth::FailureLogStore {
public:
    explicit RegistryFailureLog(Location loc) : loc_(std::move(loc)) {}

    std::vector<FailureRecord> loadRecords() override {
        std::vector<FailureRecord> out;
        Key k;
        if (k.open(loc_.hive, sub(loc_, L"Failures"), KEY_QUERY_VALUE) != ERROR_SUCCESS) return out;
        Raw raw;
        if (queryValue(k.get(), L"Records", raw) != ERROR_SUCCESS) return out;
        for (const auto& row : asMulti(raw).value_or(std::vector<std::string>{}))
            if (const auto r = settings::parseRecord(row)) out.push_back(*r);
        return out;
    }
    std::vector<int64_t> loadTimes() override {
        Key k;
        if (k.open(loc_.hive, sub(loc_, L"Failures"), KEY_QUERY_VALUE) != ERROR_SUCCESS) return {};
        Raw raw;
        if (queryValue(k.get(), L"Times", raw) != ERROR_SUCCESS || raw.type != REG_BINARY) return {};
        return settings::decodeTimes(raw.data);
    }
    void save(const std::vector<FailureRecord>& records, const std::vector<int64_t>& times) override {
        Key k;
        if (k.create(loc_.hive, sub(loc_, L"Failures"), KEY_QUERY_VALUE | KEY_SET_VALUE) != ERROR_SUCCESS) return;
        std::vector<std::string> rows;
        for (const auto& r : records) rows.push_back(settings::formatRecord(r));
        setMulti(k.get(), L"Records", rows);
        setBinary(k.get(), L"Times", settings::encodeTimes(times));
    }

private:
    Location loc_;
};

// The password and the whitelist, for PolicyHolder.
class RegistryPolicySource : public settings::PolicySource {
public:
    explicit RegistryPolicySource(Location loc) : loc_(std::move(loc)) {}

    std::optional<settings::PolicyStamp> probe() override {
        const auto a = keyStamp(loc_.hive, loc_.path);
        const auto b = keyStamp(loc_.hive, sub(loc_, L"Secret"));
        if (!a || !b) return std::nullopt;
        return settings::PolicyStamp{*a, *b};
    }
    settings::PolicyValues load() override {
        settings::PolicyValues v;
        const Settings s = readSettings(loc_);
        const SecretRead sec = readSecret(loc_);
        v.whitelist = s.whitelist;
        v.secret = sec.secret;
        v.problem = !s.whitelistProblem.empty() ? s.whitelistProblem : sec.problem;
        return v;
    }

private:
    Location loc_;
};

// ------------------------------------------------- the window's changes

// Secret, with its DACL put back every time (RegCreateKeyEx keeps the DACL
// of a key that already exists).
inline LONG openSecretForWrite(const Location& loc, Key& out) {
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (loc.protect && !ConvertStringSecurityDescriptorToSecurityDescriptorW(kSecretSddl, SDDL_REVISION_1, &sd, nullptr))
        return LONG(GetLastError());
    SECURITY_ATTRIBUTES sa{sizeof(sa), sd, FALSE};
    LONG r = out.create(loc.hive, sub(loc, L"Secret"), KEY_QUERY_VALUE | KEY_SET_VALUE | WRITE_DAC | READ_CONTROL,
                        loc.protect ? &sa : nullptr);
    if (r == ERROR_SUCCESS && loc.protect)
        r = RegSetKeySecurity(out.get(), DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, sd);
    if (sd) LocalFree(sd);
    return r;
}

// Secret's DACL as SDDL (for the checks).
inline std::wstring secretDacl(const Location& loc) {
    Key k;
    if (k.open(loc.hive, sub(loc, L"Secret"), READ_CONTROL) != ERROR_SUCCESS) return L"";
    DWORD size = 0;
    RegGetKeySecurity(k.get(), DACL_SECURITY_INFORMATION, nullptr, &size);
    std::vector<uint8_t> buf(size ? size : 1);
    if (RegGetKeySecurity(k.get(), DACL_SECURITY_INFORMATION, buf.data(), &size) != ERROR_SUCCESS) return L"";
    LPWSTR s = nullptr;
    if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(buf.data(), SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &s,
                                                              nullptr))
        return L"";
    std::wstring out = s;
    LocalFree(s);
    return out;
}

inline Outcome setPassword(const Location& loc, const std::wstring& password, const std::wstring& confirm) {
    auto nfc = nfcCodePoints(password);
    auto nfc2 = nfcCodePoints(confirm);
    if (!nfc || !nfc2) {
        for (auto* p : {&nfc, &nfc2})
            if (*p && !(*p)->empty()) SecureZeroMemory(&(**p)[0], (*p)->size() * sizeof(char32_t));
        return settings::refused("密碼有無效字元。");
    }
    const auto refusal = settings::passwordRefusal(*nfc == *nfc2, *nfc);
    for (auto* p : {&nfc, &nfc2})
        if (!(*p)->empty()) SecureZeroMemory(&(**p)[0], (*p)->size() * sizeof(char32_t));
    if (refusal) return *refusal;

    // PBKDF2 (about half a second) before the lock: it needs only the new salt.
    auth::AuthSecret s;
    s.iterations = auth::kIterations;
    if (!auth::win::random(s.salt.data(), s.salt.size())) return settings::refused("無法產生密碼金鑰。");
    auto k = auth::win::deriveKey(password, s.salt, s.iterations);
    if (!k) return settings::refused("無法產生密碼金鑰。");
    s.key = *k;
    auth::wipe(k->data(), k->size());

    ConfigLock lock(loc, 5000);
    if (!lock.held()) return settings::refused(settings::kBusy);
    // The host id stays across changes; the salt is new every time, so
    // every remembered viewer needs the new password.
    const SecretRead old = readSecret(loc);
    if (old.secret) s.hostId = old.secret->hostId;
    else if (!auth::win::random(s.hostId.data(), s.hostId.size())) return settings::refused("無法產生密碼金鑰。");
    Bytes plain = settings::encodeSecret(s);
    const auto blob = protect(plain);
    auth::wipe(plain.data(), plain.size());
    if (!blob) return settings::refused("無法加密密碼金鑰（DPAPI）。");
    Key main, secret;
    if (main.create(loc.hive, loc.path, KEY_QUERY_VALUE | KEY_SET_VALUE) != ERROR_SUCCESS ||
        openSecretForWrite(loc, secret) != ERROR_SUCCESS || setBinary(secret.get(), L"Key", *blob) != ERROR_SUCCESS ||
        setDword(main.get(), L"PasswordSet", 1) != ERROR_SUCCESS || bumpSerial(main.get()) != ERROR_SUCCESS)
        return settings::refused("寫入 registry 失敗，密碼可能未改。");
    return settings::passwordSaved(old.secret != nullptr);
}

inline Outcome saveWhitelist(const Location& loc, const std::string& text) {
    const auto parsed = settings::parseTailnetList(text);
    if (!parsed.invalid.empty()) return settings::refused(settings::kNotTailnet + settings::joined(parsed.invalid, ", "));
    ConfigLock lock(loc, 5000);
    if (!lock.held()) return settings::refused(settings::kBusy);
    Key k;
    if (k.create(loc.hive, loc.path, KEY_QUERY_VALUE | KEY_SET_VALUE) != ERROR_SUCCESS ||
        setMulti(k.get(), L"AllowedIPs", parsed.ips) != ERROR_SUCCESS || bumpSerial(k.get()) != ERROR_SUCCESS)
        return settings::refused("白名單儲存失敗。");
    return settings::whitelistSaved(parsed.ips.size());
}

inline bool blockedHas(const Location& loc, const std::string& ip) {
    const auto list = RegistryBlocklist(loc).load();
    return list && std::any_of(list->begin(), list->end(), [&](const BlockedEntry& e) { return e.ip == ip; });
}

// 人手加 IP 落黑名單: applies at once (the host's watcher closes its
// connections).
inline Outcome block(const Location& loc, const std::string& text, int64_t now) {
    const std::string ip = settings::trimmed(text);
    if (!auth::isTailnetIpv4(ip)) return settings::refused(settings::kNotTailnet + ip);
    if (blockedHas(loc, ip)) return settings::done(ip + " 已經喺黑名單。");
    if (!RegistryBlocklist(loc).update({BlockedEntry{ip, now, "manual"}}, {}))
        return settings::refused("黑名單儲存失敗。");
    return settings::done("已封鎖 " + ip + "。");
}

// 解除封鎖: any IPv4 (a row typed in regedit may be outside the tailnet).
inline Outcome unblock(const Location& loc, const std::string& ip) {
    if (!auth::isIpv4(ip)) return settings::refused("唔係 IPv4 地址：" + ip);
    if (!blockedHas(loc, ip)) return settings::done(ip + " 已經唔喺黑名單。");
    if (!RegistryBlocklist(loc).update({}, {ip})) return settings::refused("解除封鎖失敗。");
    return settings::done("已解除封鎖 " + ip + "。");
}

inline Outcome setTheme(const Location& loc, const std::string& theme) {
    if (theme != "green" && theme != "blue") return settings::refused("唔識呢個主題：" + theme);
    ConfigLock lock(loc, 5000);
    if (!lock.held()) return settings::refused(settings::kBusy);
    Key k;
    if (k.create(loc.hive, loc.path, KEY_QUERY_VALUE | KEY_SET_VALUE) != ERROR_SUCCESS ||
        setString(k.get(), L"Theme", theme) != ERROR_SUCCESS || bumpSerial(k.get()) != ERROR_SUCCESS)
        return settings::refused("主題儲存失敗。");
    return settings::done(theme == "blue" ? "主題已改為藍色。" : "主題已改為綠色。");
}

// ------------------------------------------------------------- the watch

// Calls `tick` when anything under the settings key changes, and once a
// second whatever happens (a key that does not exist yet, a missed
// notification). RegNotifyChangeKeyValue is armed on this thread.
class PolicyWatcher {
public:
    PolicyWatcher(Location loc, std::function<void()> tick) : loc_(std::move(loc)), tick_(std::move(tick)) {
        stop_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        changed_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        t_ = std::thread([this] { run(); });
    }
    ~PolicyWatcher() {
        SetEvent(stop_);
        if (t_.joinable()) t_.join();
        CloseHandle(stop_);
        CloseHandle(changed_);
    }
    PolicyWatcher(const PolicyWatcher&) = delete;
    PolicyWatcher& operator=(const PolicyWatcher&) = delete;

private:
    void run() {
        Key k;
        bool armed = false;
        for (;;) {
            if (!k && k.open(loc_.hive, loc_.path, KEY_NOTIFY) != ERROR_SUCCESS) k.close();
            if (k && !armed) {
                const DWORD filter = REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_SECURITY;
                if (RegNotifyChangeKeyValue(k.get(), TRUE, filter, changed_, TRUE) == ERROR_SUCCESS) armed = true;
                else k.close();  // deleted: open it again next time
            }
            HANDLE hs[2] = {stop_, changed_};
            const DWORD w = WaitForMultipleObjects(2, hs, FALSE, 1000);
            if (w == WAIT_OBJECT_0) return;
            if (w == WAIT_OBJECT_0 + 1) armed = false;
            if (tick_) tick_();
        }
    }

    Location loc_;
    std::function<void()> tick_;
    HANDLE stop_ = nullptr, changed_ = nullptr;
    std::thread t_;
};

// ------------------------------------------------------------ the process

inline bool isElevated() {
    HANDLE t = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) return false;
    TOKEN_ELEVATION e{};
    DWORD n = 0;
    const bool ok = GetTokenInformation(t, TokenElevation, &e, sizeof(e), &n) != FALSE;
    CloseHandle(t);
    return ok && e.TokenIsElevated != 0;
}

// This exe again with `args`, elevated (one UAC prompt). False: refused
// or failed.
inline bool relaunchElevated(const std::wstring& args) {
    std::wstring path(32768, L'\0');
    const DWORD n = GetModuleFileNameW(nullptr, &path[0], DWORD(path.size()));
    if (n == 0 || n >= path.size()) return false;
    path.resize(n);
    SHELLEXECUTEINFOW sei{};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOASYNC;
    sei.lpVerb = L"runas";
    sei.lpFile = path.c_str();
    sei.lpParameters = args.c_str();
    sei.nShow = SW_SHOWNORMAL;
    return ShellExecuteExW(&sei) != FALSE;
}

// IPv4 addresses on interfaces that are up.
inline std::vector<std::string> localIpv4() {
    std::vector<std::string> out;
    ULONG size = 16 * 1024;
    std::vector<uint8_t> buf;
    ULONG r = ERROR_BUFFER_OVERFLOW;
    for (int attempt = 0; attempt < 4 && r == ERROR_BUFFER_OVERFLOW; ++attempt) {
        buf.assign(size, 0);
        r = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                                 nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()), &size);
    }
    if (r != NO_ERROR) return out;
    for (auto* a = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()); a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp) continue;
        for (auto* u = a->FirstUnicastAddress; u; u = u->Next) {
            if (!u->Address.lpSockaddr || u->Address.lpSockaddr->sa_family != AF_INET) continue;
            char ip[INET_ADDRSTRLEN] = {};
            const auto* sin = reinterpret_cast<const sockaddr_in*>(u->Address.lpSockaddr);
            if (inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip))) out.push_back(ip);
        }
    }
    return out;
}

}  // namespace jlh::config
