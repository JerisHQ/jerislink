// Mac right-click "Send to JerisLink" (F5b): the Downloads\JerisLink writer.
// See file_push.hpp.
#include "file_push.hpp"

#include <windows.h>
#include <objbase.h>
#include <shellapi.h>
#include <shlobj.h>

#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>

namespace jl::filepush {

void (*gPublishHook)(HANDLE file, int stage) = nullptr;
void (*gTakeOutTrace)(const char* step, bool ok) = nullptr;
void (*gFinalHook)(const std::wstring& final, int stage) = nullptr;

namespace {

// #60 r6: reports a take-back or cleanup step's result to a test.
bool traced(const char* step, bool ok) {
    if (gTakeOutTrace) gTakeOutTrace(step, ok);
    return ok;
}

std::string toUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), int(w.size()), nullptr, 0, nullptr, nullptr);
    std::string s(size_t(n > 0 ? n : 0), '\0');
    if (n > 0) WideCharToMultiByte(CP_UTF8, 0, w.data(), int(w.size()), s.data(), n, nullptr, nullptr);
    return s;
}

std::wstring toWide(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), nullptr, 0);
    std::wstring w(size_t(n > 0 ? n : 0), L'\0');
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), w.data(), n);
    return w;
}

// Long-path form for file calls; the folder may be deep and names are up
// to 259 characters.
std::wstring longPath(const std::wstring& p) {
    if (p.rfind(L"\\\\?\\", 0) == 0) return p;
    if (p.rfind(L"\\\\", 0) == 0) return L"\\\\?\\UNC\\" + p.substr(2);
    return L"\\\\?\\" + p;
}

// #60 r7: gives the open file `h` the extra name `target` (a "\\?\" long
// path), never over an existing file: a hard link, made through the handle.
// Unlike a rename it needs no DELETE access, so the sink can hold the
// Zone.Identifier stream with delete sharing denied while it is done.
// Returns the NTSTATUS (0 = linked).
constexpr LONG kNameCollision = LONG(0xC0000035);   // STATUS_OBJECT_NAME_COLLISION
LONG linkTo(HANDLE h, const std::wstring& target) {
    using NtSetInformationFileFn = LONG(NTAPI*)(HANDLE, PVOID, PVOID, ULONG, ULONG);
    static const auto ntSet = reinterpret_cast<NtSetInformationFileFn>(
        reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationFile")));
    if (!ntSet || target.rfind(L"\\\\?\\", 0) != 0) return LONG(0xC0000001);   // STATUS_UNSUCCESSFUL
    const std::wstring nt = L"\\??\\" + target.substr(4);
    const size_t nameBytes = nt.size() * sizeof(wchar_t);
    // FILE_LINK_INFORMATION has the layout of FILE_RENAME_INFO.
    std::vector<uint8_t> buf(sizeof(FILE_RENAME_INFO) + nameBytes, 0);
    auto* info = reinterpret_cast<FILE_RENAME_INFO*>(buf.data());
    info->ReplaceIfExists = FALSE;
    info->RootDirectory = nullptr;
    info->FileNameLength = DWORD(nameBytes);
    std::memcpy(info->FileName, nt.data(), nameBytes);
    ULONG_PTR io[2] = {};
    return ntSet(h, io, info, ULONG(buf.size()), 11 /* FileLinkInformation */);
}

// Marks the open file `h` for deletion (it goes when the last handle closes).
bool deleteOn(HANDLE h) {
    FILE_DISPOSITION_INFO del{};
    del.DeleteFile = TRUE;
    return SetFileInformationByHandle(h, FileDispositionInfo, &del, sizeof(del)) != 0;
}

// #60 r4: deletes the open file `h` now, also when it is read-only and
// while others hold it open (POSIX semantics: the name goes at once).
// FileDispositionInfoEx (21) and its flags, declared here for older SDKs.
bool deleteNowOn(HANDLE h) {
    struct {
        ULONG Flags;
    } del{0x1 /* DELETE */ | 0x2 /* POSIX_SEMANTICS */ | 0x10 /* IGNORE_READONLY_ATTRIBUTE */};
    return SetFileInformationByHandle(h, FILE_INFO_BY_HANDLE_CLASS(21), &del, sizeof(del)) != 0;
}

// #60 r4: cuts the open file `h` to zero bytes.
bool emptyOn(HANDLE h) {
    FILE_END_OF_FILE_INFO end{};
    return SetFileInformationByHandle(h, FileEndOfFileInfo, &end, sizeof(end)) != 0;
}

// #60 r5: overwrites every byte of the open file `h` with zeros, for a file
// that can be neither deleted nor cut (another program has it mapped).
bool zeroOn(HANDLE h) {
    LARGE_INTEGER size{};
    LARGE_INTEGER zero{};
    if (!GetFileSizeEx(h, &size) || !SetFilePointerEx(h, zero, nullptr, FILE_BEGIN)) return false;
    static const std::vector<uint8_t> zeros(1u << 16, 0);
    uint64_t left = uint64_t(size.QuadPart);
    while (left > 0) {
        const DWORD n = DWORD(std::min<uint64_t>(left, zeros.size()));
        DWORD wrote = 0;
        if (!WriteFile(h, zeros.data(), n, &wrote, nullptr) || wrote != n) return false;
        left -= n;
    }
    return FlushFileBuffers(h) != 0;
}

// #60 r6: the ZoneId in the Zone.Identifier stream open as `z`, read
// through that handle from its start; -1 when it cannot be read.
int zoneIdFrom(HANDLE z) {
    char buf[1024] = {};
    DWORD got = 0;
    OVERLAPPED at{};
    if (!ReadFile(z, buf, sizeof(buf) - 1, &got, &at)) return -1;
    const char* id = std::strstr(buf, "ZoneId=");
    return id ? std::atoi(id + 7) : -1;
}

// #60 r7: removes the name `path` if it still names the file `id`. The
// name is opened without following a link and its file id checked, so a
// file someone else put under the name is never touched. True when the name
// is gone or no longer ours; false when it is ours and could not be removed
// now (someone holds the file without delete sharing, or it is mapped as an
// image).
bool unlinkName(const std::wstring& path, const FILE_ID_INFO& id) {
    HANDLE h = CreateFileW(longPath(path).c_str(), DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                           FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        const DWORD e = GetLastError();
        return e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND;
    }
    FILE_ID_INFO got{};
    if (!filepull::fileIdOf(h, got) || !filepull::sameFile(got, id)) {
        CloseHandle(h);
        return true;
    }
    const bool ok = deleteNowOn(h) || deleteOn(h);
    CloseHandle(h);
    return ok;
}

// #60 r5/r7: true once the open file `h` holds no bytes of what was received:
// cut to zero, else every byte overwritten with zeros. Results checked.
bool blankOn(HANDLE h, const char* cut, const char* zero) {
    return traced(cut, emptyOn(h)) || traced(zero, zeroOn(h));
}

class FolderSink : public Sink {
public:
    FolderSink(std::wstring folder, std::function<void(const std::wstring&)> open, filepull::ZoneOps zone)
        : folder_(std::move(folder)), staging_(folder_ + L"\\.jlstaging"), open_(std::move(open)), ops_(zone) {}
    ~FolderSink() override {
        abort();
        // #53 r2: a file that failed its check, or a .jlpart, that could not
        // be removed at once: retried for about a second more before the sink goes.
        for (int i = 0; i < 20 && !retryCleanup(); ++i) Sleep(50);
        for (const Held& h : held_) {
            if (h.zone != INVALID_HANDLE_VALUE) CloseHandle(h.zone);
            CloseHandle(h.file);
        }
    }

    bool prepare() override {
        if (folder_.empty()) return false;
        // The folder and its parents (Downloads normally exists already).
        const int rc = SHCreateDirectoryExW(nullptr, folder_.c_str(), nullptr);
        if (rc != ERROR_SUCCESS && rc != ERROR_ALREADY_EXISTS && rc != ERROR_FILE_EXISTS) return false;
        if (!plainFolder(folder_)) return false;
        // #60 r3: partial files live in a hidden folder inside it, so nothing
        // unverified ever sits in Downloads\JerisLink itself.
        if (!CreateDirectoryW(longPath(staging_).c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) return false;
        if (!plainFolder(staging_)) return false;
        const DWORD a = GetFileAttributesW(longPath(staging_).c_str());
        if (!(a & FILE_ATTRIBUTE_HIDDEN)) SetFileAttributesW(longPath(staging_).c_str(), a | FILE_ATTRIBUTE_HIDDEN);
        return true;
    }

    bool begin(const std::wstring& name) override {
        abort();
        retryCleanup();
        name_ = name;
        for (int n = 1; n < 1000; ++n) {
            const std::wstring part = staging_ + L"\\" + name + (n == 1 ? L"" : L"." + std::to_wstring(n)) + L".jlpart";
            // #60 r7: no DELETE access and no delete sharing. Nobody can
            // delete or rename the file while it is open, and the sink can
            // hold its Zone.Identifier stream with delete sharing denied
            // (NTFS refuses that next to an open of the file with DELETE).
            HANDLE h = CreateFileW(longPath(part).c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                                   CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
            if (h != INVALID_HANDLE_VALUE) {
                file_ = h;
                part_ = part;
                written_ = 0;
                // Mark of the Web goes on the partial file first: the final
                // name is a link to this same file, so it never has that
                // name without it. commit() checks.
                ops_.writeOn(file_);
                return true;
            }
            if (GetLastError() != ERROR_FILE_EXISTS && GetLastError() != ERROR_ALREADY_EXISTS) return false;
        }
        return false;
    }

    bool write(const uint8_t* data, size_t size) override {
        if (file_ == INVALID_HANDLE_VALUE) return false;
        while (size > 0) {
            DWORD wrote = 0;
            const DWORD chunk = DWORD(std::min<size_t>(size, 1u << 20));
            if (!WriteFile(file_, data, chunk, &wrote, nullptr) || wrote == 0) return false;
            data += wrote;
            size -= wrote;
            written_ += wrote;
        }
        return true;
    }

    bool commit() override {
        zoneRefused_ = false;
        retryCleanup();
        if (file_ == INVALID_HANDLE_VALUE) return false;
        // In staging: every byte on disk, exactly as many as were written.
        LARGE_INTEGER size{};
        if (!FlushFileBuffers(file_) || !GetFileSizeEx(file_, &size) || uint64_t(size.QuadPart) != written_) {
            return dropPart();
        }
        // #53: no file reaches the folder without ZoneId=3. On a volume
        // without streams (FAT, exFAT) the mark cannot be written, and the
        // file is dropped, not delivered.
        if (!ensureZone(file_)) {
            ++zone_.failed;
            zoneRefused_ = true;
            return dropPart();
        }
        // #60 r6/r7: the mark is held, not just seen. The Zone.Identifier
        // stream is opened with read sharing only (no write, no delete) and
        // ZoneId=3 is read through that handle; it stays open while the file
        // gets its final name and through the check there, so nobody can
        // change or remove the mark in between. If the stream cannot be held
        // with ZoneId=3, the file is not published.
        HANDLE zone = lockZone();
        if (zone == INVALID_HANDLE_VALUE) {
            ++zone_.failed;
            zoneRefused_ = true;
            return dropPart();
        }
        FILE_ID_INFO id{};
        if (!filepull::fileIdOf(file_, id)) {
            CloseHandle(zone);
            return dropPart();
        }
        // The final name is a hard link made through the handle, no
        // overwrite: an existing name moves on to "name (2).ext" ...
        const std::string utf8 = toUtf8(name_);
        if (gPublishHook) gPublishHook(file_, 0);
        for (int n = 1; n < 1000; ++n) {
            const std::wstring leaf = n == 1 ? name_ : toWide(file::path::clashName(utf8, n));
            const std::wstring final = folder_ + L"\\" + leaf;
            const LONG st = linkTo(file_, longPath(final));
            if (st >= 0) {
                if (gPublishHook) gPublishHook(file_, 1);
                if (gFinalHook) gFinalHook(final, 1);
                // Checked again through the held handle and as the file is
                // seen under its final name (opened there, its file id
                // checked). Nothing can change or remove the mark while it is
                // held, so a failure here means the read failed or the name
                // no longer leads to this file; then the file is taken back
                // (takeOut()).
                const bool held = zoneIdFrom(zone) == 3 && readUnder(final, id) == 3;
                if (!held) {
                    ++zone_.failed;
                    zoneRefused_ = true;
                    takeOut(zone, final, id);
                    return false;
                }
                ++zone_.marked;
                CloseHandle(zone);
                CloseHandle(file_);
                file_ = INVALID_HANDLE_VALUE;
                // The staging name goes; if it cannot go now it is kept,
                // with its file id, and retried. It is the delivered file.
                if (!unlinkName(part_, id)) names_.push_back({part_, id});
                part_.clear();
                if (gFinalHook) gFinalHook(final, 2);
                return true;
            }
            if (st != kNameCollision) break;
        }
        CloseHandle(zone);
        return dropPart();
    }

    void abort() override {
        dropPart();
        retryCleanup();
    }

    void finished(uint32_t) override {
        retryCleanup();
        if (open_) open_(folder_);
    }

    ZoneCounts zoneCounts() const override { return zone_; }
    bool zoneRefused() const override { return zoneRefused_; }

private:
    // #60 r7: a file whose bytes could not be removed yet: its handle, the
    // held Zone.Identifier stream (if it was published), and its names.
    struct Held {
        HANDLE file;
        HANDLE zone;
        std::wstring final;   // empty while it never had one
        std::wstring part;
        FILE_ID_INFO id;
    };

    static bool plainFolder(const std::wstring& path) {
        const DWORD a = GetFileAttributesW(longPath(path).c_str());
        return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY) && !(a & FILE_ATTRIBUTE_REPARSE_POINT);
    }

    // True when the open file carries ZoneId=3 (Q1). Normally it is there
    // already; otherwise write it, retrying for about a second while
    // something (Defender scanning a new .exe) holds the stream.
    bool ensureZone(HANDLE h) {
        for (int i = 0; i < 20; ++i) {
            if (ops_.readOn(h) == 3) return true;
            if (ops_.writeOn(h) == filepull::ZoneWrite::Written) continue;
            Sleep(50);
        }
        return false;
    }

    // #60 r7: the ZoneId of the file `id` as opened under `path`; -1 when
    // the name cannot be opened, leads to another file, or reads unmarked.
    int readUnder(const std::wstring& path, const FILE_ID_INFO& id) {
        HANDLE h = CreateFileW(longPath(path).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                               OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (h == INVALID_HANDLE_VALUE) return -1;
        FILE_ID_INFO got{};
        const int zone = filepull::fileIdOf(h, got) && filepull::sameFile(got, id) ? ops_.readOn(h) : -1;
        CloseHandle(h);
        return zone;
    }

    // #60 r6/r7: the staged file's Zone.Identifier stream, open for reading
    // with only readers shared (writers and deleters kept out), once ZoneId=3
    // has been read through it. A writer that changed the mark first is
    // undone by ensureZone() and tried again for about half a second.
    // INVALID_HANDLE_VALUE: the mark cannot be held valid.
    HANDLE lockZone() {
        for (int i = 0; i < 10; ++i) {
            if (i > 0 && !ensureZone(file_)) break;
            HANDLE z = filepull::openZoneStreamOn(file_, GENERIC_READ, FILE_SHARE_READ);
            if (z != INVALID_HANDLE_VALUE) {
                if (zoneIdFrom(z) == 3) return z;
                CloseHandle(z);
            }
            Sleep(50);
        }
        return INVALID_HANDLE_VALUE;
    }

    // #60 r7: takes a file that failed its last check back out of the folder.
    // Its bytes go first, through the handle, while the mark is still held:
    // cut, else zeroed. Then the handles are closed and its final and
    // staging names removed (each kept and retried if it cannot go now).
    // If neither cut nor zero works, both handles are kept: the file stays
    // under its final name with the mark still held (nobody can change or
    // remove it, nor write or delete the file), and retryCleanup() tries
    // again while the sink lives.
    void takeOut(HANDLE zone, const std::wstring& final, const FILE_ID_INFO& id) {
        if (!blankOn(file_, "cut", "zero")) {
            held_.push_back({file_, zone, final, part_, id});
        } else {
            CloseHandle(zone);
            CloseHandle(file_);
            forget(final, part_, id, "unlink");
        }
        file_ = INVALID_HANDLE_VALUE;
        part_.clear();
        written_ = 0;
    }

    // #60 r7: removes a closed file's names, keeping each that cannot go now.
    void forget(const std::wstring& final, const std::wstring& part, const FILE_ID_INFO& id, const char* step) {
        if (!final.empty() && !traced(step, unlinkName(final, id))) names_.push_back({final, id});
        if (!part.empty() && !unlinkName(part, id)) names_.push_back({part, id});
    }

    // The partial file, never published: its bytes are cut (else zeroed)
    // through the handle (#60 r4/r5), then the handle is closed and its
    // staging name removed by name and file id (#60 r7: the handle has no
    // DELETE access). A name that cannot go now is kept and retried (#53 r2,
    // #60 r3: never just forgotten). If neither cut nor zero works, the
    // handle is kept (nobody else can write, delete or rename the file
    // meanwhile) and retryCleanup() tries again through it.
    bool dropPart() {
        if (file_ != INVALID_HANDLE_VALUE) {
            FILE_ID_INFO id{};
            const bool known = filepull::fileIdOf(file_, id);
            if (blankOn(file_, "drop.cut", "drop.zero")) {
                CloseHandle(file_);
                if (known) forget({}, part_, id, "drop.unlink");
            } else {
                held_.push_back({file_, INVALID_HANDLE_VALUE, {}, part_, id});
            }
            file_ = INVALID_HANDLE_VALUE;
        }
        part_.clear();
        written_ = 0;
        return false;
    }

    // True once nothing is left to clean up.
    bool retryCleanup() {
        for (auto it = held_.begin(); it != held_.end();) {
            if (!blankOn(it->file, "drop.cut", "drop.zero")) {
                ++it;
                continue;
            }
            if (it->zone != INVALID_HANDLE_VALUE) CloseHandle(it->zone);
            CloseHandle(it->file);
            forget(it->final, it->part, it->id, "drop.unlink");
            it = held_.erase(it);
        }
        for (auto it = names_.begin(); it != names_.end();) {
            if (unlinkName(it->first, it->second)) it = names_.erase(it);
            else ++it;
        }
        return names_.empty() && held_.empty();
    }

    std::wstring folder_;
    std::wstring staging_;   // folder_\.jlstaging (hidden)
    std::function<void(const std::wstring&)> open_;
    filepull::ZoneOps ops_;
    std::wstring name_;
    std::wstring part_;
    uint64_t written_ = 0;
    std::vector<std::pair<std::wstring, FILE_ID_INFO>> names_;   // #60 r7: names still to remove, with their file id
    std::vector<Held> held_;                                     // #60 r5/r7: files whose bytes could not be removed yet
    HANDLE file_ = INVALID_HANDLE_VALUE;
    ZoneCounts zone_;
    bool zoneRefused_ = false;
};

}  // namespace

std::unique_ptr<Sink> makeFolderSink(std::wstring folder, std::function<void(const std::wstring&)> open,
                                     filepull::ZoneOps zone) {
    return std::make_unique<FolderSink>(std::move(folder), std::move(open), zone);
}

std::wstring downloadsFolder() {
    PWSTR dir = nullptr;
    std::wstring out;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Downloads, 0, nullptr, &dir)) && dir) {
        out = std::wstring(dir) + L"\\JerisLink";
    }
    CoTaskMemFree(dir);
    return out;
}

void openInExplorer(const std::wstring& folder) {
    // Its own short STA thread: the session thread has no COM and must not
    // wait for the shell.
    std::thread([folder] {
        const HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
        ShellExecuteW(nullptr, L"open", folder.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        if (SUCCEEDED(hr)) CoUninitialize();
    }).detach();
}

}  // namespace jl::filepush
