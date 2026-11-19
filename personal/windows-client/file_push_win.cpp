// Mac right-click "Send to JerisLink" (F5b): the Downloads\JerisLink writer.
// See file_push.hpp.
#include "file_push.hpp"

#include <windows.h>
#include <objbase.h>
#include <shellapi.h>
#include <shlobj.h>

#include <cstring>
#include <thread>
#include <vector>

namespace jl::filepush {

void (*gPublishHook)(HANDLE file, int stage) = nullptr;
void (*gTakeOutTrace)(const char* step, bool ok) = nullptr;

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

// Renames the open file `h` to `target` (a full long path), never over an
// existing file. The handle keeps pointing at the same file afterwards.
bool renameTo(HANDLE h, const std::wstring& target) {
    const size_t nameBytes = target.size() * sizeof(wchar_t);
    std::vector<uint8_t> buf(sizeof(FILE_RENAME_INFO) + nameBytes, 0);
    auto* info = reinterpret_cast<FILE_RENAME_INFO*>(buf.data());
    info->ReplaceIfExists = FALSE;
    info->RootDirectory = nullptr;
    info->FileNameLength = DWORD(nameBytes);
    std::memcpy(info->FileName, target.data(), nameBytes);
    return SetFileInformationByHandle(h, FileRenameInfo, info, DWORD(buf.size())) != 0;
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

// #60 r5: true once the open file `h` is gone, or holds no bytes of what was
// received. Each step's result is checked; none is assumed.
bool removeOrBlank(HANDLE h, bool& gone) {
    gone = traced("drop.delete", deleteNowOn(h) || deleteOn(h));
    return gone || traced("drop.cut", emptyOn(h)) || traced("drop.zero", zeroOn(h));
}

class FolderSink : public Sink {
public:
    FolderSink(std::wstring folder, std::function<void(const std::wstring&)> open, filepull::ZoneOps zone)
        : folder_(std::move(folder)), staging_(folder_ + L"\\.jlstaging"), open_(std::move(open)), ops_(zone) {}
    ~FolderSink() override {
        abort();
        // #53 r2: a file that failed its check, or a .jlpart, that could not
        // be deleted at once: retried for about a second more before the sink goes.
        for (int i = 0; i < 20 && !retryCleanup(); ++i) Sleep(50);
        for (HANDLE h : held_) CloseHandle(h);
        if (dir_ != INVALID_HANDLE_VALUE) CloseHandle(dir_);
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
        // Any handle on the volume, for cleanups by file id.
        if (dir_ == INVALID_HANDLE_VALUE) {
            dir_ = CreateFileW(longPath(folder_).c_str(), FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                               FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        }
        return dir_ != INVALID_HANDLE_VALUE;
    }

    bool begin(const std::wstring& name) override {
        abort();
        retryCleanup();
        name_ = name;
        for (int n = 1; n < 1000; ++n) {
            const std::wstring part = staging_ + L"\\" + name + (n == 1 ? L"" : L"." + std::to_wstring(n)) + L".jlpart";
            // Delete access: a rename or delete later goes through this
            // handle, to this file, never to whatever has its name then.
            HANDLE h = CreateFileW(longPath(part).c_str(), GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ,
                                   nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
            if (h != INVALID_HANDLE_VALUE) {
                file_ = h;
                part_ = part;
                written_ = 0;
                // Mark of the Web goes on the partial file first: the stream
                // moves with the rename, so the file never has its final name
                // without it. commit() checks.
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
        // Moved by handle, no overwrite: an existing name moves on to
        // "name (2).ext" ...
        const std::string utf8 = toUtf8(name_);
        if (gPublishHook) gPublishHook(file_, 0);
        for (int n = 1; n < 1000; ++n) {
            const std::wstring leaf = n == 1 ? name_ : toWide(file::path::clashName(utf8, n));
            if (renameTo(file_, longPath(folder_ + L"\\" + leaf))) {
                if (gPublishHook) gPublishHook(file_, 1);
                // The stream moved with the file; checked again on it, now
                // under its final name. Without it the file is taken back
                // out through the handle: back to staging first, so it never
                // stays under the name it was meant to have, then deleted.
                // If it cannot be moved back, dropPart() still deletes it
                // there or, failing that, empties it (#60 r4). #60 r5: a
                // taken staging name moves it to another staging name, and
                // every result is checked (takeOut(), dropPart()). A same-name
                // file someone put there meanwhile is not ours and is never
                // touched.
                if (ensureZone(file_)) {
                    ++zone_.marked;
                    CloseHandle(file_);
                    file_ = INVALID_HANDLE_VALUE;
                    part_.clear();
                    return true;
                }
                ++zone_.failed;
                zoneRefused_ = true;
                // Stuck under its final name: it leaves that name, or its
                // bytes go, before anything else.
                takeOut();
                return dropPart();
            }
            const DWORD e = GetLastError();
            if (e != ERROR_ALREADY_EXISTS && e != ERROR_FILE_EXISTS && e != ERROR_ACCESS_DENIED) break;
        }
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

    // #60 r5: moves the open file out of the folder, back to its staging
    // name or, if that name was taken meanwhile, another one in staging.
    // Failing that it is cut or zeroed in place. False if none of it worked;
    // dropPart() then keeps the handle.
    bool takeOut() {
        if (traced("back", renameTo(file_, longPath(part_)))) return true;
        for (int n = 2; n < 100; ++n) {
            if (renameTo(file_, longPath(part_ + L"." + std::to_wstring(n)))) return traced("aside", true);
        }
        traced("aside", false);
        return traced("cut", emptyOn(file_)) || traced("zero", zeroOn(file_));
    }

    // Deletes the partial file through its handle, its name gone at once
    // where the volume allows (#60 r4). If that cannot be done now, its
    // bytes are cut to zero through the handle (#60 r4) and its identity is
    // kept for retryCleanup() (#53 r2, #60 r3: never just forgotten, never
    // retried by name).
    bool dropPart() {
        if (file_ != INVALID_HANDLE_VALUE) {
            FILE_ID_INFO id{};
            const bool known = filepull::fileIdOf(file_, id);
            bool gone = false;
            if (removeOrBlank(file_, gone)) {
                CloseHandle(file_);
                if (!gone && known) cleanup_.push_back(id);
            } else {
                // #60 r5: neither deleted, cut nor zeroed: the handle is
                // kept (anyone else opening the file must share writing and
                // deleting with it) and retryCleanup() tries again through it.
                held_.push_back(file_);
            }
            file_ = INVALID_HANDLE_VALUE;
        }
        part_.clear();
        written_ = 0;
        return false;
    }

    // True once nothing is left to clean up. Each record goes only when its
    // file is deleted or no longer exists.
    bool retryCleanup() {
        for (auto it = held_.begin(); it != held_.end();) {
            FILE_ID_INFO id{};
            const bool known = filepull::fileIdOf(*it, id);
            bool gone = false;
            if (!removeOrBlank(*it, gone)) {
                ++it;
                continue;
            }
            CloseHandle(*it);
            if (!gone && known) cleanup_.push_back(id);
            it = held_.erase(it);
        }
        if (dir_ == INVALID_HANDLE_VALUE) return cleanup_.empty() && held_.empty();
        for (auto it = cleanup_.begin(); it != cleanup_.end();) {
            if (filepull::deleteFileById(dir_, *it)) it = cleanup_.erase(it);
            else ++it;
        }
        return cleanup_.empty() && held_.empty();
    }

    std::wstring folder_;
    std::wstring staging_;   // folder_\.jlstaging (hidden)
    std::function<void(const std::wstring&)> open_;
    filepull::ZoneOps ops_;
    std::wstring name_;
    std::wstring part_;
    uint64_t written_ = 0;
    std::vector<FILE_ID_INFO> cleanup_;   // files still to delete, by identity
    std::vector<HANDLE> held_;            // #60 r5: files whose bytes could not be removed yet
    HANDLE file_ = INVALID_HANDLE_VALUE;
    HANDLE dir_ = INVALID_HANDLE_VALUE;   // folder_, a volume hint for cleanups
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
