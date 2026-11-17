// Mac right-click "Send to JerisLink" (F5b): the Downloads\JerisLink writer.
// See file_push.hpp.
#include "file_push.hpp"

#include <windows.h>
#include <objbase.h>
#include <shellapi.h>
#include <shlobj.h>

#include <thread>

namespace jl::filepush {
namespace {

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

class FolderSink : public Sink {
public:
    FolderSink(std::wstring folder, std::function<void(const std::wstring&)> open)
        : folder_(std::move(folder)), open_(std::move(open)) {}
    ~FolderSink() override { abort(); }

    bool prepare() override {
        if (folder_.empty()) return false;
        // The folder and its parents (Downloads normally exists already).
        const int rc = SHCreateDirectoryExW(nullptr, folder_.c_str(), nullptr);
        if (rc != ERROR_SUCCESS && rc != ERROR_ALREADY_EXISTS && rc != ERROR_FILE_EXISTS) return false;
        const DWORD a = GetFileAttributesW(longPath(folder_).c_str());
        return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY) && !(a & FILE_ATTRIBUTE_REPARSE_POINT);
    }

    bool begin(const std::wstring& name) override {
        abort();
        name_ = name;
        for (int n = 1; n < 1000; ++n) {
            const std::wstring part = folder_ + L"\\" + name + (n == 1 ? L"" : L"." + std::to_wstring(n)) + L".jlpart";
            HANDLE h = CreateFileW(longPath(part).c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                                   FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
            if (h != INVALID_HANDLE_VALUE) {
                file_ = h;
                part_ = part;
                // Mark of the Web goes on the partial file first: the stream
                // moves with the rename, so the file never has its final name
                // without it (a scanner opening a new .exe right after the
                // rename can no longer make the mark fail). commit() checks.
                filepull::writeInternetZone(longPath(part));
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
        }
        return true;
    }

    bool commit() override {
        if (file_ == INVALID_HANDLE_VALUE) return false;
        const BOOL flushed = FlushFileBuffers(file_);
        CloseHandle(file_);
        file_ = INVALID_HANDLE_VALUE;
        if (!flushed) return dropPart();
        // No overwrite: an existing name moves on to "name (2).ext" ...
        const std::string utf8 = toUtf8(name_);
        for (int n = 1; n < 1000; ++n) {
            const std::wstring leaf = n == 1 ? name_ : toWide(file::path::clashName(utf8, n));
            const std::wstring target = folder_ + L"\\" + leaf;
            if (MoveFileExW(longPath(part_).c_str(), longPath(target).c_str(), MOVEFILE_WRITE_THROUGH)) {
                part_.clear();
                ensureZone(longPath(target));
                return true;
            }
            const DWORD e = GetLastError();
            if (e != ERROR_ALREADY_EXISTS && e != ERROR_FILE_EXISTS && e != ERROR_ACCESS_DENIED) break;
        }
        return dropPart();
    }

    void abort() override {
        if (file_ != INVALID_HANDLE_VALUE) {
            CloseHandle(file_);
            file_ = INVALID_HANDLE_VALUE;
        }
        dropPart();
    }

    void finished(uint32_t) override {
        if (open_) open_(folder_);
    }

    ZoneCounts zoneCounts() const override { return zone_; }

private:
    // The file must carry ZoneId=3 (Q1). Normally it came with the rename;
    // otherwise write it, retrying for about a second while something
    // (Defender scanning a new .exe) holds the file.
    void ensureZone(const std::wstring& path) {
        for (int i = 0; i < 20; ++i) {
            if (filepull::readZoneId(path) == 3) {
                ++zone_.marked;
                return;
            }
            if (filepull::writeInternetZone(path) == filepull::ZoneWrite::Written) continue;
            Sleep(50);
        }
        ++zone_.failed;
    }

    bool dropPart() {
        if (!part_.empty()) DeleteFileW(longPath(part_).c_str());
        part_.clear();
        return false;
    }

    std::wstring folder_;
    std::function<void(const std::wstring&)> open_;
    std::wstring name_;
    std::wstring part_;
    HANDLE file_ = INVALID_HANDLE_VALUE;
    ZoneCounts zone_;
};

}  // namespace

std::unique_ptr<Sink> makeFolderSink(std::wstring folder, std::function<void(const std::wstring&)> open) {
    return std::make_unique<FolderSink>(std::move(folder), std::move(open));
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
