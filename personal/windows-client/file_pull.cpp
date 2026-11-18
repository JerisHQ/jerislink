// Mac->Windows paste (F3), the Windows clipboard object. See file_pull.hpp.
//
// The object lives on its own STA thread: Explorer (another process) calls
// GetData and IStream::Read through COM, and those calls arrive on this
// thread's message loop. A Read blocks here until PullHub has bytes, up to
// kReadTimeoutMs without progress. Nothing here touches the UI, render or
// input threads, and nothing here logs a file name.

#include <winsock2.h>
#include <windows.h>
#include <ole2.h>
#include <shlobj.h>
#include <shlguid.h>
#include <shlwapi.h>
#include <bcrypt.h>

#include "file_pull.hpp"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exdisp.h>
#include <shobjidl.h>
#include <algorithm>
#include <future>
#include <iterator>
#include <optional>
#include <thread>

namespace jl::filepull {

namespace {

constexpr UINT kMsgOffer = WM_APP + 1;
constexpr UINT kMsgWithdraw = WM_APP + 2;
constexpr UINT kMsgQuit = WM_APP + 3;
// F3 r2, Mark of the Web: posted by the clipboard object to the STA window.
constexpr UINT kMsgPasteStart = WM_APP + 4;  // wParam transfer
constexpr UINT kMsgDelivered = WM_APP + 5;   // wParam transfer, lParam manifest index
constexpr UINT kMsgShellChange = WM_APP + 6; // SHChangeNotifyRegister
constexpr UINT_PTR kMarkTimer = 1;
// What the paste source says about its data (design (j)): the shell's
// "high risk" URL action, so Explorer treats the files as from the Internet
// zone. Its effect on Mark of the Web is checked in the hand test.
constexpr DWORD kUrlActionShellExecuteHighRisk = 0x1806;

class BCryptDigest : public Digest {
public:
    BCryptDigest() {
        ok_ = BCryptOpenAlgorithmProvider(&alg_, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0 &&
              BCryptCreateHash(alg_, &hash_, nullptr, 0, nullptr, 0, 0) == 0;
    }
    ~BCryptDigest() override {
        if (hash_) BCryptDestroyHash(hash_);
        if (alg_) BCryptCloseAlgorithmProvider(alg_, 0);
    }
    void update(const uint8_t* data, size_t size) override {
        if (ok_ && BCryptHashData(hash_, const_cast<PUCHAR>(data), ULONG(size), 0) != 0) ok_ = false;
    }
    std::vector<uint8_t> finish() override {
        std::vector<uint8_t> out(32, 0);
        if (!ok_ || BCryptFinishHash(hash_, out.data(), 32, 0) != 0) return {};  // never matches
        return out;
    }

private:
    BCRYPT_ALG_HANDLE alg_ = nullptr;
    BCRYPT_HASH_HANDLE hash_ = nullptr;
    bool ok_ = false;
};

FILETIME fileTime(int64_t unixSeconds) {
    const int64_t t = unixSeconds * 10000000LL + 116444736000000000LL;
    FILETIME ft{};
    if (t > 0) {
        ft.dwLowDateTime = DWORD(uint64_t(t) & 0xffffffffu);
        ft.dwHighDateTime = DWORD(uint64_t(t) >> 32);
    }
    return ft;
}

HGLOBAL globalCopy(const void* data, size_t size) {
    HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, size);
    if (!h) return nullptr;
    void* p = GlobalLock(h);
    if (!p) { GlobalFree(h); return nullptr; }
    std::memcpy(p, data, size);
    GlobalUnlock(h);
    return h;
}

// One file's bytes for Explorer. Sequential only: Seek may only report or
// keep the current position.
// Called once when Explorer releases a FileContents stream: whether it read
// the file to its end (F3 r2, Mark of the Web).
using StreamEndFn = std::function<void(bool delivered)>;

class PullStream : public IStream {
public:
    PullStream(PullHub& hub, uint64_t token, uint64_t size, std::wstring leaf, StreamEndFn onEnd = {})
        : hub_(hub), token_(token), size_(size), leaf_(std::move(leaf)), onEnd_(std::move(onEnd)) {}

    // IUnknown
    STDMETHODIMP QueryInterface(REFIID riid, void** out) override {
        if (!out) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IStream || riid == IID_ISequentialStream) {
            *out = static_cast<IStream*>(this);
            AddRef();
            return S_OK;
        }
        *out = nullptr;
        return E_NOINTERFACE;
    }
    STDMETHODIMP_(ULONG) AddRef() override { return ULONG(++refs_); }
    STDMETHODIMP_(ULONG) Release() override {
        const long n = --refs_;
        if (n == 0) delete this;
        return ULONG(n);
    }

    // ISequentialStream
    STDMETHODIMP Read(void* out, ULONG size, ULONG* read) override {
        if (read) *read = 0;
        if (!out) return STG_E_INVALIDPOINTER;
        auto* p = static_cast<uint8_t*>(out);
        ULONG done = 0;
        while (done < size) {
            size_t got = 0;
            const auto r = hub_.read(token_, p + done, size - done, got, kReadTimeoutMs);
            if (r == PullHub::ReadResult::Ok) {
                done += ULONG(got);
                continue;
            }
            if (r == PullHub::ReadResult::Eof) break;
            // Failed or no progress: hand over what we have; the next Read fails.
            if (done == 0) return STG_E_READFAULT;
            break;
        }
        pos_ += done;
        if (read) *read = done;
        return done < size ? S_FALSE : S_OK;
    }
    STDMETHODIMP Write(const void*, ULONG, ULONG*) override { return STG_E_ACCESSDENIED; }

    // IStream
    STDMETHODIMP Seek(LARGE_INTEGER move, DWORD origin, ULARGE_INTEGER* newPos) override {
        int64_t target = -1;
        if (origin == STREAM_SEEK_CUR) target = int64_t(pos_) + move.QuadPart;
        else if (origin == STREAM_SEEK_SET) target = move.QuadPart;
        else if (origin == STREAM_SEEK_END) target = int64_t(size_) + move.QuadPart;
        if (target != int64_t(pos_)) return STG_E_INVALIDFUNCTION;
        if (newPos) newPos->QuadPart = pos_;
        return S_OK;
    }
    STDMETHODIMP SetSize(ULARGE_INTEGER) override { return E_NOTIMPL; }
    STDMETHODIMP CopyTo(IStream*, ULARGE_INTEGER, ULARGE_INTEGER*, ULARGE_INTEGER*) override { return E_NOTIMPL; }
    STDMETHODIMP Commit(DWORD) override { return S_OK; }
    STDMETHODIMP Revert() override { return E_NOTIMPL; }
    STDMETHODIMP LockRegion(ULARGE_INTEGER, ULARGE_INTEGER, DWORD) override { return STG_E_INVALIDFUNCTION; }
    STDMETHODIMP UnlockRegion(ULARGE_INTEGER, ULARGE_INTEGER, DWORD) override { return STG_E_INVALIDFUNCTION; }
    STDMETHODIMP Stat(STATSTG* st, DWORD flag) override {
        if (!st) return STG_E_INVALIDPOINTER;
        *st = STATSTG{};
        st->type = STGTY_STREAM;
        st->cbSize.QuadPart = size_;
        st->grfMode = STGM_READ;
        if (!(flag & STATFLAG_NONAME)) {
            const size_t bytes = (leaf_.size() + 1) * sizeof(wchar_t);
            st->pwcsName = static_cast<LPOLESTR>(CoTaskMemAlloc(bytes));
            if (!st->pwcsName) return E_OUTOFMEMORY;
            std::memcpy(st->pwcsName, leaf_.c_str(), bytes);
        }
        return S_OK;
    }
    STDMETHODIMP Clone(IStream**) override { return E_NOTIMPL; }

private:
    ~PullStream() {
        hub_.close(token_);
        // Explorer may stop at the size without asking again for the end.
        if (onEnd_) onEnd_(pos_ == size_);
    }

    PullHub& hub_;
    uint64_t token_;
    uint64_t size_;
    std::wstring leaf_;
    uint64_t pos_ = 0;
    StreamEndFn onEnd_;
    std::atomic<long> refs_{1};
};

// ---- Mark of the Web (F3 r2) ----------------------------------------------

std::wstring wideOf(const std::string& u) {
    const int n = MultiByteToWideChar(CP_UTF8, 0, u.data(), int(u.size()), nullptr, 0);
    std::wstring w(size_t(n > 0 ? n : 0), L'\0');
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, u.data(), int(u.size()), w.data(), n);
    return w;
}

std::string utf8Of(const std::wstring& w) {
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), int(w.size()), nullptr, 0, nullptr, nullptr);
    std::string u(size_t(n > 0 ? n : 0), '\0');
    if (n > 0) WideCharToMultiByte(CP_UTF8, 0, w.data(), int(w.size()), u.data(), n, nullptr, nullptr);
    return u;
}

// The top item's name, then Explorer's "Keep both" names: "a (2).txt" ...
std::vector<std::wstring> topNames(const std::wstring& top) {
    std::vector<std::wstring> out{top};
    const std::string u = utf8Of(top);
    for (int n = 2; n <= 20; ++n) out.push_back(wideOf(file::path::clashName(u, n)));
    return out;
}

bool sameOrLater(const FILETIME& a, const FILETIME& since) {
    return CompareFileTime(&a, &since) >= 0;
}

}  // namespace

ZoneWrite writeInternetZone(const std::wstring& path) {
    const std::wstring stream = path + L":Zone.Identifier";
    HANDLE h = CreateFileW(stream.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return GetLastError() == ERROR_FILE_EXISTS ? ZoneWrite::Exists : ZoneWrite::Failed;
    }
    static const char kBody[] = "[ZoneTransfer]\r\nZoneId=3\r\n";
    DWORD wrote = 0;
    const BOOL ok = WriteFile(h, kBody, DWORD(sizeof(kBody) - 1), &wrote, nullptr);
    CloseHandle(h);
    return ok && wrote == sizeof(kBody) - 1 ? ZoneWrite::Written : ZoneWrite::Failed;
}

int readZoneId(const std::wstring& path) {
    const std::wstring stream = path + L":Zone.Identifier";
    HANDLE h = CreateFileW(stream.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return -1;
    char buf[1024] = {};
    DWORD got = 0;
    ReadFile(h, buf, sizeof(buf) - 1, &got, nullptr);
    CloseHandle(h);
    const char* z = std::strstr(buf, "ZoneId=");
    return z ? std::atoi(z + 7) : -1;
}

ZoneMarkStats markDelivered(const Manifest& m, const std::vector<std::wstring>& folders, const FILETIME& since,
                            std::set<uint32_t>& want, std::set<uint32_t>& done, const ZoneOps& zone) {
    ZoneMarkStats stats;
    for (auto it = want.begin(); it != want.end();) {
        const uint32_t i = *it;
        if (i >= m.items.size() || m.items[i].dir) { it = want.erase(it); continue; }
        const Item& item = m.items[i];
        const size_t cut = item.rel.find(L'\\');
        const std::wstring top = cut == std::wstring::npos ? item.rel : item.rel.substr(0, cut);
        const std::wstring rest = cut == std::wstring::npos ? L"" : item.rel.substr(cut);
        // Counted once per item: the same file can be reached through two
        // folder spellings (a short 8.3 path and its long name).
        bool found = false, wrote = false, existed = false, failed = false, removed = false;
        for (const auto& folder : folders) {
            for (const auto& name : topNames(top)) {
                const std::wstring path = folder + L"\\" + name + rest;
                WIN32_FILE_ATTRIBUTE_DATA a{};
                if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &a)) continue;
                if (a.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                const uint64_t size = (uint64_t(a.nFileSizeHigh) << 32) | a.nFileSizeLow;
                if (size != item.size || !sameOrLater(a.ftCreationTime, since)) continue;
                found = true;
                switch (zone.write(path)) {
                case ZoneWrite::Written: wrote = true; break;
                case ZoneWrite::Exists: existed = true; break;
                case ZoneWrite::Failed:
                    // #53: no mark, no delivery. Explorer may still be closing
                    // the file, so the delete is retried for about a second.
                    failed = true;
                    for (int n = 0; n < 20; ++n) {
                        if (DeleteFileW(path.c_str())) { removed = true; break; }
                        Sleep(50);
                    }
                    break;
                }
            }
        }
        if (wrote) ++stats.written;
        else if (failed) {
            ++stats.failed;
            if (removed) ++stats.removed;
        }
        else if (existed) ++stats.existed;
        if (found) {
            done.insert(i);
            it = want.erase(it);
        } else {
            ++it;
        }
    }
    return stats;
}

namespace {

// The clipboard object for one announce.
class PullDataObject : public IDataObject {
public:
    PullDataObject(PullHub& hub, Manifest m, std::function<void(const std::string&)> log, HWND notify)
        : hub_(hub), m_(std::move(m)), log_(std::move(log)), notify_(notify) {
        cfDescriptor_ = CLIPFORMAT(RegisterClipboardFormatW(CFSTR_FILEDESCRIPTORW));
        cfContents_ = CLIPFORMAT(RegisterClipboardFormatW(CFSTR_FILECONTENTS));
        cfDropEffect_ = CLIPFORMAT(RegisterClipboardFormatW(CFSTR_PREFERREDDROPEFFECT));
        cfUntrusted_ = CLIPFORMAT(RegisterClipboardFormatW(L"UntrustedDragDrop"));
    }

    uint32_t transfer() const { return m_.transfer; }

    // IUnknown
    STDMETHODIMP QueryInterface(REFIID riid, void** out) override {
        if (!out) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IDataObject) {
            *out = static_cast<IDataObject*>(this);
            AddRef();
            return S_OK;
        }
        *out = nullptr;
        return E_NOINTERFACE;
    }
    STDMETHODIMP_(ULONG) AddRef() override { return ULONG(++refs_); }
    STDMETHODIMP_(ULONG) Release() override {
        const long n = --refs_;
        if (n == 0) delete this;
        return ULONG(n);
    }

    // IDataObject
    STDMETHODIMP GetData(FORMATETC* fe, STGMEDIUM* med) override {
        if (!fe || !med) return E_INVALIDARG;
        *med = STGMEDIUM{};
        const HRESULT q = QueryGetData(fe);
        if (q != S_OK) return q;
        if (fe->cfFormat == cfDescriptor_) {
            const size_t n = m_.items.size();
            const size_t bytes = sizeof(FILEGROUPDESCRIPTORW) + (n - 1) * sizeof(FILEDESCRIPTORW);
            HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, bytes);
            if (!h) return E_OUTOFMEMORY;
            auto* g = static_cast<FILEGROUPDESCRIPTORW*>(GlobalLock(h));
            if (!g) { GlobalFree(h); return E_OUTOFMEMORY; }
            g->cItems = UINT(n);
            for (size_t i = 0; i < n; ++i) {
                const Item& it = m_.items[i];
                FILEDESCRIPTORW& d = g->fgd[i];
                d.dwFlags = FD_UNICODE | FD_ATTRIBUTES | FD_WRITESTIME | FD_FILESIZE | FD_PROGRESSUI;
                d.dwFileAttributes = it.dir ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
                d.ftLastWriteTime = fileTime(it.mtime);
                d.nFileSizeHigh = DWORD(it.size >> 32);
                d.nFileSizeLow = DWORD(it.size & 0xffffffffu);
                // Checked against kMaxNameChars when the manifest was built.
                wcsncpy_s(d.cFileName, MAX_PATH, it.rel.c_str(), _TRUNCATE);
            }
            GlobalUnlock(h);
            med->tymed = TYMED_HGLOBAL;
            med->hGlobal = h;
            if (!descriptorLogged_) {
                descriptorLogged_ = true;
                log_("file.paste=requested transfer=" + std::to_string(m_.transfer) +
                     " entries=" + std::to_string(n));
            }
            return S_OK;
        }
        if (fe->cfFormat == cfContents_) {
            const LONG index = fe->lindex;
            if (index < 0 || size_t(index) >= m_.items.size() || m_.items[size_t(index)].dir) return DV_E_LINDEX;
            const uint64_t token = hub_.open(m_.transfer, uint32_t(index));
            if (token == 0) return E_FAIL;   // the announce was cancelled
            const Item& it = m_.items[size_t(index)];
            const size_t cut = it.rel.find_last_of(L'\\');
            std::wstring leaf = cut == std::wstring::npos ? it.rel : it.rel.substr(cut + 1);
            // Tell the STA window a paste is running and, when Explorer is
            // done with this file, whether it got all of it.
            const HWND w = notify_;
            const uint32_t t = m_.transfer;
            if (w) PostMessageW(w, kMsgPasteStart, WPARAM(t), 0);
            StreamEndFn onEnd;
            if (w) {
                onEnd = [w, t, index](bool delivered) {
                    if (delivered) PostMessageW(w, kMsgDelivered, WPARAM(t), LPARAM(index));
                };
            }
            med->tymed = TYMED_ISTREAM;
            med->pstm = new PullStream(hub_, token, it.size, std::move(leaf), std::move(onEnd));
            return S_OK;
        }
        DWORD value = fe->cfFormat == cfDropEffect_ ? DROPEFFECT_COPY : kUrlActionShellExecuteHighRisk;
        HGLOBAL h = globalCopy(&value, sizeof(value));
        if (!h) return E_OUTOFMEMORY;
        med->tymed = TYMED_HGLOBAL;
        med->hGlobal = h;
        return S_OK;
    }
    STDMETHODIMP GetDataHere(FORMATETC*, STGMEDIUM*) override { return E_NOTIMPL; }
    STDMETHODIMP QueryGetData(FORMATETC* fe) override {
        if (!fe) return E_INVALIDARG;
        if (fe->dwAspect != DVASPECT_CONTENT) return DV_E_DVASPECT;
        if (fe->cfFormat == cfContents_) return (fe->tymed & TYMED_ISTREAM) ? S_OK : DV_E_TYMED;
        if (fe->cfFormat == cfDescriptor_ || fe->cfFormat == cfDropEffect_ || fe->cfFormat == cfUntrusted_) {
            return (fe->tymed & TYMED_HGLOBAL) ? S_OK : DV_E_TYMED;
        }
        return DV_E_FORMATETC;
    }
    STDMETHODIMP GetCanonicalFormatEtc(FORMATETC*, FORMATETC* out) override {
        if (out) out->ptd = nullptr;
        return DATA_S_SAMEFORMATETC;
    }
    // Explorer reports "Performed DropEffect", "Paste Succeeded" and the like
    // here. Accepted and ignored.
    STDMETHODIMP SetData(FORMATETC*, STGMEDIUM* med, BOOL release) override {
        if (release && med) ReleaseStgMedium(med);
        return S_OK;
    }
    STDMETHODIMP EnumFormatEtc(DWORD dir, IEnumFORMATETC** out) override {
        if (!out) return E_POINTER;
        *out = nullptr;
        if (dir != DATADIR_GET) return E_NOTIMPL;
        FORMATETC f[4] = {
            {cfDescriptor_, nullptr, DVASPECT_CONTENT, -1, TYMED_HGLOBAL},
            {cfContents_, nullptr, DVASPECT_CONTENT, -1, TYMED_ISTREAM},
            {cfDropEffect_, nullptr, DVASPECT_CONTENT, -1, TYMED_HGLOBAL},
            {cfUntrusted_, nullptr, DVASPECT_CONTENT, -1, TYMED_HGLOBAL},
        };
        return SHCreateStdEnumFmtEtc(4, f, out);
    }
    STDMETHODIMP DAdvise(FORMATETC*, DWORD, IAdviseSink*, DWORD*) override { return OLE_E_ADVISENOTSUPPORTED; }
    STDMETHODIMP DUnadvise(DWORD) override { return OLE_E_ADVISENOTSUPPORTED; }
    STDMETHODIMP EnumDAdvise(IEnumSTATDATA**) override { return OLE_E_ADVISENOTSUPPORTED; }

private:
    ~PullDataObject() = default;

    PullHub& hub_;
    Manifest m_;
    std::function<void(const std::string&)> log_;
    HWND notify_ = nullptr;
    CLIPFORMAT cfDescriptor_ = 0;
    CLIPFORMAT cfContents_ = 0;
    CLIPFORMAT cfDropEffect_ = 0;
    CLIPFORMAT cfUntrusted_ = 0;
    bool descriptorLogged_ = false;
    std::atomic<long> refs_{1};
};

}  // namespace

DigestFactory sha256Digest() {
    return [] { return std::unique_ptr<Digest>(new BCryptDigest()); };
}

struct FileClipboard::Impl {
    PullHub& hub;
    LogFn log;
    std::thread thread;
    HWND hwnd = nullptr;
    std::mutex mu;
    std::optional<Manifest> pending;   // guarded by mu
    std::vector<std::wstring> extraFolders;  // guarded by mu
    ZoneMarkStats totals;                    // guarded by mu
    PullDataObject* current = nullptr; // STA thread only

    // Mark of the Web for the paste running now (STA thread only).
    struct MarkJob {
        Manifest m;
        FILETIME since{};
        std::set<uint32_t> want;   // read to the end, not found yet
        std::set<uint32_t> done;   // marked (or found already marked)
        std::vector<std::wstring> seen;  // folders the shell reported new items in
        ULONG notifyId = 0;
        int misses = 0;            // passes that found nothing new
    };
    std::optional<MarkJob> job;
    std::optional<Manifest> offered;  // the manifest behind `current`

    static constexpr int kMarkDelayMs = 1500;
    static constexpr int kMarkRetries = 8;   // about 12 s after the last file

    Impl(PullHub& h, LogFn l) : hub(h), log(std::move(l)) {}

    static LRESULT CALLBACK wndProc(HWND w, UINT msg, WPARAM wp, LPARAM lp) {
        auto* self = reinterpret_cast<Impl*>(GetWindowLongPtrW(w, GWLP_USERDATA));
        if (self) {
            if (msg == WM_TIMER && wp == kMarkTimer) { self->markPass(); return 0; }
            if (msg == kMsgShellChange) { self->shellChange(wp, lp); return 0; }
        }
        return DefWindowProcW(w, msg, wp, lp);
    }

    static HWND createWindow() {
        HINSTANCE hi = GetModuleHandleW(nullptr);
        WNDCLASSEXW wc{};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = wndProc;
        wc.hInstance = hi;
        wc.lpszClassName = L"JerislinkFilePull";
        if (!RegisterClassExW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) return nullptr;
        return CreateWindowExW(0, wc.lpszClassName, L"", 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, hi, nullptr);
    }

    void run(std::promise<HWND>& ready) {
        if (FAILED(OleInitialize(nullptr))) {
            log("file.clipboard=unavailable reason=ole_init");
            ready.set_value(nullptr);
            return;
        }
        HWND w = createWindow();
        if (w) SetWindowLongPtrW(w, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));
        hwnd = w;
        ready.set_value(w);
        if (w) {
            MSG msg;
            while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
                if (msg.hwnd == w && msg.message == kMsgOffer) {
                    std::optional<Manifest> m;
                    {
                        std::lock_guard<std::mutex> lock(mu);
                        m.swap(pending);
                    }
                    if (m) set(std::move(*m));
                    continue;
                }
                if (msg.hwnd == w && msg.message == kMsgWithdraw) {
                    withdraw(uint32_t(msg.wParam));
                    continue;
                }
                if (msg.hwnd == w && msg.message == kMsgPasteStart) {
                    pasteStarted(uint32_t(msg.wParam));
                    continue;
                }
                if (msg.hwnd == w && msg.message == kMsgDelivered) {
                    delivered(uint32_t(msg.wParam), uint32_t(msg.lParam));
                    continue;
                }
                if (msg.hwnd == w && msg.message == kMsgQuit) {
                    withdraw(0);
                    break;
                }
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            endJob();
            SetWindowLongPtrW(w, GWLP_USERDATA, 0);
            DestroyWindow(w);
        }
        withdraw(0);
        OleUninitialize();
    }

    // OleSetClipboard fails while another program holds the clipboard open;
    // try a few times, briefly.
    static HRESULT setClipboard(IDataObject* obj) {
        HRESULT hr = E_FAIL;
        for (int i = 0; i < 5; ++i) {
            hr = OleSetClipboard(obj);
            if (hr != CLIPBRD_E_CANT_OPEN) break;
            Sleep(20);
        }
        return hr;
    }

    void set(Manifest m) {
        withdraw(0);
        const uint32_t t = m.transfer;
        const size_t entries = m.items.size();
        auto* obj = new PullDataObject(hub, m, log, hwnd);
        const HRESULT hr = setClipboard(obj);
        if (FAILED(hr)) {
            obj->Release();
            char buf[16];
            std::snprintf(buf, sizeof(buf), "%08lx", static_cast<unsigned long>(hr));
            log("file.announce=refused transfer=" + std::to_string(t) + " reason=clipboard hr=0x" + buf);
            return;
        }
        current = obj;   // keeps our reference; the clipboard holds its own
        offered = std::move(m);
        log("file.announce=offered transfer=" + std::to_string(t) + " entries=" + std::to_string(entries));
    }

    // Clears Windows' clipboard only while it still holds our object: a copy
    // the user made on Windows since then is never wiped. A paste already
    // running keeps its mark job.
    void withdraw(uint32_t t) {
        if (!current) return;
        if (t != 0 && current->transfer() != t) return;
        if (OleIsCurrentClipboard(current) == S_OK) setClipboard(nullptr);
        current->Release();
        current = nullptr;
        offered.reset();
    }

    // ---- Mark of the Web ----

    void pasteStarted(uint32_t t) {
        if (job && job->m.transfer == t) return;
        if (!offered || offered->transfer != t) return;
        endJob();   // an earlier paste: one last look first
        MarkJob j;
        j.m = *offered;
        // A little before now: file times and clocks are coarse.
        GetSystemTimeAsFileTime(&j.since);
        ULARGE_INTEGER u{j.since.dwLowDateTime, j.since.dwHighDateTime};
        u.QuadPart -= 5ull * 10000000ull;
        j.since = FILETIME{u.LowPart, u.HighPart};
        // New items anywhere under the desktop namespace, while this paste runs.
        PIDLIST_ABSOLUTE desk = nullptr;
        if (SUCCEEDED(SHGetSpecialFolderLocation(nullptr, CSIDL_DESKTOP, &desk)) && desk) {
            SHChangeNotifyEntry e{desk, TRUE};
            j.notifyId = SHChangeNotifyRegister(hwnd, SHCNRF_ShellLevel | SHCNRF_NewDelivery,
                                                SHCNE_CREATE | SHCNE_MKDIR | SHCNE_RENAMEITEM, kMsgShellChange, 1, &e);
            CoTaskMemFree(desk);
        }
        job = std::move(j);
    }

    void delivered(uint32_t t, uint32_t index) {
        if (!job || job->m.transfer != t) return;
        job->done.erase(index);   // the same copy pasted again somewhere else
        job->want.insert(index);
        job->misses = 0;
        SetTimer(hwnd, kMarkTimer, kMarkDelayMs, nullptr);
    }

    void shellChange(WPARAM wp, LPARAM lp) {
        PIDLIST_ABSOLUTE* pidls = nullptr;
        LONG event = 0;
        HANDLE lock = SHChangeNotification_Lock(reinterpret_cast<HANDLE>(wp), DWORD(lp), &pidls, &event);
        if (!lock) return;
        if (job && pidls) {
            PIDLIST_ABSOLUTE item = (event & SHCNE_RENAMEITEM) && pidls[1] ? pidls[1] : pidls[0];
            wchar_t path[MAX_PATH * 2] = {};
            if (item && SHGetPathFromIDListEx(item, path, DWORD(std::size(path)), GPFIDL_DEFAULT)) {
                std::wstring p(path);
                const size_t cut = p.find_last_of(L'\\');
                if (cut != std::wstring::npos && cut > 0) {
                    std::wstring dir = p.substr(0, cut);
                    if (dir.size() == 2 && dir[1] == L':') dir += L'\\';
                    auto& seen = job->seen;
                    if (std::find(seen.begin(), seen.end(), dir) == seen.end() && seen.size() < 64) seen.push_back(dir);
                }
            }
        }
        SHChangeNotification_Unlock(lock);
    }

    // Folders open in Explorer windows (Raymond Chen's ShellWindows walk).
    static void openWindowFolders(std::vector<std::wstring>& out) {
        IShellWindows* windows = nullptr;
        if (FAILED(CoCreateInstance(CLSID_ShellWindows, nullptr, CLSCTX_ALL, IID_PPV_ARGS(&windows)))) return;
        long count = 0;
        windows->get_Count(&count);
        for (long i = 0; i < count && i < 64; ++i) {
            VARIANT v;
            VariantInit(&v);
            v.vt = VT_I4;
            v.lVal = i;
            IDispatch* disp = nullptr;
            if (windows->Item(v, &disp) != S_OK || !disp) continue;
            IServiceProvider* sp = nullptr;
            IShellBrowser* browser = nullptr;
            IShellView* view = nullptr;
            IFolderView* fv = nullptr;
            IPersistFolder2* pf = nullptr;
            PIDLIST_ABSOLUTE pidl = nullptr;
            if (SUCCEEDED(disp->QueryInterface(IID_PPV_ARGS(&sp))) &&
                SUCCEEDED(sp->QueryService(SID_STopLevelBrowser, IID_PPV_ARGS(&browser))) &&
                SUCCEEDED(browser->QueryActiveShellView(&view)) && SUCCEEDED(view->QueryInterface(IID_PPV_ARGS(&fv))) &&
                SUCCEEDED(fv->GetFolder(IID_PPV_ARGS(&pf))) && SUCCEEDED(pf->GetCurFolder(&pidl)) && pidl) {
                wchar_t path[MAX_PATH * 2] = {};
                if (SHGetPathFromIDListEx(pidl, path, DWORD(std::size(path)), GPFIDL_DEFAULT)) out.emplace_back(path);
            }
            if (pidl) CoTaskMemFree(pidl);
            if (pf) pf->Release();
            if (fv) fv->Release();
            if (view) view->Release();
            if (browser) browser->Release();
            if (sp) sp->Release();
            disp->Release();
        }
        windows->Release();
    }

    std::vector<std::wstring> searchFolders() {
        std::vector<std::wstring> out;
        if (job) out = job->seen;
        {
            std::lock_guard<std::mutex> lock(mu);
            out.insert(out.end(), extraFolders.begin(), extraFolders.end());
        }
        openWindowFolders(out);
        PWSTR desktop = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Desktop, 0, nullptr, &desktop)) && desktop) out.emplace_back(desktop);
        CoTaskMemFree(desktop);
        // One look per folder, case-insensitively.
        std::vector<std::wstring> unique;
        for (auto& f : out) {
            while (f.size() > 3 && f.back() == L'\\') f.pop_back();
            const bool dup = std::any_of(unique.begin(), unique.end(),
                                         [&](const std::wstring& u) { return _wcsicmp(u.c_str(), f.c_str()) == 0; });
            if (!dup && !f.empty()) unique.push_back(f);
        }
        return unique;
    }

    void markPass() {
        if (!job) { KillTimer(hwnd, kMarkTimer); return; }
        const auto stats = markDelivered(job->m, searchFolders(), job->since, job->want, job->done);
        {
            std::lock_guard<std::mutex> lock(mu);
            totals.written += stats.written;
            totals.existed += stats.existed;
            totals.failed += stats.failed;
            totals.removed += stats.removed;
        }
        if (stats.written || stats.existed || stats.failed) {
            log("file.motw transfer=" + std::to_string(job->m.transfer) + " written=" + std::to_string(stats.written) +
                " existed=" + std::to_string(stats.existed) + " failed=" + std::to_string(stats.failed) +
                " removed=" + std::to_string(stats.removed));
        }
        if (stats.failed) {
            // #53: these files could not carry ZoneId=3 (a volume without
            // streams?) and were taken back out of the paste folder.
            log("file.motw transfer=" + std::to_string(job->m.transfer) + " refused=" + std::to_string(stats.failed) +
                " reason=zone_write_failed removed=" + std::to_string(stats.removed) +
                " left=" + std::to_string(stats.failed - stats.removed));
        }
        if (job->want.empty()) {
            KillTimer(hwnd, kMarkTimer);   // the next delivered file restarts it
            if (job->done.size() >= job->m.files) endJob();
            return;
        }
        if (stats.written + stats.existed + stats.failed == 0 && ++job->misses >= kMarkRetries) {
            KillTimer(hwnd, kMarkTimer);
            log("file.motw transfer=" + std::to_string(job->m.transfer) + " not_found=" +
                std::to_string(job->want.size()));
            job->want.clear();
        }
    }

    void endJob() {
        if (!job) return;
        KillTimer(hwnd, kMarkTimer);
        if (!job->want.empty()) {
            const auto stats = markDelivered(job->m, searchFolders(), job->since, job->want, job->done);
            std::lock_guard<std::mutex> lock(mu);
            totals.written += stats.written;
            totals.existed += stats.existed;
            totals.failed += stats.failed;
            totals.removed += stats.removed;
        }
        if (job->notifyId) SHChangeNotifyDeregister(job->notifyId);
        job.reset();
    }
};

FileClipboard::FileClipboard(PullHub& hub, LogFn log) : impl_(std::make_unique<Impl>(hub, std::move(log))) {}

FileClipboard::~FileClipboard() { stop(); }

void FileClipboard::start() {
    if (impl_->thread.joinable()) return;
    std::promise<HWND> ready;
    auto got = ready.get_future();
    impl_->thread = std::thread([this, &ready] { impl_->run(ready); });
    got.get();
}

void FileClipboard::stop() {
    if (!impl_->thread.joinable()) return;
    if (impl_->hwnd) PostMessageW(impl_->hwnd, kMsgQuit, 0, 0);
    impl_->thread.join();
    impl_->hwnd = nullptr;
}

void FileClipboard::offer(const Manifest& m) {
    if (!impl_->hwnd) return;
    {
        std::lock_guard<std::mutex> lock(impl_->mu);
        impl_->pending = m;
    }
    PostMessageW(impl_->hwnd, kMsgOffer, 0, 0);
}

void FileClipboard::withdraw(uint32_t transfer) {
    if (!impl_->hwnd) return;
    {
        // An offer not yet placed is dropped with it.
        std::lock_guard<std::mutex> lock(impl_->mu);
        if (impl_->pending && (transfer == 0 || impl_->pending->transfer == transfer)) impl_->pending.reset();
    }
    PostMessageW(impl_->hwnd, kMsgWithdraw, WPARAM(transfer), 0);
}

void FileClipboard::addSearchFolder(const std::wstring& folder) {
    std::lock_guard<std::mutex> lock(impl_->mu);
    impl_->extraFolders.push_back(folder);
}

ZoneMarkStats FileClipboard::zoneStats() const {
    std::lock_guard<std::mutex> lock(impl_->mu);
    return impl_->totals;
}

}  // namespace jl::filepull
