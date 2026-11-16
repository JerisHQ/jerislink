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
#include <shlwapi.h>
#include <bcrypt.h>

#include "file_pull.hpp"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <future>
#include <optional>
#include <thread>

namespace jl::filepull {

namespace {

constexpr UINT kMsgOffer = WM_APP + 1;
constexpr UINT kMsgWithdraw = WM_APP + 2;
constexpr UINT kMsgQuit = WM_APP + 3;
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
class PullStream : public IStream {
public:
    PullStream(PullHub& hub, uint64_t token, uint64_t size, std::wstring leaf)
        : hub_(hub), token_(token), size_(size), leaf_(std::move(leaf)) {}

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
    ~PullStream() { hub_.close(token_); }

    PullHub& hub_;
    uint64_t token_;
    uint64_t size_;
    std::wstring leaf_;
    uint64_t pos_ = 0;
    std::atomic<long> refs_{1};
};

// The clipboard object for one announce.
class PullDataObject : public IDataObject {
public:
    PullDataObject(PullHub& hub, Manifest m, std::function<void(const std::string&)> log)
        : hub_(hub), m_(std::move(m)), log_(std::move(log)) {
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
            med->tymed = TYMED_ISTREAM;
            med->pstm = new PullStream(hub_, token, it.size, std::move(leaf));
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
    PullDataObject* current = nullptr; // STA thread only

    Impl(PullHub& h, LogFn l) : hub(h), log(std::move(l)) {}

    void run(std::promise<HWND>& ready) {
        if (FAILED(OleInitialize(nullptr))) {
            log("file.clipboard=unavailable reason=ole_init");
            ready.set_value(nullptr);
            return;
        }
        HWND w = CreateWindowExW(0, L"STATIC", L"", 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, nullptr, nullptr);
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
                if (msg.hwnd == w && msg.message == kMsgQuit) {
                    withdraw(0);
                    break;
                }
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
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
        auto* obj = new PullDataObject(hub, std::move(m), log);
        const HRESULT hr = setClipboard(obj);
        if (FAILED(hr)) {
            obj->Release();
            char buf[16];
            std::snprintf(buf, sizeof(buf), "%08lx", static_cast<unsigned long>(hr));
            log("file.announce=refused transfer=" + std::to_string(t) + " reason=clipboard hr=0x" + buf);
            return;
        }
        current = obj;   // keeps our reference; the clipboard holds its own
        log("file.announce=offered transfer=" + std::to_string(t) + " entries=" + std::to_string(entries));
    }

    // Clears Windows' clipboard only while it still holds our object: a copy
    // the user made on Windows since then is never wiped.
    void withdraw(uint32_t t) {
        if (!current) return;
        if (t != 0 && current->transfer() != t) return;
        if (OleIsCurrentClipboard(current) == S_OK) setClipboard(nullptr);
        current->Release();
        current = nullptr;
    }
};

FileClipboard::FileClipboard(PullHub& hub, LogFn log) : impl_(std::make_unique<Impl>(hub, std::move(log))) {}

FileClipboard::~FileClipboard() { stop(); }

void FileClipboard::start() {
    if (impl_->thread.joinable()) return;
    std::promise<HWND> ready;
    auto got = ready.get_future();
    impl_->thread = std::thread([this, &ready] { impl_->run(ready); });
    impl_->hwnd = got.get();
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

}  // namespace jl::filepull
