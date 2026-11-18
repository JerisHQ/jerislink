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
constexpr UINT kMsgShellChange = WM_APP + 6; // SHChangeNotifyRegister
// #53 r2: how much of a file's start and end the gate compares.
constexpr size_t kGateBytes = 64 * 1024;
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

// Asked once per file, before Explorer gets its last byte (#53 r2): true
// only when the copy on disk was found and carries ZoneId=3.
using GateFn = std::function<bool(const GateRequest&)>;

// One file's bytes for Explorer. Sequential only: Seek may only report or
// keep the current position. The last byte is held back until the gate
// passes; if it fails, this read and every later one fail, so Explorer never
// completes the file.
class PullStream : public IStream {
public:
    PullStream(PullHub& hub, uint64_t token, uint64_t size, std::wstring leaf, GateRequest req, GateFn gate)
        : hub_(hub), token_(token), size_(size), leaf_(std::move(leaf)), req_(std::move(req)), gate_(std::move(gate)) {}

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
        if (gateFailed_) return STG_E_READFAULT;
        auto* p = static_cast<uint8_t*>(out);
        ULONG done = 0;
        bool atGate = false;
        while (done < size) {
            uint64_t want = size - done;
            if (!gatePassed_ && size_ > 0) {
                const uint64_t at = pos_ + done;
                if (at == size_ - 1) {
                    // The last byte: hand over what this call has first, then
                    // run the gate on the next call, once Explorer wrote it.
                    if (done > 0) { atGate = true; break; }
                    if (!runGate()) {
                        gateFailed_ = true;
                        return STG_E_READFAULT;
                    }
                    gatePassed_ = true;
                } else if (at < size_ - 1) {
                    want = std::min<uint64_t>(want, size_ - 1 - at);
                }
            }
            size_t got = 0;
            const auto r = hub_.read(token_, p + done, size_t(want), got, kReadTimeoutMs);
            if (r == PullHub::ReadResult::Ok) {
                if (!gatePassed_) keep(p + done, got);
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
        if (atGate) return S_OK;
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

    // The first and the last kGateBytes handed out, for the gate's proof.
    void keep(const uint8_t* b, size_t n) {
        if (req_.head.size() < kGateBytes) {
            req_.head.insert(req_.head.end(), b, b + std::min(n, kGateBytes - req_.head.size()));
        }
        if (n >= kGateBytes) {
            req_.tail.assign(b + n - kGateBytes, b + n);
            return;
        }
        req_.tail.insert(req_.tail.end(), b, b + n);
        if (req_.tail.size() > kGateBytes) {
            req_.tail.erase(req_.tail.begin(), req_.tail.begin() + std::ptrdiff_t(req_.tail.size() - kGateBytes));
        }
    }

    // No gate (no clipboard thread behind us) means no mark: fail closed.
    bool runGate() { return gate_ && gate_(req_); }

    PullHub& hub_;
    uint64_t token_;
    uint64_t size_;
    std::wstring leaf_;
    uint64_t pos_ = 0;
    GateRequest req_;
    GateFn gate_;
    bool gatePassed_ = false;
    bool gateFailed_ = false;
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

// Whether the file at `path` starts with r.head and has r.tail right before
// its last byte: the bytes this transfer handed out, not a neighbour's.
enum class Bytes { Same, OpenFailed, HeadDiff, TailDiff };

Bytes sameBytes(const std::wstring& path, const GateRequest& r, DWORD& openError) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        openError = GetLastError();
        return Bytes::OpenFailed;
    }
    std::vector<uint8_t> buf;
    auto readAt = [&](uint64_t off, size_t n) {
        buf.assign(n, 0);
        if (n == 0) return true;
        OVERLAPPED o{};
        o.Offset = DWORD(off & 0xffffffffu);
        o.OffsetHigh = DWORD(off >> 32);
        DWORD got = 0;
        return ReadFile(h, buf.data(), DWORD(n), &got, &o) && got == n;
    };
    const uint64_t body = r.size > 0 ? r.size - 1 : 0;   // bytes handed out before the gate
    // Ours, or not written yet: Explorer writes its last buffer only after
    // it has the last byte, and a file it sized first reads as zeros there.
    auto oursOrUnwritten = [&](const std::vector<uint8_t>& want) {
        return buf == want || std::all_of(buf.begin(), buf.end(), [](uint8_t b) { return b == 0; });
    };
    Bytes out = Bytes::Same;
    if (r.head.size() > body || !readAt(0, r.head.size()) || !oursOrUnwritten(r.head)) out = Bytes::HeadDiff;
    else if (r.tail.size() > body || !readAt(body - r.tail.size(), r.tail.size()) || !oursOrUnwritten(r.tail))
        out = Bytes::TailDiff;
    CloseHandle(h);
    return out;
}

enum class MarkResult { Written, Existed, WriteFailed, Invalid };

// Makes sure `path` carries ZoneId=3 (or the stricter 4). A weaker or broken
// Zone.Identifier is removed and written again; the result is read back.
MarkResult markOne(const std::wstring& path, const ZoneOps& zone) {
    const int before = zone.read(path);
    if (before == 3 || before == 4) return MarkResult::Existed;
    DeleteFileW((path + L":Zone.Identifier").c_str());
    ZoneWrite w = ZoneWrite::Failed;
    for (int n = 0; n < 10; ++n) {
        if (n) Sleep(100);
        w = zone.write(path);
        if (zone.read(path) == 3) return MarkResult::Written;
    }
    return w == ZoneWrite::Failed ? MarkResult::WriteFailed : MarkResult::Invalid;
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

GateOutcome gateFile(const GateRequest& r, const std::vector<std::wstring>& folders, const ZoneOps& zone,
                     ZoneMarkStats& stats, GateProbe* probe) {
    GateProbe local;
    GateProbe& pr = probe ? *probe : local;
    const size_t cut = r.rel.find(L'\\');
    const std::wstring top = cut == std::wstring::npos ? r.rel : r.rel.substr(0, cut);
    const std::wstring rest = cut == std::wstring::npos ? L"" : r.rel.substr(cut);
    const uint64_t minSize = r.size > 0 ? r.size - 1 : 0;
    // Counted once per file: the same copy can be reached through two folder
    // spellings (a short 8.3 path and its long name).
    bool found = false, wrote = false;
    GateOutcome bad = GateOutcome::Marked;
    for (const auto& folder : folders) {
        for (const auto& name : topNames(top)) {
            const std::wstring path = folder + L"\\" + name + rest;
            ++pr.paths;
            WIN32_FILE_ATTRIBUTE_DATA a{};
            if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &a)) continue;
            if (a.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            const uint64_t size = (uint64_t(a.nFileSizeHigh) << 32) | a.nFileSizeLow;
            ++pr.present;
            pr.lastSize = size;
            const ULARGE_INTEGER c{a.ftCreationTime.dwLowDateTime, a.ftCreationTime.dwHighDateTime};
            const ULARGE_INTEGER s{r.since.dwLowDateTime, r.since.dwHighDateTime};
            pr.lastAgeMs = (int64_t(c.QuadPart) - int64_t(s.QuadPart)) / 10000;
            if (size < minSize) { ++pr.tooSmall; continue; }
            if (size > r.size) ++pr.larger;
            if (!sameOrLater(a.ftCreationTime, r.since)) { ++pr.older; continue; }
            DWORD openError = 0;
            const Bytes b = sameBytes(path, r, openError);
            if (b == Bytes::OpenFailed) { ++pr.openFailed; pr.openError = openError; continue; }
            if (b == Bytes::HeadDiff) { ++pr.headDiff; continue; }
            if (b == Bytes::TailDiff) { ++pr.tailDiff; continue; }
            found = true;
            switch (markOne(path, zone)) {
            case MarkResult::Written: wrote = true; break;
            case MarkResult::Existed: break;
            case MarkResult::WriteFailed: if (bad == GateOutcome::Marked) bad = GateOutcome::WriteFailed; break;
            case MarkResult::Invalid: bad = GateOutcome::Invalid; break;
            }
        }
    }
    if (!found) return GateOutcome::NotFound;
    if (bad != GateOutcome::Marked) {
        ++stats.failed;
        return bad;
    }
    if (wrote) ++stats.written;
    else ++stats.existed;
    return GateOutcome::Marked;
}

namespace {

// The clipboard object for one announce.
class PullDataObject : public IDataObject {
public:
    PullDataObject(PullHub& hub, Manifest m, std::function<void(const std::string&)> log, HWND notify, GateFn gate)
        : hub_(hub), m_(std::move(m)), log_(std::move(log)), notify_(notify), gate_(std::move(gate)) {
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
            // Tell the STA window a paste is running, so it watches the shell
            // for the folder the copy lands in.
            if (notify_) PostMessageW(notify_, kMsgPasteStart, WPARAM(m_.transfer), 0);
            GateRequest req;
            req.transfer = m_.transfer;
            req.index = uint32_t(index);
            req.rel = it.rel;
            req.size = it.size;
            // A little before now: file times and clocks are coarse.
            GetSystemTimeAsFileTime(&req.since);
            ULARGE_INTEGER u{req.since.dwLowDateTime, req.since.dwHighDateTime};
            u.QuadPart -= 5ull * 10000000ull;
            req.since = FILETIME{u.LowPart, u.HighPart};
            med->tymed = TYMED_ISTREAM;
            med->pstm = new PullStream(hub_, token, it.size, std::move(leaf), std::move(req), gate_);
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
    GateFn gate_;
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
    // Folders where the shell reported new items during the paste, and the
    // folders open in Explorer windows when it started (guarded by mu).
    std::vector<std::wstring> seen;
    std::vector<std::wstring> windowFolders;
    PullDataObject* current = nullptr; // STA thread only
    std::optional<Manifest> offered;   // the manifest behind `current` (STA thread only)
    uint32_t watching = 0;             // the transfer the shell watch is for (STA thread only)
    ULONG notifyId = 0;                // STA thread only
    DWORD threadId = 0;

    // How long the gate looks for a copy before it gives up.
    static constexpr int kGateWaitMs = 5000;

    ZoneOps zone;

    Impl(PullHub& h, LogFn l, ZoneOps z) : hub(h), log(std::move(l)), zone(z) {}

    static LRESULT CALLBACK wndProc(HWND w, UINT msg, WPARAM wp, LPARAM lp) {
        auto* self = reinterpret_cast<Impl*>(GetWindowLongPtrW(w, GWLP_USERDATA));
        if (self) {
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
        threadId = GetCurrentThreadId();
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
                if (msg.hwnd == w && msg.message == kMsgQuit) {
                    withdraw(0);
                    break;
                }
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            endWatch();
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
        auto* obj = new PullDataObject(hub, m, log, hwnd, [this](const GateRequest& r) { return gate(r); });
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
    // running keeps its gate.
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
        if (watching == t) return;
        if (!offered || offered->transfer != t) return;
        endWatch();
        std::vector<std::wstring> wins;
        openWindowFolders(wins);
        {
            std::lock_guard<std::mutex> lock(mu);
            seen.clear();
            windowFolders = std::move(wins);
        }
        // New items anywhere under the desktop namespace, while this paste runs.
        PIDLIST_ABSOLUTE desk = nullptr;
        if (SUCCEEDED(SHGetSpecialFolderLocation(nullptr, CSIDL_DESKTOP, &desk)) && desk) {
            SHChangeNotifyEntry e{desk, TRUE};
            notifyId = SHChangeNotifyRegister(hwnd, SHCNRF_ShellLevel | SHCNRF_NewDelivery,
                                              SHCNE_CREATE | SHCNE_MKDIR | SHCNE_RENAMEITEM, kMsgShellChange, 1, &e);
            CoTaskMemFree(desk);
        }
        watching = t;
    }

    void endWatch() {
        if (notifyId) SHChangeNotifyDeregister(notifyId);
        notifyId = 0;
        watching = 0;
    }

    void shellChange(WPARAM wp, LPARAM lp) {
        PIDLIST_ABSOLUTE* pidls = nullptr;
        LONG event = 0;
        HANDLE lock = SHChangeNotification_Lock(reinterpret_cast<HANDLE>(wp), DWORD(lp), &pidls, &event);
        if (!lock) return;
        if (watching && pidls) {
            PIDLIST_ABSOLUTE item = (event & SHCNE_RENAMEITEM) && pidls[1] ? pidls[1] : pidls[0];
            wchar_t path[MAX_PATH * 2] = {};
            if (item && SHGetPathFromIDListEx(item, path, DWORD(std::size(path)), GPFIDL_DEFAULT)) {
                std::wstring p(path);
                const size_t cut = p.find_last_of(L'\\');
                if (cut != std::wstring::npos && cut > 0) {
                    std::wstring dir = p.substr(0, cut);
                    if (dir.size() == 2 && dir[1] == L':') dir += L'\\';
                    std::lock_guard<std::mutex> guard(mu);
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
        {
            std::lock_guard<std::mutex> lock(mu);
            out = seen;
            out.insert(out.end(), extraFolders.begin(), extraFolders.end());
            out.insert(out.end(), windowFolders.begin(), windowFolders.end());
        }
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

    // Shell notifications and paste starts that arrived while a gate runs
    // inside Explorer's Read (STA thread only).
    void pumpShell() {
        MSG msg;
        while (hwnd && PeekMessageW(&msg, hwnd, kMsgPasteStart, kMsgShellChange, PM_REMOVE)) {
            if (msg.message == kMsgPasteStart) pasteStarted(uint32_t(msg.wParam));
            else if (msg.message == kMsgShellChange) shellChange(msg.wParam, msg.lParam);
        }
    }

    // #53 r2: runs before Explorer gets a file's last byte. True only when
    // the copy on disk is proven ours and carries ZoneId=3. Logs no names.
    bool gate(const GateRequest& r) {
        const bool onSta = GetCurrentThreadId() == threadId;
        if (onSta) {
            pumpShell();
            pasteStarted(r.transfer);
        }
        const ULONGLONG until = GetTickCount64() + kGateWaitMs;
        GateOutcome got = GateOutcome::NotFound;
        ZoneMarkStats st;
        GateProbe probe;
        size_t folders = 0;
        for (;;) {
            st = ZoneMarkStats{};
            probe = GateProbe{};
            const auto where = searchFolders();
            folders = where.size();
            got = gateFile(r, where, zone, st, &probe);
            if (got != GateOutcome::NotFound || GetTickCount64() >= until) break;
            Sleep(100);
            if (onSta) pumpShell();
        }
        {
            std::lock_guard<std::mutex> lock(mu);
            totals.written += st.written;
            totals.existed += st.existed;
            totals.failed += st.failed;
        }
        const std::string head = "file.motw transfer=" + std::to_string(r.transfer) + " index=" + std::to_string(r.index);
        switch (got) {
        case GateOutcome::Marked:
            log(head + (st.written ? " marked=written" : " marked=existed"));
            return true;
        case GateOutcome::NotFound:
            log(head + " refused reason=not_found sta=" + (onSta ? "1" : "0") + " folders=" + std::to_string(folders) +
                " paths=" + std::to_string(probe.paths) + " present=" + std::to_string(probe.present) +
                " small=" + std::to_string(probe.tooSmall) + " larger=" + std::to_string(probe.larger) +
                " older=" + std::to_string(probe.older) + " open_failed=" + std::to_string(probe.openFailed) +
                " head_diff=" + std::to_string(probe.headDiff) + " tail_diff=" + std::to_string(probe.tailDiff) +
                " size=" + std::to_string(probe.lastSize) + "/" + std::to_string(r.size) +
                " age_ms=" + std::to_string(probe.lastAgeMs) + " open_error=" + std::to_string(probe.openError));
            break;
        case GateOutcome::WriteFailed: log(head + " refused reason=zone_write_failed"); break;
        case GateOutcome::Invalid: log(head + " refused reason=zone_invalid"); break;
        }
        return false;
    }
};

FileClipboard::FileClipboard(PullHub& hub, LogFn log, ZoneOps zone)
    : impl_(std::make_unique<Impl>(hub, std::move(log), zone)) {}

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
