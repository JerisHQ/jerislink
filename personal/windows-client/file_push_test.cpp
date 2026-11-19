// Tests for file_push.hpp (F5b Mac "Send to JerisLink" into Downloads\JerisLink):
// push checks (files only, no folders, at most 1000), accept with no prompt,
// sequential REQUESTs inside the 4 MiB window, hash check before a file gets
// its name, RESULT on every end, busy, Mac refusal, cancel both ways,
// disconnect. On Windows it also runs the real folder writer in a temp
// folder: "name (2).ext" on a clash, Zone.Identifier ZoneId=3, no .jlpart
// left behind, nothing overwritten.
#include "file_push.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

using namespace jl::filepush;
namespace file = jl::file;
namespace fpull = jl::filepull;

namespace {

int gPass = 0;
int gFail = 0;

void expect(bool cond, const std::string& what) {
    if (cond) { ++gPass; std::printf("PASS %s\n", what.c_str()); }
    else { ++gFail; std::printf("FAIL %s\n", what.c_str()); }
}

class FakeDigest : public fpull::Digest {
public:
    void update(const uint8_t* d, size_t n) override {
        for (size_t i = 0; i < n; ++i) { h_ ^= d[i]; h_ *= 1099511628211ull; }
        len_ += n;
    }
    std::vector<uint8_t> finish() override { return pack(h_, len_); }
    static std::vector<uint8_t> pack(uint64_t h, uint64_t len) {
        std::vector<uint8_t> out(32, 0);
        for (int i = 0; i < 8; ++i) { out[i] = uint8_t(h >> (8 * i)); out[8 + i] = uint8_t(len >> (8 * i)); }
        return out;
    }
    static std::vector<uint8_t> of(const std::vector<uint8_t>& bytes) {
        FakeDigest d;
        d.update(bytes.data(), bytes.size());
        return d.finish();
    }
private:
    uint64_t h_ = 14695981039346656037ull;
    uint64_t len_ = 0;
};

fpull::DigestFactory fakeDigest() {
    return [] { return std::unique_ptr<fpull::Digest>(new FakeDigest()); };
}

// Records what the receiver did to the folder.
struct Folder {
    bool prepareOk = true;
    bool writeOk = true;
    std::vector<std::wstring> committed;   // names, in order
    std::vector<std::vector<uint8_t>> data;
    std::vector<uint8_t> partial;
    bool open = false;                     // a partial file exists
    int aborts = 0;
    int opened = 0;                        // Explorer shown
};

class FakeSink : public Sink {
public:
    explicit FakeSink(Folder& f) : f_(f) {}
    bool prepare() override { return f_.prepareOk; }
    bool begin(const std::wstring& name) override {
        name_ = name;
        f_.partial.clear();
        f_.open = true;
        return true;
    }
    bool write(const uint8_t* d, size_t n) override {
        if (!f_.writeOk) return false;
        f_.partial.insert(f_.partial.end(), d, d + n);
        return true;
    }
    bool commit() override {
        f_.committed.push_back(name_);
        f_.data.push_back(f_.partial);
        f_.partial.clear();
        f_.open = false;
        return true;
    }
    void abort() override {
        if (f_.open) ++f_.aborts;
        f_.partial.clear();
        f_.open = false;
    }
    void finished(uint32_t) override { ++f_.opened; }
private:
    Folder& f_;
    std::wstring name_;
};

std::vector<uint8_t> utf8(const std::string& s) { return {s.begin(), s.end()}; }

std::vector<uint8_t> bytes(size_t n, uint8_t seed) {
    std::vector<uint8_t> v(n);
    for (size_t i = 0; i < n; ++i) v[i] = uint8_t(seed + i * 7);
    return v;
}

struct Push {
    file::Offer offer;
    std::vector<file::Entry> entries;
    std::vector<std::vector<uint8_t>> contents;
};

Push makePush(uint32_t t, const std::vector<std::pair<std::string, size_t>>& files) {
    Push p;
    uint64_t total = 0;
    for (size_t i = 0; i < files.size(); ++i) {
        p.contents.push_back(bytes(files[i].second, uint8_t(i + 1)));
        p.entries.push_back({t, uint32_t(i), file::kind::kFile, files[i].second, 1700000000, utf8(files[i].first)});
        total += files[i].second;
    }
    p.offer = {t, file::purpose::kPush, uint32_t(files.size()), total};
    return p;
}

template <class T>
const T* only(const PushReceiver::Out& out) {
    return out.size() == 1 ? std::get_if<T>(&out[0]) : nullptr;
}

PushReceiver::Out offerAll(PushReceiver& r, const Push& p) {
    auto out = r.onOffer(p.offer);
    if (!out.empty()) return out;
    for (const auto& e : p.entries) {
        auto o = r.onEntry(e);
        if (!o.empty()) return o;
    }
    return {};
}

// Plays the Mac: answers every REQUEST from `p.contents` until nothing is
// asked. Returns the last messages the receiver sent.
PushReceiver::Out serveAll(PushReceiver& r, const Push& p, int* requests = nullptr, uint64_t* maxUnread = nullptr) {
    PushReceiver::Out last;
    std::vector<uint64_t> sent(p.contents.size(), 0);
    for (int guard = 0; guard < 100000; ++guard) {
        auto q = r.nextRequest();
        if (!q) break;
        if (requests) ++*requests;
        const auto& c = p.contents[q->index];
        if (q->offset != sent[q->index]) return {};
        // Answer in one go, like the host: DATA chunks, then FILE_END at the end.
        uint64_t end = std::min<uint64_t>(c.size(), q->offset + q->length);
        while (sent[q->index] < end) {
            const uint64_t n = std::min<uint64_t>(file::kMaxChunk, end - sent[q->index]);
            std::vector<uint8_t> chunk(c.begin() + std::ptrdiff_t(sent[q->index]),
                                       c.begin() + std::ptrdiff_t(sent[q->index] + n));
            last = r.onData({p.offer.transfer, q->index, sent[q->index], chunk});
            if (!last.empty()) return last;
            sent[q->index] += n;
        }
        if (maxUnread) *maxUnread = std::max<uint64_t>(*maxUnread, q->length);
        if (sent[q->index] == c.size()) {
            last = r.onFileEnd({p.offer.transfer, q->index, FakeDigest::of(c)});
            if (!last.empty()) return last;
        }
    }
    return last;
}

void checks() {
    fpull::Manifest m;
    auto p = makePush(2, {{"a.txt", 3}, {"b.bin", 0}});
    expect(checkPush(p.offer, p.entries, m).empty() && m.items.size() == 2, "check: two files ok");
    auto d = p;
    d.entries[1].kind = file::kind::kDir;
    expect(checkPush(d.offer, d.entries, m) == "kind", "check: a folder is refused");
    auto n = makePush(2, {{"dir/a.txt", 3}});
    expect(checkPush(n.offer, n.entries, m) == "nested", "check: a path with a folder is refused");
    auto t = makePush(2, {{"../a.txt", 3}});
    expect(!checkPush(t.offer, t.entries, m).empty(), "check: traversal is refused");
    auto w = makePush(2, {{"what?.txt", 3}});
    expect(checkPush(w.offer, w.entries, m).empty() && m.items[0].rel != L"what?.txt" && m.renamed == 1,
           "check: a Windows-only bad name is mapped, not refused");
    auto dup = makePush(2, {{"A.txt", 1}, {"a.txt", 1}});
    expect(checkPush(dup.offer, dup.entries, m) == "duplicate", "check: names equal on NTFS are refused");
    file::Offer big{2, file::purpose::kPush, kMaxFiles + 1, 0};
    expect(checkPush(big, {}, m) == "too_many", "check: over 1000 files is refused");
}

void happyPath() {
    Folder f;
    PushReceiver r(std::make_unique<FakeSink>(f), fakeDigest());
    auto p = makePush(4, {{"one.txt", 100}, {"empty.dat", 0}, {"big.bin", 9 * 1024 * 1024 + 5}});
    auto out = offerAll(r, p);
    const auto* ok = only<file::Reply>(out);
    expect(ok && ok->transfer == 4 && ok->status == file::status::kOk, "push: accepted with no prompt (Q1)");
    expect(r.active() && r.current() == 4 && r.progress().active && r.progress().files == 3, "push: running");
    int requests = 0;
    uint64_t maxLen = 0;
    out = serveAll(r, p, &requests, &maxLen);
    const auto* res = only<file::Result>(out);
    expect(res && res->transfer == 4 && res->status == file::status::kOk && res->filesOk == 3, "push: RESULT ok 3");
    expect(f.committed.size() == 3 && f.committed[0] == L"one.txt" && f.committed[1] == L"empty.dat" &&
               f.committed[2] == L"big.bin",
           "push: files committed in order with their names");
    expect(f.data.size() == 3 && f.data[0] == p.contents[0] && f.data[1].empty() && f.data[2] == p.contents[2],
           "push: bytes match");
    expect(f.opened == 1 && f.aborts == 0, "push: Explorer shown once, nothing aborted");
    expect(maxLen <= kRequestBytes && requests >= 10, "push: requests of at most 1 MiB");
    const auto pr = r.progress();
    expect(!r.active() && !pr.active && pr.last == Outcome::Done && pr.lastFiles == 3 && pr.pushes == 1,
           "push: idle after, outcome done");
    expect(r.rxBytes() == 100 + 9 * 1024 * 1024 + 5, "push: rx bytes counted");
    expect(!r.nextRequest(), "push: nothing more asked");
}

void window() {
    Folder f;
    PushReceiver r(std::make_unique<FakeSink>(f), fakeDigest());
    auto p = makePush(6, {{"big.bin", 10 * 1024 * 1024}});
    offerAll(r, p);
    uint64_t asked = 0;
    int n = 0;
    while (auto q = r.nextRequest()) {
        expect(q->offset == asked, "window: sequential offsets " + std::to_string(n));
        asked += q->length;
        ++n;
    }
    expect(asked == kWindowBytes, "window: at most 4 MiB asked and not received");
    r.onData({6, 0, 0, std::vector<uint8_t>(p.contents[0].begin(), p.contents[0].begin() + file::kMaxChunk)});
    auto q = r.nextRequest();
    expect(q && q->offset == kWindowBytes && q->length == file::kMaxChunk, "window: received bytes open the window");
    // Out-of-order DATA ends the push.
    auto out = r.onData({6, 0, 5, {1, 2}});
    const auto* res = only<file::Result>(out);
    expect(res && res->status == file::status::kFailed && res->filesOk == 0 && f.aborts == 1 && !r.active(),
           "window: out-of-order data fails, partial removed, RESULT failed");
}

void damaged() {
    Folder f;
    PushReceiver r(std::make_unique<FakeSink>(f), fakeDigest());
    auto p = makePush(8, {{"good.txt", 10}, {"bad.txt", 10}});
    offerAll(r, p);
    auto q = r.nextRequest();
    r.onData({8, 0, 0, p.contents[0]});
    r.onFileEnd({8, 0, FakeDigest::of(p.contents[0])});
    q = r.nextRequest();
    expect(q && q->index == 1, "hash: second file asked after the first");
    r.onData({8, 1, 0, p.contents[1]});
    auto out = r.onFileEnd({8, 1, FakeDigest::of(p.contents[0])});
    const auto* res = only<file::Result>(out);
    expect(res && res->status == file::status::kFailed && res->filesOk == 1, "hash: mismatch fails, 1 file ok");
    expect(f.committed.size() == 1 && f.aborts == 1 && f.opened == 0, "hash: damaged file never named, no Explorer");
    expect(r.progress().last == Outcome::Failed && r.lastReason() == "hash", "hash: outcome failed");
}

void refusals() {
    {
        Folder f;
        PushReceiver r(std::make_unique<FakeSink>(f), fakeDigest());
        auto p = makePush(10, {{"a", 1}});
        p.entries[0].kind = file::kind::kDir;
        p.entries[0].size = 0;
        p.offer.total = 0;
        auto out = offerAll(r, p);
        const auto* rep = only<file::Reply>(out);
        expect(rep && rep->status == file::status::kBadPath && !r.active(), "refuse: folder gets REPLY bad_path");
    }
    {
        Folder f;
        PushReceiver r(std::make_unique<FakeSink>(f), fakeDigest());
        auto out = r.onOffer({12, file::purpose::kPush, kMaxFiles + 1, 0});
        const auto* rep = only<file::Reply>(out);
        expect(rep && rep->status == file::status::kTooBig && !r.active(), "refuse: 1001 files");
        out = r.onOffer({12, file::purpose::kPush, 1, file::kMaxTotalBytes + 1});
        rep = only<file::Reply>(out);
        expect(rep && rep->status == file::status::kTooBig, "refuse: over 20 GiB");
    }
    {
        Folder f;
        f.prepareOk = false;
        PushReceiver r(std::make_unique<FakeSink>(f), fakeDigest());
        auto out = offerAll(r, makePush(14, {{"a.txt", 1}}));
        const auto* rep = only<file::Reply>(out);
        expect(rep && rep->status == file::status::kNoSpace && !r.active(), "refuse: no Downloads folder");
    }
    {
        Folder f;
        PushReceiver r(std::make_unique<FakeSink>(f), fakeDigest());
        offerAll(r, makePush(16, {{"a.txt", 1}}));
        auto out = r.onOffer({18, file::purpose::kPush, 1, 1});
        const auto* rep = only<file::Reply>(out);
        expect(rep && rep->transfer == 18 && rep->status == file::status::kBusy && r.current() == 16,
               "refuse: a second push while one runs is busy");
    }
}

void endings() {
    {
        Folder f;
        PushReceiver r(std::make_unique<FakeSink>(f), fakeDigest());
        auto p = makePush(20, {{"a.txt", 100}});
        offerAll(r, p);
        r.nextRequest();
        r.onData({20, 0, 0, {1, 2, 3}});
        auto out = r.onReply({20, file::status::kMacPermission});
        const auto* res = only<file::Result>(out);
        expect(res && res->status == file::status::kMacPermission && f.aborts == 1 && !r.active(),
               "end: Mac refused a read, partial removed, RESULT carries why");
        expect(r.onReply({20, file::status::kFailed}).empty(), "end: late reply ignored");
    }
    {
        Folder f;
        PushReceiver r(std::make_unique<FakeSink>(f), fakeDigest());
        offerAll(r, makePush(22, {{"a.txt", 100}}));
        r.nextRequest();
        r.onCancel({22, file::status::kCancelled});
        expect(!r.active() && f.aborts == 1 && r.progress().last == Outcome::Cancelled, "end: Mac cancel");
    }
    {
        Folder f;
        PushReceiver r(std::make_unique<FakeSink>(f), fakeDigest());
        offerAll(r, makePush(24, {{"a.txt", 100}}));
        auto out = r.cancel();
        const auto* c = only<file::Cancel>(out);
        expect(c && c->transfer == 24 && !r.active() && f.aborts == 1, "end: user cancel sends CANCEL");
        expect(r.cancel().empty(), "end: second cancel does nothing");
    }
    {
        Folder f;
        PushReceiver r(std::make_unique<FakeSink>(f), fakeDigest());
        offerAll(r, makePush(26, {{"a.txt", 100}}));
        r.disconnect();
        expect(!r.active() && f.aborts == 1 && r.progress().last == Outcome::Failed && r.lastReason() == "disconnected",
               "end: disconnect");
    }
    {
        Folder f;
        f.writeOk = false;
        PushReceiver r(std::make_unique<FakeSink>(f), fakeDigest());
        offerAll(r, makePush(28, {{"a.txt", 10}}));
        r.nextRequest();
        auto out = r.onData({28, 0, 0, std::vector<uint8_t>(10, 1)});
        const auto* res = only<file::Result>(out);
        expect(res && res->status == file::status::kNoSpace && !r.active(), "end: disk full");
    }
    {
        Folder f;
        PushReceiver r(std::make_unique<FakeSink>(f), fakeDigest());
        expect(r.onData({30, 0, 0, {1}}).empty() && r.onFileEnd({30, 0, {}}).empty(), "end: stray messages ignored");
    }
}

#ifdef _WIN32
std::wstring tempFolder() {
    wchar_t base[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, base);
    return std::wstring(base) + L"jl-push-test-" + std::to_wstring(GetCurrentProcessId()) + L"\\JerisLink";
}

std::vector<uint8_t> readAll(const std::wstring& path) {
    std::vector<uint8_t> out;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return out;
    uint8_t buf[65536];
    DWORD got = 0;
    while (ReadFile(h, buf, sizeof(buf), &got, nullptr) && got > 0) out.insert(out.end(), buf, buf + got);
    CloseHandle(h);
    return out;
}

// A scanner stand-in: the first look at a path ending in `heldName` opens
// it without delete sharing and keeps it open until releaseHeld().
std::wstring heldName;
HANDLE gHeld = INVALID_HANDLE_VALUE;

bool holdIfNamed(const std::wstring& path) {
    if (heldName.empty() || path.size() < heldName.size() ||
        path.compare(path.size() - heldName.size(), heldName.size(), heldName) != 0) {
        return false;
    }
    if (gHeld == INVALID_HANDLE_VALUE) {
        gHeld = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    }
    return true;
}

void releaseHeld() {
    if (gHeld != INVALID_HANDLE_VALUE) CloseHandle(gHeld);
    gHeld = INVALID_HANDLE_VALUE;
    heldName.clear();
}

// The path an open handle points at now (#60 r3: the sink checks by handle).
std::wstring pathOf(HANDLE h) {
    wchar_t buf[2048] = {};
    const DWORD n = GetFinalPathNameByHandleW(h, buf, 2048, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    return n > 0 && n < 2048 ? std::wstring(buf, n) : std::wstring();
}

bool endsWith(const std::wstring& s, const std::wstring& tail) {
    return s.size() >= tail.size() && s.compare(s.size() - tail.size(), tail.size(), tail) == 0;
}

// #60 r3 item 3: someone swaps the delivered file for another file of the
// same name just when the sink checks it. The first check of a path ending
// in \swap.exe moves the file aside to swap.exe.moved and writes a
// replacement under the name; the check reads "unmarked", so the sink takes
// its file back out. It must take out its own file, never the replacement.
const std::vector<uint8_t> kReplacement = {'n', 'o', 't', ' ', 'o', 'u', 'r', 's'};
bool gSwapTried = false;
bool gSwapped = false;

void swapOnce(const std::wstring& path) {
    if (gSwapTried) return;
    gSwapTried = true;
    std::wstring p = path;
    if (p.rfind(L"\\\\?\\", 0) == 0) p = p.substr(4);
    if (!MoveFileExW(p.c_str(), (p + L".moved").c_str(), 0)) return;
    HANDLE h = CreateFileW(p.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD w = 0;
    WriteFile(h, kReplacement.data(), DWORD(kReplacement.size()), &w, nullptr);
    CloseHandle(h);
    gSwapped = true;
}

// #60 r4 item 3: the first check under the name pinned.exe takes the
// file's staging name (another file now holds it, so the move back fails)
// and makes the file read-only (so a plain delete fails).
std::wstring gStuckPart;
bool gStuckBlocked = false;
// #60 r5: a read-only view of the file mapped here, as another program can
// map it: while it is mapped the file can be neither deleted nor cut.
HANDLE gStuckMap = nullptr;
void* gStuckView = nullptr;
// #60 r5: also take every other staging name the sink may move the file to
// (".2" to ".99"), so the file cannot leave its final name at all.
bool gStuckAllNames = false;
// #60 r5: map the file as an executable image, as Windows does for a
// program that runs, and as a scanner may: while an image section exists
// the file can be neither deleted nor cut (a plain data view still lets
// a POSIX delete through, so it does not block the delete).
bool gStuckImage = false;
DWORD gStuckMapError = 0;

bool takeName(const std::wstring& path) {
    HANDLE p = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, 0, nullptr);
    if (p == INVALID_HANDLE_VALUE) return false;
    CloseHandle(p);
    return true;
}

void blockTakeBack(HANDLE h) {
    if (gStuckBlocked) return;
    if (!takeName(gStuckPart)) return;
    if (gStuckAllNames) {
        for (int n = 2; n < 100; ++n) {
            if (!takeName(gStuckPart + L"." + std::to_wstring(n))) return;
        }
    }
    FILE_BASIC_INFO b{};
    if (!GetFileInformationByHandleEx(h, FileBasicInfo, &b, sizeof(b))) return;
    b.FileAttributes |= FILE_ATTRIBUTE_READONLY;
    if (SetFileInformationByHandle(h, FileBasicInfo, &b, sizeof(b)) == 0) return;
    if (gStuckImage) {
        const std::wstring p = pathOf(h);
        const DWORD share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
        HANDLE x = CreateFileW(p.c_str(), GENERIC_READ | GENERIC_EXECUTE, share, nullptr, OPEN_EXISTING, 0, nullptr);
        if (x == INVALID_HANDLE_VALUE) {
            gStuckMapError = GetLastError();
            return;
        }
        gStuckMap = CreateFileMappingW(x, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr);
        if (!gStuckMap) gStuckMapError = GetLastError();
        CloseHandle(x);
    } else {
        gStuckMap = CreateFileMappingW(h, nullptr, PAGE_READONLY, 0, 0, nullptr);
    }
    if (gStuckMap) gStuckView = MapViewOfFile(gStuckMap, FILE_MAP_READ, 0, 0, 0);
    if (gStuckMap && !gStuckView) gStuckMapError = GetLastError();
    gStuckBlocked = gStuckView != nullptr;
}

// #60 r5: the real size of `path`, without reading it. False when the file
// exists but cannot be opened: that is a failure, never an empty file.
bool diskSize(const std::wstring& path, bool& exists, uint64_t& size) {
    exists = false;
    size = 0;
    HANDLE h = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        const DWORD e = GetLastError();
        return e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND;
    }
    exists = true;
    LARGE_INTEGER s{};
    const bool ok = GetFileSizeEx(h, &s) != 0;
    CloseHandle(h);
    size = uint64_t(s.QuadPart);
    return ok;
}

// #60 r5: true when `path` is gone, or holds `size` bytes that are all zero
// (read with sharing, as the file may still be mapped elsewhere). A file that
// exists but cannot be read in full is a failure.
bool goneOrZeroed(const std::wstring& path, uint64_t size) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        const DWORD e = GetLastError();
        return e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND;
    }
    uint64_t seen = 0;
    bool zero = true;
    uint8_t buf[65536];
    DWORD got = 0;
    while (ReadFile(h, buf, sizeof(buf), &got, nullptr) && got > 0) {
        for (DWORD i = 0; i < got; ++i) zero = zero && buf[i] == 0;
        seen += got;
    }
    CloseHandle(h);
    return zero && seen == size;
}

// #60 r6: someone tries to open the file's Zone.Identifier stream for
// writing just before the rename to its final name (stage 0) or just after
// it, before the last check (stage 1), and to write ZoneId=0 into it.
int gUnmarkStage = -1;
int gUnmarkResult[2] = {0, 0};   // 1 = the open was refused, 2 = opened and ZoneId=0 written
DWORD gUnmarkError[2] = {0, 0};

void tryUnmark(HANDLE file, int stage) {
    if (stage != gUnmarkStage) return;
    const std::wstring p = pathOf(file) + L":Zone.Identifier";
    HANDLE z = CreateFileW(p.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, 0, nullptr);
    if (z == INVALID_HANDLE_VALUE) {
        gUnmarkResult[stage] = 1;
        gUnmarkError[stage] = GetLastError();
        return;
    }
    static const char kZero[] = "[ZoneTransfer]\r\nZoneId=0\r\n";
    DWORD w = 0;
    const bool ok = WriteFile(z, kZero, DWORD(sizeof(kZero) - 1), &w, nullptr) && SetEndOfFile(z);
    CloseHandle(z);
    gUnmarkResult[stage] = ok ? 2 : 1;
}

// #60 r6: every take-back and cleanup step the sink reports, in order.
std::vector<std::pair<std::string, bool>> gTrace;
void collectTrace(const char* step, bool ok) { gTrace.push_back({step, ok}); }
// 1 = the step ran and worked, 0 = it ran and failed, -1 = it did not run.
int traced(const char* step) {
    for (const auto& t : gTrace) {
        if (t.first == step) return t.second ? 1 : 0;
    }
    return -1;
}

// #60 r6: the check under gBranchName's final name reads unmarked; the
// first time, the staging name (gBranchNames 1) or every staging name the
// sink may move the file to (gBranchNames 2) is taken first.
std::wstring gBranchName;
std::wstring gBranchPart;
int gBranchNames = 0;
bool gBranchTaken = false;

int branchRead(HANDLE h) {
    if (!endsWith(pathOf(h), L"\\" + gBranchName)) return fpull::readZoneIdOn(h);
    if (!gBranchTaken) {
        gBranchTaken = true;
        if (gBranchNames >= 1) takeName(gBranchPart);
        if (gBranchNames >= 2) {
            for (int n = 2; n < 100; ++n) takeName(gBranchPart + L"." + std::to_wstring(n));
        }
    }
    return -1;
}

fpull::ZoneWrite branchWrite(HANDLE h) {
    return endsWith(pathOf(h), L"\\" + gBranchName) ? fpull::ZoneWrite::Failed : fpull::writeInternetZoneOn(h);
}

void clearStaging(const std::wstring& dir, const std::wstring& name) {
    const std::wstring staging = dir + L"\\.jlstaging\\";
    WIN32_FIND_DATAW fd{};
    HANDLE f = FindFirstFileW((staging + name + L".jlpart*").c_str(), &fd);
    if (f == INVALID_HANDLE_VALUE) return;
    do {
        SetFileAttributesW((staging + fd.cFileName).c_str(), FILE_ATTRIBUTE_NORMAL);
        DeleteFileW((staging + fd.cFileName).c_str());
    } while (FindNextFileW(f, &fd));
    FindClose(f);
}

int countIn(const std::wstring& folder, const wchar_t* pattern) {
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW((folder + L"\\" + pattern).c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    int n = 0;
    do { ++n; } while (FindNextFileW(h, &fd));
    FindClose(h);
    return n;
}

int countParts(const std::wstring& folder) {
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW((folder + L"\\*.jlpart").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    int n = 0;
    do { ++n; } while (FindNextFileW(h, &fd));
    FindClose(h);
    return n;
}

// #60 r7: someone tries to remove the file's Zone.Identifier stream (an
// open of the stream with delete access, then delete-on-close) just before
// the rename to its final name (stage 0) or just after it (stage 1).
int gUnlinkStage = -1;
int gUnlinkResult[2] = {0, 0};   // 1 = refused, 2 = the stream was opened with delete access and marked for deletion
DWORD gUnlinkError[2] = {0, 0};

void tryUnlink(HANDLE file, int stage) {
    if (stage != gUnlinkStage) return;
    const std::wstring p = pathOf(file) + L":Zone.Identifier";
    HANDLE z = CreateFileW(p.c_str(), DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, 0, nullptr);
    if (z == INVALID_HANDLE_VALUE) {
        gUnlinkResult[stage] = 1;
        gUnlinkError[stage] = GetLastError();
        return;
    }
    FILE_DISPOSITION_INFO del{};
    del.DeleteFile = TRUE;
    const bool ok = SetFileInformationByHandle(z, FileDispositionInfo, &del, sizeof(del)) != 0;
    if (!ok) gUnlinkError[stage] = GetLastError();
    CloseHandle(z);
    gUnlinkResult[stage] = ok ? 2 : 1;
}

// #60 r7: whether another program could open `path`'s Zone.Identifier for
// writing (1) or with delete access (2) right now; 0 when both are refused.
int zoneOpenable(const std::wstring& path) {
    const std::wstring p = path + L":Zone.Identifier";
    const DWORD all = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    int r = 0;
    HANDLE w = CreateFileW(p.c_str(), GENERIC_WRITE, all, nullptr, OPEN_EXISTING, 0, nullptr);
    if (w != INVALID_HANDLE_VALUE) {
        r |= 1;
        CloseHandle(w);
    }
    HANDLE d = CreateFileW(p.c_str(), DELETE, all, nullptr, OPEN_EXISTING, 0, nullptr);
    if (d != INVALID_HANDLE_VALUE) {
        r |= 2;
        CloseHandle(d);
    }
    return r;
}

// #60 r7: the file named gIsoName cannot be taken back at all: every
// staging name is taken, it is mapped as an image (no delete, no cut) and
// another handle holds an exclusive lock on all of it (no zero-fill).
std::wstring gIsoName;
HANDLE gIsoLock = INVALID_HANDLE_VALUE;
bool gIsoLocked = false;

int isoRead(HANDLE h) {
    if (!endsWith(pathOf(h), L"\\" + gIsoName)) return fpull::readZoneIdOn(h);
    if (!gStuckBlocked) {
        blockTakeBack(h);
        gIsoLock = CreateFileW(pathOf(h).c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, 0, nullptr);
        OVERLAPPED at{};
        gIsoLocked = gIsoLock != INVALID_HANDLE_VALUE &&
                     LockFileEx(gIsoLock, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, MAXDWORD, MAXDWORD, &at);
    }
    return -1;
}

// #60 r7 probe (printed, not asserted): how NTFS applies delete sharing
// between a file's main stream and its Zone.Identifier stream.
using NtSetInfoFn = LONG(NTAPI*)(HANDLE, PVOID, PVOID, ULONG, ULONG);
LONG ntLink(HANDLE h, const std::wstring& target) {
    static const auto fn = reinterpret_cast<NtSetInfoFn>(
        reinterpret_cast<void*>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationFile")));
    const std::wstring nt = L"\\??\\" + target;
    const size_t bytes = nt.size() * sizeof(wchar_t);
    std::vector<uint8_t> buf(sizeof(FILE_RENAME_INFO) + bytes, 0);
    auto* info = reinterpret_cast<FILE_RENAME_INFO*>(buf.data());
    info->FileNameLength = DWORD(bytes);
    std::memcpy(info->FileName, nt.data(), bytes);
    ULONG_PTR io[2] = {};
    return fn ? fn(h, io, info, ULONG(buf.size()), 11 /* FileLinkInformation */) : -1;
}

unsigned long openErr(const std::wstring& p, DWORD access, DWORD share, HANDLE* keep = nullptr) {
    HANDLE h = CreateFileW(p.c_str(), access, share, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return GetLastError();
    if (keep) *keep = h;
    else CloseHandle(h);
    return 0;
}

void sharingProbe(const std::wstring& dir) {
    const DWORD R = FILE_SHARE_READ, RD = FILE_SHARE_READ | FILE_SHARE_DELETE,
                ALL = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    auto mk = [&](const std::wstring& n) {
        const std::wstring p = dir + L"\\" + n;
        HANDLE f = CreateFileW(p.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
        DWORD w = 0;
        WriteFile(f, "data", 4, &w, nullptr);
        CloseHandle(f);
        HANDLE z = CreateFileW((p + L":Zone.Identifier").c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
        static const char k3[] = "[ZoneTransfer]\r\nZoneId=3\r\n";
        WriteFile(z, k3, DWORD(sizeof(k3) - 1), &w, nullptr);
        CloseHandle(z);
        return p;
    };
    // A: main open with delete access, sharing read only (the r6 .jlpart).
    {
        const std::wstring p = mk(L"probeA.bin");
        const std::wstring zs = p + L":Zone.Identifier";
        HANDLE h = CreateFileW(p.c_str(), GENERIC_READ | GENERIC_WRITE | DELETE, R, nullptr, OPEN_EXISTING, 0, nullptr);
        HANDLE z = INVALID_HANDLE_VALUE;
        const unsigned long a1 = openErr(zs, GENERIC_READ, R);
        const unsigned long a2 = openErr(zs, GENERIC_READ, RD, &z);
        const unsigned long a3 = openErr(zs, DELETE, ALL);
        const unsigned long a4 = openErr(p, DELETE, ALL);
        std::printf("  r7 probe A (main RW+DELETE share R, h=%d): zone R/shareR=%lu zone R/shareRD=%lu "
                    "other zone DELETE=%lu other main DELETE=%lu\n",
                    int(h != INVALID_HANDLE_VALUE), a1, a2, a3, a4);
        if (z != INVALID_HANDLE_VALUE) CloseHandle(z);
        CloseHandle(h);
    }
    // B: main open without delete access, sharing read only; the zone
    // stream held with no write or delete sharing.
    {
        const std::wstring p = mk(L"probeB.bin");
        const std::wstring zs = p + L":Zone.Identifier";
        HANDLE h = CreateFileW(p.c_str(), GENERIC_READ | GENERIC_WRITE, R, nullptr, OPEN_EXISTING, 0, nullptr);
        HANDLE z = INVALID_HANDLE_VALUE;
        const unsigned long b1 = openErr(zs, GENERIC_READ, R, &z);
        const unsigned long b2 = openErr(zs, DELETE, ALL);
        const unsigned long b3 = openErr(zs, GENERIC_WRITE, ALL);
        const unsigned long b4 = openErr(p, DELETE, ALL);
        const LONG b5 = ntLink(h, dir + L"\\probeB-final.bin");
        const unsigned long b6 = openErr(dir + L"\\probeB-final.bin:Zone.Identifier", DELETE, ALL);
        const unsigned long b7 = openErr(dir + L"\\probeB-final.bin", DELETE, ALL);
        if (z != INVALID_HANDLE_VALUE) CloseHandle(z);
        const unsigned long b8 = openErr(dir + L"\\probeB-final.bin", DELETE, ALL);
        std::printf("  r7 probe B (main RW share R, h=%d): hold zone R/shareR=%lu other zone DELETE=%lu "
                    "other zone WRITE=%lu other main DELETE=%lu link=0x%08lx final zone DELETE=%lu final main DELETE=%lu "
                    "after zone closed final main DELETE=%lu\n",
                    int(h != INVALID_HANDLE_VALUE), b1, b2, b3, b4, (unsigned long)b5, b6, b7, b8);
        CloseHandle(h);
        DeleteFileW((dir + L"\\probeB-final.bin").c_str());
    }
    // C: as B, but the main handle shares read and delete.
    {
        const std::wstring p = mk(L"probeC.bin");
        const std::wstring zs = p + L":Zone.Identifier";
        HANDLE h = CreateFileW(p.c_str(), GENERIC_READ | GENERIC_WRITE, RD, nullptr, OPEN_EXISTING, 0, nullptr);
        HANDLE z = INVALID_HANDLE_VALUE;
        const unsigned long c1 = openErr(zs, GENERIC_READ, R, &z);
        const unsigned long c2 = openErr(p, DELETE, ALL);
        const unsigned long c3 = openErr(zs, DELETE, ALL);
        if (z != INVALID_HANDLE_VALUE) CloseHandle(z);
        const unsigned long c4 = openErr(p, DELETE, ALL);
        std::printf("  r7 probe C (main RW share RD, h=%d): hold zone R/shareR=%lu other main DELETE=%lu "
                    "other zone DELETE=%lu after zone closed other main DELETE=%lu\n",
                    int(h != INVALID_HANDLE_VALUE), c1, c2, c3, c4);
        CloseHandle(h);
    }
    DeleteFileW((dir + L"\\probeA.bin").c_str());
    DeleteFileW((dir + L"\\probeB.bin").c_str());
    DeleteFileW((dir + L"\\probeC.bin").c_str());
}

void realFolder() {
    const std::wstring dir = tempFolder();
    std::vector<std::wstring> opened;
    const auto run = [&](uint32_t t, const Push& p) {
        PushReceiver r(makeFolderSink(dir, [&](const std::wstring& d) { opened.push_back(d); }),
                       fpull::sha256Digest());
        auto out = offerAll(r, p);
        const auto* ok = only<file::Reply>(out);
        if (!ok || ok->status != file::status::kOk) return PushReceiver::Out{};
        // The real digest: FILE_END carries the SHA-256 the receiver computes too.
        PushReceiver::Out last;
        std::vector<uint64_t> sent(p.contents.size(), 0);
        while (auto q = r.nextRequest()) {
            const auto& c = p.contents[q->index];
            const uint64_t end = std::min<uint64_t>(c.size(), q->offset + q->length);
            if (end > sent[q->index]) {
                last = r.onData({t, q->index, sent[q->index],
                                 std::vector<uint8_t>(c.begin() + std::ptrdiff_t(sent[q->index]),
                                                      c.begin() + std::ptrdiff_t(end))});
                if (!last.empty()) return last;
                sent[q->index] = end;
            }
            if (sent[q->index] == c.size()) {
                auto d = fpull::sha256Digest()();
                d->update(c.data(), c.size());
                last = r.onFileEnd({t, q->index, d->finish()});
                if (!last.empty()) return last;
            }
        }
        return last;
    };
    auto p = makePush(40, {{"report.pdf", 70000}, {"notes", 5}, {".profile", 0}});
    auto out = run(40, p);
    const auto* res = only<file::Result>(out);
    expect(res && res->status == file::status::kOk && res->filesOk == 3, "folder: first push done");
    expect(readAll(dir + L"\\report.pdf") == p.contents[0] && readAll(dir + L"\\notes") == p.contents[1],
           "folder: files written with their names");
    expect(fpull::readZoneId(dir + L"\\report.pdf") == 3 && fpull::readZoneId(dir + L"\\.profile") == 3,
           "folder: Zone.Identifier ZoneId=3");
    // Same names again: nothing is overwritten.
    auto p2 = makePush(42, {{"report.pdf", 10}, {"notes", 6}, {".profile", 1}});
    out = run(42, p2);
    res = only<file::Result>(out);
    expect(res && res->status == file::status::kOk, "folder: second push done");
    expect(readAll(dir + L"\\report.pdf") == p.contents[0], "folder: first file kept");
    expect(readAll(dir + L"\\report (2).pdf") == p2.contents[0] && readAll(dir + L"\\notes (2)") == p2.contents[1] &&
               readAll(dir + L"\\.profile (2)") == p2.contents[2],
           "folder: clash names name (2).ext, notes (2), .profile (2)");
    out = run(44, makePush(44, {{"report.pdf", 1}}));
    expect(GetFileAttributesW((dir + L"\\report (3).pdf").c_str()) != INVALID_FILE_ATTRIBUTES, "folder: then (3)");
    expect(fpull::readZoneId(dir + L"\\report (2).pdf") == 3, "folder: clash file marked too");
    expect(countParts(dir) == 0, "folder: no .jlpart left after success");
    expect(opened.size() == 3 && opened[0] == dir, "folder: Explorer asked to show the folder each time");
    // A damaged file leaves nothing behind.
    {
        PushReceiver r(makeFolderSink(dir, [&](const std::wstring& d) { opened.push_back(d); }), fpull::sha256Digest());
        auto bad = makePush(46, {{"broken.bin", 1000}});
        offerAll(r, bad);
        r.nextRequest();
        r.onData({46, 0, 0, bad.contents[0]});
        out = r.onFileEnd({46, 0, std::vector<uint8_t>(32, 0)});
        res = only<file::Result>(out);
        expect(res && res->status == file::status::kFailed, "folder: bad hash fails");
        expect(GetFileAttributesW((dir + L"\\broken.bin").c_str()) == INVALID_FILE_ATTRIBUTES && countParts(dir) == 0,
               "folder: bad file not named, .jlpart removed");
    }
    // F5b r3 (hand test item 6): an .exe gets the mark too, and the
    // receiver counts it for the log.
    {
        PushReceiver r(makeFolderSink(dir, {}), fpull::sha256Digest());
        auto exe = makePush(50, {{"setup.exe", 4096}, {"tool.exe", 0}});
        offerAll(r, exe);
        PushReceiver::Out last;
        std::vector<uint64_t> sent(exe.contents.size(), 0);
        while (auto q = r.nextRequest()) {
            const auto& c = exe.contents[q->index];
            const uint64_t end = std::min<uint64_t>(c.size(), q->offset + q->length);
            if (end > sent[q->index]) {
                last = r.onData({50, q->index, sent[q->index],
                                 std::vector<uint8_t>(c.begin() + std::ptrdiff_t(sent[q->index]),
                                                      c.begin() + std::ptrdiff_t(end))});
                if (!last.empty()) break;
                sent[q->index] = end;
            }
            if (sent[q->index] == c.size()) {
                auto d = fpull::sha256Digest()();
                d->update(c.data(), c.size());
                last = r.onFileEnd({50, q->index, d->finish()});
                if (!last.empty()) break;
            }
        }
        const auto* res = only<file::Result>(last);
        expect(res && res->status == file::status::kOk && res->filesOk == 2, "folder: .exe push done");
        expect(fpull::readZoneId(dir + L"\\setup.exe") == 3 && fpull::readZoneId(dir + L"\\tool.exe") == 3,
               "folder: pushed .exe files carry ZoneId=3");
        const auto z = r.zoneCounts();
        expect(z.marked == 2 && z.failed == 0, "folder: zone counts marked=2 failed=0");
    }
    // #53: on a volume without streams (FAT, exFAT) ZoneId=3 cannot be
    // written. The file is not delivered: the push fails, nothing is left.
    {
        fpull::ZoneOps noStreams;
        noStreams.write = [](const std::wstring&) { return fpull::ZoneWrite::Failed; };
        noStreams.read = [](const std::wstring&) { return -1; };
        noStreams.writeOn = [](HANDLE) { return fpull::ZoneWrite::Failed; };
        noStreams.readOn = [](HANDLE) { return -1; };
        PushReceiver r(makeFolderSink(dir, {}, noStreams), fpull::sha256Digest());
        auto nm = makePush(54, {{"nomark.exe", 2048}});
        offerAll(r, nm);
        r.nextRequest();
        r.onData({54, 0, 0, nm.contents[0]});
        auto d = fpull::sha256Digest()();
        d->update(nm.contents[0].data(), nm.contents[0].size());
        const auto endOut = r.onFileEnd({54, 0, d->finish()});
        const auto* nres = only<file::Result>(endOut);
        expect(nres && nres->status != file::status::kOk && nres->filesOk == 0,
               "folder: push fails when ZoneId=3 cannot be written (#53)");
        expect(GetFileAttributesW((dir + L"\\nomark.exe").c_str()) == INVALID_FILE_ATTRIBUTES && countParts(dir) == 0 &&
                   countParts(dir + L"\\.jlstaging") == 0,
               "folder: a file without ZoneId=3 is not delivered, no .jlpart left (#53)");
        expect(r.lastReason() == "motw", "folder: failure reason motw (#53)");
        expect(r.zoneCounts().failed == 1 && r.zoneCounts().marked == 0, "folder: zone counts marked=0 failed=1 (#53)");
    }
    // #53 r2: a scanner holds the file (no delete sharing) just when the
    // sink checks or cleans it. The cleanup is kept and retried, so once the
    // holder lets go nothing unverified is left in the folder.
    {
        heldName = L"held.exe";
        fpull::ZoneOps afterRename;   // the part is marked; the final name reads unmarked
        afterRename.write = [](const std::wstring&) { return fpull::ZoneWrite::Written; };
        afterRename.read = [](const std::wstring& p) { return holdIfNamed(p) ? -1 : 3; };
        afterRename.writeOn = fpull::writeInternetZoneOn;   // #60 r6: a real mark, held through the rename
        afterRename.readOn = [](HANDLE h) { return holdIfNamed(pathOf(h)) ? -1 : 3; };
        {
            PushReceiver r(makeFolderSink(dir, {}, afterRename), fpull::sha256Digest());
            auto hp = makePush(55, {{"held.exe", 2048}});
            offerAll(r, hp);
            r.nextRequest();
            r.onData({55, 0, 0, hp.contents[0]});
            auto d = fpull::sha256Digest()();
            d->update(hp.contents[0].data(), hp.contents[0].size());
            const auto hresOut = r.onFileEnd({55, 0, d->finish()});   // kept alive for the pointer (#60 r4)
            const auto* hres = only<file::Result>(hresOut);
            expect(hres && hres->status != file::status::kOk && hres->filesOk == 0,
                   "folder: a file that fails the check after the rename is not delivered (#53)");
            releaseHeld();
        }
        expect(GetFileAttributesW((dir + L"\\held.exe").c_str()) == INVALID_FILE_ATTRIBUTES && countParts(dir) == 0,
               "folder: a file that failed the check is not left in the folder once its holder lets go (#53)");
    }
    {
        heldName = L"stuck.exe.jlpart";
        fpull::ZoneOps partHeld;      // no mark possible, and the part is held
        partHeld.write = [](const std::wstring&) { return fpull::ZoneWrite::Failed; };
        partHeld.read = [](const std::wstring& p) { holdIfNamed(p); return -1; };
        partHeld.writeOn = [](HANDLE) { return fpull::ZoneWrite::Failed; };
        partHeld.readOn = [](HANDLE h) { holdIfNamed(pathOf(h)); return -1; };
        {
            PushReceiver r(makeFolderSink(dir, {}, partHeld), fpull::sha256Digest());
            auto sp = makePush(56, {{"stuck.exe", 2048}});
            offerAll(r, sp);
            r.nextRequest();
            r.onData({56, 0, 0, sp.contents[0]});
            auto d = fpull::sha256Digest()();
            d->update(sp.contents[0].data(), sp.contents[0].size());
            const auto sresOut = r.onFileEnd({56, 0, d->finish()});   // kept alive for the pointer (#60 r4)
            const auto* sres = only<file::Result>(sresOut);
            expect(sres && sres->status != file::status::kOk, "folder: an unmarkable held part fails the push (#53)");
            releaseHeld();
        }
        expect(countParts(dir) == 0 && countParts(dir + L"\\.jlstaging") == 0 &&
                   GetFileAttributesW((dir + L"\\stuck.exe").c_str()) == INVALID_FILE_ATTRIBUTES,
               "folder: a .jlpart that could not be deleted at once is removed later, not forgotten (#53)");
    }
    // #60 r3 item 3: the file is swapped for another of the same name while
    // the sink checks it under its final name. The replacement stays.
    {
        fpull::ZoneOps swapping;
        swapping.read = [](const std::wstring& p) {
            if (!endsWith(p, L"\\swap.exe")) return fpull::readZoneId(p);
            swapOnce(p);
            return -1;
        };
        swapping.write = [](const std::wstring& p) {
            return endsWith(p, L"\\swap.exe") ? fpull::ZoneWrite::Failed : fpull::writeInternetZone(p);
        };
        swapping.readOn = [](HANDLE h) {
            const std::wstring p = pathOf(h);
            if (!endsWith(p, L"\\swap.exe")) return fpull::readZoneIdOn(h);
            swapOnce(p);
            return -1;
        };
        swapping.writeOn = [](HANDLE h) {
            return endsWith(pathOf(h), L"\\swap.exe") ? fpull::ZoneWrite::Failed : fpull::writeInternetZoneOn(h);
        };
        PushReceiver r(makeFolderSink(dir, {}, swapping), fpull::sha256Digest());
        auto sw = makePush(57, {{"swap.exe", 3000}});
        offerAll(r, sw);
        r.nextRequest();
        r.onData({57, 0, 0, sw.contents[0]});
        auto d = fpull::sha256Digest()();
        d->update(sw.contents[0].data(), sw.contents[0].size());
        const auto wresOut = r.onFileEnd({57, 0, d->finish()});   // kept alive for the pointer (#60 r4)
        const auto* wres = only<file::Result>(wresOut);
        const std::wstring target = dir + L"\\swap.exe";
        std::printf("  swap: tried=%d swapped=%d exists=%d\n", int(gSwapTried), int(gSwapped),
                    int(GetFileAttributesW(target.c_str()) != INVALID_FILE_ATTRIBUTES));
        expect(wres && wres->status != file::status::kOk, "folder: a file that fails the check under its name is not delivered");
        expect(gSwapTried, "folder: the swap test reached the check under the final name");
        expect(gSwapped ? readAll(target) == kReplacement : GetFileAttributesW(target.c_str()) == INVALID_FILE_ATTRIBUTES,
               "folder: taking a failed file back out never moves or deletes a same-name replacement (#60 r3)");
        DeleteFileW(target.c_str());
        DeleteFileW((target + L".moved").c_str());
    }
    // #60 r4 item 3: the check under the final name fails, and taking the
    // file back out fails both ways: its staging name is taken meanwhile and
    // it was made read-only. It must not stay in the folder under its final
    // name with its bytes, unmarked. #60 r5: the file is also mapped
    // elsewhere, so it can be neither deleted nor cut (both results checked).
    {
        gStuckPart = dir + L"\\.jlstaging\\pinned.exe.jlpart";
        fpull::ZoneOps stuck;
        stuck.readOn = [](HANDLE h) {
            if (!endsWith(pathOf(h), L"\\pinned.exe")) return fpull::readZoneIdOn(h);
            blockTakeBack(h);
            return -1;
        };
        stuck.writeOn = [](HANDLE h) {
            return endsWith(pathOf(h), L"\\pinned.exe") ? fpull::ZoneWrite::Failed : fpull::writeInternetZoneOn(h);
        };
        const std::wstring target = dir + L"\\pinned.exe";
        {
            PushReceiver r(makeFolderSink(dir, {}, stuck), fpull::sha256Digest());
            auto pp = makePush(58, {{"pinned.exe", 3000}});
            offerAll(r, pp);
            r.nextRequest();
            r.onData({58, 0, 0, pp.contents[0]});
            auto d = fpull::sha256Digest()();
            d->update(pp.contents[0].data(), pp.contents[0].size());
            const auto presOut = r.onFileEnd({58, 0, d->finish()});
            const auto* pres = only<file::Result>(presOut);
            expect(pres && pres->status != file::status::kOk, "folder: a file whose take-back fails is not delivered (#60 r4)");
        }
        bool exists = false;
        uint64_t onDisk = 0;
        const bool known = diskSize(target, exists, onDisk);
        std::printf("  take-back: blocked=%d known=%d exists=%d size=%llu zone=%d\n", int(gStuckBlocked), int(known),
                    int(exists), (unsigned long long)onDisk, fpull::readZoneId(target));
        expect(gStuckBlocked, "folder: the take-back test blocked the move back and mapped the file");
        expect(known && (!exists || onDisk == 0),
               "folder: when the move back, the delete and the cut all fail, the file's bytes do not stay under its final name (#60 r5)");
        if (gStuckView) UnmapViewOfFile(gStuckView);
        if (gStuckMap) CloseHandle(gStuckMap);
        gStuckView = nullptr;
        gStuckMap = nullptr;
        SetFileAttributesW(target.c_str(), FILE_ATTRIBUTE_NORMAL);
        DeleteFileW(target.c_str());
        // The staging name taken by the test, and wherever r5 moved the file.
        const std::wstring staging = dir + L"\\.jlstaging\\";
        WIN32_FIND_DATAW fd{};
        HANDLE f = FindFirstFileW((staging + L"pinned.exe.jlpart*").c_str(), &fd);
        if (f != INVALID_HANDLE_VALUE) {
            do {
                SetFileAttributesW((staging + fd.cFileName).c_str(), FILE_ATTRIBUTE_NORMAL);
                DeleteFileW((staging + fd.cFileName).c_str());
            } while (FindNextFileW(f, &fd));
            FindClose(f);
        }
    }
    // #60 r5: as above, but every staging name is taken too, so the file
    // cannot leave its final name; it is a real program (this test's own
    // .exe) mapped as an image, so it can be neither deleted nor cut. Its
    // bytes must not stay under its final name.
    {
        gStuckPart = dir + L"\\.jlstaging\\pinned2.exe.jlpart";
        gStuckBlocked = false;
        gStuckAllNames = true;
        gStuckImage = true;
        gStuckMapError = 0;
        gTrace.clear();
        gTakeOutTrace = collectTrace;
        fpull::ZoneOps stuck;
        stuck.readOn = [](HANDLE h) {
            if (!endsWith(pathOf(h), L"\\pinned2.exe")) return fpull::readZoneIdOn(h);
            blockTakeBack(h);
            return -1;
        };
        stuck.writeOn = [](HANDLE h) {
            return endsWith(pathOf(h), L"\\pinned2.exe") ? fpull::ZoneWrite::Failed : fpull::writeInternetZoneOn(h);
        };
        const std::wstring target = dir + L"\\pinned2.exe";
        {
            PushReceiver r(makeFolderSink(dir, {}, stuck), fpull::sha256Digest());
            wchar_t self[MAX_PATH] = {};
            GetModuleFileNameW(nullptr, self, MAX_PATH);
            const std::vector<uint8_t> image = readAll(self);
            auto pp = makePush(59, {{"pinned2.exe", image.size()}});
            pp.contents[0] = image;
            offerAll(r, pp);
            PushReceiver::Out presOut;
            uint64_t sent = 0;
            while (presOut.empty()) {
                auto q = r.nextRequest();
                if (!q || q->offset != sent) break;
                const uint64_t end = std::min<uint64_t>(image.size(), q->offset + q->length);
                while (presOut.empty() && sent < end) {
                    const uint64_t n = std::min<uint64_t>(file::kMaxChunk, end - sent);
                    presOut = r.onData({59, 0, sent, std::vector<uint8_t>(image.begin() + std::ptrdiff_t(sent),
                                                                         image.begin() + std::ptrdiff_t(sent + n))});
                    sent += n;
                }
                if (presOut.empty() && sent == image.size()) {
                    auto d = fpull::sha256Digest()();
                    d->update(image.data(), image.size());
                    presOut = r.onFileEnd({59, 0, d->finish()});
                }
            }
            std::printf("  stuck in place: image=%zu bytes sent=%llu\n", image.size(), (unsigned long long)sent);
            const auto* pres = only<file::Result>(presOut);
            expect(pres && pres->status != file::status::kOk,
                   "folder: a file that cannot leave its final name is not delivered (#60 r5)");
        }
        bool exists = false;
        uint64_t onDisk = 0;
        const bool known = diskSize(target, exists, onDisk);
        const bool blank = known && goneOrZeroed(target, onDisk);
        std::printf("  stuck in place: blocked=%d maperr=%lu known=%d exists=%d size=%llu blank=%d\n",
                    int(gStuckBlocked), (unsigned long)gStuckMapError, int(known), int(exists),
                    (unsigned long long)onDisk, int(blank));
        gTakeOutTrace = nullptr;
        expect(gStuckBlocked, "folder: the stuck-in-place test took every staging name and mapped the file as an image");
        // #60 r6: the zero-fill branch is proven taken: the sink's own
        // results show the move back, every other staging name and the cut
        // all failed before it zeroed the file.
        expect(traced("back") == 0, "folder: take-back branch 4 (zero): the move back to its staging name failed (#60 r6)");
        expect(traced("aside") == 0, "folder: take-back branch 4 (zero): every other staging name failed (#60 r6)");
        expect(traced("cut") == 0, "folder: take-back branch 4 (zero): the cut failed (image section) (#60 r6)");
        expect(traced("zero") == 1, "folder: take-back branch 4 (zero): the bytes were overwritten with zeros (#60 r6)");
        expect(blank,
               "folder: a file that can neither leave its final name, be deleted nor be cut has its bytes zeroed (#60 r5)");
        if (gStuckView) UnmapViewOfFile(gStuckView);
        if (gStuckMap) CloseHandle(gStuckMap);
        gStuckView = nullptr;
        gStuckMap = nullptr;
        gStuckAllNames = false;
        gStuckImage = false;
        SetFileAttributesW(target.c_str(), FILE_ATTRIBUTE_NORMAL);
        DeleteFileW(target.c_str());
        const std::wstring staging = dir + L"\\.jlstaging\\";
        WIN32_FIND_DATAW fd{};
        HANDLE f = FindFirstFileW((staging + L"pinned2.exe.jlpart*").c_str(), &fd);
        if (f != INVALID_HANDLE_VALUE) {
            do {
                SetFileAttributesW((staging + fd.cFileName).c_str(), FILE_ATTRIBUTE_NORMAL);
                DeleteFileW((staging + fd.cFileName).c_str());
            } while (FindNextFileW(f, &fd));
            FindClose(f);
        }
    }
    // #60 r6 item 1: the mark is held from the staging check through the
    // rename and the last check: nobody can open the Zone.Identifier stream
    // for writing in between, and the file is delivered with ZoneId=3.
    for (int stage = 0; stage < 2; ++stage) {
        const std::string leaf = stage == 0 ? "guard0.exe" : "guard1.exe";
        const std::wstring target = dir + L"\\" + std::wstring(leaf.begin(), leaf.end());
        gUnmarkStage = stage;
        gPublishHook = tryUnmark;
        PushReceiver::Out out;
        {
            PushReceiver r(makeFolderSink(dir, {}), fpull::sha256Digest());
            auto gp = makePush(70 + uint32_t(stage), {{leaf, 2048}});
            offerAll(r, gp);
            r.nextRequest();
            r.onData({70 + uint32_t(stage), 0, 0, gp.contents[0]});
            auto d = fpull::sha256Digest()();
            d->update(gp.contents[0].data(), gp.contents[0].size());
            out = r.onFileEnd({70 + uint32_t(stage), 0, d->finish()});
        }
        gPublishHook = nullptr;
        gUnmarkStage = -1;
        const auto* res = only<file::Result>(out);
        const int zone = fpull::readZoneId(target);
        std::printf("  publish window stage %d: unmark=%d err=%lu ok=%d zone=%d\n", stage, gUnmarkResult[stage],
                    (unsigned long)gUnmarkError[stage], int(res && res->status == file::status::kOk), zone);
        expect(gUnmarkResult[stage] == 1,
               stage == 0 ? "folder: between the staging check and the rename nobody can open the file's Zone.Identifier for writing (#60 r6)"
                          : "folder: between the rename and the last check nobody can open the file's Zone.Identifier for writing (#60 r6)");
        expect(res && res->status == file::status::kOk && zone == 3,
               stage == 0 ? "folder: a file whose mark someone tries to change before the rename is delivered with ZoneId=3 (#60 r6)"
                          : "folder: a file whose mark someone tries to change after the rename is delivered with ZoneId=3 (#60 r6)");
        DeleteFileW(target.c_str());
    }
    // #60 r6 item 2: each take-back branch on its own. The check under the
    // final name reads unmarked; the sink's own result for every step is
    // asserted, so each branch is shown taken, and the steps before it shown
    // to have failed. (Branch 4, the zero-fill, is the stuck-in-place test.)
    for (int names = 0; names < 3; ++names) {
        const std::string leaf = "branch" + std::to_string(names + 1) + ".exe";
        gBranchName = std::wstring(leaf.begin(), leaf.end());
        gBranchPart = dir + L"\\.jlstaging\\" + gBranchName + L".jlpart";
        gBranchNames = names;
        gBranchTaken = false;
        gTrace.clear();
        gTakeOutTrace = collectTrace;
        fpull::ZoneOps branch;
        branch.readOn = branchRead;
        branch.writeOn = branchWrite;
        PushReceiver::Out out;
        {
            PushReceiver r(makeFolderSink(dir, {}, branch), fpull::sha256Digest());
            auto bp = makePush(72 + uint32_t(names), {{leaf, 3000}});
            offerAll(r, bp);
            r.nextRequest();
            r.onData({72 + uint32_t(names), 0, 0, bp.contents[0]});
            auto d = fpull::sha256Digest()();
            d->update(bp.contents[0].data(), bp.contents[0].size());
            out = r.onFileEnd({72 + uint32_t(names), 0, d->finish()});
        }
        gTakeOutTrace = nullptr;
        const auto* res = only<file::Result>(out);
        const std::wstring target = dir + L"\\" + gBranchName;
        bool exists = false;
        uint64_t onDisk = 0;
        const bool known = diskSize(target, exists, onDisk);
        std::printf("  branch %d: taken=%d back=%d aside=%d cut=%d zero=%d exists=%d size=%llu\n", names + 1,
                    int(gBranchTaken), traced("back"), traced("aside"), traced("cut"), traced("zero"), int(exists),
                    (unsigned long long)onDisk);
        expect(gBranchTaken && res && res->status != file::status::kOk,
               "folder: take-back branch " + std::to_string(names + 1) + ": the check under the final name failed and the file is not delivered (#60 r6)");
        if (names == 0) {
            expect(traced("back") == 1, "folder: take-back branch 1 (back): the file moved back to its staging name (#60 r6)");
        } else if (names == 1) {
            expect(traced("back") == 0, "folder: take-back branch 2 (aside): the move back to its staging name failed (#60 r6)");
            expect(traced("aside") == 1, "folder: take-back branch 2 (aside): the file moved to another staging name (#60 r6)");
        } else {
            expect(traced("back") == 0, "folder: take-back branch 3 (cut): the move back to its staging name failed (#60 r6)");
            expect(traced("aside") == 0, "folder: take-back branch 3 (cut): every other staging name failed (#60 r6)");
            expect(traced("cut") == 1, "folder: take-back branch 3 (cut): the file was cut to zero bytes (#60 r6)");
        }
        expect(known && (!exists || onDisk == 0),
               "folder: take-back branch " + std::to_string(names + 1) + ": the file's bytes do not stay under its final name (#60 r6)");
        SetFileAttributesW(target.c_str(), FILE_ATTRIBUTE_NORMAL);
        DeleteFileW(target.c_str());
        clearStaging(dir, gBranchName);
    }
    // #60 r7 probe: NTFS delete sharing between the main stream and the mark.
    sharingProbe(dir);
    // #60 r7 item 1: from the staging check through the rename and the last
    // check nobody can remove the Zone.Identifier stream either, and a file
    // whose mark someone tried to remove is never delivered without it.
    for (int stage = 0; stage < 2; ++stage) {
        const std::string leaf = stage == 0 ? "keep0.exe" : "keep1.exe";
        const std::wstring target = dir + L"\\" + std::wstring(leaf.begin(), leaf.end());
        gUnlinkStage = stage;
        gPublishHook = tryUnlink;
        PushReceiver::Out out;
        {
            PushReceiver r(makeFolderSink(dir, {}), fpull::sha256Digest());
            auto gp = makePush(75 + uint32_t(stage), {{leaf, 2048}});
            offerAll(r, gp);
            r.nextRequest();
            r.onData({75 + uint32_t(stage), 0, 0, gp.contents[0]});
            auto d = fpull::sha256Digest()();
            d->update(gp.contents[0].data(), gp.contents[0].size());
            out = r.onFileEnd({75 + uint32_t(stage), 0, d->finish()});
        }
        gPublishHook = nullptr;
        gUnlinkStage = -1;
        const auto* res = only<file::Result>(out);
        const int zone = fpull::readZoneId(target);
        const bool delivered = res && res->status == file::status::kOk;
        std::printf("  remove window stage %d: unlink=%d err=%lu ok=%d zone=%d\n", stage, gUnlinkResult[stage],
                    (unsigned long)gUnlinkError[stage], int(delivered), zone);
        expect(gUnlinkResult[stage] == 1,
               stage == 0 ? "folder: between the staging check and the rename nobody can remove the file's Zone.Identifier (#60 r7)"
                          : "folder: between the rename and the last check nobody can remove the file's Zone.Identifier (#60 r7)");
        expect(!delivered || zone == 3,
               stage == 0 ? "folder: a file whose mark someone tries to remove before the rename is never delivered without ZoneId=3 (#60 r7)"
                          : "folder: a file whose mark someone tries to remove after the rename is never delivered without ZoneId=3 (#60 r7)");
        DeleteFileW(target.c_str());
        clearStaging(dir, std::wstring(leaf.begin(), leaf.end()));
    }
    // #60 r7 item 2: a file that can be neither taken back, deleted, cut nor
    // zeroed (every staging name taken, mapped as an image, locked) after
    // someone tried to remove its mark before the rename: while the sink
    // lives it stays isolated, still marked ZoneId=3, and nobody can write
    // or remove its Zone.Identifier.
    {
        gIsoName = L"isolated.exe";
        gStuckPart = dir + L"\\.jlstaging\\isolated.exe.jlpart";
        gStuckBlocked = false;
        gStuckAllNames = true;
        gStuckImage = true;
        gStuckMapError = 0;
        gIsoLocked = false;
        gUnlinkStage = 0;
        gUnlinkResult[0] = 0;
        gUnlinkError[0] = 0;
        gPublishHook = tryUnlink;
        gTrace.clear();
        gTakeOutTrace = collectTrace;
        fpull::ZoneOps iso;
        iso.readOn = isoRead;
        const std::wstring target = dir + L"\\isolated.exe";
        int zone = -2;
        int openable = -1;
        bool delivered = true;
        {
            PushReceiver r(makeFolderSink(dir, {}, iso), fpull::sha256Digest());
            wchar_t self[MAX_PATH] = {};
            GetModuleFileNameW(nullptr, self, MAX_PATH);
            const std::vector<uint8_t> image = readAll(self);
            auto ip = makePush(77, {{"isolated.exe", image.size()}});
            ip.contents[0] = image;
            offerAll(r, ip);
            PushReceiver::Out iout;
            uint64_t sent = 0;
            while (iout.empty()) {
                auto q = r.nextRequest();
                if (!q || q->offset != sent) break;
                const uint64_t end = std::min<uint64_t>(image.size(), q->offset + q->length);
                while (iout.empty() && sent < end) {
                    const uint64_t n = std::min<uint64_t>(file::kMaxChunk, end - sent);
                    iout = r.onData({77, 0, sent, std::vector<uint8_t>(image.begin() + std::ptrdiff_t(sent),
                                                                      image.begin() + std::ptrdiff_t(sent + n))});
                    sent += n;
                }
                if (iout.empty() && sent == image.size()) {
                    auto d = fpull::sha256Digest()();
                    d->update(image.data(), image.size());
                    iout = r.onFileEnd({77, 0, d->finish()});
                }
            }
            const auto* ires = only<file::Result>(iout);
            delivered = ires && ires->status == file::status::kOk;
            // Still inside the sink's life: the leftover is checked now.
            zone = fpull::readZoneId(target);
            openable = zoneOpenable(target);
        }
        gPublishHook = nullptr;
        gUnlinkStage = -1;
        gTakeOutTrace = nullptr;
        bool exists = false;
        uint64_t onDisk = 0;
        diskSize(target, exists, onDisk);
        std::printf("  isolated: blocked=%d locked=%d maperr=%lu unlink=%d err=%lu delivered=%d zone=%d openable=%d "
                    "back=%d cut=%d zero=%d exists=%d size=%llu\n",
                    int(gStuckBlocked), int(gIsoLocked), (unsigned long)gStuckMapError, gUnlinkResult[0],
                    (unsigned long)gUnlinkError[0], int(delivered), zone, openable, traced("back"), traced("cut"),
                    traced("zero"), int(exists), (unsigned long long)onDisk);
        expect(gStuckBlocked && gIsoLocked,
               "folder: the isolation test took every staging name, mapped the file as an image and locked it (#60 r7)");
        expect(!delivered, "folder: a file that fails its last check and cannot be taken back is not delivered (#60 r7)");
        expect(traced("cut") == 0 && traced("zero") == 0,
               "folder: isolation: the cut and the zero-fill both failed, so the file stayed under its final name (#60 r7)");
        expect(zone == 3,
               "folder: a file left under its final name because it cannot be taken back still carries ZoneId=3 while the sink lives (#60 r7)");
        expect(openable == 0,
               "folder: while the sink lives nobody can write or remove the Zone.Identifier of a file it cannot take back (#60 r7)");
        if (gIsoLock != INVALID_HANDLE_VALUE) CloseHandle(gIsoLock);
        gIsoLock = INVALID_HANDLE_VALUE;
        if (gStuckView) UnmapViewOfFile(gStuckView);
        if (gStuckMap) CloseHandle(gStuckMap);
        gStuckView = nullptr;
        gStuckMap = nullptr;
        gStuckAllNames = false;
        gStuckImage = false;
        SetFileAttributesW(target.c_str(), FILE_ATTRIBUTE_NORMAL);
        DeleteFileW(target.c_str());
        clearStaging(dir, gIsoName);
    }
    // Disconnect mid-file removes the partial file.
    {
        PushReceiver r(makeFolderSink(dir, {}), fpull::sha256Digest());
        auto half = makePush(48, {{"half.bin", 100000}});
        offerAll(r, half);
        r.nextRequest();
        r.onData({48, 0, 0, std::vector<uint8_t>(half.contents[0].begin(), half.contents[0].begin() + 1000)});
        // #60 r3 item 3: the partial file is in a hidden staging folder, not
        // in Downloads\JerisLink itself.
        const std::wstring staging = dir + L"\\.jlstaging";
        const DWORD sa = GetFileAttributesW(staging.c_str());
        expect(countParts(dir) == 0 && countParts(staging) == 1, "folder: .jlpart while receiving is in .jlstaging (#60 r3)");
        expect(sa != INVALID_FILE_ATTRIBUTES && (sa & FILE_ATTRIBUTE_DIRECTORY) && (sa & FILE_ATTRIBUTE_HIDDEN) &&
                   !(sa & FILE_ATTRIBUTE_REPARSE_POINT),
               "folder: .jlstaging is a hidden plain folder (#60 r3)");
        // F5b r3: the mark is on the partial file already, while the
        // receiver still holds it open, so it moves with the rename.
        expect(fpull::readZoneId(staging + L"\\half.bin.jlpart") == 3, "folder: .jlpart carries ZoneId=3 while receiving");
        r.disconnect();
        expect(countParts(dir) == 0 && countParts(staging) == 0 &&
                   GetFileAttributesW((dir + L"\\half.bin").c_str()) == INVALID_FILE_ATTRIBUTES,
               "folder: disconnect removes the .jlpart");
    }
    expect(!downloadsFolder().empty() && downloadsFolder().size() > 10 &&
               downloadsFolder().substr(downloadsFolder().size() - 10) == L"\\JerisLink",
           "folder: Downloads\\JerisLink from FOLDERID_Downloads");
    // Nothing else is ever left in the folder: only delivered files.
    expect(countIn(dir, L"*.jlpart") == 0 && countParts(dir + L"\\.jlstaging") == 0, "folder: no partial files left anywhere");
    // Clean up the temp folder.
    {
        const std::wstring st = dir + L"\\.jlstaging";
        WIN32_FIND_DATAW sf{};
        HANDLE sh = FindFirstFileW((st + L"\\*").c_str(), &sf);
        if (sh != INVALID_HANDLE_VALUE) {
            do {
                if (!(sf.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) DeleteFileW((st + L"\\" + sf.cFileName).c_str());
            } while (FindNextFileW(sh, &sf));
            FindClose(sh);
        }
        RemoveDirectoryW(st.c_str());
    }
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) DeleteFileW((dir + L"\\" + fd.cFileName).c_str());
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    RemoveDirectoryW(dir.c_str());
    RemoveDirectoryW(dir.substr(0, dir.size() - 10).c_str());
}
#endif

}  // namespace

int main() {
    checks();
    happyPath();
    window();
    damaged();
    refusals();
    endings();
#ifdef _WIN32
    realFolder();
#endif
    std::printf("%d passed, %d failed\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
