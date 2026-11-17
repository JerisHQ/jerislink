// Tests for file_push.hpp (F5b Mac "Send to JerisLink" into Downloads\JerisLink):
// push checks (files only, no folders, at most 1000), accept with no prompt,
// sequential REQUESTs inside the 4 MiB window, hash check before a file gets
// its name, RESULT on every end, busy, Mac refusal, cancel both ways,
// disconnect. On Windows it also runs the real folder writer in a temp
// folder: "name (2).ext" on a clash, Zone.Identifier ZoneId=3, no .jlpart
// left behind, nothing overwritten.
#include "file_push.hpp"

#include <cstdio>
#include <string>
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

int countParts(const std::wstring& folder) {
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW((folder + L"\\*.jlpart").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    int n = 0;
    do { ++n; } while (FindNextFileW(h, &fd));
    FindClose(h);
    return n;
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
    // Disconnect mid-file removes the partial file.
    {
        PushReceiver r(makeFolderSink(dir, {}), fpull::sha256Digest());
        auto half = makePush(48, {{"half.bin", 100000}});
        offerAll(r, half);
        r.nextRequest();
        r.onData({48, 0, 0, std::vector<uint8_t>(half.contents[0].begin(), half.contents[0].begin() + 1000)});
        expect(countParts(dir) == 1, "folder: .jlpart while receiving");
        r.disconnect();
        expect(countParts(dir) == 0 && GetFileAttributesW((dir + L"\\half.bin").c_str()) == INVALID_FILE_ATTRIBUTES,
               "folder: disconnect removes the .jlpart");
    }
    expect(!downloadsFolder().empty() && downloadsFolder().size() > 10 &&
               downloadsFolder().substr(downloadsFolder().size() - 10) == L"\\JerisLink",
           "folder: Downloads\\JerisLink from FOLDERID_Downloads");
    // Clean up the temp folder.
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
