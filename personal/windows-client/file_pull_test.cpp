// Tests for file_pull.hpp (F3 Mac->Windows paste): announce checks against
// the Windows name rules, and PullHub: the request window, sequential
// offsets, the last byte held back until FILE_END's hash matched, stale bytes
// drained when Explorer reopens a file, cancel and failure.
#include "file_pull.hpp"

#include <cstdio>
#include <string>
#include <vector>

using namespace jl::filepull;
namespace file = jl::file;

namespace {

int gPass = 0;
int gFail = 0;

void expect(bool cond, const std::string& what) {
    if (cond) { ++gPass; std::printf("PASS %s\n", what.c_str()); }
    else { ++gFail; std::printf("FAIL %s\n", what.c_str()); }
}

// A stand-in hash (FNV-1a and length): the hub only compares bytes.
class FakeDigest : public Digest {
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
private:
    uint64_t h_ = 14695981039346656037ull;
    uint64_t len_ = 0;
};

std::vector<uint8_t> hashOf(const std::vector<uint8_t>& b) {
    FakeDigest d;
    d.update(b.data(), b.size());
    return d.finish();
}

DigestFactory fake() {
    return [] { return std::unique_ptr<Digest>(new FakeDigest()); };
}

std::vector<uint8_t> bytesOf(const std::string& s) { return {s.begin(), s.end()}; }

std::vector<uint8_t> body(size_t n, unsigned seed = 3) {
    std::vector<uint8_t> b(n);
    for (size_t i = 0; i < n; ++i) b[i] = uint8_t((i * seed + 11) & 0xff);
    return b;
}

file::Entry entry(uint32_t t, uint32_t i, bool dir, uint64_t size, const std::string& path) {
    return file::Entry{t, i, dir ? file::kind::kDir : file::kind::kFile, size, 1700000000, bytesOf(path)};
}

std::string build(const std::vector<file::Entry>& es, uint64_t total, uint32_t t = 2, uint32_t count = 0) {
    Manifest m;
    return buildManifest(file::Offer{t, file::purpose::kAnnounce, count ? count : uint32_t(es.size()), total}, es, m);
}

// The host's DATA for [offset, offset+len) of `b`, in 32 KiB chunks.
void deliver(PullHub& hub, uint32_t t, uint32_t i, const std::vector<uint8_t>& b, uint64_t offset, uint64_t len) {
    uint64_t at = offset;
    while (at < offset + len) {
        const uint64_t n = std::min<uint64_t>(file::kMaxChunk, offset + len - at);
        hub.onData(file::Data{t, i, at, std::vector<uint8_t>(b.begin() + ptrdiff_t(at), b.begin() + ptrdiff_t(at + n))});
        at += n;
    }
}

// Reads everything available right now (short timeout).
std::vector<uint8_t> drain(PullHub& hub, uint64_t token, PullHub::ReadResult& last) {
    std::vector<uint8_t> out;
    std::vector<uint8_t> buf(100000);
    while (true) {
        size_t got = 0;
        last = hub.read(token, buf.data(), buf.size(), got, 10);
        if (last != PullHub::ReadResult::Ok) break;
        out.insert(out.end(), buf.begin(), buf.begin() + ptrdiff_t(got));
    }
    return out;
}

void manifests() {
    Manifest m;
    const std::vector<file::Entry> ok = {entry(2, 0, true, 0, "Photos"), entry(2, 1, false, 10, "Photos/a.jpg"),
                                         entry(2, 2, false, 0, "note.txt")};
    expect(buildManifest(file::Offer{2, file::purpose::kAnnounce, 3, 10}, ok, m).empty(), "manifest: accepted");
    expect(m.transfer == 2 && m.items.size() == 3 && m.files == 2 && m.total == 10, "manifest: counts");
    expect(m.items[1].rel == L"Photos\\a.jpg" && m.items[0].dir && !m.items[1].dir, "manifest: Windows separators, kinds");
    // "Cafe" + combining acute arrives NFC.
    expect(buildManifest(file::Offer{4, 3, 1, 1}, {entry(4, 0, false, 1, "Cafe\xCC\x81.txt")}, m).empty() &&
               m.items[0].rel == L"Caf\u00e9.txt",
           "manifest: names normalised to NFC");

    expect(build(ok, 10, 2, 4) == "count", "manifest: entry count must match the offer");
    expect(build({entry(2, 1, false, 1, "a")}, 1) == "index", "manifest: indices are sequential");
    expect(build({entry(3, 0, false, 1, "a")}, 1) == "transfer", "manifest: entries belong to the offer");
    expect(build({entry(2, 0, false, 1, "../a")}, 1) == "bad_path", "manifest: traversal refused");
    expect(build({entry(2, 0, false, 1, "a\\b")}, 1) == "bad_path", "manifest: backslash still refused");
    expect(build({entry(2, 0, false, 1, "/a")}, 1) == "bad_path", "manifest: absolute path still refused");
    // F3 r2: names Windows cannot hold are mapped, not refused, so they paste.
    {
        Manifest r;
        const auto rel = [&](const std::string& p) {
            r = Manifest{};
            const std::string why = buildManifest(file::Offer{2, file::purpose::kAnnounce, 1, 1}, {entry(2, 0, false, 1, p)}, r);
            return why.empty() && r.items.size() == 1 && r.renamed == 1 ? r.items[0].rel : L"<refused:" + std::wstring(why.begin(), why.end()) + L">";
        };
        expect(rel("what?.txt") == L"what_.txt", "manifest: ? mapped to _");
        expect(rel("a*b:c\"d<e>f|g.txt") == L"a_b_c_d_e_f_g.txt", "manifest: * : \" < > | mapped to _");
        expect(rel("con.txt") == L"con_.txt", "manifest: reserved device name gets _ after the stem");
        expect(rel("NUL") == L"NUL_" && rel("com1.tar.gz") == L"com1_.tar.gz", "manifest: NUL, COM1 mapped");
        expect(rel("notes. ") == L"notes" && rel("...") == L"_", "manifest: trailing dots and spaces removed");
        expect(rel("C:x") == L"C_x", "manifest: a leading drive letter becomes a plain name");
        expect(buildManifest(file::Offer{2, file::purpose::kAnnounce, 1, 1}, {entry(2, 0, false, 1, "fine.txt")}, r).empty() &&
                   r.renamed == 0 && r.items[0].rel == L"fine.txt",
               "manifest: a valid name is left alone and not counted");
    }
    {
        // A mapped folder: its children follow the new name.
        Manifest r;
        expect(buildManifest(file::Offer{2, file::purpose::kAnnounce, 3, 2},
                             {entry(2, 0, true, 0, "Q?"), entry(2, 1, false, 1, "Q?/a.txt"), entry(2, 2, false, 1, "Q?/b|c")}, r)
                       .empty() &&
                   r.items[0].rel == L"Q_" && r.items[1].rel == L"Q_\\a.txt" && r.items[2].rel == L"Q_\\b_c" && r.renamed == 3,
               "manifest: children of a mapped folder follow it");
        // Two names that map to the same Windows name: the later one is numbered.
        expect(buildManifest(file::Offer{2, file::purpose::kAnnounce, 3, 3},
                             {entry(2, 0, false, 1, "a?.txt"), entry(2, 1, false, 1, "a*.txt"), entry(2, 2, false, 1, "a_.txt")}, r)
                       .empty() &&
                   r.items[0].rel == L"a_.txt" && r.items[1].rel == L"a_ (2).txt" && r.items[2].rel == L"a_ (3).txt",
               "manifest: mapped names that clash are numbered like Explorer");
        expect(buildManifest(file::Offer{2, file::purpose::kAnnounce, 4, 2},
                             {entry(2, 0, true, 0, "d:"), entry(2, 1, true, 0, "d*"), entry(2, 2, false, 1, "d:/x"),
                              entry(2, 3, false, 1, "d*/x")}, r)
                       .empty() &&
                   r.items[0].rel == L"d_" && r.items[1].rel == L"d_ (2)" && r.items[2].rel == L"d_\\x" &&
                   r.items[3].rel == L"d_ (2)\\x",
               "manifest: a numbered folder keeps its own children");
    }
    std::vector<file::Entry> deep;
    std::string acc;
    uint32_t idx = 0;
    for (int i = 0; i < 26; ++i) {
        acc += (acc.empty() ? "" : "/") + std::string(9, char('a' + i));
        deep.push_back(entry(2, idx++, true, 0, acc));
    }
    deep.push_back(entry(2, idx++, false, 1, acc + "/x.txt"));   // 26*10 + 5 = 265 chars
    expect(build(deep, 1) == "name_too_long", "manifest: a path over MAX_PATH is refused");
    expect(build({entry(2, 0, false, 1, "A.txt"), entry(2, 1, false, 1, "a.TXT")}, 2) == "duplicate",
           "manifest: names that differ only in case are refused");
    expect(build({entry(2, 0, false, 1, "x/y.txt")}, 1) == "no_parent", "manifest: a file before its folder is refused");
    expect(build({entry(2, 0, false, 5, "a")}, 6) == "size", "manifest: sizes must add up to the offer total");
    expect(build({entry(2, 0, true, 5, "d")}, 0) == "size", "manifest: folders carry no size");
    expect(build({}, 0, 2, 0) == "empty", "manifest: empty announce refused");
    expect(build({entry(2, 0, false, 1, "a")}, 1, 2, file::kMaxEntries + 1) == "too_many", "manifest: entry limit");
    expect(build({entry(2, 0, false, 1, "a")}, file::kMaxTotalBytes + 1) == "too_big", "manifest: size limit");
    // #49/#53: 10 + (2^64 - 5) wraps to 5 when added first and checked after.
    expect(build({entry(2, 0, false, 10, "a"), entry(2, 1, false, UINT64_MAX - 4, "b")}, 5) == "too_big",
           "manifest: a size sum that wraps past 2^64 is refused");
    expect(build({entry(2, 0, false, file::kMaxTotalBytes + 1, "a")}, 0) == "too_big",
           "manifest: one entry over the limit is refused");
    expect(build({entry(2, 0, false, file::kMaxTotalBytes - 1, "a"), entry(2, 1, false, 1, "b")}, file::kMaxTotalBytes).empty(),
           "manifest: exactly the limit is accepted");
}

Manifest oneFile(uint32_t t, uint64_t size) {
    Manifest m;
    buildManifest(file::Offer{t, file::purpose::kAnnounce, 2, size},
                  {entry(t, 0, true, 0, "d"), entry(t, 1, false, size, "d/f.bin")}, m);
    return m;
}

void pulling() {
    using RR = PullHub::ReadResult;
    PullHub hub(fake());
    const uint64_t size = 600 * 1024;
    const auto b = body(size);
    hub.announce(oneFile(6, size));
    expect(!hub.nextRequest(), "pull: nothing is requested before Explorer pastes");
    expect(hub.open(6, 0) == 0 && hub.open(8, 1) == 0, "pull: folders and other transfers do not open");
    const uint64_t tok = hub.open(6, 1);
    expect(tok != 0 && hub.wantsService(), "pull: a stream opens and needs the network");
    const auto q1 = hub.nextRequest();
    const auto q2 = hub.nextRequest();
    const auto q3 = hub.nextRequest();
    expect(q1 && q1->transfer == 6 && q1->index == 1 && q1->offset == 0 && q1->length == kRequestBytes,
           "pull: first REQUEST is 256 KiB from 0");
    expect(q2 && q2->offset == kRequestBytes && q3 && q3->offset == 2 * kRequestBytes &&
               q3->length == size - 2 * kRequestBytes,
           "pull: next REQUESTs continue, the last is clipped to the file");
    expect(!hub.nextRequest(), "pull: nothing past the end");

    RR last;
    deliver(hub, 6, 1, b, 0, size);
    std::vector<uint8_t> got = drain(hub, tok, last);
    expect(got.size() == size - 1 && last == RR::Timeout, "pull: the last byte waits for FILE_END");
    hub.onFileEnd(file::FileEnd{6, 1, hashOf(b)});
    const auto rest = drain(hub, tok, last);
    got.insert(got.end(), rest.begin(), rest.end());
    expect(got == b && last == RR::Eof, "pull: after a matching FILE_END the file completes");
    const auto p = hub.progress();
    expect(p.filesDone == 1 && p.received == size && hub.rxBytes() == size && !p.active, "pull: progress counts");
    expect(!hub.wantsService(), "pull: idle once every stream ended");
    hub.close(tok);
}

void window() {
    PullHub hub(fake());
    const uint64_t size = 10ull * 1024 * 1024;
    const auto b = body(size, 5);
    hub.announce(oneFile(10, size));
    const uint64_t tok = hub.open(10, 1);
    uint64_t asked = 0;
    while (auto q = hub.nextRequest()) asked += q->length;
    expect(asked == kWindowBytes, "window: at most 4 MiB requested and unread");
    deliver(hub, 10, 1, b, 0, asked);
    std::vector<uint8_t> buf(1024 * 1024);
    size_t got = 0;
    hub.read(tok, buf.data(), buf.size(), got, 10);
    expect(got == buf.size(), "window: Explorer reads 1 MiB");
    uint64_t more = 0;
    while (auto q = hub.nextRequest()) more += q->length;
    expect(more == 1024 * 1024, "window: reading reopens the window by what was read");
}

void damaged() {
    using RR = PullHub::ReadResult;
    PullHub hub(fake());
    const auto b = body(1000);
    hub.announce(oneFile(12, 1000));
    const uint64_t tok = hub.open(12, 1);
    hub.nextRequest();
    deliver(hub, 12, 1, b, 0, 1000);
    auto bad = hashOf(b);
    bad[0] ^= 1;
    hub.onFileEnd(file::FileEnd{12, 1, bad});
    RR last;
    drain(hub, tok, last);
    expect(last == RR::Failed, "damaged: a hash mismatch fails the stream; the last byte is never handed out");

    hub.announce(oneFile(14, 1000));
    const uint64_t t2 = hub.open(14, 1);
    hub.nextRequest();
    hub.onData(file::Data{14, 1, 500, std::vector<uint8_t>(10, 1)});
    drain(hub, t2, last);
    expect(last == RR::Failed, "damaged: DATA at the wrong offset fails the stream");
}

void reopen() {
    using RR = PullHub::ReadResult;
    PullHub hub(fake());
    const uint64_t size = 300 * 1024;
    const auto b = body(size, 7);
    hub.announce(oneFile(16, size));
    const uint64_t a = hub.open(16, 1);
    const auto first = hub.nextRequest();   // 256 KiB in flight
    hub.close(a);
    const uint64_t c = hub.open(16, 1);
    expect(c != a && !hub.nextRequest(), "reopen: a new stream waits while the old one's bytes are in flight");
    deliver(hub, 16, 1, b, 0, first->length);   // the old request arrives and is dropped
    const auto q = hub.nextRequest();
    expect(q && q->offset == 0 && q->length == kRequestBytes, "reopen: then it asks again from offset 0");
    const auto q2 = hub.nextRequest();
    deliver(hub, 16, 1, b, 0, size);
    hub.onFileEnd(file::FileEnd{16, 1, hashOf(b)});
    RR last;
    expect(q2 && drain(hub, c, last) == b && last == RR::Eof, "reopen: the new stream gets the whole file");

    // A stream whose whole file was requested also waits for that FILE_END.
    const uint64_t d = hub.open(16, 1);
    hub.nextRequest();
    hub.nextRequest();
    hub.close(d);
    const uint64_t e = hub.open(16, 1);
    deliver(hub, 16, 1, b, 0, size);
    expect(!hub.nextRequest(), "reopen: still waiting for the old FILE_END");
    hub.onFileEnd(file::FileEnd{16, 1, hashOf(b)});
    const auto q3 = hub.nextRequest();
    expect(q3 && q3->offset == 0, "reopen: the old FILE_END drained, the new stream starts");
    hub.close(e);
}

void emptyFile() {
    using RR = PullHub::ReadResult;
    PullHub hub(fake());
    hub.announce(oneFile(18, 0));
    const uint64_t tok = hub.open(18, 1);
    const auto q = hub.nextRequest();
    expect(q && q->offset == 0 && q->length == 0, "empty: one zero-length REQUEST");
    expect(!hub.nextRequest(), "empty: only one");
    hub.onFileEnd(file::FileEnd{18, 1, hashOf({})});
    RR last;
    expect(drain(hub, tok, last).empty() && last == RR::Eof, "empty: FILE_END ends it");
}

void cancelAndFail() {
    using RR = PullHub::ReadResult;
    PullHub hub(fake());
    const auto b = body(5000);
    hub.announce(oneFile(20, 5000));
    const uint64_t tok = hub.open(20, 1);
    hub.nextRequest();
    hub.cancel(22);
    expect(hub.current() == 20, "cancel: another transfer's CANCEL is ignored");
    hub.cancel(20);
    RR last;
    drain(hub, tok, last);
    expect(last == RR::Failed && hub.current() == 0 && hub.open(20, 1) == 0, "cancel: streams fail, nothing opens");
    hub.onData(file::Data{20, 1, 0, std::vector<uint8_t>(10, 1)});
    expect(hub.rxBytes() == 0, "cancel: late DATA is dropped");

    hub.announce(oneFile(24, 5000));
    const uint64_t t2 = hub.open(24, 1);
    hub.nextRequest();
    deliver(hub, 24, 1, b, 0, 100);
    hub.onFailed(24);
    drain(hub, t2, last);
    expect(last == RR::Failed, "fail: REPLY failed fails the streams in flight");
    const uint64_t t3 = hub.open(24, 1);
    expect(t3 != 0 && hub.nextRequest()->offset == 0, "fail: Explorer may open the file again");

    hub.disconnect();
    drain(hub, t3, last);
    expect(last == RR::Failed && hub.current() == 0, "disconnect: everything fails");
}

}  // namespace

int main() {
    manifests();
    pulling();
    window();
    damaged();
    reopen();
    emptyFile();
    cancelAndFail();
    std::printf("%d passed, %d failed\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
