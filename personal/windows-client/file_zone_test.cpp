// Mark of the Web for Mac->Windows paste (F3 r2, hand test H): Explorer does
// not write Zone.Identifier for virtual files pasted from the clipboard, so
// the viewer makes sure the copy carries ZoneId=3 before Explorer gets the
// file's last byte (#53 r2).
//
// 1. writeInternetZone / readZoneId / gateFile on real NTFS files.
// 2. End to end: FileClipboard offers a manifest (names mapped for Windows),
//    the folder's shell drop target pastes it (the same path Explorer's
//    Ctrl+V takes), a fake host thread serves the bytes with real SHA-256,
//    and the pasted files must carry Zone.Identifier with ZoneId=3.
#include <winsock2.h>
#include <windows.h>
#include <ole2.h>
#include <shlobj.h>

#include "file_pull.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace jl::filepull;
namespace file = jl::file;

namespace {

int gPass = 0;
int gFail = 0;

void expect(bool cond, const std::string& what) {
    if (cond) { ++gPass; std::printf("PASS %s\n", what.c_str()); }
    else { ++gFail; std::printf("FAIL %s\n", what.c_str()); }
    std::fflush(stdout);
}

std::wstring tempDir(const wchar_t* tag) {
    wchar_t base[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, base);
    std::wstring d = std::wstring(base) + L"jl-zone-" + tag + L"-" + std::to_wstring(GetCurrentProcessId());
    CreateDirectoryW(d.c_str(), nullptr);
    return d;
}

bool writeFile(const std::wstring& path, const std::vector<uint8_t>& b) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD wrote = 0;
    const BOOL ok = WriteFile(h, b.data(), DWORD(b.size()), &wrote, nullptr);
    CloseHandle(h);
    return ok && wrote == b.size();
}

std::vector<uint8_t> readFile(const std::wstring& path) {
    std::vector<uint8_t> out;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return out;
    uint8_t buf[65536];
    DWORD got = 0;
    while (ReadFile(h, buf, sizeof(buf), &got, nullptr) && got > 0) out.insert(out.end(), buf, buf + got);
    CloseHandle(h);
    return out;
}

std::vector<uint8_t> body(size_t n, unsigned seed) {
    std::vector<uint8_t> b(n);
    for (size_t i = 0; i < n; ++i) b[i] = uint8_t((i * seed + 7) & 0xff);
    return b;
}

std::vector<uint8_t> bytesOf(const std::string& s) { return {s.begin(), s.end()}; }

// The gate request a PullStream builds for `full`.
GateRequest requestFor(const std::wstring& rel, const std::vector<uint8_t>& full, const FILETIME& since) {
    GateRequest r;
    r.rel = rel;
    r.size = full.size();
    r.since = since;
    return r;
}

FILETIME nowMinus(int seconds) {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u{ft.dwLowDateTime, ft.dwHighDateTime};
    u.QuadPart -= uint64_t(seconds) * 10000000ull;
    return FILETIME{u.LowPart, u.HighPart};
}

void pump(int ms) {
    const auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
    while (std::chrono::steady_clock::now() < end) {
        MSG msg;
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        MsgWaitForMultipleObjects(0, nullptr, FALSE, 20, QS_ALLINPUT);
    }
}

bool exists(const std::wstring& path) { return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES; }

// Holds a file open for writing, as Explorer does while it copies (sharing
// read, write and delete, so the test can still read, rename or delete it).
struct Writer {
    HANDLE h = INVALID_HANDLE_VALUE;
    explicit Writer(const std::wstring& path) {
        h = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    }
    ~Writer() { close(); }
    Writer(const Writer&) = delete;
    Writer& operator=(const Writer&) = delete;
    bool ok() const { return h != INVALID_HANDLE_VALUE; }
    bool append(const std::vector<uint8_t>& b) {
        LARGE_INTEGER zero{};
        DWORD wrote = 0;
        return SetFilePointerEx(h, zero, nullptr, FILE_END) &&
               (b.empty() || (WriteFile(h, b.data(), DWORD(b.size()), &wrote, nullptr) && wrote == b.size()));
    }
    void close() {
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
        h = INVALID_HANDLE_VALUE;
    }
};

std::vector<uint8_t> sha256Of(const std::vector<uint8_t>& b) {
    auto d = sha256Digest()();
    d->update(b.data(), b.size());
    return d->finish();
}

// #60 r3: a file swapped in under the copy's name while it is marked. The
// zone write first moves the copy away and puts a replacement at its path.
std::wstring gSwapPath;
std::vector<uint8_t> gSwapBytes;
bool gSwapped = false;

void swapNow() {
    if (gSwapped || gSwapPath.empty()) return;
    gSwapped = MoveFileExW(gSwapPath.c_str(), (gSwapPath + L".moved").c_str(), 0) && writeFile(gSwapPath, gSwapBytes);
}

ZoneOps swappingOps() {
    ZoneOps z;
    z.write = [](const std::wstring& path) { swapNow(); return writeInternetZone(path); };
    z.writeOn = [](HANDLE h) { swapNow(); return writeInternetZoneOn(h); };
    return z;
}

void helpers() {
    const std::wstring dir = tempDir(L"unit");
    const std::wstring a = dir + L"\\a.txt";
    expect(writeFile(a, body(1000, 3)), "unit: test file written");
    expect(readZoneId(a) == -1, "unit: a new local file has no Zone.Identifier");
    expect(writeInternetZone(a) == ZoneWrite::Written, "unit: Zone.Identifier written");
    expect(readZoneId(a) == 3, "unit: ZoneId=3 read back");
    expect(writeInternetZone(a) == ZoneWrite::Exists, "unit: an existing Zone.Identifier is kept, not overwritten");

    // gateFile: the manifest's file, Explorer's "Keep both" name, size,
    // time and being-written checks.
    const std::wstring sub = dir + L"\\m";
    CreateDirectoryW(sub.c_str(), nullptr);
    const auto x = body(500, 5);
    // The old x.bin was there before the paste: older than `since`.
    expect(writeFile(sub + L"\\x.bin", x), "unit: an older x.bin exists");
    Sleep(1100);
    const FILETIME since = nowMinus(0);
    Sleep(50);
    // #60 r3: a copy is only taken while something (Explorer) still has it
    // open for writing; each pasted copy below is held so.
    expect(writeFile(sub + L"\\x (2).bin", x), "unit: pasted x (2).bin");
    Writer wx(sub + L"\\x (2).bin");
    CreateDirectoryW((sub + L"\\d").c_str(), nullptr);
    const auto inner = body(300, 7);
    expect(writeFile(sub + L"\\d\\inner.bin", inner), "unit: pasted d\\inner.bin");
    Writer wInner(sub + L"\\d\\inner.bin");
    const auto part = body(4000, 13);
    // What Explorer has written when the gate runs: all but the last byte.
    expect(writeFile(sub + L"\\part.bin", {part.begin(), part.end() - 1}), "unit: a copy one byte short");
    Writer wPart(sub + L"\\part.bin");
    expect(writeFile(sub + L"\\wrong-size.bin", body(70, 7)), "unit: a same-name file shorter than the bytes handed out");
    // What CI showed the shell doing: the file sized past the manifest size
    // first, the start written, the last buffer not written yet (zeros).
    const auto sized = body(200000, 17);
    // Written up to 170000: the last 64 KiB handed out are part ours, part zeros.
    std::vector<uint8_t> sizedOnDisk(sized.begin(), sized.begin() + 170000);
    sizedOnDisk.resize(sized.size() + 5000, 0);
    expect(writeFile(sub + L"\\sized.bin", sizedOnDisk), "unit: a copy Explorer sized past the manifest size");
    Writer wSized(sub + L"\\sized.bin");
    expect(wx.ok() && wInner.ok() && wPart.ok() && wSized.ok(), "unit: the pasted copies are held open for writing");
    // The same, but the end holds someone else's bytes, not zeros.
    std::vector<uint8_t> foreignTail = sizedOnDisk;
    for (size_t i = 180000; i < 190000; ++i) foreignTail[i] = 0x5a;
    expect(writeFile(sub + L"\\foreign.bin", foreignTail), "unit: a same-name file with our start and other bytes at the end");
    expect(writeFile(sub + L"\\other.bin", body(600, 3)), "unit: a same-name, same-size file with other bytes");
    const std::vector<std::wstring> folders{dir + L"\\nowhere", sub};
    ZoneMarkStats st;
    expect(gateFile(requestFor(L"x.bin", x, since), folders, {}, st) == GateOutcome::Marked,
           "unit: the Keep-both copy passes the gate");
    expect(readZoneId(sub + L"\\x (2).bin") == 3, "unit: the Keep-both copy carries ZoneId=3");
    expect(readZoneId(sub + L"\\x.bin") == -1, "unit: the older file of the same name is left alone");
    expect(gateFile(requestFor(L"d\\inner.bin", inner, since), folders, {}, st) == GateOutcome::Marked &&
               readZoneId(sub + L"\\d\\inner.bin") == 3,
           "unit: a file inside a pasted folder carries ZoneId=3");
    expect(gateFile(requestFor(L"part.bin", part, since), folders, {}, st) == GateOutcome::Marked &&
               readZoneId(sub + L"\\part.bin") == 3,
           "unit: a copy one byte short (the last byte held back) is proven and marked");
    expect(gateFile(requestFor(L"wrong-size.bin", body(77, 7), since), folders, {}, st) == GateOutcome::NotFound &&
               readZoneId(sub + L"\\wrong-size.bin") == -1,
           "unit: a file shorter than the bytes handed out is not ours and left alone");
    expect(gateFile(requestFor(L"sized.bin", sized, since), folders, {}, st) == GateOutcome::Marked &&
               readZoneId(sub + L"\\sized.bin") == 3,
           "unit: a copy Explorer sized past the manifest size, its end not written yet, is proven and marked");
    expect(gateFile(requestFor(L"foreign.bin", sized, since), folders, {}, st) == GateOutcome::NotFound &&
               readZoneId(sub + L"\\foreign.bin") == -1,
           "unit: a file with our start but other bytes at the end is not ours and left alone");
    expect(gateFile(requestFor(L"other.bin", body(600, 5), since), folders, {}, st) == GateOutcome::NotFound &&
               readZoneId(sub + L"\\other.bin") == -1,
           "unit: a file with other bytes is not ours and left alone");
    expect(gateFile(requestFor(L"absent.bin", body(10, 1), since), folders, {}, st) == GateOutcome::NotFound,
           "unit: a missing file is not found");
    expect(gateFile(requestFor(L"x.bin", x, since), folders, {}, st) == GateOutcome::Marked,
           "unit: a second gate on a marked copy passes (ZoneId=3 kept)");
    expect(st.written == 4 && st.existed == 1 && st.failed == 0, "unit: gate counts written=4 existed=1 failed=0");

    // #60 r3 item 1: the gate proves which file is this paste's copy without
    // sampling bytes (zeros prove nothing). A same-name, same-size file of
    // zeros that nobody is writing is not ours: never marked, never taken.
    const std::wstring sub2 = dir + L"\\m2";
    CreateDirectoryW(sub2.c_str(), nullptr);
    const std::vector<std::wstring> both{sub, sub2};
    const auto zfull = body(3000, 41);
    expect(writeFile(sub2 + L"\\zeros.bin", std::vector<uint8_t>(zfull.size(), 0)),
           "unit: a same-name, same-size file of zeros next to the copy");
    expect(writeFile(sub + L"\\zeros.bin", {zfull.begin(), zfull.end() - 1}), "unit: the real copy, being written");
    {
        Writer w(sub + L"\\zeros.bin");
        ZoneMarkStats zst;
        expect(gateFile(requestFor(L"zeros.bin", zfull, since), both, {}, zst) == GateOutcome::Marked &&
                   readZoneId(sub + L"\\zeros.bin") == 3,
               "unit: the copy being written passes the gate and carries ZoneId=3");
        expect(readZoneId(sub2 + L"\\zeros.bin") == -1 && readFile(sub2 + L"\\zeros.bin") == std::vector<uint8_t>(zfull.size(), 0),
               "unit: a same-name, same-size file of zeros nobody writes is not marked and kept as it was (#60 r3)");
    }
    {
        // Nothing writes it: the zeros file alone is never taken.
        ZoneMarkStats zst;
        const std::wstring lone = dir + L"\\m3";
        CreateDirectoryW(lone.c_str(), nullptr);
        writeFile(lone + L"\\lone.bin", std::vector<uint8_t>(zfull.size(), 0));
        expect(gateFile(requestFor(L"lone.bin", zfull, since), {lone}, {}, zst) == GateOutcome::NotFound &&
                   readZoneId(lone + L"\\lone.bin") == -1,
               "unit: a file of zeros with the right name and size, nobody writing it, is not found (#60 r3)");
    }
    {
        // Two copies being written: which one is ours cannot be told, so
        // neither is marked and the gate fails closed.
        const auto tfull = body(2000, 43);
        writeFile(sub + L"\\twin.bin", {tfull.begin(), tfull.end() - 1});
        writeFile(sub2 + L"\\twin.bin", {tfull.begin(), tfull.end() - 1});
        Writer w1(sub + L"\\twin.bin");
        Writer w2(sub2 + L"\\twin.bin");
        ZoneMarkStats zst;
        const GateOutcome g = gateFile(requestFor(L"twin.bin", tfull, since), both, {}, zst);
        expect(g != GateOutcome::Marked && readZoneId(sub + L"\\twin.bin") == -1 && readZoneId(sub2 + L"\\twin.bin") == -1,
               "unit: two candidate copies being written: the gate fails and marks neither (#60 r3)");
    }
    {
        // The mark goes to the locked copy: a file swapped in under its name
        // while it is marked gets nothing.
        const auto sfull = body(2500, 47);
        gSwapPath = sub + L"\\swap.bin";
        gSwapBytes = body(2500, 53);
        gSwapped = false;
        writeFile(gSwapPath, {sfull.begin(), sfull.end() - 1});
        Writer w(gSwapPath);
        ZoneMarkStats zst;
        gateFile(requestFor(L"swap.bin", sfull, since), {sub}, swappingOps(), zst);
        w.close();
        std::printf("  swap: swapped=%d copy zone=%d replacement zone=%d\n", int(gSwapped),
                    readZoneId(gSwapPath + L".moved"), readZoneId(gSwapPath));
        expect(gSwapped && readZoneId(gSwapPath + L".moved") == 3 && readZoneId(gSwapPath) == -1 &&
                   readFile(gSwapPath) == gSwapBytes,
               "unit: a file swapped in under the copy's name while it is marked is not marked; the copy is (#60 r3)");
        gSwapPath.clear();
    }

    // #60 r3 item 2: after the paste the locked copy is kept only when it is
    // complete, exactly the manifest size, has the bytes handed out and
    // carries ZoneId=3. Anything else is removed through its identity.
    {
        struct Settle {
            const wchar_t* name;
            int kind;   // 0 good, 1 longer than the manifest, 2 mark gone, 3 paste not complete
            const char* what;
        };
        const Settle cases[] = {
            {L"keep.bin", 0, "unit: settle keeps a complete, marked copy with the right bytes"},
            {L"long.bin", 1, "unit: settle removes a copy that ends longer than the manifest (#60 r3)"},
            {L"nomark2.bin", 2, "unit: settle removes a complete copy whose mark is gone (#60 r3)"},
            {L"cut.bin", 3, "unit: settle removes a copy whose paste did not complete (#60 r3)"},
        };
        const std::wstring sd = dir + L"\\settle";
        CreateDirectoryW(sd.c_str(), nullptr);
        for (const auto& c : cases) {
            const auto full = body(5000, 59);
            const std::wstring path = sd + L"\\" + c.name;
            writeFile(path, {full.begin(), full.end() - 1});
            Writer w(path);
            ZoneMarkStats zst;
            LockedCopy locked;
            const GateOutcome g = gateFile(requestFor(c.name, full, since), {sd}, {}, zst, nullptr, &locked);
            w.append({full.back()});
            if (c.kind == 1) w.append(body(100, 61));
            if (c.kind == 2) DeleteFileW((path + L":Zone.Identifier").c_str());
            w.close();
            SettleRequest sr;
            sr.size = full.size();
            sr.sha256 = sha256Of(full);
            sr.complete = c.kind != 3;
            const SettleOutcome o = settleCopy(locked, sr, {}, zst, 3000);
            const bool there = exists(path);
            std::printf("  settle %ls: gate=%d outcome=%d exists=%d\n", c.name, int(g), int(o), int(there));
            if (c.kind == 0) expect(o == SettleOutcome::Kept && there && readFile(path) == full && readZoneId(path) == 3, c.what);
            else expect(o == SettleOutcome::Removed && !there, c.what);
        }
    }

    // #53: a volume without streams (FAT, exFAT): ZoneId=3 cannot be
    // written, so the gate fails and the file is not completed. The gate
    // deletes nothing.
    const std::wstring fat = dir + L"\\fat";
    CreateDirectoryW(fat.c_str(), nullptr);
    const FILETIME since2 = nowMinus(0);
    Sleep(50);
    const auto nomark = body(64, 9);
    expect(writeFile(fat + L"\\nomark.exe", {nomark.begin(), nomark.end() - 1}), "unit: pasted nomark.exe, one byte short");
    Writer wNomark(fat + L"\\nomark.exe");
    ZoneOps noStreams;
    noStreams.write = [](const std::wstring&) { return ZoneWrite::Failed; };
    noStreams.read = [](const std::wstring&) { return -1; };
    noStreams.writeOn = [](HANDLE) { return ZoneWrite::Failed; };
    noStreams.readOn = [](HANDLE) { return -1; };
    ZoneMarkStats fst;
    expect(gateFile(requestFor(L"nomark.exe", nomark, since2), {fat}, noStreams, fst) == GateOutcome::WriteFailed &&
               fst.failed == 1 && fst.written == 0,
           "unit: a mark that cannot be written fails the gate (#53)");
}

// The host side of a pull: answers the hub's REQUESTs from `files`, ends
// each file with its real SHA-256.
void fakeHost(PullHub& hub, uint32_t t, const std::vector<std::vector<uint8_t>>& files, std::atomic<bool>& stop) {
    auto factory = sha256Digest();
    while (!stop) {
        auto req = hub.nextRequest();
        if (!req) { Sleep(2); continue; }
        if (req->transfer != t || req->index >= files.size()) continue;
        const auto& b = files[req->index];
        const uint64_t end = std::min<uint64_t>(b.size(), req->offset + req->length);
        for (uint64_t at = req->offset; at < end;) {
            const uint64_t n = std::min<uint64_t>(file::kMaxChunk, end - at);
            hub.onData(file::Data{t, req->index, at, std::vector<uint8_t>(b.begin() + ptrdiff_t(at), b.begin() + ptrdiff_t(at + n))});
            at += n;
        }
        if (end == b.size()) {
            auto d = factory();
            d->update(b.data(), b.size());
            hub.onFileEnd(file::FileEnd{t, req->index, d->finish()});
        }
    }
}

IDropTarget* folderDropTarget(const std::wstring& dir) {
    PIDLIST_ABSOLUTE pidl = nullptr;
    if (FAILED(SHParseDisplayName(dir.c_str(), nullptr, &pidl, 0, nullptr)) || !pidl) return nullptr;
    IShellFolder* parent = nullptr;
    PCUITEMID_CHILD child = nullptr;
    IDropTarget* dt = nullptr;
    if (SUCCEEDED(SHBindToParent(pidl, IID_PPV_ARGS(&parent), &child))) {
        parent->GetUIObjectOf(nullptr, 1, &child, IID_IDropTarget, nullptr, reinterpret_cast<void**>(&dt));
        parent->Release();
    }
    CoTaskMemFree(pidl);
    return dt;
}

void endToEnd() {
    const std::wstring dir = tempDir(L"paste");
    const uint32_t t = 4;
    // Mac names Windows cannot hold: mapped, and still pasted (E).
    // #60 r3: and an empty file, which gets the mark too.
    const std::vector<std::vector<uint8_t>> files = {body(300000, 3), {}, body(5000, 11), {}};
    std::vector<file::Entry> es = {
        {t, 0, file::kind::kFile, files[0].size(), 1700000000, bytesOf("report?.txt")},
        {t, 1, file::kind::kDir, 0, 1700000000, bytesOf("box*")},
        {t, 2, file::kind::kFile, files[2].size(), 1700000000, bytesOf("box*/inner.bin")},
        {t, 3, file::kind::kFile, 0, 1700000000, bytesOf("empty.txt")},
    };
    Manifest m;
    const std::string why = buildManifest(file::Offer{t, file::purpose::kAnnounce, 4, files[0].size() + files[2].size()}, es, m);
    expect(why.empty() && m.renamed == 3, "e2e: manifest built with mapped names");
    if (!why.empty()) return;

    PullHub hub(sha256Digest());
    std::vector<std::string> logs;
    std::mutex logMu;
    FileClipboard clip(hub, [&](const std::string& s) {
        std::lock_guard<std::mutex> lock(logMu);
        std::printf("  log: %s\n", s.c_str());
        logs.push_back(s);
    });
    clip.start();
    clip.addSearchFolder(dir);
    hub.announce(m);
    clip.offer(m);
    std::atomic<bool> stop{false};
    std::thread host([&] { fakeHost(hub, t, files, stop); });
    pump(500);

    IDataObject* obj = nullptr;
    const HRESULT got = OleGetClipboard(&obj);
    expect(SUCCEEDED(got) && obj, "e2e: the offer is on the clipboard");
    IDropTarget* dt = folderDropTarget(dir);
    expect(dt != nullptr, "e2e: the folder's shell drop target");
    if (obj && dt) {
        POINTL pt{0, 0};
        DWORD effect = DROPEFFECT_COPY;
        const HRESULT enter = dt->DragEnter(obj, MK_LBUTTON, pt, &effect);
        effect = DROPEFFECT_COPY;
        const HRESULT drop = dt->Drop(obj, MK_LBUTTON, pt, &effect);
        std::printf("  DragEnter=0x%08lx Drop=0x%08lx effect=%lu\n", static_cast<unsigned long>(enter),
                    static_cast<unsigned long>(drop), static_cast<unsigned long>(effect));
        expect(SUCCEEDED(enter) && SUCCEEDED(drop), "e2e: the shell accepted the paste");
    }
    if (dt) dt->Release();
    if (obj) obj->Release();

    const std::wstring p0 = dir + L"\\report_.txt";
    const std::wstring p2 = dir + L"\\box_\\inner.bin";
    const std::wstring p3 = dir + L"\\empty.txt";
    // The shell copies on its own thread; the viewer marks each file before
    // the shell gets its last byte. Wait up to 30 s.
    for (int i = 0; i < 300; ++i) {
        if (readZoneId(p0) == 3 && readZoneId(p2) == 3 && readZoneId(p3) == 3) break;
        pump(100);
    }
    expect(readFile(p0) == files[0], "e2e: report?.txt pasted as report_.txt with the right bytes");
    expect(readFile(p2) == files[2], "e2e: box*/inner.bin pasted as box_\\inner.bin with the right bytes");
    expect(readZoneId(p0) == 3, "e2e: report_.txt carries Zone.Identifier ZoneId=3");
    expect(readZoneId(p2) == 3, "e2e: box_\\inner.bin carries Zone.Identifier ZoneId=3");
    expect(exists(p3) && readFile(p3).empty() && readZoneId(p3) == 3,
           "e2e: an empty pasted file carries Zone.Identifier ZoneId=3 too (#60 r3)");
    // The same Mac copy pasted a second time, into another folder.
    const std::wstring dir2 = tempDir(L"paste2");
    clip.addSearchFolder(dir2);
    obj = nullptr;
    dt = nullptr;
    if (SUCCEEDED(OleGetClipboard(&obj)) && obj && (dt = folderDropTarget(dir2)) != nullptr) {
        POINTL pt{0, 0};
        DWORD effect = DROPEFFECT_COPY;
        dt->DragEnter(obj, MK_LBUTTON, pt, &effect);
        effect = DROPEFFECT_COPY;
        expect(SUCCEEDED(dt->Drop(obj, MK_LBUTTON, pt, &effect)), "e2e: a second paste of the same copy");
    } else {
        expect(false, "e2e: a second paste of the same copy");
    }
    if (dt) dt->Release();
    if (obj) obj->Release();
    const std::wstring q0 = dir2 + L"\\report_.txt";
    const std::wstring q2 = dir2 + L"\\box_\\inner.bin";
    const std::wstring q3 = dir2 + L"\\empty.txt";
    for (int i = 0; i < 300 && (readZoneId(q0) != 3 || readZoneId(q2) != 3 || readZoneId(q3) != 3); ++i) pump(100);
    expect(readZoneId(q2) == 3, "e2e: the second paste's folder file is marked too");
    expect(readFile(q0) == files[0] && readZoneId(q0) == 3, "e2e: the second paste is marked too");
    expect(exists(q3) && readZoneId(q3) == 3, "e2e: the second paste's empty file is marked too (#60 r3)");

    {
        std::lock_guard<std::mutex> lock(logMu);
        bool named = false;
        for (const auto& l : logs) named |= l.find("report") != std::string::npos || l.find("inner") != std::string::npos;
        expect(!named, "e2e: no file names in the log");
    }

    stop = true;
    host.join();
    clip.withdraw(0);
    clip.stop();   // waits for the checks after each paste
    const auto zs = clip.zoneStats();
    std::printf("  zone stats: written=%llu existed=%llu failed=%llu kept=%llu removed=%llu left=%llu\n",
                static_cast<unsigned long long>(zs.written), static_cast<unsigned long long>(zs.existed),
                static_cast<unsigned long long>(zs.failed), static_cast<unsigned long long>(zs.kept),
                static_cast<unsigned long long>(zs.removed), static_cast<unsigned long long>(zs.left));
    expect(zs.written == 6 && zs.failed == 0, "e2e: six delivered files marked once each, none failed");
    expect(zs.kept == 6 && zs.removed == 0 && zs.left == 0,
           "e2e: after the paste all six copies are checked (size, SHA-256, ZoneId=3) and kept (#60 r3)");
    expect(readFile(p0) == files[0] && readFile(q0) == files[0] && readFile(q2) == files[2],
           "e2e: the kept copies still hold the right bytes");
}

// ---- #53 r2: the last byte waits for the mark ----------------------------
//
// A stand-in for Explorer's copy engine, for the failure cases a real shell
// paste would answer with a dialog: it takes FileContents[0] from the
// clipboard object and writes each chunk to `path` before asking for more.
// `presetZone` puts a Zone.Identifier on the new file first; `holdMs` keeps
// the file open without delete sharing after the stream is released, so it
// cannot be deleted meanwhile. `presize` sets the file's size first to the
// manifest size plus that many bytes, as CI showed the shell doing; a copy
// that completes is cut to its real size at the end. It reads at least once,
// so an empty file's stream is read too.
struct FakeCopy {
    uint64_t got = 0;
    bool readFailed = false;
};

FakeCopy fakeExplorerCopy(IDataObject* obj, const std::wstring& path, uint64_t size, const char* presetZone,
                          int holdMs, int64_t presize) {
    FakeCopy r;
    FORMATETC fe{CLIPFORMAT(RegisterClipboardFormatW(CFSTR_FILECONTENTS)), nullptr, DVASPECT_CONTENT, 0, TYMED_ISTREAM};
    STGMEDIUM med{};
    if (FAILED(obj->GetData(&fe, &med)) || med.tymed != TYMED_ISTREAM || !med.pstm) {
        r.readFailed = true;
        return r;
    }
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, CREATE_NEW,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (presetZone) {
        HANDLE z = CreateFileW((path + L":Zone.Identifier").c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
        DWORD w = 0;
        if (z != INVALID_HANDLE_VALUE) {
            WriteFile(z, presetZone, DWORD(std::strlen(presetZone)), &w, nullptr);
            CloseHandle(z);
        }
    }
    auto setSize = [&](uint64_t n) {
        LARGE_INTEGER at{};
        at.QuadPart = LONGLONG(n);
        LARGE_INTEGER zero{};
        if (h != INVALID_HANDLE_VALUE && SetFilePointerEx(h, at, nullptr, FILE_BEGIN)) SetEndOfFile(h);
        if (h != INVALID_HANDLE_VALUE) SetFilePointerEx(h, zero, nullptr, FILE_BEGIN);
    };
    if (presize >= 0) setSize(size + uint64_t(presize));
    LARGE_INTEGER at{};
    std::vector<uint8_t> buf(65536);
    do {
        ULONG n = 0;
        const HRESULT hr = med.pstm->Read(buf.data(), ULONG(buf.size()), &n);
        if (n > 0 && h != INVALID_HANDLE_VALUE) {
            DWORD w = 0;
            at.QuadPart = LONGLONG(r.got);
            SetFilePointerEx(h, at, nullptr, FILE_BEGIN);
            WriteFile(h, buf.data(), n, &w, nullptr);
        }
        r.got += n;
        if (FAILED(hr)) { r.readFailed = true; break; }
        if (n == 0) break;
    } while (r.got < size);
    if (presize >= 0 && !r.readFailed && r.got == size) setSize(size);
    ReleaseStgMedium(&med);
    if (holdMs > 0) pump(holdMs);
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    return r;
}

struct GateCase {
    uint32_t transfer = 0;
    ZoneOps ops;
    std::vector<std::wstring> folders;   // search folders
    std::wstring dest;                   // where the stand-in writes the copy
    std::vector<uint8_t> bytes;
    const char* presetZone = nullptr;
    int holdMs = 0;
    int64_t presize = -1;
    std::function<void()> beforeCopy;
};

// One paste of `same.bin` through the stand-in, with its own clipboard, hub
// and host. Waits 3.5 s after the stream is released.
FakeCopy runGateCase(const GateCase& gc) {
    FakeCopy c;
    c.readFailed = true;
    std::vector<file::Entry> es = {
        {gc.transfer, 0, file::kind::kFile, gc.bytes.size(), 1700000000, bytesOf("same.bin")}};
    Manifest m;
    if (!buildManifest(file::Offer{gc.transfer, file::purpose::kAnnounce, 1, gc.bytes.size()}, es, m).empty()) return c;
    PullHub hub(sha256Digest());
    FileClipboard clip(hub, [](const std::string& s) { std::printf("  log: %s\n", s.c_str()); }, gc.ops);
    clip.start();
    for (const auto& f : gc.folders) clip.addSearchFolder(f);
    hub.announce(m);
    clip.offer(m);
    std::atomic<bool> stop{false};
    const std::vector<std::vector<uint8_t>> files{gc.bytes};
    std::thread host([&] { fakeHost(hub, gc.transfer, files, stop); });
    pump(300);
    if (gc.beforeCopy) gc.beforeCopy();
    IDataObject* obj = nullptr;
    if (SUCCEEDED(OleGetClipboard(&obj)) && obj) {
        c = fakeExplorerCopy(obj, gc.dest, gc.bytes.size(), gc.presetZone, gc.holdMs, gc.presize);
        obj->Release();
    }
    pump(3500);
    stop = true;
    host.join();
    clip.withdraw(0);
    clip.stop();
    return c;
}

uint64_t sizeOf(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA a{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &a)) return 0;
    return (uint64_t(a.nFileSizeHigh) << 32) | a.nFileSizeLow;
}

void gateCases() {
    ZoneOps noStreams;
    noStreams.write = [](const std::wstring&) { return ZoneWrite::Failed; };
    noStreams.read = [](const std::wstring&) { return -1; };
    noStreams.writeOn = [](HANDLE) { return ZoneWrite::Failed; };
    noStreams.readOn = [](HANDLE) { return -1; };
    ZoneOps stuckInvalid;   // a Zone.Identifier that says ZoneId=0 and cannot be replaced
    stuckInvalid.write = [](const std::wstring&) { return ZoneWrite::Exists; };
    stuckInvalid.read = [](const std::wstring&) { return 0; };
    stuckInvalid.writeOn = [](HANDLE) { return ZoneWrite::Exists; };
    stuckInvalid.readOn = [](HANDLE) { return 0; };
    const size_t n = 200000;

    {   // A working mark: the copy completes and carries ZoneId=3.
        const std::wstring dir = tempDir(L"gate-ok");
        GateCase gc;
        gc.transfer = 21;
        gc.folders = {dir};
        gc.dest = dir + L"\\same.bin";
        gc.bytes = body(n, 13);
        const FakeCopy c = runGateCase(gc);
        expect(c.got == n && !c.readFailed && readFile(gc.dest) == gc.bytes && readZoneId(gc.dest) == 3,
               "gate: with a working mark the copy completes and carries ZoneId=3");
    }
    {   // The same with the file sized first, as the shell does: kept after the check.
        const std::wstring dir = tempDir(L"gate-sized");
        GateCase gc;
        gc.transfer = 30;
        gc.folders = {dir};
        gc.dest = dir + L"\\same.bin";
        gc.bytes = body(n, 11);
        gc.presize = 5000;
        const FakeCopy c = runGateCase(gc);
        expect(c.got == n && !c.readFailed && readFile(gc.dest) == gc.bytes && readZoneId(gc.dest) == 3,
               "gate: a copy sized past the manifest first completes, is cut to size and kept with ZoneId=3");
    }
    {   // #60 r3: an empty file's stream gets the gate too.
        const std::wstring dir = tempDir(L"gate-empty");
        GateCase gc;
        gc.transfer = 28;
        gc.folders = {dir};
        gc.dest = dir + L"\\same.bin";
        const FakeCopy c = runGateCase(gc);
        expect(!c.readFailed && exists(gc.dest) && sizeOf(gc.dest) == 0 && readZoneId(gc.dest) == 3,
               "gate: an empty pasted file carries ZoneId=3 (#60 r3)");
    }
    {   // #60 r3: an empty file whose mark cannot be written is refused.
        const std::wstring dir = tempDir(L"gate-empty-noads");
        GateCase gc;
        gc.transfer = 29;
        gc.ops = noStreams;
        gc.folders = {dir};
        gc.dest = dir + L"\\same.bin";
        const FakeCopy c = runGateCase(gc);
        expect(c.readFailed, "gate: an empty file whose mark cannot be written fails its read (#60 r3)");
    }
    {   // No streams (FAT, exFAT): the mark cannot be written.
        const std::wstring dir = tempDir(L"gate-noads");
        GateCase gc;
        gc.transfer = 22;
        gc.ops = noStreams;
        gc.folders = {dir};
        gc.dest = dir + L"\\same.bin";
        gc.bytes = body(n, 17);
        const FakeCopy c = runGateCase(gc);
        std::printf("  no-ADS copy: got=%llu of %zu failed=%d\n", static_cast<unsigned long long>(c.got), n, int(c.readFailed));
        expect(c.got == n - 1 && c.readFailed,
               "gate: no Zone.Identifier possible: the last byte is withheld and the copy fails (#53)");
    }
    {   // #60 r3 item 2: the mark fails, and the shell had sized the copy to
        // its full length first and keeps it open (no delete sharing) for a
        // while. Once it lets go the copy is removed: no full-size unmarked
        // file stays.
        const std::wstring dir = tempDir(L"gate-held");
        GateCase gc;
        gc.transfer = 23;
        gc.ops = noStreams;
        gc.folders = {dir};
        gc.dest = dir + L"\\same.bin";
        gc.bytes = body(n, 19);
        gc.holdMs = 4000;
        gc.presize = 0;
        const FakeCopy c = runGateCase(gc);
        std::printf("  held copy: got=%llu failed=%d exists=%d size=%llu zone=%d\n", static_cast<unsigned long long>(c.got),
                    int(c.readFailed), int(exists(gc.dest)), static_cast<unsigned long long>(sizeOf(gc.dest)),
                    readZoneId(gc.dest));
        expect(c.readFailed && !exists(gc.dest),
               "gate: a refused copy the shell sized to full length is removed once the shell lets go (#60 r3)");
    }
    {   // An existing Zone.Identifier with ZoneId=0 (Local machine).
        const std::wstring dir = tempDir(L"gate-zone0");
        GateCase gc;
        gc.transfer = 24;
        gc.folders = {dir};
        gc.dest = dir + L"\\same.bin";
        gc.bytes = body(n, 23);
        gc.presetZone = "[ZoneTransfer]\r\nZoneId=0\r\n";
        const FakeCopy c = runGateCase(gc);
        expect(c.got == n && readZoneId(gc.dest) == 3, "gate: an existing ZoneId=0 is replaced by ZoneId=3 (#53)");
    }
    {   // A mark that stays invalid.
        const std::wstring dir = tempDir(L"gate-stuck");
        GateCase gc;
        gc.transfer = 25;
        gc.ops = stuckInvalid;
        gc.folders = {dir};
        gc.dest = dir + L"\\same.bin";
        gc.bytes = body(n, 29);
        const FakeCopy c = runGateCase(gc);
        expect(c.got == n - 1 && c.readFailed, "gate: a Zone.Identifier that stays invalid withholds the last byte (#53)");
    }
    // A neighbour: another file named same.bin, same size, all zeros (what an
    // unwritten copy reads as), created during the paste in another searched
    // folder, nobody writing it. Not ours: kept as it is and never marked,
    // whether our copy's mark fails (pass 0) or works (pass 1). #60 r3.
    for (int pass = 0; pass < 2; ++pass) {
        const std::wstring x = tempDir(pass == 0 ? L"gate-nx0" : L"gate-nx1");
        const std::wstring y = tempDir(pass == 0 ? L"gate-ny0" : L"gate-ny1");
        const std::wstring neighbour = y + L"\\same.bin";
        const std::vector<uint8_t> other(n, 0);
        GateCase gc;
        gc.transfer = 26 + uint32_t(pass);
        if (pass == 0) gc.ops = noStreams;
        gc.folders = {x, y};
        gc.dest = x + L"\\same.bin";
        gc.bytes = body(n, 37);
        gc.beforeCopy = [&] { writeFile(neighbour, other); };
        runGateCase(gc);
        if (pass == 0) {
            expect(exists(neighbour) && readFile(neighbour) == other && readZoneId(neighbour) == -1,
                   "gate: a same-name, same-size neighbour is kept and not marked when marking fails (#60 r3)");
        } else {
            expect(exists(neighbour) && readFile(neighbour) == other && readZoneId(neighbour) == -1,
                   "gate: a same-name, same-size neighbour is kept and not marked (#60 r3)");
            expect(readFile(gc.dest) == gc.bytes && readZoneId(gc.dest) == 3, "gate: our copy beside it is kept with ZoneId=3");
        }
    }
}

}  // namespace

int main() {
    if (FAILED(OleInitialize(nullptr))) {
        std::printf("FAIL OleInitialize\n");
        return 1;
    }
    // A refused paste can leave the shell's copy (and its error dialog)
    // blocking this thread; fail with a line instead of the step timeout.
    std::thread([] {
        Sleep(120000);
        std::printf("FAIL watchdog: the test did not finish in 120 s (shell paste blocked)\n");
        std::fflush(stdout);
        ExitProcess(2);
    }).detach();
    helpers();
    endToEnd();
    gateCases();
    OleUninitialize();
    std::printf("%d passed, %d failed\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
