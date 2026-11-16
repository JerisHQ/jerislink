// Mark of the Web for Mac->Windows paste (F3 r2, hand test H): Explorer does
// not write Zone.Identifier for virtual files pasted from the clipboard, so
// the viewer writes ZoneId=3 itself once each file is delivered.
//
// 1. writeInternetZone / readZoneId / markDelivered on real NTFS files.
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

void helpers() {
    const std::wstring dir = tempDir(L"unit");
    const std::wstring a = dir + L"\\a.txt";
    expect(writeFile(a, body(1000, 3)), "unit: test file written");
    expect(readZoneId(a) == -1, "unit: a new local file has no Zone.Identifier");
    expect(writeInternetZone(a) == ZoneWrite::Written, "unit: Zone.Identifier written");
    expect(readZoneId(a) == 3, "unit: ZoneId=3 read back");
    expect(writeInternetZone(a) == ZoneWrite::Exists, "unit: an existing Zone.Identifier is kept, not overwritten");

    // markDelivered: the manifest's file, Explorer's "Keep both" name, size
    // and time checks.
    const std::wstring sub = dir + L"\\m";
    CreateDirectoryW(sub.c_str(), nullptr);
    Manifest m;
    m.transfer = 2;
    m.items = {
        {false, 500, 0, L"x.bin"},            // 0: pasted as "x (2).bin" (x.bin exists, older)
        {true, 0, 0, L"d"},                   // 1: folder, never marked
        {false, 300, 0, L"d\\inner.bin"},     // 2: under the folder
        {false, 77, 0, L"wrong-size.bin"},    // 3: same name, other size: not ours
        {false, 10, 0, L"absent.bin"},        // 4: not there (yet)
    };
    m.files = 4;
    // The old x.bin was there before the paste: older than `since`.
    expect(writeFile(sub + L"\\x.bin", body(500, 5)), "unit: an older x.bin exists");
    Sleep(1100);
    const FILETIME since = nowMinus(0);
    Sleep(50);
    expect(writeFile(sub + L"\\x (2).bin", body(500, 5)), "unit: pasted x (2).bin");
    CreateDirectoryW((sub + L"\\d").c_str(), nullptr);
    expect(writeFile(sub + L"\\d\\inner.bin", body(300, 7)), "unit: pasted d\\inner.bin");
    expect(writeFile(sub + L"\\wrong-size.bin", body(78, 7)), "unit: a same-name file of another size");
    std::set<uint32_t> want{0, 1, 2, 3, 4};
    std::set<uint32_t> done;
    const auto st = markDelivered(m, {dir + L"\\nowhere", sub}, since, want, done);
    expect(st.written == 2 && st.existed == 0 && st.failed == 0, "unit: two delivered files marked");
    expect(readZoneId(sub + L"\\x (2).bin") == 3, "unit: the Keep-both copy carries ZoneId=3");
    expect(readZoneId(sub + L"\\x.bin") == -1, "unit: the older file of the same name is left alone");
    expect(readZoneId(sub + L"\\d\\inner.bin") == 3, "unit: a file inside a pasted folder carries ZoneId=3");
    expect(readZoneId(sub + L"\\wrong-size.bin") == -1, "unit: a file of another size is left alone");
    expect(done == std::set<uint32_t>{0, 2} && want == std::set<uint32_t>{3, 4},
           "unit: found files done, folder dropped, others still wanted");
    const auto again = markDelivered(m, {sub}, since, want, done);
    expect(again.written == 0 && want.size() == 2, "unit: a second pass finds nothing new");
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
    const std::vector<std::vector<uint8_t>> files = {body(300000, 3), {}, body(5000, 11)};
    std::vector<file::Entry> es = {
        {t, 0, file::kind::kFile, files[0].size(), 1700000000, bytesOf("report?.txt")},
        {t, 1, file::kind::kDir, 0, 1700000000, bytesOf("box*")},
        {t, 2, file::kind::kFile, files[2].size(), 1700000000, bytesOf("box*/inner.bin")},
    };
    Manifest m;
    const std::string why = buildManifest(file::Offer{t, file::purpose::kAnnounce, 3, files[0].size() + files[2].size()}, es, m);
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
    // The shell copies on its own thread; the viewer marks ~1.5 s after each
    // file. Wait up to 40 s.
    for (int i = 0; i < 400; ++i) {
        if (readZoneId(p0) == 3 && readZoneId(p2) == 3) break;
        pump(100);
    }
    expect(readFile(p0) == files[0], "e2e: report?.txt pasted as report_.txt with the right bytes");
    expect(readFile(p2) == files[2], "e2e: box*/inner.bin pasted as box_\\inner.bin with the right bytes");
    expect(readZoneId(p0) == 3, "e2e: report_.txt carries Zone.Identifier ZoneId=3");
    expect(readZoneId(p2) == 3, "e2e: box_\\inner.bin carries Zone.Identifier ZoneId=3");
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
    for (int i = 0; i < 400 && (readZoneId(q0) != 3 || readZoneId(q2) != 3); ++i) pump(100);
    expect(readZoneId(q2) == 3, "e2e: the second paste's folder file is marked too");
    expect(readFile(q0) == files[0] && readZoneId(q0) == 3, "e2e: the second paste is marked too");

    const auto zs = clip.zoneStats();
    std::printf("  zone stats: written=%llu existed=%llu failed=%llu (existed>0 means the shell marked them itself)\n",
                static_cast<unsigned long long>(zs.written), static_cast<unsigned long long>(zs.existed),
                static_cast<unsigned long long>(zs.failed));
    expect(zs.written == 4 && zs.failed == 0, "e2e: four delivered files marked once each, none failed");
    {
        std::lock_guard<std::mutex> lock(logMu);
        bool named = false;
        for (const auto& l : logs) named |= l.find("report") != std::string::npos || l.find("inner") != std::string::npos;
        expect(!named, "e2e: no file names in the log");
    }

    stop = true;
    host.join();
    clip.withdraw(0);
    clip.stop();
}

}  // namespace

int main() {
    if (FAILED(OleInitialize(nullptr))) {
        std::printf("FAIL OleInitialize\n");
        return 1;
    }
    helpers();
    endToEnd();
    OleUninitialize();
    std::printf("%d passed, %d failed\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
