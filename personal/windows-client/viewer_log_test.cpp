// Console test for viewer_log.hpp (the async, size-capped viewer logger).
// Also measures the caller-side cost per line: the old logger (open, write,
// flush, close two files per line) against queueing a line.
#include "viewer_log.hpp"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

static int gPass = 0, gFail = 0;
static const std::string EOL = jl::kLogEol;
static void expect(bool ok, const std::string& what) {
    if (ok) ++gPass; else ++gFail;
    std::printf("%s %s\n", ok ? "PASS" : "FAIL", what.c_str());
}

static std::string dir() {
    char buf[MAX_PATH + 2]{};
    GetTempPathA(sizeof(buf), buf);
    std::string d = std::string(buf) + "jl-log-test-" + std::to_string(GetCurrentProcessId()) + "\\";
    CreateDirectoryA(d.c_str(), nullptr);
    return d;
}
static std::string readAll(const std::string& p) {
    std::ifstream f(p, std::ios::binary);
    std::ostringstream o; o << f.rdbuf(); return o.str();
}
static void writeAll(const std::string& p, const std::string& s) {
    std::ofstream f(p, std::ios::binary | std::ios::trunc); f << s;
}
static uint64_t sizeOf(const std::string& p) { return jl::LogFile::fileSize(p); }
static bool exists(const std::string& p) { return GetFileAttributesA(p.c_str()) != INVALID_FILE_ATTRIBUTES; }
static size_t countLines(const std::string& s) { return static_cast<size_t>(std::count(s.begin(), s.end(), '\n')); }

static std::string lineN(int i) {
    char b[96];
    std::snprintf(b, sizeof(b), "stats.line i=%06d payload=abcdefghijklmnopqrstuvwxyz0123456789", i);
    return b;
}

static void testOrderAndContents(const std::string& d) {
    const std::string s = d + "order-session.log", h = d + "order-history.log";
    writeAll(s, "stale session line\n");
    writeAll(h, "earlier run\n");
    {
        jl::ViewerLog log;
        log.start(s, h);
        for (int i = 0; i < 1000; ++i) log.line(lineN(i));
        log.flush();
        expect(countLines(readAll(s)) == 1000, "flush(): all 1000 lines on disk before stop");
        log.stop();
    }
    const std::string sess = readAll(s), hist = readAll(h);
    std::string want;
    for (int i = 0; i < 1000; ++i) want += lineN(i) + EOL;
    expect(sess == want, "session log: truncated at start, 1000 lines in order");
    expect(hist == "earlier run\n" + want, "history log: appended after earlier run, in order");
}

static void testHistoryRotation(const std::string& d) {
    const std::string s = d + "rot-session.log", h = d + "rot-history.log";
    const uint64_t cap = 64 * 1024;
    uint64_t rotations = 0;
    {
        jl::ViewerLog log;
        log.start(s, h, 1ull << 30, cap);
        for (int i = 0; i < 20000; ++i) log.line(lineN(i));  // ~1.3 MB
        log.stop();
        rotations = log.historyRotations();
    }
    const uint64_t hs = sizeOf(h), os = sizeOf(h + ".old");
    std::printf("  history=%llu old=%llu rotations=%llu cap=%llu\n", (unsigned long long)hs,
                (unsigned long long)os, (unsigned long long)rotations, (unsigned long long)cap);
    expect(rotations >= 10, "history rotated many times for ~20x cap of lines");
    expect(hs <= cap, "history stays <= cap");
    expect(os <= cap, "history.old <= cap");
    const std::string tail = readAll(h);
    expect(tail.size() > 0 && tail.substr(tail.size() - lineN(19999).size() - 2) == lineN(19999) + EOL,
           "newest line is at the end of history");
    expect(readAll(h).find(lineN(0)) == std::string::npos && readAll(h + ".old").find(lineN(0)) == std::string::npos,
           "oldest lines dropped (only one .old kept)");
}

static void testLegacyOversized(const std::string& d) {
    const std::string s = d + "legacy-session.log", h = d + "legacy-history.log";
    const uint64_t cap = 256 * 1024;
    std::string big;
    int n = 0;
    while (big.size() < 3 * 1024 * 1024) big += lineN(n++) + "\n";  // 3 MB > cap
    writeAll(h, big);
    writeAll(h + ".old", "previous old file\n");
    const uint64_t before = sizeOf(h);
    uint64_t trimmedFrom = 0;
    {
        jl::ViewerLog log;
        log.start(s, h, 1ull << 30, cap);
        log.line("viewer.start pid=1");
        log.stop();
        trimmedFrom = log.legacyTrimmedFrom();
    }
    const std::string old = readAll(h + ".old"), hist = readAll(h);
    std::printf("  legacy before=%llu after: history=%llu old=%llu\n", (unsigned long long)before,
                (unsigned long long)hist.size(), (unsigned long long)old.size());
    expect(trimmedFrom == before, "legacy history over cap detected at start");
    expect(old.size() <= cap && old.size() > cap - 200, ".old keeps the newest ~cap bytes");
    expect(!old.empty() && old.find(lineN(n - 1) + "\n") == old.size() - lineN(n - 1).size() - 1,
           ".old ends with the newest legacy line");
    expect(old.compare(0, 11, "stats.line ") == 0, ".old starts at a full line");
    expect(hist.find("log.history_trimmed old_bytes=" + std::to_string(before)) == 0 &&
               hist.find("viewer.start pid=1" + EOL) != std::string::npos,
           "new history starts with a trim note, then the new lines");
    expect(readAll(s).find("log.history_trimmed") == 0, "session log records the trim too");
}

static void testUnderCapUntouched(const std::string& d) {
    const std::string s = d + "small-session.log", h = d + "small-history.log";
    writeAll(h, "keep me\n");
    {
        jl::ViewerLog log;
        log.start(s, h);
        log.line("next");
    }  // destructor drains
    expect(readAll(h) == "keep me\nnext" + EOL, "history under cap: kept, appended; destructor drains");
    expect(!exists(h + ".old"), "no .old created when under cap");
}

static void testSessionCap(const std::string& d) {
    const std::string s = d + "cap-session.log", h = d + "cap-history.log";
    const uint64_t cap = 32 * 1024;
    {
        jl::ViewerLog log;
        log.start(s, h, cap, 1ull << 30);
        for (int i = 0; i < 5000; ++i) log.line(lineN(i));
        log.stop();
        expect(log.sessionTruncations() >= 5, "session log emptied when it reached its cap");
    }
    const std::string sess = readAll(s);
    expect(sess.size() <= cap, "session log stays <= cap");
    expect(sess.find("log.truncated cap_bytes=") == 0, "session log restarts with a truncated note");
    expect(sess.find(lineN(4999) + EOL) != std::string::npos, "newest line kept in session log");
    expect(countLines(readAll(h)) == 5000, "history unaffected by session cap");
}

static void testOpenSharing(const std::string& d) {
    // Someone reading (tail -f style) the history must not block rotation.
    const std::string s = d + "share-session.log", h = d + "share-history.log";
    const uint64_t cap = 16 * 1024;
    HANDLE reader = INVALID_HANDLE_VALUE;
    {
        jl::ViewerLog log;
        log.start(s, h, 1ull << 30, cap);
        log.line("first");
        log.flush();
        reader = CreateFileA(h.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             nullptr, OPEN_EXISTING, 0, nullptr);
        for (int i = 0; i < 2000; ++i) log.line(lineN(i));
        log.stop();
        expect(log.historyRotations() >= 1, "rotation works while another process reads the file");
    }
    if (reader != INVALID_HANDLE_VALUE) CloseHandle(reader);
    expect(sizeOf(h) <= cap, "history <= cap with a reader attached");
}

// Two writers on one history, through two separate handles, taking turns.
// coordinated=false is the per-process size count from before: each writer
// sees only its own bytes, so the file passes the cap and a writer whose
// file was rotated by the other keeps appending to .old.
struct TwoWriterResult {
    uint64_t maxHistory = 0, maxOld = 0, reopens = 0, rotations = 0;
    bool newestKept = false;
};
static TwoWriterResult runTwoHandles(const std::string& h, bool coordinated) {
    const uint64_t cap = 64 * 1024;
    DeleteFileA(h.c_str());
    DeleteFileA((h + ".old").c_str());
    TwoWriterResult r;
    jl::LogFile a, b;
    a.configure(h, cap, true, false);
    b.configure(h, cap, true, false);
    a.setCoordinated(coordinated);
    b.setCoordinated(coordinated);
    a.open();
    b.open();
    std::string lastA, lastB;
    for (int i = 0; i < 200; ++i) {  // 200 x 2 x ~4 KB = ~1.6 MB, ~25 x cap
        std::string ca, cb;
        for (int k = 0; k < 50; ++k) {
            lastA = "A " + lineN(i * 50 + k);
            lastB = "B " + lineN(i * 50 + k);
            ca += lastA + EOL;
            cb += lastB + EOL;
        }
        a.write(ca);
        r.maxHistory = std::max(r.maxHistory, sizeOf(h));
        r.maxOld = std::max(r.maxOld, sizeOf(h + ".old"));
        b.write(cb);
        r.maxHistory = std::max(r.maxHistory, sizeOf(h));
        r.maxOld = std::max(r.maxOld, sizeOf(h + ".old"));
    }
    r.reopens = a.reopens() + b.reopens();
    r.rotations = a.rotations() + b.rotations();
    a.close();
    b.close();
    // B wrote last, so its newest line is in the history. A's may already
    // be in .old if B's last write rotated the file.
    const std::string hist = readAll(h), old = readAll(h + ".old");
    r.newestKept = hist.find(lastB + EOL) != std::string::npos &&
                   (hist.find(lastA + EOL) != std::string::npos || old.find(lastA + EOL) != std::string::npos);
    return r;
}

static void testTwoWritersSeparateHandles(const std::string& d) {
    const uint64_t cap = 64 * 1024;
    const TwoWriterResult before = runTwoHandles(d + "two-before-history.log", false);
    const TwoWriterResult after = runTwoHandles(d + "two-after-history.log", true);
    std::printf("  two writers, cap=%llu: before max history=%llu max old=%llu | after max history=%llu "
                "max old=%llu rotations=%llu reopens=%llu\n",
                (unsigned long long)cap, (unsigned long long)before.maxHistory, (unsigned long long)before.maxOld,
                (unsigned long long)after.maxHistory, (unsigned long long)after.maxOld,
                (unsigned long long)after.rotations, (unsigned long long)after.reopens);
    expect(before.maxHistory > cap || before.maxOld > cap,
           "two writers, per-process count (old code): a file passes the cap (the bug this test catches)");
    expect(after.maxHistory <= cap, "two writers: history stays <= cap");
    expect(after.maxOld <= cap, "two writers: .old stays <= cap (no writer left appending to it)");
    expect(after.rotations >= 10, "two writers: history rotated many times");
    expect(after.reopens >= 1, "two writers: the other writer followed the rotation and reopened");
    expect(after.newestKept, "two writers: newest line of each writer kept (last writer's in the current history)");
}

// Two viewer processes (this exe, --writer mode) writing the same history at
// the same time through ViewerLog. Each writer checks the cap after every
// write while it still holds the lock; the parent samples both sizes for
// the whole run.
static int writerMain(int argc, char** argv) {
    if (argc < 6) return 2;
    const std::string sess = argv[2], hist = argv[3], tag = argv[4];
    const int n = std::atoi(argv[5]);
    const uint64_t cap = 64 * 1024;
    uint64_t checks = 0, overCap = 0, maxHist = 0, maxOld = 0;
    jl::ViewerLog log;
    log.setHistoryTestHook([&](const char* stage) {
        if (std::strcmp(stage, "written") != 0) return;
        const uint64_t hs = sizeOf(hist), os = sizeOf(hist + ".old");
        ++checks;
        maxHist = std::max(maxHist, hs);
        maxOld = std::max(maxOld, os);
        if (hs > cap || os > cap) ++overCap;
    });
    log.start(sess, hist, 1ull << 30, cap);
    for (int i = 0; i < n; ++i) {
        log.line(tag + " " + lineN(i));
        if (i % 200 == 0) Sleep(0);
    }
    log.stop();
    std::printf("writer %s rotations=%llu reopens=%llu checks=%llu over_cap=%llu max_history=%llu max_old=%llu "
                "lock_failures=%llu dropped=%llu\n",
                tag.c_str(), (unsigned long long)log.historyRotations(), (unsigned long long)log.historyReopens(),
                (unsigned long long)checks, (unsigned long long)overCap, (unsigned long long)maxHist,
                (unsigned long long)maxOld, (unsigned long long)log.historyLockFailures(),
                (unsigned long long)log.historyDroppedChunks());
    if (overCap) return 3;
    if (checks == 0 || log.historyLockFailures() || log.historyDroppedChunks()) return 4;
    return 0;
}

static HANDLE spawnWriter(const std::string& sess, const std::string& hist, const std::string& tag, int n) {
    char exe[MAX_PATH]{};
    GetModuleFileNameA(nullptr, exe, MAX_PATH);
    std::string cmd = "\"" + std::string(exe) + "\" --writer \"" + sess + "\" \"" + hist + "\" " + tag + " " +
                      std::to_string(n);
    std::vector<char> buf(cmd.begin(), cmd.end());
    buf.push_back(0);
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessA(nullptr, buf.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi))
        return nullptr;
    CloseHandle(pi.hThread);
    return pi.hProcess;
}

static void testTwoWriterProcesses(const std::string& d) {
    const uint64_t cap = 64 * 1024;
    const std::string h = d + "proc-history.log";
    const int n = 20000;  // ~1.3 MB per process
    HANDLE p1 = spawnWriter(d + "proc-session-1.log", h, "P1", n);
    HANDLE p2 = spawnWriter(d + "proc-session-2.log", h, "P2", n);
    expect(p1 && p2, "two writer processes started");
    if (!p1 || !p2) return;
    HANDLE both[2] = {p1, p2};
    // Sample both files for the whole run, not just at the end.
    uint64_t samples = 0, maxHist = 0, maxOld = 0;
    DWORD w = WAIT_TIMEOUT;
    const ULONGLONG deadline = GetTickCount64() + 120000;
    while (w == WAIT_TIMEOUT && GetTickCount64() < deadline) {
        maxHist = std::max(maxHist, sizeOf(h));
        maxOld = std::max(maxOld, sizeOf(h + ".old"));
        ++samples;
        w = WaitForMultipleObjects(2, both, TRUE, 0);
        if (w == WAIT_TIMEOUT) Sleep(0);
    }
    DWORD e1 = 1, e2 = 1;
    GetExitCodeProcess(p1, &e1);
    GetExitCodeProcess(p2, &e2);
    CloseHandle(p1);
    CloseHandle(p2);
    std::printf("  writer exit codes: P1=%lu P2=%lu (3 = a writer saw a file over the cap)\n", e1, e2);
    expect(w != WAIT_TIMEOUT && e1 == 0 && e2 == 0,
           "both writer processes finished; each checked history and .old <= cap after every write it made");
    const std::string hist = readAll(h), old = readAll(h + ".old");
    std::printf("  two processes, cap=%llu: %llu samples during the run, max history=%llu max old=%llu | "
                "final history=%llu old=%llu\n",
                (unsigned long long)cap, (unsigned long long)samples, (unsigned long long)maxHist,
                (unsigned long long)maxOld, (unsigned long long)hist.size(), (unsigned long long)old.size());
    expect(samples >= 100, "two processes: sizes sampled throughout the run");
    expect(maxHist <= cap, "two processes: history <= cap at every sample");
    expect(maxOld <= cap, "two processes: .old <= cap at every sample");
    expect(hist.size() <= cap && old.size() <= cap, "two processes: final history and .old <= cap");
    bool whole = true;
    for (const std::string* f : {&hist, &old}) {
        size_t pos = 0;
        while (pos < f->size()) {
            const size_t e = f->find('\n', pos);
            if (e == std::string::npos) { whole = false; break; }
            const std::string l = f->substr(pos, e - pos);
            if (!(l.rfind("P1 stats.line ", 0) == 0 || l.rfind("P2 stats.line ", 0) == 0 ||
                  l.rfind("log.", 0) == 0) || l.empty() || l.back() != '\r')
                whole = false;
            pos = e + 1;
        }
    }
    expect(whole, "two processes: every line whole, none torn or mixed");
    // Whichever process finished last wrote the newest line: it must be in
    // the current history, not in .old or a file renamed away.
    expect(hist.find("P1 " + lineN(n - 1) + EOL) != std::string::npos ||
               hist.find("P2 " + lineN(n - 1) + EOL) != std::string::npos,
           "two processes: newest line is in the current history");
}

// Reads with full sharing, so it never blocks a rotation by the writer.
static std::string readShared(const std::string& p) {
    HANDLE f = CreateFileA(p.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) return {};
    std::string out;
    char buf[65536];
    DWORD got = 0;
    while (ReadFile(f, buf, sizeof(buf), &got, nullptr) && got) out.append(buf, got);
    CloseHandle(f);
    return out;
}
static size_t countOf(const std::string& hay, const std::string& needle) {
    size_t n = 0;
    for (size_t p = hay.find(needle); p != std::string::npos; p = hay.find(needle, p + 1)) ++n;
    return n;
}

// The race from review: writer B checks the cap, then writer A rotates the
// file, then B writes. B's write lands in the renamed file (.old), and if .old
// is replaced again the batch is lost. A test hook stops B between its check
// and its write and lets A try to rotate right there.
struct GapResult {
    bool aRotatedInGap = false;   // A finished its rotation while B was between check and write
    bool bLandedAtPath = false;   // right after B's write, B's batch is at the end of the file at the path
    size_t bCount = 0;            // copies of B's batch in history + .old at the end
    bool aInHistory = false;
    uint64_t history = 0, old = 0;
};
static GapResult runGap(const std::string& h, bool coordinated) {
    const uint64_t cap = 4096;
    DeleteFileA(h.c_str());
    DeleteFileA((h + ".old").c_str());
    std::string pre;
    for (int i = 0; pre.size() + 100 < cap - 100; ++i) pre += "pre " + lineN(i) + EOL;  // ~cap - 200
    writeAll(h, pre);
    const std::string bData = "B gap marker" + EOL;                   // fits: no rotation for B
    const std::string aData = "A rotating " + std::string(400, 'a') + EOL;  // over the cap: A rotates
    jl::LogFile a, b;
    a.configure(h, cap, true, false);
    b.configure(h, cap, true, false);
    a.setCoordinated(coordinated);
    b.setCoordinated(coordinated);
    a.open();
    b.open();
    HANDLE checked = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    HANDLE aDone = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    GapResult r;
    b.setTestHook([&](const char* stage) {
        if (std::strcmp(stage, "checked") == 0) {
            SetEvent(checked);
            // Uncoordinated, A rotates now. Coordinated, A must wait for
            // our lock: 500 ms without A finishing shows it is blocked.
            r.aRotatedInGap = WaitForSingleObject(aDone, coordinated ? 500 : 5000) == WAIT_OBJECT_0;
        } else {
            const std::string at = readShared(h);
            r.bLandedAtPath = at.size() >= bData.size() && at.compare(at.size() - bData.size(), bData.size(), bData) == 0;
        }
    });
    std::thread tb([&] { b.write(bData); });
    WaitForSingleObject(checked, 5000);
    a.write(aData);
    SetEvent(aDone);
    tb.join();
    a.close();
    b.close();
    CloseHandle(checked);
    CloseHandle(aDone);
    const std::string hist = readAll(h), old = readAll(h + ".old");
    r.bCount = countOf(hist, bData) + countOf(old, bData);
    r.aInHistory = hist.find(aData) != std::string::npos;
    r.history = hist.size();
    r.old = old.size();
    return r;
}

static void testCheckWriteGap(const std::string& d) {
    const GapResult before = runGap(d + "gap-before-history.log", false);
    const GapResult after = runGap(d + "gap-after-history.log", true);
    std::printf("  check/write gap: before aRotatedInGap=%d bAtPath=%d | after aRotatedInGap=%d bAtPath=%d "
                "bCopies=%zu history=%llu old=%llu\n",
                before.aRotatedInGap, before.bLandedAtPath, after.aRotatedInGap, after.bLandedAtPath, after.bCount,
                (unsigned long long)after.history, (unsigned long long)after.old);
    expect(before.aRotatedInGap && !before.bLandedAtPath,
           "gap, without the lock: A rotates between B's check and write, B's batch goes to the renamed file "
           "(the race this test catches)");
    expect(!after.aRotatedInGap, "gap, with the lock: A cannot rotate between B's check and B's write");
    expect(after.bLandedAtPath, "gap, with the lock: B's batch lands in the file at the path, not in .old");
    expect(after.bCount == 1, "gap, with the lock: B's batch is kept exactly once (not lost)");
    expect(after.aInHistory, "gap, with the lock: A rotated after B and wrote to the new history");
    expect(after.history <= 4096 && after.old <= 4096, "gap, with the lock: history and .old <= cap");
}

// Holds a log file's named mutex on another thread, like a stuck viewer.
struct LockHolder {
    HANDLE held = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    HANDLE release = CreateEventA(nullptr, TRUE, FALSE, nullptr);
    std::thread t;
    explicit LockHolder(const std::string& path) {
        const std::string name = jl::LogFile::mutexName(path);
        t = std::thread([this, name] {
            HANDLE m = CreateMutexA(nullptr, FALSE, name.c_str());
            WaitForSingleObject(m, INFINITE);
            SetEvent(held);
            WaitForSingleObject(release, INFINITE);
            ReleaseMutex(m);
            CloseHandle(m);
        });
        WaitForSingleObject(held, 5000);
    }
    void let() {
        SetEvent(release);
        if (t.joinable()) t.join();
    }
    ~LockHolder() {
        let();
        CloseHandle(held);
        CloseHandle(release);
    }
};

static void testLockTimeoutDefers(const std::string& d) {
    const std::string h = d + "locked-history.log";
    const uint64_t cap = 1024;
    DeleteFileA(h.c_str());
    DeleteFileA((h + ".old").c_str());
    jl::LogFile w;
    w.configure(h, cap, true, false);
    w.setLockTimeoutMs(50);
    w.open();
    w.write("first" + EOL);
    std::string fill;
    for (int i = 0; fill.size() + 100 < cap - 60; ++i) fill += lineN(i) + EOL;
    w.write(fill);  // just under the cap: the next lines need a rotation
    const std::string beforeLock = readShared(h);
    std::string later;
    {
        LockHolder holder(h);
        bool anyWritten = false;
        for (int i = 0; i < 5; ++i) {
            const std::string l = "deferred " + lineN(i) + EOL;
            later += l;
            anyWritten |= w.write(l);
        }
        expect(!anyWritten, "lock timeout: write() reports the data as not written");
        expect(readShared(h) == beforeLock, "lock timeout: history unchanged while another viewer holds the lock");
        expect(!exists(h + ".old"), "lock timeout: no rotation without the lock (no .old)");
        expect(w.pendingBytes() == later.size(), "lock timeout: the batches stay pending");
        expect(w.lockFailures() == 5, "lock timeout: each failed try is counted");
        holder.let();
        expect(w.flushPending(), "lock free again: pending data written on the next try");
    }
    w.close();
    const std::string hist = readAll(h), old = readAll(h + ".old");
    std::printf("  lock timeout: history=%llu old=%llu\n", (unsigned long long)hist.size(), (unsigned long long)old.size());
    const std::string note = "log.lock_timeout failures=5 dropped_chunks=0 dropped_bytes=0" + EOL;
    expect(exists(h + ".old") && old.compare(0, beforeLock.size(), beforeLock) == 0,
           "lock free again: the rotation happens then, under the lock");
    expect(countOf(hist + old, note) == 1, "lock free again: one note with the failure count");
    expect(hist == later || hist == note + later, "lock free again: every deferred line written, in order");
    expect(hist.size() <= cap && old.size() <= cap, "lock timeout: history and .old <= cap");
}

static void testLockTimeoutOverflow(const std::string& d) {
    const std::string h = d + "overflow-history.log";
    DeleteFileA(h.c_str());
    DeleteFileA((h + ".old").c_str());
    jl::LogFile w;
    w.configure(h, 64 * 1024, true, false);
    w.setLockTimeoutMs(20);
    w.setPendingCap(1000);
    w.open();
    std::vector<std::string> chunks;
    {
        LockHolder holder(h);
        for (int i = 0; i < 10; ++i) {
            chunks.push_back("chunk" + std::to_string(i) + " " + std::string(291, 'x') + EOL);  // 300 bytes
            w.write(chunks.back());
        }
        expect(sizeOf(h) == 0, "pending over its cap: still nothing written without the lock");
        expect(w.pendingBytes() <= 1000, "pending stays within its own cap");
        expect(w.droppedChunks() == 7 && w.droppedBytes() == 2100, "pending over its cap: oldest 7 chunks dropped and counted");
        holder.let();
        w.flushPending();
    }
    w.close();
    const std::string hist = readAll(h);
    expect(hist == "log.lock_timeout failures=10 dropped_chunks=7 dropped_bytes=2100" + EOL + chunks[7] + chunks[8] + chunks[9],
           "pending over its cap: note reports the drops, newest 3 chunks kept in order");
}

static double pct(std::vector<double> v, double p) {
    std::sort(v.begin(), v.end());
    return v[std::min(v.size() - 1, static_cast<size_t>(p * (v.size() - 1) + 0.5))];
}

static void oldLogLine(const std::string& sp, const std::string& hp, const std::string& s) {
    std::ofstream f(sp, std::ios::app); f << s << "\n"; f.flush();
    std::ofstream h(hp, std::ios::app); h << s << "\n"; h.flush();
}

static void testCallerCost(const std::string& d) {
    const int n = 3000;
    const std::string os = d + "bench-old-session.log", oh = d + "bench-old-history.log";
    const std::string ns = d + "bench-new-session.log", nh = d + "bench-new-history.log";
    std::vector<double> oldUs, newUs;
    oldUs.reserve(n); newUs.reserve(n);
    using clk = std::chrono::steady_clock;
    for (int i = 0; i < n; ++i) {
        const std::string l = lineN(i);
        const auto t0 = clk::now();
        oldLogLine(os, oh, l);
        oldUs.push_back(std::chrono::duration<double, std::micro>(clk::now() - t0).count());
    }
    {
        jl::ViewerLog log;
        log.start(ns, nh);
        for (int i = 0; i < n; ++i) {
            const std::string l = lineN(i);
            const auto t0 = clk::now();
            log.line(l);
            newUs.push_back(std::chrono::duration<double, std::micro>(clk::now() - t0).count());
        }
        log.stop();
    }
    const double o50 = pct(oldUs, 0.5), o99 = pct(oldUs, 0.99), n50 = pct(newUs, 0.5), n99 = pct(newUs, 0.99);
    std::printf("  caller us/line over %d lines: old open/write/close x2 p50=%.1f p99=%.1f | new queue p50=%.2f p99=%.2f\n",
                n, o50, o99, n50, n99);
    expect(n50 < o50, "queueing a line is cheaper than the old per-line open/close (p50)");
    expect(n99 < o99, "and at p99");
    expect(readAll(ns) == readAll(os) && readAll(nh) == readAll(oh), "new and old loggers write identical bytes");
}

int main(int argc, char** argv) {
    if (argc > 1 && std::string(argv[1]) == "--writer") return writerMain(argc, argv);
    const std::string d = dir();
    testOrderAndContents(d);
    testHistoryRotation(d);
    testLegacyOversized(d);
    testUnderCapUntouched(d);
    testSessionCap(d);
    testOpenSharing(d);
    testTwoWritersSeparateHandles(d);
    testCheckWriteGap(d);
    testLockTimeoutDefers(d);
    testLockTimeoutOverflow(d);
    testTwoWriterProcesses(d);
    testCallerCost(d);
    std::printf("%d PASS, %d FAIL\n", gPass, gFail);
    if (gFail) return 1;
    std::printf("VIEWER LOG TEST OK\n");
    return 0;
}
