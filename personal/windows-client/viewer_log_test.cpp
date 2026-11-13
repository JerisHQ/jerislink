// Console test for viewer_log.hpp (the async, size-capped viewer logger).
// Also measures the caller-side cost per line: the old logger (open, write,
// flush, close two files per line) against queueing a line.
#include "viewer_log.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

static int gPass = 0, gFail = 0;
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
    for (int i = 0; i < 1000; ++i) want += lineN(i) + "\n";
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
    expect(tail.size() > 0 && tail.substr(tail.size() - lineN(19999).size() - 1) == lineN(19999) + "\n",
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
               hist.find("viewer.start pid=1\n") != std::string::npos,
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
    expect(readAll(h) == "keep me\nnext\n", "history under cap: kept, appended; destructor drains");
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
    expect(sess.find(lineN(4999) + "\n") != std::string::npos, "newest line kept in session log");
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

int main() {
    const std::string d = dir();
    testOrderAndContents(d);
    testHistoryRotation(d);
    testLegacyOversized(d);
    testUnderCapUntouched(d);
    testSessionCap(d);
    testOpenSharing(d);
    testCallerCost(d);
    std::printf("%d PASS, %d FAIL\n", gPass, gFail);
    if (gFail) return 1;
    std::printf("VIEWER LOG TEST OK\n");
    return 0;
}
