#pragma once

// Mac->Windows paste (F3), viewer side. Design r2, "Windows clipboard detail
// (PR-F3)".
//
// When the user copies files in Finder, the host sends a manifest (OFFER
// purpose=announce + ENTRYs) on the pull file session. The viewer checks
// every name against the Windows path rules and puts a lazy clipboard object
// on Windows: FileGroupDescriptorW + FileContents. No data moves until
// Explorer pastes; then each FileContents stream asks PullHub for bytes and
// the session thread pulls them with REQUEST, about 256 KiB at a time, with
// at most 4 MiB requested but not yet read by Explorer.
//
// This header holds the parts with no COM so file_pull_test.cpp can lock
// them down: manifest checks and PullHub, the state shared by the session
// thread (network side) and the clipboard thread (Explorer side).
// FileClipboard, the COM object and its thread, is in file_pull.cpp.

#include "file_path_safety.hpp"
#include "file_proto.hpp"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace jl::filepull {

inline constexpr uint32_t kRequestBytes = 256 * 1024;
inline constexpr uint64_t kWindowBytes = 4ull * 1024 * 1024;
// FILEDESCRIPTORW.cFileName is MAX_PATH wide chars including the NUL.
inline constexpr size_t kMaxNameChars = 259;
// A stream read that sees no new byte for this long fails (Explorer shows
// its own error and the paste stops).
inline constexpr int kReadTimeoutMs = 30000;

struct Item {
    bool dir = false;
    uint64_t size = 0;
    int64_t mtime = 0;     // Unix seconds
    std::wstring rel;      // NFC, '\\'-separated, relative
};

struct Manifest {
    uint32_t transfer = 0;
    std::vector<Item> items;
    uint64_t total = 0;
    uint64_t files = 0;
    uint64_t renamed = 0;  // entries whose name was mapped for Windows (F3 r2)
};

// Checks a complete announce. Returns "" and fills `out`, or the reason the
// whole announce is refused (the viewer never offers part of a copy).
// Reasons: count, transfer, index, kind, bad_path, name_too_long, duplicate,
// no_parent, size, too_many, too_big, empty.
//
// F3 r2: a name Windows cannot hold (: * ? " < > |, trailing dot or space,
// CON/NUL/COM1...) is mapped by path::windowsPath() instead of refusing the
// copy; children follow their folder's new name, and a mapped name that
// clashes with another gets " (2)", " (3)" ... like Explorer. out.renamed
// counts mapped entries.
inline std::string buildManifest(const file::Offer& offer, const std::vector<file::Entry>& entries, Manifest& out) {
    out = Manifest{};
    if (offer.entries == 0) return "empty";
    if (offer.entries > file::kMaxEntries) return "too_many";
    if (offer.total > file::kMaxTotalBytes) return "too_big";
    if (entries.size() != offer.entries) return "count";
    const auto upper = [](std::wstring s) {
#ifdef _WIN32
        CharUpperBuffW(s.data(), DWORD(s.size()));
#endif
        return s;
    };
    const auto wide = [](const std::string& u) {
        std::wstring w;
#ifdef _WIN32
        const int n = MultiByteToWideChar(CP_UTF8, 0, u.data(), int(u.size()), nullptr, 0);
        if (n > 0) {
            w.assign(size_t(n), L'\0');
            MultiByteToWideChar(CP_UTF8, 0, u.data(), int(u.size()), w.data(), n);
        }
#else
        w.assign(u.begin(), u.end());
#endif
        for (wchar_t& ch : w) if (ch == L'/') ch = L'\\';
        return w;
    };
    std::set<std::wstring> seen;               // upper-cased: NTFS names are case-insensitive
    std::set<std::wstring> mappedKeys;         // keys of names that mapping produced
    std::map<std::string, std::string> dirs;   // folder as sent -> its name here
    uint64_t total = 0;
    for (size_t i = 0; i < entries.size(); ++i) {
        const auto& e = entries[i];
        if (e.transfer != offer.transfer) return "transfer";
        if (e.index != i) return "index";
        if (e.kind != file::kind::kFile && e.kind != file::kind::kDir) return "kind";
        const auto v = file::path::validate(e.path, /*mapWindowsNames=*/true);
        if (!v.ok()) return "bad_path";
        // Parent as sent; this entry lives under whatever that folder became.
        const size_t cutOrig = v.original.find_last_of('/');
        const size_t cutMapped = v.utf8.find_last_of('/');
        std::string parent;
        if (cutOrig != std::string::npos) {
            const auto it = dirs.find(v.original.substr(0, cutOrig));
            if (it == dirs.end()) return "no_parent";
            parent = it->second + "/";
        }
        const std::string leaf = cutMapped == std::string::npos ? v.utf8 : v.utf8.substr(cutMapped + 1);
        std::string name = parent + leaf;
        bool renamed = v.renamed || (cutOrig != std::string::npos && parent != v.original.substr(0, cutOrig) + "/");
        std::wstring rel = wide(name);
        if (!seen.insert(upper(rel)).second) {
            // Two Mac names that differ only in case are a real duplicate on
            // Windows; a clash that mapping caused (on either side) is
            // renumbered.
            if (!renamed && !mappedKeys.count(upper(rel))) return "duplicate";
            bool placed = false;
            for (int n = 2; n < 100 && !placed; ++n) {
                name = parent + file::path::clashName(leaf, n);
                rel = wide(name);
                placed = seen.insert(upper(rel)).second;
            }
            if (!placed) return "duplicate";
            renamed = true;
        }
        if (renamed) mappedKeys.insert(upper(rel));
        if (rel.size() > kMaxNameChars) return "name_too_long";
        const bool dir = e.kind == file::kind::kDir;
        if (dir) {
            if (e.size != 0) return "size";
            dirs[v.original] = name;
        } else {
            // #49/#53: checked before adding. Added first, a sum past 2^64
            // wraps, slips under the limit and can match offer.total.
            if (e.size > file::kMaxTotalBytes || e.size > file::kMaxTotalBytes - total) return "too_big";
            total += e.size;
            ++out.files;
        }
        if (renamed) ++out.renamed;
        out.items.push_back({dir, e.size, e.mtime, rel});
    }
    if (total != offer.total) return "size";
    out.transfer = offer.transfer;
    out.total = total;
    return "";
}

// Incremental hash for FILE_END checks (SHA-256 in the viewer, BCrypt).
class Digest {
public:
    virtual ~Digest() = default;
    virtual void update(const uint8_t* data, size_t size) = 0;
    virtual std::vector<uint8_t> finish() = 0;
};
using DigestFactory = std::function<std::unique_ptr<Digest>()>;

// Shared by the session thread and the clipboard (STA) thread; every public
// method locks. Readers are per manifest index: a new FileContents stream for
// an index replaces the old one. Bytes the old one requested and the host is
// still sending are dropped first ("stale"), and the new one asks again from
// offset 0 only after they have drained, so the host's sequential reader and
// ours always agree. The last byte of a file is held back until FILE_END's
// SHA-256 matched, so Explorer never completes a file that arrived damaged.
class PullHub {
public:
    enum class ReadResult { Ok, Eof, Failed, Timeout };
    struct Progress {
        bool active = false;      // a paste is pulling bytes
        uint64_t files = 0;       // files in the announce
        uint64_t filesDone = 0;   // files verified by FILE_END
        uint64_t total = 0;       // bytes in the announce
        uint64_t received = 0;    // bytes received for it
    };

    explicit PullHub(DigestFactory digest, std::function<void()> wake = {})
        : digest_(std::move(digest)), wake_(std::move(wake)) {}

    // ---- session thread ----

    // A checked manifest: it replaces any earlier one (its readers fail).
    void announce(const Manifest& m) {
        std::lock_guard<std::mutex> lock(mu_);
        dropLocked();
        current_ = m.transfer;
        items_ = m.items;
        files_ = m.files;
        total_ = m.total;
        filesDone_ = 0;
        received_ = 0;
        cv_.notify_all();
    }

    // CANCEL from the host, or the announce was refused: forget it.
    void cancel(uint32_t transfer) {
        std::lock_guard<std::mutex> lock(mu_);
        if (transfer != current_ || current_ == 0) return;
        dropLocked();
        cv_.notify_all();
    }

    // The session closed: nothing can arrive any more.
    void disconnect() {
        std::lock_guard<std::mutex> lock(mu_);
        dropLocked();
        cv_.notify_all();
    }

    uint32_t current() const {
        std::lock_guard<std::mutex> lock(mu_);
        return current_;
    }

    // The next REQUEST to send, or nothing. The caller paces them.
    std::optional<file::Request> nextRequest() {
        std::lock_guard<std::mutex> lock(mu_);
        if (current_ == 0) return std::nullopt;
        uint64_t unread = 0;
        for (const auto& [index, r] : readers_) unread += r.requested - r.consumed;
        for (auto& [index, r] : readers_) {
            if (r.failed || r.ended || hasStale(index)) continue;
            if (r.size == 0) {
                if (r.started) continue;
                r.started = true;
                return file::Request{current_, index, 0, 0};
            }
            if (r.requested >= r.size) continue;
            const uint64_t budget = unread >= kWindowBytes ? 0 : kWindowBytes - unread;
            const uint64_t len = std::min<uint64_t>({kRequestBytes, r.size - r.requested, budget});
            if (len == 0) continue;
            file::Request q{current_, index, r.requested, uint32_t(len)};
            r.started = true;
            r.requested += len;
            return q;
        }
        return std::nullopt;
    }

    // True while some reader still needs the network: the session polls fast.
    bool wantsService() const {
        std::lock_guard<std::mutex> lock(mu_);
        if (!stale_.empty()) return true;
        for (const auto& [index, r] : readers_) {
            if (!r.failed && !r.ended) return true;
        }
        return false;
    }

    void onData(const file::Data& d) {
        bool notify = false;
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (d.transfer != current_ || current_ == 0) return;
            auto st = stale_.find(d.index);
            if (st != stale_.end() && st->second.bytes > 0) {
                st->second.bytes -= std::min<uint64_t>(st->second.bytes, d.bytes.size());
                if (st->second.bytes == 0 && !st->second.end) stale_.erase(st);
                notify = true;   // a waiting reader may be able to start now
            } else {
                auto it = readers_.find(d.index);
                if (it == readers_.end() || it->second.failed || it->second.ended) return;
                Reader& r = it->second;
                if (d.offset != r.received || r.received + d.bytes.size() > r.requested) {
                    failLocked(r);
                } else {
                    if (r.received == 0) r.digest = digest_ ? digest_() : nullptr;
                    if (r.digest) r.digest->update(d.bytes.data(), d.bytes.size());
                    r.buf.insert(r.buf.end(), d.bytes.begin(), d.bytes.end());
                    r.received += d.bytes.size();
                    received_ += d.bytes.size();
                    rx_ += d.bytes.size();
                }
                cv_.notify_all();
            }
        }
        if (notify && wake_) wake_();
    }

    void onFileEnd(const file::FileEnd& e) {
        bool notify = false;
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (e.transfer != current_ || current_ == 0) return;
            auto st = stale_.find(e.index);
            if (st != stale_.end() && st->second.end) {
                stale_.erase(st);
                notify = true;
            } else {
                auto it = readers_.find(e.index);
                if (it == readers_.end() || it->second.failed || it->second.ended) return;
                Reader& r = it->second;
                std::vector<uint8_t> sha;
                if (r.received == r.size && r.started) {
                    if (r.received == 0) r.digest = digest_ ? digest_() : nullptr;
                    sha = r.digest ? r.digest->finish() : std::vector<uint8_t>{};
                }
                if (!sha.empty() && sha == e.sha256) {
                    r.ended = true;
                    ++filesDone_;
                } else {
                    failLocked(r);
                }
                cv_.notify_all();
            }
        }
        if (notify && wake_) wake_();
    }

    // REPLY failed carries only the transfer: every reader with bytes or a
    // FILE_END still coming fails. The host dropped its readers too.
    void onFailed(uint32_t transfer) {
        std::lock_guard<std::mutex> lock(mu_);
        if (transfer != current_ || current_ == 0) return;
        for (auto& [index, r] : readers_) {
            if (!r.ended && !r.failed && r.started) failLocked(r);
        }
        stale_.clear();
        cv_.notify_all();
    }

    // ---- clipboard thread ----

    // Explorer asked for FileContents of `index`. Returns a reader token, or
    // 0 when the announce is gone or the index is not a file.
    uint64_t open(uint32_t transfer, uint32_t index) {
        uint64_t token = 0;
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (transfer != current_ || current_ == 0 || index >= items_.size() || items_[index].dir) return 0;
            auto it = readers_.find(index);
            if (it != readers_.end()) retireLocked(index, it->second);
            Reader r;
            r.token = token = ++nextToken_;
            r.size = items_[index].size;
            readers_[index] = std::move(r);
        }
        if (wake_) wake_();
        return token;
    }

    // The stream was released.
    void close(uint64_t token) {
        std::lock_guard<std::mutex> lock(mu_);
        for (auto it = readers_.begin(); it != readers_.end(); ++it) {
            if (it->second.token == token) {
                retireLocked(it->first, it->second);
                readers_.erase(it);
                return;
            }
        }
    }

    // Copies up to `size` bytes. Blocks until at least one byte, the end of
    // the file, a failure, or `timeoutMs` without progress.
    ReadResult read(uint64_t token, uint8_t* out, size_t size, size_t& got, int timeoutMs) {
        got = 0;
        bool opened = false;
        {
            std::unique_lock<std::mutex> lock(mu_);
            Reader* r = nullptr;
            const bool ready = cv_.wait_for(lock, std::chrono::milliseconds(timeoutMs), [&] {
                r = findLocked(token);
                return !r || r->failed || deliverable(*r) > 0 || (r->ended && r->buf.empty());
            });
            if (!r || r->failed) return ReadResult::Failed;
            if (!ready) return ReadResult::Timeout;
            const size_t n = std::min(size, deliverable(*r));
            if (n == 0) return ReadResult::Eof;
            std::copy(r->buf.begin(), r->buf.begin() + ptrdiff_t(n), out);
            r->buf.erase(r->buf.begin(), r->buf.begin() + ptrdiff_t(n));
            r->consumed += n;
            got = n;
            opened = true;
        }
        if (opened && wake_) wake_();   // the window opened
        return ReadResult::Ok;
    }

    Progress progress() const {
        std::lock_guard<std::mutex> lock(mu_);
        Progress p;
        for (const auto& [index, r] : readers_) {
            if (r.started && !r.ended && !r.failed) p.active = true;
        }
        p.files = files_;
        p.filesDone = filesDone_;
        p.total = total_;
        p.received = received_;
        return p;
    }

    uint64_t rxBytes() const {
        std::lock_guard<std::mutex> lock(mu_);
        return rx_;
    }

private:
    struct Reader {
        uint64_t token = 0;
        uint64_t size = 0;
        bool started = false;
        uint64_t requested = 0;
        uint64_t received = 0;
        uint64_t consumed = 0;
        std::deque<uint8_t> buf;
        bool ended = false;
        bool failed = false;
        std::unique_ptr<Digest> digest;
    };
    struct Stale {
        uint64_t bytes = 0;   // requested, not yet arrived
        bool end = false;     // FILE_END still coming
    };

    bool hasStale(uint32_t index) const { return stale_.count(index) > 0; }

    // Bytes a read may hand out: all of them once FILE_END matched, else all
    // but the file's last byte.
    static size_t deliverable(const Reader& r) {
        if (r.ended) return r.buf.size();
        if (r.size == 0) return 0;
        const uint64_t limit = r.size - 1;
        if (r.consumed >= limit) return 0;
        return size_t(std::min<uint64_t>(r.buf.size(), limit - r.consumed));
    }

    Reader* findLocked(uint64_t token) {
        for (auto& [index, r] : readers_) {
            if (r.token == token) return &r;
        }
        return nullptr;
    }

    // What the host still owes this reader becomes stale for its index.
    void retireLocked(uint32_t index, const Reader& r) {
        if (r.failed || r.ended || !r.started) return;
        Stale& s = stale_[index];
        s.bytes += r.requested - r.received;
        if (r.requested == r.size) s.end = true;
        if (s.bytes == 0 && !s.end) stale_.erase(index);
    }

    void failLocked(Reader& r) {
        r.failed = true;
        r.buf.clear();
    }

    void dropLocked() {
        current_ = 0;
        items_.clear();
        readers_.clear();   // a blocked read finds its token gone: Failed
        stale_.clear();
        files_ = filesDone_ = total_ = received_ = 0;
    }

    DigestFactory digest_;
    std::function<void()> wake_;
    mutable std::mutex mu_;
    std::condition_variable cv_;
    uint32_t current_ = 0;
    std::vector<Item> items_;
    std::map<uint32_t, Reader> readers_;
    std::map<uint32_t, Stale> stale_;
    uint64_t nextToken_ = 0;
    uint64_t files_ = 0;
    uint64_t filesDone_ = 0;
    uint64_t total_ = 0;
    uint64_t received_ = 0;
    uint64_t rx_ = 0;
};

#ifdef _WIN32
// SHA-256 through BCrypt, for PullHub.
DigestFactory sha256Digest();

// ---- Mark of the Web for pasted Mac files (F3 r2, #53 r2) --------------
//
// Explorer writes a virtual-file paste (FileGroupDescriptorW + FileContents)
// itself and, as the F3 hand test showed, adds no Zone.Identifier to it,
// whatever the source says in "UntrustedDragDrop". The viewer never learns
// the destination folder either. So the last byte of each file waits for the
// mark: when Explorer asks for it, FileClipboard looks for the copy on disk
// (in folders where the shell reported new items during the paste, in
// folders open in Explorer windows when the paste started, and on the
// Desktop), proves it is this transfer's copy, and makes sure it carries
// ZoneId=3 (Internet), the mark a browser download gets. Only then does
// Explorer get the last byte. If no copy is found, or the mark cannot be
// written or read back, the read fails and Explorer never completes the file.
//
// A copy counts as ours only when it has the manifest's path (or Explorer's
// "name (2).ext" for the top item), was created after the paste started, is
// at least as long as the bytes handed out (Explorer may set a larger size
// before it writes), and its first and last bytes (up to 64 KiB each, at
// their offsets) are the bytes this stream handed out, or still zero:
// Explorer keeps its last buffer until it has the last byte, so the end of
// the copy is often not written yet when the gate runs. Any other bytes
// there mean the file is not ours. Nothing else is marked or deleted.
// An empty file has no last byte to hold back and is pasted unmarked.

enum class ZoneWrite { Written, Exists, Failed };

// Writes "[ZoneTransfer]\r\nZoneId=3\r\n" to `path`:Zone.Identifier unless that
// stream already exists. Failed on volumes without streams (FAT, exFAT).
ZoneWrite writeInternetZone(const std::wstring& path);

// Reads `path`:Zone.Identifier's ZoneId, or -1 if there is none.
int readZoneId(const std::wstring& path);

// The two calls above, swappable so a test can stand in for a volume
// without streams (FAT, exFAT), where writing the mark fails.
struct ZoneOps {
    ZoneWrite (*write)(const std::wstring&) = writeInternetZone;
    int (*read)(const std::wstring&) = readZoneId;
};

struct ZoneMarkStats {
    uint32_t written = 0;  // Zone.Identifier ZoneId=3 added (or a weaker zone replaced)
    uint32_t existed = 0;  // already ZoneId=3 or 4 (kept)
    uint32_t failed = 0;   // found, but could not be marked: the last byte was withheld
};

// One file's gate: asked before Explorer gets the file's last byte.
struct GateRequest {
    uint32_t transfer = 0;
    uint32_t index = 0;
    std::wstring rel;            // manifest path, Windows-mapped
    uint64_t size = 0;           // manifest size
    FILETIME since{};            // a copy must be created at or after this
    std::vector<uint8_t> head;   // the first bytes handed out (up to 64 KiB)
    std::vector<uint8_t> tail;   // the last bytes handed out before the gate (up to 64 KiB)
};

enum class GateOutcome {
    Marked,        // every copy found carries ZoneId=3 (or 4)
    NotFound,      // no copy proven to be ours
    WriteFailed,   // a copy found, the mark could not be written (a volume without streams)
    Invalid,       // a copy found, its Zone.Identifier never read back as ZoneId=3
};

// Why no copy was proven: counts and sizes only, never names, for the log.
struct GateProbe {
    uint32_t paths = 0;       // candidate paths tried
    uint32_t present = 0;     // of those, a file is there
    uint32_t tooSmall = 0;    // shorter than the bytes handed out
    uint32_t larger = 0;      // longer than the manifest size (Explorer sized it first; not a refusal)
    uint32_t older = 0;       // created before the paste started
    uint32_t openFailed = 0;  // could not be opened to check its bytes
    uint32_t headDiff = 0;    // the first bytes are neither the ones handed out nor unwritten zeros
    uint32_t tailDiff = 0;    // the bytes before the held-back one: neither ours nor unwritten zeros
    uint64_t lastSize = 0;    // size of the last file found
    int64_t lastAgeMs = 0;    // its creation time minus `since`
    uint32_t openError = 0;   // GetLastError of the last byte check that could not open
};

// Looks for `r`'s copy under `folders`, proves it by name, time, size and
// bytes, and marks every proven copy. Counts the outcome once in `stats`;
// `probe`, if given, says why nothing was proven.
GateOutcome gateFile(const GateRequest& r, const std::vector<std::wstring>& folders, const ZoneOps& zone,
                     ZoneMarkStats& stats, GateProbe* probe = nullptr);

// The Windows clipboard object for an announce, on its own STA thread.
// offer() and withdraw() return at once; the thread does the OLE calls.
// Windows' clipboard is only cleared when it still holds our object, so a
// later copy on Windows is never wiped.
class FileClipboard {
public:
    using LogFn = std::function<void(const std::string&)>;
    // `zone`: the Zone.Identifier calls (a test stands in for a volume
    // without streams, or a mark that cannot be fixed).
    FileClipboard(PullHub& hub, LogFn log, ZoneOps zone = {});
    ~FileClipboard();
    FileClipboard(const FileClipboard&) = delete;
    FileClipboard& operator=(const FileClipboard&) = delete;

    void start();
    void stop();               // withdraws our object if it is still current
    void offer(const Manifest& m);
    void withdraw(uint32_t transfer);  // 0: whatever we offered
    // Also searched for pasted files to mark (tests: the drop folder).
    void addSearchFolder(const std::wstring& folder);
    // Totals of every mark pass so far (tests, stats).
    ZoneMarkStats zoneStats() const;

    struct Impl;
private:
    std::unique_ptr<Impl> impl_;
};
#endif

}  // namespace jl::filepull
