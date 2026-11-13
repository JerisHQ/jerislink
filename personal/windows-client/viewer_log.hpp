// Viewer log writer: the session log (jerislink-viewer.log) and the history
// log (jerislink-viewer-history.log), each kept open for the whole run and
// written by one background thread. The caller only queues the line, so the
// receive loop never opens, writes or closes a file.
//
// Size caps:
// - history: when it reaches the cap it becomes <name>.old (one file,
//   replaced each time) and a new history starts. At most about 2 x cap
//   on disk.
// - session: started fresh each run; if it reaches the cap it is emptied
//   and starts again with a "log.truncated" line.
// - A history already over the cap when the viewer starts (logs from
//   before this change grew without a limit) is rotated the same way, but
//   only its newest cap bytes are kept in .old, cut at a line start.
//
// More than one viewer process may write the same files. Every change to a
// file (follow a rotation done by another viewer, check the cap, rotate or
// empty, write) happens while holding one named mutex per file path, so no
// other viewer can rotate between this writer's check and its write. The
// cap is checked against the real file size, not against what this process
// wrote. Only the writer thread takes the lock, never the caller.
//
// If the lock cannot be taken (another viewer stuck holding it, or the
// mutex could not be created), nothing is changed on disk: the data stays
// pending and is written on the next try. That includes the start-up work
// (session truncate, trim of an oversized legacy history): it runs on the
// first lock this writer gets, before anything else is written. Pending
// data has its own cap; past it the oldest pending chunks are dropped and
// counted, and a "log.lock_timeout" line reports them once the lock is
// taken again.
//
// Shutdown has one overall deadline (2 s by default) for every lock wait
// left; whatever cannot be written by then is dropped and counted.
//
// Lines end in CRLF, as the old std::ofstream (text mode) wrote them.
//
// Header-only so viewer_log_test.cpp runs the same code.
#pragma once

#include <windows.h>

#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace jl {

constexpr const char* kLogEol = "\r\n";

class LogFile {
public:
    LogFile() = default;
    LogFile(const LogFile&) = delete;
    LogFile& operator=(const LogFile&) = delete;
    ~LogFile() {
        close();
        if (mutex_) CloseHandle(mutex_);
    }

    // keepOld: rotate to path + ".old" at the cap; otherwise empty in place.
    void configure(std::string path, uint64_t cap, bool keepOld, bool truncateAtOpen) {
        path_ = std::move(path);
        cap_ = cap;
        keepOld_ = keepOld;
        truncateAtOpen_ = truncateAtOpen;
        if (mutex_) CloseHandle(mutex_);
        mutex_ = nullptr;  // created on the first lock attempt
        setupDone_ = false;
    }

    // Test only: false restores the per-process size count without a lock
    // (the behaviour before multi-writer coordination), to show what the
    // coordination fixes.
    void setCoordinated(bool on) { coordinated_ = on; }

    // Start-up work (truncate the session, trim an oversized legacy
    // history, open the handle) under the lock. Returns false if the lock
    // was not taken: then the file is not touched (not even created) and
    // the work runs on the first lock taken later, before any data.
    bool open() {
        setupDone_ = false;
        if (!coordinated_) {
            setupLocked();
            return h_ != INVALID_HANDLE_VALUE;
        }
        CapLock lk(lockMutex(), lockTimeoutMs_, deadlineMs_.load());
        if (!lk.held()) {
            ++lockFailures_;
            return false;
        }
        setupLocked();
        return h_ != INVALID_HANDLE_VALUE;
    }

    // Queues data and writes everything pending to the file under the lock.
    // Returns false if the lock was not taken: then nothing on disk changed
    // and the data stays pending for the next write() or flushPending().
    bool write(const std::string& data) {
        if (!data.empty()) defer(data);
        return flushPending();
    }

    bool flushPending() {
        if (pending_.empty()) return true;
        if (!coordinated_) {
            if (!setupDone_) setupLocked();
            for (const auto& c : pending_) {
                if (h_ == INVALID_HANDLE_VALUE) break;
                if (size_ > 0 && size_ + c.size() > cap_) capReached();
                writeChecked(c);
            }
            clearPending();
            return true;
        }
        CapLock lk(lockMutex(), lockTimeoutMs_, deadlineMs_.load());
        if (!lk.held()) {
            ++lockFailures_;
            return false;
        }
        if (!setupDone_)
            setupLocked();  // first lock this writer got: start-up work first
        else
            syncWithPath();
        if (lockFailures_ != reportedFailures_ || droppedChunks_ != reportedDroppedChunks_) {
            writeLocked("log.lock_timeout failures=" + std::to_string(lockFailures_ - reportedFailures_) +
                        " dropped_chunks=" + std::to_string(droppedChunks_ - reportedDroppedChunks_) +
                        " dropped_bytes=" + std::to_string(droppedBytes_ - reportedDroppedBytes_) + kLogEol);
            reportedFailures_ = lockFailures_;
            reportedDroppedChunks_ = droppedChunks_;
            reportedDroppedBytes_ = droppedBytes_;
        }
        for (const auto& c : pending_) writeLocked(c);
        clearPending();
        return true;
    }

    // Last try at stop: whatever still cannot be written is dropped and
    // counted.
    void finish() {
        if (flushPending()) return;
        for (const auto& c : pending_) {
            ++droppedChunks_;
            droppedBytes_ += c.size();
        }
        clearPending();
    }

    void close() {
        if (h_ != INVALID_HANDLE_VALUE) CloseHandle(h_);
        h_ = INVALID_HANDLE_VALUE;
    }

    // Every lock wait from now on ends by this time (steady clock), whatever
    // the per-try timeout. Set from another thread by ViewerLog::stop().
    void setDeadline(std::chrono::steady_clock::time_point t) {
        deadlineMs_.store(std::chrono::duration_cast<std::chrono::milliseconds>(t.time_since_epoch()).count());
    }

    // Test knobs.
    void setLockTimeoutMs(DWORD ms) { lockTimeoutMs_ = ms; }
    // Makes CreateMutex "fail" (no mutex), as when the name cannot be
    // created.
    void setMutexCreateFailsForTest(bool on) { mutexCreateFails_ = on; }
    void setPendingCap(uint64_t bytes) { pendingCap_ = bytes; }
    // Called on the writer thread with "checked" (cap checked, any rotation
    // done, about to write) and "written"; in coordinated mode both run
    // while the lock is held.
    void setTestHook(std::function<void(const char*)> hook) { hook_ = std::move(hook); }

    const std::string& path() const { return path_; }
    std::string oldPath() const { return path_ + ".old"; }
    uint64_t rotations() const { return rotations_; }
    uint64_t reopens() const { return reopens_; }
    uint64_t pendingBytes() const { return pendingBytes_; }
    uint64_t lockFailures() const { return lockFailures_; }
    uint64_t droppedChunks() const { return droppedChunks_; }
    uint64_t droppedBytes() const { return droppedBytes_; }
    uint64_t legacyTrimmedFrom() const { return legacyTrimmedFrom_; }

    static uint64_t fileSize(const std::string& path) {
        WIN32_FILE_ATTRIBUTE_DATA a{};
        if (!GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &a)) return 0;
        return (uint64_t(a.nFileSizeHigh) << 32) | a.nFileSizeLow;
    }

    // One name per file: FNV-1a of the lower-cased full path.
    static std::string mutexName(const std::string& path) {
        char full[MAX_PATH * 2]{};
        const DWORD n = GetFullPathNameA(path.c_str(), sizeof(full), full, nullptr);
        const std::string p = (n > 0 && n < sizeof(full)) ? std::string(full, n) : path;
        uint64_t h = 1469598103934665603ull;
        for (unsigned char c : p) {
            h ^= static_cast<unsigned char>(std::tolower(c));
            h *= 1099511628211ull;
        }
        char name[64];
        std::snprintf(name, sizeof(name), "Local\\jerislink-log-%016llx", static_cast<unsigned long long>(h));
        return name;
    }

private:
    static int64_t nowMs() {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
                   std::chrono::steady_clock::now().time_since_epoch())
            .count();
    }

    // Holds the per-path mutex. held() is false if there is no mutex
    // (CreateMutex failed), or the wait timed out, failed or ran into the
    // deadline: the caller must then leave the files alone. The wait runs
    // in short slices so a deadline set while waiting is noticed.
    class CapLock {
    public:
        CapLock(HANDLE m, DWORD timeoutMs, int64_t deadlineMs) {
            if (!m) return;
            const int64_t end = nowMs() + timeoutMs;
            for (;;) {
                const int64_t now = nowMs();
                const int64_t left = (end < deadlineMs ? end : deadlineMs) - now;
                const DWORD slice = left <= 0 ? 0 : static_cast<DWORD>(left < 50 ? left : 50);
                const DWORD r = WaitForSingleObject(m, slice);
                if (r == WAIT_OBJECT_0 || r == WAIT_ABANDONED) {
                    m_ = m;
                    return;
                }
                if (r != WAIT_TIMEOUT || left <= static_cast<int64_t>(slice)) return;
            }
        }
        ~CapLock() {
            if (m_) ReleaseMutex(m_);
        }
        bool held() const { return m_ != nullptr; }
        CapLock(const CapLock&) = delete;
        CapLock& operator=(const CapLock&) = delete;

    private:
        HANDLE m_ = nullptr;
    };

    // The per-path mutex, created on first use; retried on every attempt
    // if creating it failed.
    HANDLE lockMutex() {
        if (!mutex_ && !mutexCreateFails_) mutex_ = CreateMutexA(nullptr, FALSE, mutexName(path_).c_str());
        return mutexCreateFails_ ? nullptr : mutex_;
    }

    // Lock held (or uncoordinated test mode): the start-up work.
    void setupLocked() {
        setupDone_ = true;
        close();
        if (truncateAtOpen_) {
            h_ = openHandle(CREATE_ALWAYS);
            size_ = 0;
            return;
        }
        if (keepOld_) {
            const uint64_t existing = fileSize(path_);
            if (existing >= cap_) rotateLegacy(existing);
        }
        h_ = openHandle(OPEN_ALWAYS);
        size_ = h_ != INVALID_HANDLE_VALUE ? fileSize(h_) : 0;
        if (legacyTrimmedFrom_)
            writeLocked("log.history_trimmed old_bytes=" + std::to_string(legacyTrimmedFrom_) + kLogEol);
    }

    void defer(const std::string& data) {
        pending_.push_back(data);
        pendingBytes_ += data.size();
        // Over the pending cap (the lock has been unavailable for a while):
        // drop the oldest chunks, keep the newest.
        while (pendingBytes_ > pendingCap_ && pending_.size() > 1) {
            ++droppedChunks_;
            droppedBytes_ += pending_.front().size();
            pendingBytes_ -= pending_.front().size();
            pending_.pop_front();
        }
    }

    void clearPending() {
        pending_.clear();
        pendingBytes_ = 0;
    }

    // Lock held and synced with the path: check the cap, rotate if needed,
    // write. No other viewer can rotate in between.
    void writeLocked(const std::string& data) {
        if (h_ == INVALID_HANDLE_VALUE) return;
        if (size_ > 0 && size_ + data.size() > cap_) capReached();
        writeChecked(data);
    }

    void writeChecked(const std::string& data) {
        if (h_ == INVALID_HANDLE_VALUE) return;
        if (hook_) hook_("checked");
        DWORD wrote = 0;
        if (WriteFile(h_, data.data(), static_cast<DWORD>(data.size()), &wrote, nullptr)) size_ += wrote;
        if (hook_) hook_("written");
    }

    HANDLE openHandle(DWORD disposition) const {
        // FILE_APPEND_DATA: every write goes to the end, also when a second
        // viewer appends to the same history. Others may read, write,
        // rename or delete the file while it is open.
        return CreateFileA(path_.c_str(), FILE_APPEND_DATA | SYNCHRONIZE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           disposition, FILE_ATTRIBUTE_NORMAL, nullptr);
    }

    static uint64_t fileSize(HANDLE h) {
        LARGE_INTEGER sz{};
        return GetFileSizeEx(h, &sz) ? static_cast<uint64_t>(sz.QuadPart) : 0;
    }

    // True if our handle is still the file at path_ (same volume and file
    // id). False after another viewer renamed it to .old or removed it.
    bool handleIsPath() const {
        BY_HANDLE_FILE_INFORMATION a{}, b{};
        if (h_ == INVALID_HANDLE_VALUE || !GetFileInformationByHandle(h_, &a)) return false;
        HANDLE p = CreateFileA(path_.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (p == INVALID_HANDLE_VALUE) return false;
        const bool ok = GetFileInformationByHandle(p, &b) != 0;
        CloseHandle(p);
        return ok && a.dwVolumeSerialNumber == b.dwVolumeSerialNumber &&
               a.nFileIndexHigh == b.nFileIndexHigh && a.nFileIndexLow == b.nFileIndexLow;
    }

    // Lock held: follow the path if another viewer rotated the file, then
    // take the real size (it includes what other viewers appended).
    void syncWithPath() {
        if (!handleIsPath()) {
            close();
            h_ = openHandle(OPEN_ALWAYS);
            ++reopens_;
        }
        size_ = h_ != INVALID_HANDLE_VALUE ? fileSize(h_) : 0;
    }

    void capReached() {
        if (keepOld_) rotate();
        else emptyInPlace();
    }

    void rotate() {
        close();
        if (MoveFileExA(path_.c_str(), oldPath().c_str(), MOVEFILE_REPLACE_EXISTING)) {
            ++rotations_;
            h_ = openHandle(OPEN_ALWAYS);
            size_ = h_ != INVALID_HANDLE_VALUE ? fileSize(h_) : 0;
        } else {
            // .old is held open by someone (a reader, or a second viewer),
            // so it cannot be replaced. Empty the history in place instead,
            // so the size limit still holds.
            emptyInPlace("log.rotate_failed error=" + std::to_string(GetLastError()));
        }
    }

    void emptyInPlace(const std::string& why = "log.truncated") {
        close();
        h_ = openHandle(CREATE_ALWAYS);
        size_ = 0;
        ++rotations_;
        const std::string note = why + " cap_bytes=" + std::to_string(cap_) + kLogEol;
        DWORD wrote = 0;
        if (h_ != INVALID_HANDLE_VALUE &&
            WriteFile(h_, note.data(), static_cast<DWORD>(note.size()), &wrote, nullptr)) size_ = wrote;
    }

    // A history over the cap before any rotation existed: keep its newest
    // cap bytes (from the first full line) as .old and start a new history.
    void rotateLegacy(uint64_t existing) {
        HANDLE in = CreateFileA(path_.c_str(), GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (in == INVALID_HANDLE_VALUE) return;
        const uint64_t keep = existing < cap_ ? existing : cap_;
        LARGE_INTEGER pos{};
        pos.QuadPart = static_cast<LONGLONG>(existing - keep);
        std::vector<char> tail(static_cast<size_t>(keep));
        DWORD got = 0;
        const bool readOk = SetFilePointerEx(in, pos, nullptr, FILE_BEGIN) &&
                            ReadFile(in, tail.data(), static_cast<DWORD>(tail.size()), &got, nullptr);
        CloseHandle(in);
        if (!readOk) return;
        size_t start = 0;
        if (existing > keep) {
            while (start < got && tail[start] != '\n') ++start;
            if (start < got) ++start;
        }
        HANDLE out = CreateFileA(oldPath().c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                                 CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (out == INVALID_HANDLE_VALUE) return;
        DWORD wrote = 0;
        const bool writeOk = WriteFile(out, tail.data() + start, static_cast<DWORD>(got - start), &wrote, nullptr) &&
                             wrote == got - start;
        CloseHandle(out);
        if (!writeOk) return;
        // Empty the old file rather than delete it, so a second viewer that
        // still has it open keeps a valid handle.
        HANDLE t = CreateFileA(path_.c_str(), GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                               TRUNCATE_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (t != INVALID_HANDLE_VALUE) {
            CloseHandle(t);
            ++rotations_;
            legacyTrimmedFrom_ = existing;
        }
    }

    std::string path_;
    uint64_t cap_ = 0;
    bool keepOld_ = false;
    bool truncateAtOpen_ = false;
    bool coordinated_ = true;
    bool setupDone_ = false;
    bool mutexCreateFails_ = false;
    HANDLE h_ = INVALID_HANDLE_VALUE;
    HANDLE mutex_ = nullptr;
    DWORD lockTimeoutMs_ = 2000;
    std::atomic<int64_t> deadlineMs_{INT64_MAX};
    uint64_t size_ = 0;
    uint64_t rotations_ = 0;
    uint64_t reopens_ = 0;
    uint64_t legacyTrimmedFrom_ = 0;
    std::deque<std::string> pending_;
    uint64_t pendingBytes_ = 0;
    uint64_t pendingCap_ = 4ull * 1024 * 1024;
    uint64_t lockFailures_ = 0, droppedChunks_ = 0, droppedBytes_ = 0;
    uint64_t reportedFailures_ = 0, reportedDroppedChunks_ = 0, reportedDroppedBytes_ = 0;
    std::function<void(const char*)> hook_;
};

class ViewerLog {
public:
    static constexpr uint64_t kDefaultCap = 10ull * 1024 * 1024;
    static constexpr size_t kChunk = 8 * 1024;  // caps must be well above this

    ViewerLog() = default;
    ViewerLog(const ViewerLog&) = delete;
    ViewerLog& operator=(const ViewerLog&) = delete;
    ~ViewerLog() { stop(); }

    // Opens both files on the writer thread, so a large legacy history
    // never delays the caller.
    void start(const std::string& sessionPath, const std::string& historyPath,
               uint64_t sessionCap = kDefaultCap, uint64_t historyCap = kDefaultCap) {
        std::lock_guard<std::mutex> lk(mu_);
        if (running_) return;
        session_.configure(sessionPath, sessionCap, false, true);
        history_.configure(historyPath, historyCap, true, false);
        running_ = true;
        stopping_ = false;
        thread_ = std::thread([this] { run(); });
    }

    // Queues one line (CRLF is added). Cheap: no file I/O here.
    void line(const std::string& s) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (!running_ || stopping_) return;
            queue_.push_back(s);
        }
        cv_.notify_one();
    }

    // Writes everything queued so far, then stops the thread. All lock
    // waits left share one deadline (shutdownBudgetMs from now); what a
    // locked file cannot take by then is dropped and counted, so stop()
    // returns in about that time even if another viewer holds a lock.
    void stop() {
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (!running_) return;
            stopping_ = true;
        }
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(shutdownBudgetMs_);
        session_.setDeadline(deadline);
        history_.setDeadline(deadline);
        cv_.notify_one();
        if (thread_.joinable()) thread_.join();
        std::lock_guard<std::mutex> lk(mu_);
        running_ = false;
    }

    // Blocks until the writer has handled every line queued before the call
    // (written, or pending if a file's lock was not available).
    void flush() {
        std::unique_lock<std::mutex> lk(mu_);
        const uint64_t target = queued_ + queue_.size();
        drained_.wait(lk, [&] { return !running_ || written_ >= target; });
    }

    uint64_t historyRotations() const { return history_.rotations(); }
    uint64_t historyReopens() const { return history_.reopens(); }
    uint64_t historyLockFailures() const { return history_.lockFailures(); }
    uint64_t historyDroppedChunks() const { return history_.droppedChunks(); }
    uint64_t historyDroppedBytes() const { return history_.droppedBytes(); }
    uint64_t historyPendingBytes() const { return history_.pendingBytes(); }

    // Total time stop() may spend waiting for locks. Call before stop().
    void setShutdownBudgetMs(DWORD ms) { shutdownBudgetMs_ = ms; }
    uint64_t sessionTruncations() const { return session_.rotations(); }
    uint64_t legacyTrimmedFrom() const { return history_.legacyTrimmedFrom(); }

    // Test only; call before start(). Runs on the writer thread.
    void setHistoryTestHook(std::function<void(const char*)> hook) { history_.setTestHook(std::move(hook)); }

private:
    void run() {
        session_.open();
        history_.open();
        noteTrimInSession();
        std::deque<std::string> batch;
        for (;;) {
            {
                std::unique_lock<std::mutex> lk(mu_);
                const auto ready = [&] { return stopping_ || !queue_.empty(); };
                // Data left pending by a lock timeout: try again now and then
                // even if no new line arrives.
                if (session_.pendingBytes() || history_.pendingBytes())
                    cv_.wait_for(lk, std::chrono::milliseconds(250), ready);
                else
                    cv_.wait(lk, ready);
                if (queue_.empty() && stopping_) break;
                batch.swap(queue_);
                queued_ += batch.size();
            }
            std::string chunk;
            for (auto& s : batch) {
                chunk.append(s);
                chunk.append(kLogEol);
                // Write in pieces so a cap check happens at least every 8 KB.
                if (chunk.size() >= kChunk) {
                    session_.write(chunk);
                    history_.write(chunk);
                    chunk.clear();
                }
            }
            if (!chunk.empty()) {
                session_.write(chunk);
                history_.write(chunk);
            }
            if (batch.empty()) {  // woken only to retry pending data
                session_.flushPending();
                history_.flushPending();
            }
            noteTrimInSession();
            {
                std::lock_guard<std::mutex> lk(mu_);
                written_ += batch.size();
            }
            batch.clear();
            drained_.notify_all();
        }
        session_.finish();
        history_.finish();
        session_.close();
        history_.close();
        drained_.notify_all();
    }

    // The history writes its own trim note when the trim runs (at start, or
    // on its first lock if the start-up lock timed out); the session log
    // records it too, once.
    void noteTrimInSession() {
        if (trimNoted_ || !history_.legacyTrimmedFrom()) return;
        trimNoted_ = true;
        session_.write("log.history_trimmed old_bytes=" + std::to_string(history_.legacyTrimmedFrom()) + kLogEol);
    }

    bool trimNoted_ = false;
    DWORD shutdownBudgetMs_ = 2000;
    std::mutex mu_;
    std::condition_variable cv_;
    std::condition_variable drained_;
    std::deque<std::string> queue_;
    uint64_t queued_ = 0;   // lines taken off the queue by the writer
    uint64_t written_ = 0;  // lines handled by the writer
    bool running_ = false;
    bool stopping_ = false;
    std::thread thread_;
    LogFile session_;
    LogFile history_;
};

}  // namespace jl
