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
// Header-only so viewer_log_test.cpp runs the same code.
#pragma once

#include <windows.h>

#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace jl {

class LogFile {
public:
    LogFile() = default;
    LogFile(const LogFile&) = delete;
    LogFile& operator=(const LogFile&) = delete;
    ~LogFile() { close(); }

    // keepOld: rotate to path + ".old" at the cap; otherwise empty in place.
    void configure(std::string path, uint64_t cap, bool keepOld, bool truncateAtOpen) {
        path_ = std::move(path);
        cap_ = cap;
        keepOld_ = keepOld;
        truncateAtOpen_ = truncateAtOpen;
    }

    bool open() {
        if (truncateAtOpen_) {
            h_ = openHandle(CREATE_ALWAYS);
            size_ = 0;
            return h_ != INVALID_HANDLE_VALUE;
        }
        if (keepOld_) {
            const uint64_t existing = fileSize(path_);
            if (existing >= cap_) rotateLegacy(existing);
        }
        h_ = openHandle(OPEN_ALWAYS);
        size_ = h_ != INVALID_HANDLE_VALUE ? fileSize(h_) : 0;
        return h_ != INVALID_HANDLE_VALUE;
    }

    void write(const std::string& data) {
        if (h_ == INVALID_HANDLE_VALUE) return;
        if (size_ > 0 && size_ + data.size() > cap_) {
            if (keepOld_) rotate();
            else emptyInPlace();
            if (h_ == INVALID_HANDLE_VALUE) return;
        }
        DWORD wrote = 0;
        if (WriteFile(h_, data.data(), static_cast<DWORD>(data.size()), &wrote, nullptr)) size_ += wrote;
    }

    void close() {
        if (h_ != INVALID_HANDLE_VALUE) CloseHandle(h_);
        h_ = INVALID_HANDLE_VALUE;
    }

    const std::string& path() const { return path_; }
    std::string oldPath() const { return path_ + ".old"; }
    uint64_t rotations() const { return rotations_; }

    static uint64_t fileSize(const std::string& path) {
        WIN32_FILE_ATTRIBUTE_DATA a{};
        if (!GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &a)) return 0;
        return (uint64_t(a.nFileSizeHigh) << 32) | a.nFileSizeLow;
    }

private:
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

    void rotate() {
        close();
        if (MoveFileExA(path_.c_str(), oldPath().c_str(), MOVEFILE_REPLACE_EXISTING)) {
            ++rotations_;
            h_ = openHandle(CREATE_ALWAYS);
            size_ = 0;
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
        const std::string note = why + " cap_bytes=" + std::to_string(cap_) + "\n";
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

public:
    uint64_t legacyTrimmedFrom() const { return legacyTrimmedFrom_; }

private:
    std::string path_;
    uint64_t cap_ = 0;
    bool keepOld_ = false;
    bool truncateAtOpen_ = false;
    HANDLE h_ = INVALID_HANDLE_VALUE;
    uint64_t size_ = 0;
    uint64_t rotations_ = 0;
    uint64_t legacyTrimmedFrom_ = 0;
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

    // Queues one line (a newline is added). Cheap: no file I/O here.
    void line(const std::string& s) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (!running_ || stopping_) return;
            queue_.push_back(s);
        }
        cv_.notify_one();
    }

    // Writes everything queued so far, then stops the thread.
    void stop() {
        {
            std::lock_guard<std::mutex> lk(mu_);
            if (!running_) return;
            stopping_ = true;
        }
        cv_.notify_one();
        if (thread_.joinable()) thread_.join();
        std::lock_guard<std::mutex> lk(mu_);
        running_ = false;
    }

    // Blocks until the writer has written every line queued before the call.
    void flush() {
        std::unique_lock<std::mutex> lk(mu_);
        const uint64_t target = queued_ + queue_.size();
        drained_.wait(lk, [&] { return !running_ || written_ >= target; });
    }

    uint64_t historyRotations() const { return history_.rotations(); }
    uint64_t sessionTruncations() const { return session_.rotations(); }
    uint64_t legacyTrimmedFrom() const { return history_.legacyTrimmedFrom(); }

private:
    void run() {
        session_.open();
        history_.open();
        if (history_.legacyTrimmedFrom()) {
            const std::string note = "log.history_trimmed old_bytes=" +
                                     std::to_string(history_.legacyTrimmedFrom()) + "\n";
            session_.write(note);
            history_.write(note);
        }
        std::deque<std::string> batch;
        for (;;) {
            {
                std::unique_lock<std::mutex> lk(mu_);
                cv_.wait(lk, [&] { return stopping_ || !queue_.empty(); });
                if (queue_.empty() && stopping_) break;
                batch.swap(queue_);
                queued_ += batch.size();
            }
            std::string chunk;
            for (auto& s : batch) {
                chunk.append(s);
                chunk.push_back('\n');
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
            {
                std::lock_guard<std::mutex> lk(mu_);
                written_ += batch.size();
            }
            batch.clear();
            drained_.notify_all();
        }
        session_.close();
        history_.close();
        drained_.notify_all();
    }

    std::mutex mu_;
    std::condition_variable cv_;
    std::condition_variable drained_;
    std::deque<std::string> queue_;
    uint64_t queued_ = 0;   // lines taken off the queue by the writer
    uint64_t written_ = 0;  // lines written
    bool running_ = false;
    bool stopping_ = false;
    std::thread thread_;
    LogFile session_;
    LogFile history_;
};

} // namespace jl
