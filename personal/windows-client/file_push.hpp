#pragma once

// Mac right-click "Send to JerisLink" (F5b), viewer side. Design r2 section
// 3c "Mac (F5b)".
//
// The host sends OFFER purpose=push plus one ENTRY per file on the pull file
// session. The viewer accepts at once (Q1: no confirm click), then pulls the
// files one after another with REQUEST, like a paste but with a plain file
// writer and no clipboard. Files land in %USERPROFILE%\Downloads\JerisLink:
// each is written to a ".jlpart" file, and only when FILE_END's SHA-256
// matched it is renamed to its name, or "name (2).ext" ... when that name is
// taken, and gets Zone.Identifier ZoneId=3. Nothing is ever opened; Explorer
// shows the folder when every file arrived. The viewer ends every push with
// RESULT (ok or why not) so the Mac lets go of the files.
//
// This header holds the parts with no Win32 so file_push_test.cpp can lock
// them down with a fake folder. The Downloads folder writer is
// file_push_win.cpp.

#include "file_pull.hpp"
#include "file_proto.hpp"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace jl::filepush {

// The Mac helper refuses more; the viewer refuses more too.
inline constexpr uint32_t kMaxFiles = 1000;
inline constexpr uint32_t kRequestBytes = 1024 * 1024;
inline constexpr uint64_t kWindowBytes = 4ull * 1024 * 1024;

// Where pushed files go. One file is written at a time.
class Sink {
public:
    virtual ~Sink() = default;
    // Makes sure the folder exists. False: nothing can be received.
    virtual bool prepare() = 0;
    // Starts a new partial file for `name` (a checked single file name).
    virtual bool begin(const std::wstring& name) = 0;
    virtual bool write(const uint8_t* data, size_t size) = 0;
    // The file is complete and verified: close it, give it its name (or the
    // next free "name (n).ext"), mark it as from the Internet.
    virtual bool commit() = 0;
    // Closes and deletes the partial file, if there is one.
    virtual void abort() = 0;
    // Every file arrived: show the folder.
    virtual void finished(uint32_t files) = 0;
    // Mark of the Web on committed files, for the log: files that carry
    // ZoneId=3 and files that ended up without it.
    struct ZoneCounts {
        uint32_t marked = 0;
        uint32_t failed = 0;
    };
    virtual ZoneCounts zoneCounts() const { return {}; }
    // The last commit() failed because ZoneId=3 could not be put on the
    // file (#53): the file was not delivered.
    virtual bool zoneRefused() const { return false; }
};

enum class Outcome { None, Done, Failed, Cancelled };

struct Progress {
    bool active = false;
    uint64_t files = 0;
    uint64_t filesDone = 0;
    uint64_t total = 0;
    uint64_t received = 0;
    Outcome last = Outcome::None;  // how the last push ended
    uint64_t lastFiles = 0;        // files it delivered
    uint32_t pushes = 0;           // pushes that ended, any outcome
};

// Checks a complete push. Returns "" and fills `out`, or why the push is
// refused: the buildManifest() reasons, plus too_many (over kMaxFiles),
// kind (a folder) and nested (a path with a folder in it).
inline std::string checkPush(const file::Offer& offer, const std::vector<file::Entry>& entries,
                             filepull::Manifest& out) {
    if (offer.entries > kMaxFiles) return "too_many";
    for (const auto& e : entries) {
        if (e.kind != file::kind::kFile) return "kind";
        if (std::find(e.path.begin(), e.path.end(), uint8_t('/')) != e.path.end()) return "nested";
    }
    const std::string why = filepull::buildManifest(offer, entries, out);
    if (!why.empty()) return why;
    for (const auto& it : out.items) {
        if (it.dir || it.rel.find(L'\\') != std::wstring::npos) return "nested";
    }
    return "";
}

// One push at a time, driven by the session thread; progress() may be read
// from any thread. Every on*() returns the messages to send back.
class PushReceiver {
public:
    using Out = std::vector<file::Message>;

    PushReceiver(std::unique_ptr<Sink> sink, filepull::DigestFactory digest)
        : sink_(std::move(sink)), digest_(std::move(digest)) {}

    ~PushReceiver() { disconnect(); }

    bool active() const {
        std::lock_guard<std::mutex> lock(mu_);
        return state_ != State::Idle;
    }
    uint32_t current() const {
        std::lock_guard<std::mutex> lock(mu_);
        return state_ == State::Idle ? 0 : transfer_;
    }

    Progress progress() const {
        std::lock_guard<std::mutex> lock(mu_);
        Progress p = done_;
        p.active = state_ == State::Running;
        if (p.active) {
            p.files = items_.size();
            p.filesDone = cur_;
            p.total = total_;
            p.received = received_;
        }
        return p;
    }

    // Mark of the Web results since the receiver was made.
    Sink::ZoneCounts zoneCounts() const {
        std::lock_guard<std::mutex> lock(mu_);
        return sink_->zoneCounts();
    }

    // Why the last push was refused or failed, for the log ("" if none).
    std::string lastReason() const {
        std::lock_guard<std::mutex> lock(mu_);
        return reason_;
    }

    // OFFER purpose=push. A second push while one runs is answered busy.
    Out onOffer(const file::Offer& o) {
        std::lock_guard<std::mutex> lock(mu_);
        if (state_ != State::Idle) return {file::Reply{o.transfer, file::status::kBusy}};
        if (o.entries == 0 || o.entries > kMaxFiles) {
            reason_ = "too_many";
            return {file::Reply{o.transfer, file::status::kTooBig}};
        }
        if (o.total > file::kMaxTotalBytes) {
            reason_ = "too_big";
            return {file::Reply{o.transfer, file::status::kTooBig}};
        }
        state_ = State::Collecting;
        transfer_ = o.transfer;
        offer_ = o;
        entries_.clear();
        entries_.reserve(o.entries);
        return {};
    }

    Out onEntry(const file::Entry& e) {
        std::lock_guard<std::mutex> lock(mu_);
        if (state_ != State::Collecting || e.transfer != transfer_) return {};
        entries_.push_back(e);
        if (entries_.size() < offer_.entries) return {};
        filepull::Manifest m;
        const std::string why = checkPush(offer_, entries_, m);
        entries_.clear();
        if (!why.empty()) return refuseLocked(why, file::status::kBadPath);
        if (!sink_->prepare()) return refuseLocked("folder", file::status::kNoSpace);
        items_ = m.items;
        total_ = m.total;
        received_ = 0;
        cur_ = 0;
        state_ = State::Running;
        reason_.clear();
        Out out{file::Reply{transfer_, file::status::kOk}};
        if (!startFileLocked()) return failLocked("create", file::status::kNoSpace, std::move(out));
        return out;
    }

    // The next REQUEST, or nothing. Files go one at a time, in order.
    std::optional<file::Request> nextRequest() {
        std::lock_guard<std::mutex> lock(mu_);
        if (state_ != State::Running || cur_ >= items_.size()) return std::nullopt;
        const uint64_t size = items_[cur_].size;
        if (size == 0) {
            if (fileRequested_ > 0 || zeroAsked_) return std::nullopt;
            zeroAsked_ = true;
            return file::Request{transfer_, uint32_t(cur_), 0, 0};
        }
        if (fileRequested_ >= size) return std::nullopt;
        const uint64_t unread = fileRequested_ - fileReceived_;
        if (unread >= kWindowBytes) return std::nullopt;
        const uint64_t len = std::min<uint64_t>({kRequestBytes, size - fileRequested_, kWindowBytes - unread});
        file::Request q{transfer_, uint32_t(cur_), fileRequested_, uint32_t(len)};
        fileRequested_ += len;
        return q;
    }

    bool wantsService() const {
        std::lock_guard<std::mutex> lock(mu_);
        return state_ == State::Running;
    }

    Out onData(const file::Data& d) {
        std::lock_guard<std::mutex> lock(mu_);
        if (state_ != State::Running || d.transfer != transfer_) return {};
        if (d.index != cur_ || d.offset != fileReceived_ || fileReceived_ + d.bytes.size() > fileRequested_) {
            return failLocked("sequence", file::status::kFailed);
        }
        if (fileReceived_ == 0 && !hash_) hash_ = digest_ ? digest_() : nullptr;
        if (hash_) hash_->update(d.bytes.data(), d.bytes.size());
        if (!d.bytes.empty() && !sink_->write(d.bytes.data(), d.bytes.size())) {
            return failLocked("write", file::status::kNoSpace);
        }
        fileReceived_ += d.bytes.size();
        received_ += d.bytes.size();
        rx_ += d.bytes.size();
        return {};
    }

    Out onFileEnd(const file::FileEnd& f) {
        std::lock_guard<std::mutex> lock(mu_);
        if (state_ != State::Running || f.transfer != transfer_) return {};
        const auto& item = items_[cur_];
        if (f.index != cur_ || fileReceived_ != item.size || (item.size == 0 && !zeroAsked_)) {
            return failLocked("sequence", file::status::kFailed);
        }
        if (!hash_) hash_ = digest_ ? digest_() : nullptr;
        const std::vector<uint8_t> sha = hash_ ? hash_->finish() : std::vector<uint8_t>{};
        hash_.reset();
        if (sha.empty() || sha != f.sha256) return failLocked("hash", file::status::kFailed);
        if (!sink_->commit()) {
            if (sink_->zoneRefused()) return failLocked("motw", file::status::kFailed);
            return failLocked("rename", file::status::kNoSpace);
        }
        ++cur_;
        if (cur_ < items_.size()) {
            if (!startFileLocked()) return failLocked("create", file::status::kNoSpace);
            return {};
        }
        const uint32_t files = uint32_t(items_.size());
        endLocked(Outcome::Done, files);
        sink_->finished(files);
        return {file::Result{transfer_, file::status::kOk, files}};
    }

    // REPLY not ok from the Mac: it could not read a file. The push ends.
    Out onReply(const file::Reply& r) {
        std::lock_guard<std::mutex> lock(mu_);
        if (state_ != State::Running || r.transfer != transfer_ || r.status == file::status::kOk) return {};
        return failLocked(r.status == file::status::kMacPermission ? "mac_permission" : "mac_read", r.status);
    }

    // CANCEL from the Mac: stop, keep what already arrived, say nothing.
    void onCancel(const file::Cancel& c) {
        std::lock_guard<std::mutex> lock(mu_);
        if (state_ == State::Idle || c.transfer != transfer_) return;
        sink_->abort();
        reason_ = "mac_cancelled";
        endLocked(Outcome::Cancelled, cur_);
    }

    // The user pressed Cancel: tell the Mac.
    Out cancel() {
        std::lock_guard<std::mutex> lock(mu_);
        if (state_ != State::Running) return {};
        sink_->abort();
        reason_ = "cancelled";
        const uint32_t t = transfer_;
        endLocked(Outcome::Cancelled, cur_);
        return {file::Cancel{t, file::status::kCancelled}};
    }

    // The session closed: nothing more can arrive.
    void disconnect() {
        std::lock_guard<std::mutex> lock(mu_);
        if (state_ == State::Idle) return;
        const bool running = state_ == State::Running;
        sink_->abort();
        if (running) {
            reason_ = "disconnected";
            endLocked(Outcome::Failed, cur_);
        } else {
            resetLocked();
        }
    }

    uint64_t rxBytes() const {
        std::lock_guard<std::mutex> lock(mu_);
        return rx_;
    }

private:
    enum class State { Idle, Collecting, Running };

    bool startFileLocked() {
        fileRequested_ = 0;
        fileReceived_ = 0;
        zeroAsked_ = false;
        hash_.reset();
        return sink_->begin(items_[cur_].rel);
    }

    Out refuseLocked(const std::string& why, uint8_t status) {
        const uint32_t t = transfer_;
        reason_ = why;
        resetLocked();
        return {file::Reply{t, status}};
    }

    Out failLocked(const std::string& why, uint8_t status, Out out = {}) {
        sink_->abort();
        reason_ = why;
        const uint32_t t = transfer_;
        const uint32_t ok = uint32_t(cur_);
        endLocked(Outcome::Failed, ok);
        out.push_back(file::Result{t, status == file::status::kOk ? file::status::kFailed : status, ok});
        return out;
    }

    void endLocked(Outcome o, uint64_t files) {
        done_.last = o;
        done_.lastFiles = files;
        ++done_.pushes;
        resetLocked();
    }

    void resetLocked() {
        state_ = State::Idle;
        entries_.clear();
        items_.clear();
        hash_.reset();
        cur_ = 0;
        total_ = 0;
        received_ = 0;
        fileRequested_ = 0;
        fileReceived_ = 0;
        zeroAsked_ = false;
    }

    mutable std::mutex mu_;
    std::unique_ptr<Sink> sink_;
    filepull::DigestFactory digest_;
    State state_ = State::Idle;
    uint32_t transfer_ = 0;
    file::Offer offer_{};
    std::vector<file::Entry> entries_;
    std::vector<filepull::Item> items_;
    std::unique_ptr<filepull::Digest> hash_;
    size_t cur_ = 0;
    uint64_t total_ = 0;
    uint64_t received_ = 0;
    uint64_t fileRequested_ = 0;
    uint64_t fileReceived_ = 0;
    bool zeroAsked_ = false;
    uint64_t rx_ = 0;
    std::string reason_;
    Progress done_;
};

#ifdef _WIN32
// Writes into `folder` (normally %USERPROFILE%\Downloads\JerisLink, see
// downloadsFolder()). Partial files are "<name>.<n>.jlpart", created with
// CREATE_NEW; a verified file is moved to "<name>" with no overwrite, and on
// a clash to "name (2).ext", "name (3).ext" ... (up to 999). Zone.Identifier
// ZoneId=3 is written on the partial file and moves with the rename. It is
// checked before and after the rename; a file that cannot carry it (a volume
// without streams) is deleted and the push fails with reason "motw" (#53).
// `open` shows the folder in Explorer when a push finished (tests pass a no-op).
// `zone` is for tests only.
std::unique_ptr<Sink> makeFolderSink(std::wstring folder, std::function<void(const std::wstring&)> open,
                                     filepull::ZoneOps zone = {});

// %USERPROFILE%\Downloads\JerisLink from FOLDERID_Downloads, or "" if
// Windows does not know the Downloads folder.
std::wstring downloadsFolder();

// Opens `folder` in Explorer.
void openInExplorer(const std::wstring& folder);
#endif

}  // namespace jl::filepush
