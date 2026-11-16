#pragma once

// File session (F1, F2): its own TCP connection to the control port.
// It sends FILE_HELLO, waits up to 2 s for HELLO_ACK and logs
// file.capability=yes|no. With a capable host it keeps the session open with
// a PING every 15 s and reconnects with backoff if it drops. An old host
// (no ACK) is probed once per viewer session and never again, so it does not
// log an unknown message every few seconds. Nothing here runs on the UI,
// render or input threads.
//
// F2: startUpload() hands a Windows->Mac paste to the session thread. It
// walks the copied files and folders (symlinks and junctions skipped),
// sends OFFER + ENTRY, waits for the host to accept, then streams each file
// in 32 KiB DATA chunks with its SHA-256 in FILE_END, paced to
// FileTransferMaxMbps with at most 4 MiB not yet acknowledged by PROGRESS.
// The host sets the Mac pasteboard and answers RESULT. File names are never
// logged.
//
// F3: a second FileSession in the Pull role says HELLO caps=announce. The
// host then sends a manifest whenever the user copies files in Finder; the
// session checks it, puts a lazy file object on the Windows clipboard
// (FileClipboard) and, only when Explorer pastes, pulls the bytes with
// REQUEST, paced like an upload. The upload session never sees announces.
//
// F4: startUpload(..., Purpose::Send) is a drop on the viewer: the same
// upload with purpose=send, which the host puts in ~/Downloads/JerisLink and
// shows in Finder. requestReveal() sends 0x5C REVEAL for the last send so
// Finder shows that folder again. Both need a host with caps reveal.

#include <winsock2.h>
#include <ws2tcpip.h>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "file_proto.hpp"
#include "file_pull.hpp"
#include "file_upload.hpp"

#include <memory>
#include <optional>

class FileSession {
public:
    using LogFn = std::function<void(const std::string&)>;
    // Called on the session thread when an upload started with startUpload()
    // ends, whatever the outcome. Post to the UI thread; do not block.
    using UploadDoneFn = std::function<void()>;
    // Pull role: something the user should see about a Mac copy (F3 r2).
    // Called on the session thread; post to the UI thread, do not block.
    enum class PullNotice : int { MacPermission = 1, PullFailed = 2, NotOffered = 3 };
    using PullNoticeFn = std::function<void(PullNotice)>;
    enum class UploadState : int { Idle = 0, Running = 1, Done = 2, Failed = 3, Cancelled = 4 };
    // Paste: Cmd+V in Finder (F2). Send: a drop on the viewer (F4).
    enum class Purpose : int { Paste = 0, Send = 1 };
    struct UploadProgress {
        UploadState state = UploadState::Idle;
        uint64_t files = 0;      // file entries (folders not counted)
        uint64_t filesDone = 0;  // files fully sent
        uint64_t total = 0;      // bytes
        uint64_t committed = 0;  // bytes the Mac has written
        uint64_t bytesPerSec = 0;
        Purpose purpose = Purpose::Paste;
        uint8_t hostStatus = 0;  // the host's REJECT or RESULT status when not ok
        uint32_t filesOk = 0;    // files the host confirmed (Done)
    };
    enum class Capability : int { Unknown = 0, Yes = 1, No = 2 };
    // Upload: Windows->Mac (F2). Pull: Mac->Windows paste (F3).
    enum class Role { Upload, Pull };

    FileSession(std::string localIp, std::string remoteIp, uint16_t port, LogFn logFn, Role role = Role::Upload);
    ~FileSession();

    FileSession(const FileSession&) = delete;
    FileSession& operator=(const FileSession&) = delete;

    void start();
    void stop();

    Capability capability() const { return static_cast<Capability>(capability_.load()); }
    uint16_t hostCaps() const { return hostCaps_.load(); }
    uint64_t sessions() const { return sessions_.load(); }
    uint64_t pings() const { return pings_.load(); }

    // UI thread. roots: full paths from the clipboard. False when the host
    // cannot receive or an upload is already running (no callback then).
    bool startUpload(std::vector<std::wstring> roots, uint32_t maxMbps, Purpose purpose = Purpose::Paste);
    void cancelUpload() { uploadCancel_ = true; }
    bool uploadRunning() const { return uploadRunning_.load(); }
    bool canUpload() const {
        return capability() == Capability::Yes && (hostCaps() & jl::file::caps::kUpload) && !uploadRunning();
    }
    // A drop needs an F4 host: one that answers REVEAL takes purpose=send.
    bool canSend() const { return canUpload() && (hostCaps() & jl::file::caps::kReveal); }
    UploadProgress uploadProgress() const;
    // F4: Finder shows the folder the last send went to. False when no send
    // finished on this session or the host cannot reveal.
    bool requestReveal();
    void setUploadDoneCallback(UploadDoneFn fn) { uploadDone_ = std::move(fn); }  // before start()
    uint64_t txBytes() const { return txBytes_.load(); }

    // Pull role (F3).
    Role role() const { return role_; }
    bool pullRunning() const { return hub_ && hub_->progress().active; }
    jl::filepull::PullHub::Progress pullProgress() const {
        return hub_ ? hub_->progress() : jl::filepull::PullHub::Progress{};
    }
    uint64_t rxBytes() const { return hub_ ? hub_->rxBytes() : 0; }
    void setMaxMbps(uint32_t mbps) { pullMbps_ = mbps; }
    void setPullNoticeCallback(PullNoticeFn fn) { pullNotice_ = std::move(fn); }  // before start()

private:
    void run();
    SOCKET connectSocket();
    static void closeSocket(SOCKET& s);
    bool waitReadable(SOCKET s, int ms);
    bool sendPacket(SOCKET s, uint8_t type, const std::vector<uint8_t>& payload);
    bool recvPacket(SOCKET s, uint8_t& type, std::vector<uint8_t>& payload);
    static bool sendAll(SOCKET s, const uint8_t* data, size_t size);
    static bool recvExact(SOCKET s, uint8_t* data, size_t size);
    // Sleeps up to ms, waking early on stop(). Returns false if stopping.
    bool sleepFor(int ms);
    void log(const std::string& message) const;
    struct UploadEntry {
        bool dir = false;
        uint64_t size = 0;
        int64_t mtime = 0;
        std::vector<uint8_t> path;  // UTF-8, / separated
        std::wstring full;
    };
    // Runs a pending upload on the open session. Returns "" when the session
    // is still usable, else the reason it must close.
    std::string runUpload(SOCKET s);
    bool walk(const std::vector<std::wstring>& roots, std::vector<UploadEntry>& out, uint64_t& total,
              uint32_t& skipped, std::string& error);
    void endUpload(UploadState state);
    // Pull role: one message from the host. Returns "" or why the session
    // must close.
    std::string handlePull(SOCKET s, const jl::file::Message& msg);
    // Pull role: sends the REQUESTs the hub wants and the pacer allows.
    bool pumpRequests(SOCKET s);
    void dropAnnounce();

    std::string localIp_;
    std::string remoteIp_;
    uint16_t port_ = 0;
    LogFn logFn_;
    std::atomic<bool> stopRequested_{false};
    std::mutex wakeMutex_;
    std::condition_variable wake_;
    std::thread worker_;
    std::atomic<int> capability_{0};
    std::atomic<uint16_t> hostCaps_{0};
    std::atomic<uint64_t> sessions_{0};
    std::atomic<uint64_t> pings_{0};

    UploadDoneFn uploadDone_;
    std::mutex uploadMutex_;
    std::vector<std::wstring> uploadRoots_;  // guarded by uploadMutex_
    uint32_t uploadMbps_ = jl::fileup::kDefaultMaxMbps;
    std::atomic<bool> uploadPending_{false};
    std::atomic<bool> uploadRunning_{false};
    std::atomic<bool> uploadCancel_{false};
    std::atomic<int> uploadState_{0};
    std::atomic<uint64_t> upFiles_{0};
    std::atomic<uint64_t> upFilesDone_{0};
    std::atomic<uint64_t> upTotal_{0};
    std::atomic<uint64_t> upCommitted_{0};
    std::atomic<uint64_t> upRate_{0};
    std::atomic<int> upPurpose_{0};
    std::atomic<int> upHostStatus_{0};
    std::atomic<uint32_t> upFilesOk_{0};
    std::atomic<uint32_t> lastSend_{0};       // last send the host finished
    std::atomic<uint32_t> revealPending_{0};  // REVEAL to send on the session thread
    std::atomic<uint64_t> txBytes_{0};

    Role role_ = Role::Upload;
    std::unique_ptr<jl::filepull::PullHub> hub_;
    std::unique_ptr<jl::filepull::FileClipboard> clip_;
    std::atomic<uint32_t> pullMbps_{jl::fileup::kDefaultMaxMbps};
    PullNoticeFn pullNotice_;
    uint32_t noticedTransfer_ = 0;  // session thread
    jl::fileup::Pacer pullPacer_;
    double pullReadyMs_ = 0.0;
    std::optional<jl::file::Offer> collecting_;   // session thread only
    std::vector<jl::file::Entry> entries_;
};
