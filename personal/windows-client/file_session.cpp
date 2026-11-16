#include "file_session.hpp"

#include "file_proto.hpp"

#include <windows.h>
#include <bcrypt.h>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <random>
#include <utility>

namespace {
constexpr int kAckTimeoutMs = 2000;
constexpr int kPingIntervalMs = 15000;
constexpr int kPollMs = 250;
constexpr int kPullPollMs = 5;
constexpr int kBackoffMinMs = 1000;
constexpr int kBackoffMaxMs = 30000;

enum class Outcome { ConnectFailed, NoAck, Closed, Stopped };

std::string hex4(uint16_t v) {
    char buf[8];
    std::snprintf(buf, sizeof(buf), "%04x", unsigned(v));
    return buf;
}
}  // namespace

FileSession::FileSession(std::string localIp, std::string remoteIp, uint16_t port, LogFn logFn, Role role)
    : localIp_(std::move(localIp)), remoteIp_(std::move(remoteIp)), port_(port), logFn_(std::move(logFn)), role_(role) {
    if (role_ == Role::Pull) {
        hub_ = std::make_unique<jl::filepull::PullHub>(jl::filepull::sha256Digest());
        clip_ = std::make_unique<jl::filepull::FileClipboard>(*hub_, logFn_);
    }
}

FileSession::~FileSession() {
    stop();
}

void FileSession::start() {
    if (worker_.joinable()) return;
    stopRequested_ = false;
    if (clip_) clip_->start();
    worker_ = std::thread([this] { run(); });
}

void FileSession::stop() {
    {
        std::lock_guard<std::mutex> lock(wakeMutex_);
        stopRequested_ = true;
    }
    wake_.notify_all();
    if (worker_.joinable()) worker_.join();
    // Clears Windows clipboard if it still holds a Mac copy: with no session
    // nobody could paste it.
    if (clip_) clip_->stop();
}

void FileSession::log(const std::string& message) const {
    if (logFn_) logFn_(message);
}

bool FileSession::sleepFor(int ms) {
    std::unique_lock<std::mutex> lock(wakeMutex_);
    wake_.wait_for(lock, std::chrono::milliseconds(ms), [this] { return stopRequested_.load(); });
    return !stopRequested_;
}

void FileSession::closeSocket(SOCKET& s) {
    if (s != INVALID_SOCKET) {
        shutdown(s, SD_BOTH);
        closesocket(s);
        s = INVALID_SOCKET;
    }
}

// Same connect as ClipboardChannel: bound to the tailnet address, 250 ms
// non-blocking connect, then blocking I/O with a send/receive guard.
SOCKET FileSession::connectSocket() {
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    BOOL noDelay = TRUE;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&noDelay), sizeof(noDelay));
    DWORD ioTimeoutMs = kAckTimeoutMs;
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&ioTimeoutMs), sizeof(ioTimeoutMs));
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&ioTimeoutMs), sizeof(ioTimeoutMs));

    sockaddr_in local{};
    local.sin_family = AF_INET;
    if (inet_pton(AF_INET, localIp_.c_str(), &local.sin_addr) != 1 ||
        bind(s, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    sockaddr_in remote{};
    remote.sin_family = AF_INET;
    remote.sin_port = htons(port_);
    if (inet_pton(AF_INET, remoteIp_.c_str(), &remote.sin_addr) != 1) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    u_long nonBlocking = 1;
    if (ioctlsocket(s, FIONBIO, &nonBlocking) != 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    int rc = connect(s, reinterpret_cast<sockaddr*>(&remote), sizeof(remote));
    if (rc == SOCKET_ERROR) {
        const int e = WSAGetLastError();
        if (e != WSAEWOULDBLOCK && e != WSAEINPROGRESS && e != WSAEINVAL) {
            closesocket(s);
            return INVALID_SOCKET;
        }
        fd_set writeSet, errorSet;
        FD_ZERO(&writeSet);
        FD_ZERO(&errorSet);
        FD_SET(s, &writeSet);
        FD_SET(s, &errorSet);
        timeval tv{};
        tv.tv_usec = 250000;
        rc = select(0, nullptr, &writeSet, &errorSet, &tv);
        if (rc <= 0 || FD_ISSET(s, &errorSet)) {
            closesocket(s);
            return INVALID_SOCKET;
        }
        int soError = 0;
        int soLen = sizeof(soError);
        if (getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soError), &soLen) != 0 || soError != 0) {
            closesocket(s);
            return INVALID_SOCKET;
        }
    }
    nonBlocking = 0;
    if (ioctlsocket(s, FIONBIO, &nonBlocking) != 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

bool FileSession::waitReadable(SOCKET s, int ms) {
    fd_set readSet;
    FD_ZERO(&readSet);
    FD_SET(s, &readSet);
    timeval tv{};
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    return select(0, &readSet, nullptr, nullptr, &tv) > 0;
}

bool FileSession::sendAll(SOCKET s, const uint8_t* data, size_t size) {
    size_t offset = 0;
    while (offset < size) {
        const int n = send(s, reinterpret_cast<const char*>(data + offset), static_cast<int>(size - offset), 0);
        if (n <= 0) return false;
        offset += static_cast<size_t>(n);
    }
    return true;
}

bool FileSession::recvExact(SOCKET s, uint8_t* data, size_t size) {
    size_t offset = 0;
    while (offset < size) {
        const int n = recv(s, reinterpret_cast<char*>(data + offset), static_cast<int>(size - offset), 0);
        if (n <= 0) return false;
        offset += static_cast<size_t>(n);
    }
    return true;
}

bool FileSession::sendPacket(SOCKET s, uint8_t type, const std::vector<uint8_t>& payload) {
    if (payload.size() > jl::file::kMaxPayload) return false;
    const uint16_t len = static_cast<uint16_t>(payload.size());
    std::vector<uint8_t> packet{'M', 'R', 'C', '1', 1, type, uint8_t(len >> 8), uint8_t(len)};
    packet.insert(packet.end(), payload.begin(), payload.end());
    return sendAll(s, packet.data(), packet.size());
}

bool FileSession::recvPacket(SOCKET s, uint8_t& type, std::vector<uint8_t>& payload) {
    uint8_t header[8]{};
    if (!recvExact(s, header, sizeof(header))) return false;
    if (header[0] != 'M' || header[1] != 'R' || header[2] != 'C' || header[3] != '1' || header[4] != 1) return false;
    const uint16_t len = uint16_t((uint16_t(header[6]) << 8) | header[7]);
    if (len > jl::file::kMaxPayload) return false;
    type = header[5];
    payload.assign(len, 0);
    return len == 0 || recvExact(s, payload.data(), len);
}

void FileSession::run() {
    int backoffMs = kBackoffMinMs;
    while (!stopRequested_) {
        SOCKET s = connectSocket();
        Outcome outcome = Outcome::ConnectFailed;
        if (s != INVALID_SOCKET) {
            using namespace jl::file;
            const uint16_t ours = role_ == Role::Pull ? caps::kAnnounce : caps::kViewer;
            const auto hello = encode(Hello{kVersion, ours});
            if (hello && sendPacket(s, type::kHello, *hello)) {
                outcome = Outcome::NoAck;
                // Wait for HELLO_ACK in short slices so stop() is prompt.
                const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(kAckTimeoutMs);
                bool acked = false;
                while (!stopRequested_ && !acked && std::chrono::steady_clock::now() < deadline) {
                    if (!waitReadable(s, kPollMs)) continue;
                    uint8_t t = 0;
                    std::vector<uint8_t> p;
                    if (!recvPacket(s, t, p)) break;
                    const auto msg = decode(t, p);
                    const HelloAck* ack = msg ? std::get_if<HelloAck>(&*msg) : nullptr;
                    if (!ack || ack->proto < 1) break;
                    acked = true;
                    hostCaps_ = ack->caps;
                }
                if (stopRequested_) outcome = Outcome::Stopped;
                else if (acked) outcome = Outcome::Closed;
            }
            if (outcome == Outcome::Closed && role_ == Role::Pull && !(hostCaps_.load() & caps::kAnnounce)) {
                // A host without F3: Finder copies stay text-only, as before.
                capability_ = static_cast<int>(Capability::No);
                log("file.pull=unsupported caps=0x" + hex4(hostCaps_.load()));
                closeSocket(s);
                break;
            }
            if (outcome == Outcome::Closed) {
                ++sessions_;
                backoffMs = kBackoffMinMs;
                if (capability() != Capability::Yes) {
                    capability_ = static_cast<int>(Capability::Yes);
                    log(std::string(role_ == Role::Pull ? "file.pull=ready" : "file.capability=yes") + " caps=0x" +
                        hex4(hostCaps_.load()));
                }
                // Keepalive: PING every 15 s; the next PING finds the last
                // one unanswered only if the host stopped answering.
                std::string reason = "peer_closed";
                auto lastPing = std::chrono::steady_clock::now();
                uint32_t token = 0;
                bool outstanding = false;
                while (true) {
                    if (stopRequested_) { reason = "stopping"; outcome = Outcome::Stopped; break; }
                    if (uploadPending_) {
                        const std::string why = runUpload(s);
                        if (!why.empty()) {
                            reason = why;
                            if (stopRequested_) outcome = Outcome::Stopped;
                            break;
                        }
                        // The upload kept the session busy; restart the ping clock.
                        lastPing = std::chrono::steady_clock::now();
                        outstanding = false;
                        continue;
                    }
                    if (role_ == Role::Pull && !pumpRequests(s)) { reason = "send_failed"; break; }
                    if (std::chrono::steady_clock::now() - lastPing >= std::chrono::milliseconds(kPingIntervalMs)) {
                        if (outstanding) { reason = "ping_timeout"; break; }
                        ++token;
                        const auto ping = encode(Ping{{uint8_t(token >> 24), uint8_t(token >> 16), uint8_t(token >> 8), uint8_t(token)}});
                        if (!ping || !sendPacket(s, type::kPing, *ping)) { reason = "send_failed"; break; }
                        ++pings_;
                        outstanding = true;
                        lastPing = std::chrono::steady_clock::now();
                    }
                    // While Explorer is pulling, poll fast so REQUESTs follow reads.
                    const int poll = hub_ && hub_->wantsService() ? kPullPollMs : kPollMs;
                    if (!waitReadable(s, poll)) continue;
                    uint8_t t = 0;
                    std::vector<uint8_t> p;
                    if (!recvPacket(s, t, p)) break;
                    const auto msg = decode(t, p);
                    if (!msg) { reason = "malformed"; break; }
                    if (role_ == Role::Pull) {
                        const std::string why = handlePull(s, *msg);
                        if (!why.empty()) { reason = why; break; }
                    }
                    if (const Ping* pong = std::get_if<Ping>(&*msg)) {
                        const uint32_t got = (uint32_t(pong->token[0]) << 24) | (uint32_t(pong->token[1]) << 16) |
                                             (uint32_t(pong->token[2]) << 8) | uint32_t(pong->token[3]);
                        if (got == token) outstanding = false;
                    }
                    // Anything else well-formed is ignored.
                }
                log(std::string(role_ == Role::Pull ? "file.pull" : "file.session") + "=closed reason=" + reason);
                if (role_ == Role::Pull) dropAnnounce();
            }
            closeSocket(s);
        }

        // An upload asked for while the session was down fails at once.
        if (uploadPending_) endUpload(UploadState::Failed);
        if (outcome == Outcome::Stopped) break;
        if (outcome == Outcome::NoAck) {
            // An old host ignores 0x50 and keeps the socket open; a new host
            // that refused us closed it. Either way, do not probe again in
            // this viewer session.
            capability_ = static_cast<int>(Capability::No);
            log("file.capability=no");
            break;
        }
        if (!sleepFor(backoffMs)) break;
        backoffMs = std::min(backoffMs * 2, kBackoffMaxMs);
    }
    if (uploadPending_) endUpload(UploadState::Failed);
}

// ---- F2: Windows->Mac paste upload ----------------------------------------

namespace {
constexpr int kReplyTimeoutMs = 10000;
constexpr int kResultTimeoutMs = 60000;
constexpr int kCancelWaitMs = 3000;
constexpr DWORD kUploadIoTimeoutMs = 10000;

double nowMs() {
    using namespace std::chrono;
    return duration<double, std::milli>(steady_clock::now().time_since_epoch()).count();
}

// FILETIME (100 ns since 1601) to Unix seconds.
int64_t unixTime(const FILETIME& ft) {
    const int64_t t = (int64_t(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    return (t - 116444736000000000LL) / 10000000LL;
}

bool toUtf8(const std::wstring& w, std::vector<uint8_t>& out) {
    out.clear();
    if (w.empty()) return false;
    const int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, w.data(), int(w.size()), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return false;
    out.resize(size_t(n));
    return WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, w.data(), int(w.size()),
                               reinterpret_cast<char*>(out.data()), n, nullptr, nullptr) == n;
}

// Last component of a full path, without trailing separators.
std::wstring leafName(std::wstring p) {
    while (!p.empty() && (p.back() == L'\\' || p.back() == L'/')) p.pop_back();
    const size_t cut = p.find_last_of(L"\\/");
    std::wstring leaf = cut == std::wstring::npos ? p : p.substr(cut + 1);
    if (leaf.size() >= 2 && leaf[1] == L':') return {};  // a drive root
    return leaf;
}

class Sha256 {
public:
    Sha256() {
        ok_ = BCryptOpenAlgorithmProvider(&alg_, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0 &&
              BCryptCreateHash(alg_, &hash_, nullptr, 0, nullptr, 0, 0) == 0;
    }
    ~Sha256() {
        if (hash_) BCryptDestroyHash(hash_);
        if (alg_) BCryptCloseAlgorithmProvider(alg_, 0);
    }
    Sha256(const Sha256&) = delete;
    Sha256& operator=(const Sha256&) = delete;
    bool ok() const { return ok_; }
    bool update(const uint8_t* d, size_t n) {
        return ok_ && BCryptHashData(hash_, const_cast<PUCHAR>(d), ULONG(n), 0) == 0;
    }
    bool finish(std::vector<uint8_t>& out) {
        out.assign(32, 0);
        return ok_ && BCryptFinishHash(hash_, out.data(), 32, 0) == 0;
    }

private:
    BCRYPT_ALG_HANDLE alg_ = nullptr;
    BCRYPT_HASH_HANDLE hash_ = nullptr;
    bool ok_ = false;
};

const char* statusName(uint8_t s) {
    using namespace jl::file::status;
    switch (s) {
    case kOk: return "ok";
    case kTooBig: return "too_big";
    case kNoSpace: return "no_space";
    case kBusy: return "busy";
    case kDenied: return "denied";
    case kBadPath: return "bad_path";
    case kFailed: return "failed";
    case kCancelled: return "cancelled";
    default: return "unknown";
    }
}
}  // namespace

bool FileSession::startUpload(std::vector<std::wstring> roots, uint32_t maxMbps) {
    if (roots.empty() || !canUpload()) return false;
    std::lock_guard<std::mutex> lock(uploadMutex_);
    if (uploadRunning_) return false;
    uploadRoots_ = std::move(roots);
    uploadMbps_ = maxMbps;
    uploadCancel_ = false;
    upFiles_ = 0;
    upFilesDone_ = 0;
    upTotal_ = 0;
    upCommitted_ = 0;
    upRate_ = 0;
    uploadState_ = static_cast<int>(UploadState::Running);
    uploadRunning_ = true;
    uploadPending_ = true;
    return true;
}

FileSession::UploadProgress FileSession::uploadProgress() const {
    UploadProgress p;
    p.state = static_cast<UploadState>(uploadState_.load());
    p.files = upFiles_.load();
    p.filesDone = upFilesDone_.load();
    p.total = upTotal_.load();
    p.committed = upCommitted_.load();
    p.bytesPerSec = upRate_.load();
    return p;
}

void FileSession::endUpload(UploadState state) {
    {
        std::lock_guard<std::mutex> lock(uploadMutex_);
        uploadRoots_.clear();
        uploadState_ = static_cast<int>(state);
        uploadPending_ = false;
        uploadRunning_ = false;
    }
    if (uploadDone_) uploadDone_();
}

// Walks the copied roots depth first, parents before children. Symlinks,
// junctions and other reparse points are skipped and counted. Limits are the
// wire limits (10000 entries, 20 GiB, 1024-byte paths).
bool FileSession::walk(const std::vector<std::wstring>& roots, std::vector<UploadEntry>& out, uint64_t& total,
                       uint32_t& skipped, std::string& error) {
    using namespace jl::file;
    struct Pending { std::wstring full; std::vector<uint8_t> rel; };
    auto add = [&](bool dir, uint64_t size, const FILETIME& ft, std::vector<uint8_t> rel, std::wstring full) -> bool {
        if (out.size() >= kMaxEntries) { error = "too_many"; return false; }
        if (rel.size() > kMaxPathBytes) { error = "path_too_long"; return false; }
        if (!dir) {
            total += size;
            if (total > kMaxTotalBytes) { error = "too_big"; return false; }
        }
        out.push_back({dir, dir ? 0 : size, unixTime(ft), std::move(rel), std::move(full)});
        return true;
    };

    std::vector<Pending> dirs;
    for (const auto& root : roots) {
        if (stopRequested_ || uploadCancel_) { error = "cancelled"; return false; }
        WIN32_FILE_ATTRIBUTE_DATA a{};
        if (!GetFileAttributesExW(root.c_str(), GetFileExInfoStandard, &a)) { error = "missing"; return false; }
        if (a.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) { ++skipped; continue; }
        std::vector<uint8_t> rel;
        if (!toUtf8(leafName(root), rel)) { error = "name"; return false; }
        const bool isDir = (a.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        const uint64_t size = (uint64_t(a.nFileSizeHigh) << 32) | a.nFileSizeLow;
        if (!add(isDir, size, a.ftLastWriteTime, rel, root)) return false;
        if (isDir) dirs.push_back({root, rel});
        // Depth first so a folder's entries follow it.
        while (!dirs.empty()) {
            if (stopRequested_ || uploadCancel_) { error = "cancelled"; return false; }
            Pending d = std::move(dirs.back());
            dirs.pop_back();
            WIN32_FIND_DATAW f{};
            HANDLE h = FindFirstFileExW((d.full + L"\\*").c_str(), FindExInfoBasic, &f, FindExSearchNameMatch,
                                        nullptr, FIND_FIRST_EX_LARGE_FETCH);
            if (h == INVALID_HANDLE_VALUE) { error = "list"; return false; }
            std::vector<Pending> children;
            bool ok = true;
            do {
                const std::wstring name = f.cFileName;
                if (name == L"." || name == L"..") continue;
                if (f.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) { ++skipped; continue; }
                std::vector<uint8_t> leaf;
                if (!toUtf8(name, leaf)) { error = "name"; ok = false; break; }
                std::vector<uint8_t> childRel = d.rel;
                childRel.push_back('/');
                childRel.insert(childRel.end(), leaf.begin(), leaf.end());
                const bool childDir = (f.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
                const uint64_t childSize = (uint64_t(f.nFileSizeHigh) << 32) | f.nFileSizeLow;
                const std::wstring childFull = d.full + L"\\" + name;
                if (!add(childDir, childSize, f.ftLastWriteTime, childRel, childFull)) { ok = false; break; }
                if (childDir) children.push_back({childFull, std::move(childRel)});
            } while (FindNextFileW(h, &f));
            FindClose(h);
            if (!ok) return false;
            // Reverse so the first child folder is walked first.
            for (auto it = children.rbegin(); it != children.rend(); ++it) dirs.push_back(std::move(*it));
        }
    }
    if (out.empty()) { error = "empty"; return false; }
    return true;
}

std::string FileSession::runUpload(SOCKET s) {
    using namespace jl::file;
    const double started = nowMs();
    std::vector<std::wstring> roots;
    uint32_t mbps = jl::fileup::kDefaultMaxMbps;
    {
        std::lock_guard<std::mutex> lock(uploadMutex_);
        roots = uploadRoots_;
        mbps = uploadMbps_;
    }
    static std::mt19937 rng{std::random_device{}()};
    const uint32_t transfer = static_cast<uint32_t>(rng()) | 1u;
    const std::string tag = "file.tx transfer=" + std::to_string(transfer);

    std::vector<UploadEntry> entries;
    uint64_t total = 0;
    uint32_t skipped = 0;
    std::string walkError;
    if (!walk(roots, entries, total, skipped, walkError)) {
        log(tag + " result=failed:" + walkError + " skipped=" + std::to_string(skipped));
        endUpload(walkError == "cancelled" ? UploadState::Cancelled : UploadState::Failed);
        return stopRequested_ ? "stopping" : "";
    }
    uint64_t files = 0;
    for (const auto& e : entries) files += e.dir ? 0 : 1;
    upFiles_ = files;
    upTotal_ = total;

    DWORD ioTimeout = kUploadIoTimeoutMs;
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&ioTimeout), sizeof(ioTimeout));
    struct RestoreTimeout {
        SOCKET s;
        ~RestoreTimeout() {
            DWORD t = kAckTimeoutMs;
            setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&t), sizeof(t));
        }
    } restore{s};

    uint64_t sent = 0;
    uint64_t committed = 0;
    uint32_t filesOk = 0;
    bool hostResult = false;
    uint8_t hostStatus = status::kFailed;
    // Rate over ~1 s windows of committed bytes.
    double rateAt = nowMs();
    uint64_t rateBytes = 0;

    auto finish = [&](UploadState state, const std::string& result) {
        log(tag + " entries=" + std::to_string(entries.size()) + " files=" + std::to_string(files) +
            " bytes=" + std::to_string(sent) + " ms=" + std::to_string(int64_t(nowMs() - started)) +
            " skipped=" + std::to_string(skipped) + " result=" + result);
        endUpload(state);
    };
    auto sendMsg = [&](const Message& m, uint8_t type) {
        const auto bytes = encode(m);
        return bytes && sendPacket(s, type, *bytes);
    };
    // Reads one message if one is waiting (up to waitMs). Returns false on a
    // broken or confused session.
    auto pump = [&](int waitMs) -> bool {
        if (!waitReadable(s, waitMs)) return true;
        uint8_t t = 0;
        std::vector<uint8_t> p;
        if (!recvPacket(s, t, p)) return false;
        const auto msg = decode(t, p);
        if (!msg) return false;
        if (const Progress* pr = std::get_if<Progress>(&*msg)) {
            if (pr->transfer == transfer && pr->committed >= committed && pr->committed <= total) {
                committed = pr->committed;
                upCommitted_ = committed;
                const double now = nowMs();
                if (now - rateAt >= 1000.0) {
                    upRate_ = uint64_t(double(committed - rateBytes) * 1000.0 / (now - rateAt));
                    rateAt = now;
                    rateBytes = committed;
                }
            }
        } else if (const Result* r = std::get_if<Result>(&*msg)) {
            if (r->transfer == transfer) {
                hostResult = true;
                hostStatus = r->status;
                filesOk = r->filesOk;
            }
        } else if (const Reply* rep = std::get_if<Reply>(&*msg)) {
            if (rep->transfer == transfer && rep->status != status::kOk) {
                hostResult = true;
                hostStatus = rep->status;
            }
        }
        return true;
    };
    // Sends CANCEL and waits briefly for the host to confirm cleanup.
    auto cancel = [&]() -> std::string {
        if (!sendMsg(Cancel{transfer, status::kCancelled}, type::kCancel)) {
            finish(UploadState::Cancelled, "cancelled");
            return "send_failed";
        }
        if (stopRequested_) {
            finish(UploadState::Cancelled, "cancelled");
            return "stopping";
        }
        const double until = nowMs() + kCancelWaitMs;
        while (!hostResult && !stopRequested_ && nowMs() < until) {
            if (!pump(100)) {
                finish(UploadState::Cancelled, "cancelled");
                return "peer_closed";
            }
        }
        finish(UploadState::Cancelled, "cancelled");
        return "";
    };

    // OFFER + every ENTRY, then the host's single REPLY.
    if (!sendMsg(Offer{transfer, purpose::kPaste, uint32_t(entries.size()), total}, type::kOffer)) {
        finish(UploadState::Failed, "failed:send");
        return "send_failed";
    }
    for (uint32_t i = 0; i < entries.size(); ++i) {
        const auto& e = entries[i];
        if (!sendMsg(Entry{transfer, i, e.dir ? kind::kDir : kind::kFile, e.size, e.mtime, e.path}, type::kEntry)) {
            finish(UploadState::Failed, "failed:send");
            return "send_failed";
        }
    }
    {
        bool accepted = false;
        const double until = nowMs() + kReplyTimeoutMs;
        while (!accepted && !hostResult && nowMs() < until) {
            if (stopRequested_ || uploadCancel_) return cancel();
            if (!waitReadable(s, 100)) continue;
            uint8_t t = 0;
            std::vector<uint8_t> p;
            if (!recvPacket(s, t, p)) { finish(UploadState::Failed, "failed:closed"); return "peer_closed"; }
            const auto msg = decode(t, p);
            if (!msg) { finish(UploadState::Failed, "failed:malformed"); return "malformed"; }
            if (const Reply* r = std::get_if<Reply>(&*msg); r && r->transfer == transfer) {
                if (r->status == status::kOk) accepted = true;
                else { hostResult = true; hostStatus = r->status; }
            }
        }
        if (hostResult) {
            finish(UploadState::Failed, std::string("rejected:") + statusName(hostStatus));
            return "";
        }
        if (!accepted) { finish(UploadState::Failed, "failed:no_reply"); return "no_reply"; }
    }

    jl::fileup::Pacer pacer(mbps);
    std::vector<uint8_t> buf(kMaxChunk);
    for (uint32_t i = 0; i < entries.size(); ++i) {
        const auto& e = entries[i];
        if (e.dir) continue;
        HANDLE f = CreateFileW(e.full.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_REPARSE_POINT,
                               nullptr);
        if (f == INVALID_HANDLE_VALUE) {
            sendMsg(Cancel{transfer, status::kFailed}, type::kCancel);
            finish(UploadState::Failed, "failed:open");
            return "";
        }
        Sha256 sha;
        uint64_t offset = 0;
        std::string fail;
        while (offset < e.size && fail.empty()) {
            if (stopRequested_ || uploadCancel_) { CloseHandle(f); return cancel(); }
            // Drain host messages; wait while 4 MiB are unacknowledged.
            if (!pump(0)) { CloseHandle(f); finish(UploadState::Failed, "failed:closed"); return "peer_closed"; }
            if (hostResult) break;
            if (sent - committed + kMaxChunk > jl::fileup::kWindowBytes) {
                if (!pump(100)) { CloseHandle(f); finish(UploadState::Failed, "failed:closed"); return "peer_closed"; }
                continue;
            }
            const DWORD want = DWORD(std::min<uint64_t>(kMaxChunk, e.size - offset));
            DWORD got = 0;
            if (!ReadFile(f, buf.data(), want, &got, nullptr) || got != want) { fail = "read"; break; }
            if (!sha.update(buf.data(), got)) { fail = "hash"; break; }
            const double wait = pacer.delayMs(got, nowMs());
            if (wait >= 1.0 && !sleepFor(int(wait))) { CloseHandle(f); return cancel(); }
            if (!sendMsg(Data{transfer, i, offset, std::vector<uint8_t>(buf.begin(), buf.begin() + got)}, type::kData)) {
                CloseHandle(f);
                finish(UploadState::Failed, "failed:send");
                return "send_failed";
            }
            offset += got;
            sent += got;
            txBytes_ += got;
        }
        CloseHandle(f);
        if (hostResult) break;
        if (!fail.empty()) {
            sendMsg(Cancel{transfer, status::kFailed}, type::kCancel);
            finish(UploadState::Failed, "failed:" + fail);
            return "";
        }
        std::vector<uint8_t> digest;
        if (!sha.finish(digest)) {
            sendMsg(Cancel{transfer, status::kFailed}, type::kCancel);
            finish(UploadState::Failed, "failed:hash");
            return "";
        }
        if (!sendMsg(FileEnd{transfer, i, digest}, type::kFileEnd)) {
            finish(UploadState::Failed, "failed:send");
            return "send_failed";
        }
        ++upFilesDone_;
    }

    // The host commits, writes the pasteboard and answers RESULT.
    const double until = nowMs() + kResultTimeoutMs;
    while (!hostResult && nowMs() < until) {
        if (stopRequested_ || uploadCancel_) return cancel();
        if (!pump(100)) { finish(UploadState::Failed, "failed:closed"); return "peer_closed"; }
    }
    if (!hostResult) { finish(UploadState::Failed, "failed:no_result"); return "no_result"; }
    if (hostStatus == status::kOk) {
        upCommitted_ = total;
        finish(UploadState::Done, "ok files_ok=" + std::to_string(filesOk));
    } else if (hostStatus == status::kCancelled) {
        finish(UploadState::Cancelled, "cancelled");
    } else {
        finish(UploadState::Failed, std::string("failed:") + statusName(hostStatus));
    }
    return "";
}

// ---- F3: Mac->Windows paste pull -----------------------------------------

void FileSession::dropAnnounce() {
    collecting_.reset();
    entries_.clear();
    if (hub_) hub_->disconnect();
    if (clip_) clip_->withdraw(0);
}

bool FileSession::pumpRequests(SOCKET s) {
    using namespace jl::file;
    pullPacer_.setMbps(pullMbps_.load());
    while (true) {
        const double now = nowMs();
        if (now < pullReadyMs_) return true;
        const auto q = hub_->nextRequest();
        if (!q) return true;
        const auto pkt = encode(*q);
        if (!pkt || !sendPacket(s, type::kRequest, *pkt)) return false;
        // Paced when asked for, so bytes arrive at about the configured rate.
        pullReadyMs_ = now + pullPacer_.delayMs(q->length, now);
    }
}

std::string FileSession::handlePull(SOCKET s, const jl::file::Message& msg) {
    using namespace jl::file;
    const auto refuse = [&](uint32_t t, const std::string& why, uint8_t status) {
        log("file.announce=refused transfer=" + std::to_string(t) + " reason=" + why);
        if (pullNotice_) pullNotice_(PullNotice::NotOffered);
        const auto pkt = encode(Reply{t, status});
        return pkt && sendPacket(s, type::kReply, *pkt) ? std::string() : std::string("send_failed");
    };
    if (const Offer* o = std::get_if<Offer>(&msg)) {
        if (o->purpose != purpose::kAnnounce) return "";
        // A new Finder copy replaces whatever this PC was offered before.
        collecting_.reset();
        entries_.clear();
        if (const uint32_t old = hub_->current()) {
            hub_->cancel(old);
            clip_->withdraw(old);
        }
        if (o->entries == 0 || o->entries > kMaxEntries) return refuse(o->transfer, "too_many", status::kTooBig);
        if (o->total > kMaxTotalBytes) return refuse(o->transfer, "too_big", status::kTooBig);
        collecting_ = *o;
        entries_.reserve(std::min<uint32_t>(o->entries, 1024));
        return "";
    }
    if (const Entry* e = std::get_if<Entry>(&msg)) {
        if (!collecting_ || e->transfer != collecting_->transfer) return "";
        entries_.push_back(*e);
        if (entries_.size() < collecting_->entries) return "";
        const Offer offer = *collecting_;
        collecting_.reset();
        jl::filepull::Manifest m;
        const std::string why = jl::filepull::buildManifest(offer, entries_, m);
        entries_.clear();
        if (!why.empty()) return refuse(offer.transfer, why, status::kBadPath);
        hub_->announce(m);
        clip_->offer(m);
        log("file.announce=received transfer=" + std::to_string(m.transfer) + " entries=" +
            std::to_string(m.items.size()) + " files=" + std::to_string(m.files) + " bytes=" + std::to_string(m.total) +
            " renamed=" + std::to_string(m.renamed));
        return "";
    }
    if (const Cancel* c = std::get_if<Cancel>(&msg)) {
        if (collecting_ && collecting_->transfer == c->transfer) {
            collecting_.reset();
            entries_.clear();
        }
        if (hub_->current() == c->transfer) {
            hub_->cancel(c->transfer);
            clip_->withdraw(c->transfer);
            log("file.announce=cancelled transfer=" + std::to_string(c->transfer));
        }
        return "";
    }
    if (const Data* d = std::get_if<Data>(&msg)) {
        hub_->onData(*d);
        return "";
    }
    if (const FileEnd* f = std::get_if<FileEnd>(&msg)) {
        hub_->onFileEnd(*f);
        return "";
    }
    if (const Reply* r = std::get_if<Reply>(&msg)) {
        if (r->status != status::kOk && hub_->current() == r->transfer) {
            hub_->onFailed(r->transfer);
            const bool mac = r->status == status::kMacPermission;
            log("file.pull=failed transfer=" + std::to_string(r->transfer) + " status=" + std::to_string(r->status) +
                (mac ? " reason=mac_permission" : ""));
            // Once per copy: Explorer may ask for several files and fail each.
            if (pullNotice_ && noticedTransfer_ != r->transfer) {
                noticedTransfer_ = r->transfer;
                pullNotice_(mac ? PullNotice::MacPermission : PullNotice::PullFailed);
            }
        }
        return "";
    }
    return "";
}
