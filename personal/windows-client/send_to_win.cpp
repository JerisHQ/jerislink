// F5a: named pipe between "Jerislink.exe --send-to" and the running viewer.
// See send_to_win.hpp for the security model.

#include "send_to_win.hpp"

#include <sddl.h>

#include <algorithm>
#include <memory>

namespace jl::sendto {

namespace {

constexpr DWORD kServerIoMs = 3000;  // one client read / write / close
constexpr size_t kReadChunk = 64 * 1024;

struct HandleCloser {
    void operator()(HANDLE h) const {
        if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }
};
using Handle = std::unique_ptr<void, HandleCloser>;

// The token user of a process (nullptr = this one), as raw TOKEN_USER bytes.
std::vector<uint8_t> tokenUser(HANDLE process) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(process ? process : GetCurrentProcess(), TOKEN_QUERY, &token)) return {};
    Handle hold(token);
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    if (size == 0) return {};
    std::vector<uint8_t> buf(size);
    if (!GetTokenInformation(token, TokenUser, buf.data(), size, &size)) return {};
    return buf;
}

PSID sidOf(std::vector<uint8_t>& user) {
    return user.empty() ? nullptr : reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid;
}

enum class Io { Done, MoreData, Stopped, Timeout, Error };

// Finishes one overlapped call. `issued` is the call's return value.
Io finishIo(HANDLE h, OVERLAPPED& ov, BOOL issued, HANDLE stop, DWORD ms, DWORD& bytes) {
    bytes = 0;
    if (!issued) {
        const DWORD e = GetLastError();
        if (e != ERROR_IO_PENDING && e != ERROR_MORE_DATA) return Io::Error;
    }
    HANDLE waits[2] = {ov.hEvent, stop};
    const DWORD w = WaitForMultipleObjects(stop ? 2 : 1, waits, FALSE, ms);
    if (w != WAIT_OBJECT_0) {
        CancelIoEx(h, &ov);
        GetOverlappedResult(h, &ov, &bytes, TRUE);  // wait for the cancel before `ov` goes away
        bytes = 0;
        return w == WAIT_OBJECT_0 + 1 ? Io::Stopped : Io::Timeout;
    }
    if (GetOverlappedResult(h, &ov, &bytes, FALSE)) return Io::Done;
    return GetLastError() == ERROR_MORE_DATA ? Io::MoreData : Io::Error;
}

DWORD remainingMs(ULONGLONG deadline) {
    const ULONGLONG now = GetTickCount64();
    return now >= deadline ? 0 : static_cast<DWORD>(std::min<ULONGLONG>(deadline - now, 60000));
}

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring w(static_cast<size_t>(std::max(0, n)), L'\0');
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

// The pipe's server process runs as this user, in this logon session.
bool serverIsTrusted(HANDLE pipe) {
    ULONG pid = 0;
    if (!GetNamedPipeServerProcessId(pipe, &pid) || pid == 0) return false;
    DWORD serverSession = 0, mySession = 0;
    if (!ProcessIdToSessionId(pid, &serverSession) || !ProcessIdToSessionId(GetCurrentProcessId(), &mySession) ||
        serverSession != mySession) {
        return false;
    }
    Handle proc(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!proc) return false;
    auto theirs = tokenUser(proc.get());
    auto mine = tokenUser(nullptr);
    const PSID a = sidOf(theirs), b = sidOf(mine);
    return a && b && EqualSid(a, b);
}

}  // namespace

std::wstring currentUserSid() {
    auto user = tokenUser(nullptr);
    const PSID sid = sidOf(user);
    if (!sid) return {};
    LPWSTR text = nullptr;
    if (!ConvertSidToStringSidW(sid, &text) || !text) return {};
    std::wstring s = text;
    LocalFree(text);
    return s;
}

std::wstring currentPipeName() {
    const std::wstring sid = currentUserSid();
    DWORD session = 0;
    if (sid.empty() || !ProcessIdToSessionId(GetCurrentProcessId(), &session)) return {};
    return pipeName(sid, session);
}

bool Server::start(const std::wstring& name, Handler handler) {
    stop();
    error_ = 0;
    const std::wstring sid = currentUserSid();
    if (name.empty() || sid.empty()) {
        error_ = ERROR_INVALID_PARAMETER;
        return false;
    }
    // Protected DACL: full access for this user only (no inherited ACEs).
    const std::wstring sddl = L"D:P(A;;GA;;;" + sid + L")";
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &sd, nullptr)) {
        error_ = GetLastError();
        return false;
    }
    SECURITY_ATTRIBUTES sa{sizeof(sa), sd, FALSE};
    pipe_ = CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                             PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 64,
                             static_cast<DWORD>(kReadChunk), 0, &sa);
    error_ = pipe_ == INVALID_HANDLE_VALUE ? GetLastError() : 0;
    LocalFree(sd);
    if (pipe_ == INVALID_HANDLE_VALUE) return false;
    stop_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!stop_) {
        error_ = GetLastError();
        CloseHandle(pipe_);
        pipe_ = INVALID_HANDLE_VALUE;
        return false;
    }
    handler_ = std::move(handler);
    thread_ = std::thread([this] { run(); });
    return true;
}

void Server::stop() {
    if (thread_.joinable()) {
        SetEvent(stop_);
        thread_.join();
    }
    if (pipe_ != INVALID_HANDLE_VALUE) CloseHandle(pipe_);
    if (stop_) CloseHandle(stop_);
    pipe_ = INVALID_HANDLE_VALUE;
    stop_ = nullptr;
    handler_ = nullptr;
}

void Server::run() {
    OVERLAPPED ov{};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ov.hEvent) return;
    while (WaitForSingleObject(stop_, 0) != WAIT_OBJECT_0) {
        ResetEvent(ov.hEvent);
        const BOOL issued = ConnectNamedPipe(pipe_, &ov);
        bool connected = false;
        if (!issued && GetLastError() == ERROR_PIPE_CONNECTED) {
            connected = true;  // the client came between Disconnect and Connect
        } else {
            DWORD bytes = 0;
            const Io r = finishIo(pipe_, ov, issued, stop_, INFINITE, bytes);
            if (r == Io::Stopped) break;
            connected = r == Io::Done;
        }
        if (connected) serveOne(ov);
        DisconnectNamedPipe(pipe_);
        if (!connected && WaitForSingleObject(stop_, 100) == WAIT_OBJECT_0) break;  // no busy spin on errors
    }
    CloseHandle(ov.hEvent);
}

void Server::serveOne(OVERLAPPED& ov) {
    std::vector<uint8_t> request;
    std::vector<uint8_t> chunk(kReadChunk);
    bool tooBig = false;
    for (;;) {
        ResetEvent(ov.hEvent);
        DWORD got = 0;
        const BOOL issued = ReadFile(pipe_, chunk.data(), static_cast<DWORD>(chunk.size()), nullptr, &ov);
        const Io r = finishIo(pipe_, ov, issued, stop_, kServerIoMs, got);
        if (r != Io::Done && r != Io::MoreData) return;  // stop, slow or gone client: nothing to answer
        if (request.size() + got > kMaxRequestBytes) {
            tooBig = true;
            break;
        }
        request.insert(request.end(), chunk.begin(), chunk.begin() + got);
        if (r == Io::Done) break;
    }
    std::vector<std::wstring> items;
    Reply reply = Reply::BadRequest;
    if (!tooBig && decodeRequest(request.data(), request.size(), items)) {
        reply = handler_ ? handler_(std::move(items)) : Reply::Failed;
    }
    const auto out = encodeReply(reply);
    ResetEvent(ov.hEvent);
    DWORD wrote = 0;
    BOOL issued = WriteFile(pipe_, out.data(), static_cast<DWORD>(out.size()), nullptr, &ov);
    if (finishIo(pipe_, ov, issued, stop_, kServerIoMs, wrote) != Io::Done) return;
    // Let the client read the reply before the pipe is disconnected: wait
    // (bounded) for it to close its end.
    ResetEvent(ov.hEvent);
    issued = ReadFile(pipe_, chunk.data(), static_cast<DWORD>(chunk.size()), nullptr, &ov);
    finishIo(pipe_, ov, issued, stop_, kServerIoMs, wrote);
}

Reply sendItems(const std::wstring& name, const std::vector<std::wstring>& items, DWORD timeoutMs) {
    const Reply checked = checkItems(items);
    if (checked != Reply::Started) return checked;
    const auto request = encodeRequest(items);
    if (request.size() > kMaxRequestBytes) return Reply::TooMany;
    const ULONGLONG deadline = GetTickCount64() + timeoutMs;

    Handle pipe;
    for (;;) {
        // Identification only: the viewer can see who we are, not act as us.
        HANDLE h = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                               FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            pipe.reset(h);
            break;
        }
        const DWORD e = GetLastError();
        if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) return Reply::NotConnected;
        if (e == ERROR_ACCESS_DENIED) return Reply::NotTrusted;  // another user's pipe
        if (e != ERROR_PIPE_BUSY) return Reply::Failed;
        const DWORD left = remainingMs(deadline);
        if (left == 0) return Reply::Failed;
        if (!WaitNamedPipeW(name.c_str(), std::min<DWORD>(left, 2000)) && GetLastError() == ERROR_FILE_NOT_FOUND) {
            return Reply::NotConnected;
        }
    }
    if (!serverIsTrusted(pipe.get())) return Reply::NotTrusted;
    DWORD mode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(pipe.get(), &mode, nullptr, nullptr)) return Reply::Failed;

    Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!event) return Reply::Failed;
    OVERLAPPED ov{};
    ov.hEvent = event.get();
    DWORD bytes = 0;
    BOOL issued = WriteFile(pipe.get(), request.data(), static_cast<DWORD>(request.size()), nullptr, &ov);
    if (finishIo(pipe.get(), ov, issued, nullptr, remainingMs(deadline), bytes) != Io::Done ||
        bytes != request.size()) {
        return Reply::Failed;
    }
    uint8_t buf[16] = {};
    ResetEvent(ov.hEvent);
    issued = ReadFile(pipe.get(), buf, sizeof(buf), nullptr, &ov);
    if (finishIo(pipe.get(), ov, issued, nullptr, remainingMs(deadline), bytes) != Io::Done) return Reply::Failed;
    Reply reply = Reply::Failed;
    if (!decodeReply(buf, bytes, reply)) return Reply::Failed;
    return reply;
}

int runSendTo(const Args& args) {
    Reply r = checkArgs(args);
    if (r == Reply::Started) {
        const std::wstring name = currentPipeName();
        r = name.empty() ? Reply::Failed : sendItems(name, args.items);
    }
    wchar_t quiet[8] = {};
    const bool silent = GetEnvironmentVariableW(L"JERISLINK_SENDTO_QUIET", quiet, 8) == 1 && quiet[0] == L'1';
    if (r != Reply::Started && !silent) {
        const UINT icon = r == Reply::NotTrusted || r == Reply::Failed ? MB_ICONWARNING : MB_ICONINFORMATION;
        MessageBoxW(nullptr, widen(message(r)).c_str(), L"JerisLink", MB_OK | icon | MB_SETFOREGROUND);
    }
    return exitCode(r);
}

}  // namespace jl::sendto
