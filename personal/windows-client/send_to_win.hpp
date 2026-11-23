#pragma once

// F5a Win32 side of Send to JerisLink (send_to.hpp has the rules and texts).
//
// Server: the viewer owns one named pipe per user and logon session,
// created as the first instance (nobody can sit on the name before it, and
// a second viewer cannot take it over), message mode, local clients only,
// DACL = this user only. One client at a time; every read, write and wait is
// bounded so a stuck client cannot hold the viewer.
//
// Client: "Jerislink.exe --send-to" connects with identification-level
// impersonation only, checks the server process belongs to the same user
// and session, sends the paths and reads one reply.

#include "send_to.hpp"

#include <windows.h>

#include <functional>
#include <string>
#include <thread>
#include <vector>

namespace jl::sendto {

// This process's user SID ("S-1-5-21-...") and the pipe name for its user
// and logon session; "" when the token cannot be read.
std::wstring currentUserSid();
std::wstring currentPipeName();

class Server {
public:
    // Runs on the server thread; must return within a few seconds.
    using Handler = std::function<Reply(std::vector<std::wstring>&&)>;

    Server() = default;
    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;
    ~Server() { stop(); }

    // false when the name is already taken (another viewer of this user and
    // session) or the pipe could not be made; error() says why.
    bool start(const std::wstring& name, Handler handler);
    void stop();
    bool running() const { return thread_.joinable(); }
    DWORD error() const { return error_; }

private:
    void run();
    void serveOne(OVERLAPPED& ov);

    HANDLE pipe_ = INVALID_HANDLE_VALUE;
    HANDLE stop_ = nullptr;
    Handler handler_;
    std::thread thread_;
    DWORD error_ = 0;
};

// Sends items to the viewer at `name`. NotConnected when nobody listens,
// NotTrusted when the listener is not this user's process in this session.
Reply sendItems(const std::wstring& name, const std::vector<std::wstring>& items, DWORD timeoutMs = 10000);

// The whole "--send-to" run (parseArgs() result): checks the items, sends
// them, shows a dialog when nothing was sent (not with
// JERISLINK_SENDTO_QUIET=1) and returns the process exit code (exitCode()).
int runSendTo(const Args& args);

}  // namespace jl::sendto
