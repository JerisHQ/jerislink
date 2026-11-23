// Windows test for the F5a Send to pipe (send_to_win.cpp): real named pipe,
// real client. Round trip of paths (non-ASCII, folders), replies passed
// through, first-instance ownership, this-user-only DACL, corrupt and idle
// clients, no listener, the quiet "--send-to" exit code, and the Store
// Explorer command's command line through the real CommandLineToArgvW.
#include "send_to_win.hpp"

#include <aclapi.h>
#include <shellapi.h>
#include <sddl.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace jl::sendto;

namespace {

int gPass = 0;
int gFail = 0;

void expect(bool cond, const std::string& what) {
    if (cond) { ++gPass; std::printf("PASS %s\n", what.c_str()); }
    else { ++gFail; std::printf("FAIL %s\n", what.c_str()); }
    std::fflush(stdout);
}

std::wstring testPipe(const wchar_t* tag) {
    return pipeName(currentUserSid() + L".test." + tag, GetCurrentProcessId());
}

// Opens the test pipe, waiting while the single instance serves someone else.
HANDLE openPipe(const std::wstring& name) {
    for (int i = 0; i < 50; ++i) {
        HANDLE h = CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE || GetLastError() != ERROR_PIPE_BUSY) return h;
        WaitNamedPipeW(name.c_str(), 200);
    }
    return INVALID_HANDLE_VALUE;
}

// A raw client that writes `bytes` (or nothing) and returns the reply bytes.
std::vector<uint8_t> rawExchange(const std::wstring& name, const std::vector<uint8_t>& bytes, bool send) {
    HANDLE h = openPipe(name);
    if (h == INVALID_HANDLE_VALUE) return {};
    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(h, &mode, nullptr, nullptr);
    std::vector<uint8_t> reply(16);
    DWORD n = 0;
    if (send) {
        WriteFile(h, bytes.data(), static_cast<DWORD>(bytes.size()), &n, nullptr);
        if (!ReadFile(h, reply.data(), static_cast<DWORD>(reply.size()), &n, nullptr)) n = 0;
    } else {
        Sleep(4000);  // connect and say nothing for longer than the server waits
        n = 0;
    }
    CloseHandle(h);
    reply.resize(n);
    return reply;
}

void roundTrip() {
    const std::wstring name = testPipe(L"rt");
    std::mutex m;
    std::vector<std::wstring> got;
    std::atomic<int> calls{0};
    std::atomic<Reply> answer{Reply::Started};
    Server server;
    const bool started = server.start(name, [&](std::vector<std::wstring>&& items) {
        std::lock_guard<std::mutex> lock(m);
        got = std::move(items);
        ++calls;
        return answer.load();
    });
    expect(started && server.running(), "server: listening");

    const std::vector<std::wstring> items = {L"C:\\Users\\me\\a b.txt", L"C:\\\x4E2D\x6587\\\x5831\x544A.pdf",
                                             L"D:\\Photos 2026", L"\\\\nas\\share\\x.bin"};
    expect(sendItems(name, items) == Reply::Started, "client: viewer answers started");
    {
        std::lock_guard<std::mutex> lock(m);
        expect(got == items, "server: exact paths arrive (spaces, CJK, folder, UNC)");
    }
    answer = Reply::Busy;
    expect(sendItems(name, {L"C:\\a"}) == Reply::Busy, "client: viewer's refusal comes back (busy)");
    answer = Reply::NotConnected;
    expect(sendItems(name, {L"C:\\a"}) == Reply::NotConnected, "client: viewer's refusal comes back (no session)");
    expect(sendItems(name, {}) == Reply::NothingSelected && calls == 3, "client: nothing selected never reaches the viewer");
    expect(sendItems(name, {L"relative.txt"}) == Reply::BadRequest && calls == 3,
           "client: a relative path never reaches the viewer");

    Server second;
    const bool secondStarted = second.start(name, [](std::vector<std::wstring>&&) { return Reply::Started; });
    expect(!secondStarted, "server: a second listener cannot take the name (first instance)");

    // Only this user, full access, nothing inherited.
    HANDLE h = openPipe(name);
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR sd = nullptr;
    bool daclOk = false;
    if (h != INVALID_HANDLE_VALUE &&
        GetSecurityInfo(h, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &dacl, nullptr, &sd) ==
            ERROR_SUCCESS) {
        ACL_SIZE_INFORMATION info{};
        LPWSTR text = nullptr;
        if (dacl && GetAclInformation(dacl, &info, sizeof(info), AclSizeInformation) &&
            ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &text,
                                                                 nullptr)) {
            const std::wstring s = text;
            // Compare the ACE's own SID (SDDL may print well-known SIDs as aliases).
            std::wstring aceSid;
            void* ace = nullptr;
            if (info.AceCount == 1 && GetAce(dacl, 0, &ace) &&
                static_cast<ACE_HEADER*>(ace)->AceType == ACCESS_ALLOWED_ACE_TYPE) {
                LPWSTR sidText = nullptr;
                if (ConvertSidToStringSidW(&static_cast<ACCESS_ALLOWED_ACE*>(ace)->SidStart, &sidText)) {
                    aceSid = sidText;
                    LocalFree(sidText);
                }
            }
            daclOk = info.AceCount == 1 && aceSid == currentUserSid() && s.rfind(L"D:P", 0) == 0;
            std::printf("dacl aces=%lu protected=%d sddl=%ls ace_sid_is_user=%d\n", info.AceCount,
                        s.rfind(L"D:P", 0) == 0 ? 1 : 0, s.c_str(), aceSid == currentUserSid() ? 1 : 0);
            LocalFree(text);
        }
        LocalFree(sd);
    }
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    expect(daclOk, "server: pipe DACL is protected and has one ACE for this user");

    // Corrupt bytes: refused without calling the viewer.
    const int before = calls;
    const auto reply = rawExchange(name, {'J', 'L', 'S', '1', 1, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF}, true);
    Reply r = Reply::Started;
    expect(decodeReply(reply.data(), reply.size(), r) && r == Reply::BadRequest && calls == before,
           "server: corrupt request gets bad_request, viewer not called");

    // A client that connects and never writes is dropped; the next one is served.
    std::thread idle([&] { rawExchange(name, {}, false); });
    Sleep(200);
    const auto t0 = std::chrono::steady_clock::now();
    answer = Reply::Started;
    const Reply afterIdle = sendItems(name, {L"C:\\a"}, 10000);
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    idle.join();
    std::printf("after idle client: %lld ms\n", static_cast<long long>(ms));
    expect(afterIdle == Reply::Started && ms < 9000, "server: an idle client cannot block the next one");

    const auto stop0 = std::chrono::steady_clock::now();
    server.stop();
    const auto stopMs =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - stop0).count();
    expect(!server.running() && stopMs < 2000, "server: stops promptly");
    expect(sendItems(name, {L"C:\\a"}, 2000) == Reply::NotConnected, "client: no listener means not connected");

    Server again;
    expect(again.start(name, [](std::vector<std::wstring>&&) { return Reply::Started; }),
           "server: the name is free again after stop");
    again.stop();
}

void slowViewer() {
    // The viewer handler is bounded by its own wait; the client's timeout
    // still holds if a server never answers.
    const std::wstring name = testPipe(L"slow");
    Server server;
    server.start(name, [](std::vector<std::wstring>&&) {
        Sleep(2500);
        return Reply::Started;
    });
    const auto t0 = std::chrono::steady_clock::now();
    const Reply r = sendItems(name, {L"C:\\a"}, 1000);
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    expect(r == Reply::Failed && ms < 2000, "client: gives up after its timeout");
    server.stop();
}

void quietExit() {
    SetEnvironmentVariableW(L"JERISLINK_SENDTO_QUIET", L"1");
    expect(runSendTo(parseArgs({L"x.exe", kFlag, L"C:\\Windows\\win.ini"})) == exitCode(Reply::NotConnected),
           "--send-to with no viewer: exit 21, no dialog");
    expect(runSendTo(parseArgs({L"x.exe", kFlag})) == exitCode(Reply::NothingSelected), "--send-to with nothing: exit 27");
    expect(runSendTo(parseArgs({L"x.exe", kTooManyFlag})) == exitCode(Reply::TooMany),
           "--send-to-too-many: exit 28 without opening the pipe");
    SetEnvironmentVariableW(L"JERISLINK_SENDTO_QUIET", nullptr);
}

// The Store build's Explorer command builds its command line with
// commandLine(); the real CommandLineToArgvW must give every path back
// exactly (spaces, drive roots ending in a backslash, UNC, non-ASCII).
void commandLineRoundTrip() {
    const std::wstring exe = L"C:\\Program Files\\WindowsApps\\jerisHQ.JerisLink_0.3.1.0_x64__1cbzj2979sfxw\\Jerislink.exe";
    const std::vector<std::wstring> items = {L"C:\\Users\\me\\a b.txt", L"D:\\", L"\\\\nas\\share\\dir\\",
                                             L"C:\\\x4E2D\x6587\\\x5831\x544A.pdf", L"C:\\x\\\\\\y", L"C:\\ends with space \\"};
    const std::wstring line = commandLine(exe, items);
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(line.c_str(), &argc);
    std::vector<std::wstring> got;
    for (int i = 0; argv && i < argc; ++i) got.emplace_back(argv[i]);
    if (argv) LocalFree(argv);
    const Args a = parseArgs(got);
    expect(got.size() == items.size() + 2 && got[0] == exe, "cmdline: exe path with spaces comes back as argv[0]");
    expect(a.sendTo && !a.tooMany && a.items == items, "cmdline: every path round trips through CommandLineToArgvW");

    const std::vector<std::wstring> many(800, L"C:\\Users\\someone\\Documents\\a fairly long folder name\\file.bin");
    const std::wstring tooLong = commandLine(exe, many);
    argv = CommandLineToArgvW(tooLong.c_str(), &argc);
    got.clear();
    for (int i = 0; argv && i < argc; ++i) got.emplace_back(argv[i]);
    if (argv) LocalFree(argv);
    expect(tooLong.size() <= kMaxCommandLineChars && parseArgs(got).tooMany,
           "cmdline: a selection over the CreateProcess limit becomes --send-to-too-many");
}

}  // namespace

int main() {
    expect(!currentUserSid().empty() && currentUserSid().rfind(L"S-1-", 0) == 0, "sid: current user SID");
    expect(currentPipeName().rfind(L"\\\\.\\pipe\\JerisLink.SendTo.S-1-", 0) == 0, "pipe: real name");
    roundTrip();
    slowViewer();
    quietExit();
    commandLineRoundTrip();
    std::printf("send to pipe: %d passed, %d failed\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
