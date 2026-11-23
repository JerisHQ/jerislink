// Windows test for JerisLinkSendTo.dll (send_to_shell.cpp), the Store
// build's Explorer command. Loads the real DLL like the COM surrogate does
// (DllGetClassObject, IClassFactory) and checks the title, icon, canonical
// name, flags and state. For Invoke it copies the DLL into a temp folder next
// to a copy of this test exe named Jerislink.exe: started with --send-to,
// that copy writes the arguments it got to a file, so the test sees exactly
// what the real viewer would get (paths with spaces, a folder, a drive root).
#include "send_to.hpp"

#include <windows.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <shellapi.h>

#include <chrono>
#include <cstdio>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

namespace {

int gPass = 0;
int gFail = 0;

void expect(bool cond, const std::string& what) {
    if (cond) { ++gPass; std::printf("PASS %s\n", what.c_str()); }
    else { ++gFail; std::printf("FAIL %s\n", what.c_str()); }
}

constexpr CLSID kClsid = {0x8c96d31c, 0x0d45, 0x435b, {0xb5, 0x55, 0x94, 0x65, 0x09, 0x6c, 0x2e, 0x8a}};
constexpr wchar_t kOutVar[] = L"JERISLINK_SHELL_TEST_OUT";

std::wstring exePath() {
    std::wstring p(32768, L'\0');
    p.resize(GetModuleFileNameW(nullptr, p.data(), static_cast<DWORD>(p.size())));
    return p;
}

std::wstring dirOf(const std::wstring& p) { return p.substr(0, p.find_last_of(L'\\')); }

// Child mode: this exe copied as Jerislink.exe and started by Invoke.
int recordArgs(int argc, wchar_t** argv) {
    wchar_t out[MAX_PATH] = {};
    if (!GetEnvironmentVariableW(kOutVar, out, MAX_PATH)) return 3;
    std::wstring all;
    for (int i = 1; i < argc; ++i) all += std::wstring(argv[i]) + L"\n";
    const std::wstring tmp = std::wstring(out) + L".tmp";
    HANDLE h = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return 4;
    DWORD wrote = 0;
    WriteFile(h, all.data(), static_cast<DWORD>(all.size() * sizeof(wchar_t)), &wrote, nullptr);
    CloseHandle(h);
    return MoveFileExW(tmp.c_str(), out, MOVEFILE_REPLACE_EXISTING) ? 0 : 5;
}

using GetClassObjectFn = HRESULT(STDAPICALLTYPE*)(REFCLSID, REFIID, void**);
using CanUnloadFn = HRESULT(STDAPICALLTYPE*)();

IShellItemArray* arrayOf(const std::vector<std::wstring>& paths) {
    std::vector<PIDLIST_ABSOLUTE> ids;
    for (const auto& p : paths) {
        PIDLIST_ABSOLUTE id = nullptr;
        if (SUCCEEDED(SHParseDisplayName(p.c_str(), nullptr, &id, 0, nullptr))) ids.push_back(id);
    }
    IShellItemArray* arr = nullptr;
    if (ids.size() == paths.size()) {
        std::vector<PCIDLIST_ABSOLUTE> cids(ids.begin(), ids.end());
        SHCreateShellItemArrayFromIDLists(static_cast<UINT>(cids.size()), cids.data(), &arr);
    }
    for (auto id : ids) CoTaskMemFree(id);
    return arr;
}

std::wstring readAll(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return {};
    std::wstring s(GetFileSize(h, nullptr) / sizeof(wchar_t), L'\0');
    DWORD got = 0;
    ReadFile(h, s.data(), static_cast<DWORD>(s.size() * sizeof(wchar_t)), &got, nullptr);
    CloseHandle(h);
    return s;
}

std::wstring waitFor(const std::wstring& path) {
    for (int i = 0; i < 200; ++i) {  // about 10 s
        if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES) return readAll(path);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return {};
}

int runTests(const std::wstring& dllPath) {
    // Stage <temp>\jlshell-<pid>\{JerisLinkSendTo.dll, Jerislink.exe = this test}.
    wchar_t tmp[MAX_PATH] = {};
    GetTempPathW(MAX_PATH, tmp);
    const std::wstring stage = std::wstring(tmp) + L"jlshell-" + std::to_wstring(GetCurrentProcessId());
    CreateDirectoryW(stage.c_str(), nullptr);
    const std::wstring dll = stage + L"\\JerisLinkSendTo.dll";
    const std::wstring fakeViewer = stage + L"\\Jerislink.exe";
    expect(CopyFileW(dllPath.c_str(), dll.c_str(), FALSE) != 0, "stage: DLL copied");
    expect(CopyFileW(exePath().c_str(), fakeViewer.c_str(), FALSE) != 0, "stage: fake Jerislink.exe copied");
    const std::wstring folder = stage + L"\\a folder";
    const std::wstring file = stage + L"\\file with spaces.txt";
    CreateDirectoryW(folder.c_str(), nullptr);
    std::ofstream(file) << "x";
    const std::wstring outFile = stage + L"\\args.txt";
    SetEnvironmentVariableW(kOutVar, outFile.c_str());

    HMODULE mod = LoadLibraryW(dll.c_str());
    expect(mod != nullptr, "dll: loads");
    if (!mod) return 1;
    auto getClass = reinterpret_cast<GetClassObjectFn>(GetProcAddress(mod, "DllGetClassObject"));
    auto canUnload = reinterpret_cast<CanUnloadFn>(GetProcAddress(mod, "DllCanUnloadNow"));
    expect(getClass && canUnload, "dll: exports DllGetClassObject and DllCanUnloadNow");
    if (!getClass || !canUnload) return 1;

    IClassFactory* factory = nullptr;
    const CLSID other = {0x1, 0x2, 0x3, {0, 0, 0, 0, 0, 0, 0, 4}};
    expect(getClass(other, IID_IClassFactory, reinterpret_cast<void**>(&factory)) == CLASS_E_CLASSNOTAVAILABLE &&
               !factory,
           "dll: unknown CLSID refused");
    expect(SUCCEEDED(getClass(kClsid, IID_IClassFactory, reinterpret_cast<void**>(&factory))) && factory,
           "dll: class factory for the manifest CLSID");
    if (!factory) return 1;
    IExplorerCommand* cmd = nullptr;
    expect(SUCCEEDED(factory->CreateInstance(nullptr, __uuidof(IExplorerCommand), reinterpret_cast<void**>(&cmd))) && cmd,
           "factory: creates an IExplorerCommand");
    IUnknown* agg = nullptr;
    expect(factory->CreateInstance(reinterpret_cast<IUnknown*>(factory), IID_IUnknown, reinterpret_cast<void**>(&agg)) ==
               CLASS_E_NOAGGREGATION,
           "factory: no aggregation");
    factory->Release();
    if (!cmd) return 1;
    expect(canUnload() == S_FALSE, "dll: stays loaded while a command is alive");

    LPWSTR text = nullptr;
    expect(SUCCEEDED(cmd->GetTitle(nullptr, &text)) && text && std::wstring(text) == L"Send to JerisLink",
           "command: title is Send to JerisLink");
    CoTaskMemFree(text);
    text = nullptr;
    expect(SUCCEEDED(cmd->GetIcon(nullptr, &text)) && text && std::wstring(text) == fakeViewer + L",-101",
           "command: icon is Jerislink.exe's IDI_JERISLINK next to the DLL");
    CoTaskMemFree(text);
    GUID g{};
    expect(SUCCEEDED(cmd->GetCanonicalName(&g)) && g == kClsid, "command: canonical name is the CLSID");
    EXPCMDFLAGS flags = 1234;
    expect(SUCCEEDED(cmd->GetFlags(&flags)) && flags == ECF_DEFAULT, "command: plain command, no submenu");
    IEnumExplorerCommand* sub = nullptr;
    expect(cmd->EnumSubCommands(&sub) == E_NOTIMPL && !sub, "command: no subcommands");

    IShellItemArray* items = arrayOf({file, folder});
    expect(items != nullptr, "items: shell item array for a file and a folder");
    EXPCMDSTATE state = ECS_HIDDEN;
    expect(items && SUCCEEDED(cmd->GetState(items, FALSE, &state)) && state == ECS_ENABLED,
           "state: shown for files and folders");
    IShellItemArray* virt = nullptr;
    PIDLIST_ABSOLUTE ctl = nullptr;
    if (SUCCEEDED(SHGetKnownFolderIDList(FOLDERID_ControlPanelFolder, 0, nullptr, &ctl))) {
        PCIDLIST_ABSOLUTE c = ctl;
        SHCreateShellItemArrayFromIDLists(1, &c, &virt);
        CoTaskMemFree(ctl);
    }
    state = ECS_ENABLED;
    expect(virt && SUCCEEDED(cmd->GetState(virt, FALSE, &state)) && state == ECS_HIDDEN,
           "state: hidden for an item with no file system path (Control Panel)");

    // Invoke starts <dll dir>\Jerislink.exe --send-to <paths> and returns.
    const auto t0 = std::chrono::steady_clock::now();
    const HRESULT hr = items ? cmd->Invoke(items, nullptr) : E_FAIL;
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    expect(SUCCEEDED(hr) && ms < 2000, "invoke: returns at once");
    const std::wstring got = waitFor(outFile);
    expect(got == std::wstring(jl::sendto::kFlag) + L"\n" + file + L"\n" + folder + L"\n",
           "invoke: Jerislink.exe gets --send-to and both paths exactly");
    DeleteFileW(outFile.c_str());

    if (virt) {
        expect(SUCCEEDED(cmd->Invoke(virt, nullptr)), "invoke: item without a path still starts the run");
        expect(waitFor(outFile) == std::wstring(jl::sendto::kFlag) + L"\n?\n",
               "invoke: item without a path passed as ? (the run refuses it with a dialog)");
        DeleteFileW(outFile.c_str());
        virt->Release();
    }
    if (items) items->Release();
    cmd->Release();
    expect(canUnload() == S_OK, "dll: can unload once every object is released");
    FreeLibrary(mod);

    DeleteFileW(fakeViewer.c_str());
    DeleteFileW(dll.c_str());
    DeleteFileW(file.c_str());
    RemoveDirectoryW(folder.c_str());
    RemoveDirectoryW(stage.c_str());
    return 0;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc >= 2 && std::wstring(argv[1]) == jl::sendto::kFlag) return recordArgs(argc, argv);
    if (argc < 2) {
        std::printf("usage: JerislinkSendToShellTest <path to JerisLinkSendTo.dll>\n");
        return 2;
    }
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    wchar_t full[MAX_PATH] = {};
    GetFullPathNameW(argv[1], MAX_PATH, full, nullptr);
    runTests(full);
    CoUninitialize();
    std::printf("send to shell: %d passed, %d failed\n", gPass, gFail);
    return gFail == 0 ? 0 : 1;
}
