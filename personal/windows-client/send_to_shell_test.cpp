// Windows test for JerisLinkSendTo.dll (send_to_shell.cpp), the Store
// build's Explorer command. Loads the real DLL like the COM surrogate does
// (DllGetClassObject, IClassFactory) and checks the title, icon, canonical
// name, flags and state. For Invoke it copies the DLL into a temp folder next
// to a copy of this test exe named Jerislink.exe: started with --send-to,
// that copy writes the arguments it got to a file, so the test sees exactly
// what the real viewer would get (paths with spaces, a folder, a drive root).
// Fake selections check that over 1,000 items go straight to
// --send-to-too-many and that C++ exceptions become HRESULTs.
#include "send_to.hpp"

#include <windows.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <shellapi.h>

#include <chrono>
#include <cstdio>
#include <fstream>
#include <new>
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

// A selection Explorer never makes, to drive the DLL's edge cases: a huge
// item count, or a shell that throws a C++ exception out of GetItemAt or
// GetAttributes. The DLL must not allocate per counted item, and must turn
// any exception into an HRESULT instead of letting it end the process.
class FakeArray final : public IShellItemArray {
public:
    enum class Mode { Count, ThrowBadAlloc, ThrowOther };
    FakeArray(Mode mode, DWORD count) : mode_(mode), count_(count) {}
    long itemCalls = 0;

    IFACEMETHODIMP QueryInterface(REFIID riid, void** out) override {
        if (!out) return E_POINTER;
        if (riid == IID_IUnknown || riid == __uuidof(IShellItemArray)) {
            *out = static_cast<IShellItemArray*>(this);
            AddRef();
            return S_OK;
        }
        *out = nullptr;
        return E_NOINTERFACE;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++refs_; }
    IFACEMETHODIMP_(ULONG) Release() override { return --refs_; }  // lives on the test's stack
    IFACEMETHODIMP BindToHandler(IBindCtx*, REFGUID, REFIID, void** out) override {
        *out = nullptr;
        return E_NOTIMPL;
    }
    IFACEMETHODIMP GetPropertyStore(GETPROPERTYSTOREFLAGS, REFIID, void** out) override {
        *out = nullptr;
        return E_NOTIMPL;
    }
    IFACEMETHODIMP GetPropertyDescriptionList(REFPROPERTYKEY, REFIID, void** out) override {
        *out = nullptr;
        return E_NOTIMPL;
    }
    IFACEMETHODIMP GetAttributes(SIATTRIBFLAGS, SFGAOF, SFGAOF* attrs) override {
        throwIfAsked();
        *attrs = SFGAO_FILESYSTEM;
        return S_OK;
    }
    IFACEMETHODIMP GetCount(DWORD* n) override {
        *n = count_;
        return S_OK;
    }
    IFACEMETHODIMP GetItemAt(DWORD, IShellItem** item) override {
        ++itemCalls;
        *item = nullptr;
        throwIfAsked();
        return E_FAIL;  // no path: the DLL passes "?"
    }
    IFACEMETHODIMP EnumItems(IEnumShellItems** out) override {
        *out = nullptr;
        return E_NOTIMPL;
    }

private:
    void throwIfAsked() {
        if (mode_ == Mode::ThrowBadAlloc) throw std::bad_alloc();
        if (mode_ == Mode::ThrowOther) throw 42;
    }
    Mode mode_;
    DWORD count_;
    ULONG refs_ = 1;
};

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
    std::wstring stage = std::wstring(tmp) + L"jlshell-" + std::to_wstring(GetCurrentProcessId());
    CreateDirectoryW(stage.c_str(), nullptr);
    // The temp path can be 8.3 (C:\Users\RUNNER~1\...); the shell items give
    // the long path, so compare against the long form.
    wchar_t longStage[MAX_PATH] = {};
    const DWORD longLen = GetLongPathNameW(stage.c_str(), longStage, MAX_PATH);
    if (longLen > 0 && longLen < MAX_PATH) stage = longStage;
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

    // Over 1,000 items: straight to --send-to-too-many from the count alone,
    // without reading an item or sizing anything to the count.
    for (const DWORD count : {DWORD{1001}, DWORD{0xFFFFFFFF}}) {
        FakeArray many(FakeArray::Mode::Count, count);
        const std::string n = std::to_string(count);
        expect(SUCCEEDED(cmd->Invoke(&many, nullptr)), "too many: invoke with " + n + " items succeeds");
        expect(waitFor(outFile) == std::wstring(jl::sendto::kTooManyFlag) + L"\n",
               "too many: " + n + " items start --send-to-too-many only");
        expect(many.itemCalls == 0, "too many: no item read for " + n + " items");
        DeleteFileW(outFile.c_str());
    }
    {
        FakeArray limit(FakeArray::Mode::Count, 1000);
        expect(SUCCEEDED(cmd->Invoke(&limit, nullptr)), "limit: invoke with 1000 items succeeds");
        const std::wstring got1000 = waitFor(outFile);
        size_t lines = 0;
        for (wchar_t c : got1000) lines += c == L'\n';
        expect(got1000.rfind(std::wstring(jl::sendto::kFlag) + L"\n", 0) == 0 && lines == 1001 && limit.itemCalls == 1000,
               "limit: 1000 items are each read and passed (as ? without a path)");
        DeleteFileW(outFile.c_str());
    }

    // C++ exceptions from the shell stop at the COM boundary as HRESULTs.
    {
        FakeArray oom(FakeArray::Mode::ThrowBadAlloc, 2);
        expect(cmd->Invoke(&oom, nullptr) == E_OUTOFMEMORY, "exceptions: bad_alloc in Invoke becomes E_OUTOFMEMORY");
        FakeArray odd(FakeArray::Mode::ThrowOther, 2);
        expect(cmd->Invoke(&odd, nullptr) == E_UNEXPECTED, "exceptions: other exception in Invoke becomes E_UNEXPECTED");
        EXPCMDSTATE st = ECS_HIDDEN;
        expect(cmd->GetState(&odd, FALSE, &st) == E_UNEXPECTED, "exceptions: exception in GetState becomes E_UNEXPECTED");
        expect(cmd->GetState(&oom, FALSE, &st) == E_OUTOFMEMORY, "exceptions: bad_alloc in GetState becomes E_OUTOFMEMORY");
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        expect(GetFileAttributesW(outFile.c_str()) == INVALID_FILE_ATTRIBUTES, "exceptions: no run started after a throw");
        LPWSTR t2 = nullptr;
        expect(SUCCEEDED(cmd->GetTitle(nullptr, &t2)) && t2, "exceptions: command still works afterwards");
        CoTaskMemFree(t2);
    }
    expect(cmd->GetTitle(nullptr, nullptr) == E_POINTER && cmd->GetState(nullptr, FALSE, nullptr) == E_POINTER,
           "command: null out pointers refused");
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
    if (argc >= 2 && (std::wstring(argv[1]) == jl::sendto::kFlag || std::wstring(argv[1]) == jl::sendto::kTooManyFlag)) {
        return recordArgs(argc, argv);
    }
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
