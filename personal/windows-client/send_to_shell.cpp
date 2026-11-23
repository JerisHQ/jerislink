// JerisLinkSendTo.dll: Explorer's "Send to JerisLink" command for the
// Microsoft Store (MSIX) build.
//
// The installer build adds a shortcut to the user's SendTo folder. A packaged
// app cannot do that (its AppData writes are redirected into the package), so
// the Store build declares an IExplorerCommand instead
// (msix/AppxManifest.xml.in: desktop4:FileExplorerContextMenus for files and
// folders, com:SurrogateServer for this DLL). Windows 11 shows it in the first
// level of the right-click menu, Windows 10 1903+ in the classic menu.
//
// Explorer loads the DLL out of process, in dllhost.exe with the package's
// identity. Invoke() does no transfer work itself: it collects the selected
// paths and starts "<package>\Jerislink.exe --send-to <paths>", the same
// short-lived run the installer's shortcut starts (send_to_win.cpp), and
// returns. So Explorer never waits on the pipe or the Mac, and every check,
// limit and dialog stays in one place.

#include "send_to.hpp"

#include <windows.h>
#include <shlwapi.h>
#include <shobjidl.h>

#include <atomic>
#include <new>
#include <string>
#include <vector>

namespace {

// {8C96D31C-0D45-435B-B555-9465096C2E8A}: the Clsid in AppxManifest.xml.in.
constexpr CLSID kClsid = {0x8c96d31c, 0x0d45, 0x435b, {0xb5, 0x55, 0x94, 0x65, 0x09, 0x6c, 0x2e, 0x8a}};
constexpr wchar_t kTitle[] = L"Send to JerisLink";
constexpr int kIconId = 101;  // IDI_JERISLINK in resource.h, inside Jerislink.exe

HMODULE gModule = nullptr;
std::atomic<long> gObjects{0};  // live commands and factories
std::atomic<long> gLocks{0};    // IClassFactory::LockServer

// Jerislink.exe next to this DLL (the package root); "" when unknown.
std::wstring viewerExe() {
    std::wstring path(32768, L'\0');
    const DWORD n = GetModuleFileNameW(gModule, path.data(), static_cast<DWORD>(path.size()));
    if (n == 0 || n >= path.size()) return {};
    path.resize(n);
    const size_t slash = path.find_last_of(L'\\');
    if (slash == std::wstring::npos) return {};
    return path.substr(0, slash + 1) + L"Jerislink.exe";
}

// The file system path of every selected item. An item without one (a zip
// member, a library root) is passed as "?" so the --send-to run refuses the
// whole request with its "couldn't read the selected items" dialog instead of
// quietly sending fewer items than were selected.
std::vector<std::wstring> selectedPaths(IShellItemArray* items) {
    std::vector<std::wstring> paths;
    DWORD count = 0;
    if (!items || FAILED(items->GetCount(&count))) return paths;
    // Over the limit: the run answers "too many" from the count alone.
    if (count > jl::sendto::kMaxItems) return std::vector<std::wstring>(count, L"?");
    paths.reserve(count);
    for (DWORD i = 0; i < count; ++i) {
        IShellItem* item = nullptr;
        PWSTR path = nullptr;
        if (SUCCEEDED(items->GetItemAt(i, &item)) && item && SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &path)) &&
            path) {
            paths.emplace_back(path);
        } else {
            paths.emplace_back(L"?");
        }
        if (path) CoTaskMemFree(path);
        if (item) item->Release();
    }
    return paths;
}

class SendToCommand final : public IExplorerCommand {
public:
    SendToCommand() { ++gObjects; }

    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** out) override {
        if (!out) return E_POINTER;
        if (riid == IID_IUnknown || riid == __uuidof(IExplorerCommand)) {
            *out = static_cast<IExplorerCommand*>(this);
            AddRef();
            return S_OK;
        }
        *out = nullptr;
        return E_NOINTERFACE;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++refs_; }
    IFACEMETHODIMP_(ULONG) Release() override {
        const ULONG left = --refs_;
        if (left == 0) delete this;
        return left;
    }

    // IExplorerCommand
    IFACEMETHODIMP GetTitle(IShellItemArray*, LPWSTR* name) override { return SHStrDupW(kTitle, name); }
    IFACEMETHODIMP GetIcon(IShellItemArray*, LPWSTR* icon) override {
        const std::wstring exe = viewerExe();
        if (exe.empty()) {
            *icon = nullptr;
            return E_FAIL;
        }
        return SHStrDupW((exe + L",-" + std::to_wstring(kIconId)).c_str(), icon);
    }
    IFACEMETHODIMP GetToolTip(IShellItemArray*, LPWSTR* tip) override {
        *tip = nullptr;
        return E_NOTIMPL;
    }
    IFACEMETHODIMP GetCanonicalName(GUID* guid) override {
        *guid = kClsid;
        return S_OK;
    }
    // Shown for files and folders (the manifest's ItemTypes); hidden when the
    // selection has items with no file system path, which cannot be sent.
    IFACEMETHODIMP GetState(IShellItemArray* items, BOOL, EXPCMDSTATE* state) override {
        *state = ECS_ENABLED;
        SFGAOF attrs = 0;
        if (items && items->GetAttributes(SIATTRIBFLAGS_AND, SFGAO_FILESYSTEM, &attrs) == S_FALSE) *state = ECS_HIDDEN;
        return S_OK;
    }
    IFACEMETHODIMP Invoke(IShellItemArray* items, IBindCtx*) override {
        const std::wstring exe = viewerExe();
        if (exe.empty()) return E_FAIL;
        std::wstring line = jl::sendto::commandLine(exe, selectedPaths(items));
        const size_t slash = exe.find_last_of(L'\\');
        const std::wstring dir = exe.substr(0, slash);
        STARTUPINFOW si{sizeof(si)};
        PROCESS_INFORMATION pi{};
        // Suspended until it may take the foreground, so a "nothing was
        // sent" dialog comes up in front of Explorer, not behind it.
        if (!CreateProcessW(exe.c_str(), line.data(), nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, dir.c_str(), &si,
                            &pi)) {
            return HRESULT_FROM_WIN32(GetLastError());
        }
        AllowSetForegroundWindow(pi.dwProcessId);
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return S_OK;
    }
    IFACEMETHODIMP GetFlags(EXPCMDFLAGS* flags) override {
        *flags = ECF_DEFAULT;
        return S_OK;
    }
    IFACEMETHODIMP EnumSubCommands(IEnumExplorerCommand** out) override {
        *out = nullptr;
        return E_NOTIMPL;
    }

private:
    ~SendToCommand() { --gObjects; }
    std::atomic<ULONG> refs_{1};
};

class Factory final : public IClassFactory {
public:
    Factory() { ++gObjects; }

    IFACEMETHODIMP QueryInterface(REFIID riid, void** out) override {
        if (!out) return E_POINTER;
        if (riid == IID_IUnknown || riid == IID_IClassFactory) {
            *out = static_cast<IClassFactory*>(this);
            AddRef();
            return S_OK;
        }
        *out = nullptr;
        return E_NOINTERFACE;
    }
    IFACEMETHODIMP_(ULONG) AddRef() override { return ++refs_; }
    IFACEMETHODIMP_(ULONG) Release() override {
        const ULONG left = --refs_;
        if (left == 0) delete this;
        return left;
    }

    IFACEMETHODIMP CreateInstance(IUnknown* outer, REFIID riid, void** out) override {
        if (!out) return E_POINTER;
        *out = nullptr;
        if (outer) return CLASS_E_NOAGGREGATION;
        auto* cmd = new (std::nothrow) SendToCommand();
        if (!cmd) return E_OUTOFMEMORY;
        const HRESULT hr = cmd->QueryInterface(riid, out);
        cmd->Release();
        return hr;
    }
    IFACEMETHODIMP LockServer(BOOL lock) override {
        if (lock) ++gLocks;
        else --gLocks;
        return S_OK;
    }

private:
    ~Factory() { --gObjects; }
    std::atomic<ULONG> refs_{1};
};

}  // namespace

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        gModule = instance;
        DisableThreadLibraryCalls(instance);
    }
    return TRUE;
}

STDAPI DllGetClassObject(REFCLSID clsid, REFIID riid, void** out) {
    if (!out) return E_POINTER;
    *out = nullptr;
    if (clsid != kClsid) return CLASS_E_CLASSNOTAVAILABLE;
    auto* factory = new (std::nothrow) Factory();
    if (!factory) return E_OUTOFMEMORY;
    const HRESULT hr = factory->QueryInterface(riid, out);
    factory->Release();
    return hr;
}

STDAPI DllCanUnloadNow() { return gObjects.load() == 0 && gLocks.load() == 0 ? S_OK : S_FALSE; }
