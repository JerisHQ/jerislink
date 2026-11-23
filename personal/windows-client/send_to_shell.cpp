// JerisLinkSendTo.dll: Explorer's "Send to JerisLink" command for the
// Microsoft Store (MSIX) build.
//
// The installer build adds a shortcut to the user's SendTo folder. A packaged
// app cannot do that (its AppData writes are redirected into the package), so
// the Store build declares an IExplorerCommand instead
// (msix/AppxManifest.xml.in: desktop4:FileExplorerContextMenus for files and
// folders, com:SurrogateServer for this DLL). Windows 11 shows it in the first
// level of the right-click menu, Windows 10 1809+ in the classic menu.
//
// Explorer loads the DLL out of process, in dllhost.exe with the package's
// identity. Invoke() does no transfer work itself: it collects the selected
// paths and starts "<package>\Jerislink.exe --send-to <paths>", the same
// short-lived run the installer's shortcut starts (send_to_win.cpp), and
// returns. So Explorer never waits on the pipe or the Mac, and every check,
// limit and dialog stays in one place.
//
// No C++ exception leaves this DLL: every method Explorer or COM calls runs
// inside guarded(), which turns std::bad_alloc into E_OUTOFMEMORY and any
// other exception into E_UNEXPECTED, and everything it holds (shell items,
// strings, process handles) is released by RAII on the way out. A throw
// across the COM boundary would end dllhost.exe.

#include "send_to.hpp"

#include <windows.h>
#include <shlwapi.h>
#include <shobjidl.h>

#include <atomic>
#include <memory>
#include <new>
#include <string>
#include <vector>

namespace {

// {8C96D31C-0D45-435B-B555-9465096C2E8A}: the Clsid in AppxManifest.xml.in.
constexpr CLSID kClsid = {0x8c96d31c, 0x0d45, 0x435b, {0xb5, 0x55, 0x94, 0x65, 0x09, 0x6c, 0x2e, 0x8a}};
constexpr wchar_t kTitle[] = L"Send to JerisLink";
constexpr int kIconId = 101;  // IDI_JERISLINK in resource.h, inside Jerislink.exe

HMODULE gModule = nullptr;

// Runs one COM method body; no exception gets out.
template <class F>
HRESULT guarded(F&& body) noexcept {
    try {
        return body();
    } catch (const std::bad_alloc&) {
        return E_OUTOFMEMORY;
    } catch (...) {
        return E_UNEXPECTED;
    }
}

struct ReleaseUnknown {
    void operator()(IUnknown* p) const { p->Release(); }
};
using ShellItem = std::unique_ptr<IShellItem, ReleaseUnknown>;

struct FreeCoTask {
    void operator()(wchar_t* p) const { CoTaskMemFree(p); }
};
using CoTaskString = std::unique_ptr<wchar_t, FreeCoTask>;

struct CloseHandles {
    void operator()(HANDLE h) const { CloseHandle(h); }
};
using Handle = std::unique_ptr<void, CloseHandles>;
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

struct Selection {
    bool tooMany = false;            // over kMaxItems: only the count was read
    std::vector<std::wstring> paths;
};

// The file system path of every selected item. An item without one (a zip
// member, a library root) is passed as "?" so the --send-to run refuses the
// whole request with its "couldn't read the selected items" dialog instead of
// quietly sending fewer items than were selected. Over kMaxItems nothing is
// read or allocated per item: the run shows "too many" from the flag alone.
Selection selectedPaths(IShellItemArray* items) {
    Selection sel;
    DWORD count = 0;
    if (!items || FAILED(items->GetCount(&count))) return sel;
    if (count > jl::sendto::kMaxItems) {
        sel.tooMany = true;
        return sel;
    }
    sel.paths.reserve(count);
    for (DWORD i = 0; i < count; ++i) {
        IShellItem* raw = nullptr;
        const HRESULT got = items->GetItemAt(i, &raw);
        ShellItem item(raw);
        PWSTR rawPath = nullptr;
        if (SUCCEEDED(got) && item && SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &rawPath)) && rawPath) {
            CoTaskString path(rawPath);
            sel.paths.emplace_back(path.get());
        } else {
            if (rawPath) CoTaskMemFree(rawPath);
            sel.paths.emplace_back(L"?");
        }
    }
    return sel;
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
    IFACEMETHODIMP GetTitle(IShellItemArray*, LPWSTR* name) override {
        if (!name) return E_POINTER;
        *name = nullptr;
        return SHStrDupW(kTitle, name);
    }
    IFACEMETHODIMP GetIcon(IShellItemArray*, LPWSTR* icon) override {
        if (!icon) return E_POINTER;
        *icon = nullptr;
        return guarded([&]() -> HRESULT {
            const std::wstring exe = viewerExe();
            if (exe.empty()) return E_FAIL;
            return SHStrDupW((exe + L",-" + std::to_wstring(kIconId)).c_str(), icon);
        });
    }
    IFACEMETHODIMP GetToolTip(IShellItemArray*, LPWSTR* tip) override {
        if (!tip) return E_POINTER;
        *tip = nullptr;
        return E_NOTIMPL;
    }
    IFACEMETHODIMP GetCanonicalName(GUID* guid) override {
        if (!guid) return E_POINTER;
        *guid = kClsid;
        return S_OK;
    }
    // Shown for files and folders (the manifest's ItemTypes); hidden when the
    // selection has items with no file system path, which cannot be sent.
    IFACEMETHODIMP GetState(IShellItemArray* items, BOOL, EXPCMDSTATE* state) override {
        if (!state) return E_POINTER;
        *state = ECS_ENABLED;
        return guarded([&]() -> HRESULT {
            SFGAOF attrs = 0;
            if (items && items->GetAttributes(SIATTRIBFLAGS_AND, SFGAO_FILESYSTEM, &attrs) == S_FALSE) *state = ECS_HIDDEN;
            return S_OK;
        });
    }
    IFACEMETHODIMP Invoke(IShellItemArray* items, IBindCtx*) override {
        return guarded([&]() -> HRESULT {
            const std::wstring exe = viewerExe();
            if (exe.empty()) return E_FAIL;
            const Selection sel = selectedPaths(items);
            std::wstring line =
                sel.tooMany ? jl::sendto::tooManyCommandLine(exe) : jl::sendto::commandLine(exe, sel.paths);
            const size_t slash = exe.find_last_of(L'\\');
            const std::wstring dir = exe.substr(0, slash);
            STARTUPINFOW si{sizeof(si)};
            PROCESS_INFORMATION pi{};
            // Suspended until it may take the foreground, so a "nothing was
            // sent" dialog comes up in front of Explorer, not behind it.
            if (!CreateProcessW(exe.c_str(), line.data(), nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr,
                                dir.c_str(), &si, &pi)) {
                return HRESULT_FROM_WIN32(GetLastError());
            }
            const Handle process(pi.hProcess), thread(pi.hThread);
            AllowSetForegroundWindow(pi.dwProcessId);
            ResumeThread(pi.hThread);
            return S_OK;
        });
    }
    IFACEMETHODIMP GetFlags(EXPCMDFLAGS* flags) override {
        if (!flags) return E_POINTER;
        *flags = ECF_DEFAULT;
        return S_OK;
    }
    IFACEMETHODIMP EnumSubCommands(IEnumExplorerCommand** out) override {
        if (!out) return E_POINTER;
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
        return guarded([&]() -> HRESULT {
            std::unique_ptr<SendToCommand, ReleaseUnknown> cmd(new SendToCommand());
            return cmd->QueryInterface(riid, out);
        });
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
    return guarded([&]() -> HRESULT {
        std::unique_ptr<Factory, ReleaseUnknown> factory(new Factory());
        return factory->QueryInterface(riid, out);
    });
}

STDAPI DllCanUnloadNow() { return gObjects.load() == 0 && gLocks.load() == 0 ? S_OK : S_FALSE; }
