#include <windows.h>
#include <dwmapi.h>
#include <shlobj.h>
#include <shobjidl.h>
#include <shellapi.h>

#include <filesystem>
#include <string>

#include "resource.h"

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "dwmapi.lib")

namespace fs = std::filesystem;

static constexpr int IDC_DESKTOP_SHORTCUT = 1001;
static constexpr int IDC_INSTALL = 1002;
static constexpr int IDC_CANCEL = 1003;
static constexpr int IDC_STATUS = 1004;

static HFONT gBodyFont = nullptr;
static HFONT gTitleFont = nullptr;
static HBRUSH gWhiteBrush = nullptr;
static HWND gDesktopCheck = nullptr;
static HWND gInstallButton = nullptr;
static HWND gCancelButton = nullptr;
static HWND gStatus = nullptr;

static std::wstring getKnownFolder(REFKNOWNFOLDERID id) {
    PWSTR p = nullptr;
    HRESULT hr = SHGetKnownFolderPath(id, KF_FLAG_CREATE, nullptr, &p);
    if (FAILED(hr) || !p) return L"";
    std::wstring out(p);
    CoTaskMemFree(p);
    return out;
}

static bool createShortcut(const fs::path& linkPath, const fs::path& target,
                           const fs::path& workingDir, const fs::path& iconPath,
                           std::wstring& error) {
    IShellLinkW* link = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_IShellLinkW, reinterpret_cast<void**>(&link));
    if (FAILED(hr) || !link) {
        error = L"Could not create a Windows shortcut.";
        return false;
    }
    link->SetPath(target.c_str());
    link->SetWorkingDirectory(workingDir.c_str());
    link->SetIconLocation(iconPath.c_str(), 0);

    IPersistFile* persist = nullptr;
    hr = link->QueryInterface(IID_IPersistFile, reinterpret_cast<void**>(&persist));
    if (SUCCEEDED(hr) && persist) {
        std::error_code ec;
        fs::create_directories(linkPath.parent_path(), ec);
        hr = persist->Save(linkPath.c_str(), TRUE);
        persist->Release();
    }
    link->Release();
    if (FAILED(hr)) {
        error = L"Could not save a Windows shortcut.";
        return false;
    }
    return true;
}

static bool setRegString(HKEY key, const wchar_t* name, const std::wstring& value) {
    const BYTE* data = reinterpret_cast<const BYTE*>(value.c_str());
    const DWORD bytes = static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t));
    return RegSetValueExW(key, name, 0, REG_SZ, data, bytes) == ERROR_SUCCESS;
}

static bool registerUninstaller(const fs::path& installDir, std::wstring& error) {
    HKEY key = nullptr;
    const wchar_t* subkey = L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Jerislink";
    if (RegCreateKeyExW(HKEY_CURRENT_USER, subkey, 0, nullptr, 0, KEY_SET_VALUE,
                        nullptr, &key, nullptr) != ERROR_SUCCESS) {
        error = L"Could not register Jerislink in Windows installed apps.";
        return false;
    }

    const fs::path exe = installDir / L"Jerislink.exe";
    const fs::path uninstall = installDir / L"uninstall.cmd";
    const std::wstring uninstallCommand = L"cmd.exe /c \"\"" + uninstall.wstring() + L"\"\"";
    DWORD one = 1;
    bool ok = true;
    ok = setRegString(key, L"DisplayName", L"Jerislink") && ok;
    ok = setRegString(key, L"DisplayVersion", L"0.0.9.5") && ok;
    ok = setRegString(key, L"Publisher", L"Jeris") && ok;
    ok = setRegString(key, L"InstallLocation", installDir.wstring()) && ok;
    ok = setRegString(key, L"DisplayIcon", exe.wstring()) && ok;
    ok = setRegString(key, L"UninstallString", uninstallCommand) && ok;
    ok = (RegSetValueExW(key, L"NoModify", 0, REG_DWORD,
                         reinterpret_cast<const BYTE*>(&one), sizeof(one)) == ERROR_SUCCESS) && ok;
    ok = (RegSetValueExW(key, L"NoRepair", 0, REG_DWORD,
                         reinterpret_cast<const BYTE*>(&one), sizeof(one)) == ERROR_SUCCESS) && ok;
    RegCloseKey(key);
    if (!ok) error = L"Could not finish Windows installed-app registration.";
    return ok;
}

static bool writeResourceToFile(int resourceId, const fs::path& destination,
                                std::wstring& error) {
    HMODULE module = GetModuleHandleW(nullptr);
    HRSRC resource = FindResourceW(module, MAKEINTRESOURCEW(resourceId), RT_RCDATA);
    if (!resource) {
        error = L"Installer payload resource is missing.";
        return false;
    }
    HGLOBAL loaded = LoadResource(module, resource);
    const DWORD size = SizeofResource(module, resource);
    const void* data = loaded ? LockResource(loaded) : nullptr;
    if (!data || size == 0) {
        error = L"Installer payload resource could not be loaded.";
        return false;
    }

    HANDLE file = CreateFileW(destination.c_str(), GENERIC_WRITE, 0, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        error = L"Could not create " + destination.filename().wstring() + L".";
        return false;
    }
    DWORD written = 0;
    const BOOL ok = WriteFile(file, data, size, &written, nullptr);
    CloseHandle(file);
    if (!ok || written != size) {
        error = L"Could not write " + destination.filename().wstring() + L".";
        return false;
    }
    return true;
}

static bool copyPayload(const fs::path& installDir, std::wstring& error) {
    std::error_code ec;
    fs::create_directories(installDir, ec);
    if (ec) {
        error = L"Could not create the Jerislink installation folder.";
        return false;
    }
    if (!writeResourceToFile(IDR_JERISLINK_EXE, installDir / L"Jerislink.exe", error)) return false;
    if (!writeResourceToFile(IDR_README_TXT, installDir / L"README.txt", error)) return false;
    if (!writeResourceToFile(IDR_UNINSTALL_CMD, installDir / L"uninstall.cmd", error)) return false;
    return true;
}

static bool installJerislink(bool desktopShortcut, std::wstring& error) {
    const std::wstring localAppData = getKnownFolder(FOLDERID_LocalAppData);
    const std::wstring programs = getKnownFolder(FOLDERID_Programs);
    const std::wstring desktop = getKnownFolder(FOLDERID_Desktop);
    if (localAppData.empty() || programs.empty() || desktop.empty()) {
        error = L"Windows folder locations could not be resolved.";
        return false;
    }

    const fs::path installDir = fs::path(localAppData) / L"Programs" / L"Jeris" / L"Jerislink";
    const fs::path exe = installDir / L"Jerislink.exe";
    const fs::path uninstall = installDir / L"uninstall.cmd";
    if (!copyPayload(installDir, error)) return false;

    if (!createShortcut(fs::path(programs) / L"Jerislink.lnk", exe, installDir, exe, error)) return false;
    if (!createShortcut(fs::path(programs) / L"Uninstall Jerislink.lnk", uninstall, installDir, exe, error)) return false;

    const fs::path desktopLink = fs::path(desktop) / L"Jerislink.lnk";
    if (desktopShortcut) {
        if (!createShortcut(desktopLink, exe, installDir, exe, error)) return false;
    } else {
        std::error_code ec;
        fs::remove(desktopLink, ec);
    }

    return registerUninstaller(installDir, error);
}

static void applyModernChrome(HWND hwnd) {
    BOOL dark = TRUE;
    (void)DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark, sizeof(dark));
    const COLORREF caption = RGB(12, 20, 36);
    const COLORREF border = RGB(43, 68, 99);
    const COLORREF text = RGB(244, 248, 255);
    (void)DwmSetWindowAttribute(hwnd, DWMWA_CAPTION_COLOR, &caption, sizeof(caption));
    (void)DwmSetWindowAttribute(hwnd, DWMWA_BORDER_COLOR, &border, sizeof(border));
    (void)DwmSetWindowAttribute(hwnd, DWMWA_TEXT_COLOR, &text, sizeof(text));
    DWM_WINDOW_CORNER_PREFERENCE corners = DWMWCP_ROUND;
    (void)DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &corners, sizeof(corners));
}

static HWND makeLabel(HWND parent, const wchar_t* text, int x, int y, int w, int h, HFONT font) {
    HWND ctl = CreateWindowExW(0, L"STATIC", text, WS_CHILD | WS_VISIBLE,
                               x, y, w, h, parent, nullptr, GetModuleHandleW(nullptr), nullptr);
    SendMessageW(ctl, WM_SETFONT, reinterpret_cast<WPARAM>(font), TRUE);
    return ctl;
}

static LRESULT CALLBACK SetupWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        HINSTANCE hi = GetModuleHandleW(nullptr);
        HICON iconBig = static_cast<HICON>(LoadImageW(hi, MAKEINTRESOURCEW(IDI_JERISLINK), IMAGE_ICON, 64, 64, LR_DEFAULTCOLOR));
        HICON iconSmall = static_cast<HICON>(LoadImageW(hi, MAKEINTRESOURCEW(IDI_JERISLINK), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR));
        SendMessageW(hwnd, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(iconBig));
        SendMessageW(hwnd, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(iconSmall));
        applyModernChrome(hwnd);

        gBodyFont = CreateFontW(-16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        gTitleFont = CreateFontW(-27, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                                 DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                 CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");

        HWND icon = CreateWindowExW(0, L"STATIC", nullptr, WS_CHILD | WS_VISIBLE | SS_ICON,
                                    30, 28, 64, 64, hwnd, nullptr, hi, nullptr);
        SendMessageW(icon, STM_SETICON, reinterpret_cast<WPARAM>(iconBig), 0);
        makeLabel(hwnd, L"Jerislink", 112, 28, 330, 36, gTitleFont);
        makeLabel(hwnd, L"Remote access over your Tailscale network", 112, 66, 350, 24, gBodyFont);
        makeLabel(hwnd, L"Version 0.0.9.5", 32, 114, 220, 24, gBodyFont);

        gDesktopCheck = CreateWindowExW(0, L"BUTTON", L"Create a desktop shortcut",
                                        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                                        32, 153, 320, 26, hwnd,
                                        reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_DESKTOP_SHORTCUT)), hi, nullptr);
        SendMessageW(gDesktopCheck, WM_SETFONT, reinterpret_cast<WPARAM>(gBodyFont), TRUE);
        SendMessageW(gDesktopCheck, BM_SETCHECK, BST_UNCHECKED, 0);

        std::wstring pathText = L"Installs for this user to %LOCALAPPDATA%\\Programs\\Jeris\\Jerislink";
        makeLabel(hwnd, pathText.c_str(), 32, 193, 440, 40, gBodyFont);

        gStatus = makeLabel(hwnd, L"Ready to install.", 32, 246, 250, 24, gBodyFont);
        gCancelButton = CreateWindowExW(0, L"BUTTON", L"Cancel", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                        292, 240, 86, 32, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_CANCEL)), hi, nullptr);
        gInstallButton = CreateWindowExW(0, L"BUTTON", L"Install", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                                         390, 240, 86, 32, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(IDC_INSTALL)), hi, nullptr);
        SendMessageW(gCancelButton, WM_SETFONT, reinterpret_cast<WPARAM>(gBodyFont), TRUE);
        SendMessageW(gInstallButton, WM_SETFONT, reinterpret_cast<WPARAM>(gBodyFont), TRUE);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == IDC_CANCEL) {
            DestroyWindow(hwnd);
            return 0;
        }
        if (LOWORD(wParam) == IDC_INSTALL) {
            EnableWindow(gInstallButton, FALSE);
            EnableWindow(gCancelButton, FALSE);
            SetWindowTextW(gStatus, L"Installing...");
            UpdateWindow(hwnd);
            const bool desktop = SendMessageW(gDesktopCheck, BM_GETCHECK, 0, 0) == BST_CHECKED;
            std::wstring error;
            if (installJerislink(desktop, error)) {
                SetWindowTextW(gStatus, L"Installation complete.");
                MessageBoxW(hwnd, L"Jerislink has been installed successfully.\n\nYou can launch it from the Start menu.",
                            L"Jerislink", MB_OK | MB_ICONINFORMATION);
                DestroyWindow(hwnd);
            } else {
                SetWindowTextW(gStatus, L"Installation failed.");
                MessageBoxW(hwnd, error.c_str(), L"Jerislink Setup", MB_OK | MB_ICONERROR);
                EnableWindow(gInstallButton, TRUE);
                EnableWindow(gCancelButton, TRUE);
            }
            return 0;
        }
        break;
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wParam);
        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, RGB(24, 35, 52));
        return reinterpret_cast<LRESULT>(gWhiteBrush);
    }
    case WM_ERASEBKGND: {
        RECT r{};
        GetClientRect(hwnd, &r);
        FillRect(reinterpret_cast<HDC>(wParam), &r, gWhiteBrush);
        return 1;
    }
    case WM_DESTROY:
        if (gBodyFont) DeleteObject(gBodyFont);
        if (gTitleFont) DeleteObject(gTitleFont);
        if (gWhiteBrush) DeleteObject(gWhiteBrush);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hi, HINSTANCE, PWSTR, int) {
    HRESULT co = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(co)) return 1;

    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    gWhiteBrush = CreateSolidBrush(RGB(248, 250, 252));

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = SetupWndProc;
    wc.hInstance = hi;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = gWhiteBrush;
    wc.hIcon = static_cast<HICON>(LoadImageW(hi, MAKEINTRESOURCEW(IDI_JERISLINK), IMAGE_ICON, 32, 32, LR_DEFAULTCOLOR));
    wc.hIconSm = static_cast<HICON>(LoadImageW(hi, MAKEINTRESOURCEW(IDI_JERISLINK), IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR));
    wc.lpszClassName = L"JerislinkSetupWindow";
    if (!RegisterClassExW(&wc)) {
        CoUninitialize();
        return 2;
    }

    RECT r{0, 0, 510, 300};
    DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
    AdjustWindowRect(&r, style, FALSE);
    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"Jerislink Setup", style,
                                CW_USEDEFAULT, CW_USEDEFAULT, r.right-r.left, r.bottom-r.top,
                                nullptr, nullptr, hi, nullptr);
    if (!hwnd) {
        CoUninitialize();
        return 3;
    }
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    MSG m{};
    while (GetMessageW(&m, nullptr, 0, 0) > 0) {
        TranslateMessage(&m);
        DispatchMessageW(&m);
    }
    CoUninitialize();
    return static_cast<int>(m.wParam);
}
