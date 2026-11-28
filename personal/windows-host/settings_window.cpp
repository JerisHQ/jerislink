// JerisLink Windows host, H3: the connection settings window
// (JerisLinkHost.exe --connection-settings), as the macOS host's
// ConnectionSettingsWindow: password, whitelist, blacklist, recent auth
// failures, plus the theme (the viewer's green or blue, ui_theme.hpp).
//
// Runs elevated (one UAC prompt): the settings live under HKLM and the key
// under a SYSTEM/Administrators-only subkey. Every change goes through
// host_config_win.hpp; a running host sees it through its registry watch.
// Windows has no 清除密碼 (design D9: no password, no network).
#include "settings_window.hpp"

#include "host_config_win.hpp"

#include "../windows-client/ui_theme.hpp"

#include <commctrl.h>

#include <ctime>
#include <string>
#include <vector>

namespace jlh::settingsui {
namespace {

namespace ui = jl::ui;
namespace cfg = jlh::config;
namespace st = jlh::settings;

enum : int {
    kBanner = 100,
    kListen,
    kSecPassword,
    kPwStatus,
    kPwLabel1,
    kPw1,
    kPwLabel2,
    kPw2,
    kPwRules,
    kPwSet,
    kSecWhite,
    kWhiteLabel,
    kWhite,
    kWhiteSave,
    kSecTheme,
    kThemeGreen,
    kThemeBlue,
    kSecBlack,
    kBlackLabel,
    kBlackList,
    kUnblock,
    kBlockField,
    kBlockAdd,
    kSecFail,
    kFailSummary,
    kFailLabel,
    kFailList,
    kRefresh,
    kStatus,
};

// Logical (96 dpi) layout: two columns, 800 x 680.
struct Slot {
    int id;
    const wchar_t* cls;
    DWORD style;
    int x, y, w, h;
};
constexpr int kL = 20, kR = 410, kW = 370;
constexpr int kClientW = 800, kClientH = 680;
const Slot kSlots[] = {
    {kBanner, L"STATIC", SS_LEFT, kL, 14, kClientW - 2 * kL, 40},
    {kListen, L"STATIC", SS_LEFT | SS_NOPREFIX, kL, 58, kClientW - 2 * kL, 20},
    // left: password, whitelist, theme
    {kSecPassword, L"STATIC", SS_LEFT, kL, 96, kW, 20},
    {kPwStatus, L"STATIC", SS_LEFT, kL, 120, kW, 20},
    {kPwLabel1, L"STATIC", SS_LEFT, kL, 146, kW, 18},
    {kPw1, L"EDIT", WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL, kL + 6, 170, kW - 12, 22},
    {kPwLabel2, L"STATIC", SS_LEFT, kL, 202, kW, 18},
    {kPw2, L"EDIT", WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL, kL + 6, 226, kW - 12, 22},
    {kPwRules, L"STATIC", SS_LEFT, kL, 256, kW, 36},
    {kPwSet, L"BUTTON", WS_TABSTOP | BS_OWNERDRAW, kL, 296, 170, 32},
    {kSecWhite, L"STATIC", SS_LEFT, kL, 346, kW, 20},
    {kWhiteLabel, L"STATIC", SS_LEFT, kL, 370, kW, 36},
    {kWhite, L"EDIT", WS_TABSTOP | ES_MULTILINE | ES_AUTOVSCROLL | ES_WANTRETURN | WS_VSCROLL, kL + 6, 414, kW - 12, 92},
    {kWhiteSave, L"BUTTON", WS_TABSTOP | BS_OWNERDRAW, kL, 516, 130, 32},
    {kSecTheme, L"STATIC", SS_LEFT, kL, 566, kW, 20},
    {kThemeGreen, L"BUTTON", WS_TABSTOP | BS_OWNERDRAW, kL, 590, 90, 32},
    {kThemeBlue, L"BUTTON", WS_TABSTOP | BS_OWNERDRAW, kL + 100, 590, 90, 32},
    // right: blacklist, failures
    {kSecBlack, L"STATIC", SS_LEFT, kR, 96, kW, 20},
    {kBlackLabel, L"STATIC", SS_LEFT, kR, 120, kW, 36},
    {kBlackList, L"LISTBOX", WS_TABSTOP | LBS_NOTIFY | LBS_NOINTEGRALHEIGHT | WS_VSCROLL, kR + 6, 164, kW - 12, 112},
    {kUnblock, L"BUTTON", WS_TABSTOP | BS_OWNERDRAW, kR, 286, 120, 32},
    {kBlockField, L"EDIT", WS_TABSTOP | ES_AUTOHSCROLL, kR + 6, 340, 224, 22},
    {kBlockAdd, L"BUTTON", WS_TABSTOP | BS_OWNERDRAW, kR + 250, 335, 120, 32},
    {kSecFail, L"STATIC", SS_LEFT, kR, 386, kW, 20},
    {kFailSummary, L"STATIC", SS_LEFT | SS_NOPREFIX, kR, 410, kW, 36},
    {kFailLabel, L"STATIC", SS_LEFT, kR, 448, kW, 18},
    {kFailList, L"EDIT", ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL, kR + 6, 474, kW - 12, 106},
    {kRefresh, L"BUTTON", WS_TABSTOP | BS_OWNERDRAW, kR, 590, 120, 32},
    {kStatus, L"STATIC", SS_LEFT | SS_NOPREFIX, kL, 636, kClientW - 2 * kL, 36},
};
// Fields get a drawn rounded border (the controls have none).
constexpr int kFields[] = {kPw1, kPw2, kWhite, kBlackList, kBlockField, kFailList};

std::wstring W(const std::string& s) { return cfg::widen(s); }

std::string timeText(int64_t unixSeconds) {
    if (unixSeconds <= 0) return "—";
    const time_t t = time_t(unixSeconds);
    tm local{};
    if (localtime_s(&local, &t) != 0) return "—";
    char b[32];
    std::strftime(b, sizeof(b), "%Y-%m-%d %H:%M:%S", &local);
    return b;
}

std::wstring textOf(HWND h) {
    const int n = GetWindowTextLengthW(h);
    std::wstring s(size_t(std::max(n, 0)) + 1, L'\0');
    const int got = GetWindowTextW(h, &s[0], n + 1);
    s.resize(size_t(std::max(got, 0)));
    return s;
}
void wipe(std::wstring& s) {
    if (!s.empty()) SecureZeroMemory(&s[0], s.size() * sizeof(wchar_t));
    s.clear();
}
// The text of a password box, and the box emptied of it.
std::wstring takePassword(HWND h) {
    std::wstring s = textOf(h);
    SetWindowTextW(h, L"");
    return s;
}

class SettingsWindow {
public:
    explicit SettingsWindow(cfg::Location loc) : loc_(std::move(loc)) {}

    int run() {
        WNDCLASSEXW wc{};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = &SettingsWindow::proc;
        wc.hInstance = GetModuleHandleW(nullptr);
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
        wc.hIcon = LoadIconW(nullptr, IDI_SHIELD);
        wc.lpszClassName = L"JerisLinkHostConnectionSettings";
        RegisterClassExW(&wc);
        const DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
        hwnd_ = CreateWindowExW(WS_EX_CONTROLPARENT, wc.lpszClassName, L"JerisLink 連線設定（Windows host）", style,
                                CW_USEDEFAULT, CW_USEDEFAULT, 100, 100, nullptr, nullptr, wc.hInstance, this);
        if (!hwnd_) return 70;
        ShowWindow(hwnd_, SW_SHOWNORMAL);
        SetForegroundWindow(hwnd_);
        MSG m;
        while (GetMessageW(&m, nullptr, 0, 0) > 0) {
            if (IsDialogMessageW(hwnd_, &m)) continue;
            TranslateMessage(&m);
            DispatchMessageW(&m);
        }
        return 0;
    }

private:
    static LRESULT CALLBACK proc(HWND h, UINT msg, WPARAM wp, LPARAM lp) {
        SettingsWindow* self = nullptr;
        if (msg == WM_NCCREATE) {
            self = static_cast<SettingsWindow*>(reinterpret_cast<CREATESTRUCTW*>(lp)->lpCreateParams);
            SetWindowLongPtrW(h, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(self));
            self->hwnd_ = h;
        } else {
            self = reinterpret_cast<SettingsWindow*>(GetWindowLongPtrW(h, GWLP_USERDATA));
        }
        if (!self) return DefWindowProcW(h, msg, wp, lp);
        return self->handle(msg, wp, lp);
    }

    HWND item(int id) const { return GetDlgItem(hwnd_, id); }
    int px(int v) const { return ui::px(theme_.dpi, v); }

    LRESULT handle(UINT msg, WPARAM wp, LPARAM lp) {
        switch (msg) {
        case WM_CREATE: create(); return 0;
        case WM_DPICHANGED: {
            const RECT* r = reinterpret_cast<const RECT*>(lp);
            SetWindowPos(hwnd_, nullptr, r->left, r->top, r->right - r->left, r->bottom - r->top,
                         SWP_NOZORDER | SWP_NOACTIVATE);
            applyDpi();
            return 0;
        }
        case WM_ERASEBKGND: return 1;
        case WM_PAINT: paint(); return 0;
        case WM_CTLCOLORSTATIC: return colorStatic(reinterpret_cast<HDC>(wp), reinterpret_cast<HWND>(lp));
        case WM_CTLCOLOREDIT:
        case WM_CTLCOLORLISTBOX: {
            HDC dc = reinterpret_cast<HDC>(wp);
            SetTextColor(dc, ui::color::kText);
            SetBkColor(dc, ui::color::kField);
            return reinterpret_cast<LRESULT>(theme_.field);
        }
        case WM_CTLCOLORBTN: return reinterpret_cast<LRESULT>(theme_.body);
        case WM_DRAWITEM: {
            const auto* di = reinterpret_cast<const DRAWITEMSTRUCT*>(lp);
            const int id = int(di->CtlID);
            const bool primary = id == kPwSet || id == kWhiteSave || id == kBlockAdd ||
                                 (id == kThemeGreen && themeName_ == "green") ||
                                 (id == kThemeBlue && themeName_ == "blue");
            ui::drawButton(*di, theme_, primary, ui::color::kBody);
            return TRUE;
        }
        case WM_COMMAND: command(LOWORD(wp), HIWORD(wp)); return 0;
        case WM_CLOSE: DestroyWindow(hwnd_); return 0;
        case WM_DESTROY:
            if (mono_) DeleteObject(mono_);
            mono_ = nullptr;
            PostQuitMessage(0);
            return 0;
        }
        return DefWindowProcW(hwnd_, msg, wp, lp);
    }

    void create() {
        HINSTANCE inst = GetModuleHandleW(nullptr);
        for (const Slot& s : kSlots)
            CreateWindowExW(0, s.cls, L"", WS_CHILD | WS_VISIBLE | s.style, 0, 0, 10, 10, hwnd_,
                            reinterpret_cast<HMENU>(INT_PTR(s.id)), inst, nullptr);
        SendMessageW(item(kPw1), EM_SETLIMITTEXT, 256, 0);
        SendMessageW(item(kPw2), EM_SETLIMITTEXT, 256, 0);
        SendMessageW(item(kBlockField), EM_SETLIMITTEXT, 64, 0);
        SendMessageW(item(kWhite), EM_SETLIMITTEXT, 16384, 0);
        setText(kSecPassword, "連線密碼");
        setText(kPwLabel1, "新密碼（最少 " + std::to_string(auth::kMinPasswordLength) + " 個字，大細楷同符號）");
        setText(kPwLabel2, "再輸入一次");
        setText(kPwSet, "設定／更改密碼");
        setText(kSecWhite, "白名單");
        setText(kWhiteLabel, "白名單：每行一個 tailnet IPv4（100.64.0.0/10）。空白 = 任何 IP 都要密碼。");
        setText(kWhiteSave, "儲存白名單");
        setText(kSecTheme, "主題");
        setText(kThemeGreen, "綠色");
        setText(kThemeBlue, "藍色");
        setText(kSecBlack, "黑名單");
        setText(kBlackLabel, "黑名單：永遠拒絕（優先過白名單）。錯密碼太多次會自動加入。揀一行再按解除封鎖。");
        setText(kUnblock, "解除封鎖");
        setText(kBlockAdd, "加入黑名單");
        setText(kSecFail, "最近 auth 失敗");
        setText(kFailLabel, "最近 auth 失敗（最新喺最底，最多 " + std::to_string(auth::kFailureRecordLimit) + " 條）");
        setText(kRefresh, "重新整理");
        ui::applyWindowChrome(hwnd_);
        const auto s = cfg::readSettings(loc_);
        themeName_ = s.theme == "blue" ? "blue" : "green";
        ui::setAccent(themeName_ == "blue" ? ui::Accent::Blue : ui::Accent::Green);
        applyDpi();
        RECT wr{};
        GetWindowRect(hwnd_, &wr);
        HMONITOR mon = MonitorFromWindow(hwnd_, MONITOR_DEFAULTTONEAREST);
        MONITORINFO mi{};
        mi.cbSize = sizeof(mi);
        if (GetMonitorInfoW(mon, &mi)) {
            const int w = wr.right - wr.left, hgt = wr.bottom - wr.top;
            const int x = mi.rcWork.left + std::max(0L, (mi.rcWork.right - mi.rcWork.left - w) / 2);
            const int y = mi.rcWork.top + std::max(0L, (mi.rcWork.bottom - mi.rcWork.top - hgt) / 2);
            SetWindowPos(hwnd_, nullptr, x, y, 0, 0, SWP_NOZORDER | SWP_NOSIZE | SWP_NOACTIVATE);
        }
        reload();
        updateRules();
        SetFocus(item(kPw1));
    }

    void applyDpi() {
        theme_.build(hwnd_, 12);
        if (mono_) DeleteObject(mono_);
        mono_ = CreateFontW(-MulDiv(9, int(theme_.dpi), 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN,
                            L"Consolas");
        RECT want{0, 0, px(kClientW), px(kClientH)};
        AdjustWindowRectExForDpi(&want, DWORD(GetWindowLongPtrW(hwnd_, GWL_STYLE)), FALSE,
                                 DWORD(GetWindowLongPtrW(hwnd_, GWL_EXSTYLE)), theme_.dpi);
        SetWindowPos(hwnd_, nullptr, 0, 0, want.right - want.left, want.bottom - want.top,
                     SWP_NOZORDER | SWP_NOMOVE | SWP_NOACTIVATE);
        for (const Slot& s : kSlots) {
            HWND c = item(s.id);
            MoveWindow(c, px(s.x), px(s.y), px(s.w), px(s.h), FALSE);
            HFONT f = theme_.text;
            if (s.id == kSecPassword || s.id == kSecWhite || s.id == kSecTheme || s.id == kSecBlack || s.id == kSecFail)
                f = theme_.section;
            else if (s.id == kPwStatus || s.id == kBanner)
                f = theme_.label;
            else if (s.id == kWhiteLabel || s.id == kBlackLabel || s.id == kFailLabel || s.id == kPwRules ||
                     s.id == kListen)
                f = theme_.smallText;
            else if (s.id == kBlackList || s.id == kFailList || s.id == kWhite || s.id == kBlockField)
                f = mono_;
            SendMessageW(c, WM_SETFONT, reinterpret_cast<WPARAM>(f), FALSE);
        }
        RedrawWindow(hwnd_, nullptr, nullptr, RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN);
    }

    void paint() {
        PAINTSTRUCT ps;
        HDC dc = BeginPaint(hwnd_, &ps);
        RECT client{};
        GetClientRect(hwnd_, &client);
        ui::fillRect(dc, client, ui::color::kBody);
        for (int id : kFields) {
            RECT r = ui::childRect(hwnd_, id);
            InflateRect(&r, px(5), px(5));
            const bool focus = GetFocus() == item(id);
            ui::roundRect(dc, r, px(8), ui::color::kField, focus ? ui::accent().accent : ui::color::kBorder,
                          focus ? px(2) : px(1));
        }
        const int mid = px(kR - 20);
        ui::line(dc, mid, px(96), mid, px(622), ui::color::kBorder, px(1));
        EndPaint(hwnd_, &ps);
    }

    LRESULT colorStatic(HDC dc, HWND c) {
        const int id = GetDlgCtrlID(c);
        SetBkMode(dc, TRANSPARENT);
        if (id == kFailList) {
            SetTextColor(dc, ui::color::kText);
            SetBkColor(dc, ui::color::kField);
            return reinterpret_cast<LRESULT>(theme_.field);
        }
        COLORREF fg = ui::color::kText;
        switch (id) {
        case kSecPassword:
        case kSecWhite:
        case kSecTheme:
        case kSecBlack:
        case kSecFail: fg = ui::accent().accent; break;
        case kBanner: fg = bannerError_ ? ui::color::kError : ui::color::kWarning; break;
        case kWhiteLabel:
        case kBlackLabel:
        case kFailLabel:
        case kListen: fg = ui::color::kMuted; break;
        case kPwRules: fg = rulesOk_ ? ui::accent().accent : ui::color::kMuted; break;
        case kStatus: fg = statusKind_ == 1 ? ui::accent().accent : statusKind_ == 2 ? ui::color::kError : ui::color::kMuted; break;
        }
        SetTextColor(dc, fg);
        SetBkColor(dc, ui::color::kBody);
        return reinterpret_cast<LRESULT>(theme_.body);
    }

    void setText(int id, const std::string& s) { SetWindowTextW(item(id), W(s).c_str()); }

    // 0 muted (working), 1 done, 2 refused.
    void show(int kind, const std::string& s) {
        statusKind_ = kind;
        setText(kStatus, s);
        InvalidateRect(item(kStatus), nullptr, TRUE);
    }
    void show(const st::Outcome& o) {
        reload();
        show(o.ok ? 1 : 2, o.text);
    }

    void reload() {
        const cfg::Settings s = cfg::readSettings(loc_);
        const cfg::SecretRead sec = cfg::readSecret(loc_);
        const bool hasPassword = sec.secret != nullptr;
        bannerError_ = !sec.problem.empty() || !s.whitelistProblem.empty();
        std::string banner;
        if (!sec.problem.empty())
            banner = "⚠️ 連線密碼讀唔到（" + sec.problem + "）：host 唔會接受任何連線。請重新設定密碼。";
        else if (!s.whitelistProblem.empty())
            banner = "⚠️ 白名單讀唔到（" + s.whitelistProblem + "）：host 唔會接受任何連線。請重新儲存白名單。";
        else if (!hasPassword)
            banner = "⚠️ 未設定連線密碼：host 唔會聽網絡，冇 viewer 可以連線。設定密碼之後再開 host。";
        setText(kBanner, banner);
        ShowWindow(item(kBanner), banner.empty() ? SW_HIDE : SW_SHOWNA);
        setText(kPwStatus, hasPassword ? "狀態：已設定密碼" : !sec.problem.empty() ? "狀態：密碼讀唔到" : "狀態：未設定密碼");

        const auto plan = st::resolveListen(s.listenMode, s.bindIp, cfg::localIpv4());
        std::string listen;
        if (plan.kind == st::ListenPlan::Ready)
            listen = "監聽：" + plan.bindIp + "（TCP " + std::to_string(st::kControlPort) + "、UDP " +
                     std::to_string(st::kMrm1Port) + "）" + (plan.mode == "loopback" ? "，只限本機測試" : "");
        else if (plan.kind == st::ListenPlan::Waiting)
            listen = "監聽：等緊 tailnet 地址（" + plan.why + "）";
        else
            listen = "監聽設定有問題：" + plan.why;
        if (!s.problem.empty()) listen += "；registry 值讀唔到：" + s.problem;
        setText(kListen, listen);

        if (s.whitelistProblem.empty()) {
            std::string wl;
            for (const auto& ip : s.whitelist) wl += ip + "\r\n";
            setText(kWhite, wl);
        }

        blockIps_.clear();
        HWND list = item(kBlackList);
        SendMessageW(list, LB_RESETCONTENT, 0, 0);
        const auto blocks = cfg::RegistryBlocklist(loc_).load();
        if (!blocks) {
            SendMessageW(list, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"（黑名單讀唔到）"));
        } else if (blocks->empty()) {
            SendMessageW(list, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"（冇封鎖）"));
        } else {
            for (const auto& b : *blocks) {
                blockIps_.push_back(b.ip);
                const std::string row = b.ip + "  ·  " + timeText(b.at) + "  ·  " + st::reasonText(b.reason);
                SendMessageW(list, LB_ADDSTRING, 0, reinterpret_cast<LPARAM>(W(row).c_str()));
            }
        }
        EnableWindow(item(kUnblock), !blockIps_.empty());

        cfg::RegistryFailureLog flog(loc_);
        const auto records = flog.loadRecords();
        const auto summary = auth::summarizeFailures(records, flog.loadTimes(), int64_t(time(nullptr)));
        setText(kFailSummary, st::failureSummaryText(summary, summary.lastIp.empty() ? "" : timeText(summary.lastAt)));
        std::string rows;
        for (const auto& r : records) {
            if (!rows.empty()) rows += "\r\n";
            rows += timeText(r.at) + "  " + r.ip + "  " + st::failureReasonText(r.reason) + "（第 " +
                    std::to_string(r.failures) + " 次）";
        }
        setText(kFailList, rows.empty() ? "（冇紀錄）" : rows);
        const LRESULT lines = SendMessageW(item(kFailList), EM_GETLINECOUNT, 0, 0);
        SendMessageW(item(kFailList), EM_LINESCROLL, 0, lines);

        const std::string theme = s.theme == "blue" ? "blue" : "green";
        if (theme != themeName_) {
            themeName_ = theme;
            ui::setAccent(theme == "blue" ? ui::Accent::Blue : ui::Accent::Green);
        }
        RedrawWindow(hwnd_, nullptr, nullptr, RDW_INVALIDATE | RDW_ALLCHILDREN);
    }

    // The rules under the password boxes, as the password is typed.
    void updateRules() {
        std::wstring a = textOf(item(kPw1)), b = textOf(item(kPw2));
        std::string text;
        rulesOk_ = false;
        if (a.empty()) {
            text = "要求：最少 " + std::to_string(auth::kMinPasswordLength) + " 個字；大楷、細楷同符號各一。";
        } else if (auto nfc = cfg::nfcCodePoints(a)) {
            const auto problems = auth::passwordProblems(*nfc);
            if (!nfc->empty()) SecureZeroMemory(&(*nfc)[0], nfc->size() * sizeof(char32_t));
            if (!problems.empty()) text = "仲差：" + st::passwordProblemsText(problems);
            else if (b.empty()) text = "✓ 密碼夠強；請再輸入一次。", rulesOk_ = true;
            else if (a != b) text = "兩次輸入嘅密碼唔一樣。";
            else text = "✓ 密碼夠強，兩次一樣。", rulesOk_ = true;
        } else {
            text = "密碼有無效字元。";
        }
        wipe(a);
        wipe(b);
        setText(kPwRules, text);
        InvalidateRect(item(kPwRules), nullptr, TRUE);
    }

    void command(int id, int code) {
        if ((id == kPw1 || id == kPw2) && code == EN_CHANGE) return updateRules();
        if (code == EN_SETFOCUS || code == EN_KILLFOCUS || code == LBN_SETFOCUS || code == LBN_KILLFOCUS) {
            InvalidateRect(hwnd_, nullptr, FALSE);  // the field's border follows focus
            return;
        }
        if (code != BN_CLICKED) return;
        switch (id) {
        case kPwSet: {
            std::wstring a = takePassword(item(kPw1)), b = takePassword(item(kPw2));
            show(0, "處理中…");
            UpdateWindow(hwnd_);
            HCURSOR old = SetCursor(LoadCursorW(nullptr, IDC_WAIT));
            const auto o = cfg::setPassword(loc_, a, b);
            SetCursor(old);
            wipe(a);
            wipe(b);
            updateRules();
            show(o);
            break;
        }
        case kWhiteSave: show(cfg::saveWhitelist(loc_, cfg::narrow(textOf(item(kWhite))))); break;
        case kUnblock: {
            const LRESULT i = SendMessageW(item(kBlackList), LB_GETCURSEL, 0, 0);
            if (i == LB_ERR || size_t(i) >= blockIps_.size()) {
                show(2, "請先喺黑名單揀一個 IP。");
                break;
            }
            show(cfg::unblock(loc_, blockIps_[size_t(i)]));
            break;
        }
        case kBlockAdd: {
            const auto o = cfg::block(loc_, cfg::narrow(textOf(item(kBlockField))), int64_t(time(nullptr)));
            if (o.ok) SetWindowTextW(item(kBlockField), L"");
            show(o);
            break;
        }
        case kRefresh:
            reload();
            show(0, "");
            break;
        case kThemeGreen:
        case kThemeBlue: {
            const auto o = cfg::setTheme(loc_, id == kThemeBlue ? "blue" : "green");
            show(o);
            break;
        }
        }
    }

    cfg::Location loc_;
    HWND hwnd_ = nullptr;
    ui::DialogTheme theme_;
    HFONT mono_ = nullptr;
    std::string themeName_ = "green";
    std::vector<std::string> blockIps_;
    int statusKind_ = 0;
    bool bannerError_ = false;
    bool rulesOk_ = false;
};

}  // namespace

int runConnectionSettings(const jlh::config::Location& loc) {
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    SettingsWindow w(loc);
    return w.run();
}

}  // namespace jlh::settingsui
