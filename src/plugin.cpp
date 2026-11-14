#include <windows.h>
#include <commctrl.h>
#include <_plugins.h>
#include <cstring>
#include <string>
#include <mutex>
#include <vector>
#include "profiles.h"

static HINSTANCE instance;
static HWND owner;
static int pluginHandle;
static bool menuReady = false, dialogOpen = false;
static std::recursive_mutex gate;
static std::wstring iniPath;
struct Settings {
    unsigned profile = 0;
    bool enabled = true, autoEnable = true;
    bool cpuid = true, firmware = true, sandboxie = true;
};
static Settings settings;
static constexpr int settingsMenu = 100, disabledMenu = 101;

static void updateMenus()
{
    if(!menuReady) return;
    for(unsigned i = 0; i < profiles.size(); ++i)
        _plugin_menuentrysetchecked(pluginHandle, profiles[i].id,
            settings.enabled && settings.profile == i);
    _plugin_menuentrysetchecked(pluginHandle, disabledMenu, !settings.enabled);
}

static bool saveSettings()
{
    wchar_t id[16];
    swprintf_s(id, L"%d", profiles[settings.profile].id);
    bool ok = WritePrivateProfileStringW(L"Settings", L"Profile", id, iniPath.c_str()) != 0;
    auto write = [&](const wchar_t* section, const wchar_t* key, bool value) {
        if(!WritePrivateProfileStringW(section, key, value ? L"1" : L"0", iniPath.c_str())) ok = false;
    };
    write(L"Settings", L"Enabled", settings.enabled);
    write(L"Settings", L"AutoArm", settings.autoEnable);
    write(L"Options", L"CPUID", settings.cpuid);
    write(L"Options", L"Firmware", settings.firmware);
    write(L"Options", L"Sandboxie", settings.sandboxie);
    updateMenus();
    if(!ok) _plugin_logputs("[KozVM] Could not save all INI settings.");
    return ok;
}

static void loadSettings()
{
    auto read = [&](const wchar_t* section, const wchar_t* key) {
        return GetPrivateProfileIntW(section, key, 1, iniPath.c_str()) != 0;
    };
    const int id = GetPrivateProfileIntW(L"Settings", L"Profile", 331, iniPath.c_str());
    for(unsigned i = 0; i < profiles.size(); ++i)
        if(profiles[i].id == id) settings.profile = i;
    settings.enabled = read(L"Settings", L"Enabled");
    settings.autoEnable = read(L"Settings", L"AutoArm");
    settings.cpuid = read(L"Options", L"CPUID");
    settings.firmware = read(L"Options", L"Firmware");
    settings.sandboxie = read(L"Options", L"Sandboxie");
}

static void updateOptions(HWND wnd)
{
    const auto i = SendDlgItemMessageW(wnd, 110, CB_GETCURSEL, 0, 0);
    const bool extra = i >= 0 && static_cast<size_t>(i) < profiles.size()
        && profiles[static_cast<size_t>(i)].firmwareAndModule;
    EnableWindow(GetDlgItem(wnd, 122), extra);
    EnableWindow(GetDlgItem(wnd, 123), extra);
}

static INT_PTR CALLBACK dialog(HWND wnd, UINT msg, WPARAM wp, LPARAM)
{
    if(msg == WM_INITDIALOG) {
        std::lock_guard<std::recursive_mutex> lock(gate);
        for(const auto& p : profiles)
            SendDlgItemMessageW(wnd, 110, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(p.wideLabel));
        SendDlgItemMessageW(wnd, 110, CB_SETCURSEL, settings.profile, 0);
        CheckDlgButton(wnd, 120, settings.enabled ? BST_CHECKED : BST_UNCHECKED);
        CheckDlgButton(wnd, 111, settings.autoEnable ? BST_CHECKED : BST_UNCHECKED);
        CheckDlgButton(wnd, 121, settings.cpuid ? BST_CHECKED : BST_UNCHECKED);
        CheckDlgButton(wnd, 122, settings.firmware ? BST_CHECKED : BST_UNCHECKED);
        CheckDlgButton(wnd, 123, settings.sandboxie ? BST_CHECKED : BST_UNCHECKED);
        updateOptions(wnd);
        HWND tip = CreateWindowExW(WS_EX_TOPMOST, TOOLTIPS_CLASSW, nullptr,
            WS_POPUP | TTS_ALWAYSTIP, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
            CW_USEDEFAULT, wnd, nullptr, instance, nullptr);
        const wchar_t* tips[] = {
            L"CPUID policy: hypervisor bit, Microsoft Hv vendor and partition privilege. Saved configuration only; backend not published yet.",
            L"Firmware scanner option for 3.9.4 and 3.10.1. Saved configuration only; backend not published yet.",
            L"Sandboxie module query option for 3.9.4 and 3.10.1. Saved configuration only; backend not published yet."
        };
        for(int i = 0; i < 3; ++i) {
            TOOLINFOW ti{};
            ti.cbSize = sizeof(ti); ti.uFlags = TTF_IDISHWND | TTF_SUBCLASS;
            ti.hwnd = wnd; ti.uId = reinterpret_cast<UINT_PTR>(GetDlgItem(wnd, 200 + i));
            ti.lpszText = const_cast<wchar_t*>(tips[i]);
            SendMessageW(tip, TTM_ADDTOOLW, 0, reinterpret_cast<LPARAM>(&ti));
        }
        SendMessageW(tip, TTM_SETMAXTIPWIDTH, 0, 360);
        return TRUE;
    }
    if(msg == WM_COMMAND) {
        if(LOWORD(wp) == 110 && HIWORD(wp) == CBN_SELCHANGE) { updateOptions(wnd); return TRUE; }
        if(LOWORD(wp) == IDCANCEL) { EndDialog(wnd, 0); return TRUE; }
        if(LOWORD(wp) == 150) {
            MessageBoxW(wnd, L"KozVM x64\n\nCreator: Ivan Kozlovsky\nivankozlovsky.com\n"
                L"contact@ivankozlovsky.com\n\nPublic source preview: GUI and profiles only.",
                L"About KozVM", MB_OK | MB_ICONINFORMATION);
            return TRUE;
        }
        if(LOWORD(wp) == IDOK) {
            std::lock_guard<std::recursive_mutex> lock(gate);
            const auto i = SendDlgItemMessageW(wnd, 110, CB_GETCURSEL, 0, 0);
            if(i < 0 || static_cast<size_t>(i) >= profiles.size()) return TRUE;
            settings.profile = static_cast<unsigned>(i);
            settings.enabled = IsDlgButtonChecked(wnd, 120) == BST_CHECKED;
            settings.autoEnable = IsDlgButtonChecked(wnd, 111) == BST_CHECKED;
            settings.cpuid = IsDlgButtonChecked(wnd, 121) == BST_CHECKED;
            settings.firmware = IsDlgButtonChecked(wnd, 122) == BST_CHECKED;
            settings.sandboxie = IsDlgButtonChecked(wnd, 123) == BST_CHECKED;
            if(!saveSettings()) {
                MessageBoxW(wnd, L"Could not save all settings. Check the INI location is writable.",
                    L"KozVM", MB_OK | MB_ICONWARNING);
                return TRUE;
            }
            _plugin_logputs("[KozVM] Settings saved. Anti-VM backend is not included in this snapshot.");
            EndDialog(wnd, 1); return TRUE;
        }
    }
    if(msg == WM_CLOSE) { EndDialog(wnd, 0); return TRUE; }
    return FALSE;
}

static void showSettings()
{
    DialogBoxParamW(instance, MAKEINTRESOURCEW(101), owner, dialog, 0);
    std::lock_guard<std::recursive_mutex> lock(gate);
    dialogOpen = false;
}

static void menu(CBTYPE, void* data)
{
    const int id = static_cast<PLUG_CB_MENUENTRY*>(data)->hEntry;
    std::lock_guard<std::recursive_mutex> lock(gate);
    if(dialogOpen) return;
    if(id == settingsMenu) {
        // Also block unloading while the GUI callback is queued.
        dialogOpen = true;
        GuiExecuteOnGuiThread(showSettings);
        return;
    }
    if(id == disabledMenu) { settings.enabled = false; saveSettings(); return; }
    for(unsigned i = 0; i < profiles.size(); ++i)
        if(id == profiles[i].id) {
            settings.profile = i; settings.enabled = true; saveSettings();
            _plugin_logputs("[KozVM] Profile selected. Backend not included in this snapshot.");
            return;
        }
}

extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* init)
{
    pluginHandle = init->pluginHandle;
    init->sdkVersion = PLUG_SDKVERSION; init->pluginVersion = 1;
    strcpy_s(init->pluginName, "KozVM x64");
    std::vector<wchar_t> path(32768);
    const DWORD count = GetModuleFileNameW(instance, path.data(), static_cast<DWORD>(path.size()));
    if(!count || count >= path.size()) return false;
    iniPath = path.data(); iniPath += L".ini";
    loadSettings();
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_WIN95_CLASSES};
    InitCommonControlsEx(&controls);
    _plugin_registercallback(pluginHandle, CB_MENUENTRY, menu);
    _plugin_logputs("[KozVM] GUI/profile preview loaded; no anti-VM backend included.");
    return true;
}

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT* setup)
{
    owner = setup->hwndDlg;
    for(const auto& p : profiles) _plugin_menuaddentry(setup->hMenu, p.id, p.label);
    _plugin_menuaddentry(setup->hMenu, disabledMenu, "Disabled");
    _plugin_menuaddseparator(setup->hMenu);
    _plugin_menuaddentry(setup->hMenu, settingsMenu, "Settings...");
    menuReady = true; updateMenus();
}

extern "C" __declspec(dllexport) bool plugstop()
{
    std::lock_guard<std::recursive_mutex> lock(gate);
    if(dialogOpen) return false;
    _plugin_unregistercallback(pluginHandle, CB_MENUENTRY);
    menuReady = false;
    return true;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID)
{
    if(reason == DLL_PROCESS_ATTACH) { instance = h; DisableThreadLibraryCalls(h); }
    return TRUE;
}
