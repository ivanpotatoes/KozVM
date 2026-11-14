#include <windows.h>
#include <commctrl.h>
#include <_plugins.h>
#include <cstring>
#include <string>
#include <mutex>
#include <vector>
#include "profiles.h"
#include "backend.h"

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
static constexpr int settingsMenu = 100, disabledMenu = 101, applyMenu = 102, statusMenu = 103;

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

static bool applyCommand(int, char**)
{
    std::lock_guard<std::recursive_mutex> lock(gate);
    return Backend::apply(profiles[settings.profile].id, settings.enabled, settings.cpuid);
}

static void lifecycle(CBTYPE type, void*)
{
    if(type == CB_SYSTEMBREAKPOINT) {
        Backend::cleanSavedBreakpoints();
        std::lock_guard<std::recursive_mutex> lock(gate);
        if(settings.enabled && settings.autoEnable) DbgCmdExec("kvm_apply");
    } else if(type == CB_STOPPINGDEBUG || type == CB_DETACH) {
        Backend::stop(true);
    } else if(type == CB_INITDEBUG || type == CB_STOPDEBUG) {
        Backend::reset();
    }
}

static void updateOptions(HWND wnd)
{
    const auto i = SendDlgItemMessageW(wnd, 110, CB_GETCURSEL, 0, 0);
    const bool extra = i >= 0 && static_cast<size_t>(i) < profiles.size()
        && profiles[static_cast<size_t>(i)].firmwareAndModule
        && Backend::available(profiles[static_cast<size_t>(i)].id);
    const bool available = i >= 0 && static_cast<size_t>(i) < profiles.size()
        && Backend::available(profiles[static_cast<size_t>(i)].id);
    EnableWindow(GetDlgItem(wnd, 121), available);
    SetDlgItemTextW(wnd, 203, available ? L"CPUID backend available for this profile"
        : L"Backend not published for this profile yet");
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
            L"CPUID policy for 331/340/350: hypervisor bit, Microsoft Hv vendor and partition privilege. Handlers are located at runtime; target code bytes remain unchanged.",
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
                L"contact@ivankozlovsky.com\n\nPublished x64 backend: 3.3.1 / 3.4.0 / 3.5.0.",
                L"About KozVM", MB_OK | MB_ICONINFORMATION);
            return TRUE;
        }
        if(LOWORD(wp) == IDOK) {
            std::lock_guard<std::recursive_mutex> lock(gate);
            const auto i = SendDlgItemMessageW(wnd, 110, CB_GETCURSEL, 0, 0);
            if(i < 0 || static_cast<size_t>(i) >= profiles.size()) return TRUE;
            if(!Backend::stop()) {
                MessageBoxW(wnd, L"Pause the target and check the log before applying.", L"KozVM", MB_OK | MB_ICONWARNING);
                return TRUE;
            }
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
            if(DbgIsDebugging()) DbgCmdExec("kvm_apply");
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
    if(id == applyMenu) { DbgCmdExec("kvm_apply"); return; }
    if(id == statusMenu) { DbgCmdExec("kvm_status"); return; }
    if(!Backend::stop()) return;
    if(id == disabledMenu) { settings.enabled = false; saveSettings(); return; }
    for(unsigned i = 0; i < profiles.size(); ++i)
        if(id == profiles[i].id) {
            settings.profile = i; settings.enabled = true; saveSettings();
            if(DbgIsDebugging()) DbgCmdExec("kvm_apply");
            else if(!Backend::available(id)) _plugin_logputs("[KozVM] Backend not published for this profile.");
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
    _plugin_registercommand(pluginHandle, "kvm_apply", applyCommand, false);
    _plugin_registercommand(pluginHandle, "kvm_hit", Backend::hit, true);
    _plugin_registercommand(pluginHandle, "kvm_status", Backend::status, false);
    for(auto type : {CB_SYSTEMBREAKPOINT, CB_INITDEBUG, CB_STOPPINGDEBUG, CB_DETACH, CB_STOPDEBUG})
        _plugin_registercallback(pluginHandle, type, lifecycle);
    _plugin_logputs("[KozVM] Published x64 backends: 331, 340, 350.");
    return true;
}

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT* setup)
{
    owner = setup->hwndDlg;
    for(const auto& p : profiles) _plugin_menuaddentry(setup->hMenu, p.id, p.label);
    _plugin_menuaddentry(setup->hMenu, disabledMenu, "Disabled");
    _plugin_menuaddseparator(setup->hMenu);
    _plugin_menuaddentry(setup->hMenu, settingsMenu, "Settings...");
    _plugin_menuaddentry(setup->hMenu, applyMenu, "Apply to paused session");
    _plugin_menuaddentry(setup->hMenu, statusMenu, "Status");
    menuReady = true; updateMenus();
}

extern "C" __declspec(dllexport) bool plugstop()
{
    std::lock_guard<std::recursive_mutex> lock(gate);
    if(dialogOpen || !Backend::stop()) return false;
    for(const char* name : {"kvm_apply", "kvm_hit", "kvm_status"}) _plugin_unregistercommand(pluginHandle, name);
    for(auto type : {CB_SYSTEMBREAKPOINT, CB_INITDEBUG, CB_STOPPINGDEBUG, CB_DETACH, CB_STOPDEBUG})
        _plugin_unregistercallback(pluginHandle, type);
    _plugin_unregistercallback(pluginHandle, CB_MENUENTRY);
    menuReady = false;
    return true;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID)
{
    if(reason == DLL_PROCESS_ATTACH) { instance = h; DisableThreadLibraryCalls(h); }
    return TRUE;
}
