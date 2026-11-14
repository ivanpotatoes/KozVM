#include <windows.h>
#include <_plugins.h>
#include <cstring>

static int pluginHandle;
static HWND owner;

static void menu(CBTYPE, void* data)
{
    const auto* entry = static_cast<PLUG_CB_MENUENTRY*>(data);
    if(entry->hEntry == 1)
        MessageBoxW(owner,
            L"KozVM\n\nCreator: Ivan Kozlovsky\n"
            L"ivankozlovsky.com\ncontact@ivankozlovsky.com\n\n"
            L"Public source preview: plugin shell only.",
            L"About KozVM", MB_OK | MB_ICONINFORMATION);
}

extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* init)
{
    pluginHandle = init->pluginHandle;
    init->sdkVersion = PLUG_SDKVERSION;
    init->pluginVersion = 1;
    strcpy_s(init->pluginName, "KozVM x64");
    _plugin_registercallback(pluginHandle, CB_MENUENTRY, menu);
    _plugin_logputs("[KozVM] Public source preview loaded; no anti-VM handling included.");
    return true;
}

extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT* setup)
{
    owner = setup->hwndDlg;
    _plugin_menuaddentry(setup->hMenu, 1, "About KozVM");
}

extern "C" __declspec(dllexport) bool plugstop()
{
    _plugin_unregistercallback(pluginHandle, CB_MENUENTRY);
    return true;
}
