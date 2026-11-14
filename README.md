# KozVM

An x64dbg anti-anti-VM plugin for VMProtect. No kernel driver required.

## Published backends

This repository is being published in parts from the existing local project.
The current snapshot includes the x64 CPUID backend for **3.3.1, 3.4.0 and 3.5.0**,
the settings dialog and INI persistence. Later profiles remain visible so settings
can be kept, but their backends are not included here.

| VMProtect | Profile | Architecture | Backend in this repository |
|---|---|---|---|
| 3.3.1 | 331 | x64 | Included |
| 3.4.0 | 340 | x64 | Included |
| 3.5.0 | 350 | x64 | Included |
| 3.6.0 | 360 | x64 | Not published yet |
| 3.8.0 | 380 | x64 | Not published yet |
| 3.9.4 | 394 | x64 | Not published yet |
| 3.10.1 | 3101 | x64 | Not published yet |

The early backend finds CPUID handlers in executable sections at runtime.
It uses the accepted Microsoft Hv / CreatePartitions path observed in the
research samples. There are no fixed sample addresses, executable names or
hashes in the matching logic. Memory execute breakpoints track the handlers;
busy pages may move to free hardware slots without changing target code bytes.
Owned breakpoints are removed when the three-leaf path completes.

This snapshot does not contain firmware scanning hooks, Sandboxie module hooks,
an independent TF handler, or x32 support. Selecting an unpublished profile
reports that its backend is unavailable rather than using another version's backend.

## Use

Select **3.3.1**, **3.4.0** or **3.5.0** under **Plugins > KozVM x64** before
loading the target. With **Enable KozVM**, **Auto-enable on start** and
**CPUID compatibility** enabled, setup is queued at the system breakpoint.
Continue execution normally. For an already paused target, use **Apply to
paused session** before its VM checks execute.

Pause before changing profiles, applying settings or unloading the plugin.
**Status** reports the active backend and CPUID hit counts. Commands are
`kvm_apply` and `kvm_status`; `kvm_hit` is the internal breakpoint callback.
Firmware and Sandboxie controls remain disabled in this snapshot.

Settings are stored beside the DLL in `KozVM.dp64.ini`. The selected profile
uses `Settings/Profile`; enable and startup flags use `Settings/Enabled` and
`Settings/AutoArm`. Global options use `Options/CPUID`, `Options/Firmware` and
`Options/Sandboxie`. Unknown INI keys are preserved. Cancel discards dialog edits.

## Validation and limits

The local early backend previously reached the original entry in the supplied
3.3.1, 3.4.0 and 3.5.0 x64 samples, with all three CPUID leaves handled.
This separated public build passes MSVC Release compilation with `/W4 /WX /analyze`;
it has not had a fresh native regression run after extraction.

Those sample results do not establish compatibility with every protected
program or real VM configuration. Discovery can slow startup. An unsupported
handler layout, unreadable executable page or conflicting memory breakpoint
causes setup to fail with a log message. Keep existing INI files when updating.

## Build

Use Visual Studio 2022 with the C++ tools, CMake 3.20 or newer and the x64dbg plugin SDK.

```powershell
cmake -S . -B build -A x64 -DX64DBG_SDK="C:/path/to/pluginsdk"
cmake --build build --config Release
```

Output: `build/Release/KozVM.dp64`.
Copy it into x64dbg's `plugins` directory to load the plugin. Only the three published early profiles have backends in this snapshot.

## Contact

Ivan Kozlovsky  
[ivankozlovsky.com](https://ivankozlovsky.com)  
contact@ivankozlovsky.com  
[PGP key](https://ivankozlovsky.com/pgp.asc)
