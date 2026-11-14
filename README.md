# KozVM

An x64dbg anti-anti-VM plugin for VMProtect. No kernel driver required.

## Public source preview

This repository is being published in parts from the existing local project.
The current snapshot contains the settings dialog, separate version profiles,
INI persistence and the CMake build setup.
It does **not** include the anti-VM backend yet.
Building this snapshot will not bypass VM checks.

The local implementation has separate x64 profiles tested with supplied samples
of VMProtect 3.3.1, 3.4.0, 3.5.0, 3.6.0, 3.8.0, 3.9.4 and 3.10.1.
Those tests do not establish compatibility with every protected program or VM configuration.
x32 is not supported yet.

## Profiles and settings

Select a profile from **Plugins > KozVM x64**, or open **Settings...**.

| VMProtect | Profile | Architecture |
|---|---|---|
| 3.3.1 | 331 | x64 |
| 3.4.0 | 340 | x64 |
| 3.5.0 | 350 | x64 |
| 3.6.0 | 360 | x64 |
| 3.8.0 | 380 | x64 |
| 3.9.4 | 394 | x64 |
| 3.10.1 | 3101 | x64 |

The compact dialog has enable/auto-enable settings and CPUID, firmware and
Sandboxie options, each with a question-mark tooltip. Firmware and module
options are available for 394 and 3101; earlier profiles use the CPUID policy.
These controls only save configuration in this public snapshot. They do not
install hooks, modify registers or handle VM checks.

Settings are stored beside the DLL in `KozVM.dp64.ini`. The selected profile
uses `Settings/Profile`; enable and startup flags use `Settings/Enabled` and
`Settings/AutoArm`. Global options use `Options/CPUID`, `Options/Firmware` and
`Options/Sandboxie`. Unknown INI keys are preserved. Cancel discards dialog edits.

## Build

Use Visual Studio 2022 with the C++ tools, CMake 3.20 or newer and the x64dbg plugin SDK.

```powershell
cmake -S . -B build -A x64 -DX64DBG_SDK="C:/path/to/pluginsdk"
cmake --build build --config Release
```

Output: `build/Release/KozVM.dp64`.
Copy it into x64dbg's `plugins` directory to load the GUI/profile preview. This is not a replacement for a working backend build.

## Contact

Ivan Kozlovsky  
[ivankozlovsky.com](https://ivankozlovsky.com)  
contact@ivankozlovsky.com  
[PGP key](https://ivankozlovsky.com/pgp.asc)
