# KozVM

An open-source anti-anti-VM plugin for x64dbg, built from my VMProtect research. **No kernel driver required.**

KozVM discovers addresses in the loaded target instead of relying on sample names or fixed addresses. Each tested version has its own profile, selectable from the Plugins menu or the settings window.

## Supported versions

| VMProtect | Profile | x64 | x32 |
|---|---|---|---|
| 3.3.1 | 331 | Tested | Not implemented |
| 3.4.0 | 340 | Tested | Not implemented |
| 3.5.0 | 350 | Tested | Not implemented |
| 3.6.0 | 360 | Tested | Not implemented |
| 3.8.0 | 380 | Tested | Not implemented |
| 3.9.4 | 394 | Tested | Not implemented |
| 3.10.1 | 3101 | Tested | Not implemented |

Tests used our protected BasicProbe samples. Passing these tests does not guarantee compatibility with every protected program or configuration. x32 development has not started.

## Installation

Download the x64 ZIP from [Releases](https://github.com/ivanpotatoes/KozVM/releases/latest). With x64dbg closed, copy its plugins folder contents into your debugger's plugins folder.

The package includes KozVM.dp64, KozVM.dp64.ini and the KozVM runtime folder containing unicorn.dll and its license texts. Keep the runtime folder beside the plugin. **Keep your existing INI when updating** to preserve your settings.

Unicorn requires the Microsoft Visual C++ x64 runtime. Python is only needed to prepare a source build.

## Usage

1. Select the matching version under Plugins > KozVM.
2. Leave auto-arm enabled and load the protected executable.
3. Run the target. Check the debugger log for discovery and installation results.

The settings window offers CPUID handling across the supported profiles. The 3.9.4 and 3.10.1 profiles additionally handle the firmware scanner and Sandboxie module query. These options affect the debugged process, not your VM configuration globally.

Unicorn executes an isolated snapshot to discover CPUID sites, then KozVM installs hardware breakpoints in the live target. Unrecognized paths fall back to slower guarded discovery and are reported in the log. Available hardware breakpoint slots can affect installation.

## Profiles

KozVM.dp64.ini stores the selected profile, auto-arm setting and individual options. Profile IDs are listed above. The implementations are C++ code; adding an INI entry alone does not implement a new VMProtect version.

## Build

Use Visual Studio 2022 C++ tools, CMake, Python 3 and the x64dbg SDK.

```powershell
python tools/fetch_unicorn.py
cmake -S . -B build -A x64 -DX64DBG_SDK="C:/path/to/pluginsdk"
cmake --build build --config Release
```

Output: build/Release/KozVM.dp64 and its KozVM runtime directory. The dependency script downloads pinned Unicorn 2.1.4 runtime and source archives and verifies their SHA-256 hashes.

main contains the published project, x64 tracks the x64 implementation, and x32 is reserved for future development.

## License and contact

GPLv2. See [LICENSE](LICENSE) and [THIRD_PARTY.md](THIRD_PARTY.md). Release source packages include the corresponding Unicorn source archive.

Ivan Kozlovsky

- Website and research: https://ivankozlovsky.com
- Email: contact@ivankozlovsky.com
- PGP: https://ivankozlovsky.com/pgp.asc
- Bug reports: https://github.com/ivanpotatoes/KozVM/issues
