# KozVM

An x64dbg anti-anti-VM plugin for VMProtect 3.3.1 through 3.10.1. No kernel driver required.

This commit publishes all seven x64 backends: 331, 340, 350, 360, 380, 394 and 3101.
Each version has a separate profile. The 394 and 3101 profiles also handle the
firmware scanner and Sandboxie module query after the accepted CPUID path.
Addresses are discovered in the loaded target, not selected by sample name or RVA.

The guard-based discovery in this commit can take minutes. The next update adds
bounded snapshot discovery to replace page monitoring with hardware breakpoints.
x32 development has not started; there is no x32 build.

## Build

Use Visual Studio 2022 C++ tools, CMake and the x64dbg SDK.

```powershell
cmake -S . -B build -A x64 -DX64DBG_SDK="C:/path/to/pluginsdk"
cmake --build build --config Release
```

Output: `build/Release/KozVM.dp64`. Settings: `KozVM.dp64.ini` beside the plugin.
Keep existing INI files when updating. Tested examples do not establish compatibility
with every protected binary. See LICENSE for GPLv2 terms.

Ivan Kozlovsky — https://ivankozlovsky.com — contact@ivankozlovsky.com
