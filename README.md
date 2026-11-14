# KozVM

An x64dbg anti-anti-VM plugin for VMProtect. No kernel driver required.

## Public source preview

This repository is being published in parts from the existing local project.
The current commit contains the plugin shell, an About menu and the CMake build setup.
It does **not** include the anti-VM backend or configurable profiles yet.
Building this snapshot will not bypass VM checks.

The local implementation has separate x64 profiles tested with supplied samples
of VMProtect 3.3.1, 3.4.0, 3.5.0, 3.6.0, 3.8.0, 3.9.4 and 3.10.1.
Those tests do not establish compatibility with every protected program or VM configuration.
x32 is not supported yet.

## Build

Use Visual Studio 2022 with the C++ tools, CMake 3.20 or newer and the x64dbg plugin SDK.

```powershell
cmake -S . -B build -A x64 -DX64DBG_SDK="C:/path/to/pluginsdk"
cmake --build build --config Release
```

Output: `build/Release/KozVM.dp64`.
Copy it into x64dbg's `plugins` directory to load the shell.

## Contact

Ivan Kozlovsky  
[ivankozlovsky.com](https://ivankozlovsky.com)  
contact@ivankozlovsky.com  
[PGP key](https://ivankozlovsky.com/pgp.asc)
