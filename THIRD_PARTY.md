# Third-party components

KozVM uses the unmodified Windows x64 Unicorn 2.1.4 runtime for isolated snapshot execution. Unicorn is distributed under GPLv2; its public headers carry LGPL notices. License texts are included in runtime/COPYING and runtime/COPYING.LGPL2. Upstream: https://github.com/unicorn-engine/unicorn

tools/fetch_unicorn.py downloads pinned PyPI distributions and checks their SHA-256 hashes. The release source ZIP includes the corresponding Unicorn source distribution under third_party/source, including its QEMU sources.

The x64dbg SDK is an external build dependency, not bundled here. Upstream: https://github.com/x64dbg/x64dbg

tools/make_icon.py optionally uses Pillow to regenerate the supplied icon assets. Pillow is not a plugin runtime dependency.
