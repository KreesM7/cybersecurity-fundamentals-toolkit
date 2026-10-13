# Building desktop distributions

Build on the target operating system: Windows x64 or Ubuntu 24.04 x86_64. Install Python 3.12, then:

```
python -m pip install uv==0.12.24
python -m uv sync --locked --extra dev --extra build --python 3.12
python -m uv run --no-sync python scripts/prepare_windows_runtime.py # Windows only
python -m uv run --no-sync python -m PyInstaller --noconfirm toolkit.spec
python -m uv run --no-sync python scripts/build_inventory.py build/toolkit/Analysis-00.toc work/compliance --bundle dist/CybersecurityFundamentalsToolkit --download-sources
```

The result is a one-folder desktop in `dist/CybersecurityFundamentalsToolkit`. The spec discovers tools/views, includes migrations, themes and resources, and excludes Scapy, its worker, WeasyPrint and development-only modules. Packaged PDF requests explicitly fall back to HTML. Linux system libraries remain host prerequisites; use Ubuntu 24.04+ and install the Qt runtime dependencies listed in README. Builds are unsigned.

Use `scripts/stage_release.py BUNDLE COMPLIANCE --native-notices NOTICES` to stage reviewed native notices and final binary hashes. The Windows spec uses the checksum-pinned CPython x64 libffi 3.4.4 build staged by `prepare_windows_runtime.py`, leaving installed Python unchanged.

Copy `work/compliance/inventory.json` and `work/compliance/licenses` into a `compliance` folder in the frozen directory. Copy LICENSE, COPYING, THIRD_PARTY_NOTICES.md and documentation alongside it. Retain dependency source archives as a separate corresponding-source release asset. Include the exact Qt and Python sources referenced by the inventory, native runtime notices, and these build recipes. Scan the final inventory before release; the inventory generator does not by itself certify license compliance.

## Windows

Use Inno Setup 7.1.0 or a compatible compiler:

```
ISCC.exe packaging/windows/toolkit.iss
```

The per-user installer goes to `dist/installers/Toolkit-2.1.0-Windows-x64-Setup.exe`. It does not install external tools or remove user profiles during uninstall. Zip the complete frozen directory for a portable alternative; the executable cannot be moved away from `_internal`.

Smoke-test with a fresh temporary profile and from a different working directory:

```
CybersecurityFundamentalsToolkit.exe --self-test --self-test-report result.json
```

The self-test traverses every panel, establishes authenticated HTTPS/WSS, and shuts down. Check process exit 0 and `ok: true` in the JSON report. Installation and uninstallation need separate smoke tests in a disposable destination.

## Linux

Use appimagetool continuous build 854e19e (2026-10-04), SHA-256
`95cbe7cce9717fce90c484e34052ee7c7f1d7635b33c12525b4776826a7d29b6`.
Download the official type2-runtime `runtime-x86_64` to `work/runtime-x86_64`,
SHA-256 `156f4bdbde9c52d01814600013e0a273f0118dc2de98975f3c8c63427ec79074`
(source commit `8f39b89e2ac31e1640b3d3f7e9a5108e6ce805fa`). Both tools are available
from their AppImage GitHub releases; the build script rejects changed downloads
rather than silently selecting a new continuous build. Then:

```
APPIMAGETOOL=/absolute/path/appimagetool-x86_64.AppImage sh packaging/linux/build-appimage.sh
chmod +x dist/installers/Toolkit-2.1.0-Linux-x86_64.AppImage
dist/installers/Toolkit-2.1.0-Linux-x86_64.AppImage --appimage-extract-and-run --self-test
```

`--appimage-extract-and-run` supports machines without FUSE. The AppImage runtime license must be included in notices. The Debian directory is a package skeleton, not a verified .deb release. Dockerfile is only for tests, not a network-accessible backend deployment.

## Corresponding source and replacement

The repository/tag contains all original source, templates, migration scripts, resources and packaging instructions. Release dependency sources have versions/hashes matching each platform inventory. Qt's complete source is available at the inventory's versioned Qt URL; preserve its third-party notices. Build Qt using the included upstream CMake instructions and PyQt6 using its included SIP instructions. Replace the matching libraries under `_internal/PyQt6/Qt6` or rebuild the entire folder using the modified dependency wheels. No signing check prevents replacement. Preserve ABI compatibility, then repeat startup/tests.

Python extensions include their upstream source/build manifests; install an appropriate C/C++/Rust toolchain when rebuilding them. Windows Microsoft runtime libraries use their upstream redistribution terms rather than GPL. Unchanged Linux operating-system libraries excluded from the bundle remain managed by the distribution.

A release requires passing CI on all four platform/Python combinations, matching independent security signoff, installer smoke results, a reviewed software inventory, source availability and SHA256SUMS. Do not publish an incomplete candidate as a completed release.

