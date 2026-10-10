#!/bin/sh
# Run from the repository root after a native Linux PyInstaller build.
set -eu
: "${APPIMAGETOOL:?Set APPIMAGETOOL to a verified appimagetool executable}"
RUNTIME=${APPIMAGE_RUNTIME:-work/runtime-x86_64}
test "$(sha256sum "$APPIMAGETOOL" | cut -d ' ' -f 1)" = 95cbe7cce9717fce90c484e34052ee7c7f1d7635b33c12525b4776826a7d29b6
test "$(sha256sum "$RUNTIME" | cut -d ' ' -f 1)" = 156f4bdbde9c52d01814600013e0a273f0118dc2de98975f3c8c63427ec79074
SOURCE=${1:-dist/CybersecurityFundamentalsToolkit}
DEST=${2:-work/Toolkit.AppDir}
test ! -e "$DEST" || { echo "Choose a new AppDir; refusing to overwrite." >&2; exit 1; }
mkdir -p "$DEST/usr/lib" dist/installers
cp -a "$SOURCE" "$DEST/usr/lib/toolkit"
cp packaging/linux/AppRun "$DEST/AppRun"
cp packaging/linux/toolkit.desktop packaging/linux/toolkit.svg "$DEST/"
chmod +x "$DEST/AppRun"
ARCH=x86_64 "$APPIMAGETOOL" --appimage-extract-and-run --runtime-file "$RUNTIME" "$DEST" dist/installers/Toolkit-2.0.0-Linux-x86_64.AppImage
