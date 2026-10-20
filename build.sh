#!/bin/bash
# Build a standalone Lantern app with PyInstaller.
# macOS: dist/Lantern.app   Linux: dist/Lantern
# (Windows: py -m PyInstaller --name Lantern --windowed --onefile --collect-submodules zeroconf
#           --add-data "assets;assets" --icon assets\lantern.ico lantern.py)

set -e
cd "$(dirname "$0")"

echo "🏮 Building Lantern..."

if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required: https://www.python.org/downloads/"
    exit 1
fi

if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))'; then
    echo "❌ Python 3.9 or newer is required (found $(python3 --version))"
    exit 1
fi

VERSION=$(python3 -c 'import re; print(re.search(r"__version__ = \"(.+?)\"", open("lantern.py").read()).group(1))')
echo "✓ Lantern $VERSION, $(python3 --version)"

if ! python3 -m PyInstaller --version &> /dev/null; then
    echo "📦 Installing PyInstaller..."
    python3 -m pip install pyinstaller
fi

# zeroconf is optional when running from source, but built apps always bundle it
# so mDNS printer discovery works out of the box.
if ! python3 -c 'import zeroconf' &> /dev/null; then
    echo "📦 Installing zeroconf..."
    python3 -m pip install zeroconf
fi
echo "✓ Bundling zeroconf for mDNS printer discovery"

# PyInstaller needs Pillow to turn the PNG icon into a macOS .icns.
if [ "$(uname)" = "Darwin" ] && ! python3 -c 'import PIL' &> /dev/null; then
    echo "📦 Installing Pillow (for the app icon)..."
    python3 -m pip install Pillow
fi

rm -rf build/ dist/ Lantern.spec

python3 -m PyInstaller \
    --name="Lantern" \
    --windowed \
    --onefile \
    --clean \
    --noconfirm \
    --osx-bundle-identifier="com.lantern.networkscanner" \
    --collect-submodules zeroconf \
    --add-data "assets:assets" \
    --icon assets/lantern-512.png \
    lantern.py

if [ "$(uname)" = "Darwin" ]; then
    OUTPUT="dist/Lantern.app"
else
    OUTPUT="dist/Lantern"
fi

if [ ! -e "$OUTPUT" ]; then
    echo "❌ Build failed: $OUTPUT not found"
    exit 1
fi

echo "✅ Built $OUTPUT"
if [ "$(uname)" = "Darwin" ]; then
    echo "   Next: open $OUTPUT, then ./create_dmg.sh to package it"
fi
