#!/bin/bash
# Create a DMG installer for Lantern
# Run this after build.sh completes successfully

set -e

echo "🏮 Creating Lantern DMG installer..."

# Check if app exists
if [ ! -d "dist/Lantern.app" ]; then
    echo "❌ Error: Lantern.app not found in dist/"
    echo "Run ./build.sh first!"
    exit 1
fi

cd "$(dirname "$0")"

VERSION=$(python3 -c 'import re; print(re.search(r"__version__ = \"(.+?)\"", open("lantern.py", encoding="utf-8").read()).group(1))')
DMG_NAME="Lantern-${VERSION}"

# Create temporary DMG directory
echo "📁 Creating DMG structure..."
rm -rf dist/dmg
mkdir -p dist/dmg
cp -r dist/Lantern.app dist/dmg/

# Create Applications symlink for easy drag-and-drop
ln -s /Applications dist/dmg/Applications

# Create DMG
echo "💿 Creating DMG..."
hdiutil create \
    -volname "Lantern Network Scanner" \
    -srcfolder dist/dmg \
    -ov \
    -format UDZO \
    "dist/${DMG_NAME}.dmg"

# Clean up
rm -rf dist/dmg

# Get DMG size
DMG_SIZE=$(du -h "dist/${DMG_NAME}.dmg" | cut -f1)

echo "✅ DMG created successfully!"
echo ""
echo "📦 File: dist/${DMG_NAME}.dmg"
echo "💾 Size: ${DMG_SIZE}"
echo ""
echo "📋 To distribute:"
echo "   1. Test: open dist/${DMG_NAME}.dmg"
echo "   2. Upload to GitHub Releases"
echo "   3. (Optional) Code sign: codesign -s 'Developer ID' dist/${DMG_NAME}.dmg"
echo ""
echo "🎉 Done!"