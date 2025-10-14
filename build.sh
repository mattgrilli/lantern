#!/bin/bash
# Build script for Lantern Network Scanner
# Creates a standalone macOS .app bundle

set -e  # Exit on error

echo "🏮 Building Lantern Network Scanner..."

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 is required but not installed."
    echo "Install from: https://www.python.org/downloads/"
    exit 1
fi

# Check Python version
PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
echo "✓ Found Python $PYTHON_VERSION"

# Install PyInstaller if not present
if ! python3 -m pip show pyinstaller &> /dev/null; then
    echo "📦 Installing PyInstaller..."
    python3 -m pip install pyinstaller
else
    echo "✓ PyInstaller already installed"
fi

# Clean previous builds
echo "🗑️  Cleaning previous builds..."
rm -rf build/ dist/ *.spec

# Create the app bundle
echo "🔨 Building Lantern.app..."
python3 -m PyInstaller \
    --name="Lantern" \
    --windowed \
    --onefile \
    --clean \
    --noconfirm \
    --osx-bundle-identifier="com.lantern.networkscanner" \
    --add-data="scanner_data.json:." \
    scanner.py

# Check if build succeeded
if [ ! -d "dist/Lantern.app" ]; then
    echo "❌ Build failed!"
    exit 1
fi

echo "✅ Build complete!"
echo ""
echo "📦 Lantern.app created in: dist/Lantern.app"
echo ""
echo "📋 Next steps:"
echo "   1. Test the app: open dist/Lantern.app"
echo "   2. Move to Applications: cp -r dist/Lantern.app /Applications/"
echo "   3. Create DMG (optional): ./create_dmg.sh"
echo ""
echo "🎉 Done!"