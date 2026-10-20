#!/bin/bash
# Add Lantern to your Linux desktop's app menu (per user, no root needed).
# Uses dist/Lantern if you've run ./build.sh, otherwise runs lantern.py with python3.
# Remove with: ./install-linux.sh --uninstall

set -e
cd "$(dirname "$0")"
DIR="$(pwd)"
APPS="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
ICONS="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor"
SIZES="32 48 128 256 512"

if [ "$1" = "--uninstall" ]; then
    rm -f "$APPS/lantern.desktop"
    for s in $SIZES; do rm -f "$ICONS/${s}x${s}/apps/lantern.png"; done
    echo "🏮 Lantern removed from the app menu"
    exit 0
fi

if [ -x "$DIR/dist/Lantern" ]; then
    EXEC="\"$DIR/dist/Lantern\""
else
    EXEC="python3 \"$DIR/lantern.py\""
fi

mkdir -p "$APPS"
for s in $SIZES; do
    mkdir -p "$ICONS/${s}x${s}/apps"
    cp "assets/lantern-$s.png" "$ICONS/${s}x${s}/apps/lantern.png"
done
sed "s|^Exec=.*|Exec=$EXEC|" assets/lantern.desktop > "$APPS/lantern.desktop"

command -v update-desktop-database &> /dev/null && update-desktop-database -q "$APPS" || true
command -v gtk-update-icon-cache &> /dev/null && gtk-update-icon-cache -q -t "$ICONS" || true

echo "🏮 Lantern added to your app menu (runs: $EXEC)"
