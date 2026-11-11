#!/bin/zsh
set -euo pipefail
HERE="${0:A:h}"
ROOT="${HERE:h}"
HOME_DIR="$HOME"
DIST="$ROOT/.dist"
SUPPORT="$HOME_DIR/Library/Application Support/JerisLink"
LAUNCH="$HOME_DIR/Library/LaunchAgents"
DOMAIN="gui/$(id -u)"

"$HERE/build-apps.sh" "$DIST"
mkdir -p "$HOME_DIR/Applications" "$SUPPORT/bin" "$LAUNCH"
rm -rf "$HOME_DIR/Applications/JerisLink Host.app" "$HOME_DIR/Applications/JerisLink Input Helper.app"
ditto "$DIST/JerisLink Host.app" "$HOME_DIR/Applications/JerisLink Host.app"
ditto "$DIST/JerisLink Input Helper.app" "$HOME_DIR/Applications/JerisLink Input Helper.app"
cp "$ROOT/.build/release/JerisLinkHost" "$SUPPORT/bin/JerisLinkHost"
cp "$HERE/video-watchdog.zsh" "$SUPPORT/bin/video-watchdog.zsh"
cp "$HERE/input-helper-watchdog.zsh" "$SUPPORT/bin/input-helper-watchdog.zsh"
chmod +x "$SUPPORT/bin/"*

for name in org.jeris.jerislink.control org.jeris.jerislink.input-helper-watchdog org.jeris.jerislink.video-watchdog; do
    sed "s#__HOME__#$HOME_DIR#g" "$HERE/$name.plist" > "$LAUNCH/$name.plist"
    plutil -lint "$LAUNCH/$name.plist" >/dev/null
    launchctl bootout "$DOMAIN/$name" >/dev/null 2>&1 || true
done

launchctl bootstrap "$DOMAIN" "$LAUNCH/org.jeris.jerislink.input-helper-watchdog.plist"
launchctl bootstrap "$DOMAIN" "$LAUNCH/org.jeris.jerislink.control.plist"
launchctl bootstrap "$DOMAIN" "$LAUNCH/org.jeris.jerislink.video-watchdog.plist"

echo "JerisLink production services installed."
echo "On a fresh Mac, approve Screen Recording for JerisLink Host and Accessibility for JerisLink Input Helper if macOS prompts."
