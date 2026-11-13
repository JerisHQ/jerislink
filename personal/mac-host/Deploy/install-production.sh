#!/bin/zsh
# Installs JerisLink.app into ~/Applications and lets the app register its own
# background agents (SMAppService). Also migrates a Mac from the old layout
# (two apps plus three hand-installed LaunchAgents and zsh watchdogs).
#
# Usage: install-production.sh [path/to/JerisLink.app]
#   With no argument it builds the app first (build-apps.sh).
#   Pass a downloaded, notarized JerisLink.app to install that instead.
set -euo pipefail
HERE="${0:A:h}"
ROOT="${HERE:h}"
DEST_DIR="${JERISLINK_INSTALL_DIR:-$HOME/Applications}"
DEST="$DEST_DIR/JerisLink.app"
SUPPORT="$HOME/Library/Application Support/JerisLink"
LAUNCH="$HOME/Library/LaunchAgents"
DOMAIN="gui/$(id -u)"

APP_SRC="${1:-}"
if [[ -z "$APP_SRC" ]]; then
    "$HERE/build-apps.sh" "$ROOT/.dist"
    APP_SRC="$ROOT/.dist/JerisLink.app"
fi
[[ -d "$APP_SRC" ]] || { print -u2 -- "ERROR: $APP_SRC not found"; exit 1; }

# 1. Remove the old layout. network.conf and video-settings.plist are kept.
for name in org.jeris.jerislink.video-watchdog org.jeris.jerislink.input-helper-watchdog org.jeris.jerislink.control; do
    launchctl bootout "$DOMAIN/$name" >/dev/null 2>&1 || true
    rm -f "$LAUNCH/$name.plist"
done
/usr/bin/pkill -f "^$HOME/Applications/JerisLink Host.app/Contents/MacOS/JerisLinkHost" >/dev/null 2>&1 || true
/usr/bin/pkill -f "^$HOME/Applications/JerisLink Input Helper.app/Contents/MacOS/JerisLinkInputHelper" >/dev/null 2>&1 || true
rm -rf "$HOME/Applications/JerisLink Host.app" "$HOME/Applications/JerisLink Input Helper.app" "$SUPPORT/bin"

# 2. Replace the app. Unregister the old copy's agents first so launchd does not
#    keep running binaries from the bundle being replaced.
mkdir -p "$DEST_DIR"
if [[ -x "$DEST/Contents/MacOS/JerisLinkHost" ]]; then
    "$DEST/Contents/MacOS/JerisLinkHost" --unregister || true
fi
rm -rf "$DEST"
ditto "$APP_SRC" "$DEST"

# 3. Logs from an older install may be world-readable: owner only (0600).
for f in /tmp/jerislink-*.log(N) /tmp/jerislink-*.err(N); do
    [[ -O "$f" ]] && chmod 600 "$f"
done

# 4. Register the agents from the installed app.
"$DEST/Contents/MacOS/JerisLinkHost" --register || true
"$DEST/Contents/MacOS/JerisLinkHost" --status

cat <<EOF

JerisLink installed: $DEST
Next, once per Mac (see Deploy/README.md):
  1. Open JerisLink.app once. It asks for Screen Recording and shows the service status.
  2. If it says "requiresApproval", allow JerisLink in System Settings > General > Login Items & Extensions.
  3. Allow Accessibility for "JerisLink Input Helper" when macOS asks (Privacy & Security > Accessibility).
EOF
