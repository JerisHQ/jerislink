#!/bin/zsh
# Builds the single JerisLink.app bundle:
#
#   JerisLink.app/Contents/MacOS/JerisLinkHost                     video host, control service, launcher
#   JerisLink.app/Contents/Helpers/JerisLink Input Helper.app      input injection helper (own bundle id)
#   JerisLink.app/Contents/Library/LaunchAgents/*.plist            agents registered by the app (SMAppService)
#
# Signing, first match wins:
#   1. JERISLINK_DEVELOPER_ID="Developer ID Application: ..."  release signing: hardened runtime + secure timestamp
#   2. "JerisLink Local Code Signing" in the JerisLink signing keychain (local builds, see SIGNING.md)
#   3. JERISLINK_ALLOW_ADHOC=1  ad-hoc, for disposable development and CI builds
set -euo pipefail
HERE="${0:A:h}"
ROOT="${HERE:h}"
OUT="${1:-$ROOT/.dist}"
APP="$OUT/JerisLink.app"
HELPER="$APP/Contents/Helpers/JerisLink Input Helper.app"
ENTITLEMENTS="$HERE/JerisLink.entitlements"

DEVELOPER_ID="${JERISLINK_DEVELOPER_ID:-}"
SIGN_IDENTITY="${JERISLINK_SIGN_IDENTITY:-JerisLink Local Code Signing}"
SIGN_KEYCHAIN="${JERISLINK_SIGN_KEYCHAIN:-$HOME/Library/Keychains/JerisLinkSigning.keychain-db}"
SIGN_KEYCHAIN_PASSWORD_FILE="${JERISLINK_SIGN_KEYCHAIN_PASSWORD_FILE:-$HOME/Library/Application Support/JerisLink/signing/keychain.pass}"
ALLOW_ADHOC="${JERISLINK_ALLOW_ADHOC:-0}"

mkdir -p "$OUT"
cd "$ROOT"
swift build -c release

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$APP/Contents/Library/LaunchAgents" \
         "$HELPER/Contents/MacOS" "$HELPER/Contents/Resources"

/usr/bin/swiftc -O -framework Foundation -framework CoreGraphics \
    InputHelper/JerisLinkInputHelper.swift -o "$HELPER/Contents/MacOS/JerisLinkInputHelper"
cp .build/release/JerisLinkHost "$APP/Contents/MacOS/JerisLinkHost"
cp "$HERE/JerisLink-Info.plist" "$APP/Contents/Info.plist"
cp "$HERE/JerisLinkInputHelper-Info.plist" "$HELPER/Contents/Info.plist"
cp Brand/JerisLink.icns "$APP/Contents/Resources/JerisLink.icns"
cp Brand/JerisLink.icns "$HELPER/Contents/Resources/JerisLink.icns"
cp "$HERE"/LaunchAgents/*.plist "$APP/Contents/Library/LaunchAgents/"

# Single source of the version: VERSION at the repository root.
VERSION="$(head -n 1 "$ROOT/../../VERSION" | tr -d '[:space:]')"
for plist in "$APP/Contents/Info.plist" "$HELPER/Contents/Info.plist"; do
    /usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VERSION" "$plist"
done
for plist in "$APP/Contents/Info.plist" "$HELPER/Contents/Info.plist" "$APP"/Contents/Library/LaunchAgents/*.plist; do
    /usr/bin/plutil -lint "$plist" >/dev/null
done

unlock_local_keychain() {
    [[ -f "$SIGN_KEYCHAIN" && -r "$SIGN_KEYCHAIN_PASSWORD_FILE" ]] || return 1
    local keychain_password
    keychain_password="$(cat "$SIGN_KEYCHAIN_PASSWORD_FILE")"
    /usr/bin/security unlock-keychain -p "$keychain_password" "$SIGN_KEYCHAIN" >/dev/null
}

typeset -a SIGN_ARGS
if [[ -n "$DEVELOPER_ID" ]]; then
    SIGN_MODE="developer-id"
    SIGN_ARGS=(--sign "$DEVELOPER_ID" --timestamp)
    [[ -n "${JERISLINK_SIGN_KEYCHAIN:-}" ]] && SIGN_ARGS+=(--keychain "$JERISLINK_SIGN_KEYCHAIN")
elif unlock_local_keychain && \
     /usr/bin/security find-certificate -c "$SIGN_IDENTITY" "$SIGN_KEYCHAIN" >/dev/null 2>&1; then
    SIGN_MODE="local"
    SIGN_ARGS=(--sign "$SIGN_IDENTITY" --keychain "$SIGN_KEYCHAIN" --timestamp=none)
elif [[ "$ALLOW_ADHOC" == "1" ]]; then
    SIGN_MODE="ad-hoc"
    print -u2 -- "WARNING: no Developer ID and no stable JerisLink signing identity; using ad-hoc signing"
    SIGN_ARGS=(--sign - --timestamp=none)
else
    print -u2 -- "ERROR: code-signing identity '$SIGN_IDENTITY' not found in $SIGN_KEYCHAIN"
    print -u2 -- "Set JERISLINK_DEVELOPER_ID for release signing, or JERISLINK_ALLOW_ADHOC=1 for disposable builds."
    exit 1
fi

# Sign inside-out: nested helper app first, then the outer app. No --deep.
for target in "$HELPER" "$APP"; do
    /usr/bin/codesign --force --options runtime --entitlements "$ENTITLEMENTS" "${SIGN_ARGS[@]}" "$target"
done
/usr/bin/codesign --verify --strict --deep "$APP"

echo "Built: $APP"
echo "Version: $VERSION"
echo "Signing: $SIGN_MODE"
