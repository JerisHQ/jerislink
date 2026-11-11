#!/bin/zsh
set -euo pipefail
HERE="${0:A:h}"
ROOT="${HERE:h}"
OUT="${1:-$ROOT/.dist}"
SIGN_IDENTITY="${JERISLINK_SIGN_IDENTITY:-JerisLink Local Code Signing}"
SIGN_KEYCHAIN="${JERISLINK_SIGN_KEYCHAIN:-$HOME/Library/Keychains/JerisLinkSigning.keychain-db}"
SIGN_KEYCHAIN_PASSWORD_FILE="${JERISLINK_SIGN_KEYCHAIN_PASSWORD_FILE:-$HOME/Library/Application Support/JerisLink/signing/keychain.pass}"
ALLOW_ADHOC="${JERISLINK_ALLOW_ADHOC:-0}"

mkdir -p "$OUT"
cd "$ROOT"
swift build -c release
/usr/bin/swiftc -O -framework Foundation -framework CoreGraphics InputHelper/JerisLinkInputHelper.swift -o "$OUT/JerisLinkInputHelper"
for app in 'JerisLink Host' 'JerisLink Input Helper'; do
    rm -rf "$OUT/$app.app"
    mkdir -p "$OUT/$app.app/Contents/MacOS" "$OUT/$app.app/Contents/Resources"
done
cp .build/release/JerisLinkHost "$OUT/JerisLink Host.app/Contents/MacOS/JerisLinkHost"
cp "$OUT/JerisLinkInputHelper" "$OUT/JerisLink Input Helper.app/Contents/MacOS/JerisLinkInputHelper"
cp "$HERE/JerisLinkHost-Info.plist" "$OUT/JerisLink Host.app/Contents/Info.plist"
cp "$HERE/JerisLinkInputHelper-Info.plist" "$OUT/JerisLink Input Helper.app/Contents/Info.plist"
cp Brand/JerisLink.icns "$OUT/JerisLink Host.app/Contents/Resources/JerisLink.icns"
cp Brand/JerisLink.icns "$OUT/JerisLink Input Helper.app/Contents/Resources/JerisLink.icns"

# Single source of the version: VERSION at the repository root.
VERSION="$(head -n 1 "$ROOT/../../VERSION" | tr -d '[:space:]')"
for app in 'JerisLink Host' 'JerisLink Input Helper'; do
    /usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VERSION" "$OUT/$app.app/Contents/Info.plist"
done

unlock_signing_keychain() {
    [[ -r "$SIGN_KEYCHAIN_PASSWORD_FILE" ]] || return 1
    local keychain_password
    keychain_password="$(cat "$SIGN_KEYCHAIN_PASSWORD_FILE")"
    /usr/bin/security unlock-keychain -p "$keychain_password" "$SIGN_KEYCHAIN" >/dev/null
}

sign_app() {
    local app="$1"
    if [[ -f "$SIGN_KEYCHAIN" ]] && unlock_signing_keychain && \
       /usr/bin/security find-certificate -c "$SIGN_IDENTITY" "$SIGN_KEYCHAIN" >/dev/null 2>&1; then
        /usr/bin/codesign --force --deep --sign "$SIGN_IDENTITY" --keychain "$SIGN_KEYCHAIN" "$app"
        return
    fi
    if [[ "$ALLOW_ADHOC" == "1" ]]; then
        print -u2 -- "WARNING: stable JerisLink signing identity not found; using ad-hoc signing for $app"
        /usr/bin/codesign --force --deep --sign - "$app"
        return
    fi
    print -u2 -- "ERROR: code-signing identity '$SIGN_IDENTITY' not found in $SIGN_KEYCHAIN"
    print -u2 -- "Set JERISLINK_ALLOW_ADHOC=1 only for disposable development builds."
    return 1
}

sign_app "$OUT/JerisLink Host.app"
sign_app "$OUT/JerisLink Input Helper.app"

echo "Built: $OUT/JerisLink Host.app"
echo "Built: $OUT/JerisLink Input Helper.app"
echo "Signed with: $SIGN_IDENTITY"
