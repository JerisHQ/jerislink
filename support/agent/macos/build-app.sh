#!/bin/zsh
set -euo pipefail
HERE="${0:A:h}"
ROOT="${HERE:h:h}"
OUT="${1:-$ROOT/.dist}"
CORE_ROOT="${JERISLINK_CORE_ROOT:-${ROOT:h}/personal/mac-host}"
APP="$OUT/JerisLink Support.app"
RES="$APP/Contents/Resources"
MACOS="$APP/Contents/MacOS"
SIGN_IDENTITY="${JERISLINK_SIGN_IDENTITY:-JerisLink Local Code Signing}"
SIGN_KEYCHAIN="${JERISLINK_SIGN_KEYCHAIN:-$HOME/Library/Keychains/JerisLinkSigning.keychain-db}"
SIGN_KEYCHAIN_PASSWORD_FILE="${JERISLINK_SIGN_KEYCHAIN_PASSWORD_FILE:-$HOME/Library/Application Support/JerisLink/signing/keychain.pass}"
ALLOW_ADHOC="${JERISLINK_ALLOW_ADHOC:-0}"

mkdir -p "$OUT"
rm -rf "$APP"
mkdir -p "$MACOS" "$RES"

cd "$ROOT"
GOOS=darwin GOARCH=arm64 go build -trimpath -o "$RES/jeris-support-agent-darwin-arm64" ./cmd/jeris-support-agent
GOOS=darwin GOARCH=arm64 go build -trimpath -o "$RES/jeris-support-transport-darwin-arm64" ./cmd/jeris-support-transport

cd "$CORE_ROOT"
CORE_BIN="$CORE_ROOT/.build/release/JerisLinkHost"
NEED_CORE_BUILD=0
if [[ ! -x "$CORE_BIN" ]]; then
    NEED_CORE_BUILD=1
elif [[ "$CORE_ROOT/Package.swift" -nt "$CORE_BIN" ]]; then
    NEED_CORE_BUILD=1
elif /usr/bin/find "$CORE_ROOT/Sources" -type f -newer "$CORE_BIN" -print -quit | /usr/bin/grep -q .; then
    NEED_CORE_BUILD=1
fi
if [[ "$NEED_CORE_BUILD" == "1" ]]; then
    swift build -c release
else
    echo "Reusing current JerisLinkHost release binary: $CORE_BIN"
fi
cp "$CORE_BIN" "$RES/JerisLinkHost"
cp Brand/JerisLink.icns "$RES/JerisLinkSupport.icns"

/usr/bin/swiftc -O \
  -framework AppKit \
  -framework Foundation \
  "$HERE/JerisLinkSupportRuntime.swift" \
  "$HERE/JerisLinkSupportApp.swift" \
  -o "$MACOS/JerisLinkSupport"
cp "$HERE/Info.plist" "$APP/Contents/Info.plist"
chmod 755 "$MACOS/JerisLinkSupport" "$RES/jeris-support-agent-darwin-arm64" "$RES/jeris-support-transport-darwin-arm64" "$RES/JerisLinkHost"

unlock_signing_keychain() {
    [[ -r "$SIGN_KEYCHAIN_PASSWORD_FILE" ]] || return 1
    local keychain_password
    keychain_password="$(cat "$SIGN_KEYCHAIN_PASSWORD_FILE")"
    /usr/bin/security unlock-keychain -p "$keychain_password" "$SIGN_KEYCHAIN" >/dev/null
}

sign_app() {
    if [[ -f "$SIGN_KEYCHAIN" ]] && unlock_signing_keychain && \
       /usr/bin/security find-certificate -c "$SIGN_IDENTITY" "$SIGN_KEYCHAIN" >/dev/null 2>&1; then
        /usr/bin/codesign --force --deep --sign "$SIGN_IDENTITY" --keychain "$SIGN_KEYCHAIN" "$APP"
        return
    fi
    if [[ "$ALLOW_ADHOC" == "1" ]]; then
        print -u2 -- "WARNING: using ad-hoc signing for $APP"
        /usr/bin/codesign --force --deep --sign - "$APP"
        return
    fi
    print -u2 -- "ERROR: code-signing identity '$SIGN_IDENTITY' unavailable"
    return 1
}

sign_app
/usr/bin/codesign --verify --deep --strict "$APP"
"$MACOS/JerisLinkSupport" --self-test

echo "Built: $APP"
echo "Signed with: $SIGN_IDENTITY"
