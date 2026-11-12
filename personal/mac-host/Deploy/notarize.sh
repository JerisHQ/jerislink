#!/bin/zsh
# Notarizes a Developer ID signed JerisLink.app, staples the ticket and writes
# a distributable zip.
#
# Usage: notarize.sh <path/to/JerisLink.app> <output.zip>
#
# App Store Connect API key (see SIGNING.md):
#   JERISLINK_NOTARY_KEY_PATH  path to the AuthKey_XXXX.p8 file
#   JERISLINK_NOTARY_KEY_ID    key ID
#   JERISLINK_NOTARY_ISSUER    issuer ID (team keys); leave empty for an individual key
set -euo pipefail
APP="${1:?usage: notarize.sh <JerisLink.app> <output.zip>}"
OUT_ZIP="${2:?usage: notarize.sh <JerisLink.app> <output.zip>}"
KEY_PATH="${JERISLINK_NOTARY_KEY_PATH:?JERISLINK_NOTARY_KEY_PATH is not set}"
KEY_ID="${JERISLINK_NOTARY_KEY_ID:?JERISLINK_NOTARY_KEY_ID is not set}"
ISSUER="${JERISLINK_NOTARY_ISSUER:-}"

typeset -a AUTH
AUTH=(--key "$KEY_PATH" --key-id "$KEY_ID")
[[ -n "$ISSUER" ]] && AUTH+=(--issuer "$ISSUER")

tmp="$(mktemp -d "${TMPDIR:-/tmp}/jerislink-notary.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

/usr/bin/codesign --verify --strict --deep "$APP"
/usr/bin/ditto -c -k --sequesterRsrc --keepParent "$APP" "$tmp/submit.zip"

/usr/bin/xcrun notarytool submit "$tmp/submit.zip" "${AUTH[@]}" \
    --wait --timeout 30m --output-format json > "$tmp/result.json"
cat "$tmp/result.json"
echo
notary_status="$(/usr/bin/plutil -extract status raw -o - "$tmp/result.json")"
submission="$(/usr/bin/plutil -extract id raw -o - "$tmp/result.json")"
if [[ "$notary_status" != "Accepted" ]]; then
    print -u2 -- "ERROR: notarization status '$notary_status' for submission $submission"
    /usr/bin/xcrun notarytool log "$submission" "${AUTH[@]}" || true
    exit 1
fi

/usr/bin/xcrun stapler staple "$APP"
/usr/bin/xcrun stapler validate "$APP"
mkdir -p "${OUT_ZIP:h}"
rm -f "$OUT_ZIP"
/usr/bin/ditto -c -k --sequesterRsrc --keepParent "$APP" "$OUT_ZIP"
echo "Notarized and stapled: $APP"
echo "Package: $OUT_ZIP"
