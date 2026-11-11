#!/bin/zsh
set -euo pipefail

NAME="${JERISLINK_SIGN_IDENTITY:-JerisLink Local Code Signing}"
KEYCHAIN="${JERISLINK_SIGN_KEYCHAIN:-$HOME/Library/Keychains/JerisLinkSigning.keychain-db}"
PASS_DIR="$HOME/Library/Application Support/JerisLink/signing"
PASS_FILE="${JERISLINK_SIGN_KEYCHAIN_PASSWORD_FILE:-$PASS_DIR/keychain.pass}"

mkdir -p "$PASS_DIR"
chmod 700 "$PASS_DIR"

if [[ -f "$KEYCHAIN" && ! -r "$PASS_FILE" ]]; then
    print -u2 -- "ERROR: signing keychain exists but password file is missing: $PASS_FILE"
    exit 1
fi

if [[ ! -f "$KEYCHAIN" ]]; then
    keychain_password="$(/usr/bin/openssl rand -hex 24)"
    print -rn -- "$keychain_password" > "$PASS_FILE"
    chmod 600 "$PASS_FILE"
    /usr/bin/security create-keychain -p "$keychain_password" "$KEYCHAIN"
    /usr/bin/security set-keychain-settings -lut 21600 "$KEYCHAIN"
fi

keychain_password="$(cat "$PASS_FILE")"
/usr/bin/security unlock-keychain -p "$keychain_password" "$KEYCHAIN"

if ! /usr/bin/security find-certificate -c "$NAME" "$KEYCHAIN" >/dev/null 2>&1; then
    tmp="$(mktemp -d /tmp/jerislink-signing.XXXXXX)"
    trap 'rm -rf "$tmp"' EXIT
    p12_password="$(/usr/bin/openssl rand -hex 24)"

    /usr/bin/openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 3650 \
        -subj '/CN=JerisLink Local Code Signing/O=Jeris/OU=Infrastructure' \
        -addext 'keyUsage=critical,digitalSignature' \
        -addext 'extendedKeyUsage=critical,codeSigning' \
        -keyout "$tmp/key.pem" -out "$tmp/cert.pem" >/dev/null 2>&1
    /usr/bin/openssl pkcs12 -export -legacy \
        -inkey "$tmp/key.pem" -in "$tmp/cert.pem" \
        -out "$tmp/identity.p12" -passout pass:"$p12_password" >/dev/null 2>&1
    /usr/bin/security import "$tmp/identity.p12" -k "$KEYCHAIN" -P "$p12_password" \
        -T /usr/bin/codesign -T /usr/bin/security >/dev/null
fi

/usr/bin/security set-key-partition-list \
    -S apple-tool:,apple:,codesign: -s -k "$keychain_password" "$KEYCHAIN" >/dev/null
chmod 600 "$KEYCHAIN" "$PASS_FILE"

print -- "JerisLink local signing identity is ready."
/usr/bin/security find-certificate -c "$NAME" -Z "$KEYCHAIN" | /usr/bin/sed -n '1,2p'
