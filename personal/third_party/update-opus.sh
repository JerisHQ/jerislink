#!/bin/sh
# Reproduces personal/third_party/opus from the official libopus release
# tarball. Only the portable C sources that JerisLink builds are kept: no
# DNN (deep PLC / DRED / OSCE), no SIMD or arch-specific code, no tests,
# no demos, no build system. Run from any directory; needs curl and tar.
#
#   ./update-opus.sh            # verify the pinned tarball and rewrite opus/
set -eu
VERSION=1.6.1
SHA256=6ffcb593207be92584df15b32466ed64bbec99109f007c82205f0194572411a1
URL="https://downloads.xiph.org/releases/opus/opus-$VERSION.tar.gz"

HERE="$(cd "$(dirname "$0")" && pwd)"
DEST="$HERE/opus"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

curl -fsSL -o "$WORK/opus.tar.gz" "$URL"
if command -v sha256sum >/dev/null 2>&1; then
    got="$(sha256sum "$WORK/opus.tar.gz" | cut -d' ' -f1)"
else
    got="$(shasum -a 256 "$WORK/opus.tar.gz" | cut -d' ' -f1)"
fi
[ "$got" = "$SHA256" ] || { echo "sha256 mismatch: $got" >&2; exit 1; }
tar -xzf "$WORK/opus.tar.gz" -C "$WORK"
SRC="$WORK/opus-$VERSION"

# Source lists come from the release's own make fragments.
list() {  # file, variable: prints the .c files the make variable names
    awk -v v="$2" '
        $1 == v && $2 == "=" { on = 1 }
        on { for (i = 1; i <= NF; i++) if ($i ~ /\.c$/) print $i; if ($0 !~ /\\$/) on = 0 }
    ' "$SRC/$1"
}
FILES="$( (list celt_sources.mk CELT_SOURCES
           list silk_sources.mk SILK_SOURCES
           list silk_sources.mk SILK_SOURCES_FLOAT
           list opus_sources.mk OPUS_SOURCES
           list opus_sources.mk OPUS_SOURCES_FLOAT) | sort -u)"

rm -rf "$DEST"
mkdir -p "$DEST"
cd "$SRC"
for f in $FILES COPYING AUTHORS include/*.h celt/*.h silk/*.h silk/float/*.h src/*.h; do
    mkdir -p "$DEST/$(dirname "$f")"
    cp "$f" "$DEST/$f"
done
echo "opus $VERSION vendored into $DEST ($(find "$DEST" -type f | wc -l | tr -d ' ') files)"
