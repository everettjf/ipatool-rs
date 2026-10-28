#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
VERSION=$(awk '/^\[package\]/{pkg=1;next} pkg && /^version = /{gsub(/"/, "", $3);print $3;exit}' "$ROOT/Cargo.toml")
if [ -z "$VERSION" ]; then
  echo "Cargo package version is missing." >&2
  exit 1
fi
: "${IPATOOL_CODESIGN_IDENTITY:?Set IPATOOL_CODESIGN_IDENTITY to a Developer ID Application identity.}"

OUTPUT_DIR=${1:-"$ROOT/dist"}
case "$OUTPUT_DIR" in
  /*) ;;
  *) OUTPUT_DIR="$PWD/$OUTPUT_DIR" ;;
esac
mkdir -p "$OUTPUT_DIR"
STAGE=$(mktemp -d "${TMPDIR:-/tmp}/ipatool-rs-package.XXXXXX")
trap 'test ! -d "$STAGE" || rm -r "$STAGE"' EXIT HUP INT TERM

"$ROOT/scripts/build-macos.sh" --arm64 "$STAGE/ipatool-rs"
codesign --force --options runtime --timestamp \
  --entitlements "$ROOT/scripts/macos-release.entitlements" \
  --sign "$IPATOOL_CODESIGN_IDENTITY" "$STAGE/ipatool-rs"
codesign --verify --strict "$STAGE/ipatool-rs"
"$STAGE/ipatool-rs" --version
cp "$ROOT/LICENSE" "$STAGE/LICENSE"
cp "$ROOT/NOTICE" "$STAGE/NOTICE"
mkdir -p "$STAGE/licenses"
cp "$ROOT/licenses/LICENSE-DARKPHOENIX.txt" "$STAGE/licenses/LICENSE-DARKPHOENIX.txt"
cp "$ROOT/README.md" "$STAGE/README.md"

BASE="ipatool-rs-$VERSION-macos-arm64"
ARCHIVE="$OUTPUT_DIR/$BASE.tar.gz"
NOTARY_ZIP="$OUTPUT_DIR/$BASE-notary.zip"
COPYFILE_DISABLE=1 tar -C "$STAGE" -czf "$ARCHIVE" ipatool-rs LICENSE NOTICE licenses/LICENSE-DARKPHOENIX.txt README.md
ditto -c -k --keepParent "$STAGE/ipatool-rs" "$NOTARY_ZIP"
(cd "$OUTPUT_DIR" && shasum -a 256 "$BASE.tar.gz" > "$BASE.tar.gz.sha256")
tar -tzf "$ARCHIVE" >/dev/null

printf 'Archive: %s\nChecksum: %s\nNotarization input: %s\n' "$ARCHIVE" "$ARCHIVE.sha256" "$NOTARY_ZIP"
