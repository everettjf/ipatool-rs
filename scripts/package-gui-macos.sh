#!/bin/sh
# Package only a signed, notarized, stapled production desktop bundle.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
VERSION=$(awk '/^\[package\]/{pkg=1;next} pkg && /^version = /{gsub(/"/, "", $3);print $3;exit}' "$ROOT/Cargo.toml")
BUNDLE=${1:?Pass the signed and stapled IPATOOL-RS.app bundle.}
OUTPUT_DIR=${2:-"$ROOT/dist"}
case "$BUNDLE" in /*) ;; *) BUNDLE="$PWD/$BUNDLE" ;; esac
case "$OUTPUT_DIR" in /*) ;; *) OUTPUT_DIR="$PWD/$OUTPUT_DIR" ;; esac
if [ "$(basename "$BUNDLE")" != IPATOOL-RS.app ]; then
  echo 'The distribution bundle must be named IPATOOL-RS.app.' >&2
  exit 1
fi
INFO="$BUNDLE/Contents/Info.plist"
test "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$INFO")" = "$VERSION"
test "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$INFO")" = dev.ipatool.rust
if /usr/libexec/PlistBuddy -c 'Print :LSEnvironment' "$INFO" >/dev/null 2>&1; then
  echo 'A distribution bundle must not override the user environment.' >&2
  exit 1
fi
codesign --verify --deep --strict "$BUNDLE"
TEAM=
for ITEM in "$BUNDLE" "$BUNDLE/Contents/Library/LaunchServices/ipatool-fairplay-helper"; do
  DETAILS=$(codesign -d --verbose=4 "$ITEM" 2>&1)
  printf '%s\n' "$DETAILS" | grep -q '^Authority=Developer ID Application:'
  ITEM_TEAM=$(printf '%s\n' "$DETAILS" | awk -F= '/^TeamIdentifier=/{print $2}')
  test -n "$ITEM_TEAM"
  if [ -n "$TEAM" ]; then test "$TEAM" = "$ITEM_TEAM"; fi
  TEAM=$ITEM_TEAM
done
test "$(lipo -archs "$BUNDLE/Contents/MacOS/ipatool-gui")" = arm64
test "$(lipo -archs "$BUNDLE/Contents/Library/LaunchServices/ipatool-fairplay-helper")" = arm64
xcrun stapler validate "$BUNDLE"
spctl --assess --type execute --verbose=2 "$BUNDLE"
mkdir -p "$OUTPUT_DIR"
BASE="ipatool-rs-$VERSION-gui-macos-arm64.zip"
if [ -e "$OUTPUT_DIR/$BASE" ] || [ -e "$OUTPUT_DIR/$BASE.sha256" ]; then
  echo 'Distribution output already exists; use a new output directory.' >&2
  exit 1
fi
ditto -c -k --keepParent "$BUNDLE" "$OUTPUT_DIR/$BASE"
(cd "$OUTPUT_DIR" && shasum -a 256 "$BASE" > "$BASE.sha256")
printf 'Desktop archive: %s\nChecksum: %s\n' "$OUTPUT_DIR/$BASE" "$OUTPUT_DIR/$BASE.sha256"
