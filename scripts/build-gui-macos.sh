#!/bin/sh
# Build a native Apple Silicon application bundle. Ad hoc signing is local-only.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
PROFILE=release
SIGN_IDENTITY=${IPATOOL_CODESIGN_IDENTITY:--}
SIGN_TEAM=${IPATOOL_AUTHORIZATION_TEAM:-}
TIMESTAMP_OPTION=--timestamp=none
if [ "$SIGN_IDENTITY" = - ]; then
  if [ -n "$SIGN_TEAM" ]; then
    echo 'Authorization team configuration requires a Developer ID signing identity.' >&2
    exit 1
  fi
else
  TIMESTAMP_OPTION=--timestamp
  case "$SIGN_TEAM" in
    *[!A-Z0-9]*|'') echo 'Set the public 10-character IPATOOL_AUTHORIZATION_TEAM for Developer ID builds.' >&2; exit 1 ;;
  esac
  if [ "${#SIGN_TEAM}" -ne 10 ]; then echo 'Invalid authorization team identifier.' >&2; exit 1; fi
fi
if [ "${1:-}" = --debug ]; then
  PROFILE=debug
  shift
fi
if [ "$(uname -s)" != Darwin ] || [ "$(uname -m)" != arm64 ]; then
  echo 'The desktop bundle currently targets macOS on Apple Silicon.' >&2
  exit 1
fi
OUTPUT=${1:-"$ROOT/target/desktop-$PROFILE/ipatool.app"}
case "$OUTPUT" in /*) ;; *) OUTPUT="$PWD/$OUTPUT" ;; esac
case "$OUTPUT" in *.app) ;; *) echo 'Output must be an .app bundle path.' >&2; exit 1 ;; esac
VERSION=$(awk '/^\[package\]/{pkg=1;next} pkg && /^version = /{gsub(/"/, "", $3);print $3;exit}' "$ROOT/Cargo.toml")
test -n "$VERSION"
if [ -e "$OUTPUT" ] && [ ! -f "$OUTPUT/Contents/Resources/ipatool-build.txt" ]; then
  echo 'Refusing to replace an application not created by this script.' >&2
  exit 1
fi
cd "$ROOT"
if [ "$PROFILE" = release ]; then
  cargo build --locked --release --features gui --bin ipatool-gui
  cargo build --locked --release -p ipatool-authorization --bin ipatool-fairplay-helper
else
  cargo build --locked --features gui --bin ipatool-gui
  cargo build --locked -p ipatool-authorization --bin ipatool-fairplay-helper
fi
mkdir -p "$(dirname "$OUTPUT")"
STAGE=$(mktemp -d "$(dirname "$OUTPUT")/.ipatool-desktop.XXXXXX")
trap 'test ! -d "$STAGE" || rm -r "$STAGE"' EXIT HUP INT TERM
BUNDLE="$STAGE/ipatool.app"
mkdir -p "$BUNDLE/Contents/MacOS" "$BUNDLE/Contents/Resources"
mkdir -p "$BUNDLE/Contents/Library/LaunchServices" "$BUNDLE/Contents/Library/LaunchDaemons"
cp "target/$PROFILE/ipatool-gui" "$BUNDLE/Contents/MacOS/ipatool-gui"
cp "target/$PROFILE/ipatool-fairplay-helper" "$BUNDLE/Contents/Library/LaunchServices/ipatool-fairplay-helper"
cp scripts/dev.ipatool.rust.fairplay-collector.plist "$BUNDLE/Contents/Library/LaunchDaemons/"
cp LICENSE NOTICE "$BUNDLE/Contents/Resources/"
cp licenses/LICENSE-DARKPHOENIX.txt "$BUNDLE/Contents/Resources/"
cp assets/desktop/ipatool.icns "$BUNDLE/Contents/Resources/ipatool.icns"
printf 'ipatool-rs desktop %s (%s)\n' "$VERSION" "$PROFILE" > "$BUNDLE/Contents/Resources/ipatool-build.txt"
if SOURCE_COMMIT=$(git rev-parse HEAD 2>/dev/null); then
  printf 'source %s\n' "$SOURCE_COMMIT" >> "$BUNDLE/Contents/Resources/ipatool-build.txt"
fi
cat > "$BUNDLE/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>dev.ipatool.rust</string>
  <key>CFBundleName</key><string>&#x1F980;IPATOOL-RS &#x1F980;</string>
  <key>CFBundleDisplayName</key><string>&#x1F980;IPATOOL-RS &#x1F980;</string>
  <key>CFBundleExecutable</key><string>ipatool-gui</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleIconFile</key><string>ipatool.icns</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.developer-tools</string>
  <key>NSHighResolutionCapable</key><true/>
</dict></plist>
EOF
plutil -lint "$BUNDLE/Contents/Info.plist"
plutil -lint "$BUNDLE/Contents/Library/LaunchDaemons/dev.ipatool.rust.fairplay-collector.plist"
codesign --force --options runtime "$TIMESTAMP_OPTION" --sign "$SIGN_IDENTITY" \
  --identifier dev.ipatool.rust.fairplay-collector "$BUNDLE/Contents/Library/LaunchServices/ipatool-fairplay-helper"
codesign --force --options runtime "$TIMESTAMP_OPTION" --sign "$SIGN_IDENTITY" \
  --entitlements "$ROOT/scripts/macos-release.entitlements" "$BUNDLE"
codesign --verify --deep --strict "$BUNDLE"
if [ "$SIGN_IDENTITY" != - ]; then
  for SIGNED_ITEM in "$BUNDLE" "$BUNDLE/Contents/Library/LaunchServices/ipatool-fairplay-helper"; do
    ACTUAL_TEAM=$(codesign -d --verbose=4 "$SIGNED_ITEM" 2>&1 | awk -F= '/^TeamIdentifier=/{print $2}')
    if [ "$ACTUAL_TEAM" != "$SIGN_TEAM" ]; then echo 'Signature team differs from the compiled authorization policy.' >&2; exit 1; fi
  done
fi
if [ -e "$OUTPUT" ]; then mv "$OUTPUT" "$STAGE/previous.app"; fi
if ! mv "$BUNDLE" "$OUTPUT"; then
  if [ -d "$STAGE/previous.app" ]; then mv "$STAGE/previous.app" "$OUTPUT"; fi
  exit 1
fi
printf 'Built %s\n' "$OUTPUT"
if [ "$SIGN_IDENTITY" = - ]; then
  echo 'Ad hoc signature verified; protected authorization access is disabled. This bundle is not notarized.'
else
  echo 'Developer ID signatures verified. Notarization and administrator approval are still required for protected authorization access.'
fi
