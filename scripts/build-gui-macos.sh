#!/bin/sh
# Build a native Apple Silicon application bundle. Ad hoc signing is local-only.
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
PROFILE=release
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
else
  cargo build --locked --features gui --bin ipatool-gui
fi
mkdir -p "$(dirname "$OUTPUT")"
STAGE=$(mktemp -d "$(dirname "$OUTPUT")/.ipatool-desktop.XXXXXX")
trap 'test ! -d "$STAGE" || rm -r "$STAGE"' EXIT HUP INT TERM
BUNDLE="$STAGE/ipatool.app"
mkdir -p "$BUNDLE/Contents/MacOS" "$BUNDLE/Contents/Resources"
cp "target/$PROFILE/ipatool-gui" "$BUNDLE/Contents/MacOS/ipatool-gui"
cp LICENSE NOTICE "$BUNDLE/Contents/Resources/"
cp licenses/LICENSE-DARKPHOENIX.txt "$BUNDLE/Contents/Resources/"
cp assets/desktop/ipatool.icns "$BUNDLE/Contents/Resources/ipatool.icns"
printf 'ipatool-rs desktop %s (%s)\n' "$VERSION" "$PROFILE" > "$BUNDLE/Contents/Resources/ipatool-build.txt"
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
codesign --force --options runtime --sign - \
  --entitlements "$ROOT/scripts/macos-release.entitlements" "$BUNDLE"
codesign --verify --deep --strict "$BUNDLE"
if [ -e "$OUTPUT" ]; then mv "$OUTPUT" "$STAGE/previous.app"; fi
if ! mv "$BUNDLE" "$OUTPUT"; then
  if [ -d "$STAGE/previous.app" ]; then mv "$STAGE/previous.app" "$OUTPUT"; fi
  exit 1
fi
printf 'Built %s\nAd hoc signature verified; this bundle is not notarized.\n' "$OUTPUT"
