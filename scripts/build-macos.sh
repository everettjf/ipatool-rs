#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
ARCH=universal
if [ "${1:-}" = "--arm64" ]; then
  ARCH=arm64
  shift
fi
OUTPUT=${1:-"$ROOT/target/release/ipatool-macos-$ARCH"}
case "$OUTPUT" in
  /*) ;;
  *) OUTPUT="$PWD/$OUTPUT" ;;
esac

for TOOL in cargo codesign; do
  command -v "$TOOL" >/dev/null 2>&1 || {
    echo "$TOOL is required for the macOS build." >&2
    exit 1
  }
done
if [ "$ARCH" = universal ]; then
  command -v lipo >/dev/null 2>&1 || {
    echo "lipo is required for a universal macOS build." >&2
    exit 1
  }
fi

cd "$ROOT"
cargo build --release --target aarch64-apple-darwin

mkdir -p "$(dirname "$OUTPUT")"
TEMP_OUTPUT="$OUTPUT.tmp.$$"
trap 'rm -f "$TEMP_OUTPUT"' EXIT HUP INT TERM
if [ "$ARCH" = arm64 ]; then
  cp target/aarch64-apple-darwin/release/ipatool "$TEMP_OUTPUT"
else
  cargo build --release --target x86_64-apple-darwin
  lipo -create \
    target/aarch64-apple-darwin/release/ipatool \
    target/x86_64-apple-darwin/release/ipatool \
    -output "$TEMP_OUTPUT"
fi
# Copying or merging may invalidate the linker's ad-hoc signature.
codesign --force --sign - "$TEMP_OUTPUT"
codesign --verify "$TEMP_OUTPUT"
if [ "$ARCH" = universal ]; then
  lipo "$TEMP_OUTPUT" -verify_arch arm64
  lipo "$TEMP_OUTPUT" -verify_arch x86_64
fi
mv "$TEMP_OUTPUT" "$OUTPUT"
echo "Built $OUTPUT"
