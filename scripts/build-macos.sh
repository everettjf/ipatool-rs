#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
OUTPUT=${1:-"$ROOT/target/release/ipatool-macos-universal"}
case "$OUTPUT" in
  /*) ;;
  *) OUTPUT="$PWD/$OUTPUT" ;;
esac

for TOOL in cargo lipo codesign; do
  command -v "$TOOL" >/dev/null 2>&1 || {
    echo "$TOOL is required for the macOS build." >&2
    exit 1
  }
done

cd "$ROOT"
cargo build --release --target aarch64-apple-darwin
cargo build --release --target x86_64-apple-darwin

mkdir -p "$(dirname "$OUTPUT")"
TEMP_OUTPUT="$OUTPUT.tmp.$$"
trap 'rm -f "$TEMP_OUTPUT"' EXIT HUP INT TERM
lipo -create \
  target/aarch64-apple-darwin/release/ipatool \
  target/x86_64-apple-darwin/release/ipatool \
  -output "$TEMP_OUTPUT"
# The merge invalidates the arm64 linker's ad-hoc signature.
codesign --force --sign - "$TEMP_OUTPUT"
codesign --verify "$TEMP_OUTPUT"
lipo "$TEMP_OUTPUT" -verify_arch arm64
lipo "$TEMP_OUTPUT" -verify_arch x86_64
mv "$TEMP_OUTPUT" "$OUTPUT"
echo "Built $OUTPUT"
