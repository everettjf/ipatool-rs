#!/bin/bash
set -euo pipefail

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
ARCH=${1:-}
case "$ARCH" in
  x86_64|aarch64) ;;
  *) echo 'Usage: scripts/package-linux.sh [x86_64|aarch64] [output-directory]' >&2; exit 2 ;;
esac
TARGET="$ARCH-unknown-linux-gnu"
VERSION=$(awk '/^\[package\]/{pkg=1;next} pkg && /^version = /{gsub(/"/, "", $3);print $3;exit}' "$ROOT/Cargo.toml")
OUTPUT_DIR=${2:-"$ROOT/dist"}
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR=$(CDPATH='' cd -- "$OUTPUT_DIR" && pwd)
BINARY="$ROOT/target/$TARGET/release/ipatool"
test -x "$BINARY" || { echo "Missing release binary: $BINARY" >&2; exit 1; }

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
cp "$BINARY" "$STAGE/ipatool-rs"
cp "$ROOT/LICENSE" "$ROOT/NOTICE" "$ROOT/README.md" "$STAGE/"
mkdir -p "$STAGE/licenses" "$STAGE/assets"
cp "$ROOT/licenses/LICENSE-DARKPHOENIX.txt" "$STAGE/licenses/"
cp -R "$ROOT/assets/fairplay-startup" "$STAGE/assets/"

BASE="ipatool-rs-$VERSION-linux-$ARCH"
tar -C "$STAGE" --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner -cf - . | gzip -n > "$OUTPUT_DIR/$BASE.tar.gz"
(cd "$OUTPUT_DIR" && sha256sum "$BASE.tar.gz" > "$BASE.tar.gz.sha256")
tar -tzf "$OUTPUT_DIR/$BASE.tar.gz" >/dev/null
echo "Built $OUTPUT_DIR/$BASE.tar.gz"
