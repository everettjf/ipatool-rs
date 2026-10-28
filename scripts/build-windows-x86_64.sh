#!/bin/bash
set -euo pipefail

# Cross-build the Windows x86_64 CLI with MinGW-w64.
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
for tool in cargo rustup file x86_64-w64-mingw32-gcc; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "$tool is required for the Windows x86_64 cross-build." >&2
    exit 1
  }
done

TARGET=x86_64-pc-windows-gnu
LINKER=$(command -v x86_64-w64-mingw32-gcc)
rustup target add "$TARGET"
export CC_x86_64_pc_windows_gnu="$LINKER"
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER="$LINKER"

cd "$ROOT"
cargo build --release --target "$TARGET"
OUTPUT="$ROOT/target/$TARGET/release/ipatool.exe"
if [[ $(file -b "$OUTPUT") != PE32+*x86-64* ]]; then
  echo "The Windows executable is not an x86_64 PE image: $OUTPUT" >&2
  exit 1
fi
echo "Built $OUTPUT"
