#!/bin/bash
set -euo pipefail

# Build a Linux release from macOS with Zig's bundled glibc cross toolchain.
# Tested with Zig 0.17.0. Pass x86_64 or aarch64 as the first argument.
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
ARCH=${1:-x86_64}
case "$ARCH" in
  x86_64)
    TARGET=x86_64-unknown-linux-gnu
    ZIG_TARGET=x86_64-linux-gnu.2.17
    ;;
  aarch64)
    TARGET=aarch64-unknown-linux-gnu
    ZIG_TARGET=aarch64-linux-gnu.2.17
    ;;
  *)
    echo 'Usage: scripts/build-linux.sh [x86_64|aarch64]' >&2
    exit 2
    ;;
esac

for tool in zig cargo rustup file; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "$tool is required for the Linux cross-build." >&2
    exit 1
  }
done
ZIG=$(command -v zig)
rustup target add "$TARGET"

TOOLS_DIR="$ROOT/target/toolchains"
mkdir -p "$TOOLS_DIR"
LINKER="$TOOLS_DIR/ipatool-linux-$ARCH-cc"
ARCHIVER="$TOOLS_DIR/ipatool-zig-ar"
cat > "$LINKER" <<EOF
#!/bin/bash
set -euo pipefail
args=()
for arg in "\$@"; do
  case "\$arg" in
    # cc-rs passes a Rust target triple that Zig does not parse here.
    --target=*) ;;
    # Zig 0.17 rejects this AArch64 linker workaround; validate on target CPUs.
    -Wl,--fix-cortex-a53-843419) ;;
    *) args+=("\$arg") ;;
  esac
done
exec "$ZIG" cc -target "$ZIG_TARGET" "\${args[@]}"
EOF
cat > "$ARCHIVER" <<EOF
#!/bin/sh
exec "$ZIG" ar "\$@"
EOF
chmod +x "$LINKER" "$ARCHIVER"

if [[ "$ARCH" == x86_64 ]]; then
  export CC_x86_64_unknown_linux_gnu="$LINKER"
  export AR_x86_64_unknown_linux_gnu="$ARCHIVER"
  export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="$LINKER"
else
  export CC_aarch64_unknown_linux_gnu="$LINKER"
  export AR_aarch64_unknown_linux_gnu="$ARCHIVER"
  export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="$LINKER"
fi

cd "$ROOT"
cargo build --release --target "$TARGET"
OUTPUT="$ROOT/target/$TARGET/release/ipatool"
if [[ $(file -b "$OUTPUT") != ELF* ]]; then
  echo "The Linux executable is not an ELF image: $OUTPUT" >&2
  exit 1
fi
echo "Built $OUTPUT"
