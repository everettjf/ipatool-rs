#!/bin/bash
set -euo pipefail

# Reproducible Windows ARM64 cross-build from macOS. The toolchain is cached
# inside target/ and its published archive digest is checked before use.
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
if [[ $(uname -s) != Darwin ]]; then
  echo 'This cross-build script requires macOS.' >&2
  exit 1
fi
for tool in curl shasum tar rustup cargo; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "$tool is required for the Windows ARM64 build." >&2
    exit 1
  }
done
rustup target add aarch64-pc-windows-gnullvm

TAG=20261020
NAME="llvm-mingw-${TAG}-ucrt-macos-universal"
TOOLS_DIR="$ROOT/target/toolchains"
ARCHIVE="$TOOLS_DIR/$NAME.tar.xz"
TOOLCHAIN="$TOOLS_DIR/$NAME"
SHA256=e9c13e4ede38e715003ffc674d4d00a1088df8235439d1f0c16188ff0704c17e
mkdir -p "$TOOLS_DIR"
if [[ ! -f "$ARCHIVE" ]]; then
  curl -fL --retry 3 \
    "https://github.com/mstorsjo/llvm-mingw/releases/download/$TAG/$NAME.tar.xz" \
    -o "$ARCHIVE"
fi
printf '%s  %s\n' "$SHA256" "$ARCHIVE" | shasum -a 256 -c -
if [[ ! -x "$TOOLCHAIN/bin/aarch64-w64-mingw32-clang" ]]; then
  tar -xf "$ARCHIVE" -C "$TOOLS_DIR"
fi

LINKER="$TOOLS_DIR/ipatool-windows-arm64-link"
cat > "$LINKER" <<'EOF'
#!/bin/bash
set -euo pipefail
: "${IPATOOL_LLVM_MINGW_ROOT:?}"
args=()
for arg in "$@"; do
  case "$arg" in
    -lunwind) args+=("$IPATOOL_LLVM_MINGW_ROOT/aarch64-w64-mingw32/lib/libunwind.a") ;;
    *) args+=("$arg") ;;
  esac
done
exec "$IPATOOL_LLVM_MINGW_ROOT/bin/aarch64-w64-mingw32-clang" "${args[@]}"
EOF
chmod +x "$LINKER"

export IPATOOL_LLVM_MINGW_ROOT="$TOOLCHAIN"
export CC_aarch64_pc_windows_gnullvm="$TOOLCHAIN/bin/aarch64-w64-mingw32-clang"
export AR_aarch64_pc_windows_gnullvm="$TOOLCHAIN/bin/aarch64-w64-mingw32-ar"
export RANLIB_aarch64_pc_windows_gnullvm="$TOOLCHAIN/bin/aarch64-w64-mingw32-ranlib"
export CARGO_TARGET_AARCH64_PC_WINDOWS_GNULLVM_LINKER="$LINKER"

cd "$ROOT"
cargo build --release --target aarch64-pc-windows-gnullvm
OUTPUT="$ROOT/target/aarch64-pc-windows-gnullvm/release/ipatool.exe"
PE_HEADERS=$("$TOOLCHAIN/bin/llvm-readobj" --file-headers "$OUTPUT")
if [[ "$PE_HEADERS" != *'Machine: IMAGE_FILE_MACHINE_ARM64'* ]]; then
  echo 'The Windows executable is not an ARM64 PE image.' >&2
  exit 1
fi
PE_IMPORTS=$("$TOOLCHAIN/bin/llvm-objdump" -p "$OUTPUT")
if [[ "$PE_IMPORTS" == *'DLL Name: libunwind.dll'* ]]; then
  echo 'Unexpected dynamic libunwind dependency in the Windows ARM64 build.' >&2
  exit 1
fi
echo "Built $OUTPUT"
