#!/bin/sh
set -eu

# Build a standalone Rust executable for jailbroken arm64 iOS 15+ devices.
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
OUTPUT=${1:-"$ROOT/ipatool-ios-arm64"}
case "$OUTPUT" in
  /*) ;;
  *) OUTPUT="$PWD/$OUTPUT" ;;
esac

for TOOL in cmake ldid curl patch; do
  command -v "$TOOL" >/dev/null 2>&1 || {
    echo "$TOOL is required for the iOS build." >&2
    exit 1
  }
done

SDKROOT=$(xcrun --sdk iphoneos --show-sdk-path)
CC=$(xcrun --sdk iphoneos --find clang)
SDK_VERSION=$(xcrun --sdk iphoneos --show-sdk-version)
export SDKROOT CC
export IPHONEOS_DEPLOYMENT_TARGET=15.0

PATCH_HASH=$(shasum -a 256 "$ROOT/scripts/patches/unicorn-ios.patch" | cut -d ' ' -f 1)
CACHE_DIR="$ROOT/target/toolchains/unicorn-ios-2.1.4-${PATCH_HASH}-${SDK_VERSION}"
LIBRARY="$CACHE_DIR/libunicorn.a"

if [ ! -s "$LIBRARY" ]; then
  BUILD_DIR=$(mktemp -d /tmp/ipatool-rs-ios.XXXXXX)
  trap 'rm -rf "$BUILD_DIR"' EXIT HUP INT TERM

  # Keep the version and hash in sync with the pinned desktop runtime.
  curl -fL --retry 3 \
    https://github.com/unicorn-engine/unicorn/archive/refs/tags/2.1.4.tar.gz \
    -o "$BUILD_DIR/unicorn.tar.gz"
  echo "ea8863f095a0136388694e5a6063afd9bb7650e30243dd6251af59c5ce5601f4  $BUILD_DIR/unicorn.tar.gz" |
    shasum -a 256 -c -
  tar -xzf "$BUILD_DIR/unicorn.tar.gz" -C "$BUILD_DIR"
  patch -d "$BUILD_DIR/unicorn-2.1.4" -p1 < "$ROOT/scripts/patches/unicorn-ios.patch"

  cmake -S "$BUILD_DIR/unicorn-2.1.4" -B "$BUILD_DIR/build" \
    -DCMAKE_SYSTEM_NAME=iOS -DCMAKE_OSX_SYSROOT="$SDKROOT" \
    -DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_OSX_DEPLOYMENT_TARGET=15.0 \
    -DCMAKE_C_FLAGS='-target arm64-apple-ios15.0' -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF -DUNICORN_ARCH=aarch64 \
    -DUNICORN_BUILD_TESTS=OFF -DUNICORN_INSTALL=OFF
  cmake --build "$BUILD_DIR/build" --parallel "$(sysctl -n hw.ncpu)"
  mkdir -p "$CACHE_DIR"
  cp "$BUILD_DIR/build/libunicorn.a" "$LIBRARY.tmp.$$"
  mv "$LIBRARY.tmp.$$" "$LIBRARY"
fi

export RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=-Wl,-force_load,$LIBRARY -C link-arg=-Wl,-export_dynamic"
cd "$ROOT"
cargo build --release --target aarch64-apple-ios
cp target/aarch64-apple-ios/release/ipatool "$OUTPUT"
ldid -S"$ROOT/scripts/ios-entitlements.plist" "$OUTPUT"
echo "Built $OUTPUT"
