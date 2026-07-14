#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_DIR="$ROOT_DIR/NoctweaveCore/liboqs"
OUTPUT_DIR="$ROOT_DIR/NoctweaveCore/Vendor/liboqs.xcframework"
MODULE_MAP="$ROOT_DIR/scripts/liboqs-module.modulemap"
source "$ROOT_DIR/scripts/liboqs-version.sh"

for command in cmake xcodebuild; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "Required command is unavailable: $command" >&2
    exit 1
  }
done

if [[ ! -d "$SOURCE_DIR/.git" ]]; then
  echo "Clone liboqs into $SOURCE_DIR before building the XCFramework." >&2
  exit 1
fi

actual_commit="$(git -C "$SOURCE_DIR" rev-parse HEAD)"
if [[ "$actual_commit" != "$LIBOQS_COMMIT" ]]; then
  echo "Refusing to build liboqs $actual_commit; expected $LIBOQS_VERSION at $LIBOQS_COMMIT." >&2
  exit 1
fi
if [[ -n "$(git -C "$SOURCE_DIR" status --short)" ]]; then
  echo "Refusing to build from a modified liboqs source checkout." >&2
  exit 1
fi

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/noctweave-liboqs-xcframework.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT

build_slice() {
  local name="$1"
  local sysroot="$2"
  local deployment_target="$3"
  local build_dir="$WORK_DIR/build-$name"
  local install_dir="$WORK_DIR/install-$name"
  echo "Building liboqs $LIBOQS_VERSION for $name..."
  local system_name=""
  if [[ "$sysroot" == iphone* ]]; then
    system_name="-DCMAKE_SYSTEM_NAME=iOS"
  fi
  cmake -S "$SOURCE_DIR" -B "$build_dir" \
    ${system_name:+"$system_name"} \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$install_dir" \
    -DCMAKE_OSX_ARCHITECTURES=arm64 \
    -DCMAKE_SYSTEM_PROCESSOR=arm64 \
    -DCMAKE_OSX_DEPLOYMENT_TARGET="$deployment_target" \
    -DCMAKE_OSX_SYSROOT="$sysroot" \
    -DCMAKE_TRY_COMPILE_TARGET_TYPE=STATIC_LIBRARY \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DOQS_MINIMAL_BUILD="KEM_ml_kem_768;SIG_ml_dsa_65" \
    -DOQS_DIST_BUILD=OFF \
    -DOQS_USE_OPENSSL=OFF \
    -DBUILD_SHARED_LIBS=OFF >/dev/null
  cmake --build "$build_dir" --parallel >/dev/null
  cmake --install "$build_dir" >/dev/null
  cp "$MODULE_MAP" "$install_dir/include/module.modulemap"
}

build_slice macos-arm64 macosx 13.0
build_slice ios-arm64 iphoneos 16.0
build_slice ios-arm64-simulator iphonesimulator 16.0

GENERATED_DIR="$WORK_DIR/liboqs.xcframework"
xcodebuild -create-xcframework \
  -library "$WORK_DIR/install-macos-arm64/lib/liboqs.a" \
  -headers "$WORK_DIR/install-macos-arm64/include" \
  -library "$WORK_DIR/install-ios-arm64/lib/liboqs.a" \
  -headers "$WORK_DIR/install-ios-arm64/include" \
  -library "$WORK_DIR/install-ios-arm64-simulator/lib/liboqs.a" \
  -headers "$WORK_DIR/install-ios-arm64-simulator/include" \
  -output "$GENERATED_DIR" >/dev/null

for config in "$GENERATED_DIR"/*/Headers/oqs/oqsconfig.h; do
  grep -q "OQS_VERSION_TEXT \"$LIBOQS_VERSION\"" "$config"
done

rm -rf "$OUTPUT_DIR"
mv "$GENERATED_DIR" "$OUTPUT_DIR"
echo "Updated $OUTPUT_DIR with liboqs $LIBOQS_VERSION ($LIBOQS_COMMIT)."
