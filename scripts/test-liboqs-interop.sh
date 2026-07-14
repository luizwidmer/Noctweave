#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOL_SOURCE="$ROOT_DIR/scripts/liboqs-interop-tool.c"
LIBOQS_015_COMMIT="97f6b86b1b6d109cfd43cf276ae39c2e776aed80"
source "$ROOT_DIR/scripts/liboqs-version.sh"
LIBOQS_016_COMMIT="$LIBOQS_COMMIT"

umask 077
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/noctweave-liboqs-interop.XXXXXX")"
if [[ "${KEEP_LIBOQS_INTEROP_TMP:-0}" != "1" ]]; then
  trap 'rm -rf "$WORK_DIR"' EXIT
else
  echo "Keeping interoperability workspace at $WORK_DIR"
fi

for command in git cmake cc cmp; do
  command -v "$command" >/dev/null 2>&1 || {
    echo "Required command is unavailable: $command" >&2
    exit 1
  }
done

fetch_and_build() {
  local label="$1"
  local commit="$2"
  local source_dir="$WORK_DIR/source-$label"
  local build_dir="$WORK_DIR/build-$label"
  local install_dir="$WORK_DIR/install-$label"

  git init -q "$source_dir"
  git -C "$source_dir" remote add origin https://github.com/open-quantum-safe/liboqs.git
  git -C "$source_dir" fetch -q --depth 1 origin "$commit"
  git -C "$source_dir" checkout -q --detach FETCH_HEAD
  test "$(git -C "$source_dir" rev-parse HEAD)" = "$commit"

  cmake -S "$source_dir" -B "$build_dir" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$install_dir" \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DOQS_MINIMAL_BUILD="KEM_ml_kem_768;SIG_ml_dsa_65" \
    -DOQS_DIST_BUILD=OFF \
    -DOQS_USE_OPENSSL=OFF \
    -DBUILD_SHARED_LIBS=OFF >/dev/null
  cmake --build "$build_dir" --parallel >/dev/null
  cmake --install "$build_dir" >/dev/null

  local archive="$install_dir/lib/liboqs.a"
  if [[ ! -f "$archive" ]]; then
    archive="$install_dir/lib64/liboqs.a"
  fi
  test -f "$archive"
  cc -std=c11 -O2 -I"$install_dir/include" "$TOOL_SOURCE" "$archive" -pthread -lm \
    -o "$WORK_DIR/oqs-$label"
}

echo "Building reviewed liboqs 0.15.0 and 0.16.0 profiles..."
fetch_and_build 015 "$LIBOQS_015_COMMIT"
fetch_and_build 016 "$LIBOQS_016_COMMIT"

OQS_015="$WORK_DIR/oqs-015"
OQS_016="$WORK_DIR/oqs-016"
DATA_DIR="$WORK_DIR/data"
mkdir -p "$DATA_DIR"
printf '%s' 'Noctweave/liboqs/bidirectional-compatibility/v1' >"$DATA_DIR/message"

check_signature_key_origin() {
  local origin="$1"
  local peer="$2"
  local label="$3"
  local public_key="$DATA_DIR/$label.sig.pk"
  local secret_key="$DATA_DIR/$label.sig.sk"

  "$origin" sig-keygen "$public_key" "$secret_key"
  "$origin" sig-sign "$secret_key" "$DATA_DIR/message" "$DATA_DIR/$label.origin.sig"
  "$peer" sig-verify "$public_key" "$DATA_DIR/message" "$DATA_DIR/$label.origin.sig"
  "$peer" sig-sign "$secret_key" "$DATA_DIR/message" "$DATA_DIR/$label.peer.sig"
  "$origin" sig-verify "$public_key" "$DATA_DIR/message" "$DATA_DIR/$label.peer.sig"
}

check_kem_direction() {
  local encapsulator="$1"
  local decapsulator="$2"
  local public_key="$3"
  local secret_key="$4"
  local label="$5"

  "$encapsulator" kem-encaps "$public_key" "$DATA_DIR/$label.ct" "$DATA_DIR/$label.encaps.ss"
  "$decapsulator" kem-decaps "$secret_key" "$DATA_DIR/$label.ct" "$DATA_DIR/$label.decaps.ss"
  cmp "$DATA_DIR/$label.encaps.ss" "$DATA_DIR/$label.decaps.ss"
}

check_kem_key_origin() {
  local origin="$1"
  local peer="$2"
  local label="$3"
  local public_key="$DATA_DIR/$label.kem.pk"
  local secret_key="$DATA_DIR/$label.kem.sk"

  "$origin" kem-keygen "$public_key" "$secret_key"
  check_kem_direction "$origin" "$peer" "$public_key" "$secret_key" "$label.origin-to-peer"
  check_kem_direction "$peer" "$origin" "$public_key" "$secret_key" "$label.peer-to-origin"
}

echo "Testing ML-DSA-65 keys and signatures in both directions..."
check_signature_key_origin "$OQS_015" "$OQS_016" keys-from-015
check_signature_key_origin "$OQS_016" "$OQS_015" keys-from-016

echo "Testing ML-KEM-768 keys, ciphertexts, and shared secrets in both directions..."
check_kem_key_origin "$OQS_015" "$OQS_016" keys-from-015
check_kem_key_origin "$OQS_016" "$OQS_015" keys-from-016

echo "liboqs 0.15.0 <-> 0.16.0 interoperability passed."
