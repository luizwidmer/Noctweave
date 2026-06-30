#!/usr/bin/env bash
set -euo pipefail

_noctweave_liboqs_sourced=0
if (return 0 2>/dev/null); then
  _noctweave_liboqs_sourced=1
fi

_noctweave_liboqs_candidates=()
_noctweave_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_noctweave_root_dir="$(cd "$_noctweave_script_dir/.." && pwd)"

case "$(uname -s)" in
  Darwin)
    _noctweave_liboqs_candidates=(
      "$_noctweave_root_dir/.runtime/liboqs/lib/liboqs.dylib"
      "/opt/homebrew/lib/liboqs.dylib"
      "/usr/local/lib/liboqs.dylib"
    )
    ;;
  Linux)
    _noctweave_liboqs_candidates=(
      "$_noctweave_root_dir/.runtime/liboqs/lib/liboqs.so"
      "/usr/local/lib/liboqs.so"
      "/usr/lib/liboqs.so"
      "/usr/lib64/liboqs.so"
    )
    ;;
  *)
    _noctweave_liboqs_candidates=()
    ;;
esac

_noctweave_liboqs_runtime=""
for candidate in "${_noctweave_liboqs_candidates[@]}"; do
  if [[ -f "$candidate" ]]; then
    _noctweave_liboqs_runtime="$candidate"
    break
  fi
done

if [[ -z "$_noctweave_liboqs_runtime" ]]; then
  echo "liboqs runtime not found. Install liboqs first, for example: brew install liboqs" >&2
  if [[ "$_noctweave_liboqs_sourced" == "1" ]]; then
    return 1
  fi
  exit 1
fi

_noctweave_liboqs_dir="$(cd "$(dirname "$_noctweave_liboqs_runtime")" && pwd)"
export NOCTWEAVE_LIBOQS_RUNTIME="$_noctweave_liboqs_runtime"
export DYLD_LIBRARY_PATH="$_noctweave_liboqs_dir:${DYLD_LIBRARY_PATH:-}"
export LD_LIBRARY_PATH="$_noctweave_liboqs_dir:${LD_LIBRARY_PATH:-}"

if [[ "$_noctweave_liboqs_sourced" != "1" ]]; then
  echo "$NOCTWEAVE_LIBOQS_RUNTIME"
fi
