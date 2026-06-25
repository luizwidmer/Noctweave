#!/usr/bin/env bash
set -euo pipefail

_piccp_liboqs_sourced=0
if (return 0 2>/dev/null); then
  _piccp_liboqs_sourced=1
fi

_piccp_liboqs_candidates=()
_piccp_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_piccp_root_dir="$(cd "$_piccp_script_dir/.." && pwd)"

case "$(uname -s)" in
  Darwin)
    _piccp_liboqs_candidates=(
      "$_piccp_root_dir/.runtime/liboqs/lib/liboqs.dylib"
      "/opt/homebrew/lib/liboqs.dylib"
      "/usr/local/lib/liboqs.dylib"
    )
    ;;
  Linux)
    _piccp_liboqs_candidates=(
      "$_piccp_root_dir/.runtime/liboqs/lib/liboqs.so"
      "/usr/local/lib/liboqs.so"
      "/usr/lib/liboqs.so"
      "/usr/lib64/liboqs.so"
    )
    ;;
  *)
    _piccp_liboqs_candidates=()
    ;;
esac

_piccp_liboqs_runtime=""
for candidate in "${_piccp_liboqs_candidates[@]}"; do
  if [[ -f "$candidate" ]]; then
    _piccp_liboqs_runtime="$candidate"
    break
  fi
done

if [[ -z "$_piccp_liboqs_runtime" ]]; then
  echo "liboqs runtime not found. Install liboqs first, for example: brew install liboqs" >&2
  if [[ "$_piccp_liboqs_sourced" == "1" ]]; then
    return 1
  fi
  exit 1
fi

_piccp_liboqs_dir="$(cd "$(dirname "$_piccp_liboqs_runtime")" && pwd)"
export PICCP_LIBOQS_RUNTIME="$_piccp_liboqs_runtime"
export DYLD_LIBRARY_PATH="$_piccp_liboqs_dir:${DYLD_LIBRARY_PATH:-}"
export LD_LIBRARY_PATH="$_piccp_liboqs_dir:${LD_LIBRARY_PATH:-}"

if [[ "$_piccp_liboqs_sourced" != "1" ]]; then
  echo "$PICCP_LIBOQS_RUNTIME"
fi
