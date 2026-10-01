#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER_DIR="$ROOT_DIR/NoctweaveRelayServer"
BUILD_MODE="${BUILD_MODE:-release}"
HOST="${NOCTWEAVE_RELAY_HOST:-0.0.0.0}"
PORT="${NOCTWEAVE_RELAY_PORT:-9339}"
DATA_DIR="${NOCTWEAVE_RELAY_DATA_DIR:-$ROOT_DIR/.relay-data}"
MEMORY_ONLY="${NOCTWEAVE_RELAY_MEMORY_ONLY:-0}"

cd "$SERVER_DIR"
source "$ROOT_DIR/scripts/swiftpm-options.sh"

if [[ "$BUILD_MODE" == "release" ]]; then
  CONFIGURATION=release
else
  CONFIGURATION=debug
fi
swift build "${NOCTWEAVE_SWIFT_BUILD_FLAGS[@]}" -c "$CONFIGURATION"
BIN_DIR="$(swift build "${NOCTWEAVE_SWIFT_BUILD_FLAGS[@]}" -c "$CONFIGURATION" --show-bin-path)"
BIN="$BIN_DIR/NoctweaveRelayServer"
test -x "$BIN"

ARGS=("--host" "$HOST" "--port" "$PORT")
if [[ "$MEMORY_ONLY" == "1" ]]; then
  ARGS+=("--memory-only")
else
  mkdir -p "$DATA_DIR"
  ARGS+=("--data-dir" "$DATA_DIR")
fi

exec "$BIN" "${ARGS[@]}"
