#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER_DIR="$ROOT_DIR/PICCP Relay Server"
BUILD_MODE="${BUILD_MODE:-release}"
HOST="${PICCP_RELAY_HOST:-0.0.0.0}"
PORT="${PICCP_RELAY_PORT:-9339}"
DATA_DIR="${PICCP_RELAY_DATA_DIR:-$ROOT_DIR/.relay-data}"
MEMORY_ONLY="${PICCP_RELAY_MEMORY_ONLY:-0}"

cd "$SERVER_DIR"

if [[ "$BUILD_MODE" == "release" ]]; then
  swift build -c release
  BIN="$SERVER_DIR/.build/release/PICCPRelayServer"
else
  swift build
  BIN="$SERVER_DIR/.build/debug/PICCPRelayServer"
fi

ARGS=("--host" "$HOST" "--port" "$PORT")
if [[ "$MEMORY_ONLY" == "1" ]]; then
  ARGS+=("--memory-only")
else
  mkdir -p "$DATA_DIR"
  ARGS+=("--data-dir" "$DATA_DIR")
fi

exec "$BIN" "${ARGS[@]}"
