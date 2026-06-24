#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELAY_DIR="$ROOT_DIR/PICCP Relay Server"
CORE_DIR="$ROOT_DIR/PICCPCore"

PORT="${PICCP_TEST_SERVER_PORT:-9440}"
HOST="${PICCP_TEST_SERVER_HOST:-127.0.0.1}"

echo "Building relay server..."
(cd "$RELAY_DIR" && swift build)

echo "Starting relay server on $HOST:$PORT..."
"$RELAY_DIR/.build/debug/PICCPRelayServer" --host "$HOST" --port "$PORT" --memory-only > "$ROOT_DIR/.relay_test.log" 2>&1 &
SERVER_PID=$!

cleanup() {
  if kill -0 "$SERVER_PID" >/dev/null 2>&1; then
    kill "$SERVER_PID"
  fi
}
trap cleanup EXIT

sleep 1

echo "Running core test harness..."
(cd "$CORE_DIR" && PICCP_TEST_SERVER_HOST="$HOST" PICCP_TEST_SERVER_PORT="$PORT" swift run PICCPCoreTestHarness)

echo "Tests complete."
