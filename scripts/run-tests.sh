#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELAY_DIR="$ROOT_DIR/NoctweaveRelayServer"
CORE_DIR="$ROOT_DIR/NoctweaveCore"
JS_DIR="$ROOT_DIR/NoctweaveJS"

source "$ROOT_DIR/scripts/liboqs-runtime.sh"

echo "Running core XCTest suite..."
(cd "$CORE_DIR" && swift test)

echo "Running relay XCTest suite..."
(cd "$RELAY_DIR" && swift test)

echo "Running JavaScript protocol suite..."
(cd "$JS_DIR" && npm test)

echo "Running JavaScript desktop type-check..."
(cd "$JS_DIR" && npm run typecheck:desktop)

echo "Tests complete."
