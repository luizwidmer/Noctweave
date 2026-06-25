#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELAY_DIR="$ROOT_DIR/PICCP Relay Server"
CORE_DIR="$ROOT_DIR/PICCPCore"

source "$ROOT_DIR/scripts/liboqs-runtime.sh"

echo "Running core XCTest suite..."
(cd "$CORE_DIR" && swift test)

echo "Running relay XCTest suite..."
(cd "$RELAY_DIR" && swift test)

echo "Tests complete."
