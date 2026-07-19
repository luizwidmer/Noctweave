#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELAY_DIR="$ROOT_DIR/NoctweaveRelayServer"
CORE_DIR="$ROOT_DIR/NoctweaveCore"
JS_DIR="${NOCTWEAVE_JS_DIR:-$ROOT_DIR/NoctweaveJS}"

source "$ROOT_DIR/scripts/liboqs-runtime.sh"

echo "Running core XCTest suite..."
(cd "$CORE_DIR" && swift test)

echo "Running NoctweaveCLI smoke suite..."
"$ROOT_DIR/scripts/test-cli.sh"

echo "Running relay XCTest suite..."
(cd "$RELAY_DIR" && swift test)

if [ -f "$JS_DIR/package.json" ]; then
  echo "Running standalone NoctweaveJS protocol suite..."
  (cd "$JS_DIR" && npm test)

  echo "Running standalone NoctweaveJS desktop type-check..."
  (cd "$JS_DIR" && npm run typecheck:desktop)
else
  echo "Standalone NoctweaveJS checkout not found; skipping cross-repository JavaScript checks."
  echo "Set NOCTWEAVE_JS_DIR or clone https://github.com/luizwidmer/NoctweaveJS beside this repository."
fi

echo "Tests complete."
