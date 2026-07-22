#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELAY_DIR="$ROOT_DIR/NoctweaveRelayServer"
CORE_DIR="$ROOT_DIR/NoctweaveCore"
JS_DIR="${NOCTWEAVE_JS_DIR:-$ROOT_DIR/NoctweaveJS}"

source "$ROOT_DIR/scripts/liboqs-runtime.sh"

echo "Building public Core and CLI product paths..."
swift build --package-path "$CORE_DIR"

echo "Running Core XCTest suite..."
swift test --package-path "$CORE_DIR"

echo "Running public CLI acceptance suite (init, state, maintenance, pairing artifacts)..."
"$ROOT_DIR/scripts/test-cli.sh"

echo "Building public relay product path..."
swift build --package-path "$RELAY_DIR"

echo "Running relay XCTest suite and product integration coverage..."
swift test --package-path "$RELAY_DIR"

if command -v bun >/dev/null 2>&1 && [ -f "$RELAY_DIR/package.json" ]; then
  echo "Running public relay OperatorWebUI and Electrobun launcher TypeScript suite..."
  (cd "$RELAY_DIR" && bun test desktop/test)
else
  echo "Bun or the public relay desktop package is unavailable; skipping Electrobun TypeScript checks."
fi

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
