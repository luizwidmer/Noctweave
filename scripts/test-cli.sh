#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORE_DIR="$ROOT_DIR/NoctweaveCore"
source "$ROOT_DIR/scripts/liboqs-runtime.sh"
source "$ROOT_DIR/scripts/swiftpm-options.sh"

# Build once, then exercise the actual product directly. Each invocation still
# uses the same fresh private state and runs the complete CLI command handler.
swift build --package-path "$CORE_DIR" "${NOCTWEAVE_SWIFT_BUILD_FLAGS[@]}" --product NoctweaveCLI
CORE_BIN="$(swift build --package-path "$CORE_DIR" "${NOCTWEAVE_SWIFT_BUILD_FLAGS[@]}" --show-bin-path)"
CLI="$CORE_BIN/NoctweaveCLI"
test -x "$CLI"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/noctweave-cli.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT

STATE_FILE="$WORK_DIR/state.json"
OFFER_FILE="$WORK_DIR/offer.private.json"
INVITATION_FILE="$WORK_DIR/invitation.share"

"$CLI" help >"$WORK_DIR/help.txt"
grep -Fq -- 'send --relationship <uuid> (--text-file <private-file> | --text-stdin true)' "$WORK_DIR/help.txt"
grep -q -- 'safety-number --relationship <uuid>' "$WORK_DIR/help.txt"

"$CLI" init \
  --display-name "CLI smoke persona" \
  --accept-privacy-policy true \
  --accept-terms-of-use true \
  --state "$STATE_FILE" \
  --plaintext true >"$WORK_DIR/init.json"

"$CLI" status \
  --state "$STATE_FILE" \
  --plaintext true >"$WORK_DIR/status.json"

"$CLI" maintain \
  --all true \
  --state "$STATE_FILE" \
  --plaintext true >"$WORK_DIR/maintenance.json"

"$CLI" pairing-invitation \
  --offer-out "$OFFER_FILE" \
  --invitation-out "$INVITATION_FILE" \
  --lifetime 30 \
  --state "$STATE_FILE" \
  --plaintext true >"$WORK_DIR/invitation.json"

file_mode() {
  if stat -f '%Lp' "$1" >/dev/null 2>&1; then
    stat -f '%Lp' "$1"
  else
    stat -c '%a' "$1"
  fi
}

test "$(file_mode "$OFFER_FILE")" = "600"
test "$(file_mode "$INVITATION_FILE")" = "600"

echo "NoctweaveCLI smoke tests passed."
