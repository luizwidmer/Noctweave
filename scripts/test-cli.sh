#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORE_DIR="$ROOT_DIR/NoctweaveCore"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/noctweave-cli.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT

STATE_FILE="$WORK_DIR/state.json"
OFFER_FILE="$WORK_DIR/offer.private.json"
INVITATION_FILE="$WORK_DIR/invitation.share"

swift run --package-path "$CORE_DIR" NoctweaveCLI help >"$WORK_DIR/help.txt"
grep -q -- 'send --relationship <uuid> --text-file <private-file>' "$WORK_DIR/help.txt"
grep -q -- 'safety-number --relationship <uuid>' "$WORK_DIR/help.txt"

swift run --package-path "$CORE_DIR" NoctweaveCLI init \
  --display-name "CLI smoke persona" \
  --state "$STATE_FILE" \
  --plaintext true >"$WORK_DIR/init.json"

swift run --package-path "$CORE_DIR" NoctweaveCLI status \
  --state "$STATE_FILE" \
  --plaintext true >"$WORK_DIR/status.json"

swift run --package-path "$CORE_DIR" NoctweaveCLI maintain \
  --all true \
  --state "$STATE_FILE" \
  --plaintext true >"$WORK_DIR/maintenance.json"

swift run --package-path "$CORE_DIR" NoctweaveCLI pairing-invitation \
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
