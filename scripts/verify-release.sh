#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELAY_DIR="$ROOT_DIR/PICCP Relay Server"
SBOM_PATH="$ROOT_DIR/PICCP Documentation/noctyra_sbom.json"
CYCLONEDX_SBOM_PATH="$ROOT_DIR/PICCP Documentation/noctyra_cyclonedx_sbom.json"

source "$ROOT_DIR/scripts/liboqs-runtime.sh"

cd "$ROOT_DIR"

echo "Refreshing machine-readable SBOM..."
scripts/generate-sbom.py >/dev/null
git diff --exit-code -- "$SBOM_PATH"
git diff --exit-code -- "$CYCLONEDX_SBOM_PATH"

echo "Validating SBOM JSON..."
python3 -m json.tool "$SBOM_PATH" >/dev/null
python3 -m json.tool "$CYCLONEDX_SBOM_PATH" >/dev/null
python3 - <<'PY' "$CYCLONEDX_SBOM_PATH"
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    payload = json.load(handle)

if payload.get("bomFormat") != "CycloneDX" or payload.get("specVersion") != "1.6":
    raise SystemExit("CycloneDX SBOM must declare bomFormat=CycloneDX and specVersion=1.6")

refs = [component.get("bom-ref") for component in payload.get("components", [])]
if not refs or any(not ref for ref in refs):
    raise SystemExit("CycloneDX SBOM components must include bom-ref values")
if len(refs) != len(set(refs)):
    raise SystemExit("CycloneDX SBOM component bom-ref values must be unique")
PY

echo "Generating release provenance manifest..."
PROVENANCE_PATH="$(mktemp)"
trap 'rm -f "$PROVENANCE_PATH"' EXIT
scripts/generate-release-provenance.py --output "$PROVENANCE_PATH" >/dev/null
python3 -m json.tool "$PROVENANCE_PATH" >/dev/null
python3 - <<'PY' "$PROVENANCE_PATH"
import json
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as handle:
    payload = json.load(handle)

if payload.get("schema") != "noctyra-release-provenance-v1":
    raise SystemExit("Release provenance manifest has unexpected schema")
if not payload.get("git", {}).get("commit"):
    raise SystemExit("Release provenance manifest must include a git commit")
tracked = payload.get("trackedInputs", [])
if not tracked or any(len(item.get("sha256", "")) != 64 for item in tracked):
    raise SystemExit("Release provenance tracked inputs must include SHA-256 hashes")
if not payload.get("swiftPackagePins"):
    raise SystemExit("Release provenance manifest must include Swift package pins")
PY

echo "Resolving Swift package pins..."
(cd "$RELAY_DIR" && swift package resolve)
git diff --exit-code -- "$RELAY_DIR/Package.resolved"

echo "Checking Swift package dependency graph..."
(cd "$RELAY_DIR" && swift package show-dependencies >/dev/null)

echo "Running Linux relay test suite..."
(cd "$RELAY_DIR" && swift test)

if command -v docker >/dev/null 2>&1; then
  echo "Checking Dockerfile syntax..."
  docker build --check "$RELAY_DIR" >/dev/null

  if command -v trivy >/dev/null 2>&1; then
    echo "Running Trivy filesystem scan..."
    trivy fs --scanners vuln,secret --severity HIGH,CRITICAL --exit-code 1 "$ROOT_DIR"
  else
    echo "Trivy not installed; skipping container/filesystem vulnerability scan."
  fi
else
  echo "Docker not installed; skipping Dockerfile and container checks."
fi

echo "Release verification complete."
