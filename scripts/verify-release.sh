#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELAY_DIR="$ROOT_DIR/Noctweave Relay Server"
SBOM_PATH="$ROOT_DIR/Noctweave Documentation/noctyra_sbom.json"
CYCLONEDX_SBOM_PATH="$ROOT_DIR/Noctweave Documentation/noctyra_cyclonedx_sbom.json"

source "$ROOT_DIR/scripts/liboqs-runtime.sh"

cd "$ROOT_DIR"

echo "Resolving Swift package pins..."
(cd "$RELAY_DIR" && swift package resolve)
git diff --exit-code -- "$RELAY_DIR/Package.resolved"

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
