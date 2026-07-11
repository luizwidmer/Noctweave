#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELAY_DIR="$ROOT_DIR/NoctweaveRelayServer"
SBOM_PATH="$ROOT_DIR/NoctweaveDocumentation/noctweave_sbom.json"
CYCLONEDX_SBOM_PATH="$ROOT_DIR/NoctweaveDocumentation/noctweave_cyclonedx_sbom.json"

source "$ROOT_DIR/scripts/liboqs-runtime.sh"

cd "$ROOT_DIR"

echo "Resolving Swift package pins..."
(cd "$RELAY_DIR" && swift package resolve)
git diff --exit-code -- "$RELAY_DIR/Package.resolved"

echo "Checking immutable liboqs Docker source pin..."
python3 - <<'PY' "$RELAY_DIR/Dockerfile"
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
match = re.search(r"^ARG LIBOQS_COMMIT=([0-9a-f]{40})$", text, flags=re.MULTILINE)
if not match:
    raise SystemExit("Dockerfile must pin LIBOQS_COMMIT to a 40-character commit")
if 'git -C /tmp/liboqs fetch --depth 1 origin "${LIBOQS_COMMIT}"' not in text:
    raise SystemExit("Dockerfile must fetch liboqs by LIBOQS_COMMIT")
if 'test "$(git -C /tmp/liboqs rev-parse HEAD)" = "${LIBOQS_COMMIT}"' not in text:
    raise SystemExit("Dockerfile must verify the fetched liboqs commit")
stages = re.findall(r"^FROM\s+([^\s]+)(?:\s+AS\s+[^\s]+)?$", text, flags=re.MULTILINE | re.IGNORECASE)
if len(stages) < 2 or stages[-1] != "ubuntu:22.04":
    raise SystemExit("Docker runtime stage must remain the slim Ubuntu 22.04 image")
if 'COPY --from=builder /usr/lib/swift/linux/*.so /usr/lib/swift/linux/' not in text:
    raise SystemExit("Docker runtime stage must copy only Swift shared libraries")
if 'strip --strip-unneeded .build/release/NoctweaveRelayServer' not in text:
    raise SystemExit("Docker relay binary must be stripped for release")
PY

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
