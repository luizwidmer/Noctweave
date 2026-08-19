#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELAY_DIR="$ROOT_DIR/NoctweaveRelayServer"
SBOM_PATH="$ROOT_DIR/NoctweaveDocumentation/noctweave_sbom.json"
CYCLONEDX_SBOM_PATH="$ROOT_DIR/NoctweaveDocumentation/noctweave_cyclonedx_sbom.json"
BUN_LOCK_PATH="$RELAY_DIR/bun.lock"

source "$ROOT_DIR/scripts/liboqs-runtime.sh"
source "$ROOT_DIR/scripts/liboqs-version.sh"

cd "$ROOT_DIR"

VERIFY_TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/noctweave-release-check.XXXXXX")"
trap 'rm -rf "$VERIFY_TMP_DIR"' EXIT

echo "Resolving Swift package pins..."
cp "$RELAY_DIR/Package.resolved" "$VERIFY_TMP_DIR/Package.resolved.before"
(cd "$RELAY_DIR" && swift package resolve)
if ! cmp -s "$VERIFY_TMP_DIR/Package.resolved.before" "$RELAY_DIR/Package.resolved"; then
  diff -u "$VERIFY_TMP_DIR/Package.resolved.before" "$RELAY_DIR/Package.resolved"
  echo "Swift package resolution changed Package.resolved." >&2
  exit 1
fi

echo "Checking immutable liboqs Docker source pin..."
python3 - <<'PY' "$RELAY_DIR/Dockerfile" "$LIBOQS_VERSION" "$LIBOQS_COMMIT"
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
expected_version = sys.argv[2]
expected_commit = sys.argv[3]
version_match = re.search(r"^ARG LIBOQS_VERSION=([^\s]+)$", text, flags=re.MULTILINE)
if not version_match or version_match.group(1) != expected_version:
    raise SystemExit("Dockerfile liboqs version does not match scripts/liboqs-version.sh")
match = re.search(r"^ARG LIBOQS_COMMIT=([0-9a-f]{40})$", text, flags=re.MULTILINE)
if not match:
    raise SystemExit("Dockerfile must pin LIBOQS_COMMIT to a 40-character commit")
if match.group(1) != expected_commit:
    raise SystemExit("Dockerfile liboqs commit does not match scripts/liboqs-version.sh")
if 'git -C /tmp/liboqs fetch --depth 1 origin "${LIBOQS_COMMIT}"' not in text:
    raise SystemExit("Dockerfile must fetch liboqs by LIBOQS_COMMIT")
if 'test "$(git -C /tmp/liboqs rev-parse HEAD)" = "${LIBOQS_COMMIT}"' not in text:
    raise SystemExit("Dockerfile must verify the fetched liboqs commit")
stages = re.findall(r"^FROM\s+([^\s]+)(?:\s+AS\s+[^\s]+)?$", text, flags=re.MULTILINE | re.IGNORECASE)
if len(stages) < 2 or not stages[-1].startswith("ubuntu:22.04@sha256:"):
    raise SystemExit("Docker runtime stage must remain digest-pinned Ubuntu 22.04")
if 'COPY --from=builder /usr/lib/swift/linux/*.so /usr/lib/swift/linux/' not in text:
    raise SystemExit("Docker runtime stage must copy only Swift shared libraries")
if 'strip --strip-unneeded .build/release/NoctweaveRelayServer' not in text:
    raise SystemExit("Docker relay binary must be stripped for release")
PY

echo "Checking immutable container bases and runtime users..."
python3 - <<'PY' \
  "$RELAY_DIR/Dockerfile" \
  "$RELAY_DIR/Dockerfile.caddy-l4" \
  "$RELAY_DIR/Dockerfile.coturn" \
  "$RELAY_DIR/ReticulumBridge/Dockerfile"
import pathlib
import re
import sys

for value in sys.argv[1:]:
    path = pathlib.Path(value)
    text = path.read_text(encoding="utf-8")
    bases = re.findall(
        r"^FROM\s+([^\s]+)(?:\s+AS\s+[^\s]+)?$",
        text,
        flags=re.MULTILINE | re.IGNORECASE,
    )
    if not bases or any(not re.search(r"@sha256:[0-9a-f]{64}$", base) for base in bases):
        raise SystemExit(f"Every container base must be digest-pinned: {path}")

required = {
    "Dockerfile": "USER noctweave:noctweave",
    "Dockerfile.caddy-l4": "USER noctweave-caddy:noctweave-caddy",
    "Dockerfile.coturn": "USER nobody:nogroup",
    "ReticulumBridge/Dockerfile": "USER noctweave:noctweave",
}
for suffix, marker in required.items():
    path = next(pathlib.Path(value) for value in sys.argv[1:] if str(value).endswith(suffix))
    if marker not in path.read_text(encoding="utf-8"):
        raise SystemExit(f"Container runtime must retain its non-root user: {path}")

caddy = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
for marker in (
    "xcaddy build v2.11.4",
    "github.com/mholt/caddy-l4@v0.1.2",
    "golang.org/x/text@v0.39.0",
    "google.golang.org/grpc@v1.82.1",
):
    if marker not in caddy:
        raise SystemExit(f"Caddy dependency floor missing: {marker}")

reticulum = pathlib.Path(sys.argv[4]).read_text(encoding="utf-8")
if "python -m pip uninstall --yes pip setuptools" not in reticulum:
    raise SystemExit("Reticulum runtime must remove packaging tools after installation")
PY

echo "Checking vendored Apple liboqs version..."
for config in "$ROOT_DIR"/NoctweaveCore/Vendor/liboqs.xcframework/*/Headers/oqs/oqsconfig.h; do
  grep -q "OQS_VERSION_TEXT \"$LIBOQS_VERSION\"" "$config"
done

echo "Refreshing machine-readable SBOM..."
SBOM_CHECK_DIR="$VERIFY_TMP_DIR/sbom"
mkdir -p "$SBOM_CHECK_DIR"
GENERATED_SBOM_PATH="$SBOM_CHECK_DIR/noctweave_sbom.json"
GENERATED_CYCLONEDX_SBOM_PATH="$SBOM_CHECK_DIR/noctweave_cyclonedx_sbom.json"
scripts/generate-sbom.py \
  --output "$GENERATED_SBOM_PATH" \
  --cyclonedx-output "$GENERATED_CYCLONEDX_SBOM_PATH" \
  >/dev/null
diff -u "$SBOM_PATH" "$GENERATED_SBOM_PATH"
diff -u "$CYCLONEDX_SBOM_PATH" "$GENERATED_CYCLONEDX_SBOM_PATH"

echo "Checking documented container pins against the SBOM..."
python3 - <<'PY' "$SBOM_PATH" "$ROOT_DIR/NoctweaveDocumentation/dependency_sbom_and_release_policy.md"
import json
import pathlib
import sys

sbom_path, policy_path = sys.argv[1:]
with open(sbom_path, encoding="utf-8") as handle:
    payload = json.load(handle)
policy = pathlib.Path(policy_path).read_text(encoding="utf-8")

runtime = next(
    (
        component
        for component in payload.get("components", [])
        if component.get("type") == "container-base-image"
        and component.get("pinFile") == "NoctweaveRelayServer/Dockerfile"
        and component.get("stage") == "stage-2"
    ),
    None,
)
if runtime is None:
    raise SystemExit("SBOM must inventory the relay runtime container image")
version = runtime.get("version")
revision = runtime.get("revision")
if not version or not revision or len(revision) != 64:
    raise SystemExit("Relay runtime SBOM pin must include a version and SHA-256 digest")
documented_pin = f"`{runtime['name']}:{version}@sha256:{revision[:6]}…`"
if documented_pin not in policy:
    raise SystemExit(
        "Dependency policy relay runtime pin is stale; expected " + documented_pin
    )
PY

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

echo "Checking desktop dependency inventory and advisory state..."
python3 - <<'PY' "$SBOM_PATH" "$BUN_LOCK_PATH"
import json
import re
import sys

sbom_path, lock_path = sys.argv[1:]
with open(sbom_path, encoding="utf-8") as handle:
    payload = json.load(handle)
with open(lock_path, encoding="utf-8") as handle:
    lock_text = handle.read()

npm_components = {
    (component.get("name"), component.get("version"))
    for component in payload.get("components", [])
    if component.get("type") == "npm-package"
}
if not npm_components:
    raise SystemExit("SBOM must inventory the resolved Bun/npm dependency graph")
if ("ip-address", "10.3.1") not in npm_components:
    raise SystemExit("SBOM must retain the patched ip-address 10.3.1 security floor")
if '"ip-address": "10.3.1"' not in lock_text:
    raise SystemExit("bun.lock must retain the ip-address 10.3.1 override")
if re.search(r'"ip-address": \["ip-address@(?!10\.3\.1")', lock_text):
    raise SystemExit("bun.lock resolved a vulnerable ip-address release")
PY
if command -v bun >/dev/null 2>&1; then
  cp "$RELAY_DIR/package.json" "$VERIFY_TMP_DIR/package.json.before"
  cp "$BUN_LOCK_PATH" "$VERIFY_TMP_DIR/bun.lock.before"
  (cd "$RELAY_DIR" && bun install --frozen-lockfile --ignore-scripts >/dev/null)
  for dependency_file in package.json bun.lock; do
    if ! cmp -s "$VERIFY_TMP_DIR/$dependency_file.before" "$RELAY_DIR/$dependency_file"; then
      diff -u "$VERIFY_TMP_DIR/$dependency_file.before" "$RELAY_DIR/$dependency_file"
      echo "Frozen Bun install changed $dependency_file." >&2
      exit 1
    fi
  done
  (cd "$RELAY_DIR" && bun audit)
else
  echo "Bun not installed; release candidates must run frozen install and audit on a Bun host."
fi

echo "Checking local secret and state ignore rules..."
for sensitive_path in \
  ".env" \
  "NoctweaveRelayServer/.env" \
  "NoctweaveRelayServer/relay_store.sqlite" \
  "NoctweaveRelayServer/operator-config.json" \
  "NoctweaveRelayServer/relay_identity_v1.json" \
  "NoctweaveRelayServer/coordinator_directory_signing_key"; do
  git check-ignore -q "$sensitive_path"
done

echo "Checking Swift package dependency graph..."
(cd "$RELAY_DIR" && swift package show-dependencies >/dev/null)
python3 - <<'PY' "$RELAY_DIR/Package.swift" "$RELAY_DIR/Package.resolved"
import json
import pathlib
import re
import sys

manifest = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
if not re.search(
    r'swift-nio\.git",\s*exact:\s*"2\.100\.0"',
    manifest,
):
    raise SystemExit("SwiftNIO must retain the 2.100.0 security floor")

resolved = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
nio = next(
    (pin for pin in resolved.get("pins", []) if pin.get("identity") == "swift-nio"),
    None,
)
if not nio or nio.get("state", {}).get("version") != "2.100.0":
    raise SystemExit("Package.resolved must retain SwiftNIO 2.100.0")
PY

echo "Running Linux relay test suite..."
(cd "$RELAY_DIR" && swift test)

if command -v docker >/dev/null 2>&1; then
  echo "Checking Dockerfile syntax..."
  docker build --check "$RELAY_DIR" >/dev/null
  docker build --check -f "$RELAY_DIR/Dockerfile.caddy-l4" "$RELAY_DIR" >/dev/null
  docker build --check -f "$RELAY_DIR/Dockerfile.coturn" "$RELAY_DIR" >/dev/null
  docker build --check "$RELAY_DIR/ReticulumBridge" >/dev/null

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
