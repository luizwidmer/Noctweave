#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELAY_DIR="$ROOT_DIR/NoctweaveRelayServer"
PLATFORM="${NOCTWEAVE_CONTAINER_PLATFORM:-linux/amd64}"

if [[ "$PLATFORM" != linux/amd64 && "$PLATFORM" != linux/arm64 ]]; then
  echo "NOCTWEAVE_CONTAINER_PLATFORM must be linux/amd64 or linux/arm64." >&2
  exit 1
fi
for tool in docker trivy python3; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "Final-image release verification requires $tool." >&2
    exit 1
  fi
done
if ! docker info --format '{{.ServerVersion}}' >/dev/null; then
  echo "Final-image release verification requires a running Docker daemon." >&2
  exit 1
fi

SCAN_DIR="${NOCTWEAVE_CONTAINER_SCAN_OUTPUT_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/noctweave-container-scans.XXXXXX")}"
mkdir -p "$SCAN_DIR"
SCAN_DIR="$(cd "$SCAN_DIR" && pwd)"
echo "Final-image scan reports: $SCAN_DIR"
rm -f "$SCAN_DIR/release-gate-complete"
for name in relay caddy coturn reticulum; do
  rm -f "$SCAN_DIR/$name.verified-image-id"
done

# A fresh cache forces a current vulnerability DB download for this release
# run. The parent verifier may own the cache so its final filesystem scan can
# use the same DB after the container script exits.
if [[ -n "${NOCTWEAVE_TRIVY_CACHE_DIR:-}" ]]; then
  SCAN_CACHE_DIR="$NOCTWEAVE_TRIVY_CACHE_DIR"
  mkdir -p "$SCAN_CACHE_DIR"
  OWN_SCAN_CACHE=false
else
  SCAN_CACHE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/noctweave-trivy-db.XXXXXX")"
  OWN_SCAN_CACHE=true
fi
IMAGE_PREFIX="noctweave-release-audit-$$"
cleanup() {
  if [[ "$OWN_SCAN_CACHE" == true ]]; then
    rm -rf "$SCAN_CACHE_DIR"
  fi
  # Only remove tags created by this invocation. Scan reports and exact image
  # IDs stay in SCAN_DIR for release review.
  for name in relay caddy coturn reticulum; do
    docker image rm "$IMAGE_PREFIX:$name" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT
trivy image --config "" --ignorefile "" --cache-dir "$SCAN_CACHE_DIR" --download-db-only

# A local Go replacement appears as (devel) in the final binary, so Trivy
# cannot report the upstream v3 advisories against it. Scan the exact upstream
# module separately and fail if a new advisory needs a backport review.
trivy fs --config "" --ignorefile "" --ignore-unfixed=false \
  --cache-dir "$SCAN_CACHE_DIR" --skip-db-update --scanners vuln \
  --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL --format json \
  --output "$SCAN_DIR/caddy-unpatched-jose.json" \
  "$ROOT_DIR/scripts/fixtures/caddy-go-jose-v3"
python3 - "$SCAN_DIR/caddy-unpatched-jose.json" <<'PY'
import json
import pathlib
import sys

report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if report.get("SchemaVersion") != 2 or report.get("ArtifactType") != "filesystem":
    raise SystemExit("Trivy did not scan the go-jose/v3 sentinel filesystem")
results = [
    item for item in report.get("Results", [])
    if item.get("Target") == "go.mod" and item.get("Type") == "gomod"
]
if len(results) != 1:
    raise SystemExit("Trivy did not inspect the exact go-jose/v3 sentinel go.mod")
found = {
    finding.get("VulnerabilityID")
    for finding in results[0].get("Vulnerabilities", [])
    if finding.get("PkgName") == "github.com/go-jose/go-jose/v3"
}
expected = {"CVE-2026-116585", "CVE-2026-116586", "CVE-2026-116587"}
if found != expected:
    raise SystemExit(f"go-jose/v3 backport advisory set changed: {sorted(found)}")
PY

build_and_scan() {
  local name="$1" dockerfile="$2" context="$3" os_family="$4" runtime_user="$5" image image_id report
  image="$IMAGE_PREFIX:$name"
  report="$SCAN_DIR/$name.json"
  # A reused output directory must never supply a report from an earlier run.
  rm -f "$report" "$SCAN_DIR/$name.image-id"
  echo "Building final $name image for $PLATFORM..."
  docker build --pull --no-cache --platform "$PLATFORM" \
    --file "$dockerfile" --tag "$image" "$context"
  image_id="$(docker image inspect "$image" --format '{{.Id}}')"
  if [[ ! "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    echo "Docker returned an invalid $name image ID: $image_id" >&2
    exit 1
  fi
  local actual_user
  actual_user="$(docker image inspect "$image" --format '{{.Config.User}}')"
  if [[ "$actual_user" != "$runtime_user" ]]; then
    echo "Final $name image must run as $runtime_user; found $actual_user." >&2
    exit 1
  fi
  echo "$image_id" > "$SCAN_DIR/$name.image-id"
  echo "Scanning final $name image ($image_id)..."
  trivy image --config "" --ignorefile "" --cache-dir "$SCAN_CACHE_DIR" --skip-db-update \
    --image-src docker --scanners vuln --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL \
    --ignorefile "" --ignore-unfixed=false --format json --output "$report" \
    "$image"
  local -a extra=()
  if [[ "$name" == caddy || "$name" == coturn ]]; then
    extra+=(--brotli-floor)
    # Check the actual installed package inside the final image as well as
    # Trivy's package inventory, so a scanner omission cannot hide the floor.
    local installed version comparison
    installed="$(docker run --rm --platform "$PLATFORM" --entrypoint /sbin/apk "$image" list --installed brotli-libs)"
    if [[ ! "$installed" =~ ^brotli-libs-([0-9]+\.[0-9]+\.[0-9]+-r[0-9]+)[[:space:]] ]]; then
      echo "Cannot identify final $name brotli-libs version: $installed" >&2
      exit 1
    fi
    version="${BASH_REMATCH[1]}"
    comparison="$(docker run --rm --platform "$PLATFORM" --entrypoint /sbin/apk "$image" version -t "$version" 1.2.1-r0)"
    if [[ "$comparison" != = && "$comparison" != '>' ]]; then
      echo "Final $name brotli-libs must be >=1.2.1-r0; found $version." >&2
      exit 1
    fi
  fi
  if [[ "$name" == caddy ]]; then
    local patch_file="$RELAY_DIR/CaddyPatches/go-jose-v3-rsa-limit.patch"
    python3 - "$patch_file" "$RELAY_DIR/Dockerfile.caddy-l4" <<'PY'
import hashlib
import pathlib
import sys

expected = "fc9d4b847367eef5de2bd9574ec277211b3a4564ce0b14240f01c179f020d8ad"
actual = hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest()
if actual != expected:
    raise SystemExit(f"Caddy go-jose/v3 security backport digest changed: {actual}")
dockerfile = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
for required in (
    "go mod download github.com/go-jose/go-jose/v3@v3.0.5",
    "patch --batch --fuzz=0 -p1 -d /opt/noctweave-go-jose-v3 < /tmp/go-jose-v3-rsa-limit.patch",
    "go test -count=1 . ./json ./cipher",
    "--replace github.com/go-jose/go-jose/v3=/opt/noctweave-go-jose-v3",
):
    if required not in dockerfile:
        raise SystemExit(f"Caddy Dockerfile lost the v3 backport step: {required}")
PY
    docker run --rm --platform "$PLATFORM" --entrypoint /usr/bin/caddy \
      "$image" build-info > "$SCAN_DIR/caddy.build-info"
    python3 - "$SCAN_DIR/caddy.build-info" <<'PY'
import pathlib
import sys

lines = [line.rstrip("\t ") for line in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()]
expected = [
    "dep\tgithub.com/go-jose/go-jose/v3\tv3.0.5",
    "=>\t/opt/noctweave-go-jose-v3\t(devel)",
]
if not any(lines[index:index + 2] == expected for index in range(len(lines) - 1)):
    raise SystemExit("Final Caddy binary lacks the verified local go-jose/v3 backport")
PY
    docker run --rm --platform "$PLATFORM" --entrypoint /usr/bin/caddy \
      --mount "type=bind,src=$RELAY_DIR/Caddyfile.layer4,dst=/audit/Caddyfile.layer4,readonly" \
      --env RELAY_DOMAIN=relay.example.com \
      --env ACME_EMAIL=operator@example.com \
      --env RELAY_HTTP_UPSTREAM=127.0.0.1:9340 \
      "$image" adapt --config /audit/Caddyfile.layer4 --adapter caddyfile \
      > "$SCAN_DIR/caddy-adapted.json"
    python3 "$RELAY_DIR/CaddyPatches/check-caddy-routes.py" \
      < "$SCAN_DIR/caddy-adapted.json"
    extra+=(
      --language-type gobinary --language-target usr/bin/caddy
      --required-package github.com/caddyserver/caddy/v2@v2.11.7
      --required-package github.com/mholt/caddy-l4@v0.1.2
      --required-package github.com/go-jose/go-jose/v4@v4.1.6
      --required-package github.com/go-chi/chi/v5@v5.4.0
      --required-package golang.org/x/net@v0.62.0
    )
  elif [[ "$name" == reticulum ]]; then
    extra+=(
      --language-type python-pkg
      --required-package cffi@2.1.1
      --required-package cryptography@50.0.2
      --required-package msgpack@1.2.4
      --required-package pycparser@3.12
      --required-package pyserial@3.5
      --required-package rns@1.5.7
    )
  fi
  if [[ "$name" == relay ]]; then
    # Bash 3.2 treats an empty array expansion as unbound under set -u.
    python3 "$ROOT_DIR/scripts/check-container-scan.py" "$report" \
      --image-id "$image_id" --os-family "$os_family"
  else
    python3 "$ROOT_DIR/scripts/check-container-scan.py" "$report" \
      --image-id "$image_id" --os-family "$os_family" "${extra[@]}"
  fi
  printf '%s\n' "$image_id" > "$SCAN_DIR/$name.verified-image-id"
}

build_and_scan relay "$RELAY_DIR/Dockerfile" "$RELAY_DIR" ubuntu noctweave:noctweave
build_and_scan caddy "$RELAY_DIR/Dockerfile.caddy-l4" "$RELAY_DIR" alpine noctweave-caddy:noctweave-caddy
build_and_scan coturn "$RELAY_DIR/Dockerfile.coturn" "$RELAY_DIR" alpine nobody:nogroup
build_and_scan reticulum "$RELAY_DIR/ReticulumBridge/Dockerfile" "$RELAY_DIR/ReticulumBridge" alpine noctweave:noctweave

for name in relay caddy coturn reticulum; do
  if [[ ! -s "$SCAN_DIR/$name.json" || ! -s "$SCAN_DIR/$name.image-id" || ! -s "$SCAN_DIR/$name.verified-image-id" ]] || \
    ! cmp -s "$SCAN_DIR/$name.image-id" "$SCAN_DIR/$name.verified-image-id"; then
    echo "Final $name image lacks a completed scan for this run." >&2
    exit 1
  fi
done
printf '%s\n' "${NOCTWEAVE_CONTAINER_SCAN_RUN_TOKEN:-standalone}" > "$SCAN_DIR/release-gate-complete"
echo "All final container images passed the release scan for $PLATFORM."
