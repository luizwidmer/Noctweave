#!/usr/bin/env python3
import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run_git(args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_entry(path):
    absolute = ROOT / path
    return {
        "path": path,
        "sha256": sha256_file(absolute),
        "bytes": absolute.stat().st_size,
    }


def git_status():
    status = run_git(["status", "--porcelain"])
    return {
        "commit": run_git(["rev-parse", "HEAD"]),
        "shortCommit": run_git(["rev-parse", "--short", "HEAD"]),
        "branch": run_git(["branch", "--show-current"]),
        "dirty": bool(status),
        "dirtyPaths": [line[3:] for line in status.splitlines() if line],
    }


def package_pin_summary():
    package = ROOT / "PICCP Relay Server" / "Package.resolved"
    payload = json.loads(package.read_text(encoding="utf-8"))
    pins = []
    for pin in payload.get("pins", []):
        state = pin.get("state", {})
        pins.append(
            {
                "identity": pin.get("identity"),
                "location": pin.get("location"),
                "version": state.get("version"),
                "revision": state.get("revision"),
            }
        )
    return sorted(pins, key=lambda item: item["identity"] or "")


def make_manifest():
    tracked_inputs = [
        "PICCP Documentation/noctyra_sbom.json",
        "PICCP Documentation/noctyra_cyclonedx_sbom.json",
        "PICCP Relay Server/Package.resolved",
        "PICCP Relay Server/Dockerfile",
        "scripts/generate-sbom.py",
        "scripts/verify-release.sh",
    ]
    return {
        "schema": "noctyra-release-provenance-v1",
        "generatedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "generatedBy": "scripts/generate-release-provenance.py",
        "git": git_status(),
        "trackedInputs": [file_entry(path) for path in tracked_inputs],
        "swiftPackagePins": package_pin_summary(),
        "releasePolicy": "PICCP Documentation/dependency_sbom_and_release_policy.md",
        "verificationCommand": "scripts/verify-release.sh",
    }


def main():
    parser = argparse.ArgumentParser(description="Generate a Noctyra release provenance manifest.")
    parser.add_argument("--output", help="Output path. Defaults to stdout.")
    args = parser.parse_args()
    payload = json.dumps(make_manifest(), indent=2, sort_keys=True) + "\n"
    if args.output:
        output = Path(args.output)
        if not output.is_absolute():
            output = ROOT / output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(payload, encoding="utf-8")
        try:
            print(output.relative_to(ROOT))
        except ValueError:
            print(output)
    else:
        print(payload, end="")


if __name__ == "__main__":
    main()
