#!/usr/bin/env python3
"""Check the YubiKit source snapshot against its pinned upstream digests."""

import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent.parent
VENDOR = ROOT / "NoctweaveSecurityKeys" / "Vendor" / "YubiKit"
SOURCES = VENDOR / "Sources" / "YubiKit"
PATCH_ROOT = Path("YubiKit/YubiKit")
PATCHED_FILES = {
    "APDU.swift",
    "Connection/FIDO/HIDFIDOConnection.swift",
    "SCP/SCPState.swift",
    "Utilities/Logger+Extensions.swift",
    "Utilities/Logs.swift",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


metadata = json.loads((VENDOR / "upstream.json").read_text(encoding="utf-8"))
if (metadata.get("version"), metadata.get("revision"), metadata.get("patch")) != (
    "1.4.0", "e19212f2efbca9af280e57542e669885de5acdc1", "local-hardening.patch"
):
    raise SystemExit("YubiKit upstream version, revision, or patch pin changed")

digests = json.loads((VENDOR / "upstream-sha256.json").read_text(encoding="utf-8"))
source_files = {str(path.relative_to(SOURCES)): path for path in SOURCES.rglob("*.swift")}
if len(source_files) != 195 or set(source_files) != set(digests):
    raise SystemExit("YubiKit Swift source inventory differs from its upstream digest list")
if any(path.is_symlink() or not path.is_file() for path in source_files.values()):
    raise SystemExit("YubiKit Swift source contains a symlink or non-regular file")
for name, path in source_files.items():
    if name not in PATCHED_FILES and sha256(path) != digests[name]:
        raise SystemExit(f"YubiKit source differs from upstream: {name}")

patch = VENDOR / metadata["patch"]
patched_paths = subprocess.run(
    ["git", "apply", "--numstat", str(patch)],
    check=True,
    capture_output=True,
    text=True,
).stdout
actual_paths = {line.split("\t", 2)[2] for line in patched_paths.splitlines()}
expected_paths = {str(PATCH_ROOT / name) for name in PATCHED_FILES}
if actual_paths != expected_paths:
    raise SystemExit("YubiKit local patch edits unexpected source files")

original_patched = {name: source_files[name].read_bytes() for name in PATCHED_FILES}
with tempfile.TemporaryDirectory(prefix="noctweave-yubikit-check-") as temporary:
    checkout = Path(temporary)
    for name, content in original_patched.items():
        target = checkout / PATCH_ROOT / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    subprocess.run(["git", "apply", "--unidiff-zero", "--reverse", "--check", str(patch)], cwd=checkout, check=True)
    subprocess.run(["git", "apply", "--unidiff-zero", "--reverse", str(patch)], cwd=checkout, check=True)
    for name in PATCHED_FILES:
        if sha256(checkout / PATCH_ROOT / name) != digests[name]:
            raise SystemExit(f"YubiKit local patch does not recover upstream: {name}")
    subprocess.run(["git", "apply", "--unidiff-zero", "--check", str(patch)], cwd=checkout, check=True)
    subprocess.run(["git", "apply", "--unidiff-zero", str(patch)], cwd=checkout, check=True)
    for name, content in original_patched.items():
        if (checkout / PATCH_ROOT / name).read_bytes() != content:
            raise SystemExit(f"YubiKit local patch does not reproduce vendor: {name}")

print("YubiKit 1.4.0: 195 upstream Swift source digests and 5 local patch files verified")
