#!/usr/bin/env python3
import argparse
import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_text(path):
    return path.read_text(encoding="utf-8")


def package_resolved_components():
    path = ROOT / "PICCP Relay Server" / "Package.resolved"
    payload = json.loads(read_text(path))
    components = []
    for pin in payload.get("pins", []):
        state = pin.get("state", {})
        components.append(
            {
                "type": "swift-package",
                "name": pin.get("identity"),
                "version": state.get("version"),
                "revision": state.get("revision"),
                "source": pin.get("location"),
                "pinFile": str(path.relative_to(ROOT)),
            }
        )
    return sorted(components, key=lambda item: item["name"] or "")


def docker_components():
    path = ROOT / "PICCP Relay Server" / "Dockerfile"
    text = read_text(path)
    components = []

    for index, match in enumerate(
        re.finditer(r"^FROM\s+([^\s]+)(?:\s+AS\s+([^\s]+))?", text, flags=re.MULTILINE),
        start=1,
    ):
        image = match.group(1)
        stage = match.group(2) or f"stage-{index}"
        components.append(
            {
                "type": "container-base-image",
                "name": image,
                "version": None,
                "revision": None,
                "source": "Dockerfile FROM",
                "stage": stage,
                "pinFile": str(path.relative_to(ROOT)),
            }
        )

    liboqs_match = re.search(r"^ARG\s+LIBOQS_VERSION=([^\s]+)", text, flags=re.MULTILINE)
    if liboqs_match:
        version = liboqs_match.group(1)
        components.append(
            {
                "type": "source-build",
                "name": "liboqs",
                "version": version,
                "revision": version,
                "source": "https://github.com/open-quantum-safe/liboqs.git",
                "pinFile": str(path.relative_to(ROOT)),
            }
        )
    return components


def vendored_components():
    components = []
    liboqs = ROOT / "PICCPCore" / "Vendor" / "liboqs.xcframework"
    if liboqs.exists():
        files = sorted(path for path in liboqs.rglob("*") if path.is_file())
        tree_digest = hashlib.sha256()
        for file_path in files:
            relative = file_path.relative_to(ROOT).as_posix()
            file_digest = sha256_file(file_path)
            tree_digest.update(relative.encode("utf-8"))
            tree_digest.update(b"\0")
            tree_digest.update(file_digest.encode("ascii"))
            tree_digest.update(b"\0")
        components.append(
            {
                "type": "vendored-binary",
                "name": "liboqs.xcframework",
                "version": None,
                "revision": tree_digest.hexdigest(),
                "source": str(liboqs.relative_to(ROOT)),
                "fileCount": len(files),
            }
        )
    return components


def workspace_components():
    return [
        {
            "type": "local-source",
            "name": "PICCPCore",
            "source": "PICCPCore",
        },
        {
            "type": "local-source",
            "name": "PICCP Relay Server",
            "source": "PICCP Relay Server",
        },
        {
            "type": "local-source",
            "name": "PICCP Messaging Client",
            "source": "PICCP Messaging Client",
        },
        {
            "type": "local-source",
            "name": "PICCP Server",
            "source": "PICCP Server",
        },
    ]


def make_sbom():
    components = []
    components.extend(workspace_components())
    components.extend(package_resolved_components())
    components.extend(docker_components())
    components.extend(vendored_components())
    return {
        "schema": "noctyra-sbom-v1",
        "name": "Noctyra",
        "generatedBy": "scripts/generate-sbom.py",
        "inputs": [
            "PICCP Relay Server/Package.resolved",
            "PICCP Relay Server/Dockerfile",
            "PICCPCore/Vendor/liboqs.xcframework",
        ],
        "components": components,
    }


def main():
    parser = argparse.ArgumentParser(description="Generate the Noctyra machine-readable SBOM snapshot.")
    parser.add_argument(
        "--output",
        default="PICCP Documentation/noctyra_sbom.json",
        help="Output path relative to the repository root.",
    )
    args = parser.parse_args()

    output = ROOT / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = make_sbom()
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(output.relative_to(ROOT))


if __name__ == "__main__":
    main()
