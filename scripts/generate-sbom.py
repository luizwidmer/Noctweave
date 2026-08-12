#!/usr/bin/env python3
import argparse
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import quote


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
    path = ROOT / "NoctweaveRelayServer" / "Package.resolved"
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
    components = []
    paths = [
        ROOT / "NoctweaveRelayServer" / "Dockerfile",
        ROOT / "NoctweaveRelayServer" / "Dockerfile.caddy-l4",
        ROOT / "NoctweaveRelayServer" / "Dockerfile.coturn",
        ROOT / "NoctweaveRelayServer" / "ReticulumBridge" / "Dockerfile",
    ]
    for path in paths:
        if not path.exists():
            continue
        text = read_text(path)
        for index, match in enumerate(
            re.finditer(r"^FROM\s+([^\s]+)(?:\s+AS\s+([^\s]+))?", text, flags=re.MULTILINE),
            start=1,
        ):
            reference = match.group(1)
            image, separator, digest = reference.partition("@sha256:")
            stage = match.group(2) or f"stage-{index}"
            image_name, version_separator, image_version = image.rpartition(":")
            if not version_separator or "/" in image_version:
                image_name = image
                image_version = None
            components.append(
                {
                    "type": "container-base-image",
                    "name": image_name,
                    "version": image_version,
                    "revision": digest if separator else None,
                    "source": "Dockerfile FROM",
                    "stage": stage,
                    "pinFile": str(path.relative_to(ROOT)),
                }
            )

        liboqs_match = re.search(r"^ARG\s+LIBOQS_VERSION=([^\s]+)", text, flags=re.MULTILINE)
        if liboqs_match:
            version = liboqs_match.group(1)
            commit_match = re.search(r"^ARG\s+LIBOQS_COMMIT=([0-9a-f]{40})", text, flags=re.MULTILINE)
            revision = commit_match.group(1) if commit_match else None
            components.append(
                {
                    "type": "source-build",
                    "name": "liboqs",
                    "version": version,
                    "revision": revision,
                    "source": "https://github.com/open-quantum-safe/liboqs.git",
                    "pinFile": str(path.relative_to(ROOT)),
                }
            )
    return components


def python_components():
    path = ROOT / "NoctweaveRelayServer" / "ReticulumBridge" / "requirements.txt"
    if not path.exists():
        return []
    components = []
    for line in read_text(path).splitlines():
        requirement = line.strip()
        if not requirement or requirement.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+-]+)", requirement)
        if match is None:
            raise ValueError(f"Unpinned Python dependency in {path}: {requirement}")
        name, version = match.groups()
        components.append(
            {
                "type": "python-package",
                "name": name,
                "version": version,
                "revision": None,
                "source": f"https://pypi.org/project/{name}/{version}/",
                "pinFile": str(path.relative_to(ROOT)),
            }
        )
    return components


def bun_components():
    lock_path = ROOT / "NoctweaveRelayServer" / "bun.lock"
    package_path = ROOT / "NoctweaveRelayServer" / "package.json"
    if not lock_path.exists():
        return []

    direct_names = set()
    if package_path.exists():
        manifest = json.loads(read_text(package_path))
        for field in ("dependencies", "devDependencies", "optionalDependencies"):
            direct_names.update((manifest.get(field) or {}).keys())

    quoted_json_string = r'"(?:\\.|[^"\\])*"'
    entry_pattern = re.compile(
        rf"^\s{{4}}({quoted_json_string}):\s*\[({quoted_json_string})",
        flags=re.MULTILINE,
    )
    components = {}
    for match in entry_pattern.finditer(read_text(lock_path)):
        resolved = json.loads(match.group(2))
        separator = resolved.rfind("@")
        if separator <= 0 or separator == len(resolved) - 1:
            raise ValueError(f"Unsupported Bun lock package identifier: {resolved}")
        name = resolved[:separator]
        version = resolved[separator + 1 :]
        components[(name, version)] = {
            "type": "npm-package",
            "name": name,
            "version": version,
            "revision": None,
            "source": f"https://www.npmjs.com/package/{quote(name, safe='@/')}/v/{quote(version, safe='.-_~')}",
            "pinFile": str(lock_path.relative_to(ROOT)),
            "direct": name in direct_names,
        }
    return [components[key] for key in sorted(components)]


def vendored_components():
    components = []
    liboqs = ROOT / "NoctweaveCore" / "Vendor" / "liboqs.xcframework"
    if liboqs.exists():
        version_header = liboqs / "macos-arm64" / "Headers" / "oqs" / "oqsconfig.h"
        version = None
        if version_header.exists():
            match = re.search(
                r'^#define OQS_VERSION_TEXT "([^"]+)"',
                read_text(version_header),
                flags=re.MULTILINE,
            )
            version = match.group(1) if match else None
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
                "version": version,
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
            "name": "NoctweaveCore",
            "source": "NoctweaveCore",
        },
        {
            "type": "local-source",
            "name": "NoctweaveCLI",
            "source": "NoctweaveCore/Sources/NoctweaveCLI",
        },
        {
            "type": "local-source",
            "name": "NoctweaveRelayServer",
            "source": "NoctweaveRelayServer",
        },
        {
            "type": "local-source",
            "name": "@noctweave/relay-desktop",
            "source": "NoctweaveRelayServer/desktop",
        },
    ]


def make_sbom():
    components = []
    components.extend(workspace_components())
    components.extend(package_resolved_components())
    components.extend(docker_components())
    components.extend(python_components())
    components.extend(bun_components())
    components.extend(vendored_components())
    return {
        "schema": "noctweave-sbom-v1",
        "name": "Noctweave",
        "generatedBy": "scripts/generate-sbom.py",
        "inputs": [
            "NoctweaveRelayServer/Package.resolved",
            "NoctweaveRelayServer/Dockerfile",
            "NoctweaveRelayServer/Dockerfile.caddy-l4",
            "NoctweaveRelayServer/Dockerfile.coturn",
            "NoctweaveRelayServer/ReticulumBridge/Dockerfile",
            "NoctweaveRelayServer/ReticulumBridge/requirements.txt",
            "NoctweaveRelayServer/package.json",
            "NoctweaveRelayServer/bun.lock",
            "NoctweaveCore/Vendor/liboqs.xcframework",
        ],
        "components": components,
    }


def cyclonedx_component(component):
    component_type = component.get("type")
    name = component.get("name")
    version = component.get("version") or component.get("revision") or "unknown"
    purl = None
    external_references = []

    if component_type == "swift-package":
        purl = f"pkg:swift/{name}@{version}"
    elif component_type == "python-package":
        purl = f"pkg:pypi/{name}@{version}"
    elif component_type == "npm-package":
        purl = f"pkg:npm/{quote(name, safe='/')}@{quote(version, safe='.-_~')}"
    elif component_type == "container-base-image":
        image_name = name or "unknown"
        image_version = component.get("version")
        purl = f"pkg:docker/{image_name}@{image_version}" if image_version else f"pkg:docker/{image_name}"
    elif name == "liboqs":
        purl = f"pkg:github/open-quantum-safe/liboqs@{version}"

    source = component.get("source")
    pin_file = component.get("pinFile")
    if source:
        external_references.append(
            {
                "type": "distribution",
                "url": source if re.match(r"^https?://", source) else f"file:{source}",
            }
        )
    if pin_file and pin_file != source:
        external_references.append({"type": "documentation", "url": f"file:{pin_file}"})

    bom_ref_name = re.sub(r"[^A-Za-z0-9_.:-]+", "-", name or "unknown")
    bom_ref_parts = [component_type or "component", bom_ref_name, version]
    if component.get("stage"):
        bom_ref_parts.append(component["stage"])
    payload = {
        "type": "library" if component_type != "container-base-image" else "container",
        "name": name,
        "version": version,
        "bom-ref": ":".join(bom_ref_parts),
    }
    if purl:
        payload["purl"] = purl
    revision = component.get("revision")
    if revision and re.fullmatch(r"[0-9a-fA-F]{64}", revision):
        payload["hashes"] = [{"alg": "SHA-256", "content": component["revision"]}]
    elif revision:
        payload["properties"] = [{"name": "noctweave:revision", "value": revision}]
    if external_references:
        payload["externalReferences"] = external_references
    return payload


def make_cyclonedx_sbom(noctweave_sbom):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000001",
        "version": 1,
        "metadata": {
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "scripts/generate-sbom.py",
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": noctweave_sbom["name"],
                "bom-ref": "application:Noctweave",
            },
        },
        "components": [cyclonedx_component(component) for component in noctweave_sbom["components"]],
    }


def main():
    parser = argparse.ArgumentParser(description="Generate the Noctweave machine-readable SBOM snapshot.")
    parser.add_argument(
        "--output",
        default="NoctweaveDocumentation/noctweave_sbom.json",
        help="Output path relative to the repository root.",
    )
    parser.add_argument(
        "--cyclonedx-output",
        default="NoctweaveDocumentation/noctweave_cyclonedx_sbom.json",
        help="CycloneDX JSON output path relative to the repository root.",
    )
    args = parser.parse_args()

    output = ROOT / args.output
    cyclonedx_output = ROOT / args.cyclonedx_output
    output.parent.mkdir(parents=True, exist_ok=True)
    cyclonedx_output.parent.mkdir(parents=True, exist_ok=True)
    payload = make_sbom()
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    cyclonedx_output.write_text(
        json.dumps(make_cyclonedx_sbom(payload), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    for path in (output, cyclonedx_output):
        try:
            print(path.relative_to(ROOT))
        except ValueError:
            print(path)


if __name__ == "__main__":
    main()
