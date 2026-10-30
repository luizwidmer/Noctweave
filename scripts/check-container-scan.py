#!/usr/bin/env python3
"""Fail a release if a final-image Trivy report is incomplete or actionable."""

import argparse
import json
import pathlib
import re
import sys
from typing import List, Optional


def check_report(
    path: pathlib.Path,
    image_id: str,
    os_family: str,
    brotli: bool,
    language_type: Optional[str],
    language_target: Optional[str],
    required_packages: List[str],
) -> None:
    with path.open(encoding="utf-8") as handle:
        report = json.load(handle)

    metadata = report.get("Metadata") or {}
    os_metadata = metadata.get("OS") or {}
    if report.get("SchemaVersion") != 2 or report.get("ArtifactType") != "container_image":
        raise ValueError("Trivy report is not a version-2 container-image scan")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise ValueError("Docker did not return a valid image ID")
    if metadata.get("ImageID") != image_id:
        raise ValueError("Trivy scanned a different image ID than Docker built")
    if os_metadata.get("Family") != os_family:
        raise ValueError(f"Trivy did not identify the expected {os_family} runtime OS")

    results = report.get("Results")
    if not isinstance(results, list) or not results:
        raise ValueError("Trivy report has no package results")
    os_packages = [
        package
        for result in results
        if result.get("Class") == "os-pkgs"
        for package in result.get("Packages") or []
    ]
    if not os_packages:
        raise ValueError("Trivy report has no installed OS package inventory")

    if required_packages and not language_type:
        raise ValueError("Required language packages need --language-type")
    if language_type:
        language_results = [
            result
            for result in results
            if result.get("Class") == "lang-pkgs"
            and result.get("Type") == language_type
            and (
                language_target is None
                or str(result.get("Target", "")).lstrip("/") == language_target.lstrip("/")
            )
            and result.get("Packages")
        ]
        if not language_results:
            raise ValueError(
                f"Trivy did not inventory {language_type} packages"
                + (f" in {language_target}" if language_target else "")
            )
        found_packages = {
            (package.get("Name"), package.get("Version"))
            for result in language_results
            for package in result.get("Packages") or []
        }
        for required in required_packages:
            name, separator, version = required.rpartition("@")
            if not separator or not name or not version:
                raise ValueError(f"Invalid required package: {required}")
            if (name, version) not in found_packages:
                raise ValueError(f"Trivy did not inventory {required}")

    if brotli:
        versions = [package.get("Version") for package in os_packages if package.get("Name") == "brotli-libs"]
        if len(versions) != 1:
            raise ValueError(f"Expected one installed brotli-libs package, found {versions}")
        match = re.fullmatch(r"([0-9]+)\.([0-9]+)\.([0-9]+)-r([0-9]+)", versions[0] or "")
        if not match or tuple(map(int, match.groups())) < (1, 2, 1, 0):
            raise ValueError(f"Installed brotli-libs is below 1.2.1-r0: {versions[0]}")

    blocked = [
        vulnerability
        for result in results
        for vulnerability in result.get("Vulnerabilities") or []
        if vulnerability.get("Severity") in ("CRITICAL", "HIGH")
    ]
    if blocked:
        summary = ", ".join(
            f"{vulnerability.get('VulnerabilityID', '?')} "
            f"{vulnerability.get('PkgName', '?')}@{vulnerability.get('InstalledVersion', '?')}"
            for vulnerability in blocked[:10]
        )
        raise ValueError(
            f"Final image has {len(blocked)} HIGH/CRITICAL findings: {summary}"
        )
    print(f"Passed final-image scan: {image_id} ({os_family}; no HIGH/CRITICAL findings)")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=pathlib.Path)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--os-family", required=True, choices=("alpine", "ubuntu"))
    parser.add_argument("--brotli-floor", action="store_true")
    parser.add_argument("--language-type", choices=("gobinary", "python-pkg"))
    parser.add_argument("--language-target")
    parser.add_argument("--required-package", action="append", default=[])
    args = parser.parse_args()
    try:
        check_report(
            args.report,
            args.image_id,
            args.os_family,
            args.brotli_floor,
            args.language_type,
            args.language_target,
            args.required_package,
        )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"Container release scan failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
