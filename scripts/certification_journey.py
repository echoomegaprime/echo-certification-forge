#!/usr/bin/env python3
"""Run the offline, dependency-free Certification Forge release journey.

Cert Forge executes this script inside its pinned, network-isolated Python image.
The broader hosted workflow runs the complete test suite; this journey exercises
the repository's release-critical declarations and certificate renderer using
only the checked-out source revision and a disposable output directory.
"""
from __future__ import annotations

import json
import sys
import tempfile
import tokenize
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

from echo_certification_forge import __version__  # noqa: E402
from echo_certification_forge.certificate_graphic import (  # noqa: E402
    RepositoryCertificate,
    build_manifest,
    render_svg,
)


EXPECTED_APPS = {
    "arcanum",
    "build-tracker",
    "certification-forge",
    "fleet-builder",
    "knowledge-forge",
    "release-sentinel",
    "repo-steward",
    "sdk",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> int:
    require(__version__ == "1.1.0", "package version is not synchronized")
    python_files = sorted(SRC.rglob("*.py"))
    require(bool(python_files), "source tree contains no Python modules")
    for path in python_files:
        with tokenize.open(path) as handle:
            compile(handle.read(), path.as_posix(), "exec")

    apps = json.loads((ROOT / ".echo" / "apps.json").read_text(encoding="utf-8"))
    enabled = {
        name
        for name, value in apps.get("apps", {}).items()
        if isinstance(value, dict) and value.get("enabled") is True
    }
    require(enabled == EXPECTED_APPS, "the exact eight-app conformance set is not enabled")

    sdk = json.loads((ROOT / ".echo" / "sdk.json").read_text(encoding="utf-8"))
    capabilities = sdk.get("capabilities", [])
    require(len(capabilities) == 60, "SDK capability declaration must contain exactly 60 entries")
    require(len(set(capabilities)) == 60, "SDK capability declaration contains duplicates")
    require(all(isinstance(item, str) and item.startswith("echo.") for item in capabilities),
            "SDK capability declaration contains an invalid identifier")

    for relative in (
        "README.md",
        "LICENSE",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "CODE_OF_CONDUCT.md",
        "docs/ARCHITECTURE.md",
        "docs/OPERATIONS.md",
    ):
        require((ROOT / relative).is_file(), f"required showroom file missing: {relative}")

    certificate = RepositoryCertificate(
        repository="echoomegaprime/echo-certification-forge",
        source_commit="1" * 40,
        certified_at="2026-08-09T00:00:00Z",
        certforge_run_id="offline-release-journey",
        certforge_certificate_sha256="2" * 64,
        github_apps_certificate_id="offline-eight-app-journey",
        github_apps_certificate_sha256="3" * 64,
        verification_url="https://github.com/echoomegaprime/echo-certification-forge/releases",
    )
    with tempfile.TemporaryDirectory(prefix="echo-cert-journey-") as temporary:
        output = Path(temporary)
        graphic = output / "repository-certificate.svg"
        manifest = output / "repository-certificate.manifest.json"
        svg = render_svg(certificate)
        payload = build_manifest(certificate, svg)
        graphic.write_bytes(svg)
        manifest.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
        require(graphic.is_file() and graphic.stat().st_size > 100_000, "certificate SVG was not rendered")
        payload = json.loads(manifest.read_text(encoding="utf-8"))
        require(payload["source_commit"] == "1" * 40, "manifest lost source binding")
        require(payload["graphic_sha256"], "manifest lost graphic digest")

    print(json.dumps({
        "apps": "8/8",
        "capabilities": len(capabilities),
        "certificate_renderer": "PASS",
        "compiled_modules": len(python_files),
        "version": __version__,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
