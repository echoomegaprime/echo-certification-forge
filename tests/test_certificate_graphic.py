from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from echo_certification_forge.certificate_graphic import (
    RepositoryCertificate,
    build_manifest,
    main,
    render_svg,
)


def certificate() -> RepositoryCertificate:
    return RepositoryCertificate(
        repository="echoomegaprime/example-repository",
        source_commit="a" * 40,
        certified_at="2026-08-09T12:34:56Z",
        certforge_run_id="cert_0123456789abcdef",
        certforge_certificate_sha256="b" * 64,
        github_apps_certificate_id="ghapps_0123456789abcdef",
        github_apps_certificate_sha256="c" * 64,
        verification_url="https://github.com/echoomegaprime/example-repository/releases/tag/cert-a",
    )


def test_render_is_deterministic_self_contained_and_exactly_bound() -> None:
    cert = certificate()
    first = render_svg(cert)
    second = render_svg(cert)

    assert first == second
    text = first.decode("utf-8")
    assert "data:image/png;base64," in text
    assert cert.repository in text
    assert cert.source_commit in text
    assert cert.certforge_run_id in text
    assert cert.github_apps_certificate_id in text
    assert "PRODUCTION_READY" in text and "PASSED · 8/8" in text
    assert "ECHO OMEGA PRIME" in text and "Bob McWilliams II" in text
    assert cert.payload_sha256 in text


@pytest.mark.parametrize(
    "changed, message",
    [
        ({"release_verdict": "NOT_READY"}, "PRODUCTION_READY"),
        ({"github_apps_verdict": "FAILED"}, "all eight GitHub Apps"),
        ({"github_apps_passed": 7}, "all eight GitHub Apps"),
        ({"source_commit": "bad"}, "40-character"),
        ({"verification_url": "http://example.test"}, "HTTPS"),
        ({"certforge_certificate_sha256": "x" * 64}, "SHA-256"),
    ],
)
def test_render_fails_closed_when_evidence_is_incomplete(changed: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        render_svg(replace(certificate(), **changed))


def test_xml_values_are_escaped() -> None:
    svg = render_svg(replace(certificate(), repository="echoomegaprime/a&b<repo>"))
    text = svg.decode("utf-8")
    assert "a&amp;b&lt;repo&gt;" in text
    assert "a&b<repo>" not in text


def test_manifest_binds_payload_and_rendered_graphic() -> None:
    cert = certificate()
    svg = render_svg(cert)
    manifest = build_manifest(cert, svg)

    assert manifest["schema_version"] == "echo.repository-certificate-graphic.v1"
    assert manifest["source_commit"] == cert.source_commit
    assert manifest["payload_sha256"] == cert.payload_sha256
    assert manifest["graphic_sha256"] == hashlib.sha256(svg).hexdigest()
    assert manifest["visual_signers"] == ["ECHO OMEGA PRIME", "Bob McWilliams II"]


def test_cli_writes_svg_and_integrity_manifest_atomically(tmp_path: Path) -> None:
    input_path = tmp_path / "certificate.json"
    output_path = tmp_path / "certificate.svg"
    manifest_path = tmp_path / "certificate.manifest.json"
    input_path.write_text(json.dumps(certificate().__dict__), encoding="utf-8")

    assert main([
        "--input", str(input_path),
        "--output", str(output_path),
        "--manifest-output", str(manifest_path),
    ]) == 0

    svg = output_path.read_bytes()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert svg.startswith(b'<?xml version="1.0"')
    assert manifest["graphic_sha256"] == hashlib.sha256(svg).hexdigest()
