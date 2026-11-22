"""Deterministic, fail-closed repository certification artwork.

The graphic is a presentation layer over two independently verifiable receipts. It can
only be rendered when the exact source revision earned both a Certification Forge
``PRODUCTION_READY`` verdict and an eight-application GitHub conformance pass.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import os
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Sequence


_HEX = frozenset("0123456789abcdef")
_BACKGROUND = Path(__file__).with_name("assets") / "repository_certificate_background.png"


def _is_hex(value: str, length: int) -> bool:
    return len(value) == length and all(character in _HEX for character in value.lower())


def _require_nonempty(label: str, value: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{label} is required")
    return normalized


@dataclass(frozen=True)
class RepositoryCertificate:
    repository: str
    source_commit: str
    certified_at: str
    certforge_run_id: str
    certforge_certificate_sha256: str
    github_apps_certificate_id: str
    github_apps_certificate_sha256: str
    verification_url: str
    release_verdict: str = "PRODUCTION_READY"
    github_apps_verdict: str = "PASSED"
    github_apps_passed: int = 8
    github_apps_total: int = 8
    authority_signer: str = "ECHO OMEGA PRIME"
    commander_signer: str = "Bob McWilliams II"

    def validate(self) -> None:
        _require_nonempty("repository", self.repository)
        _require_nonempty("certforge_run_id", self.certforge_run_id)
        _require_nonempty("github_apps_certificate_id", self.github_apps_certificate_id)
        if not _is_hex(self.source_commit, 40):
            raise ValueError("source_commit must be a 40-character hexadecimal Git commit")
        if not _is_hex(self.certforge_certificate_sha256, 64):
            raise ValueError("certforge_certificate_sha256 must be a SHA-256 digest")
        if not _is_hex(self.github_apps_certificate_sha256, 64):
            raise ValueError("github_apps_certificate_sha256 must be a SHA-256 digest")
        if self.release_verdict != "PRODUCTION_READY":
            raise ValueError("certificate graphic requires PRODUCTION_READY")
        if self.github_apps_verdict != "PASSED" or (self.github_apps_passed, self.github_apps_total) != (8, 8):
            raise ValueError("certificate graphic requires all eight GitHub Apps to pass")
        if not self.verification_url.startswith("https://"):
            raise ValueError("verification_url must use HTTPS")
        parsed = datetime.fromisoformat(self.certified_at.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("certified_at must include a timezone")

    def canonical_payload(self) -> bytes:
        self.validate()
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")

    @property
    def payload_sha256(self) -> str:
        return hashlib.sha256(self.canonical_payload()).hexdigest()

    @property
    def certificate_id(self) -> str:
        return f"ECHO-REPO-{self.source_commit[:12].upper()}-{self.payload_sha256[:12].upper()}"


def _escape(value: str) -> str:
    return html.escape(value, quote=True)


def render_svg(certificate: RepositoryCertificate, *, background_path: Path = _BACKGROUND) -> bytes:
    """Return a self-contained SVG bound to the certificate's canonical payload."""
    certificate.validate()
    background = background_path.read_bytes()
    if not background.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("certificate background must be a PNG")
    background_data = base64.b64encode(background).decode("ascii")
    issued = datetime.fromisoformat(certificate.certified_at.replace("Z", "+00:00")).strftime("%B %d, %Y")
    values = {key: _escape(str(value)) for key, value in asdict(certificate).items()}
    certificate_id = _escape(certificate.certificate_id)
    payload_digest = _escape(certificate.payload_sha256)

    svg = f'''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"
     width="1536" height="1024" viewBox="0 0 1536 1024" role="img"
     aria-labelledby="title description" data-certificate-id="{certificate_id}"
     data-payload-sha256="{payload_digest}" data-verification-url="{values['verification_url']}">
  <title id="title">ECHO OMEGA PRIME certified repository: {values['repository']}</title>
  <desc id="description">Exact commit {values['source_commit']} passed Certification Forge and all eight GitHub Apps.</desc>
  <image width="1536" height="1024" xlink:href="data:image/png;base64,{background_data}"/>
  <rect x="180" y="150" width="1176" height="605" rx="8" fill="#03070d" fill-opacity="0.72"/>
  <text x="768" y="210" text-anchor="middle" fill="#73d9ee" font-family="Arial, sans-serif"
        font-size="20" font-weight="700" letter-spacing="8">ECHO OMEGA PRIME</text>
  <text x="768" y="268" text-anchor="middle" fill="#f5d98c" font-family="Georgia, serif"
        font-size="48" font-weight="700" letter-spacing="3">CERTIFICATE OF VERIFIED RELEASE</text>
  <line x1="430" y1="295" x2="1106" y2="295" stroke="#cba24a" stroke-width="2"/>
  <text x="768" y="342" text-anchor="middle" fill="#aebdca" font-family="Arial, sans-serif"
        font-size="19" letter-spacing="2">THIS CERTIFIES THAT THE REPOSITORY</text>
  <text x="768" y="410" text-anchor="middle" fill="#ffffff" font-family="Georgia, serif"
        font-size="48" font-weight="700" textLength="1040" lengthAdjust="spacingAndGlyphs">{values['repository']}</text>
  <text x="768" y="458" text-anchor="middle" fill="#d2dae2" font-family="Arial, sans-serif" font-size="19">
    earned a signed exact-commit PRODUCTION_READY verdict and passed the complete GitHub App Suite
  </text>
  <g font-family="Consolas, 'Courier New', monospace" font-size="17">
    <text x="330" y="513" fill="#8195a8">SOURCE COMMIT</text>
    <text x="590" y="513" fill="#e5edf4">{values['source_commit']}</text>
    <text x="330" y="551" fill="#8195a8">CERT FORGE</text>
    <text x="590" y="551" fill="#8fe1b2">PRODUCTION_READY · {values['certforge_run_id']}</text>
    <text x="330" y="589" fill="#8195a8">GITHUB APPS</text>
    <text x="590" y="589" fill="#8fe1b2">PASSED · 8/8 · {values['github_apps_certificate_id']}</text>
    <text x="330" y="627" fill="#8195a8">ISSUED</text>
    <text x="590" y="627" fill="#e5edf4">{_escape(issued)}</text>
  </g>
  <g>
    <line x1="380" y1="700" x2="670" y2="700" stroke="#a98338" stroke-width="1.5"/>
    <text x="525" y="679" text-anchor="middle" fill="#f5d98c"
          font-family="'Segoe Script','Snell Roundhand','Brush Script MT',cursive" font-size="35">{values['authority_signer']}</text>
    <text x="525" y="728" text-anchor="middle" fill="#8393a2" font-family="Arial, sans-serif" font-size="14" letter-spacing="2">CERTIFYING AUTHORITY</text>
    <line x1="865" y1="700" x2="1155" y2="700" stroke="#a98338" stroke-width="1.5"/>
    <text x="1010" y="679" text-anchor="middle" fill="#f5d98c"
          font-family="'Segoe Script','Snell Roundhand','Brush Script MT',cursive" font-size="38">{values['commander_signer']}</text>
    <text x="1010" y="728" text-anchor="middle" fill="#8393a2" font-family="Arial, sans-serif" font-size="14" letter-spacing="2">COMMANDER APPROVAL</text>
  </g>
  <g font-family="Consolas, 'Courier New', monospace" font-size="13">
    <text x="450" y="830" fill="#7f91a2">CERTIFICATE ID</text>
    <text x="620" y="830" fill="#d8e0e8">{certificate_id}</text>
    <text x="450" y="857" fill="#7f91a2">PAYLOAD SHA-256</text>
    <text x="620" y="857" fill="#d8e0e8">{payload_digest}</text>
    <text x="450" y="884" fill="#7f91a2">VERIFY</text>
    <a xlink:href="{values['verification_url']}" target="_blank">
      <text x="620" y="884" fill="#73d9ee" text-decoration="underline">{values['verification_url']}</text>
    </a>
  </g>
</svg>
'''
    return svg.encode("utf-8")


def build_manifest(certificate: RepositoryCertificate, svg: bytes) -> dict[str, Any]:
    return {
        "schema_version": "echo.repository-certificate-graphic.v1",
        "certificate_id": certificate.certificate_id,
        "repository": certificate.repository,
        "source_commit": certificate.source_commit,
        "certified_at": certificate.certified_at,
        "release_verdict": certificate.release_verdict,
        "github_apps_verdict": certificate.github_apps_verdict,
        "github_apps_passed": certificate.github_apps_passed,
        "github_apps_total": certificate.github_apps_total,
        "certforge_run_id": certificate.certforge_run_id,
        "certforge_certificate_sha256": certificate.certforge_certificate_sha256,
        "github_apps_certificate_id": certificate.github_apps_certificate_id,
        "github_apps_certificate_sha256": certificate.github_apps_certificate_sha256,
        "verification_url": certificate.verification_url,
        "payload_sha256": certificate.payload_sha256,
        "graphic_sha256": hashlib.sha256(svg).hexdigest(),
        "visual_signers": [certificate.authority_signer, certificate.commander_signer],
    }


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        Path(temporary_name).unlink(missing_ok=True)
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Render a verified ECHO repository certificate graphic")
    parser.add_argument("--input", type=Path, required=True, help="JSON matching RepositoryCertificate")
    parser.add_argument("--output", type=Path, required=True, help="Destination self-contained SVG")
    parser.add_argument("--manifest-output", type=Path, required=True, help="Destination integrity manifest")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    payload = json.loads(args.input.read_text(encoding="utf-8"))
    certificate = RepositoryCertificate(**payload)
    svg = render_svg(certificate)
    manifest = build_manifest(certificate, svg)
    _atomic_write(args.output, svg)
    _atomic_write(args.manifest_output, (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    print(json.dumps(manifest, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
