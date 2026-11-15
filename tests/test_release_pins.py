"""ops-20260924: the supply-chain pins stay consistent and patched (issue #22 security release).

P4 image sealing fails closed on HIGH vulnerabilities with an available fix. This guards the
fix: consistent role-image base and OS package pins, a separately pinned sandbox input,
and the patched cryptography release hash-locked,
and the dispatcher unit decoupled from API restarts.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATCHED_BASE = "sha256:a61cbd76a882645de7f91423329fe43a67eed60d7da24f9e5331414bb3618b20"
P4_BASE_NAME = "python:3.12.16-alpine3.24"
# Actual qualified offline image ID; archive/recipe binding has a separate drift guard.
SANDBOX_IMAGE = "sha256:061deb070723eabc0cb5cb8ffd1eeab591206d27fdf71991e915cce72e4e7558"
VULNERABLE_BASE = "sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df"
ROLES = ("runner", "custody", "anchor", "signer", "worker", "verifier")


def _text(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_every_role_image_uses_the_patched_base() -> None:
    for role in ROLES:
        dockerfile = _text(f"images/{role}/Dockerfile")
        assert dockerfile.startswith(f"FROM {P4_BASE_NAME}@{PATCHED_BASE}\n"), role
        assert f'org.opencontainers.image.base.digest="{PATCHED_BASE}"' in dockerfile, role
        assert VULNERABLE_BASE not in dockerfile, role
        assert "apk add --no-cache --upgrade krb5-libs=1.22.3-r0" in dockerfile, role
        assert 'org.opencontainers.image.source="https://github.com/echoomegaprime/echo-certification-forge"' in dockerfile, role


def test_sandbox_runtime_reference_stays_exactly_pinned() -> None:
    assert f'DEFAULT_IMAGE = "{SANDBOX_IMAGE}"' in _text("src/echo_certification_forge/sandbox.py")


def test_p4_gate_uses_the_current_role_base() -> None:
    assert f'BASE_DIGEST="${{BASE_DIGEST:-{PATCHED_BASE}}}"' in _text("scripts/run_p4_gate.sh")
    assert f'BASE_NAME = "{P4_BASE_NAME}"' in _text("scripts/seal_p4_images.py")


def test_cryptography_is_the_patched_hash_locked_release() -> None:
    assert "cryptography==50.0.0" in _text("images/requirements.in")
    lock = _text("images/requirements.lock").replace("\r\n", "\n")
    block = re.search(r"^cryptography==(\S+) \\\n((?:    --hash=sha256:[0-9a-f]{64}(?: \\)?\n)+)", lock, re.M)
    assert block is not None
    major = int(block.group(1).split(".")[0])
    assert major >= 50
    assert len(re.findall(r"sha256:[0-9a-f]{64}", block.group(2))) >= 20
    assert "cryptography==49" not in lock


def test_dispatcher_wants_but_does_not_require_the_api_service() -> None:
    script = _text("deploy/deploy_forge.sh")
    dispatcher = script[script.index('sudo tee "$DISPATCH_UNIT_PATH"'):]
    unit = dispatcher[: dispatcher.index("[Service]")]
    assert "Wants=$SERVICE.service" in unit
    assert "Requires=$SERVICE.service" not in unit
    assert "After=network.target $SERVICE.service" in unit


def test_source_fetch_credential_helper_is_configurable_with_safe_default() -> None:
    script = _text("deploy/deploy_forge.sh")
    assert ('GIT_CREDENTIAL_HELPER="${CERTFORGE_GIT_CREDENTIAL_HELPER:-store --file='
            '/home/forge/.config/echo/omega_git_creds}"') in script
    assert 'GITC=(-c credential.helper= -c credential.helper="$GIT_CREDENTIAL_HELPER")' in script


def test_deploy_default_manifest_digest_matches_the_enforced_pin() -> None:
    script = _text("deploy/deploy_forge.sh")
    run_worker = _text("src/echo_certification_forge/run_worker.py")
    pinned = re.search(r'_PRODUCTION_MANIFEST_SHA256 = \(\s*"([0-9a-f]{64})"', run_worker)
    default = re.search(r'TRUSTED_MANIFEST_SHA256="\$\{ECHO_CERTFORGE_TRUSTED_MANIFEST_SHA256:-([0-9a-f]{64})\}"',
                        script)
    assert pinned and default and default.group(1) == pinned.group(1)


def test_new_p4_provenance_uses_the_canonical_repository() -> None:
    assert '"uri": "git+https://github.com/echoomegaprime/echo-certification-forge"' in _text("scripts/seal_p4_images.py")
    assert "https://github.com/echoomegaprime/echo-certification-forge" in _text("scripts/run_p4_gate.sh")
