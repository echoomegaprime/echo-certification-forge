from __future__ import annotations

from types import SimpleNamespace

import pytest

from echo_certification_forge.master_acceptance import MasterAcceptanceRunner


def _digest(reference: str) -> str:
    runner = object.__new__(MasterAcceptanceRunner)
    runner.sandbox = SimpleNamespace(image=reference)
    return runner._sandbox_image_digest()


@pytest.mark.parametrize("reference", [
    "sha256:" + "a" * 64,
    "repository/runtime@sha256:" + "a" * 64,
    "registry.example/runtime:qualified@sha256:" + "a" * 64,
])
def test_master_binds_full_local_or_registry_content_digest(reference: str) -> None:
    assert _digest(reference) == "a" * 64


@pytest.mark.parametrize("reference", [
    "python:latest", "sha256:abc", "sha256:" + "a" * 63,
    "sha256:" + "A" * 64, "sha256:" + "g" * 64,
    "repository@@sha256:" + "a" * 64,
    "repository@sha256:" + "a" * 64 + "suffix",
    " repository@sha256:" + "a" * 64,
    "sha256:" + "a" * 64 + "\n", "",
])
def test_master_rejects_mutable_short_or_malformed_image_identity(reference: str) -> None:
    with pytest.raises(ValueError, match="digest-pinned"):
        _digest(reference)
