from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

import p3_forge_acceptance as p3  # noqa: E402

SIGNER_TAG = "echo-certforge-signer:p4-test-a"
SIGNER_ID = "sha256:" + "ab" * 32
OTHER_ID = "sha256:" + "cd" * 32


class FakeDockerAPI:
    def __init__(self, *, resolved_id: str, container_image_id: str) -> None:
        self.resolved_id = resolved_id
        self.container_image_id = container_image_id
        self.created_payload: dict | None = None
        self.requested_paths: list[str] = []

    def request(self, method: str, path: str, body=None, **kwargs):
        self.requested_paths.append(path)
        assert method == "GET"
        assert path.startswith("/images/")
        return {"Id": self.resolved_id}

    def create(self, name: str, payload: dict) -> str:
        self.created_payload = payload
        return "container-id"

    def inspect(self, container_id: str) -> dict:
        return {
            "Image": self.container_image_id,
            "Config": {"User": "1000:1000"},
            "HostConfig": {},
        }

    def start(self, container_id: str) -> None:
        pass

    def logs(self, container_id: str) -> str:
        return ""


def run_container(api: FakeDockerAPI, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict:
    monkeypatch.setattr(p3.os, "getuid", lambda: 1000, raising=False)
    monkeypatch.setattr(p3.os, "getgid", lambda: 1000, raising=False)
    monkeypatch.setattr(
        p3,
        "wait_not_running",
        lambda _api, _cid, _timeout: {
            "Image": api.container_image_id,
            "Config": {"User": "1000:1000"},
            "HostConfig": {},
            "State": {"ExitCode": 0},
        },
    )
    return p3.run_signer_container(
        api,
        image=SIGNER_TAG,
        source_root=tmp_path / "src",
        input_root=tmp_path / "input",
        output_root=tmp_path / "output",
        command=["signer.py"],
        run_id="run.test",
        case="success",
        owned_ids=set(),
    )


def test_resolve_image_id_returns_exact_id() -> None:
    api = FakeDockerAPI(resolved_id=SIGNER_ID, container_image_id=SIGNER_ID)
    assert p3.resolve_image_id(api, SIGNER_TAG) == SIGNER_ID
    assert api.requested_paths == [f"/images/{SIGNER_TAG}/json"]


def test_resolve_image_id_fails_closed_on_unresolvable() -> None:
    api = FakeDockerAPI(resolved_id="", container_image_id=SIGNER_ID)
    with pytest.raises(RuntimeError, match="unresolvable image reference"):
        p3.resolve_image_id(api, SIGNER_TAG)


def test_tag_reference_binds_creation_to_exact_id_without_false_mismatch(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    api = FakeDockerAPI(resolved_id=SIGNER_ID, container_image_id=SIGNER_ID)
    result = run_container(api, monkeypatch, tmp_path)
    assert api.created_payload is not None
    assert api.created_payload["Image"] == SIGNER_ID
    assert "signer_image_identity_mismatch" not in result["inspect_issues"]


def test_container_running_different_image_is_flagged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    api = FakeDockerAPI(resolved_id=SIGNER_ID, container_image_id=OTHER_ID)
    result = run_container(api, monkeypatch, tmp_path)
    assert "signer_image_identity_mismatch" in result["inspect_issues"]
