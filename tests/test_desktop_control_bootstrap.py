from __future__ import annotations

from argparse import Namespace
from pathlib import Path

import pytest

from scripts import bootstrap_desktop_control as subject


def arguments(tmp_path) -> Namespace:
    return Namespace(
        database=str(tmp_path / "certforge.sqlite3"),
        vault_base="http://vault.invalid",
        vault_service=subject.DEFAULT_SERVICE,
        sovereign_key_file=str(tmp_path / "sovereign"),
        subscriber_policy=str(Path("policies/subscriber-governance.v1.json")),
        api_key_pepper="desktop-bootstrap-test-pepper-material-32-bytes",
        organization_id="org-echo-sovereign",
        tenant_id="echo-sovereign",
        organization_name="Echo Omega Prime",
        project_id="project-echo-desktop",
        project_name="Echo Desktop",
        target_reference="github:ECHO-OMEGA-PRIME/echo-desktop",
        required_policy="mandatory-rules-v1",
        owner_user_id="user-echo-desktop-admin",
        owner_email="certforge-admin@echo-op.com",
        plan="sovereign",
    )


def test_provision_moves_generated_key_to_vault_without_returning_it(tmp_path, monkeypatch):
    args = arguments(tmp_path)
    captured = {}
    monkeypatch.setattr(subject, "_sovereign_key", lambda _path: "sovereign-test-key")
    monkeypatch.setattr(subject, "_vault_has_service", lambda *_args: False)

    def store(**kwargs):
        captured.update(kwargs)
        return {
            "stored": True,
            "service": subject.DEFAULT_SERVICE,
            "version": 1,
            "key_fingerprint": "fingerprint",
        }

    monkeypatch.setattr(subject, "_store_in_vault", store)
    result = subject.provision(args)

    assert result["ok"] is True and result["created"] is True
    assert "api_key" not in result
    assert captured["account"]["api_key"].startswith("ecf_live_key_")
    assert captured["account"]["api_key"] not in str(result)
    assert subject._organization_exists(tmp_path / "certforge.sqlite3", args.organization_id)


def test_provision_is_idempotent_only_when_tenant_and_vault_both_exist(tmp_path, monkeypatch):
    args = arguments(tmp_path)
    monkeypatch.setattr(subject, "_sovereign_key", lambda _path: "sovereign-test-key")
    monkeypatch.setattr(subject, "_vault_has_service", lambda *_args: False)
    monkeypatch.setattr(
        subject,
        "_store_in_vault",
        lambda **_kwargs: {"stored": True, "service": subject.DEFAULT_SERVICE},
    )
    subject.provision(args)

    monkeypatch.setattr(subject, "_vault_has_service", lambda *_args: True)
    result = subject.provision(args)
    assert result["ok"] is True and result["created"] is False
    assert result["organization_id"] == args.organization_id
    assert result["project_id"].startswith("prj_")
    assert result["vault_service"] == subject.DEFAULT_SERVICE


def test_provision_rejects_partial_state_without_overwriting_credentials(tmp_path, monkeypatch):
    args = arguments(tmp_path)
    monkeypatch.setattr(subject, "_sovereign_key", lambda _path: "sovereign-test-key")
    monkeypatch.setattr(subject, "_vault_has_service", lambda *_args: True)
    with pytest.raises(RuntimeError, match="partial provisioning state"):
        subject.provision(args)


def test_provision_can_rotate_only_an_orphaned_vault_credential(tmp_path, monkeypatch):
    args = arguments(tmp_path)
    args.rotate_orphaned_vault = True
    monkeypatch.setattr(subject, "_sovereign_key", lambda _path: "sovereign-test-key")
    monkeypatch.setattr(subject, "_vault_has_service", lambda *_args: True)
    stored = {}

    def store(**kwargs):
        stored.update(kwargs)
        return {"stored": True, "service": kwargs["service"], "version": 2}

    monkeypatch.setattr(subject, "_store_in_vault", store)
    result = subject.provision(args)
    assert result["created"] is True
    assert result["vault"]["version"] == 2
    assert stored["account"]["api_key"].startswith("ecf_live_key_")


def test_desktop_cap_registration_uses_vault_references_not_literal_credentials():
    sql = Path("scripts/register_certforge_caps.sql").read_text(encoding="utf-8")
    assert sql.count("('echo.certforge.admin.") >= 10
    assert sql.count('"Authorization":"vault:certforge.desktop_admin_api_key"') >= 48
    assert '"X-Tenant-ID":"org-echo-sovereign"' in sql
    assert '"X-CertForge-API-Key"' not in sql
    assert "echo.certforge.telemetry" in sql
    assert "echo.certforge.admin.evidence_artifact" in sql
    assert "echo.certforge.admin.rerun" in sql
    assert "echo.certforge.admin.quarantine" in sql
    assert "echo.certforge.admin.quarantine_release" in sql
    assert "removing it from eligible capacity/execution without deleting telemetry" in sql
    assert "immutable lineage" in sql
    assert "5 MiB raw" in sql
    assert "WHERE id = 'echo.certforge.admin.evidence_artifact'" in sql
    assert "ecf_" not in sql


def test_live_accepted_lifecycle_cap_is_durably_green():
    sql = Path("scripts/register_certforge_caps.sql").read_text(encoding="utf-8")
    lifecycle = sql.split("('echo.certforge.admin.lifecycle',", 1)[1].split("('echo.certforge.admin.publish',", 1)[0]
    assert "revocation, invalidation, or supersession" in lifecycle
    assert "expiry" not in lifecycle
    assert "15, 'active', 'green'" in lifecycle
    assert "WHERE id = 'echo.certforge.admin.lifecycle'" in sql


def test_live_accepted_telemetry_cap_is_durably_green():
    sql = Path("scripts/register_certforge_caps.sql").read_text(encoding="utf-8")
    assert "explicit UNKNOWN/UNAVAILABLE source truth" in sql
    assert "WHERE id = 'echo.certforge.telemetry'" in sql
