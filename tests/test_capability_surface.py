from __future__ import annotations

import json
from pathlib import Path

from echo_certification_forge.evidence import EvidenceStore
from echo_certification_forge.policy import RuleManifest
from echo_certification_forge.service import ServiceContext, create_app
from echo_certification_forge.signing import TrustedPublicKeyRegistry


ROOT = Path(__file__).parents[1]


def test_every_openapi_operation_is_mapped_or_a_signed_inbound_boundary(tmp_path):
    contract = json.loads(
        (ROOT / "contracts" / "certforge-capability-surface.v2.json").read_text(
            encoding="utf-8"
        )
    )
    app = create_app(
        ServiceContext(
            EvidenceStore(tmp_path / "certforge.sqlite3", tmp_path / "evidence"),
            RuleManifest.load(ROOT / "policies" / "mandatory-rules.v1.json"),
            TrustedPublicKeyRegistry.empty(),
        )
    )
    operations = {
        f"{method.upper()} {path}"
        for path, item in app.openapi()["paths"].items()
        for method in item
        if method.lower() in {"get", "post", "put", "patch", "delete"}
    }
    mapped = set(contract["capabilities"])
    excluded = set(contract["signed_inbound_exclusions"])
    assert mapped.isdisjoint(excluded)
    assert operations == mapped | excluded


def test_every_mapped_capability_is_registered_without_literal_credentials():
    contract = json.loads(
        (ROOT / "contracts" / "certforge-capability-surface.v2.json").read_text(
            encoding="utf-8"
        )
    )
    registration = (ROOT / "scripts" / "register_certforge_caps.sql").read_text(
        encoding="utf-8"
    )
    for capability in contract["capabilities"].values():
        assert f"'{capability}'" in registration
    assert '"Authorization":"vault:certforge.desktop_admin_api_key"' in registration
    assert '"Authorization":"Bearer ' not in registration


def test_public_responses_get_production_security_headers(tmp_path):
    from fastapi.testclient import TestClient

    app = create_app(
        ServiceContext(
            EvidenceStore(tmp_path / "certforge.sqlite3", tmp_path / "evidence"),
            RuleManifest.load(ROOT / "policies" / "mandatory-rules.v1.json"),
            TrustedPublicKeyRegistry.empty(),
        )
    )
    response = TestClient(app).get("/healthz")
    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["strict-transport-security"].startswith("max-age=31536000")
    assert response.headers["cache-control"] == "no-store"
