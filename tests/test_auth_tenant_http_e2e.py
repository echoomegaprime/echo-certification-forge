"""Real HTTP E2E for the auth/tenant surface.

`tests/test_t4p7_e2e.py` covers the executor → signed-verdict → deploy-gate path.
It never opens the HTTP API. This module boots the production ASGI app with
uvicorn and speaks HTTP over the loopback so anonymous auth and tenant isolation
are proven on the same surface operators expose.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from echo_certification_forge.subscriber import SubscriberGovernance, SubscriberPolicy

DIGEST = "0" * 64
PEPPER = "auth-tenant-http-e2e-pepper-material-32-bytes"


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _json_request(
    url: str,
    *,
    method: str = "GET",
    payload: dict | None = None,
    headers: dict[str, str] | None = None,
) -> tuple[int, dict | list | None, bytes]:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            raw = response.read()
            parsed = json.loads(raw.decode("utf-8")) if raw else None
            return response.status, parsed, raw
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        parsed = None
        if raw:
            try:
                parsed = json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError:
                parsed = None
        return exc.code, parsed, raw


def _wait_healthy(base: str, process: subprocess.Popen[str]) -> None:
    output = ""
    for _ in range(100):
        if process.poll() is not None:
            if process.stdout is not None:
                output = process.stdout.read()
            break
        try:
            status, _, _ = _json_request(f"{base}/healthz")
            if status == 200:
                return
        except OSError:
            time.sleep(0.05)
    raise AssertionError(f"uvicorn never became healthy: {output}")


def _valid_submit(tenant_id: str, project_id: str, key: str, manifest_id: str) -> dict:
    return {
        "tenant_id": tenant_id,
        "project_id": project_id,
        "target": {
            "target_type": "git",
            "identity_digest": DIGEST,
            "reference": f"https://github.com/example/{key}",
        },
        "environment": {
            "identity_digest": DIGEST,
            "runner_image_digest": "sha256:" + DIGEST,
        },
        "policy_version": manifest_id,
        "idempotency_key": key,
    }


def test_live_http_anonymous_submit_is_indistinguishable_and_tenants_stay_isolated(
    tmp_path: Path, manifest
) -> None:
    repo = Path(__file__).parents[1]
    port = _free_port()
    db = tmp_path / "e2e.sqlite3"
    env = os.environ.copy()
    env.update(
        {
            "PYTHONPATH": str(repo / "src"),
            "ECHO_CERTFORGE_DB": str(db),
            "ECHO_CERTFORGE_EVIDENCE_ROOT": str(tmp_path / "evidence"),
            "ECHO_CERTFORGE_POLICY": str(repo / "policies" / "mandatory-rules.v1.json"),
            "ECHO_CERTFORGE_SUBSCRIBER_POLICY": str(
                repo / "policies" / "subscriber-governance.v1.json"
            ),
            "ECHO_CERTFORGE_TRUSTED_KEYS": str(tmp_path / "trusted-keys"),
            "ECHO_CERTFORGE_SUBSCRIBERS_ENABLED": "1",
            "ECHO_CERTFORGE_API_KEY_PEPPER": PEPPER,
        }
    )
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "echo_certification_forge.app:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        cwd=repo,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    base = f"http://127.0.0.1:{port}"
    try:
        _wait_healthy(base, process)

        malformed_status, malformed_body, malformed_raw = _json_request(
            f"{base}/v1/certifications", method="POST", payload={}
        )
        wellformed_status, wellformed_body, wellformed_raw = _json_request(
            f"{base}/v1/certifications",
            method="POST",
            payload=_valid_submit("probe", "proj-1", "probe-key-1", manifest.manifest_id),
        )
        assert malformed_status == 401
        assert wellformed_status == 401
        assert malformed_body == wellformed_body
        assert malformed_raw == wellformed_raw

        governance = SubscriberGovernance(
            db,
            SubscriberPolicy.load(repo / "policies" / "subscriber-governance.v1.json"),
            PEPPER.encode("utf-8"),
        )
        alpha = governance.provision_organization(
            slug="alpha-http",
            display_name="Alpha HTTP",
            owner_email="owner@alpha-http.example",
            owner_display_name="Alpha Owner",
            plan_code="developer",
        )
        beta = governance.provision_organization(
            slug="beta-http",
            display_name="Beta HTTP",
            owner_email="owner@beta-http.example",
            owner_display_name="Beta Owner",
            plan_code="developer",
        )
        alpha_headers = {
            "X-Tenant-ID": alpha.organization_id,
            "Authorization": f"Bearer {alpha.bootstrap_api_key}",
        }
        beta_headers = {
            "X-Tenant-ID": beta.organization_id,
            "Authorization": f"Bearer {beta.bootstrap_api_key}",
        }

        alpha_project_status, alpha_project, _ = _json_request(
            f"{base}/v1/subscriber/projects",
            method="POST",
            headers=alpha_headers,
            payload={
                "slug": "alpha-app",
                "name": "Alpha App",
                "target_reference": "https://github.com/example/alpha",
            },
        )
        assert alpha_project_status == 201
        assert isinstance(alpha_project, dict)

        beta_project_status, beta_project, _ = _json_request(
            f"{base}/v1/subscriber/projects",
            method="POST",
            headers=beta_headers,
            payload={
                "slug": "beta-app",
                "name": "Beta App",
                "target_reference": "https://github.com/example/beta",
            },
        )
        assert beta_project_status == 201
        assert isinstance(beta_project, dict)

        alpha_submit_status, alpha_run, _ = _json_request(
            f"{base}/v1/certifications",
            method="POST",
            headers=alpha_headers,
            payload=_valid_submit(
                alpha.organization_id,
                str(alpha_project["project_id"]),
                "alpha-key-1",
                manifest.manifest_id,
            ),
        )
        assert alpha_submit_status == 201, alpha_run
        assert isinstance(alpha_run, dict)
        alpha_run_id = str(alpha_run["run_id"])

        stolen_status, stolen_body, _ = _json_request(
            f"{base}/v1/certifications/{alpha_run_id}",
            headers=beta_headers,
        )
        assert stolen_status == 404
        assert stolen_body == {"detail": "run not found"}

        own_status, own_body, _ = _json_request(
            f"{base}/v1/certifications/{alpha_run_id}",
            headers=alpha_headers,
        )
        assert own_status == 200
        assert isinstance(own_body, dict)
        assert own_body["run_id"] == alpha_run_id
        assert own_body["tenant_id"] == alpha.organization_id

        cross_header_status, cross_header_body, _ = _json_request(
            f"{base}/v1/certifications/{alpha_run_id}",
            headers={
                "X-Tenant-ID": beta.organization_id,
                "Authorization": f"Bearer {alpha.bootstrap_api_key}",
            },
        )
        assert cross_header_status in {401, 403, 404}
        assert cross_header_body != own_body
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
