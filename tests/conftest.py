from __future__ import annotations

import re
import subprocess
import sys
import time
import urllib.request
from contextlib import contextmanager
from pathlib import Path

import pytest

from echo_certification_forge.evidence import EvidenceStore
from echo_certification_forge.models import EnvironmentIdentity, TargetIdentity
from echo_certification_forge.policy import RuleManifest


def digest(label: str) -> str:
    import hashlib
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


@pytest.fixture
def manifest() -> RuleManifest:
    return RuleManifest.load(Path(__file__).parents[1] / "policies" / "mandatory-rules.v1.json")


@pytest.fixture
def store(tmp_path: Path) -> EvidenceStore:
    return EvidenceStore(tmp_path / "certforge.sqlite3", tmp_path / "evidence")


@pytest.fixture
def target() -> TargetIdentity:
    return TargetIdentity(
        tenant_id="tenant-alpha",
        target_type="git",
        canonical_ref="https://github.com/example/project@abc123",
        artifact_sha256=digest("artifact"),
        source_commit="abc123",
        dependency_sha256=digest("dependencies"),
        configuration_sha256=digest("configuration"),
    )


@pytest.fixture
def environment() -> EnvironmentIdentity:
    return EnvironmentIdentity(
        runner_image_sha256=digest("runner"),
        adapter_set_sha256=digest("adapters"),
        test_plan_sha256=digest("test-plan"),
        policy_sha256=digest("policy"),
        harness_sha256=digest("harness"),
        prompt_set_sha256=digest("prompts"),
        model_route_sha256=digest("models"),
        os_runtime_sha256=digest("os-runtime"),
        egress_policy_sha256=digest("egress"),
    )


@pytest.fixture
def live_certforge(tmp_path):
    """Start the real ASGI service on a port owned by its child process."""
    @contextmanager
    def start(env):
        repo = Path(__file__).parents[1]
        log_path = tmp_path / "uvicorn-startup.log"
        with log_path.open("wb") as log:
            process = subprocess.Popen(
                [sys.executable, "-m", "uvicorn", "echo_certification_forge.app:app",
                 "--host", "127.0.0.1", "--port", "0", "--no-access-log",
                 "--log-level", "info", "--no-use-colors"],
                cwd=repo, env=env, stdout=log, stderr=subprocess.STDOUT,
            )
        try:
            # Give a cold interpreter and ASGI lifespan a bounded bootstrap window.
            # Uvicorn reports the actual port only after its socket has been bound.
            startup_deadline = time.monotonic() + 30
            while time.monotonic() < startup_deadline and process.poll() is None:
                output = log_path.read_text(encoding="utf-8", errors="replace")
                address = re.search(r"Uvicorn running on (http://127\.0\.0\.1:[0-9]+)", output)
                if address:
                    break
                time.sleep(0.05)
            else:
                output = log_path.read_text(encoding="utf-8", errors="replace")
                pytest.fail(f"Uvicorn did not bind a listener (exit={process.poll()}):\n{output[-4000:]}")

            base = address.group(1)
            health_deadline = time.monotonic() + 5
            last_error = "no response"
            while time.monotonic() < health_deadline and process.poll() is None:
                try:
                    with urllib.request.urlopen(f"{base}/healthz", timeout=1) as response:
                        if response.status == 200:
                            break
                        last_error = f"HTTP {response.status}"
                except OSError as exc:
                    last_error = str(exc)
                time.sleep(0.05)
            else:
                output = log_path.read_text(encoding="utf-8", errors="replace")
                pytest.fail(f"CertForge health check failed ({last_error}, exit={process.poll()}):\n{output[-4000:]}")
            yield base
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

    return start
