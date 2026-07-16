"""Launch and verify the real ASGI process using observable readiness."""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def get_json(url: str) -> dict[str, object]:
    with urllib.request.urlopen(url, timeout=1.0) as response:
        if response.status != 200:
            raise RuntimeError(f"unexpected status {response.status}")
        return json.loads(response.read().decode("utf-8"))


def main() -> int:
    port = free_port()
    with tempfile.TemporaryDirectory(prefix="certforge-runtime-") as temporary:
        root = Path(temporary)
        env = {
            **os.environ,
            "PYTHONUTF8": "1",
            "ECHO_CERTFORGE_DB": str(root / "certforge.sqlite3"),
            "ECHO_CERTFORGE_EVIDENCE_ROOT": str(root / "evidence"),
            "ECHO_CERTFORGE_POLICY": str(REPO / "policies" / "mandatory-rules.v1.json"),
            "ECHO_CERTFORGE_TRUSTED_KEYS": str(root / "trusted-public-keys"),
        }
        process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "echo_certification_forge.app:app", "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
            cwd=REPO,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        deadline = time.monotonic() + 15.0
        health: dict[str, object] | None = None
        last_error = "service not observed"
        try:
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    last_error = f"service exited early with {process.returncode}"
                    break
                try:
                    health = get_json(f"http://127.0.0.1:{port}/healthz")
                    break
                except (OSError, urllib.error.URLError, RuntimeError, json.JSONDecodeError) as error:
                    last_error = str(error)
                    time.sleep(0.1)
            if health is None:
                raise RuntimeError(last_error)
            status = get_json(f"http://127.0.0.1:{port}/v1/status")
            passed = (
                health.get("status") == "ok"
                and health.get("control_plane_executes_customer_code") is False
                and health.get("private_signing_key_loaded") is False
                and status.get("external_evidence_anchor") == "PENDING"
                and status.get("runner_isolation") == "PENDING"
            )
            report = {
                "schema_version": "1.0.0",
                "passed": passed,
                "pid": process.pid,
                "port": port,
                "readiness": "observable_http_predicate",
                "health": health,
                "status": status,
            }
            output = REPO / "artifacts" / "p1_runtime_smoke.json"
            output.parent.mkdir(exist_ok=True)
            output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
            print(json.dumps(report, indent=2, sort_keys=True))
            return 0 if passed else 1
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            if process.stdout is not None:
                logs = process.stdout.read()
                (REPO / "artifacts" / "p1_runtime_service.txt").write_text(logs, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    raise SystemExit(main())
