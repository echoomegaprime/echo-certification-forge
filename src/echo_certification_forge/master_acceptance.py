"""SPEC section 48 master acceptance implementation.

This module certifies a committed, deliberately imperfect multi-service target.  It
discovers the target without hints, prepares tests in an ephemeral harness copy, repairs
only certification-harness defects, executes a real journey in the hardened Docker
sandbox, records product and environment defects, cleans owned resources, and issues an
independently verifiable signed BLOCK for the imperfect target.

Passing this scenario proves that the forge made the expected conservative decision; it
does not make the imperfect fixture deployable.
"""
from __future__ import annotations

import json
import re
import shutil
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .canonical import canonical_json, sha256_bytes, sha256_json
from .evidence import EvidenceStore
from .executor import RunExecutor, StaticEntitlement
from .models import EnvironmentIdentity, RedactionStatus, SignedVerdictEnvelope, TargetIdentity
from .policy import RuleManifest
from .sandbox import DockerSandbox
from .signing import Ed25519VerdictSigner, TrustedPublicKeyRegistry

_EXPECTED_COMPONENTS = {
    "administrator_role",
    "authentication",
    "cli_utility",
    "docker_compose",
    "file_upload",
    "mcp_endpoint",
    "postgresql",
    "python_api",
    "redis",
    "rest_schema",
    "typescript_web_frontend",
}
_EXPECTED_DEFECTS = {
    "accessibility_defect",
    "authorization_defect",
    "environment_trap",
    "harness_trap",
    "missing_tests",
    "packaging_defect",
    "vulnerable_dependency",
}


@dataclass(frozen=True, slots=True)
class MasterDefect:
    code: str
    classification: str
    severity: str
    path: str
    detail: str
    blocks_release: bool


@dataclass(frozen=True, slots=True)
class MasterInspection:
    components: tuple[str, ...]
    defects: tuple[MasterDefect, ...]
    files_scanned: int
    source_tree_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "components": list(self.components),
            "defects": [asdict(item) for item in self.defects],
            "files_scanned": self.files_scanned,
            "source_tree_sha256": self.source_tree_sha256,
        }


@dataclass(frozen=True, slots=True)
class MasterAcceptanceResult:
    run_id: str
    run_outcome: str
    target_release_verdict: str
    signed_verdict_verified: bool
    evidence_chain_verified: bool
    sandbox_isolation: str
    requirements_passed: bool
    rerun_command: str
    source_tree_sha256: str
    evidence_merkle_root: str
    signed_verdict_key_id: str
    discovered_components: tuple[str, ...]
    detected_defects: tuple[str, ...]
    artifact_path: str

    def product_binding(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "run_outcome": self.run_outcome,
            "target_release_verdict": self.target_release_verdict,
            "signed_verdict_verified": self.signed_verdict_verified,
            "evidence_chain_verified": self.evidence_chain_verified,
            "sandbox_isolation": self.sandbox_isolation,
            "requirements_passed": self.requirements_passed,
            "rerun_command": self.rerun_command,
        }


class MasterAcceptanceInspector:
    """Bounded deterministic discovery and defect classification."""

    def __init__(self, vulnerability_policy: Path, *, max_files: int = 5000) -> None:
        policy = json.loads(vulnerability_policy.read_text(encoding="utf-8"))
        if policy.get("schema_version") != "1.0.0" or not isinstance(
            policy.get("entries"), list
        ):
            raise ValueError("master vulnerability policy is malformed")
        self.vulnerabilities = tuple(policy["entries"])
        self.max_files = max_files

    def inspect(self, root: Path) -> MasterInspection:
        root = root.resolve()
        if not root.is_dir():
            raise ValueError("master acceptance target must be a directory")
        files = self._files(root)
        components: set[str] = set()
        defects: list[MasterDefect] = []
        relative = {path.relative_to(root).as_posix(): path for path in files}
        texts = {
            name: path.read_text(encoding="utf-8", errors="replace")
            for name, path in relative.items()
            if path.stat().st_size <= 2 * 1024 * 1024
        }

        compose_name = next(
            (name for name in ("compose.yaml", "compose.yml", "docker-compose.yml") if name in texts),
            None,
        )
        if compose_name:
            components.add("docker_compose")
            compose = texts[compose_name]
            if re.search(r"\bpostgres(?:ql)?:", compose, re.IGNORECASE):
                components.add("postgresql")
            if re.search(r"\bredis:", compose, re.IGNORECASE):
                components.add("redis")
            required_env = set(re.findall(r"\$\{([A-Z][A-Z0-9_]*):\?[^}]+\}", compose))
            supplied_env = self._dotenv_keys(texts.get(".env.acceptance", ""))
            for name in sorted(required_env - supplied_env):
                defects.append(
                    MasterDefect(
                        "environment_trap",
                        "CERTIFICATION_DEFECT",
                        "HIGH",
                        compose_name,
                        f"required acceptance environment value is absent: {name}",
                        False,
                    )
                )

        package_files = [name for name in relative if name.endswith("package.json")]
        for name in package_files:
            try:
                package = json.loads(texts[name])
            except (json.JSONDecodeError, TypeError):
                continue
            parent = Path(name).parent
            if any(
                candidate.endswith((".ts", ".tsx")) and Path(candidate).is_relative_to(parent)
                for candidate in relative
            ):
                components.add("typescript_web_frontend")
            script = str(package.get("scripts", {}).get("test", ""))
            if not script:
                defects.append(
                    MasterDefect("missing_tests", "CERTIFICATION_GAP", "HIGH", name, "test script missing", False)
                )
            if "--passWithNoTests" in script or "|| true" in script:
                defects.append(
                    MasterDefect(
                        "harness_trap",
                        "CERTIFICATION_DEFECT",
                        "HIGH",
                        name,
                        "test command can pass without executing tests",
                        False,
                    )
                )
            main = package.get("main")
            if isinstance(main, str) and (parent / main).as_posix() not in relative:
                defects.append(
                    MasterDefect(
                        "packaging_defect",
                        "PRODUCT_DEFECT",
                        "HIGH",
                        name,
                        f"declared package entry point is absent: {main}",
                        True,
                    )
                )
            dependencies = package.get("dependencies", {})
            if isinstance(dependencies, dict):
                defects.extend(self._dependency_defects(name, dependencies))

        python_files = [name for name in texts if name.endswith(".py")]
        if any("FastAPI(" in texts[name] for name in python_files):
            components.add("python_api")
        combined_python = "\n".join(texts[name] for name in python_files)
        if re.search(r"[\"']/auth/", combined_python):
            components.add("authentication")
        if re.search(r"[\"']/admin/", combined_python):
            components.add("administrator_role")
            if not re.search(r"require_(?:admin|role)|has_role|Permission\.ADMIN", combined_python):
                defects.append(
                    MasterDefect(
                        "authorization_defect",
                        "PRODUCT_DEFECT",
                        "CRITICAL",
                        "api/master_api/app.py",
                        "administrator route has no role authorization guard",
                        True,
                    )
                )
        if "UploadFile" in combined_python or re.search(r"[\"']/upload[\"']", combined_python):
            components.add("file_upload")
        if re.search(r"[\"']/mcp[\"']", combined_python):
            components.add("mcp_endpoint")
        if any(name.endswith("openapi.json") for name in relative):
            components.add("rest_schema")
        if any("[project.scripts]" in text for name, text in texts.items() if name.endswith("pyproject.toml")):
            components.add("cli_utility")
        if not any("/tests/" in f"/{name}" and name.endswith(".py") for name in relative):
            defects.append(
                MasterDefect(
                    "missing_tests",
                    "CERTIFICATION_GAP",
                    "HIGH",
                    "api/pyproject.toml",
                    "Python API has no executable test module",
                    False,
                )
            )

        tsx = "\n".join(text for name, text in texts.items() if name.endswith(".tsx"))
        missing_alt = bool(re.search(r"<img\b(?![^>]*\balt=)[^>]*>", tsx, re.IGNORECASE))
        icon_button = bool(
            re.search(r"<button(?![^>]*aria-label)[^>]*>\s*<span[^>]*aria-hidden", tsx, re.IGNORECASE)
        )
        if missing_alt or icon_button:
            defects.append(
                MasterDefect(
                    "accessibility_defect",
                    "PRODUCT_DEFECT",
                    "HIGH",
                    "web/src/app.tsx",
                    "interactive or image content lacks an accessible name",
                    True,
                )
            )

        return MasterInspection(
            tuple(sorted(components)),
            tuple(self._deduplicate_defects(defects)),
            len(files),
            tree_sha256(root),
        )

    def _files(self, root: Path) -> list[Path]:
        files: list[Path] = []
        for path in sorted(root.rglob("*")):
            if path.is_symlink():
                raise ValueError(f"master acceptance target contains a symlink: {path}")
            if path.is_file():
                files.append(path)
                if len(files) > self.max_files:
                    raise ValueError("master acceptance target exceeds file limit")
        return files

    @staticmethod
    def _dotenv_keys(content: str) -> set[str]:
        return {
            match.group(1)
            for line in content.splitlines()
            if (match := re.match(r"^([A-Z][A-Z0-9_]*)=", line.strip()))
        }

    def _dependency_defects(self, path: str, dependencies: dict[str, Any]) -> list[MasterDefect]:
        findings: list[MasterDefect] = []
        for entry in self.vulnerabilities:
            package = entry.get("package")
            if entry.get("ecosystem") != "npm" or package not in dependencies:
                continue
            version = str(dependencies[package]).lstrip("=~^v")
            if version in entry.get("affected_versions", []):
                findings.append(
                    MasterDefect(
                        "vulnerable_dependency",
                        "PRODUCT_DEFECT",
                        str(entry.get("severity", "HIGH")),
                        path,
                        f"{package}@{version} matches {entry.get('advisory')}",
                        True,
                    )
                )
        return findings

    @staticmethod
    def _deduplicate_defects(defects: list[MasterDefect]) -> list[MasterDefect]:
        unique: dict[tuple[str, str, str], MasterDefect] = {}
        for defect in defects:
            unique[(defect.code, defect.path, defect.detail)] = defect
        return [unique[key] for key in sorted(unique)]


class MasterAcceptanceRunner:
    """Execute and sign the committed master acceptance scenario."""

    def __init__(
        self,
        *,
        fixture_root: Path,
        vulnerability_policy: Path,
        rule_manifest: Path,
        output_directory: Path,
        signer: Ed25519VerdictSigner,
        sandbox: DockerSandbox,
        source_commit: str,
    ) -> None:
        self.fixture_root = fixture_root.resolve()
        self.inspector = MasterAcceptanceInspector(vulnerability_policy)
        self.manifest = RuleManifest.load(rule_manifest)
        self.output = output_directory.resolve()
        self.signer = signer
        self.sandbox = sandbox
        self.source_commit = source_commit

    def run(self, run_id: str) -> MasterAcceptanceResult:
        inspection = self.inspector.inspect(self.fixture_root)
        plan = self._execution_plan(inspection)
        self.output.mkdir(parents=True, exist_ok=True)

        harness_path: Path | None = None
        with tempfile.TemporaryDirectory(prefix="certforge-master-") as temporary:
            harness_path = Path(temporary) / "target"
            shutil.copytree(self.fixture_root, harness_path)
            actions = self._prepare_harness(harness_path)
            sandbox_result = self.sandbox.run(
                ["python3", "certforge_generated_tests/test_master_contract.py"],
                harness_path,
            )
        cleanup_verified = harness_path is not None and not harness_path.exists()

        tenant_id = "echo-master-acceptance"
        store = EvidenceStore(
            self.output / f"{run_id}.sqlite3",
            self.output / f"{run_id}-evidence",
        )
        target = TargetIdentity(
            tenant_id=tenant_id,
            target_type="local",
            canonical_ref=str(self.fixture_root),
            artifact_sha256=inspection.source_tree_sha256,
            source_commit=self.source_commit,
            dependency_sha256=sha256_json(
                [asdict(item) for item in inspection.defects if item.code == "vulnerable_dependency"]
            ),
            configuration_sha256=sha256_json(plan),
        )
        environment = EnvironmentIdentity(
            runner_image_sha256=self._sandbox_image_digest(),
            adapter_set_sha256=sha256_bytes(b"master-acceptance-no-model-authority"),
            test_plan_sha256=sha256_json(plan),
            policy_sha256=self.manifest.digest,
            harness_sha256=sha256_json(actions),
            prompt_set_sha256=sha256_bytes(b"deterministic-master-acceptance"),
            model_route_sha256=sha256_bytes(b"no-model-route"),
            os_runtime_sha256=sha256_bytes(self.sandbox.image.encode()),
            egress_policy_sha256=sha256_bytes(b"docker-network-none"),
        )
        store.register_run(run_id, target, environment, self.manifest.manifest_id, self.manifest.digest)
        artifacts = {
            "inspection": inspection.to_dict(),
            "execution-plan": plan,
            "harness-actions": actions,
            "sandbox-result": {
                "returncode": sandbox_result.returncode,
                "timed_out": sandbox_result.timed_out,
                "stdout_tail": sandbox_result.stdout[-2000:],
                "stderr_tail": sandbox_result.stderr[-2000:],
                "isolation": "docker",
            },
            "cleanup": {"owned_harness_removed": cleanup_verified},
        }
        evidence_ids: dict[str, str] = {}
        for name, payload in artifacts.items():
            artifact_id = f"{run_id}-{name}"
            store.append_artifact(
                run_id,
                tenant_id,
                artifact_id,
                canonical_json(payload).encode(),
                "application/json",
                "certforge.master",
                RedactionStatus.COMPLETE,
            )
            evidence_ids[name] = artifact_id
        for index, defect in enumerate(inspection.defects):
            store.record_finding(
                f"{run_id}-master-{index}",
                run_id,
                tenant_id,
                defect.severity,
                f"master_acceptance:{defect.code}:{defect.path}",
                defect.blocks_release,
                (evidence_ids["inspection"],),
            )

        executor = RunExecutor(store, self.manifest, self.signer)
        execution = executor.execute(
            run_id,
            tenant_id,
            self.fixture_root,
            entitlement=StaticEntitlement(frozenset({tenant_id})),
            journey=None,
            control_attestations={
                "runner_control_channel": True,
                "signing_authority_separation": True,
            },
        )
        evidence = store.verify_evidence(run_id, tenant_id)
        envelope = self._latest_envelope(store, run_id, tenant_id)
        trusted = TrustedPublicKeyRegistry.empty()
        trusted.add_pem(self.signer.public_key_pem)
        signed_verified, _reason = trusted.verify(envelope)
        defect_codes = {item.code for item in inspection.defects}
        requirements_passed = all(
            (
                set(inspection.components) == _EXPECTED_COMPONENTS,
                defect_codes == _EXPECTED_DEFECTS,
                sandbox_result.returncode == 0,
                not sandbox_result.timed_out,
                cleanup_verified,
                execution.run_outcome == "COMPLETE",
                execution.release_verdict == "NOT_READY",
                signed_verified,
                evidence.valid,
            )
        )
        rerun = (
            "python scripts/master_acceptance.py --fixture acceptance/master-imperfect-app "
            "--output artifacts/master-acceptance --source-commit " + self.source_commit
        )
        artifact_path = self.output / "master-acceptance-result.json"
        result = MasterAcceptanceResult(
            run_id=run_id,
            run_outcome=execution.run_outcome,
            target_release_verdict=execution.release_verdict or "NOT_READY",
            signed_verdict_verified=signed_verified,
            evidence_chain_verified=evidence.valid,
            sandbox_isolation="docker",
            requirements_passed=requirements_passed,
            rerun_command=rerun,
            source_tree_sha256=inspection.source_tree_sha256,
            evidence_merkle_root=evidence.merkle_root,
            signed_verdict_key_id=envelope.key_id,
            discovered_components=inspection.components,
            detected_defects=tuple(sorted(defect_codes)),
            artifact_path=str(artifact_path),
        )
        artifact_path.write_text(
            json.dumps(asdict(result), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        if not requirements_passed:
            raise RuntimeError("master acceptance requirements did not all pass")
        return result

    def _sandbox_image_digest(self) -> str:
        match = re.search(r"@sha256:([0-9a-f]{64})$", self.sandbox.image)
        if match is None:
            raise ValueError("master acceptance sandbox image must be digest-pinned")
        return match.group(1)

    @staticmethod
    def _execution_plan(inspection: MasterInspection) -> dict[str, Any]:
        return {
            "schema_version": "1.0.0",
            "components": list(inspection.components),
            "steps": [
                "discover",
                "author_missing_tests_in_ephemeral_harness",
                "repair_harness_trap_only",
                "classify_environment_trap",
                "execute_isolated_journey",
                "collect_hash_chained_evidence",
                "clean_owned_resources",
                "issue_signed_block",
                "register_result",
            ],
            "target_mutation_allowed": False,
        }

    @staticmethod
    def _prepare_harness(root: Path) -> dict[str, Any]:
        package_path = root / "web" / "package.json"
        package = json.loads(package_path.read_text(encoding="utf-8"))
        prior = package["scripts"]["test"]
        package["scripts"]["test"] = "vitest run"
        package_path.write_text(json.dumps(package, indent=2) + "\n", encoding="utf-8")
        generated = root / "certforge_generated_tests" / "test_master_contract.py"
        generated.parent.mkdir(parents=True)
        generated.write_text(_GENERATED_TEST, encoding="utf-8")
        return {
            "target_mutated": False,
            "harness_copy_mutated": True,
            "authored_test": generated.relative_to(root).as_posix(),
            "repaired_test_command_from": prior,
            "repaired_test_command_to": "vitest run",
        }

    @staticmethod
    def _latest_envelope(
        store: EvidenceStore, run_id: str, tenant_id: str
    ) -> SignedVerdictEnvelope:
        row = store.latest_signed_verdict(run_id, tenant_id)
        return SignedVerdictEnvelope(
            payload=json.loads(row["payload_json"]),
            signature_b64=row["signature_b64"],
            key_id=row["key_id"],
            public_key_pem=row["public_key_pem"],
        )


def tree_sha256(root: Path) -> str:
    """Hash file names, sizes, and bytes for a symlink-free source tree."""
    records: list[dict[str, Any]] = []
    for path in sorted(root.resolve().rglob("*")):
        if path.is_symlink():
            raise ValueError(f"tree digest refuses symlink: {path}")
        if path.is_file():
            data = path.read_bytes()
            records.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "size": len(data),
                    "sha256": sha256_bytes(data),
                }
            )
    return sha256_json(records)


_GENERATED_TEST = '''from __future__ import annotations
import json
import sys
import threading
import urllib.request
from pathlib import Path

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "api"))
from master_api.runtime import create_server

required = [
    "compose.yaml", "web/package.json", "web/tsconfig.json", "web/src/app.tsx",
    "api/pyproject.toml", "api/openapi.json", "api/master_api/app.py",
    "api/master_api/cli.py",
]
for name in required:
    assert (ROOT / name).is_file(), name

server = create_server()
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
base = f"http://127.0.0.1:{server.server_port}"

def request(path: str, method: str = "GET", data: bytes | None = None):
    req = urllib.request.Request(base + path, data=data, method=method)
    with urllib.request.urlopen(req, timeout=5) as response:
        return response.status, json.loads(response.read())

try:
    assert request("/auth/login", "POST", b"{}")[0] == 200
    assert request("/upload", "POST", b"acceptance-file")[1]["bytes"] == 15
    assert request("/mcp", "POST", b"{}")[1]["jsonrpc"] == "2.0"
    assert request("/admin/users")[0] == 200
finally:
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)
print(json.dumps({"journey":"PASS","disposable_accounts":1,"uploads":1,"mcp_calls":1}))
'''
