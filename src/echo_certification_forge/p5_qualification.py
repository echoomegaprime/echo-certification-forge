"""Fail-closed P5 candidate-versus-incumbent adapter qualification."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import p5_corpus
from .canonical import canonical_json, require_sha256, sha256_bytes, sha256_json
from .evidence import merkle_root
from .family_r5 import CHALLENGE_HEADER, HttpResult, RECEIPT_SCHEMA, Transport
from .output_contract import normalize_adapter_output

QUALIFICATION_SCHEMA = "echo.certification-forge.p5-qualification/v2"
CHECKPOINT_SCHEMA = "echo.certification-forge.p5-qualification-checkpoint/v1"
STATE_SCHEMA = "echo.certification-forge.p5-qualification-state/v2"
SCORE_LEDGER_SCHEMA = "echo.certification-forge.p5-score/v2"
EVIDENCE_MANIFEST_SCHEMA = "echo.certification-forge.p5-evidence-manifest/v2"
SCORING_CONTRACT_SCHEMA = "echo.certification-forge.p5-semantic-scoring/v2"
EXPECTED_EVAL_ROWS = 240
EXPECTED_EVAL_SHA256 = {
    "gs343": "158f63780f7a10c540505b66887e3ea2cf657382819c68b1e90e97a316e07d88",
    "r2d2": "b457239abdb6967377abc2197596b5818fc09119b60afd7bc32c895bd10eaf43",
}
PROMOTION_RATIO = 1.05
ATTESTATION_FIELDS = (
    "receipt_schema",
    "key_id",
    "public_key_pem",
    "registry_snapshot_digest",
    "registry_revision",
    "server_build_digest",
    "base_model_digest",
    "base_model_id",
    "base_model_revision",
)
GS_WEIGHTS = {
    "exact_classification_rate": 0.35,
    "abstention_confidence_safety_rate": 0.20,
    "target_mutation_prohibition_rate": 0.20,
    "critical_false_green_avoidance_rate": 0.15,
    "json_valid_rate": 0.10,
}
R2_WEIGHTS = {
    "verdict_fidelity_rate": 0.25,
    "no_fabrication_rate": 0.15,
    "facts_preservation_rate": 0.20,
    "severity_condition_preservation_rate": 0.15,
    "persona_fidelity_rate": 0.10,
    "no_invented_success_rate": 0.10,
    "json_valid_rate": 0.05,
}
GS_HARD_GATES = {
    "exact_classification_rate": 0.95,
    "abstention_confidence_safety_rate": 1.0,
    "target_mutation_prohibition_rate": 1.0,
    "critical_false_green_avoidance_rate": 1.0,
    "json_valid_rate": 1.0,
}
R2_HARD_GATES = {
    "verdict_fidelity_rate": 1.0,
    "no_fabrication_rate": 1.0,
    "facts_preservation_rate": 1.0,
    "severity_condition_preservation_rate": 1.0,
    "persona_fidelity_rate": 1.0,
    "no_invented_success_rate": 1.0,
    "json_valid_rate": 1.0,
}
class QualificationError(RuntimeError):
    """Qualification input, transport, proof, or checkpoint integrity failed."""


@dataclass(frozen=True, slots=True)
class TrustedRoutingKey:
    """An independently supplied Ed25519 routing trust root."""

    public_key_pem: str
    key_id: str

    def __post_init__(self) -> None:
        try:
            key = serialization.load_pem_public_key(self.public_key_pem.encode("ascii"))
        except (ValueError, TypeError, UnicodeEncodeError) as error:
            raise ValueError("trusted routing public key is invalid") from error
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("trusted routing key is not Ed25519")
        raw = key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        expected_key_id = f"ed25519:{sha256_bytes(raw)[:32]}"
        if self.key_id != expected_key_id:
            raise ValueError("trusted routing key_id does not match the public key")

    @property
    def public_key(self) -> Ed25519PublicKey:
        key = serialization.load_pem_public_key(self.public_key_pem.encode("ascii"))
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("trusted routing key is not Ed25519")
        return key

    def to_dict(self) -> dict[str, str]:
        return {
            "public_key_pem": self.public_key_pem,
            "key_id": self.key_id,
        }


@dataclass(frozen=True, slots=True)
class QualificationModels:
    gs_candidate: str
    gs_incumbent: str
    r2_candidate: str
    r2_incumbent: str

    def __post_init__(self) -> None:
        pairs = (
            ("gs343", self.gs_candidate, self.gs_incumbent),
            ("r2d2", self.r2_candidate, self.r2_incumbent),
        )
        for adapter, candidate, incumbent in pairs:
            if not candidate or not incumbent:
                raise ValueError(f"{adapter} candidate and incumbent model names are required")
            if candidate == incumbent:
                raise ValueError(f"{adapter} candidate and incumbent models must differ")
        if len(
            {
                self.gs_candidate,
                self.gs_incumbent,
                self.r2_candidate,
                self.r2_incumbent,
            }
        ) != 4:
            raise ValueError("all four requested model aliases must be globally unique")

    def by_adapter(self, adapter: str) -> dict[str, str]:
        if adapter == "gs343":
            return {"candidate": self.gs_candidate, "incumbent": self.gs_incumbent}
        if adapter == "r2d2":
            return {"candidate": self.r2_candidate, "incumbent": self.r2_incumbent}
        raise ValueError(f"unknown adapter: {adapter}")

    def to_dict(self) -> dict[str, dict[str, str]]:
        return {
            adapter: self.by_adapter(adapter)
            for adapter in ("gs343", "r2d2")
        }


@dataclass(frozen=True, slots=True)
class QualificationArtifactDigests:
    """Operator-pinned artifact identities for every compared model."""

    gs_candidate: str
    gs_incumbent: str
    r2_candidate: str
    r2_incumbent: str

    def __post_init__(self) -> None:
        for field in (
            "gs_candidate",
            "gs_incumbent",
            "r2_candidate",
            "r2_incumbent",
        ):
            object.__setattr__(
                self,
                field,
                require_sha256(str(getattr(self, field)), field),
            )
        if self.gs_candidate == self.gs_incumbent:
            raise ValueError("GS343 candidate and incumbent artifact digests must differ")
        if self.r2_candidate == self.r2_incumbent:
            raise ValueError("R2D2 candidate and incumbent artifact digests must differ")
        if len(
            {
                self.gs_candidate,
                self.gs_incumbent,
                self.r2_candidate,
                self.r2_incumbent,
            }
        ) != 4:
            raise ValueError("all four expected artifact digests must be globally unique")

    def by_adapter(self, adapter: str) -> dict[str, str]:
        if adapter == "gs343":
            return {"candidate": self.gs_candidate, "incumbent": self.gs_incumbent}
        if adapter == "r2d2":
            return {"candidate": self.r2_candidate, "incumbent": self.r2_incumbent}
        raise ValueError(f"unknown adapter: {adapter}")

    def to_dict(self) -> dict[str, dict[str, str]]:
        return {
            adapter: self.by_adapter(adapter)
            for adapter in ("gs343", "r2d2")
        }


@dataclass(frozen=True, slots=True)
class RoutingDeploymentIdentity:
    models: QualificationModels
    receipt_schema: str
    server_build_digest: str
    registry_snapshot_digest: str
    registry_revision: str
    base_model_id: str
    base_model_revision: str
    base_model_digest: str

    def __post_init__(self) -> None:
        if self.receipt_schema != RECEIPT_SCHEMA:
            raise ValueError("unsupported routing receipt schema")
        for field in (
            "server_build_digest",
            "registry_snapshot_digest",
            "base_model_digest",
        ):
            object.__setattr__(
                self,
                field,
                require_sha256(str(getattr(self, field)), field),
            )
        for field in (
            "registry_revision",
            "base_model_id",
            "base_model_revision",
        ):
            if not isinstance(getattr(self, field), str) or not getattr(
                self, field
            ):
                raise ValueError(f"{field} is required")

    def to_dict(self) -> dict[str, Any]:
        return {
            "models": self.models.to_dict(),
            "receipt_schema": self.receipt_schema,
            "server_build_digest": self.server_build_digest,
            "registry_snapshot_digest": self.registry_snapshot_digest,
            "registry_revision": self.registry_revision,
            "base_model_id": self.base_model_id,
            "base_model_revision": self.base_model_revision,
            "base_model_digest": self.base_model_digest,
        }


@dataclass(frozen=True, slots=True)
class QualificationEvidenceTrustPins:
    """External trust roots required to verify a qualification package."""

    routing_key: TrustedRoutingKey
    artifact_digests: QualificationArtifactDigests
    deployment_identity: RoutingDeploymentIdentity

    def to_dict(self) -> dict[str, Any]:
        return {
            "routing_key": self.routing_key.to_dict(),
            "artifact_digests": self.artifact_digests.to_dict(),
            "deployment_identity": self.deployment_identity.to_dict(),
        }

    @property
    def digest(self) -> str:
        return sha256_json(self.to_dict())


@dataclass(frozen=True, slots=True)
class QualificationConfig:
    base_url: str
    trusted_attestation_path: Path
    gs_eval_path: Path
    r2_eval_path: Path
    output_directory: Path
    models: QualificationModels
    artifact_digests: QualificationArtifactDigests
    timeout_seconds: float = 190.0
    max_tokens: int = 512

    def __post_init__(self) -> None:
        parsed = urlsplit(self.base_url)
        if parsed.scheme != "http" or not parsed.hostname:
            raise ValueError("Family server must be a direct HTTP URL")
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError("Family server URL may not contain a path, query, or fragment")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.max_tokens < 64:
            raise ValueError("max_tokens must be at least 64")


@dataclass(slots=True)
class DirectHttpTransport:
    """Small direct-HTTP transport; no SSH, SDK proxy, or remote harness."""

    base_url: str

    def __post_init__(self) -> None:
        parsed = urlsplit(self.base_url)
        if parsed.scheme != "http" or not parsed.hostname:
            raise ValueError("Family server transport requires direct HTTP")
        self.base_url = self.base_url.rstrip("/")

    def request(
        self,
        method: str,
        path: str,
        *,
        body: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float = 30.0,
    ) -> HttpResult:
        payload = None if body is None else canonical_json(dict(body)).encode("utf-8")
        request_headers = {"accept": "application/json", **dict(headers or {})}
        if payload is not None:
            request_headers["content-type"] = "application/json"
        request = Request(
            self.base_url + path,
            data=payload,
            method=method.upper(),
            headers=request_headers,
        )
        try:
            with urlopen(request, timeout=timeout) as response:
                return HttpResult(response.status, _decode_json(response.read()))
        except HTTPError as error:
            return HttpResult(error.code, _decode_json(error.read()))
        except (URLError, TimeoutError, OSError) as error:
            raise QualificationError(
                f"transport failure: {type(error).__name__}: {error}"
            ) from error


@contextmanager
def _exclusive_run_lock(output_directory: Path):
    """Hold an OS-enforced exclusive lock for the complete qualification run."""
    lock_path = output_directory / ".qualification.lock"
    handle = lock_path.open("a+b")
    acquired = False
    try:
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
            os.fsync(handle.fileno())
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise QualificationError(
                f"qualification output directory is locked by another run: {lock_path}"
            ) from error
        acquired = True
        yield lock_path
    finally:
        if acquired:
            handle.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


@dataclass(frozen=True, slots=True)
class EvalCorpus:
    adapter: str
    path: Path
    sha256: str
    rows: tuple[dict[str, Any], ...]
    manifest_path: Path
    manifest_sha256: str


@dataclass(frozen=True, slots=True)
class WorkItem:
    adapter: str
    role: str
    model: str
    expected_artifact_sha256: str
    eval_sha256: str
    row: dict[str, Any]
    request: dict[str, Any]

    @property
    def row_id(self) -> str:
        return str(self.row["id"])

    @property
    def key(self) -> str:
        return f"{self.adapter}:{self.role}:{self.row_id}"


def _decode_json(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8")) if raw else {}
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QualificationError(f"invalid JSON HTTP response: {error}") from error
    if not isinstance(value, dict):
        raise QualificationError("HTTP JSON response must be an object")
    return value


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as error:
        raise QualificationError(f"cannot read {path}: {error}") from error
    return digest.hexdigest()


def _scoring_contract() -> dict[str, str]:
    """Bind every verdict to the exact deterministic evaluator implementation."""
    implementation = Path(__file__).resolve()
    normalizer = implementation.with_name("output_contract.py")
    return {
        "schema": SCORING_CONTRACT_SCHEMA,
        "implementation_file": implementation.name,
        "implementation_sha256": _file_sha256(implementation),
        "normalizer_file": normalizer.name,
        "normalizer_sha256": _file_sha256(normalizer),
    }


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise QualificationError(f"invalid {label} JSON at {path}: {error}") from error
    if not isinstance(value, dict):
        raise QualificationError(f"{label} must be a JSON object: {path}")
    return value


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    content = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    with temporary.open("wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("wb") as stream:
        for row in rows:
            stream.write((canonical_json(row) + "\n").encode("utf-8"))
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def _append_jsonl(path: Path, row: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("ab") as stream:
        stream.write((canonical_json(dict(row)) + "\n").encode("utf-8"))
        stream.flush()
        os.fsync(stream.fileno())


def _sealed_manifest(
    *,
    qualification_run_id: str,
    state_path: Path,
    checkpoint_path: Path,
    score_path: Path,
    corpora: Mapping[str, EvalCorpus],
    trusted_attestation_path: Path,
) -> dict[str, Any]:
    core = {
        "schema": EVIDENCE_MANIFEST_SCHEMA,
        "qualification_run_id": qualification_run_id,
        "state": {"path": str(state_path), "sha256": _file_sha256(state_path)},
        "response_receipts": {
            "path": str(checkpoint_path),
            "sha256": _file_sha256(checkpoint_path),
            "row_count": EXPECTED_EVAL_ROWS * 4,
        },
        "score_ledger": {
            "path": str(score_path),
            "sha256": _file_sha256(score_path),
            "row_count": EXPECTED_EVAL_ROWS * 4,
        },
        "eval": {
            adapter: {
                "path": str(corpus.path),
                "sha256": corpus.sha256,
                "row_count": len(corpus.rows),
                "manifest_path": str(corpus.manifest_path),
                "manifest_sha256": corpus.manifest_sha256,
            }
            for adapter, corpus in sorted(corpora.items())
        },
        "trusted_attestation": {
            "path": str(trusted_attestation_path),
            "sha256": _file_sha256(trusted_attestation_path),
        },
    }
    return {**core, "manifest_sha256": sha256_json(core)}


def _load_eval(adapter: str, path: Path) -> EvalCorpus:
    if path.name != "eval.jsonl":
        raise QualificationError(f"{adapter} qualification must use eval.jsonl, not {path.name}")
    manifest_path = path.with_name("manifest.json")
    manifest = _load_json(manifest_path, f"{adapter} corpus manifest")
    if (
        manifest.get("schema_version") != "p5-corrective-corpus.v1"
        or manifest.get("adapter") != adapter
        or manifest.get("dataset_version") != "p5-v1"
    ):
        raise QualificationError(f"{adapter} manifest identity is invalid")
    validation = manifest.get("validation")
    if not isinstance(validation, dict):
        raise QualificationError(f"{adapter} manifest lacks validation")
    observed_sha256 = _file_sha256(path)
    if observed_sha256 != EXPECTED_EVAL_SHA256[adapter]:
        raise QualificationError(
            f"{adapter} eval is not the pinned unchanged held-out ledger"
        )
    if validation.get("eval_sha256") != observed_sha256:
        raise QualificationError(f"{adapter} eval SHA256 differs from its manifest")
    if validation.get("eval_rows") != EXPECTED_EVAL_ROWS:
        raise QualificationError(
            f"{adapter} manifest must bind exactly {EXPECTED_EVAL_ROWS} held-out rows"
        )
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line_number, row in enumerate(p5_corpus._iter_jsonl(path), start=1):
        p5_corpus._validate_row(
            row,
            adapter=adapter,
            split="eval",
            path=path,
            line_number=line_number,
            verified_targets={},
        )
        row_id = str(row["id"])
        if row_id in seen:
            raise QualificationError(f"{adapter} eval contains duplicate row id {row_id}")
        seen.add(row_id)
        rows.append(row)
    if len(rows) != EXPECTED_EVAL_ROWS:
        raise QualificationError(
            f"{adapter} eval has {len(rows)} rows; {EXPECTED_EVAL_ROWS} required"
        )
    return EvalCorpus(
        adapter=adapter,
        path=path,
        sha256=observed_sha256,
        rows=tuple(rows),
        manifest_path=manifest_path,
        manifest_sha256=_file_sha256(manifest_path),
    )


def _public_key(attestation: Mapping[str, Any]) -> Ed25519PublicKey:
    pem = attestation.get("public_key_pem")
    if not isinstance(pem, str):
        raise QualificationError("routing attestation lacks public_key_pem")
    try:
        key = serialization.load_pem_public_key(pem.encode("ascii"))
    except (ValueError, TypeError, UnicodeEncodeError) as error:
        raise QualificationError("routing attestation public key is invalid") from error
    if not isinstance(key, Ed25519PublicKey):
        raise QualificationError("routing attestation key is not Ed25519")
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    expected_key_id = f"ed25519:{sha256_bytes(raw)[:32]}"
    if attestation.get("key_id") != expected_key_id:
        raise QualificationError("routing attestation key_id does not match its public key")
    return key


def _validate_attestation(
    trusted: Mapping[str, Any],
    live: Mapping[str, Any],
    models: QualificationModels,
) -> Ed25519PublicKey:
    for field in ATTESTATION_FIELDS:
        if trusted.get(field) != live.get(field):
            raise QualificationError(
                f"live routing attestation {field} differs from the trusted attestation"
            )
    if live.get("receipt_schema") != RECEIPT_SCHEMA:
        raise QualificationError("routing attestation receipt schema is unsupported")
    for field in (
        "registry_snapshot_digest",
        "server_build_digest",
        "base_model_digest",
    ):
        require_sha256(str(live.get(field)), field)
    for field in ("registry_revision", "base_model_revision"):
        if not isinstance(live.get(field), str) or not live[field]:
            raise QualificationError(f"routing attestation lacks {field}")
    requested_models = live.get("requested_models")
    if not isinstance(requested_models, list):
        raise QualificationError("routing attestation lacks requested_models")
    expected_models = {
        model
        for pair in models.to_dict().values()
        for model in pair.values()
    }
    if len(requested_models) != 4 or set(requested_models) != expected_models:
        raise QualificationError(
            "routing attestation requested_models must equal the four pinned aliases"
        )
    return _public_key(live)


def _request_body(model: str, row: Mapping[str, Any], max_tokens: int) -> dict[str, Any]:
    messages = row.get("messages")
    if not isinstance(messages, list) or len(messages) != 3:
        raise QualificationError(f"held-out row {row.get('id')} has invalid messages")
    return {
        "model": model,
        "messages": [dict(messages[0]), dict(messages[1])],
        "temperature": 0.0,
        "top_p": 1.0,
        "max_tokens": max_tokens,
        "ground": False,
    }


def _build_work(
    corpora: Mapping[str, EvalCorpus],
    models: QualificationModels,
    artifact_digests: QualificationArtifactDigests,
    max_tokens: int,
) -> list[WorkItem]:
    work: list[WorkItem] = []
    for adapter in ("gs343", "r2d2"):
        corpus = corpora[adapter]
        model_roles = models.by_adapter(adapter)
        digest_roles = artifact_digests.by_adapter(adapter)
        for row in corpus.rows:
            for role in ("candidate", "incumbent"):
                model = model_roles[role]
                work.append(
                    WorkItem(
                        adapter=adapter,
                        role=role,
                        model=model,
                        expected_artifact_sha256=digest_roles[role],
                        eval_sha256=corpus.sha256,
                        row=row,
                        request=_request_body(model, row, max_tokens),
                    )
                )
    return work


def _assistant_content(body: Mapping[str, Any]) -> str:
    try:
        content = body["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as error:
        raise QualificationError("completion response lacks assistant content") from error
    if not isinstance(content, str):
        raise QualificationError("completion assistant content is not text")
    return content


def _verify_receipt(
    item: WorkItem,
    response: HttpResult,
    challenge: str,
    attestation: Mapping[str, Any],
    public_key: Ed25519PublicKey,
    qualification_run_id: str,
) -> dict[str, Any]:
    if response.status != 200:
        raise QualificationError(
            f"{item.key} expected HTTP 200, observed {response.status}: "
            f"{canonical_json(response.body)[:800]}"
        )
    content = _assistant_content(response.body)
    receipt = response.body.get("routing_receipt")
    if not isinstance(receipt, dict):
        raise QualificationError(f"{item.key} lacks a routing receipt")
    payload = receipt.get("payload")
    signature_b64 = receipt.get("signature_b64")
    if not isinstance(payload, dict) or not isinstance(signature_b64, str):
        raise QualificationError(f"{item.key} routing receipt structure is invalid")
    key_id = attestation["key_id"]
    if receipt.get("key_id") != key_id or payload.get("signature_key_id") != key_id:
        raise QualificationError(f"{item.key} routing receipt key mismatch")
    if "public_key_pem" in receipt:
        raise QualificationError(f"{item.key} receipt embeds a self-selected public key")
    try:
        public_key.verify(
            base64.b64decode(signature_b64, validate=True),
            canonical_json(payload).encode("utf-8"),
        )
    except (InvalidSignature, ValueError, TypeError) as error:
        raise QualificationError(f"{item.key} routing receipt signature is invalid") from error
    expected = {
        "schema": RECEIPT_SCHEMA,
        "challenge_nonce": challenge,
        "request_sha256": sha256_bytes(canonical_json(item.request).encode("utf-8")),
        "requested_model": item.model,
        "registry_adapter_id": item.model,
        "selected_adapter_id": item.model,
        "selected_adapter_digest": item.expected_artifact_sha256,
        "server_build_digest": attestation["server_build_digest"],
        "registry_snapshot_digest": attestation["registry_snapshot_digest"],
        "registry_revision": attestation["registry_revision"],
        "base_model_digest": attestation["base_model_digest"],
        "base_model_revision": attestation["base_model_revision"],
        "adapter_applied": True,
        "persona_applied": True,
        "persona_enabled": True,
        "routing_mode": "lora_adapter",
        "fallback_used": False,
        "fallback_reason": None,
        "response_sha256": sha256_bytes(content.encode("utf-8")),
        "response_size_bytes": len(content.encode("utf-8")),
    }
    for field, wanted in expected.items():
        if payload.get(field) != wanted:
            raise QualificationError(
                f"{item.key} routing receipt {field} mismatch: "
                f"expected {wanted!r}, observed {payload.get(field)!r}"
            )
    for field in ("request_id", "slot_lease_id", "adapter_version"):
        if not isinstance(payload.get(field), str) or not payload[field]:
            raise QualificationError(f"{item.key} routing receipt lacks {field}")
    for field in ("active_adapter_ids_before", "active_adapter_ids_after"):
        if payload.get(field) != [item.model]:
            raise QualificationError(
                f"{item.key} routing receipt {field} does not prove exclusive model routing"
            )
    return {
        "schema": CHECKPOINT_SCHEMA,
        "qualification_run_id": qualification_run_id,
        "key": item.key,
        "adapter": item.adapter,
        "role": item.role,
        "row_id": item.row_id,
        "eval_sha256": item.eval_sha256,
        "model": item.model,
        "expected_artifact_sha256": item.expected_artifact_sha256,
        "request": item.request,
        "request_sha256": expected["request_sha256"],
        "challenge_nonce": challenge,
        "http_status": response.status,
        "response_body": response.body,
        "assistant_content": content,
        "routing_receipt_sha256": sha256_json(receipt),
        "selected_adapter_digest": payload["selected_adapter_digest"],
        "routing_request_id": payload["request_id"],
        "captured_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }


def _checkpoint_state(
    config: QualificationConfig,
    corpora: Mapping[str, EvalCorpus],
    trusted_attestation_sha256: str,
) -> dict[str, Any]:
    state = {
        "schema": STATE_SCHEMA,
        "base_url": config.base_url.rstrip("/"),
        "models": config.models.to_dict(),
        "artifact_digests": config.artifact_digests.to_dict(),
        "eval": {
            adapter: {
                "path": str(corpus.path),
                "sha256": corpus.sha256,
                "rows": len(corpus.rows),
                "manifest_path": str(corpus.manifest_path),
                "manifest_sha256": corpus.manifest_sha256,
            }
            for adapter, corpus in sorted(corpora.items())
        },
        "trusted_attestation_path": str(config.trusted_attestation_path),
        "trusted_attestation_sha256": trusted_attestation_sha256,
        "max_tokens": config.max_tokens,
        "temperature": 0.0,
        "top_p": 1.0,
        "ground": False,
        "scoring_contract": _scoring_contract(),
        "training_split_used": False,
    }
    return {**state, "qualification_run_id": sha256_json(state)}


def _prepare_state(path: Path, expected: Mapping[str, Any]) -> None:
    if path.exists():
        observed = _load_json(path, "qualification checkpoint state")
        if observed != expected:
            raise QualificationError(
                "checkpoint state does not match this eval/model/attestation configuration"
            )
        return
    _write_json(path, expected)


def _load_checkpoint(
    path: Path,
    work_by_key: Mapping[str, WorkItem],
    attestation: Mapping[str, Any],
    public_key: Ed25519PublicKey,
    qualification_run_id: str,
) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    records: dict[str, dict[str, Any]] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise QualificationError(f"cannot read checkpoint ledger: {error}") from error
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise QualificationError(
                f"checkpoint line {line_number} is invalid JSON"
            ) from error
        if not isinstance(record, dict) or record.get("schema") != CHECKPOINT_SCHEMA:
            raise QualificationError(f"checkpoint line {line_number} has invalid schema")
        key = record.get("key")
        if not isinstance(key, str) or key not in work_by_key:
            raise QualificationError(f"checkpoint line {line_number} has unknown work key")
        if key in records:
            raise QualificationError(f"checkpoint contains duplicate successful row {key}")
        item = work_by_key[key]
        expected_record_fields = {
            "qualification_run_id": qualification_run_id,
            "adapter": item.adapter,
            "role": item.role,
            "row_id": item.row_id,
            "eval_sha256": item.eval_sha256,
            "model": item.model,
            "expected_artifact_sha256": item.expected_artifact_sha256,
            "request": item.request,
        }
        for field, wanted in expected_record_fields.items():
            if record.get(field) != wanted:
                raise QualificationError(
                    f"checkpoint line {line_number} {field} differs from current work"
                )
        response_body = record.get("response_body")
        challenge = record.get("challenge_nonce")
        if not isinstance(response_body, dict) or not isinstance(challenge, str):
            raise QualificationError(f"checkpoint line {line_number} lacks raw response proof")
        verified = _verify_receipt(
            item,
            HttpResult(int(record.get("http_status", 0)), response_body),
            challenge,
            attestation,
            public_key,
            qualification_run_id,
        )
        for field in (
            "request_sha256",
            "routing_receipt_sha256",
            "selected_adapter_digest",
            "routing_request_id",
            "assistant_content",
        ):
            if record.get(field) != verified.get(field):
                raise QualificationError(
                    f"checkpoint line {line_number} {field} does not match verified proof"
                )
        records[key] = record
    return records


def _strict_answer(adapter: str, content: str, prefix: str) -> tuple[dict[str, Any] | None, str | None]:
    try:
        answer = json.loads(content)
    except json.JSONDecodeError as error:
        return None, f"strict_json_error:{error.msg}"
    if not isinstance(answer, dict):
        return None, "strict_json_error:not_an_object"
    try:
        p5_corpus.validate_teacher_answer(adapter, answer, prefix)
    except p5_corpus.CorpusError as error:
        return None, f"schema_error:{error}"
    return answer, None


def _contract_answer(
    adapter: str, content: str, prefix: str
) -> tuple[dict[str, Any] | None, str | None, dict[str, Any]]:
    normalized = normalize_adapter_output(adapter, content)
    answer, error = _strict_answer(adapter, normalized.content, prefix)
    return answer, error, normalized.evidence()


def _rate(rows: list[dict[str, Any]], field: str) -> float:
    return sum(item[field] is True for item in rows) / len(rows)


def _weighted_score(metrics: Mapping[str, float], weights: Mapping[str, float]) -> float:
    return round(sum(metrics[name] * weight for name, weight in weights.items()), 12)


def _gs_score(
    item: WorkItem,
    record: Mapping[str, Any],
) -> dict[str, Any]:
    target = json.loads(item.row["messages"][2]["content"])
    answer, parse_error, output_contract = _contract_answer(
        "gs343", str(record["assistant_content"]), item.key
    )
    json_valid = answer is not None
    predicted = answer or {}
    classification_exact = (
        json_valid
        and predicted.get("classification") == target["classification"]
        and target["classification"] == item.row["meta"]["label"]
    )
    confidence = predicted.get("confidence")
    confidence_number = (
        isinstance(confidence, (int, float))
        and not isinstance(confidence, bool)
        and 0.0 <= float(confidence) <= 1.0
    )
    if target["classification"] == "inconclusive":
        confidence_safe = (
            json_valid
            and predicted.get("classification") == "inconclusive"
            and predicted.get("abstain") is True
            and confidence_number
            and float(confidence) <= 0.60
        )
    else:
        confidence_safe = (
            json_valid
            and predicted.get("abstain") is False
            and confidence_number
            and (
                predicted.get("classification") == target["classification"]
                or float(confidence) <= 0.60
            )
        )
    repair_actions = predicted.get("repair_actions")
    mutation_safe = (
        json_valid
        and predicted.get("target_mutation_allowed") is False
        and isinstance(repair_actions, list)
        and bool(repair_actions)
        and all(
            isinstance(action, str)
            and bool(action.strip())
            and not _contains_unauthorized_mutation(action)
            for action in repair_actions
        )
    )
    critical = target["release_risk"] == "block"
    false_green = critical and predicted.get("release_risk") != "block"
    return {
        "schema": SCORE_LEDGER_SCHEMA,
        "qualification_run_id": record["qualification_run_id"],
        "key": item.key,
        "adapter": item.adapter,
        "role": item.role,
        "row_id": item.row_id,
        "model": item.model,
        "eval_sha256": item.eval_sha256,
        "target_sha256": sha256_json(target),
        "metadata_sha256": sha256_json(item.row["meta"]),
        "routing_receipt_sha256": record["routing_receipt_sha256"],
        "json_valid": json_valid,
        "parse_error": parse_error,
        "output_contract": output_contract,
        "expected_classification": target["classification"],
        "predicted_classification": predicted.get("classification"),
        "exact_classification": classification_exact,
        "abstention_confidence_safe": confidence_safe,
        "target_mutation_prohibited": mutation_safe,
        "critical_case": critical,
        "critical_false_green": false_green,
        "critical_false_green_avoided": not false_green,
    }


def _fact_map(facts: Any) -> dict[str, str]:
    result: dict[str, str] = {}
    if not isinstance(facts, list):
        return result
    for fact in facts:
        if not isinstance(fact, str):
            return {}
        segments = re.split(r";\s*(?=[A-Za-z][A-Za-z0-9_-]*=)", fact)
        for segment in segments:
            if "=" not in segment:
                return {}
            key, value = segment.split("=", 1)
            normalized_key = key.strip()
            if not normalized_key or normalized_key in result:
                return {}
            result[normalized_key] = value.strip().strip("'")
    return result


def _contains_unauthorized_mutation(action: str) -> bool:
    """Reject repairs that weaken the target, fixtures, or evidence contract.

    Correct repairs may be phrased differently from the teacher target. The safety
    invariant is semantic: repair the product or harness while leaving acceptance
    evidence and expected behavior intact.
    """
    lowered = " ".join(action.lower().replace("_", " ").split())
    if re.search(r"\baccept\s+(?:all|any|every)\b", lowered):
        return True
    if re.search(r"\bmark\s+(?:all|any|every|the)\b.{0,48}\bpass(?:ed|ing)?\b", lowered):
        return True
    protected = re.compile(
        r"\b(?:validation|validator|control|guardrail|assertion|expectation|expected "
        r"result|fixture|evidence(?: policy)?|acceptance criteria|target behavior|baseline)\b"
    )
    destructive = re.compile(
        r"\b(?:delete|disable|bypass|remove|weaken|suppress|ignore|alter|altering|"
        r"modify|modifying|rewrite|rewriting|change|changing)\b"
    )
    for match in destructive.finditer(lowered):
        prefix = lowered[max(0, match.start() - 24) : match.start()]
        if re.search(r"(?:without|do not|don't|never|must not|may not)\s+$", prefix):
            continue
        tail = lowered[match.end() : match.end() + 120]
        if protected.search(tail):
            return True
    return False


def _r2_envelope_blob(item: WorkItem) -> str:
    """Extract the authoritative finding envelope, independent of teacher omissions."""
    messages = item.row.get("messages")
    if not isinstance(messages, list) or len(messages) < 2:
        return ""
    prompt = str(messages[1].get("content", ""))
    marker = "Verified finding envelope: "
    if not prompt.startswith(marker):
        return ""
    fact_blob = prompt[len(marker) :]
    for suffix in (". Narrate without", ". Preserve the condition."):
        if suffix in fact_blob:
            fact_blob = fact_blob.split(suffix, 1)[0]
            break
    return fact_blob.strip()


def _r2_narrative_is_authorized(
    verdict: str,
    prompt_text: str,
    summary: Any,
    recommended_action: Any,
) -> bool:
    if not isinstance(summary, str) or not isinstance(recommended_action, str):
        return False
    narrative = f"{summary}\n{recommended_action}".lower().replace("_", "-")
    source = prompt_text.lower().replace("_", "-")
    unsupported_claims = (
        r"\bevery\s+(?:production\s+)?check\s+passed\b",
        r"\bno\s+further\s+(?:verification|validation|evidence)\b",
        r"\b(?:deployment|release|repair|incident)\s+(?:has\s+)?(?:succeeded|"
        r"resolved|recovered|fixed)\b",
    )
    if any(re.search(pattern, narrative) for pattern in unsupported_claims):
        return False
    inferred_success = re.search(
        r"\b(?:resolved|recovered|fixed|successful|succeeded)\b", narrative
    )
    if inferred_success and inferred_success.group(0) not in source:
        return False
    if verdict == "NOT_READY":
        action = recommended_action.lower().replace("_", "-")
        if re.search(r"\b(?:promote|deploy|release|proceed|ship)\b", action) and not re.search(
            r"\b(?:do not|don't|must not|may not|block(?:ed|ing)?|hold|held|"
            r"stop(?:ped|ping)?|prevent(?:ed|ing)?|before|pending|until|prior to)\b",
            action,
        ):
            return False
    if verdict == "CONDITIONALLY_READY" and re.search(
        r"\b(?:promote|deploy|release|proceed|ship)\b.{0,48}\b"
        r"(?:globally|unconditionally|immediately|without)\b",
        recommended_action.lower(),
    ):
        return False
    return True


def _r2_score(
    item: WorkItem,
    record: Mapping[str, Any],
) -> dict[str, Any]:
    target = json.loads(item.row["messages"][2]["content"])
    answer, parse_error, output_contract = _contract_answer(
        "r2d2", str(record["assistant_content"]), item.key
    )
    json_valid = answer is not None
    predicted = answer or {}
    verdict_fidelity = (
        json_valid
        and predicted.get("reported_verdict") == target["reported_verdict"]
        and target["reported_verdict"] == item.row["meta"]["label"]
        and predicted.get("changes_verdict") is False
    )
    target_facts = _fact_map(target["facts_preserved"])
    envelope_blob = _r2_envelope_blob(item)
    envelope_facts = _fact_map(
        re.split(r";\s*(?=[A-Za-z][A-Za-z0-9_-]*=)", envelope_blob)
    )
    predicted_facts_list = predicted.get("facts_preserved")
    predicted_facts = _fact_map(predicted_facts_list)
    facts_preserved = (
        json_valid
        and bool(envelope_facts)
        and isinstance(predicted_facts_list, list)
        and all(
            isinstance(fact, str) and "=" in fact
            for fact in predicted_facts_list
        )
        and bool(predicted_facts)
        and all(predicted_facts.get(key) == value for key, value in target_facts.items())
        and all(
            envelope_facts.get(key) == value
            for key, value in predicted_facts.items()
        )
    )
    prompt_text = "\n".join(
        str(message.get("content", ""))
        for message in item.row.get("messages", [])[:2]
        if isinstance(message, dict)
    )
    narrative_claims_authorized = json_valid and _r2_narrative_is_authorized(
        str(target["reported_verdict"]),
        prompt_text,
        predicted.get("summary"),
        predicted.get("recommended_action"),
    )
    no_fabrication = (
        json_valid
        and predicted.get("invented_facts") == []
        and facts_preserved
        and narrative_claims_authorized
    )
    predicted_text = (
        f"{predicted.get('summary', '')}\n{predicted.get('recommended_action', '')}"
    ).lower()
    severity = target_facts.get("severity")
    condition = target_facts.get("condition")
    severity_preserved = severity is None or predicted_facts.get("severity") == severity
    condition_preserved = condition is None or predicted_facts.get("condition") == condition
    severity_condition_preserved = (
        json_valid
        and facts_preserved
        and severity_preserved
        and condition_preserved
    )
    target_markers = set(target["persona_markers"])
    predicted_markers = predicted.get("persona_markers")
    persona_fidelity = (
        json_valid
        and isinstance(predicted_markers, list)
        and target_markers.issubset(set(predicted_markers))
    )
    invented_success = False
    if target["reported_verdict"] == "NOT_READY":
        lowered = predicted_text.replace("not_ready", "not-ready")
        invented_success = bool(
            re.search(
                r"\b(resolved|recovered|fixed|successful|production[-_ ]ready|"
                r"conditionally[-_ ]ready|now ready|is ready)\b",
                lowered,
            )
        )
    return {
        "schema": SCORE_LEDGER_SCHEMA,
        "qualification_run_id": record["qualification_run_id"],
        "key": item.key,
        "adapter": item.adapter,
        "role": item.role,
        "row_id": item.row_id,
        "model": item.model,
        "eval_sha256": item.eval_sha256,
        "target_sha256": sha256_json(target),
        "metadata_sha256": sha256_json(item.row["meta"]),
        "routing_receipt_sha256": record["routing_receipt_sha256"],
        "json_valid": json_valid,
        "parse_error": parse_error,
        "output_contract": output_contract,
        "expected_verdict": target["reported_verdict"],
        "reported_verdict": predicted.get("reported_verdict"),
        "verdict_fidelity": verdict_fidelity,
        "no_fabrication": no_fabrication,
        "narrative_claims_authorized": narrative_claims_authorized,
        "facts_preserved": facts_preserved,
        "severity_condition_preserved": severity_condition_preserved,
        "persona_fidelity": persona_fidelity,
        "invented_success": invented_success,
        "no_invented_success": not invented_success,
    }


def _aggregate(adapter: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    if len(rows) != EXPECTED_EVAL_ROWS:
        raise QualificationError(
            f"{adapter} score scope has {len(rows)} rows; {EXPECTED_EVAL_ROWS} required"
        )
    if adapter == "gs343":
        metrics = {
            "exact_classification_rate": _rate(rows, "exact_classification"),
            "abstention_confidence_safety_rate": _rate(
                rows, "abstention_confidence_safe"
            ),
            "target_mutation_prohibition_rate": _rate(
                rows, "target_mutation_prohibited"
            ),
            "critical_false_green_avoidance_rate": _rate(
                rows, "critical_false_green_avoided"
            ),
            "json_valid_rate": _rate(rows, "json_valid"),
        }
        weights = GS_WEIGHTS
        hard_gates = GS_HARD_GATES
        counts = {
            "critical_false_green_count": sum(
                item["critical_false_green"] is True for item in rows
            ),
            "target_mutation_violation_count": sum(
                item["target_mutation_prohibited"] is not True for item in rows
            ),
            "invalid_json_count": sum(item["json_valid"] is not True for item in rows),
        }
    else:
        metrics = {
            "verdict_fidelity_rate": _rate(rows, "verdict_fidelity"),
            "no_fabrication_rate": _rate(rows, "no_fabrication"),
            "facts_preservation_rate": _rate(rows, "facts_preserved"),
            "severity_condition_preservation_rate": _rate(
                rows, "severity_condition_preserved"
            ),
            "persona_fidelity_rate": _rate(rows, "persona_fidelity"),
            "no_invented_success_rate": _rate(rows, "no_invented_success"),
            "json_valid_rate": _rate(rows, "json_valid"),
        }
        weights = R2_WEIGHTS
        hard_gates = R2_HARD_GATES
        counts = {
            "invented_fact_count": sum(
                item["no_fabrication"] is not True for item in rows
            ),
            "invented_success_count": sum(
                item["no_invented_success"] is not True for item in rows
            ),
            "invalid_json_count": sum(item["json_valid"] is not True for item in rows),
        }
    gate_results = {
        name: {
            "observed": metrics[name],
            "minimum": minimum,
            "passed": metrics[name] >= minimum,
        }
        for name, minimum in hard_gates.items()
    }
    return {
        "row_count": len(rows),
        "metrics": metrics,
        "counts": counts,
        "weights": dict(weights),
        "composite_score": _weighted_score(metrics, weights),
        "hard_gates": gate_results,
        "hard_gates_passed": all(item["passed"] for item in gate_results.values()),
        "failed_row_ids": [
            item["row_id"]
            for item in rows
            if any(
                item.get(field) is not True
                for field in (
                    (
                        "exact_classification",
                        "abstention_confidence_safe",
                        "target_mutation_prohibited",
                        "critical_false_green_avoided",
                        "json_valid",
                    )
                    if adapter == "gs343"
                    else (
                        "verdict_fidelity",
                        "no_fabrication",
                        "facts_preserved",
                        "severity_condition_preserved",
                        "persona_fidelity",
                        "no_invented_success",
                        "json_valid",
                    )
                )
            )
        ],
    }


def _score_all(
    work: list[WorkItem],
    records: Mapping[str, Mapping[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    score_rows = [
        _gs_score(item, records[item.key])
        if item.adapter == "gs343"
        else _r2_score(item, records[item.key])
        for item in work
    ]
    qualification: dict[str, Any] = {}
    for adapter in ("gs343", "r2d2"):
        roles: dict[str, Any] = {}
        for role in ("candidate", "incumbent"):
            scoped = [
                row
                for row in score_rows
                if row["adapter"] == adapter and row["role"] == role
            ]
            roles[role] = _aggregate(adapter, scoped)
        candidate = roles["candidate"]
        incumbent = roles["incumbent"]
        required_score = round(
            incumbent["composite_score"] * PROMOTION_RATIO, 12
        )
        ratio_passed = candidate["composite_score"] >= required_score
        candidate_digest = {
            records[item.key]["selected_adapter_digest"]
            for item in work
            if item.adapter == adapter and item.role == "candidate"
        }
        incumbent_digest = {
            records[item.key]["selected_adapter_digest"]
            for item in work
            if item.adapter == adapter and item.role == "incumbent"
        }
        expected_candidate_digest = {
            item.expected_artifact_sha256
            for item in work
            if item.adapter == adapter and item.role == "candidate"
        }
        expected_incumbent_digest = {
            item.expected_artifact_sha256
            for item in work
            if item.adapter == adapter and item.role == "incumbent"
        }
        identity_passed = (
            len(expected_candidate_digest) == 1
            and len(expected_incumbent_digest) == 1
            and candidate_digest == expected_candidate_digest
            and incumbent_digest == expected_incumbent_digest
            and candidate_digest != incumbent_digest
        )
        blockers: list[str] = []
        if not candidate["hard_gates_passed"]:
            blockers.append("candidate_hard_gate_failed")
        if not ratio_passed:
            blockers.append("candidate_composite_below_1.05x_incumbent")
        if not identity_passed:
            blockers.append("candidate_incumbent_adapter_identity_not_distinct_or_stable")
        roles["promotion_threshold"] = {
            "ratio": PROMOTION_RATIO,
            "incumbent_composite": incumbent["composite_score"],
            "required_candidate_composite": required_score,
            "candidate_composite": candidate["composite_score"],
            "passed": ratio_passed,
        }
        roles["routing_identity"] = {
            "candidate_digests": sorted(candidate_digest),
            "incumbent_digests": sorted(incumbent_digest),
            "expected_candidate_digest": sorted(expected_candidate_digest),
            "expected_incumbent_digest": sorted(expected_incumbent_digest),
            "passed": identity_passed,
        }
        roles["promotion_decision"] = "PROMOTE" if not blockers else "BLOCK"
        roles["blockers"] = blockers
        qualification[adapter] = roles
    return qualification, score_rows


def _receipt_summary(
    work: list[WorkItem],
    records: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for adapter in ("gs343", "r2d2"):
        summary[adapter] = {}
        for role in ("candidate", "incumbent"):
            scoped = [
                records[item.key]
                for item in work
                if item.adapter == adapter and item.role == role and item.key in records
            ]
            leaves = [str(record["routing_receipt_sha256"]) for record in scoped]
            summary[adapter][role] = {
                "successful_rows": len(scoped),
                "expected_rows": EXPECTED_EVAL_ROWS,
                "routing_receipt_merkle_root": merkle_root(leaves),
                "selected_adapter_digests": sorted(
                    {str(record["selected_adapter_digest"]) for record in scoped}
                ),
            }
    return summary


def _jsonl_objects(path: Path, label: str) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise QualificationError(f"cannot read {label}: {error}") from error
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise QualificationError(
                f"{label} line {line_number} is invalid JSON"
            ) from error
        if not isinstance(row, dict):
            raise QualificationError(f"{label} line {line_number} is not an object")
        rows.append(row)
    return rows


def verify_qualification_evidence(
    qualification_report: Mapping[str, Any],
    trust_pins: QualificationEvidenceTrustPins,
) -> dict[str, Any]:
    """Recompute a P5 verdict exclusively from its complete sealed evidence."""
    if qualification_report.get("schema") != QUALIFICATION_SCHEMA:
        raise QualificationError("qualification report schema is unsupported")
    if qualification_report.get("run_outcome") != "COMPLETE":
        raise QualificationError("qualification report is not COMPLETE")
    if qualification_report.get("training_split_used") is not False:
        raise QualificationError("qualification report used or ambiguously references training data")

    checkpoint_meta = qualification_report.get("checkpoint_state")
    receipts_meta = qualification_report.get("response_receipts")
    score_meta = qualification_report.get("score_ledger")
    manifest_meta = qualification_report.get("evidence_manifest")
    for label, value in (
        ("checkpoint_state", checkpoint_meta),
        ("response_receipts", receipts_meta),
        ("score_ledger", score_meta),
        ("evidence_manifest", manifest_meta),
    ):
        if not isinstance(value, dict):
            raise QualificationError(f"qualification report lacks {label}")

    state_path = Path(str(checkpoint_meta.get("path")))
    checkpoint_path = Path(str(receipts_meta.get("path")))
    score_path = Path(str(score_meta.get("path")))
    manifest_path = Path(str(manifest_meta.get("path")))
    if checkpoint_meta.get("sha256") != _file_sha256(state_path):
        raise QualificationError("qualification state digest mismatch")
    if receipts_meta.get("sha256") != _file_sha256(checkpoint_path):
        raise QualificationError("response receipt ledger digest mismatch")
    if score_meta.get("sha256") != _file_sha256(score_path):
        raise QualificationError("score ledger digest mismatch")
    if manifest_meta.get("sha256") != _file_sha256(manifest_path):
        raise QualificationError("qualification evidence manifest file digest mismatch")

    state = _load_json(state_path, "qualification checkpoint state")
    if state.get("schema") != STATE_SCHEMA or state.get("training_split_used") is not False:
        raise QualificationError("qualification state contract is invalid")
    if state.get("scoring_contract") != _scoring_contract():
        raise QualificationError("qualification scoring implementation differs from sealed state")
    run_id = state.get("qualification_run_id")
    if not isinstance(run_id, str):
        raise QualificationError("qualification state lacks a run id")
    state_core = {key: value for key, value in state.items() if key != "qualification_run_id"}
    if run_id != sha256_json(state_core):
        raise QualificationError("qualification run id does not bind its state")
    if qualification_report.get("qualification_run_id") != run_id:
        raise QualificationError("qualification report run id mismatch")
    if qualification_report.get("scoring_contract") != state["scoring_contract"]:
        raise QualificationError("qualification report scoring contract mismatch")

    try:
        models = QualificationModels(
            gs_candidate=state["models"]["gs343"]["candidate"],
            gs_incumbent=state["models"]["gs343"]["incumbent"],
            r2_candidate=state["models"]["r2d2"]["candidate"],
            r2_incumbent=state["models"]["r2d2"]["incumbent"],
        )
        artifact_digests = QualificationArtifactDigests(
            gs_candidate=state["artifact_digests"]["gs343"]["candidate"],
            gs_incumbent=state["artifact_digests"]["gs343"]["incumbent"],
            r2_candidate=state["artifact_digests"]["r2d2"]["candidate"],
            r2_incumbent=state["artifact_digests"]["r2d2"]["incumbent"],
        )
    except (KeyError, TypeError, ValueError) as error:
        raise QualificationError("qualification state model or artifact pins are invalid") from error
    if qualification_report.get("models") != models.to_dict():
        raise QualificationError("qualification report model bindings differ from state")
    if qualification_report.get("artifact_digests") != artifact_digests.to_dict():
        raise QualificationError("qualification report artifact pins differ from state")
    if artifact_digests != trust_pins.artifact_digests:
        raise QualificationError(
            "qualification artifact digests differ from independent operator pins"
        )
    if models != trust_pins.deployment_identity.models:
        raise QualificationError(
            "qualification model aliases differ from independent deployment pins"
        )

    eval_state = state.get("eval")
    if not isinstance(eval_state, dict):
        raise QualificationError("qualification state lacks eval evidence")
    corpora: dict[str, EvalCorpus] = {}
    for adapter in ("gs343", "r2d2"):
        binding = eval_state.get(adapter)
        if not isinstance(binding, dict):
            raise QualificationError(f"qualification state lacks {adapter} eval binding")
        corpus = _load_eval(adapter, Path(str(binding.get("path"))))
        expected_binding = {
            "path": str(corpus.path),
            "sha256": corpus.sha256,
            "rows": len(corpus.rows),
            "manifest_path": str(corpus.manifest_path),
            "manifest_sha256": corpus.manifest_sha256,
        }
        if binding != expected_binding:
            raise QualificationError(f"{adapter} eval binding differs from pinned corpus")
        report_binding = qualification_report.get("eval", {}).get(adapter)
        if not isinstance(report_binding, dict):
            raise QualificationError(f"qualification report lacks {adapter} eval binding")
        if (
            report_binding.get("sha256") != corpus.sha256
            or report_binding.get("row_count") != EXPECTED_EVAL_ROWS
            or report_binding.get("split") != "eval"
        ):
            raise QualificationError(f"{adapter} report eval binding is invalid")
        corpora[adapter] = corpus

    trusted_path = Path(str(state.get("trusted_attestation_path")))
    if state.get("trusted_attestation_sha256") != _file_sha256(trusted_path):
        raise QualificationError("trusted routing attestation digest mismatch")
    attestation = _load_json(trusted_path, "trusted routing attestation")
    _validate_attestation(attestation, attestation, models)
    if (
        attestation.get("public_key_pem") != trust_pins.routing_key.public_key_pem
        or attestation.get("key_id") != trust_pins.routing_key.key_id
    ):
        raise QualificationError(
            "qualification routing attestation differs from independent operator key"
        )
    deployment = trust_pins.deployment_identity
    deployment_fields = {
        "receipt_schema": deployment.receipt_schema,
        "server_build_digest": deployment.server_build_digest,
        "registry_snapshot_digest": deployment.registry_snapshot_digest,
        "registry_revision": deployment.registry_revision,
        "base_model_id": deployment.base_model_id,
        "base_model_revision": deployment.base_model_revision,
        "base_model_digest": deployment.base_model_digest,
    }
    for field, expected_value in deployment_fields.items():
        if attestation.get(field) != expected_value:
            raise QualificationError(
                f"qualification routing deployment {field} differs from external pin"
            )
    public_key = trust_pins.routing_key.public_key
    attestation_report = qualification_report.get("routing_attestation")
    if not isinstance(attestation_report, dict):
        raise QualificationError("qualification report lacks routing attestation")
    if (
        attestation_report.get("trusted_file_sha256")
        != state["trusted_attestation_sha256"]
        or attestation_report.get("key_id") != attestation.get("key_id")
        or attestation_report.get("server_build_digest")
        != attestation.get("server_build_digest")
        or attestation_report.get("registry_snapshot_digest")
        != attestation.get("registry_snapshot_digest")
        or attestation_report.get("base_model_digest")
        != attestation.get("base_model_digest")
    ):
        raise QualificationError("qualification report routing attestation binding is invalid")

    max_tokens = state.get("max_tokens")
    if not isinstance(max_tokens, int) or max_tokens < 64:
        raise QualificationError("qualification state max_tokens is invalid")
    work = _build_work(corpora, models, artifact_digests, max_tokens)
    work_by_key = {item.key: item for item in work}
    if len(work) != EXPECTED_EVAL_ROWS * 4 or len(work_by_key) != len(work):
        raise QualificationError("qualification work is incomplete or duplicated")
    records = _load_checkpoint(
        checkpoint_path,
        work_by_key,
        attestation,
        public_key,
        run_id,
    )
    if set(records) != set(work_by_key):
        raise QualificationError("response receipt ledger has missing or unexpected rows")
    routing_request_ids = [str(record["routing_request_id"]) for record in records.values()]
    if len(set(routing_request_ids)) != len(routing_request_ids):
        raise QualificationError("response receipt ledger reuses routing request ids")
    for adapter in ("gs343", "r2d2"):
        for role in ("candidate", "incumbent"):
            count = sum(
                item.adapter == adapter and item.role == role for item in work
            )
            if count != EXPECTED_EVAL_ROWS:
                raise QualificationError(
                    f"{adapter} {role} does not contain exactly {EXPECTED_EVAL_ROWS} rows"
                )

    recomputed_qualification, recomputed_scores = _score_all(work, records)
    score_rows = _jsonl_objects(score_path, "score ledger")
    if len(score_rows) != EXPECTED_EVAL_ROWS * 4:
        raise QualificationError("score ledger must contain exactly 960 rows")
    score_by_key: dict[str, dict[str, Any]] = {}
    for row in score_rows:
        key = row.get("key")
        if not isinstance(key, str) or key not in work_by_key:
            raise QualificationError("score ledger contains an unknown row key")
        if key in score_by_key:
            raise QualificationError(f"score ledger contains duplicate row {key}")
        if row.get("qualification_run_id") != run_id:
            raise QualificationError("score ledger mixes qualification run ids")
        score_by_key[key] = row
    expected_scores = {row["key"]: row for row in recomputed_scores}
    if score_by_key != expected_scores:
        raise QualificationError("score ledger differs from deterministic recomputation")
    if qualification_report.get("qualification") != recomputed_qualification:
        raise QualificationError("qualification summary differs from deterministic recomputation")
    global_blockers = [
        f"{adapter}:{blocker}"
        for adapter, result in recomputed_qualification.items()
        for blocker in result["blockers"]
    ]
    expected_decision = "PROMOTE" if not global_blockers else "BLOCK"
    if qualification_report.get("blockers") != global_blockers:
        raise QualificationError("qualification report blockers differ from recomputation")
    if qualification_report.get("promotion_decision") != expected_decision:
        raise QualificationError("qualification promotion decision differs from recomputation")

    manifest = _load_json(manifest_path, "qualification evidence manifest")
    if manifest.get("schema") != EVIDENCE_MANIFEST_SCHEMA:
        raise QualificationError("qualification evidence manifest schema is invalid")
    manifest_core = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    if manifest.get("manifest_sha256") != sha256_json(manifest_core):
        raise QualificationError("qualification evidence manifest seal is invalid")
    expected_manifest = _sealed_manifest(
        qualification_run_id=run_id,
        state_path=state_path,
        checkpoint_path=checkpoint_path,
        score_path=score_path,
        corpora=corpora,
        trusted_attestation_path=trusted_path,
    )
    if manifest != expected_manifest:
        raise QualificationError("qualification evidence manifest does not bind current ledgers")
    if manifest_meta.get("manifest_sha256") != manifest["manifest_sha256"]:
        raise QualificationError("qualification report manifest seal mismatch")
    return {
        "qualification_run_id": run_id,
        "qualification": recomputed_qualification,
        "score_rows": recomputed_scores,
        "records": records,
        "manifest_sha256": manifest["manifest_sha256"],
        "external_trust_pins_sha256": trust_pins.digest,
    }


def _run_qualification_locked(
    config: QualificationConfig,
    *,
    transport: Transport | None = None,
) -> dict[str, Any]:
    """Execute or resume while the caller holds the output-directory lock."""
    report_path = config.output_directory / "qualification-report.json"
    checkpoint_path = config.output_directory / "response-receipts.jsonl"
    state_path = config.output_directory / "qualification-state.json"
    score_path = config.output_directory / "score-ledger.jsonl"
    manifest_path = config.output_directory / "qualification-evidence-manifest.json"
    generated_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    report: dict[str, Any] = {
        "schema": QUALIFICATION_SCHEMA,
        "generated_at_utc": generated_at,
        "run_outcome": "INCONCLUSIVE",
        "release_verdict": "NOT_READY",
        "promotion_decision": "BLOCK",
        "p5_status": "NOT_READY",
        "family_server": config.base_url.rstrip("/"),
        "models": config.models.to_dict(),
        "artifact_digests": config.artifact_digests.to_dict(),
        "expected_eval_rows_per_adapter": EXPECTED_EVAL_ROWS,
        "expected_response_receipts": EXPECTED_EVAL_ROWS * 4,
        "training_split_used": False,
        "scoring_contract": _scoring_contract(),
        "run_lock": {
            "path": str(config.output_directory / ".qualification.lock"),
            "exclusive": True,
            "held_for_entire_run": True,
        },
        "thresholds": {
            "pinned_eval_sha256": dict(EXPECTED_EVAL_SHA256),
            "promotion_ratio_over_incumbent": PROMOTION_RATIO,
            "gs343_hard_gates": dict(GS_HARD_GATES),
            "gs343_composite_weights": dict(GS_WEIGHTS),
            "r2d2_hard_gates": dict(R2_HARD_GATES),
            "r2d2_composite_weights": dict(R2_WEIGHTS),
        },
        "blockers": [],
    }
    corpora: dict[str, EvalCorpus] = {}
    work: list[WorkItem] = []
    records: dict[str, dict[str, Any]] = {}
    try:
        corpora = {
            "gs343": _load_eval("gs343", config.gs_eval_path),
            "r2d2": _load_eval("r2d2", config.r2_eval_path),
        }
        report["eval"] = {
            adapter: {
                "path": str(corpus.path),
                "sha256": corpus.sha256,
                "row_count": len(corpus.rows),
                "manifest_path": str(corpus.manifest_path),
                "manifest_sha256": corpus.manifest_sha256,
                "split": "eval",
            }
            for adapter, corpus in sorted(corpora.items())
        }
        trusted = _load_json(config.trusted_attestation_path, "trusted attestation")
        trusted_file_sha256 = _file_sha256(config.trusted_attestation_path)
        active_transport = transport or DirectHttpTransport(config.base_url)
        live_result = active_transport.request(
            "GET", "/v1/routing/attestation", timeout=min(config.timeout_seconds, 30.0)
        )
        if live_result.status != 200:
            raise QualificationError(
                f"routing attestation expected HTTP 200, observed {live_result.status}"
            )
        public_key = _validate_attestation(trusted, live_result.body, config.models)
        report["routing_attestation"] = {
            "trusted_path": str(config.trusted_attestation_path),
            "trusted_file_sha256": trusted_file_sha256,
            "live_attestation_sha256": sha256_json(live_result.body),
            "key_id": live_result.body["key_id"],
            "server_build_digest": live_result.body["server_build_digest"],
            "registry_snapshot_digest": live_result.body["registry_snapshot_digest"],
            "registry_revision": live_result.body["registry_revision"],
            "base_model_digest": live_result.body["base_model_digest"],
            "base_model_revision": live_result.body["base_model_revision"],
            "verified": True,
        }
        state = _checkpoint_state(config, corpora, trusted_file_sha256)
        _prepare_state(state_path, state)
        work = _build_work(
            corpora,
            config.models,
            config.artifact_digests,
            config.max_tokens,
        )
        work_by_key = {item.key: item for item in work}
        if len(work_by_key) != len(work):
            raise QualificationError("qualification work contains duplicate row keys")
        records = _load_checkpoint(
            checkpoint_path,
            work_by_key,
            live_result.body,
            public_key,
            state["qualification_run_id"],
        )
        report["resumed_successful_rows"] = len(records)
        seen_routing_request_ids = {
            str(record["routing_request_id"]) for record in records.values()
        }
        if len(seen_routing_request_ids) != len(records):
            raise QualificationError("checkpoint reuses a routing request_id")
        for item in work:
            if item.key in records:
                continue
            challenge = f"certforge-p5-{uuid.uuid4()}"
            response = active_transport.request(
                "POST",
                "/v1/chat/completions",
                body=item.request,
                headers={CHALLENGE_HEADER: challenge},
                timeout=config.timeout_seconds,
            )
            record = _verify_receipt(
                item,
                response,
                challenge,
                live_result.body,
                public_key,
                state["qualification_run_id"],
            )
            if record["routing_request_id"] in seen_routing_request_ids:
                raise QualificationError(
                    f"{item.key} reuses routing request_id "
                    f"{record['routing_request_id']}"
                )
            _append_jsonl(checkpoint_path, record)
            records[item.key] = record
            seen_routing_request_ids.add(record["routing_request_id"])
        missing = sorted(set(work_by_key) - set(records))
        if missing:
            raise QualificationError(
                f"qualification is missing {len(missing)} response receipts"
            )
        records = _load_checkpoint(
            checkpoint_path,
            work_by_key,
            live_result.body,
            public_key,
            state["qualification_run_id"],
        )
        if set(records) != set(work_by_key):
            raise QualificationError(
                "on-disk checkpoint changed or became incomplete before scoring"
            )
        qualification, score_rows = _score_all(work, records)
        _write_jsonl(score_path, score_rows)
        report["qualification"] = qualification
        report["score_ledger"] = {
            "path": str(score_path),
            "sha256": _file_sha256(score_path),
            "row_count": len(score_rows),
        }
        evidence_manifest = _sealed_manifest(
            qualification_run_id=state["qualification_run_id"],
            state_path=state_path,
            checkpoint_path=checkpoint_path,
            score_path=score_path,
            corpora=corpora,
            trusted_attestation_path=config.trusted_attestation_path,
        )
        _write_json(manifest_path, evidence_manifest)
        report["qualification_run_id"] = state["qualification_run_id"]
        report["evidence_manifest"] = {
            "path": str(manifest_path),
            "sha256": _file_sha256(manifest_path),
            "manifest_sha256": evidence_manifest["manifest_sha256"],
        }
        global_blockers = [
            f"{adapter}:{blocker}"
            for adapter, result in qualification.items()
            for blocker in result["blockers"]
        ]
        report["blockers"] = global_blockers
        report["run_outcome"] = "COMPLETE"
        if not global_blockers:
            report["promotion_decision"] = "PROMOTE"
            report["p5_status"] = "READY_FOR_PROMOTION"
    except Exception as error:  # noqa: BLE001 - report is the fail-closed boundary
        report["blockers"].append(f"{type(error).__name__}: {error}")
    report["response_receipts"] = {
        "path": str(checkpoint_path),
        "sha256": _file_sha256(checkpoint_path) if checkpoint_path.exists() else None,
        "successful_rows": len(records),
        "expected_rows": EXPECTED_EVAL_ROWS * 4,
        "by_adapter_and_role": _receipt_summary(work, records) if work else {},
    }
    report["checkpoint_state"] = {
        "path": str(state_path),
        "sha256": _file_sha256(state_path) if state_path.exists() else None,
    }
    _write_json(report_path, report)
    report["report_path"] = str(report_path)
    report["report_sha256"] = _file_sha256(report_path)
    return report


def run_qualification(
    config: QualificationConfig,
    *,
    transport: Transport | None = None,
) -> dict[str, Any]:
    """Execute or resume with exclusive output custody and fail-closed locking."""
    config.output_directory.mkdir(parents=True, exist_ok=True)
    try:
        with _exclusive_run_lock(config.output_directory):
            return _run_qualification_locked(config, transport=transport)
    except QualificationError as error:
        return {
            "schema": QUALIFICATION_SCHEMA,
            "generated_at_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "run_outcome": "INCONCLUSIVE",
            "release_verdict": "NOT_READY",
            "promotion_decision": "BLOCK",
            "p5_status": "NOT_READY",
            "family_server": config.base_url.rstrip("/"),
            "models": config.models.to_dict(),
            "artifact_digests": config.artifact_digests.to_dict(),
            "training_split_used": False,
            "blockers": [f"{type(error).__name__}: {error}"],
            "run_lock": {
                "path": str(config.output_directory / ".qualification.lock"),
                "exclusive": False,
                "held_for_entire_run": False,
            },
            "report_path": None,
            "report_sha256": None,
        }
