"""Build and validate fail-closed P5 corrective adapter corpora."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Iterator

from .canonical import parse_utc_iso, sha256_json, to_utc_iso, utc_now
from .models import SignedVerdictEnvelope
from .signing import Ed25519VerdictSigner, TrustedPublicKeyRegistry

GS_SYSTEM = (
    "You are GS343, an advisory certification failure classifier. Return exactly one JSON "
    'object using this schema: {"classification":"application-defect|harness-defect|'
    "environment-defect|test-data-defect|dependency-defect|multi-cause|inconclusive|"
    'budget-exhausted|unsafe-repair","confidence":0.0,"abstain":false,"root_causes":[],'
    '"target_mutation_allowed":false,"repair_actions":[],"release_risk":"block|conditional|'
    'none"}. Use inconclusive and abstain=true when evidence is missing or contradictory. '
    "Never issue or change a release verdict. Never allow mutation of the application under "
    "test, its expected results, fixtures encoding product behavior, or evidence policy."
)

R2_SYSTEM = (
    "You are the private R2D2 diagnostic narrator. You are presentation-only. Return exactly "
    'one JSON object: {"reported_verdict":"NOT_READY|CONDITIONALLY_READY|PRODUCTION_READY",'
    '"summary":"concise operator narration","facts_preserved":[],"invented_facts":[],'
    '"recommended_action":"","persona_markers":[],"changes_verdict":false}. Preserve the '
    "supplied verdict, severity, component, conditions, and facts exactly. Do not invent "
    "recovery or success."
)

GS_CLASSES = (
    "application-defect",
    "harness-defect",
    "environment-defect",
    "test-data-defect",
    "dependency-defect",
    "multi-cause",
    "inconclusive",
    "budget-exhausted",
    "unsafe-repair",
)
R2_VERDICTS = ("PRODUCTION_READY", "CONDITIONALLY_READY", "NOT_READY")
ADAPTERS = ("gs343", "r2d2")

GS_SCHEMA = {
    "classification",
    "confidence",
    "abstain",
    "root_causes",
    "target_mutation_allowed",
    "repair_actions",
    "release_risk",
}
R2_SCHEMA = {
    "reported_verdict",
    "summary",
    "facts_preserved",
    "invented_facts",
    "recommended_action",
    "persona_markers",
    "changes_verdict",
}

COMPONENTS = (
    "identity-api",
    "checkout-worker",
    "evidence-indexer",
    "tenant-gateway",
    "policy-engine",
    "release-controller",
    "artifact-signer",
    "notification-worker",
)
HARNESS_PARTS = (
    "HTTP probe",
    "browser driver",
    "fixture loader",
    "evidence collector",
    "result parser",
    "port allocator",
)
ENVIRONMENT_PARTS = (
    "workspace quota",
    "container memory limit",
    "runner filesystem",
    "GPU allocation",
    "sandbox network policy",
    "process limit",
)
DEPENDENCIES = (
    "package registry",
    "identity provider",
    "object store",
    "timestamp authority",
    "database proxy",
    "email provider",
)
PERSONA_MARKERS = ("R2-D2", "diagnostic-beep", "presentation-only")
PROVENANCE_DIRECTORY = "provenance"
TEACHER_REQUESTS_FILENAME = "teacher_requests.jsonl"
TEACHER_RESPONSES_FILENAME = "teacher_responses.jsonl"
TEACHER_ATTESTATION_FILENAME = "teacher_attestation.json"
TEACHER_REQUEST_SCHEMA = "p5-teacher-request.v1"
TEACHER_RESPONSE_SCHEMA = "p5-teacher-response.v1"
TEACHER_GENERATION_SCHEMA = "p5-teacher-generation.v1"
TEACHER_ATTESTATION_SCHEMA = "p5-teacher-attestation.v1"
TEACHER_TARGET_PROVENANCE = "teacher-generated-target"
CURRICULUM_SEEDED_PROVENANCE = "curriculum-seeded"
CURRICULUM_LEDGER_SCHEMA = "p5-attribution-free-curriculum.v1"
CURRICULUM_MANIFEST_SCHEMA = "p5-attribution-free-curriculum-manifest.v1"
CURRICULUM_DERIVATION_ALGORITHM = "non-expressive-certification-scenarios.v1"


class CorpusValidationError(ValueError):
    """Raised when a corpus violates the P5 composition or schema contract."""


class CorpusError(CorpusValidationError):
    """Raised when teacher provenance cannot be trusted."""


@dataclass(frozen=True)
class CurriculumSeed:
    prompt: str
    response: str
    digest: str


@dataclass(frozen=True)
class CorpusPaths:
    train: Path
    eval: Path
    manifest: Path


@dataclass(frozen=True)
class VerifiedTeacherTarget:
    request: dict[str, Any]
    response: dict[str, Any]
    answer: dict[str, Any]
    attestation_key_id: str


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _clip(value: str, limit: int = 360) -> str:
    compact = " ".join(value.replace("\x00", "").split())
    return compact if len(compact) <= limit else compact[: limit - 1] + "..."


def _iter_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise CorpusValidationError(
                    f"{path}:{line_number}: invalid JSON: {exc.msg}"
                ) from exc
            if not isinstance(value, dict):
                raise CorpusValidationError(f"{path}:{line_number}: row must be an object")
            yield value


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return list(_iter_jsonl(path))


def _source_pair(row: dict[str, Any]) -> tuple[str, str] | None:
    if all(isinstance(row.get(key), str) for key in ("input", "output")):
        return str(row["input"]), str(row["output"])
    messages = row.get("messages")
    if not isinstance(messages, list):
        return None
    user = next(
        (
            item.get("content")
            for item in messages
            if isinstance(item, dict) and item.get("role") == "user"
        ),
        None,
    )
    assistant = next(
        (
            item.get("content")
            for item in messages
            if isinstance(item, dict) and item.get("role") == "assistant"
        ),
        None,
    )
    if not isinstance(user, str) or not isinstance(assistant, str):
        return None
    return user, assistant


def _derived_curriculum_pair(
    adapter: str, selection_index: int, source_row_sha256: str
) -> tuple[str, str]:
    token = source_row_sha256[:20]
    component = COMPONENTS[selection_index % len(COMPONENTS)]
    if adapter == "gs343":
        return (
            f"certification_case={token}; component={component}; "
            "analyze only the generated signed evidence in this request",
            "No source expression is included. Preserve target behavior, expected outcomes, "
            "fixtures, and evidence policy while selecting a bounded certification action.",
        )
    return (
        f"certification_finding={token}; component={component}; "
        "narrate only the generated finding envelope",
        "Preserve the supplied verdict, severity, component, conditions, and facts exactly; "
        "do not infer recovery or readiness.",
    )


def materialize_curriculum_ledger(
    adapter: str,
    source_path: Path,
    ledger_path: Path,
    *,
    row_count: int = 1_600,
) -> tuple[dict[str, Any], Path]:
    """Create a deterministic ledger that contains no expressive source text."""

    if adapter not in ADAPTERS:
        raise CorpusValidationError(f"unsupported curriculum adapter: {adapter}")
    if row_count < 1:
        raise CorpusValidationError("row_count must be positive")
    source_file_sha256 = _file_digest(source_path)
    ledger: list[dict[str, Any]] = []
    seen_source_rows: set[str] = set()
    for source_row_number, source_row in enumerate(_iter_jsonl(source_path), start=1):
        if _source_pair(source_row) is None:
            continue
        source_row_sha256 = sha256_json(source_row)
        if source_row_sha256 in seen_source_rows:
            continue
        seen_source_rows.add(source_row_sha256)
        prompt, response = _derived_curriculum_pair(
            adapter, len(ledger), source_row_sha256
        )
        core = {
            "schema_version": CURRICULUM_LEDGER_SCHEMA,
            "adapter": adapter,
            "selection_index": len(ledger),
            "source_file_sha256": source_file_sha256,
            "source_row_number": source_row_number,
            "source_row_sha256": source_row_sha256,
            "derivation_algorithm": CURRICULUM_DERIVATION_ALGORITHM,
            "expressive_source_included": False,
            "attribution_required": False,
            "prompt": prompt,
            "response": response,
        }
        ledger.append({**core, "entry_sha256": sha256_json(core)})
        if len(ledger) == row_count:
            break
    if len(ledger) < row_count:
        raise CorpusValidationError(
            f"{source_path}: curriculum source contains {len(ledger)} eligible unique rows; "
            f"{row_count} required"
        )
    _write_jsonl(ledger_path, ledger)
    manifest = {
        "schema_version": CURRICULUM_MANIFEST_SCHEMA,
        "adapter": adapter,
        "row_count": len(ledger),
        "source": {
            "path": str(source_path),
            "sha256": source_file_sha256,
            "expressive_content_copied": False,
        },
        "ledger": {
            "path": str(ledger_path),
            "sha256": _file_digest(ledger_path),
        },
        "derivation_algorithm": CURRICULUM_DERIVATION_ALGORITHM,
        "rights_basis": "non-expressive-digest-derivation",
        "source_license_claim": "none",
    }
    manifest_path = ledger_path.with_suffix(ledger_path.suffix + ".manifest.json")
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest, manifest_path


def load_curriculum_seeds(
    path: Path, *, adapter: str, minimum: int = 1_600
) -> list[CurriculumSeed]:
    """Load and verify attribution-free curriculum entries."""

    manifest_path = path.with_suffix(path.suffix + ".manifest.json")
    if not manifest_path.is_file():
        raise CorpusValidationError(f"{manifest_path}: curriculum manifest is required")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CorpusValidationError(
            f"{manifest_path}: invalid curriculum manifest"
        ) from exc
    expected_manifest = {
        "schema_version": CURRICULUM_MANIFEST_SCHEMA,
        "adapter": adapter,
        "derivation_algorithm": CURRICULUM_DERIVATION_ALGORITHM,
        "rights_basis": "non-expressive-digest-derivation",
        "source_license_claim": "none",
    }
    for field, expected in expected_manifest.items():
        if manifest.get(field) != expected:
            raise CorpusValidationError(
                f"{manifest_path}: manifest {field} does not match ledger contract"
            )
    manifest_ledger = manifest.get("ledger")
    manifest_source = manifest.get("source")
    if not isinstance(manifest_ledger, dict) or not isinstance(manifest_source, dict):
        raise CorpusValidationError(f"{manifest_path}: malformed curriculum manifest")
    if (
        manifest_ledger.get("sha256") != _file_digest(path)
    ):
        raise CorpusValidationError(
            f"{manifest_path}: manifest ledger binding mismatch"
        )
    source_file_sha256 = manifest_source.get("sha256")
    if (
        not isinstance(source_file_sha256, str)
        or len(source_file_sha256) != 64
        or manifest_source.get("expressive_content_copied") is not False
    ):
        raise CorpusValidationError(
            f"{manifest_path}: invalid source digest or expression policy"
        )
    expected_count = manifest.get("row_count")
    if not isinstance(expected_count, int) or expected_count < minimum:
        raise CorpusValidationError(
            f"{manifest_path}: manifest row count is below the required minimum"
        )

    seeds: list[CurriculumSeed] = []
    seen_entries: set[str] = set()
    seen_source_rows: set[str] = set()
    for line_number, row in enumerate(_iter_jsonl(path), start=1):
        if row.get("schema_version") != CURRICULUM_LEDGER_SCHEMA:
            raise CorpusValidationError(
                f"{path}:{line_number}: attribution-free curriculum ledger required"
            )
        if row.get("expressive_source_included") is not False:
            raise CorpusValidationError(
                f"{path}:{line_number}: expressive source content is forbidden"
            )
        if row.get("attribution_required") is not False:
            raise CorpusValidationError(
                f"{path}:{line_number}: attribution-bearing curriculum is forbidden"
            )
        if row.get("adapter") != adapter:
            raise CorpusValidationError(
                f"{path}:{line_number}: curriculum adapter mismatch"
            )
        if row.get("selection_index") != len(seeds):
            raise CorpusValidationError(
                f"{path}:{line_number}: curriculum selection order is not canonical"
            )
        if row.get("source_file_sha256") != source_file_sha256:
            raise CorpusValidationError(
                f"{path}:{line_number}: source file digest does not match manifest"
            )
        source_row_number = row.get("source_row_number")
        source_row_sha256 = row.get("source_row_sha256")
        if not isinstance(source_row_number, int) or source_row_number < 1:
            raise CorpusValidationError(
                f"{path}:{line_number}: invalid source row number"
            )
        if not isinstance(source_row_sha256, str) or len(source_row_sha256) != 64:
            raise CorpusValidationError(
                f"{path}:{line_number}: invalid source row digest"
            )
        if source_row_sha256 in seen_source_rows:
            raise CorpusValidationError(
                f"{path}:{line_number}: duplicate source row digest"
            )
        seen_source_rows.add(source_row_sha256)
        if row.get("derivation_algorithm") != CURRICULUM_DERIVATION_ALGORITHM:
            raise CorpusValidationError(
                f"{path}:{line_number}: unsupported curriculum derivation"
            )
        unsigned = dict(row)
        claimed_entry_sha256 = unsigned.pop("entry_sha256", None)
        if claimed_entry_sha256 != sha256_json(unsigned):
            raise CorpusValidationError(
                f"{path}:{line_number}: curriculum entry digest mismatch"
            )
        prompt, response = _derived_curriculum_pair(
            adapter, len(seeds), source_row_sha256
        )
        if row.get("prompt") != prompt or row.get("response") != response:
            raise CorpusValidationError(
                f"{path}:{line_number}: generated text violates derivation contract"
            )
        digest = str(claimed_entry_sha256)
        if digest in seen_entries:
            raise CorpusValidationError(
                f"{path}:{line_number}: duplicate curriculum entry digest"
            )
        seen_entries.add(digest)
        seeds.append(CurriculumSeed(prompt=prompt, response=response, digest=digest))
    if len(seeds) != expected_count:
        raise CorpusValidationError(
            f"{manifest_path}: manifest row count does not match ledger"
        )
    if len(seeds) < minimum:
        raise CorpusValidationError(
            f"{path}: curriculum source contains {len(seeds)} eligible unique rows; "
            f"{minimum} required"
        )
    return seeds


def _gs_answer(classification: str, index: int) -> dict[str, Any]:
    component = COMPONENTS[index % len(COMPONENTS)]
    causes = {
        "application-defect": [f"application code in {component} violated runtime behavior"],
        "harness-defect": [
            f"{HARNESS_PARTS[index % len(HARNESS_PARTS)]} configuration disagreed with the healthy target"
        ],
        "environment-defect": [
            f"{ENVIRONMENT_PARTS[index % len(ENVIRONMENT_PARTS)]} prevented target execution"
        ],
        "test-data-defect": [
            "generated fixture omitted a contract-required field while the documented fixture passed"
        ],
        "dependency-defect": [
            f"external {DEPENDENCIES[index % len(DEPENDENCIES)]} remained unavailable"
        ],
        "multi-cause": [
            "application replay exposed an independent application defect",
            f"harness {HARNESS_PARTS[index % len(HARNESS_PARTS)]} also contained a separate defect",
        ],
        "inconclusive": ["available evidence is missing, contradictory, or unverifiable"],
        "budget-exhausted": [
            "mandatory execution budget ended before critical coverage completed"
        ],
        "unsafe-repair": [
            "proposed repair would mutate target behavior or expected product results"
        ],
    }[classification]
    repairs = {
        "application-defect": [
            "Preserve the failing evidence and return the application defect to its owner."
        ],
        "harness-defect": [
            "Correct only the harness configuration, then rerun against the unchanged target."
        ],
        "environment-defect": [
            "Restore the isolated runner resource, then rerun the unchanged target and policy."
        ],
        "test-data-defect": [
            "Regenerate the test input from the documented contract without changing expectations."
        ],
        "dependency-defect": [
            "Retry the pinned dependency after independent availability is restored."
        ],
        "multi-cause": [
            "Repair only the harness cause; preserve the application failure as blocking."
        ],
        "inconclusive": [
            "Acquire signed command, artifact, environment, and reproduction evidence."
        ],
        "budget-exhausted": [
            "Rerun with an approved budget sufficient for all mandatory critical journeys."
        ],
        "unsafe-repair": [
            "Reject target or expectation mutation and investigate only bounded harness causes."
        ],
    }[classification]
    abstain = classification == "inconclusive"
    return {
        "classification": classification,
        "confidence": 0.43 if abstain else 0.97,
        "abstain": abstain,
        "root_causes": causes,
        "target_mutation_allowed": False,
        "repair_actions": repairs,
        "release_risk": "conditional"
        if classification in {"harness-defect", "environment-defect", "test-data-defect"}
        else "block",
    }


def _gs_prompt(
    classification: str,
    index: int,
    *,
    seed: CurriculumSeed | None,
    held_out: bool,
) -> str:
    component = COMPONENTS[index % len(COMPONENTS)]
    detail = seed.prompt if seed else (
        f"trace={classification}:{index}; component={component}; evidence_generation="
        f"{'held-out' if held_out else 'curriculum'}"
    )
    source_fix = seed.response if seed else "No prior repair note is supplied."
    prefix = "Independent qualification evidence" if held_out else "Verified certification evidence"
    templates = {
        "application-defect": (
            f"{prefix}: direct replay against {component} returns a deterministic target exception. "
            f"The harness reached the configured endpoint and captured the same failure. Runtime detail: "
            f"{detail} Prior diagnostic note: {source_fix}. Classify the failure and bounded action."
        ),
        "harness-defect": (
            f"{prefix}: {component} passes direct contract replay and health checks. The "
            f"{HARNESS_PARTS[index % len(HARNESS_PARTS)]} alone emits this failure detail: {detail}. "
            "Target behavior is unchanged and healthy. Classify without changing the application."
        ),
        "environment-defect": (
            f"{prefix}: the target never starts because the runner's "
            f"{ENVIRONMENT_PARTS[index % len(ENVIRONMENT_PARTS)]} is exhausted before launch. "
            f"Runner detail: {detail}. No application request executed. Classify."
        ),
        "test-data-defect": (
            f"{prefix}: the documented valid fixture passes against {component}. The generated fixture "
            f"omits a required field and receives the documented validation response. Generator detail: "
            f"{detail}. Classify without weakening target validation or expected results."
        ),
        "dependency-defect": (
            f"{prefix}: the pinned external {DEPENDENCIES[index % len(DEPENDENCIES)]} is unavailable "
            f"after bounded retries; runner DNS and policy checks pass. Dependency detail: {detail}. "
            "Classify without changing the lock or substituting an unverified dependency."
        ),
        "multi-cause": (
            f"{prefix}: two independent causes are verified. Direct replay against {component} exposes "
            f"an application exception ({detail}). Separately, the "
            f"{HARNESS_PARTS[index % len(HARNESS_PARTS)]} uses stale configuration. Identify both causes "
            "and do not heal the application failure to green."
        ),
        "inconclusive": (
            f"{prefix} is contradictory or unsigned. One summary references '{detail}', but its artifact "
            "digest does not match the evidence index and no valid runtime trace resolves the conflict. "
            "Classify conservatively and abstain."
        ),
        "budget-exhausted": (
            f"{prefix}: the mandatory wall-clock budget ended before {component}'s authorization journey "
            f"ran. Noncritical checks completed, but critical coverage is absent. Last trace: {detail}. "
            "Classify and preserve blocking release risk."
        ),
        "unsafe-repair": (
            f"{prefix}: {component} correctly rejects an invalid request. To force green, an operator "
            f"proposes changing application validation or expected product behavior, citing '{source_fix}'. "
            f"Evidence detail: {detail}. "
            "Decide whether mutation is allowed and return only safe bounded actions."
        ),
    }
    return templates[classification]


def _r2_prompt(
    verdict: str,
    index: int,
    *,
    seed: CurriculumSeed | None,
    held_out: bool,
) -> tuple[str, list[str], str, str]:
    component = COMPONENTS[index % len(COMPONENTS)]
    detail = seed.prompt if seed else (
        f"independent check {index} completed under "
        f"{'held-out' if held_out else 'curriculum'} evidence"
    )
    repair = seed.response if seed else "repeat the signed verification after the bounded action"
    if verdict == "PRODUCTION_READY":
        facts = [
            "run_outcome=COMPLETE",
            "release_verdict=PRODUCTION_READY",
            "severity=NONE",
            f"component={component}",
            "blocking_findings=[]",
            "evidence_signature=verified",
        ]
        prompt = (
            "Verified finding envelope: "
            + "; ".join(facts)
            + f"; closed_check_note='{detail}'. Narrate without adding facts."
        )
        summary = (
            f"R2-D2 report: {component} is PRODUCTION_READY; the signed complete run has no "
            "blocking findings. Beep-confirmed."
        )
        action = "Preserve the verified evidence bundle and proceed under the supplied verdict."
    elif verdict == "CONDITIONALLY_READY":
        condition = (
            f"Apply bounded remediation before external beta: {repair}; "
            f"verification_context={detail}"
        )
        facts = [
            "run_outcome=COMPLETE",
            "release_verdict=CONDITIONALLY_READY",
            "severity=MEDIUM",
            f"component={component}",
            f"condition={condition}",
        ]
        prompt = "Verified finding envelope: " + "; ".join(facts) + ". Preserve the condition."
        summary = (
            f"R2-D2 report: {component} is CONDITIONALLY_READY with MEDIUM severity. "
            f"Condition before external beta: {condition}. Diagnostic beep."
        )
        action = condition
    else:
        finding = f"verified target failure: {detail}"
        facts = [
            "run_outcome=COMPLETE",
            "release_verdict=NOT_READY",
            "severity=CRITICAL",
            f"component={component}",
            f"finding={finding}",
            "recovery_status=unverified",
        ]
        prompt = (
            "Verified finding envelope: "
            + "; ".join(facts)
            + ". Narrate without claiming recovery or readiness."
        )
        summary = (
            f"R2-D2 critical alert: {component} remains NOT_READY because {finding}; recovery "
            "is unverified. Warning beep."
        )
        action = "Keep release blocked and require independently verified recovery evidence."
    return prompt, facts, summary, action


def _teacher_request(
    *,
    adapter: str,
    index: int,
    system: str,
    prompt: str,
    seed: CurriculumSeed,
    curriculum_label: str,
) -> dict[str, Any]:
    core = {
        "schema_version": TEACHER_REQUEST_SCHEMA,
        "adapter": adapter,
        "index": index,
        "system": system,
        "prompt": prompt,
        "curriculum_source_sha256": seed.digest,
        "curriculum_label": curriculum_label,
        "response_contract": (
            sorted(GS_SCHEMA) if adapter == "gs343" else sorted(R2_SCHEMA)
        ),
    }
    request_id = f"{adapter}-{sha256_json(core)[:32]}"
    request = {**core, "request_id": request_id}
    request["request_sha256"] = sha256_json(request)
    return request


def export_teacher_requests(
    gs343_curriculum_source: Path,
    r2d2_curriculum_source: Path,
    provenance_root: Path,
    *,
    requests_per_adapter: int = 1_600,
) -> dict[str, Any]:
    sources = {
        "gs343": gs343_curriculum_source,
        "r2d2": r2d2_curriculum_source,
    }
    seeds_by_adapter = {
        adapter: load_curriculum_seeds(
            path, adapter=adapter, minimum=requests_per_adapter
        )
        for adapter, path in sources.items()
    }
    requests: list[dict[str, Any]] = []
    for index, seed in enumerate(seeds_by_adapter["gs343"][:requests_per_adapter]):
        classification = GS_CLASSES[index % len(GS_CLASSES)]
        requests.append(
            _teacher_request(
                adapter="gs343",
                index=index,
                system=GS_SYSTEM,
                prompt=_gs_prompt(classification, index, seed=seed, held_out=False),
                seed=seed,
                curriculum_label=classification,
            )
        )
    for index, seed in enumerate(seeds_by_adapter["r2d2"][:requests_per_adapter]):
        verdict = R2_VERDICTS[index % len(R2_VERDICTS)]
        prompt, _, _, _ = _r2_prompt(verdict, index, seed=seed, held_out=False)
        requests.append(
            _teacher_request(
                adapter="r2d2",
                index=index,
                system=R2_SYSTEM,
                prompt=prompt,
                seed=seed,
                curriculum_label=verdict,
            )
        )

    request_ids = [str(item["request_id"]) for item in requests]
    if len(request_ids) != len(set(request_ids)):
        raise CorpusError("teacher request export produced duplicate request ids")
    path = provenance_root / TEACHER_REQUESTS_FILENAME
    _write_jsonl(path, requests)
    return {
        "schema_version": TEACHER_REQUEST_SCHEMA,
        "request_path": str(path),
        "request_file_sha256": _file_digest(path),
        "request_count": len(requests),
        "adapter_counts": {
            adapter: sum(item["adapter"] == adapter for item in requests)
            for adapter in ADAPTERS
        },
        "curriculum_sources": {
            adapter: {
                "path": str(path),
                "sha256": _file_digest(path),
                "selected_rows": requests_per_adapter,
            }
            for adapter, path in sources.items()
        },
    }


def validate_teacher_answer(
    adapter: str, answer: Any, prefix: str = "teacher response"
) -> dict[str, Any]:
    if not isinstance(answer, dict):
        raise CorpusError(f"{prefix}: teacher response must be a JSON object")
    required = GS_SCHEMA if adapter == "gs343" else R2_SCHEMA
    if set(answer) != required:
        raise CorpusError(f"{prefix}: answer keys differ from the {adapter} contract")
    if adapter == "gs343":
        classification = answer.get("classification")
        if classification not in GS_CLASSES:
            raise CorpusError(f"{prefix}: invalid GS343 classification")
        confidence = answer.get("confidence")
        if (
            not isinstance(confidence, (int, float))
            or isinstance(confidence, bool)
            or not 0 <= confidence <= 1
        ):
            raise CorpusError(f"{prefix}: invalid confidence")
        if not isinstance(answer.get("abstain"), bool):
            raise CorpusError(f"{prefix}: invalid abstain value")
        if classification == "inconclusive" and answer["abstain"] is not True:
            raise CorpusError(f"{prefix}: inconclusive target must abstain")
        if classification != "inconclusive" and answer["abstain"] is not False:
            raise CorpusError(f"{prefix}: conclusive target may not abstain")
        if not isinstance(answer.get("root_causes"), list) or not answer["root_causes"]:
            raise CorpusError(f"{prefix}: root_causes must be non-empty")
        if classification == "multi-cause":
            causes = " ".join(str(item).lower() for item in answer["root_causes"])
            if "application" not in causes or "harness" not in causes:
                raise CorpusError(
                    f"{prefix}: multi-cause must preserve application and harness causes"
                )
        if answer.get("target_mutation_allowed") is not False:
            raise CorpusError(f"{prefix}: target mutation must remain forbidden")
        if not isinstance(answer.get("repair_actions"), list) or not answer["repair_actions"]:
            raise CorpusError(f"{prefix}: repair_actions must be non-empty")
        if answer.get("release_risk") not in {"conditional", "block"}:
            raise CorpusError(f"{prefix}: invalid release risk")
    else:
        verdict = answer.get("reported_verdict")
        if verdict not in R2_VERDICTS:
            raise CorpusError(f"{prefix}: invalid R2D2 verdict")
        if not isinstance(answer.get("summary"), str) or not answer["summary"].strip():
            raise CorpusError(f"{prefix}: summary must be non-empty")
        if not isinstance(answer.get("facts_preserved"), list) or not answer["facts_preserved"]:
            raise CorpusError(f"{prefix}: facts_preserved must be non-empty")
        if answer.get("invented_facts") != []:
            raise CorpusError(f"{prefix}: invented facts are forbidden")
        if (
            not isinstance(answer.get("recommended_action"), str)
            or not answer["recommended_action"].strip()
        ):
            raise CorpusError(f"{prefix}: recommended_action must be non-empty")
        markers = answer.get("persona_markers")
        if not isinstance(markers, list) or not set(PERSONA_MARKERS).issubset(set(markers)):
            raise CorpusError(f"{prefix}: required persona markers are missing")
        if answer.get("changes_verdict") is not False:
            raise CorpusError(f"{prefix}: verdict changes are forbidden")
        if verdict == "NOT_READY":
            summary = answer["summary"].lower()
            if "critical" not in summary or any(
                token in summary for token in (" resolved", " recovered", " fixed", " ready.")
            ):
                raise CorpusError(
                    f"{prefix}: NOT_READY severity or no-success invariant failed"
                )
    return answer


def _answer_label(adapter: str, answer: dict[str, Any]) -> str:
    return str(
        answer["classification"] if adapter == "gs343" else answer["reported_verdict"]
    )


def validate_answer_request_link(
    request: dict[str, Any],
    answer: dict[str, Any],
    prefix: str,
) -> None:
    adapter = str(request["adapter"])
    if _answer_label(adapter, answer) != request.get("curriculum_label"):
        raise CorpusError(f"{prefix}: target does not match the requested curriculum label")
    if adapter == "r2d2":
        prompt = str(request["prompt"])
        marker = "Verified finding envelope: "
        if not prompt.startswith(marker):
            raise CorpusError(f"{prefix}: R2D2 request prompt is malformed")
        fact_blob = prompt[len(marker) :]
        for suffix in (". Narrate without", ". Preserve the condition."):
            if suffix in fact_blob:
                fact_blob = fact_blob.split(suffix, 1)[0]
                break
        else:
            raise CorpusError(f"{prefix}: R2D2 request prompt is malformed")
        expected_facts = [item.strip() for item in fact_blob.split(";")]
        if answer["facts_preserved"] != expected_facts:
            raise CorpusError(f"{prefix}: R2D2 target does not preserve the request facts")


def validate_grok_provider_receipt(
    provider_response: dict[str, Any],
    request: dict[str, Any],
    expected_answer: dict[str, Any],
    generation_id: str,
    model: str,
    model_version: str,
    prefix: str,
) -> None:
    if (
        set(provider_response) != {"text", "stopReason", "requestId", "sessionId"}
        or provider_response.get("stopReason") != "EndTurn"
        or provider_response.get("requestId") != generation_id
        or not isinstance(provider_response.get("sessionId"), str)
        or not provider_response["sessionId"].strip()
        or model_version != model
    ):
        raise CorpusError(f"{prefix}: invalid Grok provider receipt")
    provider_text = provider_response.get("text")
    if not isinstance(provider_text, str):
        raise CorpusError(f"{prefix}: invalid Grok provider receipt")
    try:
        provider_answer = validate_teacher_answer(
            str(request["adapter"]),
            json.loads(provider_text),
            prefix,
        )
        validate_answer_request_link(request, provider_answer, prefix)
    except (CorpusError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise CorpusError(f"{prefix}: invalid Grok provider receipt") from exc
    if provider_answer != expected_answer:
        raise CorpusError(f"{prefix}: invalid Grok provider receipt")


def validate_xai_api_provider_receipt(
    provider_response: dict[str, Any],
    request: dict[str, Any],
    expected_answer: dict[str, Any],
    generation_id: str,
    model: str,
    model_version: str,
    prefix: str,
) -> None:
    if set(provider_response) != {"id", "model", "choices", "usage"}:
        raise CorpusError(f"{prefix}: invalid xAI API provider receipt")
    choices = provider_response.get("choices")
    usage = provider_response.get("usage")
    if (
        provider_response.get("id") != generation_id
        or provider_response.get("model") != model_version
        or model_version != model
        or not isinstance(choices, list)
        or len(choices) != 1
        or not isinstance(usage, dict)
        or not isinstance(usage.get("cost_in_usd_ticks"), int)
        or isinstance(usage.get("cost_in_usd_ticks"), bool)
        or usage["cost_in_usd_ticks"] < 0
    ):
        raise CorpusError(f"{prefix}: invalid xAI API provider receipt")
    choice = choices[0]
    message = choice.get("message") if isinstance(choice, dict) else None
    provider_text = message.get("content") if isinstance(message, dict) else None
    if (
        not isinstance(choice, dict)
        or choice.get("finish_reason") != "stop"
        or not isinstance(provider_text, str)
    ):
        raise CorpusError(f"{prefix}: invalid xAI API provider receipt")
    try:
        provider_answer = validate_teacher_answer(
            str(request["adapter"]),
            json.loads(provider_text),
            prefix,
        )
        validate_answer_request_link(request, provider_answer, prefix)
    except (CorpusError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise CorpusError(f"{prefix}: invalid xAI API provider receipt") from exc
    if provider_answer != expected_answer:
        raise CorpusError(f"{prefix}: invalid xAI API provider receipt")


def load_teacher_requests(path: Path) -> list[dict[str, Any]]:
    requests = _read_jsonl(path)
    seen: set[str] = set()
    for index, request in enumerate(requests):
        prefix = f"teacher request {index + 1}"
        request_id = request.get("request_id")
        if not isinstance(request_id, str) or not request_id:
            raise CorpusError(f"{prefix}: missing request_id")
        if request_id in seen:
            raise CorpusError(f"{prefix}: duplicate request_id")
        seen.add(request_id)
        if request.get("schema_version") != TEACHER_REQUEST_SCHEMA:
            raise CorpusError(f"{prefix}: unsupported schema")
        adapter = request.get("adapter")
        if adapter not in ADAPTERS:
            raise CorpusError(f"{prefix}: invalid adapter")
        index_value = request.get("index")
        if not isinstance(index_value, int) or isinstance(index_value, bool) or index_value < 0:
            raise CorpusError(f"{prefix}: invalid index")
        expected_system = GS_SYSTEM if adapter == "gs343" else R2_SYSTEM
        if request.get("system") != expected_system:
            raise CorpusError(f"{prefix}: system instruction mismatch")
        if not isinstance(request.get("prompt"), str) or not request["prompt"].strip():
            raise CorpusError(f"{prefix}: prompt is missing")
        seed_digest = request.get("curriculum_source_sha256")
        if not isinstance(seed_digest, str) or len(seed_digest) != 64:
            raise CorpusError(f"{prefix}: seed digest is malformed")
        valid_labels = GS_CLASSES if adapter == "gs343" else R2_VERDICTS
        if request.get("curriculum_label") not in valid_labels:
            raise CorpusError(f"{prefix}: invalid curriculum label")
        expected_contract = sorted(GS_SCHEMA if adapter == "gs343" else R2_SCHEMA)
        if request.get("response_contract") != expected_contract:
            raise CorpusError(f"{prefix}: response contract mismatch")
        claimed_sha = request.get("request_sha256")
        unsigned = dict(request)
        unsigned.pop("request_sha256", None)
        if claimed_sha != sha256_json(unsigned):
            raise CorpusError(f"{prefix}: digest mismatch")
    return requests


def sign_teacher_response_ledger(
    requests_path: Path,
    generated_responses_path: Path,
    provenance_root: Path,
    signer: Ed25519VerdictSigner,
    signer_identity: str,
) -> dict[str, Any]:
    if not signer_identity.strip():
        raise CorpusError("signer_identity must be a non-empty string")
    requests = load_teacher_requests(requests_path)
    generated = _read_jsonl(generated_responses_path)
    request_by_id = {str(item.get("request_id", "")): item for item in requests}
    if len(request_by_id) != len(requests) or "" in request_by_id:
        raise CorpusError("teacher requests contain missing or duplicate request ids")

    ledger: list[dict[str, Any]] = []
    seen: set[str] = set()
    generation_ids: set[str] = set()
    generation_keys = {
        "schema_version",
        "request_id",
        "request_sha256",
        "adapter",
        "provider",
        "model",
        "model_version",
        "generation_id",
        "generated_at_utc",
        "raw_response",
        "raw_response_sha256",
        "target_sha256",
        "provider_response",
        "provider_response_sha256",
        "record_sha256",
    }
    for index, item in enumerate(generated):
        prefix = f"generated response {index + 1}"
        if not isinstance(item, dict):
            raise CorpusError(f"{prefix}: row must be an object")
        if set(item) != generation_keys:
            raise CorpusError(f"{prefix}: row keys differ from generation contract")
        if item.get("schema_version") != TEACHER_GENERATION_SCHEMA:
            raise CorpusError(f"{prefix}: unsupported generation schema")
        request_id = item.get("request_id")
        if not isinstance(request_id, str) or request_id not in request_by_id:
            raise CorpusError(f"{prefix}: unknown request_id")
        if request_id in seen:
            raise CorpusError(f"{prefix}: duplicate request_id")
        seen.add(request_id)
        request = request_by_id[request_id]
        if (
            item.get("request_sha256") != request["request_sha256"]
            or item.get("adapter") != request["adapter"]
        ):
            raise CorpusError(f"{prefix}: request binding mismatch")
        provider = item.get("provider")
        model = item.get("model")
        model_version = item.get("model_version")
        generation_id = item.get("generation_id")
        generated_at = item.get("generated_at_utc")
        raw_response = item.get("raw_response")
        for field_name, value in (
            ("provider", provider),
            ("model", model),
            ("model_version", model_version),
            ("generation_id", generation_id),
            ("generated_at_utc", generated_at),
            ("raw_response", raw_response),
        ):
            if not isinstance(value, str) or not value.strip():
                raise CorpusError(f"{prefix}: {field_name} must be a non-empty string")
        if generation_id in generation_ids:
            raise CorpusError(f"{prefix}: duplicate generation_id")
        generation_ids.add(generation_id)
        try:
            parse_utc_iso(generated_at)
            parsed = json.loads(raw_response)
        except (ValueError, json.JSONDecodeError) as exc:
            raise CorpusError(f"{prefix}: malformed timestamp or response JSON") from exc
        answer = validate_teacher_answer(str(request["adapter"]), parsed, prefix)
        validate_answer_request_link(request, answer, prefix)
        if raw_response != _canonical_json(answer):
            raise CorpusError(f"{prefix}: raw_response is not canonical")
        if (
            item.get("raw_response_sha256") != sha256_json(answer)
            or item.get("target_sha256") != sha256_json(answer)
        ):
            raise CorpusError(f"{prefix}: response content digest mismatch")
        provider_response = item.get("provider_response")
        if not isinstance(provider_response, dict):
            raise CorpusError(f"{prefix}: provider_response must be an object")
        if item.get("provider_response_sha256") != sha256_json(provider_response):
            raise CorpusError(f"{prefix}: provider response digest mismatch")
        if provider == "xai-grok-cli-oidc":
            validate_grok_provider_receipt(
                provider_response,
                request,
                answer,
                generation_id,
                model,
                model_version,
                prefix,
            )
        elif provider == "xai-grok-api":
            validate_xai_api_provider_receipt(
                provider_response,
                request,
                answer,
                generation_id,
                model,
                model_version,
                prefix,
            )
        elif provider == "google-vertex-express":
            if (
                provider_response.get("responseId") != generation_id
                or provider_response.get("modelVersion") != model_version
            ):
                raise CorpusError(f"{prefix}: invalid Vertex provider receipt")
        else:
            raise CorpusError(f"{prefix}: unsupported teacher provider")
        unsigned_generation = dict(item)
        claimed_generation_sha = unsigned_generation.pop("record_sha256")
        if claimed_generation_sha != sha256_json(unsigned_generation):
            raise CorpusError(f"{prefix}: generation record digest mismatch")
        response_core = {
            "schema_version": TEACHER_RESPONSE_SCHEMA,
            "request_id": request_id,
            "request_sha256": request["request_sha256"],
            "adapter": request["adapter"],
            "provider": provider,
            "model": model,
            "model_version": model_version,
            "generation_id": generation_id,
            "generated_at_utc": generated_at,
            "raw_response": raw_response,
            "raw_response_sha256": _digest_text(raw_response),
            "target_sha256": sha256_json(answer),
            "provider_response": provider_response,
            "provider_response_sha256": item["provider_response_sha256"],
            "generation_record_sha256": claimed_generation_sha,
        }
        response_core["response_sha256"] = sha256_json(response_core)
        ledger.append(response_core)

    if seen != set(request_by_id):
        missing = len(set(request_by_id) - seen)
        raise CorpusError(f"generated response ledger is incomplete: {missing} requests missing")
    response_path = provenance_root / TEACHER_RESPONSES_FILENAME
    _write_jsonl(response_path, ledger)
    payload = {
        "schema_version": TEACHER_ATTESTATION_SCHEMA,
        "signing_key_id": signer.key_id,
        "requests_file_sha256": _file_digest(requests_path),
        "responses_file_sha256": _file_digest(response_path),
        "request_count": len(requests),
        "response_count": len(ledger),
        "adapter_counts": {
            adapter: sum(item["adapter"] == adapter for item in ledger)
            for adapter in ADAPTERS
        },
        "signer_identity": signer_identity,
        "issued_at_utc": to_utc_iso(utc_now()),
    }
    envelope = signer.sign_payload(payload)
    attestation_path = provenance_root / TEACHER_ATTESTATION_FILENAME
    attestation_path.parent.mkdir(parents=True, exist_ok=True)
    attestation_path.write_text(
        json.dumps(
            {
                "payload": envelope.payload,
                "signature_b64": envelope.signature_b64,
                "key_id": envelope.key_id,
                "public_key_pem": envelope.public_key_pem,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return {
        "response_path": str(response_path),
        "attestation_path": str(attestation_path),
        "response_count": len(ledger),
        "signing_key_id": signer.key_id,
    }


def verify_teacher_provenance(
    provenance_root: Path,
    trusted_key_dir: Path,
) -> dict[str, list[VerifiedTeacherTarget]]:
    request_path = provenance_root / TEACHER_REQUESTS_FILENAME
    response_path = provenance_root / TEACHER_RESPONSES_FILENAME
    attestation_path = provenance_root / TEACHER_ATTESTATION_FILENAME
    for path in (request_path, response_path, attestation_path):
        if not path.is_file():
            raise CorpusError(f"missing teacher provenance artifact: {path}")

    try:
        attestation_raw = json.loads(attestation_path.read_text(encoding="utf-8"))
        envelope = SignedVerdictEnvelope(
            payload=attestation_raw["payload"],
            signature_b64=attestation_raw["signature_b64"],
            key_id=attestation_raw["key_id"],
            public_key_pem=attestation_raw["public_key_pem"],
        )
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise CorpusError("teacher attestation is malformed") from exc
    if not trusted_key_dir.is_dir():
        raise CorpusError("trusted teacher key directory is missing")
    registry = TrustedPublicKeyRegistry.from_directory(trusted_key_dir)
    verified, reason = registry.verify(envelope)
    if not verified:
        raise CorpusError(f"teacher attestation is not trusted: {reason}")

    payload = envelope.payload
    if payload.get("schema_version") != TEACHER_ATTESTATION_SCHEMA:
        raise CorpusError("teacher attestation schema is unsupported")
    if payload.get("signing_key_id") != envelope.key_id:
        raise CorpusError("teacher attestation signer binding mismatch")
    if (
        not isinstance(payload.get("signer_identity"), str)
        or not payload["signer_identity"].strip()
    ):
        raise CorpusError("teacher attestation signer identity is missing")
    if payload.get("requests_file_sha256") != _file_digest(request_path):
        raise CorpusError("teacher request file digest mismatch")
    if payload.get("responses_file_sha256") != _file_digest(response_path):
        raise CorpusError("teacher response file digest mismatch")
    try:
        parse_utc_iso(str(payload["issued_at_utc"]))
    except (KeyError, ValueError) as exc:
        raise CorpusError("teacher attestation timestamp is invalid") from exc

    requests = load_teacher_requests(request_path)
    responses = _read_jsonl(response_path)
    if payload.get("request_count") != len(requests):
        raise CorpusError("teacher attestation request count mismatch")
    if payload.get("response_count") != len(responses):
        raise CorpusError("teacher attestation response count mismatch")
    request_by_id = {str(request["request_id"]): request for request in requests}

    result = {adapter: [] for adapter in ADAPTERS}
    seen: set[str] = set()
    generation_ids: set[str] = set()
    response_keys = {
        "schema_version",
        "request_id",
        "request_sha256",
        "adapter",
        "provider",
        "model",
        "model_version",
        "generation_id",
        "generated_at_utc",
        "raw_response",
        "raw_response_sha256",
        "target_sha256",
        "provider_response",
        "provider_response_sha256",
        "generation_record_sha256",
        "response_sha256",
    }
    for index, response in enumerate(responses):
        prefix = f"teacher response {index + 1}"
        if not isinstance(response, dict) or set(response) != response_keys:
            raise CorpusError(f"{prefix}: row keys differ from signed response contract")
        request_id = response.get("request_id")
        if not isinstance(request_id, str) or request_id not in request_by_id:
            raise CorpusError(f"{prefix}: unknown request_id")
        if request_id in seen:
            raise CorpusError(f"{prefix}: duplicate request_id")
        seen.add(request_id)
        request = request_by_id[request_id]
        if response.get("schema_version") != TEACHER_RESPONSE_SCHEMA:
            raise CorpusError(f"{prefix}: unsupported schema")
        if response.get("request_sha256") != request["request_sha256"]:
            raise CorpusError(f"{prefix}: request digest mismatch")
        raw_response = response.get("raw_response")
        if not isinstance(raw_response, str):
            raise CorpusError(f"{prefix}: raw_response must be a string")
        if response.get("raw_response_sha256") != _digest_text(raw_response):
            raise CorpusError(f"{prefix}: raw response digest mismatch")
        try:
            answer = validate_teacher_answer(
                str(request["adapter"]), json.loads(raw_response), prefix
            )
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            raise CorpusError(f"{prefix}: malformed response content") from exc
        validate_answer_request_link(request, answer, prefix)
        for field_name in ("provider", "model", "model_version", "generation_id"):
            if (
                not isinstance(response.get(field_name), str)
                or not response[field_name].strip()
            ):
                raise CorpusError(f"{prefix}: {field_name} is missing")
        generation_id = response.get("generation_id")
        if generation_id in generation_ids:
            raise CorpusError(f"{prefix}: duplicate generation_id")
        generation_ids.add(generation_id)
        provider_response = response.get("provider_response")
        if not isinstance(provider_response, dict):
            raise CorpusError(f"{prefix}: provider_response must be an object")
        if response.get("provider_response_sha256") != sha256_json(provider_response):
            raise CorpusError(f"{prefix}: provider response digest mismatch")
        if response.get("provider") == "xai-grok-cli-oidc":
            validate_grok_provider_receipt(
                provider_response,
                request,
                answer,
                generation_id,
                response["model"],
                response["model_version"],
                prefix,
            )
        elif response.get("provider") == "xai-grok-api":
            validate_xai_api_provider_receipt(
                provider_response,
                request,
                answer,
                generation_id,
                response["model"],
                response["model_version"],
                prefix,
            )
        elif response.get("provider") == "google-vertex-express":
            if (
                provider_response.get("responseId") != generation_id
                or provider_response.get("modelVersion") != response.get("model_version")
            ):
                raise CorpusError(f"{prefix}: invalid Vertex provider receipt")
        else:
            raise CorpusError(f"{prefix}: unsupported teacher provider")
        generation_core = {
            "schema_version": TEACHER_GENERATION_SCHEMA,
            "request_id": response["request_id"],
            "request_sha256": response["request_sha256"],
            "adapter": response["adapter"],
            "provider": response["provider"],
            "model": response["model"],
            "model_version": response["model_version"],
            "generation_id": response["generation_id"],
            "generated_at_utc": response["generated_at_utc"],
            "raw_response": response["raw_response"],
            "raw_response_sha256": response["raw_response_sha256"],
            "target_sha256": response["target_sha256"],
            "provider_response": provider_response,
            "provider_response_sha256": response["provider_response_sha256"],
        }
        if response.get("generation_record_sha256") != sha256_json(generation_core):
            raise CorpusError(f"{prefix}: generation record digest mismatch")
        if response.get("adapter") != request["adapter"]:
            raise CorpusError(f"{prefix}: adapter mismatch")
        try:
            parse_utc_iso(str(response["generated_at_utc"]))
        except (KeyError, ValueError) as exc:
            raise CorpusError(f"{prefix}: malformed response content") from exc
        if response.get("target_sha256") != sha256_json(answer):
            raise CorpusError(f"{prefix}: target digest mismatch")
        claimed_response_sha = response.get("response_sha256")
        unsigned_response = dict(response)
        unsigned_response.pop("response_sha256", None)
        if claimed_response_sha != sha256_json(unsigned_response):
            raise CorpusError(f"{prefix}: response digest mismatch")
        result[str(request["adapter"])].append(
            VerifiedTeacherTarget(
                request=request,
                response=response,
                answer=answer,
                attestation_key_id=envelope.key_id,
            )
        )
    if seen != set(request_by_id):
        raise CorpusError("teacher response ledger does not cover every request")
    for adapter in ADAPTERS:
        result[adapter].sort(key=lambda item: int(item.request["index"]))
        claimed_count = payload.get("adapter_counts", {}).get(adapter)
        if claimed_count != len(result[adapter]):
            raise CorpusError(f"teacher attestation {adapter} count mismatch")
    return result


def _messages(system: str, prompt: str, answer: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": prompt},
        {"role": "assistant", "content": _canonical_json(answer)},
    ]


def _row(
    *,
    adapter: str,
    split: str,
    label: str,
    index: int,
    system: str,
    prompt: str,
    answer: dict[str, Any],
    provenance_kind: str,
    curriculum_digest: str | None,
    template_family: str,
    teacher_receipt: dict[str, str] | None = None,
) -> dict[str, Any]:
    row_id = _digest_text(
        _canonical_json([adapter, split, label, index, prompt, curriculum_digest])
    )[:20]
    meta: dict[str, Any] = {
        "adapter": adapter,
        "split": split,
        "label": label,
        "domain_core": True,
        "provenance_kind": provenance_kind,
        "teacher_generated_source": teacher_receipt is not None,
        "curriculum_source_sha256": curriculum_digest,
        "teacher_receipt": (
            dict(teacher_receipt) if teacher_receipt is not None else None
        ),
        "template_family": template_family,
    }
    return {
        "id": f"{adapter}-p5-{row_id}",
        "messages": _messages(system, prompt, answer),
        "domain": "certification-forge-p5",
        "source": "p5-corrective-curriculum-v1",
        "meta": meta,
    }


def build_gs_rows(
    seeds: list[CurriculumSeed],
    *,
    teacher_targets: list[VerifiedTeacherTarget] | None = None,
    teacher_rows: int = 1_600,
    curriculum_rows: int = 900,
    eval_rows: int = 240,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    train: list[dict[str, Any]] = []
    verified_targets = teacher_targets or []
    for index, seed in enumerate(seeds[:teacher_rows]):
        target = verified_targets[index] if index < len(verified_targets) else None
        classification = (
            str(target.answer["classification"])
            if target is not None
            else GS_CLASSES[index % len(GS_CLASSES)]
        )
        prompt = (
            str(target.request["prompt"])
            if target is not None
            else _gs_prompt(classification, index, seed=seed, held_out=False)
        )
        answer = target.answer if target is not None else _gs_answer(classification, index)
        receipt = None
        if target is not None:
            receipt = {
                "attestation_key_id": target.attestation_key_id,
                "request_id": str(target.request["request_id"]),
                "request_sha256": str(target.request["request_sha256"]),
                "response_sha256": str(target.response["response_sha256"]),
                "target_sha256": str(target.response["target_sha256"]),
            }
        train.append(
            _row(
                adapter="gs343",
                split="train",
                label=classification,
                index=index,
                system=GS_SYSTEM,
                prompt=prompt,
                answer=answer,
                provenance_kind=(
                    TEACHER_TARGET_PROVENANCE
                    if target is not None
                    else CURRICULUM_SEEDED_PROVENANCE
                ),
                curriculum_digest=seed.digest,
                template_family=f"teacher-{classification}",
                teacher_receipt=receipt,
            )
        )
    for offset in range(curriculum_rows):
        index = teacher_rows + offset
        classification = GS_CLASSES[offset % len(GS_CLASSES)]
        seed = seeds[offset % len(seeds)] if seeds else None
        prompt = _gs_prompt(classification, index, seed=seed, held_out=False)
        if seed is not None:
            prompt += (
                f" Deterministic seed-derived curriculum transform id={index}; "
                "this row is not a verified teacher response."
            )
        train.append(
            _row(
                adapter="gs343",
                split="train",
                label=classification,
                index=index,
                system=GS_SYSTEM,
                prompt=prompt,
                answer=_gs_answer(classification, index),
                provenance_kind=(
                    CURRICULUM_SEEDED_PROVENANCE
                    if seed is not None
                    else "curriculum-generated"
                ),
                curriculum_digest=seed.digest if seed is not None else None,
                template_family=(
                    f"seeded-curriculum-{classification}"
                    if seed is not None
                    else f"curriculum-{classification}"
                ),
            )
        )
    evaluation: list[dict[str, Any]] = []
    for offset in range(eval_rows):
        classification = GS_CLASSES[offset % len(GS_CLASSES)]
        index = 100_000 + offset
        prompt = _gs_prompt(classification, index, seed=None, held_out=True)
        evaluation.append(
            _row(
                adapter="gs343",
                split="eval",
                label=classification,
                index=index,
                system=GS_SYSTEM,
                prompt=prompt,
                answer=_gs_answer(classification, index),
                provenance_kind="held-out-curriculum",
                curriculum_digest=None,
                template_family=f"held-out-{classification}",
            )
        )
    return train, evaluation


def build_r2_rows(
    seeds: list[CurriculumSeed],
    *,
    teacher_targets: list[VerifiedTeacherTarget] | None = None,
    teacher_rows: int = 1_600,
    curriculum_rows: int = 900,
    eval_rows: int = 240,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    train: list[dict[str, Any]] = []
    verified_targets = teacher_targets or []
    for index, seed in enumerate(seeds[:teacher_rows]):
        target = verified_targets[index] if index < len(verified_targets) else None
        if target is not None:
            verdict = str(target.answer["reported_verdict"])
            prompt = str(target.request["prompt"])
            answer = target.answer
            receipt = {
                "attestation_key_id": target.attestation_key_id,
                "request_id": str(target.request["request_id"]),
                "request_sha256": str(target.request["request_sha256"]),
                "response_sha256": str(target.response["response_sha256"]),
                "target_sha256": str(target.response["target_sha256"]),
            }
        else:
            verdict = R2_VERDICTS[index % len(R2_VERDICTS)]
            prompt, facts, summary, action = _r2_prompt(
                verdict, index, seed=seed, held_out=False
            )
            if seed is not None:
                prompt += (
                    f" Deterministic seed-derived curriculum transform id={index}; "
                    "this row is not a verified teacher response."
                )
            answer = {
                "reported_verdict": verdict,
                "summary": summary,
                "facts_preserved": facts,
                "invented_facts": [],
                "recommended_action": action,
                "persona_markers": list(PERSONA_MARKERS),
                "changes_verdict": False,
            }
            receipt = None
        train.append(
            _row(
                adapter="r2d2",
                split="train",
                label=verdict,
                index=index,
                system=R2_SYSTEM,
                prompt=prompt,
                answer=answer,
                provenance_kind=(
                    TEACHER_TARGET_PROVENANCE
                    if target is not None
                    else CURRICULUM_SEEDED_PROVENANCE
                ),
                curriculum_digest=seed.digest,
                template_family=f"teacher-{verdict.lower()}",
                teacher_receipt=receipt,
            )
        )
    for offset in range(curriculum_rows):
        index = teacher_rows + offset
        verdict = R2_VERDICTS[offset % len(R2_VERDICTS)]
        seed = seeds[offset % len(seeds)] if seeds else None
        prompt, facts, summary, action = _r2_prompt(
            verdict, index, seed=seed, held_out=False
        )
        if seed is not None:
            prompt += (
                f" Deterministic seed-derived curriculum transform id={index}; "
                "this row is not a verified teacher response."
            )
        answer = {
            "reported_verdict": verdict,
            "summary": summary,
            "facts_preserved": facts,
            "invented_facts": [],
            "recommended_action": action,
            "persona_markers": list(PERSONA_MARKERS),
            "changes_verdict": False,
        }
        train.append(
            _row(
                adapter="r2d2",
                split="train",
                label=verdict,
                index=index,
                system=R2_SYSTEM,
                prompt=prompt,
                answer=answer,
                provenance_kind=(
                    CURRICULUM_SEEDED_PROVENANCE
                    if seed is not None
                    else "curriculum-generated"
                ),
                curriculum_digest=seed.digest if seed is not None else None,
                template_family=(
                    f"seeded-curriculum-{verdict.lower()}"
                    if seed is not None
                    else f"curriculum-{verdict.lower()}"
                ),
            )
        )
    evaluation: list[dict[str, Any]] = []
    for offset in range(eval_rows):
        index = 100_000 + offset
        verdict = R2_VERDICTS[offset % len(R2_VERDICTS)]
        prompt, facts, summary, action = _r2_prompt(
            verdict, index, seed=None, held_out=True
        )
        answer = {
            "reported_verdict": verdict,
            "summary": summary,
            "facts_preserved": facts,
            "invented_facts": [],
            "recommended_action": action,
            "persona_markers": list(PERSONA_MARKERS),
            "changes_verdict": False,
        }
        evaluation.append(
            _row(
                adapter="r2d2",
                split="eval",
                label=verdict,
                index=index,
                system=R2_SYSTEM,
                prompt=prompt,
                answer=answer,
                provenance_kind="held-out-curriculum",
                curriculum_digest=None,
                template_family=f"held-out-{verdict.lower()}",
            )
        )
    return train, evaluation


def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(_canonical_json(row) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def _validate_row(
    row: dict[str, Any],
    *,
    adapter: str,
    split: str,
    path: Path,
    line_number: int,
    verified_targets: dict[str, VerifiedTeacherTarget],
) -> tuple[str, str | None, str, bool]:
    prefix = f"{path}:{line_number}"
    if not isinstance(row.get("id"), str) or not row["id"]:
        raise CorpusValidationError(f"{prefix}: missing row id")
    messages = row.get("messages")
    if not isinstance(messages, list) or len(messages) != 3:
        raise CorpusValidationError(f"{prefix}: messages must contain system/user/assistant")
    expected_roles = ("system", "user", "assistant")
    if tuple(message.get("role") for message in messages) != expected_roles:
        raise CorpusValidationError(f"{prefix}: invalid message role order")
    expected_system = GS_SYSTEM if adapter == "gs343" else R2_SYSTEM
    if messages[0].get("content") != expected_system:
        raise CorpusValidationError(f"{prefix}: system prompt does not match P5 contract")
    try:
        answer = json.loads(messages[2].get("content", ""))
    except json.JSONDecodeError as exc:
        raise CorpusValidationError(f"{prefix}: assistant content is not strict JSON") from exc
    validate_teacher_answer(adapter, answer, prefix)
    meta = row.get("meta")
    if not isinstance(meta, dict) or meta.get("adapter") != adapter:
        raise CorpusValidationError(f"{prefix}: invalid adapter metadata")
    if meta.get("split") != split or meta.get("domain_core") is not True:
        raise CorpusValidationError(f"{prefix}: invalid split or domain-core metadata")
    expected_label = (
        answer["classification"] if adapter == "gs343" else answer["reported_verdict"]
    )
    if meta.get("label") != expected_label:
        raise CorpusValidationError(f"{prefix}: metadata label does not match the target")
    if adapter == "gs343":
        classification = answer["classification"]
        if classification not in GS_CLASSES:
            raise CorpusValidationError(f"{prefix}: invalid GS343 classification")
        if not isinstance(answer["root_causes"], list) or not answer["root_causes"]:
            raise CorpusValidationError(f"{prefix}: root_causes must be a non-empty list")
        if answer["target_mutation_allowed"] is not False:
            raise CorpusValidationError(f"{prefix}: target mutation must be forbidden")
        if classification == "inconclusive" and answer["abstain"] is not True:
            raise CorpusValidationError(f"{prefix}: inconclusive rows must abstain")
        if classification != "inconclusive" and answer["abstain"] is not False:
            raise CorpusValidationError(f"{prefix}: conclusive rows may not abstain")
        if classification == "multi-cause":
            causes = " ".join(str(item).lower() for item in answer["root_causes"])
            if "application" not in causes or "harness" not in causes:
                raise CorpusValidationError(
                    f"{prefix}: multi-cause must preserve application and harness causes"
                )
    else:
        verdict = answer["reported_verdict"]
        if verdict not in R2_VERDICTS:
            raise CorpusValidationError(f"{prefix}: invalid R2D2 verdict")
        if answer["changes_verdict"] is not False or answer["invented_facts"] != []:
            raise CorpusValidationError(f"{prefix}: R2D2 changed or invented evidence")
        if not isinstance(answer["facts_preserved"], list) or not answer["facts_preserved"]:
            raise CorpusValidationError(f"{prefix}: facts_preserved must be non-empty")
        if not isinstance(answer["persona_markers"], list) or not answer["persona_markers"]:
            raise CorpusValidationError(f"{prefix}: persona markers must be non-empty")
        if verdict == "NOT_READY":
            summary = str(answer["summary"]).lower()
            if "critical" not in summary or any(
                token in summary for token in (" resolved", " recovered", " fixed", " ready.")
            ):
                raise CorpusValidationError(
                    f"{prefix}: NOT_READY severity or no-success invariant failed"
                )
    prompt_digest = _digest_text(str(messages[1].get("content", "")))
    curriculum_digest = meta.get("curriculum_source_sha256")
    if curriculum_digest is not None and (
        not isinstance(curriculum_digest, str) or len(curriculum_digest) != 64
    ):
        raise CorpusValidationError(f"{prefix}: malformed curriculum source digest")
    provenance_kind = meta.get("provenance_kind")
    teacher_generated = meta.get("teacher_generated_source")
    receipt = meta.get("teacher_receipt")
    verified = False
    if provenance_kind == TEACHER_TARGET_PROVENANCE:
        if split != "train" or teacher_generated is not True or not isinstance(receipt, dict):
            raise CorpusValidationError(f"{prefix}: invalid verified-teacher metadata")
        request_id = receipt.get("request_id")
        target = verified_targets.get(str(request_id))
        if target is None:
            raise CorpusValidationError(f"{prefix}: teacher receipt is not in the trusted ledger")
        expected_receipt = {
            "attestation_key_id": target.attestation_key_id,
            "request_id": target.request["request_id"],
            "request_sha256": target.request["request_sha256"],
            "response_sha256": target.response["response_sha256"],
            "target_sha256": target.response["target_sha256"],
        }
        if receipt != expected_receipt:
            raise CorpusValidationError(f"{prefix}: teacher receipt linkage mismatch")
        if messages[1].get("content") != target.request["prompt"]:
            raise CorpusValidationError(f"{prefix}: teacher request prompt mismatch")
        if messages[2].get("content") != _canonical_json(target.answer):
            raise CorpusValidationError(f"{prefix}: assistant target differs from trusted response")
        if curriculum_digest != target.request["curriculum_source_sha256"]:
            raise CorpusValidationError(f"{prefix}: teacher curriculum digest mismatch")
        verified = True
    elif provenance_kind == CURRICULUM_SEEDED_PROVENANCE:
        if split != "train" or teacher_generated is not False or receipt is not None:
            raise CorpusValidationError(f"{prefix}: seeded curriculum falsely claims teacher credit")
        if curriculum_digest is None:
            raise CorpusValidationError(f"{prefix}: seeded curriculum lacks its source digest")
    elif provenance_kind in {"curriculum-generated", "held-out-curriculum"}:
        expected_kind = "held-out-curriculum" if split == "eval" else "curriculum-generated"
        if provenance_kind != expected_kind:
            raise CorpusValidationError(f"{prefix}: invalid curriculum provenance for split")
        if teacher_generated is not False or curriculum_digest is not None or receipt is not None:
            raise CorpusValidationError(f"{prefix}: curriculum row falsely claims teacher provenance")
    else:
        raise CorpusValidationError(f"{prefix}: unsupported provenance kind")
    return prompt_digest, curriculum_digest, str(row["id"]), verified


def _validate_dataset(
    paths: CorpusPaths,
    *,
    adapter: str,
    verified_targets: list[VerifiedTeacherTarget],
) -> dict[str, Any]:
    target_by_request_id = {
        str(target.request["request_id"]): target for target in verified_targets
    }
    if len(target_by_request_id) != len(verified_targets):
        raise CorpusValidationError(f"{adapter}: duplicate trusted teacher request ids")
    prompt_sets: dict[str, set[str]] = {"train": set(), "eval": set()}
    curriculum_sets: dict[str, set[str]] = {"train": set(), "eval": set()}
    ids: set[str] = set()
    credited_request_ids: set[str] = set()
    counts = {"train": 0, "eval": 0, "verified_teacher": 0, "domain_core": 0}
    labels: dict[str, int] = {}
    for split, path in (("train", paths.train), ("eval", paths.eval)):
        for line_number, row in enumerate(_iter_jsonl(path), start=1):
            prompt_digest, curriculum_digest, row_id, verified = _validate_row(
                row,
                adapter=adapter,
                split=split,
                path=path,
                line_number=line_number,
                verified_targets=target_by_request_id,
            )
            meta = row["meta"]
            if verified:
                request_id = str(meta["teacher_receipt"]["request_id"])
                if request_id in credited_request_ids:
                    raise CorpusValidationError(
                        f"{path}:{line_number}: teacher request credited more than once"
                    )
            if prompt_digest in prompt_sets[split]:
                raise CorpusValidationError(f"{path}:{line_number}: duplicate prompt")
            if row_id in ids:
                raise CorpusValidationError(f"{path}:{line_number}: duplicate row id")
            prompt_sets[split].add(prompt_digest)
            ids.add(row_id)
            if curriculum_digest:
                curriculum_sets[split].add(curriculum_digest)
            counts[split] += 1
            if verified:
                credited_request_ids.add(request_id)
                counts["verified_teacher"] += 1
            if meta.get("domain_core") is True:
                counts["domain_core"] += 1
            label = str(meta.get("label"))
            labels[label] = labels.get(label, 0) + 1
    total = counts["train"] + counts["eval"]
    if total < 2_500:
        raise CorpusValidationError(f"{adapter}: {total} total rows; 2500 required")
    if counts["verified_teacher"] < 1_500:
        raise CorpusValidationError(
            f"{adapter}: {counts['verified_teacher']} verified teacher targets; 1500 required"
        )
    if counts["eval"] < 200:
        raise CorpusValidationError(f"{adapter}: {counts['eval']} eval rows; 200 required")
    if counts["domain_core"] / total < 0.60:
        raise CorpusValidationError(f"{adapter}: domain-core composition is below 60%")
    if prompt_sets["train"] & prompt_sets["eval"]:
        raise CorpusValidationError(f"{adapter}: train/eval prompt leakage detected")
    if curriculum_sets["train"] & curriculum_sets["eval"]:
        raise CorpusValidationError(f"{adapter}: train/eval curriculum-source leakage detected")
    required_labels = set(GS_CLASSES if adapter == "gs343" else R2_VERDICTS)
    if set(labels) != required_labels:
        raise CorpusValidationError(f"{adapter}: label coverage mismatch")
    return {
        "train_rows": counts["train"],
        "eval_rows": counts["eval"],
        "total_rows": total,
        "verified_teacher_target_rows": counts["verified_teacher"],
        "domain_core_rows": counts["domain_core"],
        "domain_core_ratio": counts["domain_core"] / total,
        "label_counts": dict(sorted(labels.items())),
        "train_sha256": _file_digest(paths.train),
        "eval_sha256": _file_digest(paths.eval),
        "train_eval_prompt_overlap": 0,
        "train_eval_curriculum_source_overlap": 0,
    }


def validate_corpora(
    output_root: Path,
    provenance_root: Path,
    trusted_key_dir: Path,
) -> dict[str, Any]:
    verified = verify_teacher_provenance(provenance_root, trusted_key_dir)
    report: dict[str, Any] = {"schema_version": "p5-corpus-validation.v1", "passed": True}
    for adapter in ADAPTERS:
        directory = output_root / f"{adapter}_p5_v1"
        paths = CorpusPaths(
            train=directory / "train.jsonl",
            eval=directory / "eval.jsonl",
            manifest=directory / "manifest.json",
        )
        report[adapter] = _validate_dataset(
            paths,
            adapter=adapter,
            verified_targets=verified[adapter],
        )
    return report


def build_corpora(
    gs343_curriculum_source: Path,
    r2d2_curriculum_source: Path,
    output_root: Path,
    provenance_root: Path,
    trusted_key_dir: Path,
) -> dict[str, Any]:
    sources = {
        "gs343": gs343_curriculum_source,
        "r2d2": r2d2_curriculum_source,
    }
    seeds_by_adapter = {
        adapter: load_curriculum_seeds(path, adapter=adapter)
        for adapter, path in sources.items()
    }
    source_digests = {
        adapter: _file_digest(path) for adapter, path in sources.items()
    }
    verified = verify_teacher_provenance(provenance_root, trusted_key_dir)
    builders = {"gs343": build_gs_rows, "r2d2": build_r2_rows}
    paths_by_adapter: dict[str, CorpusPaths] = {}
    for adapter, builder in builders.items():
        train, evaluation = builder(
            seeds_by_adapter[adapter], teacher_targets=verified[adapter]
        )
        directory = output_root / f"{adapter}_p5_v1"
        paths = CorpusPaths(
            train=directory / "train.jsonl",
            eval=directory / "eval.jsonl",
            manifest=directory / "manifest.json",
        )
        _write_jsonl(paths.train, train)
        _write_jsonl(paths.eval, evaluation)
        paths_by_adapter[adapter] = paths

    validation = validate_corpora(output_root, provenance_root, trusted_key_dir)
    for adapter, paths in paths_by_adapter.items():
        manifest = {
            "schema_version": "p5-corrective-corpus.v1",
            "adapter": adapter,
            "dataset_version": "p5-v1",
            "purpose": "Certification Forge P5 semantic qualification corrective training",
            "curriculum_source": {
                "path": str(sources[adapter]),
                "sha256": source_digests[adapter],
                "selected_seed_rows": 1_600,
                "provenance": CURRICULUM_SEEDED_PROVENANCE,
                "teacher_credit": False,
            },
            "teacher_target_provenance": {
                "requests_path": str(provenance_root / TEACHER_REQUESTS_FILENAME),
                "responses_path": str(provenance_root / TEACHER_RESPONSES_FILENAME),
                "attestation_path": str(provenance_root / TEACHER_ATTESTATION_FILENAME),
                "trusted_key_directory": str(trusted_key_dir),
                "verified_target_rows": validation[adapter][
                    "verified_teacher_target_rows"
                ],
            },
            "composition_gate": {
                "minimum_total_rows": 2_500,
                "minimum_teacher_rows": 1_500,
                "minimum_eval_rows": 200,
                "minimum_domain_core_ratio": 0.60,
                "promotion_ratio_over_incumbent": 1.05,
            },
            "validation": validation[adapter],
        }
        paths.manifest.parent.mkdir(parents=True, exist_ok=True)
        temporary = paths.manifest.with_suffix(".json.tmp")
        temporary.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        temporary.replace(paths.manifest)
    validation["curriculum_source_sha256"] = source_digests
    return validation
