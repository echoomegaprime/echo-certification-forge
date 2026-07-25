import json
from pathlib import Path

import pytest

from echo_certification_forge import p5_corpus
from echo_certification_forge.p5_corpus import (
    CorpusError,
    CorpusValidationError,
    TEACHER_ATTESTATION_FILENAME,
    TEACHER_REQUESTS_FILENAME,
    TEACHER_RESPONSES_FILENAME,
    build_corpora,
    export_teacher_requests,
    sign_teacher_response_ledger,
    validate_corpora,
    verify_teacher_provenance,
)
from echo_certification_forge.signing import Ed25519VerdictSigner


ROOT = Path(__file__).resolve().parents[1]


def _read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def _r2_facts(prompt: str) -> list[str]:
    fact_blob = prompt.split("Verified finding envelope: ", 1)[1]
    for suffix in (". Narrate without", ". Preserve the condition."):
        if suffix in fact_blob:
            fact_blob = fact_blob.split(suffix, 1)[0]
            break
    return [item.strip() for item in fact_blob.split(";")]


def _seed_source(root: Path, adapter: str) -> Path:
    path = root / f"{adapter}_curriculum_source.jsonl"
    raw_path = root / f"{adapter}_raw_source.jsonl"
    rows = [
        {
            "input": f"RAW_{adapter.upper()}_EXPRESSION_{index}_DO_NOT_COPY",
            "output": f"RAW_{adapter.upper()}_TARGET_{index}_DO_NOT_COPY",
        }
        for index in range(1_600)
    ]
    _write_jsonl(raw_path, rows)
    p5_corpus.materialize_curriculum_ledger(
        adapter, raw_path, path, row_count=1_600
    )
    return path


def _answer(request: dict) -> dict:
    label = request["curriculum_label"]
    if request["adapter"] == "gs343":
        causes = (
            ["application failure", "harness failure"]
            if label == "multi-cause"
            else [f"{label} evidence"]
        )
        return {
            "classification": label,
            "confidence": 0.5 if label == "inconclusive" else 0.95,
            "abstain": label == "inconclusive",
            "root_causes": causes,
            "target_mutation_allowed": False,
            "repair_actions": ["Repair only the classified source of failure."],
            "release_risk": "block",
        }
    summary = (
        "R2-D2 critical alert: release remains blocked; recovery is unverified."
        if label == "NOT_READY"
        else f"R2-D2 reports the supplied {label} verdict without alteration."
    )
    return {
        "reported_verdict": label,
        "summary": summary,
        "facts_preserved": _r2_facts(request["prompt"]),
        "invented_facts": [],
        "recommended_action": "Follow the supplied evidence and release conditions.",
        "persona_markers": ["R2-D2", "diagnostic-beep", "presentation-only"],
        "changes_verdict": False,
    }


def _generated_responses(requests: list[dict]) -> list[dict]:
    responses = []
    for index, request in enumerate(requests):
        answer = _answer(request)
        raw_response = p5_corpus._canonical_json(answer)
        generation_id = f"generation-{index}"
        provider_response = {
            "text": raw_response,
            "stopReason": "EndTurn",
            "requestId": generation_id,
            "sessionId": f"session-{index}",
        }
        core = {
            "schema_version": p5_corpus.TEACHER_GENERATION_SCHEMA,
            "request_id": request["request_id"],
            "request_sha256": request["request_sha256"],
            "adapter": request["adapter"],
            "provider": "xai-grok-cli-oidc",
            "model": "grok-4.5",
            "model_version": "grok-4.5",
            "generation_id": generation_id,
            "generated_at_utc": "2026-07-20T00:00:00Z",
            "raw_response": raw_response,
            "raw_response_sha256": p5_corpus.sha256_json(answer),
            "target_sha256": p5_corpus.sha256_json(answer),
            "provider_response": provider_response,
            "provider_response_sha256": p5_corpus.sha256_json(provider_response),
        }
        responses.append({**core, "record_sha256": p5_corpus.sha256_json(core)})
    return responses


def _create_signed_provenance(
    root: Path,
    *,
    requests_per_adapter: int = 1_600,
    trust_signer: bool = True,
) -> tuple[Path, Path, Ed25519VerdictSigner]:
    provenance = root / "provenance"
    trusted = root / "trusted"
    trusted.mkdir(parents=True)
    gs343_source = _seed_source(root, "gs343")
    r2d2_source = _seed_source(root, "r2d2")
    export_teacher_requests(
        gs343_source,
        r2d2_source,
        provenance,
        requests_per_adapter=requests_per_adapter,
    )
    requests = _read_jsonl(provenance / TEACHER_REQUESTS_FILENAME)
    generated = root / "generated.jsonl"
    _write_jsonl(generated, _generated_responses(requests))
    signer = Ed25519VerdictSigner.generate()
    if trust_signer:
        (trusted / "teacher.pem").write_text(signer.public_key_pem, encoding="ascii")
    sign_teacher_response_ledger(
        provenance / TEACHER_REQUESTS_FILENAME,
        generated,
        provenance,
        signer,
        signer_identity="test-frontier-teacher-operator",
    )
    return provenance, trusted, signer


@pytest.fixture(scope="module")
def signed_corpora(tmp_path_factory: pytest.TempPathFactory):
    root = tmp_path_factory.mktemp("signed-corpora")
    provenance, trusted, _ = _create_signed_provenance(root)
    output = root / "output"
    report = build_corpora(
        root / "gs343_curriculum_source.jsonl",
        root / "r2d2_curriculum_source.jsonl",
        output,
        provenance,
        trusted,
    )
    return output, provenance, trusted, report


def test_builds_complete_leak_free_corpora(signed_corpora):
    output, provenance, trusted, report = signed_corpora
    for adapter in ("gs343", "r2d2"):
        result = report[adapter]
        assert result["total_rows"] >= 2_500
        assert result["verified_teacher_target_rows"] == 1_600
        assert result["eval_rows"] >= 200
        assert result["domain_core_ratio"] >= 0.60
        assert result["train_eval_prompt_overlap"] == 0
        assert result["train_eval_curriculum_source_overlap"] == 0
        manifest = json.loads(
            (output / f"{adapter}_p5_v1" / "manifest.json").read_text(
                encoding="utf-8"
            )
        )
        assert manifest["validation"]["verified_teacher_target_rows"] == 1_600
        assert manifest["curriculum_source"]["teacher_credit"] is False
        assert (
            manifest["curriculum_source"]["sha256"]
            == report["curriculum_source_sha256"][adapter]
        )
    assert (
        report["curriculum_source_sha256"]["gs343"]
        != report["curriculum_source_sha256"]["r2d2"]
    )
    assert validate_corpora(output, provenance, trusted)["passed"] is True


def test_builds_versioned_contract_weighted_corpora(signed_corpora):
    output, provenance, trusted, _ = signed_corpora
    root = output.parent
    v2_output = root / "output-v2"
    report = build_corpora(
        root / "gs343_curriculum_source.jsonl",
        root / "r2d2_curriculum_source.jsonl",
        v2_output,
        provenance,
        trusted,
        curriculum_rows=1_800,
        dataset_version="p5-v2",
    )
    for adapter in ("gs343", "r2d2"):
        assert report[adapter]["train_rows"] == 3_400
        manifest = json.loads(
            (v2_output / f"{adapter}_p5_v2" / "manifest.json").read_text(
                encoding="utf-8"
            )
        )
        assert manifest["dataset_version"] == "p5-v2"
        assert manifest["validation"]["verified_teacher_target_rows"] == 1_600
        assert manifest["curriculum_source"]["selected_seed_rows"] == 1_800
    assert (
        validate_corpora(
            v2_output,
            provenance,
            trusted,
            dataset_version="p5-v2",
        )["passed"]
        is True
    )


def test_exports_requests_from_separate_curriculum_ledgers(tmp_path: Path):
    provenance = tmp_path / "provenance"
    report = export_teacher_requests(
        _seed_source(tmp_path, "gs343"),
        _seed_source(tmp_path, "r2d2"),
        provenance,
        requests_per_adapter=2,
    )
    requests = _read_jsonl(provenance / TEACHER_REQUESTS_FILENAME)
    by_adapter = {
        adapter: [row for row in requests if row["adapter"] == adapter]
        for adapter in ("gs343", "r2d2")
    }
    serialized = json.dumps(requests)
    assert "RAW_GS343_EXPRESSION" not in serialized
    assert "RAW_GS343_TARGET" not in serialized
    assert "RAW_R2D2_EXPRESSION" not in serialized
    assert "RAW_R2D2_TARGET" not in serialized
    assert {
        row["curriculum_source_sha256"] for row in by_adapter["gs343"]
    }.isdisjoint(
        {row["curriculum_source_sha256"] for row in by_adapter["r2d2"]}
    )
    assert (
        report["curriculum_sources"]["gs343"]["sha256"]
        != report["curriculum_sources"]["r2d2"]["sha256"]
    )


def test_deterministic_seed_rows_never_receive_teacher_credit(signed_corpora):
    output, _, _, _ = signed_corpora
    rows = _read_jsonl(output / "gs343_p5_v1" / "train.jsonl")
    seeded = [
        row for row in rows if row["meta"]["provenance_kind"] == "curriculum-seeded"
    ]
    assert seeded
    assert all(row["meta"]["teacher_generated_source"] is False for row in seeded)
    assert all(row["meta"]["teacher_receipt"] is None for row in seeded)


def test_rejects_altered_curriculum_binding_in_corpus(signed_corpora):
    output, provenance, trusted, _ = signed_corpora
    path = output / "gs343_p5_v1" / "train.jsonl"
    original = path.read_text(encoding="utf-8")
    try:
        rows = _read_jsonl(path)
        generated = next(
            row
            for row in rows
            if row["meta"]["provenance_kind"] == "teacher-generated-target"
        )
        generated["meta"]["curriculum_source_sha256"] = "0" * 64
        _write_jsonl(path, rows)
        with pytest.raises(
            CorpusValidationError, match="teacher curriculum digest mismatch"
        ):
            validate_corpora(output, provenance, trusted)
    finally:
        path.write_text(original, encoding="utf-8")


def test_rejects_insufficient_adapter_curriculum_source(tmp_path: Path):
    gs343_source = _seed_source(tmp_path, "gs343")
    r2d2_source = _seed_source(tmp_path, "r2d2")
    rows = _read_jsonl(r2d2_source)
    _write_jsonl(r2d2_source, rows[:-1])
    with pytest.raises(
        CorpusValidationError,
        match="manifest ledger binding mismatch",
    ):
        export_teacher_requests(
            gs343_source,
            r2d2_source,
            tmp_path / "provenance",
        )


def test_curriculum_materialization_is_deterministic_and_non_expressive(
    tmp_path: Path,
):
    raw = tmp_path / "raw.jsonl"
    _write_jsonl(
        raw,
        [
            {
                "input": f"PRIVATE_SOURCE_EXPRESSION_{index}",
                "output": f"PRIVATE_SOURCE_TARGET_{index}",
            }
            for index in range(5)
        ],
    )
    first = tmp_path / "first.jsonl"
    second = tmp_path / "second.jsonl"
    first_manifest, _ = p5_corpus.materialize_curriculum_ledger(
        "gs343", raw, first, row_count=5
    )
    second_manifest, _ = p5_corpus.materialize_curriculum_ledger(
        "gs343", raw, second, row_count=5
    )

    assert first.read_bytes() == second.read_bytes()
    assert first_manifest["ledger"]["sha256"] == second_manifest["ledger"]["sha256"]
    assert b"PRIVATE_SOURCE_EXPRESSION" not in first.read_bytes()
    assert b"PRIVATE_SOURCE_TARGET" not in first.read_bytes()
    assert len(
        p5_corpus.load_curriculum_seeds(first, adapter="gs343", minimum=5)
    ) == 5


def test_curriculum_loader_rejects_rights_and_text_tampering(tmp_path: Path):
    ledger = _seed_source(tmp_path, "r2d2")
    manifest_path = ledger.with_suffix(ledger.suffix + ".manifest.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["rights_basis"] = "unknown-third-party-license"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(CorpusValidationError, match="rights_basis"):
        p5_corpus.load_curriculum_seeds(
            ledger, adapter="r2d2", minimum=1_600
        )

    p5_corpus.materialize_curriculum_ledger(
        "r2d2",
        tmp_path / "r2d2_raw_source.jsonl",
        ledger,
        row_count=1_600,
    )
    rows = _read_jsonl(ledger)
    rows[0]["prompt"] = "substituted expressive content"
    rows[0]["entry_sha256"] = p5_corpus.sha256_json(
        {key: value for key, value in rows[0].items() if key != "entry_sha256"}
    )
    _write_jsonl(ledger, rows)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["ledger"]["sha256"] = p5_corpus._file_digest(ledger)
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(CorpusValidationError, match="derivation contract"):
        p5_corpus.load_curriculum_seeds(
            ledger, adapter="r2d2", minimum=1_600
        )


def test_curriculum_loader_allows_relocated_verified_ledger(tmp_path: Path):
    original = _seed_source(tmp_path, "gs343")
    original_manifest = original.with_suffix(original.suffix + ".manifest.json")
    relocated = tmp_path / "relocated" / "gs343.jsonl"
    relocated.parent.mkdir()
    relocated.write_bytes(original.read_bytes())
    relocated.with_suffix(relocated.suffix + ".manifest.json").write_bytes(
        original_manifest.read_bytes()
    )

    seeds = p5_corpus.load_curriculum_seeds(
        relocated, adapter="gs343", minimum=1_600
    )

    assert len(seeds) == 1_600


def test_materialization_rejects_insufficient_unique_rows(tmp_path: Path):
    raw = tmp_path / "duplicates.jsonl"
    _write_jsonl(raw, [{"input": "same", "output": "same"}] * 4)
    with pytest.raises(CorpusValidationError, match="contains 1 eligible unique rows"):
        p5_corpus.materialize_curriculum_ledger(
            "gs343", raw, tmp_path / "ledger.jsonl", row_count=2
        )


def test_rejects_untrusted_self_signed_attestation(tmp_path: Path):
    provenance, trusted, _ = _create_signed_provenance(
        tmp_path, requests_per_adapter=2, trust_signer=False
    )
    with pytest.raises(CorpusError, match="untrusted_signing_key"):
        verify_teacher_provenance(provenance, trusted)


def test_rejects_invalid_signature(tmp_path: Path):
    provenance, trusted, _ = _create_signed_provenance(
        tmp_path, requests_per_adapter=2
    )
    attestation_path = provenance / TEACHER_ATTESTATION_FILENAME
    attestation = json.loads(attestation_path.read_text(encoding="utf-8"))
    attestation["payload"]["response_count"] += 1
    attestation_path.write_text(json.dumps(attestation), encoding="utf-8")
    with pytest.raises(CorpusError, match="invalid_signature"):
        verify_teacher_provenance(provenance, trusted)


def test_accepts_noncanonical_grok_provider_json_order(tmp_path: Path):
    provenance = tmp_path / "provenance"
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    export_teacher_requests(
        _seed_source(tmp_path, "gs343"),
        _seed_source(tmp_path, "r2d2"),
        provenance,
        requests_per_adapter=1,
    )
    requests = _read_jsonl(provenance / TEACHER_REQUESTS_FILENAME)
    generated = _generated_responses(requests)
    answer = _answer(requests[0])
    reordered_answer = {key: answer[key] for key in reversed(answer)}
    generated[0]["provider_response"]["text"] = json.dumps(
        reordered_answer,
        indent=2,
    )
    assert generated[0]["provider_response"]["text"] != generated[0]["raw_response"]
    generated[0]["provider_response_sha256"] = p5_corpus.sha256_json(
        generated[0]["provider_response"]
    )
    unsigned_generation = dict(generated[0])
    unsigned_generation.pop("record_sha256")
    generated[0]["record_sha256"] = p5_corpus.sha256_json(unsigned_generation)
    generated_path = tmp_path / "generated.jsonl"
    _write_jsonl(generated_path, generated)
    signer = Ed25519VerdictSigner.generate()
    (trusted / "teacher.pem").write_text(signer.public_key_pem, encoding="ascii")

    sign_teacher_response_ledger(
        provenance / TEACHER_REQUESTS_FILENAME,
        generated_path,
        provenance,
        signer,
        signer_identity="test-frontier-teacher-operator",
    )

    verified = verify_teacher_provenance(provenance, trusted)
    assert len(verified["gs343"]) == 1
    assert len(verified["r2d2"]) == 1


@pytest.mark.parametrize(
    ("filename", "field"),
    [
        (TEACHER_REQUESTS_FILENAME, "prompt"),
        (TEACHER_RESPONSES_FILENAME, "raw_response"),
    ],
)
def test_rejects_altered_provenance_files(
    tmp_path: Path, filename: str, field: str
):
    provenance, trusted, _ = _create_signed_provenance(
        tmp_path, requests_per_adapter=2
    )
    path = provenance / filename
    rows = _read_jsonl(path)
    rows[0][field] += " tampered"
    _write_jsonl(path, rows)
    with pytest.raises(CorpusError, match="file digest mismatch"):
        verify_teacher_provenance(provenance, trusted)


def test_rejects_target_that_conflicts_with_request_label(tmp_path: Path):
    provenance = tmp_path / "provenance"
    export_teacher_requests(
        _seed_source(tmp_path, "gs343"),
        _seed_source(tmp_path, "r2d2"),
        provenance,
        requests_per_adapter=1,
    )
    requests = _read_jsonl(provenance / TEACHER_REQUESTS_FILENAME)
    generated = _generated_responses(requests)
    generated[0]["raw_response"] = json.dumps(
        {
            **_answer(requests[0]),
            "classification": "harness-defect",
        },
        sort_keys=True,
    )
    generated_path = tmp_path / "generated.jsonl"
    _write_jsonl(generated_path, generated)
    with pytest.raises(CorpusError, match="curriculum label"):
        sign_teacher_response_ledger(
            provenance / TEACHER_REQUESTS_FILENAME,
            generated_path,
            provenance,
            Ed25519VerdictSigner.generate(),
            signer_identity="test-frontier-teacher-operator",
        )


def test_rejects_incomplete_response_ledger(tmp_path: Path):
    provenance = tmp_path / "provenance"
    export_teacher_requests(
        _seed_source(tmp_path, "gs343"),
        _seed_source(tmp_path, "r2d2"),
        provenance,
        requests_per_adapter=2,
    )
    requests = _read_jsonl(provenance / TEACHER_REQUESTS_FILENAME)
    generated_path = tmp_path / "generated.jsonl"
    _write_jsonl(generated_path, _generated_responses(requests[:-1]))
    with pytest.raises(CorpusError, match="incomplete"):
        sign_teacher_response_ledger(
            provenance / TEACHER_REQUESTS_FILENAME,
            generated_path,
            provenance,
            Ed25519VerdictSigner.generate(),
            signer_identity="test-frontier-teacher-operator",
        )


@pytest.mark.parametrize(
    ("case", "expected_error"),
    [
        ("forged-provider-response", "invalid Grok provider receipt"),
        ("provider-response-hash", "provider response digest mismatch"),
        ("generation-record-digest", "generation record digest mismatch"),
        ("duplicate-generation-id", "duplicate generation_id"),
        ("model-version-binding", "invalid Grok provider receipt"),
    ],
)
def test_rejects_adversarial_generation_receipts(
    tmp_path: Path, case: str, expected_error: str
):
    provenance = tmp_path / "provenance"
    export_teacher_requests(
        _seed_source(tmp_path, "gs343"),
        _seed_source(tmp_path, "r2d2"),
        provenance,
        requests_per_adapter=1,
    )
    requests = _read_jsonl(provenance / TEACHER_REQUESTS_FILENAME)
    generated = _generated_responses(requests)

    if case == "forged-provider-response":
        generated[0]["provider_response"]["requestId"] = "forged-request"
        generated[0]["provider_response_sha256"] = p5_corpus.sha256_json(
            generated[0]["provider_response"]
        )
        generated[0]["record_sha256"] = p5_corpus.sha256_json(
            {key: value for key, value in generated[0].items() if key != "record_sha256"}
        )
    elif case == "provider-response-hash":
        generated[0]["provider_response_sha256"] = "0" * 64
    elif case == "generation-record-digest":
        generated[0]["record_sha256"] = "0" * 64
    elif case == "duplicate-generation-id":
        generated[1]["generation_id"] = generated[0]["generation_id"]
        generated[1]["provider_response"]["requestId"] = generated[0]["generation_id"]
        generated[1]["provider_response_sha256"] = p5_corpus.sha256_json(
            generated[1]["provider_response"]
        )
        generated[1]["record_sha256"] = p5_corpus.sha256_json(
            {key: value for key, value in generated[1].items() if key != "record_sha256"}
        )
    elif case == "model-version-binding":
        generated[0]["model_version"] = "grok-4.5-forged"
        generated[0]["record_sha256"] = p5_corpus.sha256_json(
            {key: value for key, value in generated[0].items() if key != "record_sha256"}
        )

    generated_path = tmp_path / f"{case}.jsonl"
    _write_jsonl(generated_path, generated)
    with pytest.raises(CorpusError, match=expected_error):
        sign_teacher_response_ledger(
            provenance / TEACHER_REQUESTS_FILENAME,
            generated_path,
            provenance,
            Ed25519VerdictSigner.generate(),
            signer_identity="test-frontier-teacher-operator",
        )


def test_rejects_forged_teacher_label_in_corpus(signed_corpora):
    output, provenance, trusted, _ = signed_corpora
    path = output / "gs343_p5_v1" / "train.jsonl"
    original = path.read_text(encoding="utf-8")
    try:
        rows = _read_jsonl(path)
        rows[0]["meta"]["label"] = "harness-defect"
        _write_jsonl(path, rows)
        with pytest.raises(CorpusValidationError, match="metadata label"):
            validate_corpora(output, provenance, trusted)
    finally:
        path.write_text(original, encoding="utf-8")


def test_rejects_duplicate_teacher_request_credit(signed_corpora):
    output, provenance, trusted, _ = signed_corpora
    path = output / "gs343_p5_v1" / "train.jsonl"
    original = path.read_text(encoding="utf-8")
    try:
        rows = _read_jsonl(path)
        first = next(
            row
            for row in rows
            if row["meta"]["provenance_kind"] == "teacher-generated-target"
        )
        duplicate = json.loads(json.dumps(first))
        duplicate["id"] = "forged-duplicate-credit"
        rows.append(duplicate)
        _write_jsonl(path, rows)
        with pytest.raises(
            CorpusValidationError, match="teacher request credited more than once"
        ):
            validate_corpora(output, provenance, trusted)
    finally:
        path.write_text(original, encoding="utf-8")


def test_rejects_insufficient_verified_teacher_targets(tmp_path: Path):
    provenance, trusted, _ = _create_signed_provenance(
        tmp_path, requests_per_adapter=10
    )
    with pytest.raises(CorpusValidationError, match="1500 required"):
        build_corpora(
            tmp_path / "gs343_curriculum_source.jsonl",
            tmp_path / "r2d2_curriculum_source.jsonl",
            tmp_path / "output",
            provenance,
            trusted,
        )
