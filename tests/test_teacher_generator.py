import json
import subprocess
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

import pytest

import echo_certification_forge.p5_corpus as p5_corpus
import echo_certification_forge.teacher_generator as teacher_generator
from echo_certification_forge.canonical import canonical_json, sha256_json
from echo_certification_forge.p5_corpus import (
    GS_SCHEMA,
    GS_SYSTEM,
    TEACHER_REQUEST_SCHEMA,
    sign_teacher_response_ledger,
    verify_teacher_provenance,
)
from echo_certification_forge.signing import Ed25519VerdictSigner
from echo_certification_forge.teacher_generator import (
    GROK_PROVIDER,
    TeacherGenerationError,
    XAI_API_PROVIDER,
    generate_teacher_responses,
)


NOW = datetime(2026, 7, 20, tzinfo=timezone.utc)


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(canonical_json(row) + "\n" for row in rows),
        encoding="utf-8",
    )


def _read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line
    ]


def _request(index: int = 0) -> dict:
    row = {
        "schema_version": TEACHER_REQUEST_SCHEMA,
        "request_id": f"request-{index}",
        "adapter": "gs343",
        "index": index,
        "curriculum_source_sha256": f"{index + 1:064x}",
        "curriculum_label": "application-defect",
        "system": GS_SYSTEM,
        "prompt": f"Classify deterministic application failure probe {index}.",
        "response_contract": sorted(GS_SCHEMA),
    }
    row["request_sha256"] = sha256_json(row)
    return row


def _answer() -> dict:
    return {
        "classification": "application-defect",
        "confidence": 0.95,
        "abstain": False,
        "root_causes": ["application failure evidence"],
        "target_mutation_allowed": False,
        "repair_actions": ["Repair only the application failure."],
        "release_risk": "block",
    }


def _provider_response(generation_id: str = "generation-1") -> dict:
    return {
        "responseId": generation_id,
        "modelVersion": "gemini-2.5-pro-001",
        "candidates": [
            {
                "finishReason": "STOP",
                "content": {"parts": [{"text": canonical_json(_answer())}]},
            }
        ],
    }


def _grok_response(generation_id: str = "grok-request-1") -> dict:
    return {
        "text": canonical_json(_answer()),
        "stopReason": "EndTurn",
        "sessionId": "grok-session-1",
        "requestId": generation_id,
        "thought": "redacted provider reasoning summary",
    }


def _xai_api_response(request) -> dict:
    payload = json.loads(request.data)
    generation_id = f"xai-{sha256_json(payload)[:20]}"
    return {
        "id": generation_id,
        "model": "grok-4.5",
        "choices": [
            {
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": canonical_json(_answer())},
            }
        ],
        "usage": {
            "prompt_tokens": 100,
            "completion_tokens": 50,
            "total_tokens": 150,
            "cost_in_usd_ticks": 5_000_000,
        },
        "created": 1,
        "object": "chat.completion",
    }


def _run(
    root: Path,
    transport,
    *,
    requests: list[dict] | None = None,
    api_key: str = "secret-key",
    **kwargs,
) -> dict:
    request_path = root / "requests.jsonl"
    if not request_path.exists():
        _write_jsonl(request_path, requests or [_request()])
    return generate_teacher_responses(
        requests_path=request_path,
        successes_path=root / "successes.jsonl",
        failures_path=root / "failures.jsonl",
        api_key=api_key,
        transport=transport,
        clock=lambda: NOW,
        sleeper=kwargs.pop("sleeper", lambda _: None),
        jitter=kwargs.pop("jitter", lambda: 1.0),
        **kwargs,
    )


@pytest.mark.parametrize(
    ("verdict", "index"),
    [
        ("PRODUCTION_READY", 100_000),
        ("CONDITIONALLY_READY", 100_001),
        ("NOT_READY", 100_002),
    ],
)
def test_r2_teacher_contract_matches_canonical_targets(verdict: str, index: int):
    prompt, facts, summary, action = p5_corpus._r2_prompt(
        verdict, index, seed=None, held_out=True
    )
    expected = {
        "facts_preserved": facts,
        "summary": summary,
        "recommended_action": action,
    }
    assert teacher_generator._r2_exact_contract(prompt) == expected

    request = {"adapter": "r2d2", "system": p5_corpus.R2_SYSTEM, "prompt": prompt}
    vertex = json.loads(teacher_generator._request_payload(request))
    xai = json.loads(teacher_generator._xai_request_payload(request, "grok-4.5"))
    for reminder in (
        vertex["systemInstruction"]["parts"][0]["text"],
        xai["messages"][0]["content"],
    ):
        assert canonical_json(facts) in reminder
        assert canonical_json(summary) in reminder
        assert canonical_json(action) in reminder


def test_generates_content_addressed_success_and_resumes(tmp_path: Path):
    calls = []

    def transport(request, timeout):
        calls.append((request, timeout))
        return _provider_response()

    first = _run(tmp_path, transport)
    second = _run(tmp_path, transport)

    assert first["generated_success_count"] == 1
    assert first["pending_count"] == 0
    assert second["existing_success_count"] == 1
    assert second["generated_success_count"] == 0
    assert len(calls) == 1
    request = calls[0][0]
    assert request.get_header("X-goog-api-key") == "secret-key"
    assert "secret-key" not in request.full_url
    assert "secret-key" not in request.data.decode("utf-8")
    success = _read_jsonl(tmp_path / "successes.jsonl")[0]
    unsigned = dict(success)
    assert unsigned.pop("record_sha256") == sha256_json(unsigned)
    assert success["raw_response"] == canonical_json(_answer())


def test_retries_transient_failure_with_bounded_backoff(tmp_path: Path):
    attempts = 0
    sleeps = []

    def transport(request, timeout):
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise urllib.error.URLError("temporary")
        return _provider_response()

    report = _run(
        tmp_path,
        transport,
        max_attempts=3,
        base_backoff_seconds=2,
        max_backoff_seconds=3,
        sleeper=sleeps.append,
    )

    assert report["generated_success_count"] == 1
    assert sleeps == [2.0, 3.0]
    assert not (tmp_path / "failures.jsonl").exists()


def test_records_redacted_failure_and_retries_it_later(tmp_path: Path):
    secret = "credential-must-not-leak"

    def failing_transport(request, timeout):
        raise urllib.error.URLError(f"temporary failure for {secret}")

    first = _run(
        tmp_path,
        failing_transport,
        api_key=secret,
        max_attempts=1,
    )
    failure_text = (tmp_path / "failures.jsonl").read_text(encoding="utf-8")
    second = _run(
        tmp_path,
        lambda request, timeout: _provider_response(),
        api_key=secret,
    )

    assert first["failed_count"] == 1
    assert first["pending_count"] == 1
    assert secret not in failure_text
    assert "[REDACTED]" in failure_text
    assert second["generated_success_count"] == 1
    assert second["pending_count"] == 0


@pytest.mark.parametrize(
    "mutate",
    [
        lambda response: response.update({"promptFeedback": {"blockReason": "SAFETY"}}),
        lambda response: response.pop("responseId"),
        lambda response: response["candidates"][0].update({"finishReason": "MAX_TOKENS"}),
        lambda response: response["candidates"][0]["content"]["parts"][0].update(
            {"text": "```json\n{}\n```"}
        ),
        lambda response: response["candidates"][0]["content"]["parts"][0].update(
            {"text": canonical_json({**_answer(), "classification": "harness-failure"})}
        ),
    ],
)
def test_rejects_invalid_provider_envelopes(tmp_path: Path, mutate):
    response = _provider_response()
    mutate(response)

    report = _run(tmp_path, lambda request, timeout: response)

    assert report["generated_success_count"] == 0
    assert report["failed_count"] == 1
    assert report["pending_count"] == 1
    assert not (tmp_path / "successes.jsonl").exists()
    assert _read_jsonl(tmp_path / "failures.jsonl")[0]["failure_kind"] == (
        "permanent_response"
    )


def test_rejects_tampered_resume_ledger(tmp_path: Path):
    _run(tmp_path, lambda request, timeout: _provider_response())
    successes = _read_jsonl(tmp_path / "successes.jsonl")
    successes[0]["target_sha256"] = "0" * 64
    _write_jsonl(tmp_path / "successes.jsonl", successes)

    with pytest.raises(TeacherGenerationError, match="receipt mismatch"):
        _run(tmp_path, lambda request, timeout: _provider_response())


def test_rejects_duplicate_provider_generation_id(tmp_path: Path):
    requests = [_request(0), _request(1)]

    report = _run(
        tmp_path,
        lambda request, timeout: _provider_response("duplicate-generation"),
        requests=requests,
    )

    assert report["generated_success_count"] == 1
    assert report["failed_count"] == 1
    assert report["pending_count"] == 1


def test_generator_ledger_is_signer_and_verifier_compatible(tmp_path: Path):
    request_path = tmp_path / "requests.jsonl"
    success_path = tmp_path / "successes.jsonl"
    provenance_root = tmp_path / "provenance"
    trusted_key_dir = tmp_path / "trusted"
    trusted_key_dir.mkdir()
    _write_jsonl(request_path, [_request()])
    generate_teacher_responses(
        requests_path=request_path,
        successes_path=success_path,
        failures_path=tmp_path / "failures.jsonl",
        api_key="secret-key",
        transport=lambda request, timeout: _provider_response(),
        clock=lambda: NOW,
    )
    signer = Ed25519VerdictSigner.generate()
    (trusted_key_dir / "teacher.pem").write_text(
        signer.public_key_pem,
        encoding="ascii",
    )
    provenance_root.mkdir()
    provenance_requests = provenance_root / "teacher_requests.jsonl"
    provenance_requests.write_bytes(request_path.read_bytes())

    report = sign_teacher_response_ledger(
        provenance_requests,
        success_path,
        provenance_root,
        signer,
        signer_identity="test-vertex-teacher-operator",
    )
    verified = verify_teacher_provenance(provenance_root, trusted_key_dir)

    assert report["response_count"] == 1
    assert len(verified["gs343"]) == 1
    assert verified["gs343"][0].answer == _answer()


def test_grok_generates_native_provider_receipt_and_resumes(tmp_path: Path):
    prompts = []

    def transport(prompt, timeout):
        prompts.append((prompt, timeout))
        return _grok_response()

    first = _run(
        tmp_path,
        transport,
        provider=GROK_PROVIDER,
        model="grok-4.5",
        api_key="",
    )
    second = _run(
        tmp_path,
        transport,
        provider=GROK_PROVIDER,
        model="grok-4.5",
        api_key="",
    )

    assert first["generated_success_count"] == 1
    assert second["existing_success_count"] == 1
    assert len(prompts) == 1
    assert GS_SYSTEM in prompts[0][0]
    success = _read_jsonl(tmp_path / "successes.jsonl")[0]
    assert success["provider"] == GROK_PROVIDER
    assert success["model"] == "grok-4.5"
    assert success["generation_id"] == "grok-request-1"
    assert success["provider_response"]["sessionId"] == "grok-session-1"
    assert "thought" not in success["provider_response"]


def test_xai_api_generation_is_concurrent_cost_bounded_and_verifiable(tmp_path: Path):
    requests = [_request(0), _request(1)]
    request_path = tmp_path / "requests.jsonl"
    success_path = tmp_path / "successes.jsonl"
    provenance_root = tmp_path / "provenance"
    trusted_key_dir = tmp_path / "trusted"
    trusted_key_dir.mkdir()
    _write_jsonl(request_path, requests)

    report = generate_teacher_responses(
        requests_path=request_path,
        successes_path=success_path,
        failures_path=tmp_path / "failures.jsonl",
        api_key="xai-secret",
        provider=XAI_API_PROVIDER,
        model="grok-4.5",
        concurrency=2,
        max_cost_usd=1.0,
        transport=lambda request, timeout: _xai_api_response(request),
        clock=lambda: NOW,
    )

    assert report["generated_success_count"] == 2
    assert report["failed_count"] == 0
    assert report["cost_usd"] == pytest.approx(0.001)
    successes = _read_jsonl(success_path)
    assert {row["provider"] for row in successes} == {XAI_API_PROVIDER}
    assert all(set(row["provider_response"]) == {"id", "model", "choices", "usage"} for row in successes)

    signer = Ed25519VerdictSigner.generate()
    (trusted_key_dir / "teacher.pem").write_text(
        signer.public_key_pem,
        encoding="ascii",
    )
    provenance_root.mkdir()
    provenance_requests = provenance_root / "teacher_requests.jsonl"
    provenance_requests.write_bytes(request_path.read_bytes())
    signed = sign_teacher_response_ledger(
        provenance_requests,
        success_path,
        provenance_root,
        signer,
        signer_identity="test-xai-api-teacher-operator",
    )
    verified = verify_teacher_provenance(provenance_root, trusted_key_dir)

    assert signed["response_count"] == 2
    assert len(verified["gs343"]) == 2


def test_xai_api_cost_preflight_fails_closed(tmp_path: Path):
    with pytest.raises(
        TeacherGenerationError,
        match="conservative cost estimate exceeds max_cost_usd",
    ):
        _run(
            tmp_path,
            lambda request, timeout: _xai_api_response(request),
            requests=[_request(0), _request(1)],
            provider=XAI_API_PROVIDER,
            model="grok-4.5",
            concurrency=2,
            max_cost_usd=0.001,
        )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda response: response.update({"text": "```json\n{}\n```"}),
        lambda response: response.pop("requestId"),
        lambda response: response.pop("sessionId"),
        lambda response: response.update({"stopReason": "MaxTokens"}),
        lambda response: response.update({"text": "not-json"}),
        lambda response: response.update(
            {
                "text": canonical_json(
                    {**_answer(), "classification": "harness-failure"}
                )
            }
        ),
    ],
)
def test_grok_rejects_invalid_provider_envelopes(tmp_path: Path, mutate):
    response = _grok_response()
    mutate(response)

    report = _run(
        tmp_path,
        lambda prompt, timeout: response,
        provider=GROK_PROVIDER,
        model="grok-4.5",
        api_key="",
    )

    assert report["generated_success_count"] == 0
    assert report["failed_count"] == 1
    assert not (tmp_path / "successes.jsonl").exists()


def test_grok_retries_response_contract_drift_within_same_run(tmp_path: Path):
    invalid = _grok_response("grok-invalid")
    invalid["text"] = canonical_json({**_answer(), "release_risk": "high"})
    responses = [invalid, _grok_response("grok-valid")]

    report = _run(
        tmp_path,
        lambda prompt, timeout: responses.pop(0),
        provider=GROK_PROVIDER,
        model="grok-4.5",
        api_key="",
        max_attempts=2,
    )

    assert report["generated_success_count"] == 1
    assert report["failed_count"] == 0
    assert not responses
    assert not (tmp_path / "failures.jsonl").exists()


def test_rejects_provider_mismatch_on_resume(tmp_path: Path):
    _run(tmp_path, lambda request, timeout: _provider_response())

    with pytest.raises(TeacherGenerationError, match="binding mismatch"):
        _run(
            tmp_path,
            lambda prompt, timeout: _grok_response(),
            provider=GROK_PROVIDER,
            model="grok-4.5",
            api_key="",
        )


def test_rejects_concurrent_ledger_writer(tmp_path: Path):
    lock_path = tmp_path / "successes.jsonl.lock"
    with teacher_generator._ledger_lock(lock_path):
        with pytest.raises(TeacherGenerationError, match="active writer"):
            _run(tmp_path, lambda request, timeout: _provider_response())


def test_ignores_unlocked_stale_ledger_lock_file(tmp_path: Path):
    lock_path = tmp_path / "successes.jsonl.lock"
    lock_path.write_text('{"stale":true}\n', encoding="utf-8")

    report = _run(tmp_path, lambda request, timeout: _provider_response())

    assert report["generated_success_count"] == 1


def test_grok_transport_uses_oidc_safe_headless_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    grok_cwd = tmp_path / "grok-repo"
    (grok_cwd / ".git").mkdir(parents=True)
    captured = {}
    monkeypatch.setenv("GROK_CODE_XAI_API_KEY", "strip-one")
    monkeypatch.setenv("GROK_API_KEY", "strip-two")
    monkeypatch.setenv("XAI_API_KEY", "strip-three")
    monkeypatch.setenv("UNRELATED_SECRET", "must-not-cross-boundary")

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=canonical_json(_grok_response()),
            stderr="",
        )

    monkeypatch.setattr(teacher_generator.subprocess, "run", fake_run)
    report = generate_teacher_responses(
        requests_path=_write_request_file(tmp_path),
        successes_path=tmp_path / "successes.jsonl",
        failures_path=tmp_path / "failures.jsonl",
        provider=GROK_PROVIDER,
        model="grok-4.5",
        grok_cwd=grok_cwd,
        clock=lambda: NOW,
    )

    assert report["generated_success_count"] == 1
    command = captured["command"]
    call_kwargs = captured["kwargs"]
    assert "--single" in command
    assert "--no-memory" in command
    assert "--no-subagents" in command
    assert "--verbatim" in command
    assert "--disable-web-search" in command
    assert "--always-approve" not in command
    assert command[command.index("--permission-mode") + 1] == "dontAsk"
    assert command[command.index("--tools") + 1] == ""
    assert "--max-turns" not in command
    assert call_kwargs["stdin"] is subprocess.DEVNULL
    assert all(
        name not in call_kwargs["env"]
        for name in ("GROK_CODE_XAI_API_KEY", "GROK_API_KEY", "XAI_API_KEY")
    )
    assert "UNRELATED_SECRET" not in call_kwargs["env"]


def test_grok_timeout_is_recorded_as_retryable_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    grok_cwd = tmp_path / "grok-repo"
    (grok_cwd / ".git").mkdir(parents=True)

    def timeout_run(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(teacher_generator.subprocess, "run", timeout_run)
    report = generate_teacher_responses(
        requests_path=_write_request_file(tmp_path),
        successes_path=tmp_path / "successes.jsonl",
        failures_path=tmp_path / "failures.jsonl",
        provider=GROK_PROVIDER,
        model="grok-4.5",
        grok_cwd=grok_cwd,
        max_attempts=1,
        clock=lambda: NOW,
    )

    assert report["failed_count"] == 1
    failure = _read_jsonl(tmp_path / "failures.jsonl")[0]
    assert failure["failure_kind"] == "transient_exhausted"
    assert "timed out" in failure["detail"]


def _write_request_file(root: Path) -> Path:
    path = root / "requests.jsonl"
    _write_jsonl(path, [_request()])
    return path
