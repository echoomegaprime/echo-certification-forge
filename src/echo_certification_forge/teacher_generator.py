"""Resumable, fail-closed teacher generation for P5 curricula."""

from __future__ import annotations

import json
import os
import random
import re
import socket
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from datetime import datetime
from functools import wraps
from pathlib import Path
from typing import Any

from .canonical import canonical_json, parse_utc_iso, sha256_json, to_utc_iso, utc_now
from .p5_corpus import (
    CorpusError,
    load_teacher_requests,
    validate_answer_request_link,
    validate_teacher_answer,
)

VERTEX_PROVIDER = "google-vertex-express"
GROK_PROVIDER = "xai-grok-cli-oidc"
XAI_API_PROVIDER = "xai-grok-api"
PROVIDER = VERTEX_PROVIDER
DEFAULT_MODEL = "gemini-2.5-pro"
DEFAULT_GROK_MODEL = "grok-4.5"
DEFAULT_XAI_API_MODEL = "grok-4.5"
ENDPOINT_TEMPLATE = (
    "https://aiplatform.googleapis.com/v1/publishers/google/models/"
    "{model}:generateContent"
)
XAI_API_ENDPOINT = "https://api.x.ai/v1/chat/completions"
USD_TICKS = 10_000_000_000
XAI_CONSERVATIVE_REQUEST_COST_USD = 0.0075
SUCCESS_SCHEMA = "p5-teacher-generation.v1"
FAILURE_SCHEMA = "p5-teacher-generation-failure.v1"
TRANSIENT_HTTP_STATUSES = frozenset({408, 409, 425, 429, 500, 502, 503, 504})
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

ProviderRequest = urllib.request.Request | str
Transport = Callable[[ProviderRequest, float], dict[str, Any]]
Clock = Callable[[], datetime]
Sleeper = Callable[[float], None]
Jitter = Callable[[], float]


class TeacherGenerationError(CorpusError):
    """Raised when generation or an existing ledger violates the contract."""


class _PermanentProviderError(Exception):
    pass


class _TransientProviderError(Exception):
    pass


def _append_jsonl(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(canonical_json(row) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


@contextmanager
def _ledger_lock(lock_path: Path):
    """Hold an advisory lock that the OS releases after process termination."""
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    stream = lock_path.open("a+b")
    try:
        stream.seek(0, os.SEEK_END)
        if stream.tell() == 0:
            stream.write(b"\0")
            stream.flush()
            os.fsync(stream.fileno())
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise TeacherGenerationError(
                f"teacher ledger already has an active writer: {lock_path}"
            ) from exc
        yield
    finally:
        try:
            stream.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        stream.close()


def _exclusive_ledger_writer(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        successes_path = Path(kwargs["successes_path"])
        lock_path = successes_path.with_suffix(successes_path.suffix + ".lock")
        with _ledger_lock(lock_path):
            return function(*args, **kwargs)

    return wrapper


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                raise TeacherGenerationError(f"{path}:{line_number}: blank JSONL row")
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise TeacherGenerationError(
                    f"{path}:{line_number}: malformed JSON"
                ) from exc
            if not isinstance(row, dict):
                raise TeacherGenerationError(f"{path}:{line_number}: row must be an object")
            rows.append(row)
    return rows


def _urllib_transport(
    request: ProviderRequest, timeout_seconds: float
) -> dict[str, Any]:
    if not isinstance(request, urllib.request.Request):
        raise TypeError("Vertex transport requires an HTTP request")
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        payload = response.read()
    try:
        decoded = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _PermanentProviderError("provider returned malformed JSON") from exc
    if not isinstance(decoded, dict):
        raise _PermanentProviderError("provider response must be a JSON object")
    return decoded


def _grok_prompt(request: dict[str, Any]) -> str:
    return (
        f"{request['system']}\n\n"
        f"{request['prompt']}\n\n"
        "Return strict JSON only. Do not use markdown fences, prose, or tools. "
        "Before returning, verify that every key matches the requested response "
        "contract and every enum value is one of the literal choices shown in "
        "the schema; never paraphrase enum values."
    )


def _grok_transport(
    request: ProviderRequest,
    timeout_seconds: float,
    *,
    command: str,
    cwd: Path,
    model: str,
) -> dict[str, Any]:
    if not isinstance(request, str):
        raise TypeError("Grok transport requires a prompt string")
    if not (cwd / ".git").is_dir():
        raise TeacherGenerationError(
            "Grok working directory must be a dedicated Git repository"
        )
    allowed_env = {
        "APPDATA",
        "COMSPEC",
        "HOME",
        "HOMEDRIVE",
        "HOMEPATH",
        "LANG",
        "LC_ALL",
        "LOCALAPPDATA",
        "NO_COLOR",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TERM",
        "TMP",
        "USERPROFILE",
        "WINDIR",
    }
    env = {name: value for name, value in os.environ.items() if name in allowed_env}
    try:
        completed = subprocess.run(
            [
                command,
                "--cwd",
                str(cwd),
                "--model",
                model,
                "--no-memory",
                "--no-subagents",
                "--verbatim",
                "--single",
                request,
                "--permission-mode",
                "dontAsk",
                "--tools",
                "",
                "--output-format",
                "json",
                "--reasoning-effort",
                "low",
                "--disable-web-search",
            ],
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise _TransientProviderError("Grok CLI timed out") from exc
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise _TransientProviderError(
            f"Grok CLI exited with status {completed.returncode}: {detail[:300]}"
        )
    try:
        decoded = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise _PermanentProviderError("Grok CLI returned malformed JSON") from exc
    if not isinstance(decoded, dict):
        raise _PermanentProviderError("Grok CLI response must be a JSON object")
    return decoded


def _normalize_provider_response(
    provider: str, response: dict[str, Any]
) -> dict[str, Any]:
    if provider == GROK_PROVIDER:
        allowed = ("text", "stopReason", "requestId", "sessionId")
        return {name: response[name] for name in allowed if name in response}
    if provider == XAI_API_PROVIDER:
        allowed = ("id", "model", "choices", "usage")
        return {name: response[name] for name in allowed if name in response}
    return response


def _request_payload(request: dict[str, Any]) -> bytes:
    payload = {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": request["prompt"]}],
            }
        ],
        "systemInstruction": {
            "parts": [{"text": request["system"]}],
        },
        "generationConfig": {
            "candidateCount": 1,
            "responseMimeType": "application/json",
            "temperature": 0.2,
        },
    }
    return canonical_json(payload).encode("utf-8")


def _xai_contract_reminder(adapter: str) -> str:
    if adapter == "gs343":
        return (
            " Contract reminders: root_causes and repair_actions must be non-empty. "
            "release_risk must be conditional for harness-defect, environment-defect, "
            "or test-data-defect and block for every other class. For multi-cause, "
            "root_causes must explicitly contain both application and harness causes. "
            "Inconclusive requires abstain=true, confidence below 0.6, and at least one "
            "root_causes entry describing why the evidence cannot be trusted. "
            "target_mutation_allowed is always false."
        )
    return (
        " Contract reminders: recommended_action must be non-empty; persona_markers "
        "must include the exact strings R2-D2, diagnostic-beep, and presentation-only; "
        "facts_preserved must equal, in order and verbatim, the semicolon-separated "
        "facts after 'Verified finding envelope: ' and before the narration suffix; "
        "invented_facts must be empty; changes_verdict must be false."
    )


def _xai_request_payload(request: dict[str, Any], model: str) -> bytes:
    contract = _xai_contract_reminder(str(request["adapter"]))
    if request["adapter"] == "r2d2":
        fact_blob = str(request["prompt"])[len("Verified finding envelope: ") :]
        for suffix in (". Narrate without", ". Preserve the condition."):
            if suffix in fact_blob:
                fact_blob = fact_blob.split(suffix, 1)[0]
                break
        expected_facts = [item.strip() for item in fact_blob.split(";")]
        contract += (
            " The exact facts_preserved JSON array for this request is: "
            + canonical_json(expected_facts)
            + "."
        )
    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": request["system"] + contract,
            },
            {
                "role": "user",
                "content": request["prompt"]
                + "\nReturn strict JSON only. Verify every enum and contract field.",
            },
        ],
        "temperature": 0.0,
        "max_tokens": 500,
        "reasoning_effort": "low",
        "response_format": {"type": "json_object"},
    }
    return canonical_json(payload).encode("utf-8")


def _parse_vertex_response(
    provider_response: dict[str, Any],
    request: dict[str, Any],
) -> tuple[dict[str, Any], str, str]:
    prompt_feedback = provider_response.get("promptFeedback")
    if isinstance(prompt_feedback, dict) and prompt_feedback.get("blockReason"):
        raise _PermanentProviderError("provider blocked the request")

    generation_id = provider_response.get("responseId")
    model_version = provider_response.get("modelVersion")
    if not isinstance(generation_id, str) or not generation_id.strip():
        raise _PermanentProviderError("provider responseId is missing")
    if not isinstance(model_version, str) or not model_version.strip():
        raise _PermanentProviderError("provider modelVersion is missing")

    candidates = provider_response.get("candidates")
    if not isinstance(candidates, list) or len(candidates) != 1:
        raise _PermanentProviderError("provider must return exactly one candidate")
    candidate = candidates[0]
    if not isinstance(candidate, dict) or candidate.get("finishReason") != "STOP":
        raise _PermanentProviderError("provider candidate did not finish successfully")
    content = candidate.get("content")
    parts = content.get("parts") if isinstance(content, dict) else None
    if not isinstance(parts, list):
        raise _PermanentProviderError("provider candidate has no content parts")
    text_parts = [
        part["text"]
        for part in parts
        if isinstance(part, dict) and isinstance(part.get("text"), str)
    ]
    if len(text_parts) != 1 or not text_parts[0].strip():
        raise _PermanentProviderError("provider must return one non-empty text part")
    raw_text = text_parts[0]
    if "```" in raw_text:
        raise _PermanentProviderError("fenced JSON is forbidden")
    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise _PermanentProviderError("provider text is not strict JSON") from exc
    try:
        answer = validate_teacher_answer(
            str(request["adapter"]), parsed, f"request {request['request_id']}"
        )
        validate_answer_request_link(
            request, answer, f"request {request['request_id']}"
        )
    except CorpusError as exc:
        raise _PermanentProviderError(str(exc)) from exc
    return answer, generation_id, model_version


def _parse_grok_response(
    provider_response: dict[str, Any],
    request: dict[str, Any],
    model: str,
) -> tuple[dict[str, Any], str, str]:
    generation_id = provider_response.get("requestId")
    session_id = provider_response.get("sessionId")
    if not isinstance(generation_id, str) or not generation_id.strip():
        raise _PermanentProviderError("Grok requestId is missing")
    if not isinstance(session_id, str) or not session_id.strip():
        raise _PermanentProviderError("Grok sessionId is missing")
    if provider_response.get("stopReason") != "EndTurn":
        raise _PermanentProviderError("Grok response did not finish successfully")
    raw_text = provider_response.get("text")
    if not isinstance(raw_text, str) or not raw_text.strip():
        raise _PermanentProviderError("Grok response text is missing")
    if "```" in raw_text:
        raise _PermanentProviderError("fenced JSON is forbidden")
    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise _PermanentProviderError("Grok response text is not strict JSON") from exc
    try:
        answer = validate_teacher_answer(
            str(request["adapter"]), parsed, f"request {request['request_id']}"
        )
        validate_answer_request_link(
            request, answer, f"request {request['request_id']}"
        )
    except CorpusError as exc:
        raise _PermanentProviderError(str(exc)) from exc
    return answer, generation_id, model


def _parse_xai_api_response(
    provider_response: dict[str, Any],
    request: dict[str, Any],
) -> tuple[dict[str, Any], str, str]:
    generation_id = provider_response.get("id")
    model_version = provider_response.get("model")
    if not isinstance(generation_id, str) or not generation_id.strip():
        raise _PermanentProviderError("xAI response id is missing")
    if not isinstance(model_version, str) or not model_version.strip():
        raise _PermanentProviderError("xAI response model is missing")
    choices = provider_response.get("choices")
    if not isinstance(choices, list) or len(choices) != 1:
        raise _PermanentProviderError("xAI must return exactly one choice")
    choice = choices[0]
    if not isinstance(choice, dict) or choice.get("finish_reason") != "stop":
        raise _PermanentProviderError("xAI choice did not finish successfully")
    message = choice.get("message")
    raw_text = message.get("content") if isinstance(message, dict) else None
    if not isinstance(raw_text, str) or not raw_text.strip():
        raise _PermanentProviderError("xAI response content is missing")
    if "```" in raw_text:
        raise _PermanentProviderError("fenced JSON is forbidden")
    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise _PermanentProviderError("xAI response content is not strict JSON") from exc
    try:
        answer = validate_teacher_answer(
            str(request["adapter"]), parsed, f"request {request['request_id']}"
        )
        validate_answer_request_link(
            request, answer, f"request {request['request_id']}"
        )
    except CorpusError as exc:
        raise _PermanentProviderError(str(exc)) from exc
    usage = provider_response.get("usage")
    cost_ticks = usage.get("cost_in_usd_ticks") if isinstance(usage, dict) else None
    if (
        not isinstance(cost_ticks, int)
        or isinstance(cost_ticks, bool)
        or cost_ticks < 0
    ):
        raise _PermanentProviderError("xAI response lacks exact cost accounting")
    return answer, generation_id, model_version


def _parse_provider_response(
    provider_response: dict[str, Any],
    request: dict[str, Any],
    provider: str,
    model: str,
) -> tuple[dict[str, Any], str, str]:
    if provider == VERTEX_PROVIDER:
        return _parse_vertex_response(provider_response, request)
    if provider == GROK_PROVIDER:
        return _parse_grok_response(provider_response, request, model)
    if provider == XAI_API_PROVIDER:
        return _parse_xai_api_response(provider_response, request)
    raise _PermanentProviderError(f"unsupported provider: {provider}")


def _success_core(
    *,
    request: dict[str, Any],
    model: str,
    generated_at: str,
    answer: dict[str, Any],
    generation_id: str,
    model_version: str,
    provider_response: dict[str, Any],
    provider: str,
) -> dict[str, Any]:
    raw_response = canonical_json(answer)
    return {
        "schema_version": SUCCESS_SCHEMA,
        "request_id": request["request_id"],
        "request_sha256": request["request_sha256"],
        "adapter": request["adapter"],
        "provider": provider,
        "model": model,
        "model_version": model_version,
        "generation_id": generation_id,
        "generated_at_utc": generated_at,
        "raw_response": raw_response,
        "raw_response_sha256": sha256_json(answer),
        "target_sha256": sha256_json(answer),
        "provider_response": provider_response,
        "provider_response_sha256": sha256_json(provider_response),
    }


def _validate_success_ledger(
    path: Path,
    request_by_id: dict[str, dict[str, Any]],
    provider: str,
    model: str,
) -> tuple[dict[str, dict[str, Any]], set[str]]:
    successes: dict[str, dict[str, Any]] = {}
    generation_ids: set[str] = set()
    required = {
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
    for index, row in enumerate(_read_jsonl(path), start=1):
        prefix = f"{path}:{index}"
        if set(row) != required:
            raise TeacherGenerationError(f"{prefix}: success row keys differ from contract")
        request_id = row.get("request_id")
        if not isinstance(request_id, str) or request_id not in request_by_id:
            raise TeacherGenerationError(f"{prefix}: foreign request_id")
        if request_id in successes:
            raise TeacherGenerationError(f"{prefix}: duplicate request_id")
        request = request_by_id[request_id]
        if (
            row.get("schema_version") != SUCCESS_SCHEMA
            or row.get("request_sha256") != request["request_sha256"]
            or row.get("adapter") != request["adapter"]
            or row.get("provider") != provider
            or row.get("model") != model
        ):
            raise TeacherGenerationError(f"{prefix}: request or model binding mismatch")
        generation_id = row.get("generation_id")
        if not isinstance(generation_id, str) or not generation_id.strip():
            raise TeacherGenerationError(f"{prefix}: missing generation_id")
        if generation_id in generation_ids:
            raise TeacherGenerationError(f"{prefix}: duplicate generation_id")
        try:
            parse_utc_iso(str(row["generated_at_utc"]))
            answer = json.loads(str(row["raw_response"]))
            validated = validate_teacher_answer(str(request["adapter"]), answer, prefix)
            validate_answer_request_link(request, validated, prefix)
            extracted, extracted_id, extracted_version = _parse_provider_response(
                row["provider_response"], request, provider, model
            )
        except (ValueError, json.JSONDecodeError, CorpusError, _PermanentProviderError) as exc:
            raise TeacherGenerationError(f"{prefix}: invalid success content") from exc
        if (
            row.get("model_version") != extracted_version
            or generation_id != extracted_id
            or validated != extracted
            or str(row["raw_response"]) != canonical_json(validated)
            or row.get("raw_response_sha256") != sha256_json(validated)
            or row.get("target_sha256") != sha256_json(validated)
            or row.get("provider_response_sha256")
            != sha256_json(row["provider_response"])
        ):
            raise TeacherGenerationError(f"{prefix}: content-addressed receipt mismatch")
        unsigned = dict(row)
        claimed_record_sha = unsigned.pop("record_sha256")
        if claimed_record_sha != sha256_json(unsigned):
            raise TeacherGenerationError(f"{prefix}: record digest mismatch")
        successes[request_id] = row
        generation_ids.add(generation_id)
    return successes, generation_ids


def _validate_failure_ledger(
    path: Path,
    request_by_id: dict[str, dict[str, Any]],
    provider: str,
    model: str,
) -> None:
    required = {
        "schema_version",
        "request_id",
        "request_sha256",
        "adapter",
        "provider",
        "model",
        "failed_at_utc",
        "attempt_count",
        "failure_kind",
        "retryable_on_later_run",
        "detail",
        "record_sha256",
    }
    for index, row in enumerate(_read_jsonl(path), start=1):
        prefix = f"{path}:{index}"
        request = request_by_id.get(str(row.get("request_id", "")))
        if set(row) != required or request is None:
            raise TeacherGenerationError(f"{prefix}: invalid failure row")
        if (
            row.get("schema_version") != FAILURE_SCHEMA
            or row.get("request_sha256") != request["request_sha256"]
            or row.get("adapter") != request["adapter"]
            or row.get("provider") != provider
            or row.get("model") != model
            or row.get("retryable_on_later_run") is not True
            or not isinstance(row.get("attempt_count"), int)
            or row["attempt_count"] < 1
            or not isinstance(row.get("detail"), str)
        ):
            raise TeacherGenerationError(f"{prefix}: failure binding mismatch")
        try:
            parse_utc_iso(str(row["failed_at_utc"]))
        except ValueError as exc:
            raise TeacherGenerationError(f"{prefix}: invalid failure timestamp") from exc
        unsigned = dict(row)
        claimed_record_sha = unsigned.pop("record_sha256")
        if claimed_record_sha != sha256_json(unsigned):
            raise TeacherGenerationError(f"{prefix}: failure digest mismatch")


def _safe_detail(error: BaseException, secrets: tuple[str, ...]) -> str:
    if isinstance(error, urllib.error.HTTPError):
        detail = f"http_status={error.code}; reason={error.reason}"
    else:
        detail = f"{type(error).__name__}: {error}"
    for secret in secrets:
        if secret:
            detail = detail.replace(secret, "[REDACTED]")
    return detail[:500]


def _failure_row(
    *,
    request: dict[str, Any],
    model: str,
    failed_at: str,
    attempt_count: int,
    failure_kind: str,
    detail: str,
    provider: str,
) -> dict[str, Any]:
    row = {
        "schema_version": FAILURE_SCHEMA,
        "request_id": request["request_id"],
        "request_sha256": request["request_sha256"],
        "adapter": request["adapter"],
        "provider": provider,
        "model": model,
        "failed_at_utc": failed_at,
        "attempt_count": attempt_count,
        "failure_kind": failure_kind,
        "retryable_on_later_run": True,
        "detail": detail,
    }
    row["record_sha256"] = sha256_json(row)
    return row


@_exclusive_ledger_writer
def generate_teacher_responses(
    *,
    requests_path: Path,
    successes_path: Path,
    failures_path: Path,
    api_key: str = "",
    provider: str = VERTEX_PROVIDER,
    model: str = DEFAULT_MODEL,
    timeout_seconds: float = 120.0,
    max_attempts: int = 5,
    base_backoff_seconds: float = 1.0,
    max_backoff_seconds: float = 30.0,
    transport: Transport | None = None,
    grok_command: str = "grok",
    grok_cwd: Path | None = None,
    concurrency: int = 1,
    max_cost_usd: float = 25.0,
    clock: Clock = utc_now,
    sleeper: Sleeper = time.sleep,
    jitter: Jitter = random.random,
) -> dict[str, Any]:
    """Generate all missing responses while preserving append-only receipts."""
    if provider not in {VERTEX_PROVIDER, GROK_PROVIDER, XAI_API_PROVIDER}:
        raise TeacherGenerationError(f"unsupported teacher provider: {provider}")
    if provider in {VERTEX_PROVIDER, XAI_API_PROVIDER} and not api_key.strip():
        raise TeacherGenerationError(f"{provider} API key must be non-empty")
    if provider == GROK_PROVIDER and transport is None and grok_cwd is None:
        raise TeacherGenerationError("Grok working directory is required")
    if not _MODEL_RE.fullmatch(model):
        raise TeacherGenerationError("model contains unsupported characters")
    if timeout_seconds <= 0 or max_attempts < 1:
        raise TeacherGenerationError("timeout and max_attempts must be positive")
    if base_backoff_seconds < 0 or max_backoff_seconds < base_backoff_seconds:
        raise TeacherGenerationError("invalid backoff bounds")
    if concurrency < 1 or concurrency > 64:
        raise TeacherGenerationError("concurrency must be between 1 and 64")
    if max_cost_usd <= 0:
        raise TeacherGenerationError("max_cost_usd must be positive")

    requests = load_teacher_requests(requests_path)
    request_by_id = {str(row["request_id"]): row for row in requests}
    successes, generation_ids = _validate_success_ledger(
        successes_path, request_by_id, provider, model
    )
    _validate_failure_ledger(failures_path, request_by_id, provider, model)
    existing_count = len(successes)
    generated_count = 0
    failed_count = 0
    cost_ticks = sum(
        int(row.get("provider_response", {}).get("usage", {}).get("cost_in_usd_ticks", 0))
        for row in successes.values()
        if row.get("provider") == XAI_API_PROVIDER
    )
    endpoint = ENDPOINT_TEMPLATE.format(model=model)
    if transport is None:
        if provider in {VERTEX_PROVIDER, XAI_API_PROVIDER}:
            transport = _urllib_transport
        else:
            assert grok_cwd is not None

            def grok_transport(
                prompt: ProviderRequest, timeout: float
            ) -> dict[str, Any]:
                return _grok_transport(
                    prompt,
                    timeout,
                    command=grok_command,
                    cwd=grok_cwd,
                    model=model,
                )

            transport = grok_transport
    pending = [
        teacher_request
        for teacher_request in requests
        if str(teacher_request["request_id"]) not in successes
    ]
    if (
        provider == XAI_API_PROVIDER
        and len(pending) * XAI_CONSERVATIVE_REQUEST_COST_USD
        + cost_ticks / USD_TICKS
        > max_cost_usd
    ):
        raise TeacherGenerationError(
            "xAI conservative cost estimate exceeds max_cost_usd"
        )

    def generate_one(
        teacher_request: dict[str, Any],
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        if provider == VERTEX_PROVIDER:
            provider_request: ProviderRequest = urllib.request.Request(
                endpoint,
                data=_request_payload(teacher_request),
                headers={
                    "Content-Type": "application/json",
                    "x-goog-api-key": api_key,
                },
                method="POST",
            )
        elif provider == XAI_API_PROVIDER:
            provider_request = urllib.request.Request(
                XAI_API_ENDPOINT,
                data=_xai_request_payload(teacher_request, model),
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
        else:
            provider_request = _grok_prompt(teacher_request)
        last_error: BaseException | None = None
        failure_kind = ""
        for attempt in range(1, max_attempts + 1):
            try:
                provider_response = transport(provider_request, timeout_seconds)
                if not isinstance(provider_response, dict):
                    raise _PermanentProviderError(
                        "transport returned a non-object provider response"
                    )
                provider_response = _normalize_provider_response(
                    provider, provider_response
                )
                try:
                    answer, generation_id, model_version = _parse_provider_response(
                        provider_response, teacher_request, provider, model
                    )
                except _PermanentProviderError as exc:
                    if provider not in {GROK_PROVIDER, XAI_API_PROVIDER}:
                        raise
                    raise _TransientProviderError(
                        f"Grok response contract validation failed: {exc}"
                    ) from exc
                core = _success_core(
                    request=teacher_request,
                    model=model,
                    generated_at=to_utc_iso(clock()),
                    answer=answer,
                    generation_id=generation_id,
                    model_version=model_version,
                    provider_response=provider_response,
                    provider=provider,
                )
                core["record_sha256"] = sha256_json(core)
                return core, None
            except _PermanentProviderError as exc:
                last_error = exc
                failure_kind = "permanent_response"
                break
            except urllib.error.HTTPError as exc:
                last_error = exc
                if exc.code not in TRANSIENT_HTTP_STATUSES:
                    failure_kind = "permanent_http"
                    break
            except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
                last_error = exc
            except _TransientProviderError as exc:
                last_error = exc
            if attempt < max_attempts:
                delay = min(
                    max_backoff_seconds,
                    base_backoff_seconds * (2 ** (attempt - 1)),
                )
                sleeper(delay * (0.5 + 0.5 * jitter()))
        if last_error is not None:
            if failure_kind not in {
                "permanent_response",
                "permanent_http",
            }:
                failure_kind = "transient_exhausted"
            row = _failure_row(
                request=teacher_request,
                model=model,
                failed_at=to_utc_iso(clock()),
                attempt_count=attempt,
                failure_kind=failure_kind,
                detail=_safe_detail(last_error, (api_key,)),
                provider=provider,
            )
            return None, row
        raise AssertionError("teacher request ended without success or failure")

    worker_count = concurrency if provider == XAI_API_PROVIDER else 1
    if worker_count == 1:
        results = (generate_one(request) for request in pending)
        for core, failure in results:
            if core is not None:
                generation_id = str(core["generation_id"])
                if generation_id in generation_ids:
                    duplicate = _failure_row(
                        request=request_by_id[str(core["request_id"])],
                        model=model,
                        failed_at=to_utc_iso(clock()),
                        attempt_count=1,
                        failure_kind="permanent_response",
                        detail="duplicate provider generation_id",
                        provider=provider,
                    )
                    _append_jsonl(failures_path, duplicate)
                    failed_count += 1
                    continue
                if provider == XAI_API_PROVIDER:
                    cost_ticks += int(
                        core["provider_response"]["usage"]["cost_in_usd_ticks"]
                    )
                    if cost_ticks / USD_TICKS > max_cost_usd:
                        raise TeacherGenerationError("xAI generation exceeded max_cost_usd")
                _append_jsonl(successes_path, core)
                successes[str(core["request_id"])] = core
                generation_ids.add(generation_id)
                generated_count += 1
            else:
                assert failure is not None
                _append_jsonl(failures_path, failure)
                failed_count += 1
    else:
        with ThreadPoolExecutor(max_workers=worker_count) as pool:
            futures = {pool.submit(generate_one, request): request for request in pending}
            for future in as_completed(futures):
                core, failure = future.result()
                if core is not None:
                    generation_id = str(core["generation_id"])
                    if generation_id in generation_ids:
                        duplicate = _failure_row(
                            request=request_by_id[str(core["request_id"])],
                            model=model,
                            failed_at=to_utc_iso(clock()),
                            attempt_count=1,
                            failure_kind="permanent_response",
                            detail="duplicate provider generation_id",
                            provider=provider,
                        )
                        _append_jsonl(failures_path, duplicate)
                        failed_count += 1
                        continue
                    cost_ticks += int(
                        core["provider_response"]["usage"]["cost_in_usd_ticks"]
                    )
                    if cost_ticks / USD_TICKS > max_cost_usd:
                        raise TeacherGenerationError("xAI generation exceeded max_cost_usd")
                    _append_jsonl(successes_path, core)
                    successes[str(core["request_id"])] = core
                    generation_ids.add(generation_id)
                    generated_count += 1
                else:
                    assert failure is not None
                    _append_jsonl(failures_path, failure)
                    failed_count += 1

    completed_count = len(successes)
    return {
        "request_count": len(requests),
        "existing_success_count": existing_count,
        "generated_success_count": generated_count,
        "completed_success_count": completed_count,
        "failed_count": failed_count,
        "pending_count": len(requests) - completed_count,
        "successes_path": str(successes_path),
        "failures_path": str(failures_path),
        "provider": provider,
        "model": model,
        "cost_usd": cost_ticks / USD_TICKS,
    }
