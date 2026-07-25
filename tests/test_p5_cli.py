from pathlib import Path

import pytest

from echo_certification_forge.teacher_generator import (
    GROK_PROVIDER,
    TeacherGenerationError,
)
from scripts import build_p5_corrective_corpora


def _generation_args(tmp_path: Path) -> list[str]:
    return [
        "generate-teacher-responses",
        "--requests",
        str(tmp_path / "requests.jsonl"),
        "--successes",
        str(tmp_path / "successes.jsonl"),
        "--failures",
        str(tmp_path / "failures.jsonl"),
    ]


def test_generate_command_rejects_missing_api_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.delenv("VERTEX_EXPRESS_API_KEY", raising=False)

    with pytest.raises(TeacherGenerationError, match="environment variable is unset"):
        build_p5_corrective_corpora.main(_generation_args(tmp_path))


def test_generate_command_rejects_incomplete_ledger(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("VERTEX_EXPRESS_API_KEY", "test-secret")
    monkeypatch.setattr(
        build_p5_corrective_corpora,
        "generate_teacher_responses",
        lambda **kwargs: {
            "request_count": 2,
            "existing_success_count": 0,
            "generated_success_count": 1,
            "completed_success_count": 1,
            "failed_count": 1,
            "pending_count": 1,
        },
    )

    with pytest.raises(TeacherGenerationError, match="response ledger is incomplete"):
        build_p5_corrective_corpora.main(_generation_args(tmp_path))


def test_grok_generate_command_does_not_require_vertex_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.delenv("VERTEX_EXPRESS_API_KEY", raising=False)
    received = {}
    monkeypatch.setattr(
        build_p5_corrective_corpora,
        "generate_teacher_responses",
        lambda **kwargs: received.update(kwargs)
        or {
            "request_count": 1,
            "existing_success_count": 0,
            "generated_success_count": 1,
            "completed_success_count": 1,
            "failed_count": 0,
            "pending_count": 0,
        },
    )

    result = build_p5_corrective_corpora.main(
        _generation_args(tmp_path)
        + ["--provider", GROK_PROVIDER, "--grok-cwd", str(tmp_path)]
    )

    assert result == 0
    assert received["provider"] == GROK_PROVIDER
    assert received["model"] == "grok-4.5"
    assert received["api_key"] == ""
