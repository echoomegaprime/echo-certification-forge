from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "build_p4_evidence_index.py"
SOURCE_COMMIT = "b9f93c922ccbaa0deab2d9356f3faf329d4ab6e1"


def load_builder():
    spec = importlib.util.spec_from_file_location("build_p4_evidence_index_test", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixture_files(tmp_path: Path, *, report_passed: bool = True) -> tuple[Path, Path, Path]:
    report = tmp_path / "report.json"
    manifest = tmp_path / "manifest.json"
    extra = tmp_path / "verification.json"
    report.write_text(
        json.dumps(
            {
                "passed": report_passed,
                "run_outcome": "COMPLETE" if report_passed else "INFRA_FAILED",
                "release_verdict": "NOT_READY",
                "source_commit": SOURCE_COMMIT,
            }
        ),
        encoding="utf-8",
    )
    manifest.write_text(json.dumps({"source_commit": SOURCE_COMMIT}), encoding="utf-8")
    extra.write_text(json.dumps({"passed": True}), encoding="utf-8")
    return report, manifest, extra


def test_build_index_is_sorted_and_hash_bound(tmp_path: Path, monkeypatch) -> None:
    builder = load_builder()
    monkeypatch.setattr(builder, "ROOT", tmp_path)
    report, manifest, extra = fixture_files(tmp_path)

    index = builder.build_index(
        source_commit=SOURCE_COMMIT,
        report_path=report,
        manifest_path=manifest,
        extra_paths=[extra, report],
    )

    paths = [item["path"] for item in index["files"]]
    assert paths == sorted(set(paths))
    assert index["completed_phase_gate"] == "P4"
    assert index["run_outcome"] == "COMPLETE"
    assert index["release_verdict"] == "NOT_READY"
    assert index["acceptance_report"]["sha256"] == builder.sha256_file(report)
    assert index["image_manifest"]["sha256"] == builder.sha256_file(manifest)


def test_build_index_rejects_nonpassing_report(tmp_path: Path, monkeypatch) -> None:
    builder = load_builder()
    monkeypatch.setattr(builder, "ROOT", tmp_path)
    report, manifest, _ = fixture_files(tmp_path, report_passed=False)

    with pytest.raises(ValueError, match="not a complete passing run"):
        builder.build_index(
            source_commit=SOURCE_COMMIT,
            report_path=report,
            manifest_path=manifest,
            extra_paths=[],
        )


def test_build_index_rejects_source_commit_mismatch(tmp_path: Path, monkeypatch) -> None:
    builder = load_builder()
    monkeypatch.setattr(builder, "ROOT", tmp_path)
    report, manifest, _ = fixture_files(tmp_path)
    manifest.write_text(json.dumps({"source_commit": "0" * 40}), encoding="utf-8")

    with pytest.raises(ValueError, match="image manifest source commit mismatch"):
        builder.build_index(
            source_commit=SOURCE_COMMIT,
            report_path=report,
            manifest_path=manifest,
            extra_paths=[],
        )


def test_repository_relative_rejects_escape(tmp_path: Path, monkeypatch) -> None:
    builder = load_builder()
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(builder, "ROOT", repo)

    with pytest.raises(ValueError, match="outside repository"):
        builder.repository_relative(outside)
