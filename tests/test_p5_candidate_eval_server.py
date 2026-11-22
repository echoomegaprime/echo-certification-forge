import importlib.util
import json
import sys
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "serve_p5_candidate_eval.py"
SPEC = importlib.util.spec_from_file_location("serve_p5_candidate_eval", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def adapter(root: Path, relative: str, content: bytes) -> None:
    directory = root / relative
    directory.mkdir(parents=True)
    (directory / MODULE.MODEL_FILENAME).write_bytes(content)
    (directory / MODULE.CONFIG_FILENAME).write_text("{}\n", encoding="utf-8")


def eval_adapters() -> tuple:
    return (
        MODULE.EvalAdapter("echo-gs343-incumbent", "gs343", "incumbent", "gs-old"),
        MODULE.EvalAdapter("echo-gs343-candidate", "gs343", "candidate", "gs-new"),
        MODULE.EvalAdapter("echo-r2d2-incumbent", "r2d2", "incumbent", "r2-old"),
        MODULE.EvalAdapter("echo-r2d2-candidate", "r2d2", "candidate", "r2-new"),
    )


def test_registry_pins_all_four_artifact_digests(tmp_path: Path) -> None:
    for relative, content in (
        ("gs-old", b"gs-old"),
        ("gs-new", b"gs-new"),
        ("r2-old", b"r2-old"),
        ("r2-new", b"r2-new"),
    ):
        adapter(tmp_path, relative, content)

    registry, adapter_map = MODULE.build_registry(tmp_path, eval_adapters())
    assert set(adapter_map) == {
        "echo-gs343-incumbent",
        "echo-gs343-candidate",
        "echo-r2d2-incumbent",
        "echo-r2d2-candidate",
    }
    assert len(registry["personas"]) == 4
    for row in registry["personas"]:
        model = tmp_path / row["adapter_relative_path"] / MODULE.MODEL_FILENAME
        config = tmp_path / row["adapter_relative_path"] / MODULE.CONFIG_FILENAME
        assert row["adapter_artifact_digest"] == MODULE.sha256_file(model)
        assert row["adapter_config_digest"] == MODULE.sha256_file(config)
        assert row["adapter_bundle_digest"] == MODULE.adapter_bundle_digest(
            row["adapter_artifact_digest"],
            row["adapter_config_digest"],
        )
        assert row["adapter_id"] == row["requested_model"]
        assert len(row["registry_revision"]) == 64


def test_adapter_path_cannot_escape_root(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-adapter"
    adapter(tmp_path.parent, outside.name, b"outside")
    with pytest.raises(ValueError, match="escapes root"):
        MODULE.resolve_adapter(tmp_path, f"../{outside.name}")


def test_registry_revision_changes_with_candidate_artifact(tmp_path: Path) -> None:
    for relative in ("gs-old", "gs-new", "r2-old", "r2-new"):
        adapter(tmp_path, relative, relative.encode())
    first, _ = MODULE.build_registry(tmp_path, eval_adapters())
    (tmp_path / "gs-new" / MODULE.MODEL_FILENAME).write_bytes(b"changed")
    second, _ = MODULE.build_registry(tmp_path, eval_adapters())
    assert first["registry_revision"] != second["registry_revision"]


def test_registry_revision_changes_with_adapter_configuration(tmp_path: Path) -> None:
    for relative in ("gs-old", "gs-new", "r2-old", "r2-new"):
        adapter(tmp_path, relative, relative.encode())
    first, _ = MODULE.build_registry(tmp_path, eval_adapters())
    (tmp_path / "gs-new" / MODULE.CONFIG_FILENAME).write_text(
        '{"r":32}\n',
        encoding="utf-8",
    )
    second, _ = MODULE.build_registry(tmp_path, eval_adapters())
    assert first["registry_revision"] != second["registry_revision"]


def test_atomic_json_is_canonical_and_complete(tmp_path: Path) -> None:
    output = tmp_path / "registry.json"
    MODULE.write_json_atomic(output, {"z": 1, "a": {"x": True}})
    raw = output.read_bytes()
    assert raw == b'{"a":{"x":true},"z":1}\n'
    assert json.loads(raw) == {"a": {"x": True}, "z": 1}
    assert not list(tmp_path.glob(".registry.json.*"))


def test_output_directory_must_be_new_and_isolated(tmp_path: Path) -> None:
    protected = tmp_path / "production"
    protected.mkdir()
    with pytest.raises(ValueError, match="overlaps protected"):
        MODULE.create_isolated_output_dir(
            protected / "eval",
            (protected,),
        )
    output = MODULE.create_isolated_output_dir(
        tmp_path / "isolated-eval",
        (protected,),
    )
    assert output.is_dir()
    with pytest.raises(FileExistsError):
        MODULE.create_isolated_output_dir(output, (protected,))


def test_server_requires_exactly_four_loaded_aliases() -> None:
    class Family:
        STATE = {"loaded": list(item.requested_model for item in eval_adapters())}

    expected = set(Family.STATE["loaded"])
    MODULE.assert_exact_loaded_aliases(Family, expected)
    Family.STATE["loaded"].pop()
    with pytest.raises(RuntimeError, match="exactly the required aliases"):
        MODULE.assert_exact_loaded_aliases(Family, expected)
