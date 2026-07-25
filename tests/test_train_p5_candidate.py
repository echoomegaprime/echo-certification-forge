from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[1] / "scripts" / "train_p5_candidate.py"
SPEC = importlib.util.spec_from_file_location("train_p5_candidate", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _row(row_id: str) -> dict:
    return {
        "id": row_id,
        "messages": [
            {"role": "system", "content": "system contract"},
            {"role": "user", "content": "input"},
            {"role": "assistant", "content": "output"},
        ],
    }


def test_recipe_matches_p5_v1_training_evidence():
    assert MODULE.BASE_MODEL == "Qwen/Qwen2.5-14B-Instruct"
    assert MODULE.RECIPE == {
        "epochs": 3.0,
        "gradient_accumulation_steps": 16,
        "gradient_checkpointing_use_reentrant": False,
        "learning_rate": 7e-5,
        "lora_alpha": 32,
        "lora_dropout": 0.05,
        "lora_r": 16,
        "max_length": 1024,
        "optimizer": "paged_adamw_8bit",
        "quantization": "4bit-nf4-double-quant",
        "save_steps": 50,
    }


def test_load_training_rows_is_strict(tmp_path: Path):
    path = tmp_path / "train.jsonl"
    path.write_text(json.dumps(_row("a")) + "\n", encoding="utf-8")
    assert MODULE.load_training_rows(path) == [_row("a")]

    path.write_text(
        json.dumps(_row("a")) + "\n" + json.dumps(_row("a")) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(MODULE.TrainingInputError, match="duplicate row id"):
        MODULE.load_training_rows(path)


def test_latest_checkpoint_ignores_incomplete_and_non_numeric(tmp_path: Path):
    (tmp_path / "checkpoint-bad").mkdir()
    (tmp_path / "checkpoint-50").mkdir()
    latest = tmp_path / "checkpoint-100"
    latest.mkdir()
    (latest / "trainer_state.json").write_text("{}", encoding="utf-8")
    assert MODULE.latest_checkpoint(tmp_path) == latest
