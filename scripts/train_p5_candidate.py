#!/usr/bin/env python3
"""Train one Certification Forge P5 14B LoRA candidate on ANVIL.

The defaults intentionally reproduce the P5-v1 recipe. Training checkpoints live
outside the final adapter directory so interrupted runs can resume without ever
presenting a partial adapter as a promotion candidate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any


BASE_MODEL = "Qwen/Qwen2.5-14B-Instruct"
TARGET_MODULES = ("q_proj", "k_proj", "v_proj", "o_proj")
RECIPE = {
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
    "trainable_dtype": "bfloat16",
}


class TrainingInputError(ValueError):
    """Raised when the immutable training input contract is violated."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_training_rows(path: Path) -> list[dict[str, Any]]:
    """Load strict system/user/assistant JSONL without silently dropping rows."""
    if not path.is_file():
        raise TrainingInputError(f"training JSONL is missing: {path}")
    rows: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                raise TrainingInputError(f"blank row at line {line_number}")
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise TrainingInputError(
                    f"invalid JSON at line {line_number}: {exc.msg}"
                ) from exc
            row_id = row.get("id")
            if not isinstance(row_id, str) or not row_id.strip():
                raise TrainingInputError(f"missing row id at line {line_number}")
            if row_id in seen_ids:
                raise TrainingInputError(f"duplicate row id: {row_id}")
            seen_ids.add(row_id)
            messages = row.get("messages")
            if not isinstance(messages, list) or [m.get("role") for m in messages] != [
                "system",
                "user",
                "assistant",
            ]:
                raise TrainingInputError(
                    f"row {row_id} must contain system/user/assistant messages"
                )
            if any(
                not isinstance(message.get("content"), str)
                or not message["content"].strip()
                for message in messages
            ):
                raise TrainingInputError(f"row {row_id} contains empty message content")
            rows.append(row)
    if not rows:
        raise TrainingInputError("training JSONL contains no rows")
    return rows


def latest_checkpoint(work_dir: Path) -> Path | None:
    checkpoints: list[tuple[int, Path]] = []
    for path in work_dir.glob("checkpoint-*"):
        try:
            step = int(path.name.removeprefix("checkpoint-"))
        except ValueError:
            continue
        if (path / "trainer_state.json").is_file():
            checkpoints.append((step, path))
    return max(checkpoints, default=(0, None), key=lambda item: item[0])[1]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adapter", choices=("gs343", "r2d2"), required=True)
    parser.add_argument("--train-jsonl", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--base-model", default=BASE_MODEL)
    parser.add_argument(
        "--max-length",
        type=int,
        default=RECIPE["max_length"],
        choices=range(512, RECIPE["max_length"] + 1, 64),
        help="Token ceiling; lower in 64-token steps when activation memory requires it.",
    )
    parser.add_argument("--resume", action="store_true")
    parser.add_argument(
        "--lock-file",
        type=Path,
        default=Path("/home/anvil/adapter_training/.certforge-p5-train.lock"),
    )
    return parser


def _write_evidence(
    output_dir: Path,
    *,
    args: argparse.Namespace,
    row_count: int,
    train_sha256: str,
    elapsed_seconds: float,
    global_step: int,
    recipe: dict[str, Any],
) -> None:
    evidence = {
        "adapter": args.adapter,
        "base_model": args.base_model,
        "elapsed_seconds": round(elapsed_seconds, 3),
        "global_step": global_step,
        "recipe": recipe,
        "target_modules": list(TARGET_MODULES),
        "train_jsonl": str(args.train_jsonl.resolve()),
        "train_rows": row_count,
        "train_sha256": train_sha256,
        "trained_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    (output_dir / "train_meta.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    sums: list[str] = []
    for path in sorted(output_dir.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS.txt":
            sums.append(f"{sha256_file(path)}  {path.relative_to(output_dir).as_posix()}")
    (output_dir / "SHA256SUMS.txt").write_text(
        "\n".join(sums) + "\n", encoding="utf-8"
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    run_recipe = {**RECIPE, "max_length": args.max_length}
    rows = load_training_rows(args.train_jsonl)
    if args.output_dir.exists():
        raise TrainingInputError(f"final output already exists: {args.output_dir}")
    args.work_dir.mkdir(parents=True, exist_ok=True)
    args.output_dir.parent.mkdir(parents=True, exist_ok=True)
    args.lock_file.parent.mkdir(parents=True, exist_ok=True)

    import fcntl

    lock_handle = args.lock_file.open("a+", encoding="utf-8")
    try:
        fcntl.flock(lock_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        raise TrainingInputError("another Certification Forge training run is active") from exc

    import torch
    from datasets import Dataset
    from peft import LoraConfig, TaskType, get_peft_model, prepare_model_for_kbit_training
    from transformers import (
        AutoModelForCausalLM,
        AutoTokenizer,
        BitsAndBytesConfig,
        DataCollatorForLanguageModeling,
        Trainer,
        TrainingArguments,
    )

    if not torch.cuda.is_available():
        raise RuntimeError("CUDA is required for the 14B QLoRA recipe")
    free_bytes, _ = torch.cuda.mem_get_info(0)
    if free_bytes < 13 * 1024**3:
        raise RuntimeError(
            f"insufficient free GPU memory: {free_bytes / 1024**3:.1f} GiB; need 13 GiB"
        )

    tokenizer = AutoTokenizer.from_pretrained(args.base_model, trust_remote_code=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"

    quantization = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.bfloat16,
        bnb_4bit_use_double_quant=True,
    )
    model = AutoModelForCausalLM.from_pretrained(
        args.base_model,
        device_map="auto",
        quantization_config=quantization,
        torch_dtype=torch.bfloat16,
        trust_remote_code=True,
    )
    model.config.use_cache = False
    model = prepare_model_for_kbit_training(model, use_gradient_checkpointing=True)
    model = get_peft_model(
        model,
        LoraConfig(
            r=RECIPE["lora_r"],
            lora_alpha=RECIPE["lora_alpha"],
            lora_dropout=RECIPE["lora_dropout"],
            target_modules=list(TARGET_MODULES),
            task_type=TaskType.CAUSAL_LM,
            bias="none",
        ),
    )
    for parameter in model.parameters():
        if parameter.requires_grad:
            parameter.data = parameter.data.to(dtype=torch.bfloat16)
    trainable_dtypes = {
        parameter.dtype for parameter in model.parameters() if parameter.requires_grad
    }
    if trainable_dtypes != {torch.bfloat16}:
        raise RuntimeError(f"unexpected trainable parameter dtypes: {trainable_dtypes}")

    def tokenize(row: dict[str, Any]) -> dict[str, list[int]]:
        rendered = tokenizer.apply_chat_template(
            row["messages"], tokenize=False, add_generation_prompt=False
        )
        return tokenizer(
            rendered,
            truncation=True,
            max_length=run_recipe["max_length"],
            padding=False,
        )

    dataset = Dataset.from_list([tokenize(row) for row in rows])
    training_args = TrainingArguments(
        output_dir=str(args.work_dir),
        per_device_train_batch_size=1,
        gradient_accumulation_steps=RECIPE["gradient_accumulation_steps"],
        num_train_epochs=RECIPE["epochs"],
        learning_rate=RECIPE["learning_rate"],
        warmup_ratio=0.03,
        lr_scheduler_type="cosine",
        optim=RECIPE["optimizer"],
        bf16=True,
        fp16=False,
        gradient_checkpointing=True,
        gradient_checkpointing_kwargs={
            "use_reentrant": RECIPE["gradient_checkpointing_use_reentrant"]
        },
        max_grad_norm=1.0,
        logging_steps=10,
        save_steps=RECIPE["save_steps"],
        save_total_limit=2,
        report_to="none",
        seed=42,
    )
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=dataset,
        data_collator=DataCollatorForLanguageModeling(tokenizer=tokenizer, mlm=False),
    )
    checkpoint = latest_checkpoint(args.work_dir) if args.resume else None
    started = time.monotonic()
    result = trainer.train(resume_from_checkpoint=str(checkpoint) if checkpoint else None)
    elapsed = time.monotonic() - started

    partial = args.output_dir.with_name(f".{args.output_dir.name}.partial-{os.getpid()}")
    if partial.exists():
        shutil.rmtree(partial)
    partial.mkdir(parents=True)
    model.save_pretrained(partial)
    tokenizer.save_pretrained(partial)
    torch.save(training_args, partial / "training_args.bin")
    _write_evidence(
        partial,
        args=args,
        row_count=len(rows),
        train_sha256=sha256_file(args.train_jsonl),
        elapsed_seconds=elapsed,
        global_step=result.global_step,
        recipe=run_recipe,
    )
    os.replace(partial, args.output_dir)
    print(
        json.dumps(
            {
                "adapter": args.adapter,
                "global_step": result.global_step,
                "output_dir": str(args.output_dir),
                "status": "complete",
                "train_rows": len(rows),
            },
            sort_keys=True,
        ),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TrainingInputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
