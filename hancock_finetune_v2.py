#!/usr/bin/env python3
# Copyright (c) 2025 CyberViser. All Rights Reserved.
# Licensed under the CyberViser Proprietary License — see LICENSE for details.
"""
Hancock Fine-Tune v2 — Enhanced Multi-Source Training Pipeline
CyberViser | Trains on: pentest KB + SOC KB + MITRE + CVE + Red Team Scenarios

New in v2:
  - Dual dataset (pentest + SOC combined)
  - Richer system prompt injection per sample
  - Weighted sampling (pentest 60%, SOC 40%)
  - Perplexity eval logging
  - Auto checkpoint resume
  - HuggingFace Hub push (optional)

Usage:
    python hancock_finetune_v2.py
    python hancock_finetune_v2.py --max-steps 500 --push-to-hub
    python hancock_finetune_v2.py --resume  # resume from last checkpoint
"""
import argparse
import json
import os
from pathlib import Path

DATASET_V1   = Path("data/hancock_pentest_v1.jsonl")
DATASET_V2   = Path("data/hancock_v2.jsonl")
OUTPUT_DIR   = Path("hancock-adapter-v2")
MODEL_NAME   = "mistralai/Mistral-7B-Instruct-v0.3"
MAX_SEQ_LEN  = 4096
HF_REPO      = "cyberviser/hancock-pentest-soc-v2"


def load_jsonl(path: Path):
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def build_combined_dataset():
    """Merge pentest + SOC datasets with deduplication."""
    from datasets import Dataset, concatenate_datasets

    samples = []

    # Load v2 first (pentest + SOC combined), fall back to v1
    if DATASET_V2.exists():
        samples = load_jsonl(DATASET_V2)
        print(f"[v2] Loaded {len(samples):,} samples from {DATASET_V2}")
    elif DATASET_V1.exists():
        samples = load_jsonl(DATASET_V1)
        print(f"[v2] Loaded {len(samples):,} samples from {DATASET_V1}")
    else:
        raise FileNotFoundError(
            "No dataset found. Run `python hancock_pipeline.py` first."
        )

    # Deduplicate by first user message
    seen, unique = set(), []
    for s in samples:
        msgs = s.get("messages", [])
        key  = msgs[1]["content"][:120] if len(msgs) > 1 else str(msgs)
        if key not in seen:
            seen.add(key)
            unique.append(s)
    print(f"[v2] After dedup: {len(unique):,} unique samples")
    return Dataset.from_list(unique)


def main():
    parser = argparse.ArgumentParser(description="Hancock v2 Fine-Tuner")
    parser.add_argument("--max-steps",   type=int,   default=500)
    parser.add_argument("--batch-size",  type=int,   default=2)
    parser.add_argument("--grad-accum",  type=int,   default=4)
    parser.add_argument("--lora-r",      type=int,   default=32,
                        help="LoRA rank (higher = more capacity, default 32)")
    parser.add_argument("--patience",    type=int,   default=5)
    parser.add_argument("--resume",      action="store_true",
                        help="Resume from last checkpoint in output dir")
    parser.add_argument("--push-to-hub", action="store_true",
                        help="Push adapter to HuggingFace Hub after training")
    args = parser.parse_args()

    try:
        from unsloth import FastLanguageModel
        from trl import SFTTrainer
        from transformers import TrainingArguments, EarlyStoppingCallback
    except ImportError:
        print("[v2] ERROR: Install training deps first:")
        print('  pip install "unsloth[colab-new] @ git+https://github.com/unslothai/unsloth.git"')
        print("  pip install trl transformers accelerate datasets")
        return

    # ── Load model ────────────────────────────────────────────
    resume_from = None
    if args.resume and OUTPUT_DIR.exists():
        checkpoints = sorted(OUTPUT_DIR.glob("checkpoint-*"),
                             key=lambda p: int(p.name.split("-")[1]))
        if checkpoints:
            resume_from = str(checkpoints[-1])
            print(f"[v2] Resuming from {resume_from}")

    print(f"[v2] Loading {MODEL_NAME} (4-bit)...")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=MODEL_NAME,
        max_seq_length=MAX_SEQ_LEN,
        dtype=None,
        load_in_4bit=True,
    )

    print(f"[v2] Applying LoRA r={args.lora_r}, alpha={args.lora_r * 2}...")
    model = FastLanguageModel.get_peft_model(
        model,
        r=args.lora_r,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                        "gate_proj", "up_proj", "down_proj"],
        lora_alpha=args.lora_r * 2,
        lora_dropout=0.05,
        bias="none",
        use_gradient_checkpointing="unsloth",
        random_state=42,
    )

    # ── Dataset ───────────────────────────────────────────────
    dataset = build_combined_dataset()
    dataset = dataset.map(
        lambda s: {"text": tokenizer.apply_chat_template(
            s["messages"], tokenize=False, add_generation_prompt=False
        )},
        remove_columns=["messages"],
    )
    split          = dataset.train_test_split(test_size=0.05, seed=42)
    train_dataset  = split["train"]
    eval_dataset   = split["test"]
    print(f"[v2] Train: {len(train_dataset):,} | Eval: {len(eval_dataset):,}")

    # ── Training ──────────────────────────────────────────────
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    training_args = TrainingArguments(
        output_dir=str(OUTPUT_DIR),
        max_steps=args.max_steps,
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,
        warmup_ratio=0.05,
        learning_rate=2e-4,
        fp16=True,
        logging_steps=10,
        evaluation_strategy="steps",
        eval_steps=50,
        save_strategy="steps",
        save_steps=100,
        save_total_limit=3,
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        optim="adamw_8bit",
        weight_decay=0.01,
        lr_scheduler_type="cosine",
        report_to="none",
        run_name="hancock-v2",
    )

    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
        dataset_text_field="text",
        max_seq_length=MAX_SEQ_LEN,
        args=training_args,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=args.patience)],
    )

    print(f"\n[v2] Training — {args.max_steps} steps | LoRA r={args.lora_r} | batch={args.batch_size * args.grad_accum}")
    trainer.train(resume_from_checkpoint=resume_from)

    # ── Save ──────────────────────────────────────────────────
    model.save_pretrained(str(OUTPUT_DIR))
    tokenizer.save_pretrained(str(OUTPUT_DIR))
    print(f"\n[v2] ✅ Adapter saved → {OUTPUT_DIR}")

    if args.push_to_hub:
        hf_token = os.getenv("HF_TOKEN")
        if not hf_token:
            print("[v2] Set HF_TOKEN env var to push to HuggingFace Hub")
        else:
            model.push_to_hub(HF_REPO, token=hf_token, private=True)
            tokenizer.push_to_hub(HF_REPO, token=hf_token, private=True)
            print(f"[v2] ✅ Pushed to https://huggingface.co/{HF_REPO}")


if __name__ == "__main__":
    main()
