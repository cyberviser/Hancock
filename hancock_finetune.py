#!/usr/bin/env python3
# Copyright (c) 2025 CyberViser. All Rights Reserved.
# Licensed under the CyberViser Proprietary License — see LICENSE for details.
"""
Hancock Fine-Tune Script
CyberViser | Hancock AI Agent Phase 1: Pentest Specialist

Fine-tunes Mistral 7B Instruct using LoRA via unsloth.
Loads: data/hancock_pentest_v1.jsonl
Saves: hancock-adapter/

Requirements (install with GPU available):
    pip install "unsloth[colab-new] @ git+https://github.com/unslothai/unsloth.git"
    pip install trl transformers accelerate datasets

Usage:
    python hancock_finetune.py
    python hancock_finetune.py --max-steps 100  # quick test run
"""
import argparse
import json
from pathlib import Path

DATASET_PATH = Path(__file__).parent / "data" / "hancock_pentest_v1.jsonl"
OUTPUT_DIR = Path(__file__).parent / "hancock-adapter"

MODEL_NAME = "mistralai/Mistral-7B-Instruct-v0.3"
MAX_SEQ_LENGTH = 4096


def load_dataset_local(path: Path):
    """Load JSONL and convert to HuggingFace Dataset."""
    from datasets import Dataset
    records = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    print(f"[finetune] Loaded {len(records):,} samples from {path}")
    return Dataset.from_list(records)


def apply_chat_template(sample, tokenizer):
    """Apply Mistral chat template to messages."""
    text = tokenizer.apply_chat_template(
        sample["messages"],
        tokenize=False,
        add_generation_prompt=False,
    )
    return {"text": text}


def main():
    parser = argparse.ArgumentParser(description="Fine-tune Hancock on Mistral 7B")
    parser.add_argument("--max-steps", type=int, default=300, help="Training steps (default: 300)")
    parser.add_argument("--batch-size", type=int, default=2, help="Per-device batch size")
    parser.add_argument("--grad-accum", type=int, default=4, help="Gradient accumulation steps")
    parser.add_argument("--lora-r", type=int, default=16, help="LoRA rank")
    parser.add_argument("--patience", type=int, default=3, help="Early stopping patience (evals with no improvement, default: 3)")
    args = parser.parse_args()

    # Check dataset exists
    if not DATASET_PATH.exists():
        print(f"[finetune] ERROR: Dataset not found at {DATASET_PATH}")
        print("[finetune] Run 'python hancock_pipeline.py' first to generate the dataset.")
        return

    try:
        from unsloth import FastLanguageModel
    except ImportError:
        print("[finetune] ERROR: unsloth not installed.")
        print("[finetune] Install with:")
        print('  pip install "unsloth[colab-new] @ git+https://github.com/unslothai/unsloth.git"')
        print("  pip install trl transformers accelerate datasets")
        return

    from trl import SFTTrainer
    from transformers import TrainingArguments, EarlyStoppingCallback

    print(f"\n[finetune] Loading {MODEL_NAME} with 4-bit quantization...")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=MODEL_NAME,
        max_seq_length=MAX_SEQ_LENGTH,
        dtype=None,
        load_in_4bit=True,
    )

    print(f"[finetune] Applying LoRA (r={args.lora_r})...")
    model = FastLanguageModel.get_peft_model(
        model,
        r=args.lora_r,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
        lora_alpha=args.lora_r * 2,
        lora_dropout=0.05,
        bias="none",
        use_gradient_checkpointing="unsloth",
        random_state=42,
    )

    print("[finetune] Loading dataset...")
    dataset = load_dataset_local(DATASET_PATH)

    # Apply chat template
    dataset = dataset.map(
        lambda s: apply_chat_template(s, tokenizer),
        remove_columns=["messages"],
    )

    # Split: 95% train, 5% eval
    split = dataset.train_test_split(test_size=0.05, seed=42)
    train_dataset = split["train"]
    eval_dataset = split["test"]
    print(f"[finetune] Train: {len(train_dataset):,} | Eval: {len(eval_dataset):,}")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    training_args = TrainingArguments(
        output_dir=str(OUTPUT_DIR),
        num_train_epochs=1,
        max_steps=args.max_steps,
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,
        warmup_steps=20,
        learning_rate=2e-4,
        fp16=True,
        logging_steps=10,
        evaluation_strategy="steps",  # use eval_strategy if trl>=0.28
        eval_steps=50,
        save_strategy="steps",
        save_steps=100,
        load_best_model_at_end=True,
        optim="adamw_8bit",
        weight_decay=0.01,
        lr_scheduler_type="cosine",
        report_to="none",
        run_name="hancock-pentest-v1",
    )

    trainer = SFTTrainer(
        model=model,
        processing_class=tokenizer,
        train_dataset=train_dataset,
        eval_dataset=eval_dataset,
        dataset_text_field="text",
        max_seq_length=MAX_SEQ_LENGTH,
        args=training_args,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=args.patience)],
    )

    print(f"\n[finetune] Starting training — {args.max_steps} steps (early stopping patience: {args.patience} evals)...")
    print(f"[finetune] Effective batch size: {args.batch_size * args.grad_accum}")
    trainer.train()

    print(f"\n[finetune] Saving LoRA adapter to {OUTPUT_DIR}...")
    model.save_pretrained(str(OUTPUT_DIR))
    tokenizer.save_pretrained(str(OUTPUT_DIR))

    print("\n╔═══════════════════════════════════════════════╗")
    print("║  ✅  Hancock adapter saved!                   ║")
    print(f"║  📁  {str(OUTPUT_DIR):<41}║")
    print("║                                               ║")
    print("║  To run Hancock locally:                      ║")
    print("║  from unsloth import FastLanguageModel        ║")
    print('║  model, tok = FastLanguageModel.from_pretrained(')
    print(f'║    "{MODEL_NAME}",')
    print("║    ...                                        ║")
    print("║  )                                            ║")
    print('║  model.load_adapter("hancock-adapter/")       ║')
    print("╚═══════════════════════════════════════════════╝")


if __name__ == "__main__":
    main()
