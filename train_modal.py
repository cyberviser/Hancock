#!/usr/bin/env python3
# Copyright (c) 2026 CyberViser. All Rights Reserved.
# Licensed under the CyberViser Proprietary License — see LICENSE for details.
"""
Hancock Fine-Tuning — Modal.com GPU Runner
CyberViser | Free tier: $30/month credits (~15 hours A10G)

Setup (one-time):
    pip install modal
    modal token new          # creates ~/.modal.toml
    modal secret create cyberviser-secrets \\
        HF_TOKEN=hf_xxx \\
        NVIDIA_API_KEY=nvapi-xxx

Run:
    modal run train_modal.py                  # full training run
    modal run train_modal.py --dry-run        # validate setup only
    modal run train_modal.py --push-hub       # train + push to HF Hub

GPU cost estimate (Modal free tier: $30/mo credit):
    A10G (24GB VRAM) — $0.94/hr  → ~32 hrs free per month
    A100 (80GB VRAM) — $3.72/hr  → ~8 hrs free per month
    T4   (16GB VRAM) — $0.59/hr  → ~50 hrs free per month  ← recommended
"""
import modal
import sys
from pathlib import Path

# ── Modal app definition ──────────────────────────────────────────────────────
app = modal.App("hancock-finetune")

# Docker image with all ML dependencies
image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install([
        "unsloth[colab-new]",
        "trl>=0.8.0", "transformers>=4.40.0", "accelerate",
        "datasets>=2.18.0", "peft", "bitsandbytes",
        "sentencepiece", "requests", "tqdm", "huggingface_hub",
    ])
)

# Mount the local repo into the container
repo_mount = modal.Mount.from_local_dir(
    ".",
    remote_path="/app",
    condition=lambda p: not any(
        p.startswith(x) for x in [".git", "__pycache__", ".venv", "node_modules"]
    ),
)

VOLUME_NAME = "hancock-models"
model_vol   = modal.Volume.from_name(VOLUME_NAME, create_if_missing=True)


@app.function(
    image=image,
    gpu="T4",                          # Free-tier friendly — swap to "A10G" for speed
    timeout=60 * 90,                   # 90 min max
    secrets=[modal.Secret.from_name("cyberviser-secrets")],
    mounts=[repo_mount],
    volumes={"/models": model_vol},
)
def train(dry_run: bool = False, push_hub: bool = False):
    import os, sys, json
    from pathlib import Path

    sys.path.insert(0, "/app")
    os.chdir("/app")

    print("=" * 60)
    print("  Hancock Fine-Tuning — CyberViser")
    print("=" * 60)

    # ── Build dataset ─────────────────────────────────────────────────
    print("\n[1/4] Building training dataset...")
    from pathlib import Path as P
    data_dir     = P("data")
    data_dir.mkdir(exist_ok=True)
    dataset_path = data_dir / "hancock_v3.jsonl"
    dataset_fallback = data_dir / "hancock_v2.jsonl"

    if not dataset_path.exists():
        # Run v3 pipeline; fall back to v2 if it fails
        from hancock_pipeline import run_kev, run_atomic, run_ghsa, run_formatter_v3
        run_kev(data_dir)
        run_atomic(data_dir)
        run_ghsa(data_dir)
        run_formatter_v3()
    if not dataset_path.exists() and not dataset_fallback.exists():
        from hancock_pipeline import run_kb, run_soc_kb, run_mitre, run_nvd, run_formatter
        run_kb(data_dir); run_soc_kb(data_dir); run_mitre(data_dir)
        run_nvd(data_dir); run_formatter(v2=True)
    active = dataset_path if dataset_path.exists() else dataset_fallback
    if not active.exists():
        sys.exit(f"❌  Dataset missing — run: python hancock_pipeline.py --phase 3")
    else:
        print(f"  Using existing dataset: {active}")

    samples = active.read_text().strip().splitlines()
    print(f"  ✅ Dataset: {len(samples):,} samples")

    if dry_run:
        print("\n[DRY RUN] Setup OK — skipping training.")
        return {"status": "dry_run_ok", "samples": len(samples)}

    # ── Load model ────────────────────────────────────────────────────
    print("\n[2/4] Loading Mistral-7B with Unsloth...")
    import torch
    from unsloth import FastLanguageModel

    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name     = "mistralai/Mistral-7B-Instruct-v0.3",
        max_seq_length = 2048,
        dtype          = None,
        load_in_4bit   = True,
    )
    model = FastLanguageModel.get_peft_model(
        model,
        r=32, target_modules=["q_proj","k_proj","v_proj","o_proj",
                               "gate_proj","up_proj","down_proj"],
        lora_alpha=32, lora_dropout=0.05, bias="none",
        use_gradient_checkpointing="unsloth", random_state=42,
    )
    print("  ✅ Model + LoRA adapters loaded")

    # ── Format dataset ────────────────────────────────────────────────
    print("\n[3/4] Formatting dataset...")
    from datasets import Dataset

    raw   = [json.loads(l) for l in samples]
    texts = [tokenizer.apply_chat_template(s["messages"], tokenize=False,
             add_generation_prompt=False) for s in raw]
    ds    = Dataset.from_dict({"text": texts}).train_test_split(test_size=0.05, seed=42)
    print(f"  Train: {len(ds['train']):,} | Eval: {len(ds['test']):,}")

    # ── Train ─────────────────────────────────────────────────────────
    print("\n[4/4] Training...")
    from trl import SFTTrainer
    from transformers import TrainingArguments

    trainer = SFTTrainer(
        model=model, tokenizer=tokenizer,
        train_dataset=ds["train"], eval_dataset=ds["test"],
        dataset_text_field="text", max_seq_length=2048, packing=True,
        args=TrainingArguments(
            per_device_train_batch_size=2, gradient_accumulation_steps=4,
            warmup_ratio=0.05, num_train_epochs=3, learning_rate=2e-4,
            fp16=not torch.cuda.is_bf16_supported(),
            bf16=torch.cuda.is_bf16_supported(),
            logging_steps=20, evaluation_strategy="steps", eval_steps=100,
            save_strategy="steps", save_steps=200, save_total_limit=2,
            output_dir="/models/checkpoints", report_to="none",
            optim="adamw_8bit", weight_decay=0.01,
            lr_scheduler_type="cosine", seed=42,
        ),
    )
    result = trainer.train()
    print(f"  ✅ Training complete — final loss: {result.training_loss:.4f}")

    # ── Save ──────────────────────────────────────────────────────────
    model.save_pretrained("/models/hancock_lora")
    tokenizer.save_pretrained("/models/hancock_lora")
    model.save_pretrained_gguf("/models/hancock_gguf", tokenizer, quantization_method="q4_k_m")
    model_vol.commit()
    print("  ✅ Model saved to Modal volume 'hancock-models'")

    # ── Push to HF Hub (optional) ─────────────────────────────────────
    if push_hub:
        hf_token = os.getenv("HF_TOKEN", "")
        if hf_token:
            model.push_to_hub("cyberviser/hancock-mistral-7b-lora", token=hf_token)
            tokenizer.push_to_hub("cyberviser/hancock-mistral-7b-lora", token=hf_token)
            print("  ✅ Pushed to huggingface.co/cyberviser/hancock-mistral-7b-lora")
        else:
            print("  ⚠️  HF_TOKEN not set — skipping Hub push")

    return {
        "status": "success",
        "loss": result.training_loss,
        "samples": len(samples),
        "model_path": "/models/hancock_lora",
    }


@app.local_entrypoint()
def main(dry_run: bool = False, push_hub: bool = False):
    result = train.remote(dry_run=dry_run, push_hub=push_hub)
    print("\n" + "=" * 60)
    print("  TRAINING RESULT")
    print("=" * 60)
    for k, v in result.items():
        print(f"  {k}: {v}")
    print("\nTo download the model:")
    print("  modal volume get hancock-models hancock_lora ./hancock_lora")
    print("  modal volume get hancock-models hancock_gguf/hancock_gguf.q4_k_m.gguf .")
