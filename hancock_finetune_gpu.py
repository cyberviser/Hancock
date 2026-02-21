#!/usr/bin/env python3
# Copyright (c) 2026 CyberViser. All Rights Reserved.
"""
Hancock GPU Fine-Tuning — Universal Script
Works on: Google Colab T4, Kaggle T4, RunPod, Lambda Labs, Modal

Quick start (Colab/Kaggle):
    !pip install -q "unsloth[colab-new]" trl transformers datasets peft
    !python hancock_finetune_gpu.py

Required env (optional):
    HF_TOKEN=hf_xxx        → push model to HuggingFace Hub after training
    HANCOCK_MODEL_ID=...   → override base model (default: Mistral-7B-Instruct-v0.3)
"""
import os, sys, json, argparse
from pathlib import Path

BASE_MODEL   = os.getenv("HANCOCK_MODEL_ID", "mistralai/Mistral-7B-Instruct-v0.3")
DATASET_PATH = Path("data/hancock_v2.jsonl")
OUTPUT_DIR   = Path("models/hancock_lora")
GGUF_DIR     = Path("models/hancock_gguf")
HF_REPO      = "cyberviser/hancock-mistral-7b"
MAX_SEQ_LEN  = 2048

# ── Setup ─────────────────────────────────────────────────────────────────────
def check_deps():
    missing = []
    for pkg in ["unsloth", "trl", "transformers", "datasets", "torch"]:
        try: __import__(pkg)
        except ImportError: missing.append(pkg)
    if missing:
        sys.exit(f"Missing: {', '.join(missing)}\nRun: pip install unsloth[colab-new] trl transformers datasets")

def check_gpu():
    import torch
    if not torch.cuda.is_available():
        sys.exit("❌  No GPU detected. Run this script on Colab/Kaggle/RunPod with GPU enabled.")
    gpu = torch.cuda.get_device_name(0)
    vram = torch.cuda.get_device_properties(0).total_memory / 1e9
    print(f"  GPU: {gpu} ({vram:.1f} GB VRAM)")
    return vram

def load_dataset():
    if not DATASET_PATH.exists():
        print(f"  Dataset not found at {DATASET_PATH}")
        print("  Running pipeline to generate training data...")
        os.system("python hancock_pipeline.py")
    if not DATASET_PATH.exists():
        sys.exit(f"❌  Dataset missing: {DATASET_PATH}")
    lines = DATASET_PATH.read_text().strip().splitlines()
    print(f"  ✅ Dataset: {len(lines):,} samples from {DATASET_PATH}")
    return [json.loads(l) for l in lines]

# ── Training ──────────────────────────────────────────────────────────────────
def train(push_hub: bool = False, dry_run: bool = False):
    import torch
    from unsloth import FastLanguageModel
    from datasets import Dataset
    from trl import SFTTrainer
    from transformers import TrainingArguments

    print("\n" + "="*60)
    print("  Hancock Fine-Tuning — CyberViser")
    print("="*60)

    vram = check_gpu()

    # Reduce batch / increase gradient accumulation on small VRAM
    batch_size = 2 if vram >= 15 else 1
    grad_accum = 4 if vram >= 15 else 8
    print(f"  Config: batch={batch_size}, grad_accum={grad_accum}, seq_len={MAX_SEQ_LEN}")

    if dry_run:
        print("\n[DRY RUN] GPU + deps OK. Skipping training.")
        return

    # [1] Load model
    print(f"\n[1/4] Loading {BASE_MODEL} with 4-bit quantization...")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name     = BASE_MODEL,
        max_seq_length = MAX_SEQ_LEN,
        dtype          = None,       # auto-detect bf16/fp16
        load_in_4bit   = True,
    )
    model = FastLanguageModel.get_peft_model(
        model,
        r                  = 32,
        target_modules     = ["q_proj", "k_proj", "v_proj", "o_proj",
                              "gate_proj", "up_proj", "down_proj"],
        lora_alpha         = 32,
        lora_dropout       = 0.05,
        bias               = "none",
        use_gradient_checkpointing = "unsloth",
        random_state       = 42,
    )
    print(f"  ✅ Model loaded. Trainable params: {model.num_parameters(only_trainable=True):,}")

    # [2] Load + format dataset
    print("\n[2/4] Loading and formatting dataset...")
    raw_data = load_dataset()
    texts = [
        tokenizer.apply_chat_template(s["messages"], tokenize=False, add_generation_prompt=False)
        for s in raw_data
    ]
    ds = Dataset.from_dict({"text": texts}).train_test_split(test_size=0.05, seed=42)
    print(f"  Train: {len(ds['train']):,} | Eval: {len(ds['test']):,}")
    print(f"  Sample:\n  {texts[0][:200]}...")

    # [3] Train
    print("\n[3/4] Training...")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    trainer = SFTTrainer(
        model               = model,
        tokenizer           = tokenizer,
        train_dataset       = ds["train"],
        eval_dataset        = ds["test"],
        dataset_text_field  = "text",
        max_seq_length      = MAX_SEQ_LEN,
        packing             = True,
        args = TrainingArguments(
            per_device_train_batch_size  = batch_size,
            gradient_accumulation_steps  = grad_accum,
            warmup_ratio                 = 0.05,
            num_train_epochs             = 3,
            learning_rate                = 2e-4,
            fp16                         = not torch.cuda.is_bf16_supported(),
            bf16                         = torch.cuda.is_bf16_supported(),
            logging_steps                = 20,
            evaluation_strategy          = "steps",
            eval_steps                   = 100,
            save_strategy                = "steps",
            save_steps                   = 200,
            save_total_limit             = 2,
            output_dir                   = str(OUTPUT_DIR),
            report_to                    = "none",
            optim                        = "adamw_8bit",
            weight_decay                 = 0.01,
            lr_scheduler_type            = "cosine",
            seed                         = 42,
        ),
    )
    result = trainer.train()
    print(f"\n  ✅ Training complete — final loss: {result.training_loss:.4f}")

    # [4] Save
    print("\n[4/4] Saving model...")
    model.save_pretrained(str(OUTPUT_DIR))
    tokenizer.save_pretrained(str(OUTPUT_DIR))
    print(f"  ✅ LoRA adapters saved → {OUTPUT_DIR}")

    GGUF_DIR.mkdir(parents=True, exist_ok=True)
    model.save_pretrained_gguf(str(GGUF_DIR), tokenizer, quantization_method="q4_k_m")
    print(f"  ✅ GGUF (Q4_K_M) saved → {GGUF_DIR}")

    # [5] Push to HF Hub
    if push_hub:
        hf_token = os.getenv("HF_TOKEN", "")
        if not hf_token:
            print("  ⚠️  HF_TOKEN not set — skipping Hub push")
        else:
            print(f"\n[+] Pushing to huggingface.co/{HF_REPO} ...")
            model.push_to_hub(HF_REPO, token=hf_token, private=False)
            tokenizer.push_to_hub(HF_REPO, token=hf_token)
            print(f"  ✅ Model live at: https://huggingface.co/{HF_REPO}")

    print("\n" + "="*60)
    print(f"  DONE — Loss: {result.training_loss:.4f} | Samples: {len(ds['train']):,}")
    print(f"  LoRA:  {OUTPUT_DIR}")
    print(f"  GGUF:  {GGUF_DIR}")
    print("="*60)


# ── Entry ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hancock GPU Fine-Tuning")
    parser.add_argument("--push-hub",  action="store_true", help="Push to HuggingFace Hub after training")
    parser.add_argument("--dry-run",   action="store_true", help="Check GPU + deps only, skip training")
    parser.add_argument("--model",     default=None,        help="Override base model ID")
    args = parser.parse_args()

    if args.model:
        BASE_MODEL = args.model  # type: ignore

    check_deps()
    train(push_hub=args.push_hub, dry_run=args.dry_run)
