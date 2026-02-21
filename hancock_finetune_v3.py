#!/usr/bin/env python3
# Copyright (c) 2025 CyberViser. All Rights Reserved.
"""
Hancock Fine-Tune v3 — Universal GPU Runner
CyberViser | Mistral 7B + LoRA (Unsloth) → HuggingFace Hub + GGUF

Runs on:
  ✅ Google Colab  (T4  16GB — free)
  ✅ Kaggle        (P100 16GB — free, 30hr/week)
  ✅ SageMaker Lab (T4  16GB — free)
  ✅ RunPod / Vast (any VRAM ≥ 16GB)
  ✅ Oracle Cloud  (A10 — with startup credits)

Quick start (Colab/Kaggle):
  !git clone https://github.com/cyberviser/Hancock && cd Hancock
  !pip install -q "unsloth[colab-new] @ git+https://github.com/unslothai/unsloth.git"
  !pip install -q trl transformers accelerate datasets bitsandbytes
  !python hancock_finetune_v3.py --steps 300 --push-to-hub

Outputs:
  hancock-adapter-v3/        ← LoRA adapter (push to HF Hub)
  hancock-adapter-v3.gguf    ← GGUF quantized (deploy anywhere, no GPU)
"""
import argparse
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────
MODEL_NAME    = "mistralai/Mistral-7B-Instruct-v0.3"
OUTPUT_DIR    = Path("hancock-adapter-v3")
HF_REPO       = "cyberviser/hancock-v3"
DATASET_URL   = "https://raw.githubusercontent.com/cyberviser/Hancock/main/data/hancock_v2.jsonl"
DATASET_LOCAL = Path("data/hancock_v2.jsonl")
MAX_SEQ_LEN   = 4096


# ── Environment detection ─────────────────────────────────────────────────────
def detect_env() -> dict:
    env = {"colab": False, "kaggle": False, "gpu": None, "vram_gb": 0}
    try:
        import google.colab  # noqa
        env["colab"] = True
    except ImportError:
        pass
    if os.path.exists("/kaggle"):
        env["kaggle"] = True
    try:
        import torch
        if torch.cuda.is_available():
            env["gpu"]     = torch.cuda.get_device_name(0)
            env["vram_gb"] = torch.cuda.get_device_properties(0).total_memory / 1e9
    except ImportError:
        pass
    return env


def install_deps(env: dict):
    """Install Unsloth + training deps if not present."""
    try:
        import unsloth  # noqa
        print("[v3] Unsloth already installed.")
        return
    except ImportError:
        pass
    print("[v3] Installing training dependencies...")
    vram = env.get("vram_gb", 0)
    if vram >= 40:
        unsloth_pkg = "unsloth[cu121] @ git+https://github.com/unslothai/unsloth.git"
    else:
        unsloth_pkg = "unsloth[colab-new] @ git+https://github.com/unslothai/unsloth.git"
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q",
        f"{unsloth_pkg}", "trl>=0.8.0", "transformers>=4.40.0",
        "accelerate", "datasets>=2.18.0", "bitsandbytes", "peft",
    ])


def get_lora_config(vram_gb: float) -> dict:
    """Scale LoRA rank to available VRAM."""
    if vram_gb >= 40:   # A100/A10 — high quality
        return {"r": 64, "alpha": 128, "batch": 4, "grad_accum": 2}
    elif vram_gb >= 24: # 3090/4090
        return {"r": 32, "alpha": 64,  "batch": 2, "grad_accum": 4}
    else:               # T4/P100 16GB — free tier
        return {"r": 16, "alpha": 32,  "batch": 2, "grad_accum": 4}


# ── Dataset ───────────────────────────────────────────────────────────────────
def load_dataset_from_github() -> list:
    import urllib.request
    print(f"[v3] Downloading dataset from GitHub...")
    with urllib.request.urlopen(DATASET_URL) as r:
        lines = r.read().decode("utf-8").splitlines()
    samples = [json.loads(l) for l in lines if l.strip()]
    print(f"[v3] Downloaded {len(samples):,} samples")
    return samples


def load_dataset() -> list:
    if DATASET_LOCAL.exists():
        with open(DATASET_LOCAL) as f:
            samples = [json.loads(l) for l in f if l.strip()]
        print(f"[v3] Loaded {len(samples):,} samples from {DATASET_LOCAL}")
        return samples
    return load_dataset_from_github()


def build_dataset(tokenizer, samples: list, max_seq_len: int):
    from datasets import Dataset
    # Deduplicate
    seen, unique = set(), []
    for s in samples:
        msgs = s.get("messages", [])
        key = msgs[1]["content"][:120] if len(msgs) > 1 else str(msgs)
        if key not in seen:
            seen.add(key)
            unique.append(s)
    print(f"[v3] After dedup: {len(unique):,} unique samples")
    ds = Dataset.from_list(unique)
    ds = ds.map(
        lambda s: {"text": tokenizer.apply_chat_template(
            s["messages"], tokenize=False, add_generation_prompt=False
        )},
        remove_columns=["messages"],
    )
    return ds.train_test_split(test_size=0.05, seed=42)


# ── GGUF export ───────────────────────────────────────────────────────────────
def export_gguf(model, tokenizer, output_dir: Path):
    """Export merged model to GGUF Q4_K_M for CPU/edge deployment."""
    try:
        print("\n[v3] Exporting to GGUF Q4_K_M...")
        merged_dir = output_dir.parent / "hancock-merged"
        model.save_pretrained_merged(str(merged_dir), tokenizer, save_method="merged_16bit")
        gguf_path = str(output_dir.parent / "hancock-v3-Q4_K_M.gguf")
        model.save_pretrained_gguf(gguf_path, tokenizer, quantization_method="q4_k_m")
        size_mb = Path(gguf_path).stat().st_size / 1e6
        print(f"[v3] ✅ GGUF saved → {gguf_path} ({size_mb:.0f} MB)")
        return gguf_path
    except Exception as e:
        print(f"[v3] GGUF export failed (non-fatal): {e}")
        return None


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Hancock v3 Fine-Tuner")
    parser.add_argument("--steps",       type=int,   default=300,  help="Max training steps (default: 300)")
    parser.add_argument("--lora-r",      type=int,   default=0,    help="LoRA rank (0=auto based on VRAM)")
    parser.add_argument("--resume",      action="store_true",       help="Resume from last checkpoint")
    parser.add_argument("--push-to-hub", action="store_true",       help="Push adapter to HuggingFace Hub")
    parser.add_argument("--export-gguf", action="store_true",       help="Export merged GGUF after training")
    parser.add_argument("--hf-repo",     default=HF_REPO,           help=f"HF Hub repo (default: {HF_REPO})")
    parser.add_argument("--dry-run",     action="store_true",       help="Load model + dataset only, no training")
    args = parser.parse_args()

    # ── Environment ───────────────────────────────────────────
    env = detect_env()
    print(f"\n[v3] Hancock Fine-Tune v3 — CyberViser")
    print(f"     Platform : {platform.system()} {'(Colab)' if env['colab'] else '(Kaggle)' if env['kaggle'] else ''}")
    print(f"     GPU      : {env['gpu'] or 'NOT DETECTED — need GPU!'}")
    print(f"     VRAM     : {env['vram_gb']:.1f} GB")
    if not env["gpu"]:
        sys.exit("\n[v3] ERROR: No GPU detected. Use Colab/Kaggle/RunPod with GPU runtime.")

    install_deps(env)

    from unsloth import FastLanguageModel
    from trl import SFTTrainer
    from transformers import TrainingArguments, EarlyStoppingCallback

    # ── LoRA config ───────────────────────────────────────────
    lora = get_lora_config(env["vram_gb"])
    if args.lora_r > 0:
        lora["r"] = args.lora_r
        lora["alpha"] = args.lora_r * 2
    print(f"\n[v3] LoRA config: r={lora['r']} alpha={lora['alpha']} batch={lora['batch']}×{lora['grad_accum']}")

    # ── Load model ────────────────────────────────────────────
    resume_from = None
    if args.resume and OUTPUT_DIR.exists():
        checkpoints = sorted(OUTPUT_DIR.glob("checkpoint-*"),
                             key=lambda p: int(p.name.split("-")[1]))
        if checkpoints:
            resume_from = str(checkpoints[-1])
            print(f"[v3] Resuming from {resume_from}")

    print(f"\n[v3] Loading {MODEL_NAME} (4-bit QLoRA)...")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=MODEL_NAME,
        max_seq_length=MAX_SEQ_LEN,
        dtype=None,
        load_in_4bit=True,
    )
    model = FastLanguageModel.get_peft_model(
        model,
        r=lora["r"],
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                        "gate_proj", "up_proj", "down_proj"],
        lora_alpha=lora["alpha"],
        lora_dropout=0.05,
        bias="none",
        use_gradient_checkpointing="unsloth",
        random_state=42,
    )

    # ── Dataset ───────────────────────────────────────────────
    samples = load_dataset()
    split   = build_dataset(tokenizer, samples, MAX_SEQ_LEN)
    print(f"[v3] Train: {len(split['train']):,} | Eval: {len(split['test']):,}")

    if args.dry_run:
        print("\n[v3] Dry run complete — model + dataset loaded OK. Exiting.")
        return

    # ── Training ──────────────────────────────────────────────
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    training_args = TrainingArguments(
        output_dir=str(OUTPUT_DIR),
        max_steps=args.steps,
        per_device_train_batch_size=lora["batch"],
        gradient_accumulation_steps=lora["grad_accum"],
        warmup_ratio=0.05,
        learning_rate=2e-4,
        fp16=True,
        logging_steps=10,
        evaluation_strategy="steps",
        eval_steps=50,
        save_strategy="steps",
        save_steps=100,
        save_total_limit=2,
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        optim="adamw_8bit",
        weight_decay=0.01,
        lr_scheduler_type="cosine",
        report_to="none",
        run_name="hancock-v3",
    )
    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=split["train"],
        eval_dataset=split["test"],
        dataset_text_field="text",
        max_seq_length=MAX_SEQ_LEN,
        args=training_args,
        callbacks=[EarlyStoppingCallback(early_stopping_patience=5)],
    )

    eff_batch = lora["batch"] * lora["grad_accum"]
    print(f"\n[v3] 🚀 Training — {args.steps} steps | LoRA r={lora['r']} | effective batch={eff_batch}")
    trainer.train(resume_from_checkpoint=resume_from)

    # ── Save adapter ──────────────────────────────────────────
    model.save_pretrained(str(OUTPUT_DIR))
    tokenizer.save_pretrained(str(OUTPUT_DIR))
    print(f"\n[v3] ✅ Adapter saved → {OUTPUT_DIR}/")

    # ── GGUF export ───────────────────────────────────────────
    if args.export_gguf:
        export_gguf(model, tokenizer, OUTPUT_DIR)

    # ── Push to HuggingFace Hub ───────────────────────────────
    if args.push_to_hub:
        hf_token = os.getenv("HF_TOKEN")
        if not hf_token:
            print("\n[v3] Set HF_TOKEN env var to push to HuggingFace Hub:")
            print("     export HF_TOKEN=hf_your_token_here")
        else:
            print(f"\n[v3] Pushing adapter to https://huggingface.co/{args.hf_repo} ...")
            model.push_to_hub(args.hf_repo, token=hf_token, private=True)
            tokenizer.push_to_hub(args.hf_repo, token=hf_token, private=True)
            print(f"[v3] ✅ Pushed → https://huggingface.co/{args.hf_repo}")

    print("\n[v3] ══════════════════════════════════════════")
    print(f"[v3]  Training complete!")
    print(f"[v3]  Adapter : {OUTPUT_DIR}/")
    print(f"[v3]  Next    : load adapter in hancock_agent.py")
    print("[v3] ══════════════════════════════════════════\n")


if __name__ == "__main__":
    main()
