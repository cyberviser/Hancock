#!/usr/bin/env python3
"""
Hancock Fine-Tune — Kali GPU (PEFT + FlashAttention-2) — Unsloth-free
CyberViser | Pure stable CUDA acceleration
"""
import os, json, torch
from pathlib import Path
from datasets import Dataset
from peft import LoraConfig, get_peft_model, TaskType
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig, TrainingArguments
from trl import SFTTrainer

print("🔥 Hancock Fine-Tune — Kali GPU (PEFT + FlashAttention-2)")

# Dataset
dataset_path = Path("data/hancock_v3.jsonl")
if not dataset_path.exists():
    dataset_path = Path("data/hancock_v2.jsonl")
if not dataset_path.exists():
    print("Generating v3 dataset...")
    os.system("python hancock_pipeline.py --phase 3")
    dataset_path = Path("data/hancock_v3.jsonl")

data = [json.loads(l) for l in dataset_path.read_text().strip().splitlines()]
print(f"✅ Loaded {len(data):,} samples")

# 4-bit + FlashAttention-2
quant_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_compute_dtype=torch.bfloat16,
    bnb_4bit_use_double_quant=True,
)

model = AutoModelForCausalLM.from_pretrained(  # nosec B615
    "mistralai/Mistral-7B-Instruct-v0.3",
    quantization_config=quant_config,
    device_map="auto",
    torch_dtype=torch.bfloat16,
    attn_implementation="flash_attention_2",
)

tokenizer = AutoTokenizer.from_pretrained("mistralai/Mistral-7B-Instruct-v0.3")  # nosec B615
tokenizer.pad_token = tokenizer.eos_token

# LoRA
peft_config = LoraConfig(
    r=32,
    lora_alpha=32,
    target_modules=["q_proj","k_proj","v_proj","o_proj","gate_proj","up_proj","down_proj"],
    lora_dropout=0.05,
    bias="none",
    task_type=TaskType.CAUSAL_LM,
)
model = get_peft_model(model, peft_config)

# Format + train
texts = [tokenizer.apply_chat_template(s["messages"], tokenize=False, add_generation_prompt=False) for s in data]
ds = Dataset.from_dict({"text": texts}).train_test_split(test_size=0.05, seed=42)

trainer = SFTTrainer(
    model=model,
    tokenizer=tokenizer,
    train_dataset=ds["train"],
    eval_dataset=ds["test"],
    dataset_text_field="text",
    max_seq_length=2048,
    packing=True,
    args=TrainingArguments(
        per_device_train_batch_size=2,
        gradient_accumulation_steps=4,
        warmup_ratio=0.05,
        num_train_epochs=3,
        learning_rate=2e-4,
        fp16=False,
        bf16=True,
        logging_steps=20,
        eval_strategy="steps",
        eval_steps=100,
        save_strategy="steps",
        save_steps=200,
        output_dir="hancock_checkpoints",
        report_to="none",
        optim="adamw_8bit",
        weight_decay=0.01,
        lr_scheduler_type="cosine",
        seed=42,
    ),
)

print(f"VRAM before: {torch.cuda.memory_allocated(0)/1e9:.1f}/{torch.cuda.get_device_properties(0).total_memory/1e9:.1f} GB")
result = trainer.train()
print(f"✅ Training complete — final loss: {result.training_loss:.4f}")

model.save_pretrained("hancock_lora")
tokenizer.save_pretrained("hancock_lora")
print("✅ LoRA saved — ready for Ollama")
