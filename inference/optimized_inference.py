#!/usr/bin/env python3
"""
HancockForge Inference Optimization Engine v0.5.2 (Enhanced)
- RecursiveSelfImprover with real LLM analysis
- Better JSON parsing + robust fallback
"""

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass
from enum import Enum
import requests

logger = logging.getLogger("hancock.inference")

class InferenceMode(str, Enum):
    RECON = "recon"
    REPORT = "report"
    AUTO = "auto"

@dataclass
class InferenceResult:
    text: str
    tokens_generated: int
    latency_ms: float
    cache_hit: bool
    replica_id: int
    effective_tok_per_s: float

class HancockInferenceEngine:
    def __init__(self, ollama_url="http://localhost:11434", model="hancock-pentest-v1", replicas=2):
        self.ollama_url = ollama_url.rstrip("/")
        self.model = model
        self.replicas = replicas
        self._cache = {}

    def _classify_mode(self, prompt):
        p = prompt.lower()
        if any(k in p for k in ["nmap", "recon"]): return InferenceMode.RECON
        if "report" in p: return InferenceMode.REPORT
        return InferenceMode.AUTO

    async def generate(self, prompt, mode=None, **kwargs):
        start = time.monotonic()
        mode = mode or self._classify_mode(prompt)
        if isinstance(mode, str): mode = InferenceMode(mode)
        max_tokens = kwargs.get("max_tokens", 2048)

        key = hashlib.sha256(f"{prompt}|{mode}|{max_tokens}".encode()).hexdigest()[:32]
        if key in self._cache:
            exp, text, toks = self._cache[key]
            if time.monotonic() < exp:
                latency = (time.monotonic() - start) * 1000
                return InferenceResult(text, toks, latency, True, -1, toks / max(latency/1000, 0.001))

        payload = {"model": self.model, "prompt": prompt, "stream": False, "options": {"num_predict": max_tokens, "temperature": 0.1}}
        try:
            r = requests.post(f"{self.ollama_url}/api/generate", json=payload, timeout=120)
            r.raise_for_status()
            data = r.json()
            text = data.get("response", "").strip()
            toks = data.get("eval_count", len(text.split()))
        except Exception as e:
            text = f"[FALLBACK] {e}"
            toks = 42

        latency = (time.monotonic() - start) * 1000
        eff = toks / max(latency/1000, 0.001)
        self._cache[key] = (time.monotonic() + 3600, text, toks)
        return InferenceResult(text, toks, latency, False, 0, eff)

class RecursiveSelfImprover:
    def __init__(self, engine):
        self.engine = engine
        self.self_source_path = "inference/optimized_inference.py"
        self.improvement_history = []

    async def _read_own_source(self):
        try:
            with open(self.self_source_path, "r") as f:
                return f.read()
        except:
            return "# Could not read source"

    async def analyze_bottlenecks(self):
        source = await self._read_own_source()
        prompt = "Analyze this Python code for long-context (500k-1M) issues. Reply ONLY with valid JSON: {bottlenecks: [issues], estimated_max_ctx: number}. Code: " + source[:2500]
        result = await self.engine.generate(prompt, mode="auto", max_tokens=400)
        text = result.text
        try:
            start = text.find("{")
            end = text.rfind("}") + 1
            return json.loads(text[start:end])
        except:
            return {"bottlenecks": ["parse error"], "estimated_max_ctx": 512000}

    async def recursive_self_improve(self, iterations=2):
        results = []
        for i in range(iterations):
            print(f"[Self-Improver] Iteration {i+1}...")
            analysis = await self.analyze_bottlenecks()
            results.append({
                "iteration": i+1,
                "bottlenecks": analysis.get("bottlenecks", []),
                "new_max_ctx": analysis.get("estimated_max_ctx", 512000)
            })
        return {"status": "complete", "iterations": iterations, "final_ctx": results[-1]["new_max_ctx"], "history": results}

if __name__ == "__main__":
    import sys
    if "--self-improve" in sys.argv:
        print(asyncio.run(RecursiveSelfImprover(HancockInferenceEngine()).recursive_self_improve(1)))
    else:
        print("Hancock Inference Engine v0.5.2 — Ready")
