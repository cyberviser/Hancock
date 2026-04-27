#!/usr/bin/env python3
"""
Feedback Loop: ClusterFuzzLite → RecursiveSelfImprover
"""
import asyncio
import sys
import os

# Add project root to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from inference.optimized_inference import HancockInferenceEngine, RecursiveSelfImprover

async def process_fuzz_crash(crash_info: str):
    engine = HancockInferenceEngine()
    prompt = f"""A fuzzer found this crash: {crash_info}
Analyze and propose a fix. Return JSON with: analysis, proposed_fix, risk_level"""
    result = await engine.generate(prompt, mode="auto", max_tokens=600)
    return result.text

async def main():
    example_crash = "Segmentation fault when processing very long prompt (over 100k tokens)"
    print("[Feedback Loop] Processing fuzz crash...")
    result = await process_fuzz_crash(example_crash)
    print("[Feedback Loop] Self-Improver response:")
    print(result)

if __name__ == "__main__":
    asyncio.run(main())
