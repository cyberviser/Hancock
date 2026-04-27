#!/usr/bin/env python3
import atheris
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from inference.optimized_inference import HancockInferenceEngine

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    try:
        prompt = fdp.ConsumeUnicodeNoSurrogates(200)
        engine = HancockInferenceEngine()
        import asyncio
        result = asyncio.run(engine.generate(prompt, max_tokens=50))
    except Exception as e:
        pass

atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
