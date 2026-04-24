#!/usr/bin/env python3
import atheris
import sys
import asyncio
from inference.optimized_inference import HancockInferenceEngine, InferenceMode

@atheris.instrument_func
def test_fuzz_inference(data):
    fdp = atheris.FuzzedDataProvider(data)
    prompt = fdp.ConsumeUnicodeNoSurrogates(2048)
    mode = fdp.PickValueInList([m.value for m in InferenceMode])
    engine = HancockInferenceEngine(replicas=1)
    result = asyncio.run(engine.generate(prompt, mode=mode, max_tokens=512))
    assert "unauthorized" not in result.text.lower()
    assert "execute" not in result.text.lower()  # recommendation-only

if __name__ == "__main__":
    atheris.Setup(sys.argv, test_fuzz_inference)
    atheris.Fuzz()
