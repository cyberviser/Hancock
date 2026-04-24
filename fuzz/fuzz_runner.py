import json
import sys

import atheris

with atheris.instrument_imports():
    from sandbox.runner import run_tool_safely


def TestOneInput(data):
    try:
        obj = json.loads(data.decode("utf-8", "ignore"))
    except Exception:
        return

    tool = obj.get("tool", "nmap")
    args = obj.get("args", ["-V"])
    run_tool_safely(tool, args, {})


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
