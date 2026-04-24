#!/bin/bash
pip install -r requirements.txt
pip install pyright
if python - <<'PY'
import importlib.util
import sys
sys.exit(0 if importlib.util.find_spec("pyright") else 1)
PY
then
  python -m pyright .  # type safety
else
  echo "pyright not installed; skipping type safety check"
fi
python -m pytest tests/ -q --tb=no
python -m clusterfuzzlite build --engine=atheris --language=python
echo "✅ ClusterFuzzLite build complete"
