#!/usr/bin/env python3
"""
Hancock Pipeline — Master Runner
CyberViser | Hancock AI Agent Phase 1: Pentest Specialist

Runs all data collectors and the formatter in sequence to produce:
    data/hancock_pentest_v1.jsonl

Usage:
    python hancock_pipeline.py           # full pipeline
    python hancock_pipeline.py --kb-only # static KB only (no internet required)
    python hancock_pipeline.py --skip-nvd # skip NVD (rate limited without API key)
"""
import argparse
import sys
import time
from pathlib import Path

# ── Banner ────────────────────────────────────────────────────────────────────
BANNER = """
╔═══════════════════════════════════════════════════════╗
║           CyberViser — Hancock AI Agent               ║
║        Phase 1: Pentest Dataset Pipeline              ║
╚═══════════════════════════════════════════════════════╝
"""


def run_kb(data_dir: Path) -> bool:
    print("\n[1/3] Building static pentest knowledge base...")
    try:
        sys.path.insert(0, str(Path(__file__).parent))
        from collectors.pentest_kb import build
        build()
        return True
    except Exception as e:
        print(f"[kb] ERROR: {e}")
        return False


def run_mitre(data_dir: Path) -> bool:
    print("\n[2/3] Fetching MITRE ATT&CK techniques...")
    try:
        from collectors.mitre_collector import collect
        collect()
        return True
    except Exception as e:
        print(f"[mitre] ERROR: {e}")
        print("[mitre] Skipping MITRE — continuing with available data")
        return False


def run_nvd(data_dir: Path) -> bool:
    print("\n[3/3] Fetching NVD CVE data (this may take ~2 minutes due to rate limits)...")
    try:
        from collectors.nvd_collector import collect
        collect()
        return True
    except Exception as e:
        print(f"[nvd] ERROR: {e}")
        print("[nvd] Skipping NVD — continuing with available data")
        return False


def run_soc_kb(data_dir: Path) -> bool:
    print("\n[soc] Building SOC analyst knowledge base...")
    try:
        from collectors.soc_kb import build
        build()
        return True
    except Exception as e:
        print(f"[soc-kb] ERROR: {e}")
        return False


def run_soc_collector(data_dir: Path) -> bool:
    print("\n[soc] Fetching SOC detection data (MITRE detections + Sigma)...")
    try:
        from collectors.soc_collector import collect
        collect()
        return True
    except Exception as e:
        print(f"[soc-collector] ERROR: {e}")
        return False


def run_formatter(v2: bool = False) -> bool:
    label = "v2 (Pentest + SOC)" if v2 else "v1 (Pentest only)"
    print(f"\n[formatter] Formatting dataset → Mistral JSONL {label}...")
    try:
        if v2:
            from formatter.to_mistral_jsonl_v2 import format_all
        else:
            from formatter.to_mistral_jsonl import format_all
        samples = format_all()
        if not samples:
            print("[formatter] ERROR: No samples generated")
            return False
        return True
    except Exception as e:
        print(f"[formatter] ERROR: {e}")
        return False


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(description="Hancock Dataset Pipeline (Pentest + SOC)")
    parser.add_argument("--kb-only",    action="store_true", help="Only build static KBs (no internet needed)")
    parser.add_argument("--skip-nvd",   action="store_true", help="Skip NVD CVE collection")
    parser.add_argument("--skip-mitre", action="store_true", help="Skip MITRE ATT&CK collection")
    parser.add_argument("--phase",      choices=["1", "2", "all"], default="all",
                        help="1=Pentest only, 2=SOC only, all=both (default)")
    args = parser.parse_args()

    data_dir = Path(__file__).parent / "data"
    data_dir.mkdir(exist_ok=True)

    phase1 = args.phase in ("1", "all")
    phase2 = args.phase in ("2", "all")
    start  = time.time()
    results = {}

    if phase1:
        results["pentest-kb"] = run_kb(data_dir)
    if phase2:
        results["soc-kb"]        = run_soc_kb(data_dir)
        results["soc-detections"] = run_soc_collector(data_dir)

    if not args.kb_only:
        if phase1:
            if not args.skip_mitre:
                results["mitre"] = run_mitre(data_dir)
            if not args.skip_nvd:
                results["nvd"] = run_nvd(data_dir)

    v2 = phase2  # use v2 formatter when SOC data present
    results["formatter"] = run_formatter(v2=v2)

    elapsed = time.time() - start

    # Summary
    print("\n" + "═" * 55)
    print("  PIPELINE SUMMARY")
    print("═" * 55)
    status_icons = {True: "✅", False: "❌", None: "⏭ "}
    for step, ok in results.items():
        print(f"  {status_icons.get(ok, '?')}  {step}")
    print(f"\n  ⏱  Completed in {elapsed:.1f}s")

    output = Path(__file__).parent / "data" / "hancock_v2.jsonl"
    if not output.exists():
        output = Path(__file__).parent / "data" / "hancock_pentest_v1.jsonl"
    if output.exists():
        size_kb = output.stat().st_size / 1024
        # Count lines
        with open(output) as f:
            count = sum(1 for _ in f)
        print(f"\n  📦 Output: {output}")
        print(f"  📊 Samples: {count:,} | Size: {size_kb:.1f} KB")
        print("\n  Next step: python hancock_finetune.py")
    else:
        print("\n  ⚠️  Output file not created — check errors above")
    print("═" * 55)


if __name__ == "__main__":
    main()
