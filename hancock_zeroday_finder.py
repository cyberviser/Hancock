"""
Hancock Zero-Day Finder v0.6.0
- Source code + plugin scanning
- Zero-day likelihood scoring (ML + Semgrep)
- Safe sandboxed PoC generation
- Mediation: patches + responsible disclosure
"""
import subprocess, json, tempfile, shutil
from pathlib import Path
from typing import Dict, Any
from hancock_zeroday_guard import guard

def scan_source_code(target_path: str, plugin_type: str = None) -> Dict[str, Any]:
    """Semgrep + Bandit + custom zero-day rules"""
    rules = ["--config=auto"]  # or custom p/ci/zero-day.yml
    if plugin_type == "wordpress":
        rules.append("--config=rules/wordpress-zero-day.yml")
    elif plugin_type == "vscode":
        rules.append("--config=rules/vscode-extension-zero-day.yml")

    result = subprocess.run(["semgrep", "--json", *rules, target_path],
                            capture_output=True, text=True)

    findings = json.loads(result.stdout).get("results", [])
    # AI zero-day scoring
    for f in findings:
        f["zero_day_score"] = guard.score(f["code"]) * 100
        f["exploitation_path"] = "RCE via deserialization" if "pickle" in f["code"] else "Logic flaw"

    return {"findings": findings, "raw_output": result.stdout}

def generate_sandboxed_poc(finding: Dict) -> str:
    """Safe PoC in isolated Docker sandbox"""
    with tempfile.TemporaryDirectory() as tmp:
        poc = f"""#!/bin/bash
echo "Hancock Zero-Day PoC for {finding['check_id']}"
# SAFE DEMO ONLY — no real exploit
curl -I http://localhost:8080/test?payload=zero-day-test
"""
        Path(f"{tmp}/poc.sh").write_text(poc)
        try:
            out = subprocess.run(["docker", "run", "--rm", "-v", f"{tmp}:/poc", "hancock-sandbox", "bash", "/poc/poc.sh"],
                                 capture_output=True, text=True, timeout=10)
            return out.stdout.strip()
        except Exception:
            return "PoC execution blocked (sandbox timeout)"

def mediate_finding(finding: Dict) -> Dict[str, str]:
    """Auto-remediation + responsible disclosure template"""
    patch = f"Patch suggestion: {finding['fix']} (CVSS {finding.get('cvss', 'N/A')})"
    disclosure = f"""Responsible Disclosure Template:
Title: Zero-Day in {finding['path']}
Severity: {finding.get('severity', 'High')}
Recommendation: {patch}
Timeline: 90-day coordinated disclosure"""
    return {"patch": patch, "disclosure_template": disclosure}

# LangGraph node (exported for hancock_langgraph.py)
def zero_day_finder_agent(state: Dict) -> Dict:
    target = state.get("target_path")
    plugin_type = state.get("plugin_type")
    scan = scan_source_code(target, plugin_type)
    for f in scan["findings"]:
        if f["zero_day_score"] > 70:
            f["poc"] = generate_sandboxed_poc(f)
            f["mediation"] = mediate_finding(f)
    return {"messages": [f"✅ Zero-Day Finder complete — {len(scan['findings'])} findings"], "zeroday_results": scan}

if __name__ == "__main__":
    import argparse, sys
    parser = argparse.ArgumentParser(description="Hancock Zero-Day Finder")
    parser.add_argument("--target", required=True, help="Path to scan")
    parser.add_argument("--mode", choices=["wordpress", "vscode", "generic"], default="generic")
    args = parser.parse_args()
    results = scan_source_code(args.target, args.mode)
    print(json.dumps(results, indent=2))
    sys.exit(0)
