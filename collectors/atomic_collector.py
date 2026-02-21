"""
Atomic Red Team Collector
Source: https://github.com/redcanaryco/atomic-red-team (free, MIT license)

Fetches YAML test cases mapped to MITRE ATT&CK techniques.
Each atomic test = a real adversary TTP with commands, prerequisites, cleanup.
Generates high-quality "how would an attacker do X" training samples.
Outputs: data/raw_atomic.json
"""
import json
import time
from pathlib import Path
import requests
import re

OUTPUT_FILE = Path(__file__).parent.parent / "data" / "raw_atomic.json"

# Technique index from Atomic Red Team GitHub
ATOMICS_INDEX_URL = (
    "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/index.yaml"
)
ATOMICS_BASE_URL = (
    "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics"
)

# High-value techniques to collect (expand as needed)
TARGET_TECHNIQUES = [
    # Initial Access
    "T1566.001", "T1566.002", "T1190", "T1133",
    # Execution
    "T1059.001", "T1059.003", "T1059.004", "T1059.006",
    # Persistence
    "T1053.005", "T1547.001", "T1136.001", "T1543.003",
    # Privilege Escalation
    "T1055", "T1068", "T1548.002",
    # Defense Evasion
    "T1027", "T1070.001", "T1112", "T1562.001",
    # Credential Access
    "T1003.001", "T1110.001", "T1558.003", "T1552.001",
    # Discovery
    "T1082", "T1083", "T1087.001", "T1016", "T1049",
    # Lateral Movement
    "T1021.001", "T1021.002", "T1550.002",
    # Collection
    "T1560.001", "T1074.001",
    # Exfiltration
    "T1041", "T1048.003",
    # Command & Control
    "T1071.001", "T1105",
    # Impact
    "T1486", "T1490", "T1489",
]


def fetch_atomic_yaml(technique_id: str) -> dict | None:
    """Fetch and parse a single atomic test YAML file."""
    try:
        # Try with sub-technique dot notation converted to slash
        tid = technique_id.replace(".", "/")
        url = f"{ATOMICS_BASE_URL}/{technique_id}/{technique_id}.yaml"
        resp = requests.get(url, timeout=15)
        if resp.status_code != 200:
            return None

        # Simple YAML parse without pyyaml dependency
        content = resp.text
        return {"raw_yaml": content, "technique_id": technique_id, "url": url}
    except Exception as e:
        print(f"[atomic] Error fetching {technique_id}: {e}")
        return None


def parse_atomic_tests(raw: dict) -> list[dict]:
    """Extract structured test info from raw YAML text."""
    content = raw.get("raw_yaml", "")
    tid     = raw.get("technique_id", "")
    tests   = []

    # Extract attack name
    name_match = re.search(r"^attack_technique:\s*(.+)$", content, re.MULTILINE)
    display_match = re.search(r"^display_name:\s*(.+)$", content, re.MULTILINE)

    attack_name = display_match.group(1).strip() if display_match else tid

    # Find individual atomic tests (split by "- name:")
    test_blocks = re.split(r"\n- name:", content)
    for block in test_blocks[1:]:  # skip header
        lines = block.strip().split("\n")
        test_name = lines[0].strip().strip('"').strip("'") if lines else ""

        desc_match = re.search(r"description:\s*\|?\s*\n((?:\s+.+\n?)+)", block)
        desc = ""
        if desc_match:
            desc = re.sub(r"^\s+", "", desc_match.group(1), flags=re.MULTILINE).strip()

        # Extract commands
        commands = re.findall(r"command:\s*\|?\s*\n((?:\s+.+\n?)+)", block)
        cmd_text = "\n".join(
            re.sub(r"^\s+", "", c, flags=re.MULTILINE).strip() for c in commands
        )

        platform_match = re.search(r"supported_platforms:\s*\[?([^\]\n]+)\]?", block)
        platforms = platform_match.group(1).strip() if platform_match else ""

        if test_name and (desc or cmd_text):
            tests.append({
                "technique_id": tid,
                "technique_name": attack_name,
                "test_name": test_name,
                "description": desc[:800],
                "commands": cmd_text[:600],
                "platforms": platforms,
            })

    return tests


def collect():
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    all_tests = []

    print(f"[atomic] Fetching {len(TARGET_TECHNIQUES)} ATT&CK techniques from Atomic Red Team...")
    for i, tid in enumerate(TARGET_TECHNIQUES):
        raw = fetch_atomic_yaml(tid)
        if raw:
            tests = parse_atomic_tests(raw)
            all_tests.extend(tests)
            print(f"[atomic] {tid}: {len(tests)} tests")
        time.sleep(0.3)

    with open(OUTPUT_FILE, "w") as f:
        json.dump(all_tests, f, indent=2)
    print(f"[atomic] Saved {len(all_tests)} atomic tests → {OUTPUT_FILE}")
    return all_tests


if __name__ == "__main__":
    collect()
