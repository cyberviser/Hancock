"""
MITRE ATT&CK Collector
Fetches techniques, tactics, and mitigations from MITRE ATT&CK via TAXII 2.1
Outputs: data/raw_mitre.json
"""
import json
import sys
from pathlib import Path

try:
    from stix2 import TAXIICollectionSource, Filter
    from taxii2client.v21 import Server
except ImportError:
    try:
        from stix2 import TAXIICollectionSource, Filter
        from taxii2client.v20 import Server
    except ImportError:
        print("[mitre] stix2/taxii2client not available, using requests fallback")
        Server = None

import requests

OUTPUT_FILE = Path(__file__).parent.parent / "data" / "raw_mitre.json"
TAXII_URL = "https://attack.mitre.org/taxii/"
ATT_CK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"


def fetch_via_stix():
    """Fetch ATT&CK via TAXII (preferred method)."""
    print("[mitre] Connecting to MITRE ATT&CK TAXII server...")
    server = Server(TAXII_URL)
    api_root = server.api_roots[0]

    techniques = []
    tactics = []

    for collection in api_root.collections:
        if "Enterprise ATT&CK" in collection.title:
            src = TAXIICollectionSource(collection)
            # Fetch techniques
            tech_filter = Filter("type", "=", "attack-pattern")
            raw_techniques = src.query([tech_filter])
            for t in raw_techniques:
                if t.get("revoked") or t.get("x_mitre_deprecated"):
                    continue
                entry = {
                    "id": t.get("id", ""),
                    "name": t.get("name", ""),
                    "description": t.get("description", ""),
                    "kill_chain_phases": [
                        p["phase_name"] for p in t.get("kill_chain_phases", [])
                    ],
                    "platforms": t.get("x_mitre_platforms", []),
                    "detection": t.get("x_mitre_detection", ""),
                    "mitre_id": next(
                        (ref["external_id"] for ref in t.get("external_references", [])
                         if ref.get("source_name") == "mitre-attack"), ""
                    ),
                }
                techniques.append(entry)
            print(f"[mitre] Fetched {len(techniques)} techniques via TAXII")
            break

    return {"techniques": techniques, "tactics": tactics}


def fetch_via_github():
    """Fallback: fetch ATT&CK bundle from MITRE CTI GitHub."""
    print("[mitre] Fetching ATT&CK from MITRE CTI GitHub (fallback)...")
    resp = requests.get(ATT_CK_URL, timeout=60)
    resp.raise_for_status()
    bundle = resp.json()

    techniques = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        entry = {
            "id": obj.get("id", ""),
            "name": obj.get("name", ""),
            "description": obj.get("description", ""),
            "kill_chain_phases": [
                p["phase_name"] for p in obj.get("kill_chain_phases", [])
            ],
            "platforms": obj.get("x_mitre_platforms", []),
            "detection": obj.get("x_mitre_detection", ""),
            "mitre_id": next(
                (ref["external_id"] for ref in obj.get("external_references", [])
                 if ref.get("source_name") == "mitre-attack"), ""
            ),
        }
        techniques.append(entry)

    print(f"[mitre] Fetched {len(techniques)} techniques via GitHub")
    return {"techniques": techniques, "tactics": []}


def collect():
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        if Server:
            data = fetch_via_stix()
        else:
            data = fetch_via_github()
    except Exception as e:
        print(f"[mitre] TAXII failed ({e}), falling back to GitHub...")
        data = fetch_via_github()

    with open(OUTPUT_FILE, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[mitre] Saved {len(data['techniques'])} techniques → {OUTPUT_FILE}")
    return data


if __name__ == "__main__":
    collect()
