"""
NVD CVE Collector
Fetches recent Critical/High severity CVEs from the NVD public API (no key required).
Outputs: data/raw_cve.json
"""
import json
import time
from pathlib import Path
import requests
from tqdm import tqdm

OUTPUT_FILE = Path(__file__).parent.parent / "data" / "raw_cve.json"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Pull last 120 days of Critical + High CVEs, max 500 entries
PARAMS_BASE = {
    "resultsPerPage": 100,
    "cvssV3Severity": "CRITICAL",
}


def fetch_page(start_index: int, severity: str) -> dict:
    params = {**PARAMS_BASE, "startIndex": start_index, "cvssV3Severity": severity}
    for attempt in range(3):
        try:
            resp = requests.get(NVD_API, params=params, timeout=30)
            if resp.status_code == 200:
                return resp.json()
            time.sleep(2 ** attempt)
        except requests.RequestException as e:
            print(f"[nvd] Request error: {e}, retrying...")
            time.sleep(2 ** attempt)
    return {}


def parse_cve(vuln: dict) -> dict | None:
    cve = vuln.get("cve", {})
    cve_id = cve.get("id", "")
    descriptions = cve.get("descriptions", [])
    desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
    if not desc_en or len(desc_en) < 50:
        return None

    metrics = cve.get("metrics", {})
    cvss_data = (
        metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
        or metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
    )
    score = cvss_data.get("baseScore", 0)
    vector = cvss_data.get("attackVector", "")
    severity = cvss_data.get("baseSeverity", "")

    weaknesses = cve.get("weaknesses", [])
    cwes = [
        d["value"] for w in weaknesses
        for d in w.get("description", [])
        if d.get("value", "").startswith("CWE-")
    ]

    refs = [r["url"] for r in cve.get("references", [])[:3]]

    return {
        "cve_id": cve_id,
        "description": desc_en,
        "cvss_score": score,
        "severity": severity,
        "attack_vector": vector,
        "cwes": cwes,
        "references": refs,
    }


def collect():
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    all_cves = []

    for severity in ["CRITICAL", "HIGH"]:
        print(f"[nvd] Fetching {severity} CVEs...")
        first = fetch_page(0, severity)
        total = first.get("totalResults", 0)
        cap = min(total, 250)  # 250 per severity = 500 max
        print(f"[nvd] {total} {severity} CVEs available, fetching up to {cap}")

        for vuln in first.get("vulnerabilities", []):
            parsed = parse_cve(vuln)
            if parsed:
                all_cves.append(parsed)

        for start in tqdm(range(100, cap, 100), desc=f"{severity}"):
            time.sleep(0.6)  # NVD rate limit: ~5 req/30s without API key
            page = fetch_page(start, severity)
            for vuln in page.get("vulnerabilities", []):
                parsed = parse_cve(vuln)
                if parsed:
                    all_cves.append(parsed)

    with open(OUTPUT_FILE, "w") as f:
        json.dump(all_cves, f, indent=2)
    print(f"[nvd] Saved {len(all_cves)} CVEs → {OUTPUT_FILE}")
    return all_cves


if __name__ == "__main__":
    collect()
