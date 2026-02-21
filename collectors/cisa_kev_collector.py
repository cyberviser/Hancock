"""
CISA KEV Collector — Known Exploited Vulnerabilities
Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog (free, no key)

These are the highest-value training samples — actively exploited in the wild.
Outputs: data/raw_kev.json (~1000 entries)
"""
import json
import time
from pathlib import Path
import requests

OUTPUT_FILE = Path(__file__).parent.parent / "data" / "raw_kev.json"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def enrich_with_nvd(cve_id: str) -> dict:
    """Fetch CVSS score + description from NVD for a KEV entry."""
    try:
        resp = requests.get(NVD_API, params={"cveId": cve_id}, timeout=15)
        if resp.status_code != 200:
            return {}
        vulns = resp.json().get("vulnerabilities", [])
        if not vulns:
            return {}
        cve = vulns[0].get("cve", {})
        descriptions = cve.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        cvss = (
            metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
            or metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
        )
        return {
            "nvd_description": desc,
            "cvss_score": cvss.get("baseScore", 0),
            "attack_vector": cvss.get("attackVector", ""),
            "privileges_required": cvss.get("privilegesRequired", ""),
            "user_interaction": cvss.get("userInteraction", ""),
        }
    except Exception:
        return {}


def collect(enrich: bool = True, max_enrich: int = 300):
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    print("[kev] Fetching CISA KEV catalog...")
    resp = requests.get(KEV_URL, timeout=30)
    resp.raise_for_status()
    catalog = resp.json()
    vulns = catalog.get("vulnerabilities", [])
    print(f"[kev] {len(vulns)} KEV entries fetched")

    results = []
    for i, v in enumerate(vulns):
        entry = {
            "cve_id":            v.get("cveID", ""),
            "vendor":            v.get("vendorProject", ""),
            "product":           v.get("product", ""),
            "name":              v.get("vulnerabilityName", ""),
            "description":       v.get("shortDescription", ""),
            "action_required":   v.get("requiredAction", ""),
            "date_added":        v.get("dateAdded", ""),
            "due_date":          v.get("dueDate", ""),
            "known_ransomware":  v.get("knownRansomwareCampaignUse", "Unknown"),
            "notes":             v.get("notes", ""),
        }
        # Enrich top N with NVD data (rate limited)
        if enrich and i < max_enrich and entry["cve_id"]:
            nvd = enrich_with_nvd(entry["cve_id"])
            entry.update(nvd)
            time.sleep(0.7)  # NVD rate limit

        results.append(entry)

    with open(OUTPUT_FILE, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[kev] Saved {len(results)} KEV entries → {OUTPUT_FILE}")
    return results


if __name__ == "__main__":
    collect()
