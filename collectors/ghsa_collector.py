"""
GitHub Security Advisories (GHSA) Collector
Source: https://api.github.com/advisories (free, no auth for public data)

Covers OSS vulnerabilities across npm, PyPI, Go, Maven, RubyGems, Cargo, etc.
Critical supplement to NVD — catches many vulns before they get CVE IDs.
Outputs: data/raw_ghsa.json
"""
import json
import time
from pathlib import Path
import requests

OUTPUT_FILE = Path(__file__).parent.parent / "data" / "raw_ghsa.json"
GHSA_API    = "https://api.github.com/advisories"

# Ecosystems to cover
ECOSYSTEMS = ["npm", "pip", "go", "maven", "rubygems", "cargo", "nuget"]


def fetch_advisories(ecosystem: str, severity: str, per_page: int = 100) -> list:
    """Fetch advisories for a given ecosystem and severity."""
    results = []
    params  = {
        "ecosystem":    ecosystem,
        "severity":     severity,
        "per_page":     per_page,
        "type":         "reviewed",
    }
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    # Add token if available (higher rate limits)
    gh_token = __import__("os").getenv("GITHUB_TOKEN", "")
    if gh_token:
        headers["Authorization"] = f"Bearer {gh_token}"

    try:
        resp = requests.get(GHSA_API, params=params, headers=headers, timeout=20)
        if resp.status_code == 200:
            results = resp.json()
        elif resp.status_code == 403:
            print(f"[ghsa] Rate limited — set GITHUB_TOKEN for higher limits")
        else:
            print(f"[ghsa] HTTP {resp.status_code} for {ecosystem}/{severity}")
    except Exception as e:
        print(f"[ghsa] Error: {e}")
    return results


def parse_advisory(adv: dict) -> dict | None:
    """Extract relevant fields from a GHSA advisory."""
    summary = adv.get("summary", "")
    desc    = adv.get("description", "")
    if not summary or not desc:
        return None

    cvss = adv.get("cvss", {}) or {}
    cwes = [c.get("cwe_id", "") for c in adv.get("cwes", [])]
    packages = [
        f"{v.get('package', {}).get('name', '')} ({v.get('package', {}).get('ecosystem', '')})"
        for v in adv.get("vulnerabilities", [])
    ]
    identifiers = [i.get("value", "") for i in adv.get("identifiers", []) if i.get("type") == "CVE"]

    return {
        "ghsa_id":    adv.get("ghsa_id", ""),
        "cve_id":     identifiers[0] if identifiers else "",
        "summary":    summary,
        "description": desc[:1000],
        "severity":   adv.get("severity", ""),
        "cvss_score": cvss.get("score", 0),
        "cwes":       cwes,
        "packages":   packages[:5],
        "ecosystem":  adv.get("vulnerabilities", [{}])[0].get("package", {}).get("ecosystem", ""),
        "published":  adv.get("published_at", ""),
        "references": [r.get("url", "") for r in adv.get("references", [])[:3]],
    }


def collect(max_per_eco: int = 100):
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    all_advisories = []

    for ecosystem in ECOSYSTEMS:
        for severity in ["critical", "high"]:
            print(f"[ghsa] Fetching {ecosystem}/{severity}...")
            raw = fetch_advisories(ecosystem, severity, per_page=min(max_per_eco, 100))
            for adv in raw:
                parsed = parse_advisory(adv)
                if parsed:
                    all_advisories.append(parsed)
            time.sleep(1.0)  # respect rate limits

    # Deduplicate by GHSA ID
    seen, unique = set(), []
    for a in all_advisories:
        if a["ghsa_id"] not in seen:
            seen.add(a["ghsa_id"])
            unique.append(a)

    with open(OUTPUT_FILE, "w") as f:
        json.dump(unique, f, indent=2)
    print(f"[ghsa] Saved {len(unique)} advisories → {OUTPUT_FILE}")
    return unique


if __name__ == "__main__":
    collect()
