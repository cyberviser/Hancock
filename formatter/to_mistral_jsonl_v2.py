"""
JSONL Formatter v2 — Phase 2: SOC Analyst
Converts all raw data (pentest + SOC) into Mistral instruct format JSONL.
Output: data/hancock_v2.jsonl
"""
import json
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "data"
OUTPUT_FILE = DATA_DIR / "hancock_v2.jsonl"

PENTEST_SYSTEM = (
    "You are Hancock, an expert penetration tester and security researcher built by CyberViser. "
    "You operate strictly within authorized scope and legal boundaries on systems you have explicit "
    "written permission to test. You help security professionals understand attack techniques, "
    "identify vulnerabilities, and perform authorized penetration tests. You always recommend "
    "responsible disclosure and remediation."
)

SOC_SYSTEM = (
    "You are Hancock, an expert SOC analyst and incident responder built by CyberViser. "
    "You triage security alerts, analyze logs, hunt threats, and lead incident response. "
    "You write precise SIEM queries (Splunk SPL, Elastic KQL, Microsoft Sentinel KQL), "
    "analyze IOCs, and follow NIST IR and PICERL frameworks. "
    "You are calm under pressure, methodical, and always document your findings."
)

# Categories that belong to SOC mode
SOC_CATEGORIES = {
    "alert_triage", "log_analysis", "siem_queries", "incident_response",
    "threat_hunting", "ioc_analysis", "detection_engineering", "malware_triage",
    "soc_tools", "soc_reporting", "soc_detection", "sigma_rules",
    "cloud_security_soc", "active_directory_detection",
}


def _system_for(category: str) -> str:
    return SOC_SYSTEM if category in SOC_CATEGORIES else PENTEST_SYSTEM


def format_kb_pairs(kb_data: dict, override_system: str | None = None) -> list[dict]:
    """Convert static Q&A pairs to Mistral instruct format."""
    samples = []
    for pair in kb_data.get("pairs", []):
        system = override_system or kb_data.get("system_prompt") or _system_for(pair.get("category", ""))
        samples.append({
            "messages": [
                {"role": "system",    "content": system},
                {"role": "user",      "content": pair["user"]},
                {"role": "assistant", "content": pair["assistant"]},
            ]
        })
    return samples


def format_mitre_techniques(mitre_data: dict) -> list[dict]:
    samples = []
    for tech in mitre_data.get("techniques", []):
        name = tech.get("name", "")
        desc = tech.get("description", "")
        mitre_id = tech.get("mitre_id", "")
        tactics = tech.get("kill_chain_phases", [])
        detection = tech.get("detection", "")
        platforms = tech.get("platforms", [])

        if not name or not desc or len(desc) < 80:
            continue

        tactic_str = ", ".join(t.replace("-", " ").title() for t in tactics)
        platform_str = ", ".join(platforms) if platforms else "Multiple"
        desc_short = desc[:1200]
        det_short = detection[:600] if detection else ""

        question = f"Explain the MITRE ATT&CK technique {name} ({mitre_id}) and how defenders can detect and mitigate it."
        answer = (
            f"**{name} ({mitre_id})**\n"
            f"**Tactics:** {tactic_str}  \n**Platforms:** {platform_str}\n\n"
            f"**Description:**\n{desc_short}\n"
        )
        if det_short:
            answer += f"\n**Detection:**\n{det_short}\n"
        answer += (
            "\n**Mitigation approach:**\n"
            "- Apply least-privilege to limit blast radius\n"
            "- Enable detailed logging and forward to SIEM\n"
            "- Implement EDR/XDR with behavioral detection\n"
            f"- Refer to MITRE: https://attack.mitre.org/techniques/{mitre_id.replace('.','/')}/"
        )

        samples.append({
            "messages": [
                {"role": "system",    "content": PENTEST_SYSTEM},
                {"role": "user",      "content": question},
                {"role": "assistant", "content": answer},
            ]
        })
    return samples


def format_cves(cve_list: list) -> list[dict]:
    samples = []
    for cve in cve_list:
        cve_id  = cve.get("cve_id", "")
        desc    = cve.get("description", "")
        score   = cve.get("cvss_score", 0)
        sev     = cve.get("severity", "")
        vector  = cve.get("attack_vector", "")
        cwes    = cve.get("cwes", [])

        if not cve_id or not desc or len(desc) < 60:
            continue

        cwe_str = ", ".join(cwes) if cwes else "unspecified"
        question = f"Analyze {cve_id} (CVSS {score} {sev}). What is the vulnerability, what is the risk, and how should it be remediated?"
        answer = (
            f"**{cve_id}**  \n"
            f"**Severity:** {sev} (CVSS {score})  \n"
            f"**Attack Vector:** {vector}  \n"
            f"**CWE:** {cwe_str}\n\n"
            f"**Description:**\n{desc}\n\n"
            f"**Risk:** {'Critical — patch immediately.' if score >= 9.0 else 'High — patch within 7–14 days.' if score >= 7.0 else 'Medium — patch within 30 days.'}\n\n"
            f"**Remediation:**\n"
            f"1. Apply vendor patch / update to non-vulnerable version\n"
            f"2. Apply vendor mitigations if patch unavailable\n"
            f"3. Verify patch and re-scan\n"
            f"4. Monitor for exploitation in SIEM\n"
            f"5. https://nvd.nist.gov/vuln/detail/{cve_id}"
        )

        samples.append({
            "messages": [
                {"role": "system",    "content": PENTEST_SYSTEM},
                {"role": "user",      "content": question},
                {"role": "assistant", "content": answer},
            ]
        })
    return samples


def format_soc_detections(detections: list) -> list[dict]:
    """Format SOC detection samples (MITRE detection + Sigma)."""
    samples = []
    for item in detections:
        user  = item.get("user", "")
        asst  = item.get("assistant", "")
        if len(user) < 10 or len(asst) < 50:
            continue
        samples.append({
            "messages": [
                {"role": "system",    "content": SOC_SYSTEM},
                {"role": "user",      "content": user},
                {"role": "assistant", "content": asst},
            ]
        })
    return samples


def validate_sample(sample: dict) -> bool:
    msgs = sample.get("messages", [])
    if len(msgs) != 3:
        return False
    if [m["role"] for m in msgs] != ["system", "user", "assistant"]:
        return False
    return len(msgs[1]["content"]) >= 10 and len(msgs[2]["content"]) >= 50


def format_all():
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    all_samples = []

    # ── Pentest KB ─────────────────────────────────────────────────────────
    pentest_kb = DATA_DIR / "raw_pentest_kb.json"
    if pentest_kb.exists():
        with open(pentest_kb) as f:
            data = json.load(f)
        s = format_kb_pairs(data, override_system=PENTEST_SYSTEM)
        print(f"[formatter] Pentest KB:          {len(s):>5} samples")
        all_samples.extend(s)
    else:
        print("[formatter] WARNING: raw_pentest_kb.json not found")

    # ── SOC KB ─────────────────────────────────────────────────────────────
    soc_kb = DATA_DIR / "raw_soc_kb.json"
    if soc_kb.exists():
        with open(soc_kb) as f:
            data = json.load(f)
        s = format_kb_pairs(data, override_system=SOC_SYSTEM)
        print(f"[formatter] SOC KB:              {len(s):>5} samples")
        all_samples.extend(s)
    else:
        print("[formatter] WARNING: raw_soc_kb.json not found")

    # ── MITRE ATT&CK (pentest perspective) ──────────────────────────────────
    mitre_f = DATA_DIR / "raw_mitre.json"
    if mitre_f.exists():
        with open(mitre_f) as f:
            data = json.load(f)
        s = format_mitre_techniques(data)
        print(f"[formatter] MITRE ATT&CK:        {len(s):>5} samples")
        all_samples.extend(s)
    else:
        print("[formatter] WARNING: raw_mitre.json not found")

    # ── SOC Detections (MITRE detection + Sigma) ────────────────────────────
    soc_det = DATA_DIR / "raw_soc_detections.json"
    if soc_det.exists():
        with open(soc_det) as f:
            data = json.load(f)
        s = format_soc_detections(data)
        print(f"[formatter] SOC Detections:      {len(s):>5} samples")
        all_samples.extend(s)
    else:
        print("[formatter] WARNING: raw_soc_detections.json not found")

    # ── NVD CVEs ────────────────────────────────────────────────────────────
    cve_f = DATA_DIR / "raw_cve.json"
    if cve_f.exists():
        with open(cve_f) as f:
            data = json.load(f)
        s = format_cves(data)
        print(f"[formatter] NVD CVEs:            {len(s):>5} samples")
        all_samples.extend(s)
    else:
        print("[formatter] WARNING: raw_cve.json not found")

    # ── Validate + deduplicate ───────────────────────────────────────────────
    valid = [s for s in all_samples if validate_sample(s)]
    seen, deduped = set(), []
    for s in valid:
        key = s["messages"][1]["content"][:100]
        if key not in seen:
            seen.add(key)
            deduped.append(s)

    pentest_count = sum(1 for s in deduped if "penetration tester" in s["messages"][0]["content"])
    soc_count     = sum(1 for s in deduped if "SOC analyst" in s["messages"][0]["content"])

    print(f"\n[formatter] ─────────────────────────────────────")
    print(f"[formatter] Pentest samples:        {pentest_count:>5}")
    print(f"[formatter] SOC samples:            {soc_count:>5}")
    print(f"[formatter] Total (deduped):        {len(deduped):>5}")
    print(f"[formatter] Filtered/deduped:       {len(all_samples) - len(deduped):>5}")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for s in deduped:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")

    size_kb = OUTPUT_FILE.stat().st_size / 1024
    print(f"\n[formatter] ✅ Dataset → {OUTPUT_FILE}")
    print(f"[formatter] Size: {size_kb:.1f} KB")
    return deduped


if __name__ == "__main__":
    format_all()
