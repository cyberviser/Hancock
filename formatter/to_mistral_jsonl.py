"""
JSONL Formatter
Converts all raw data sources into Mistral instruct format JSONL for fine-tuning.
Output: data/hancock_pentest_v1.jsonl
"""
import json
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "data"
OUTPUT_FILE = DATA_DIR / "hancock_pentest_v1.jsonl"

HANCOCK_SYSTEM = (
    "You are Hancock, an expert penetration tester and security researcher built by CyberViser. "
    "You operate strictly within authorized scope and legal boundaries on systems you have explicit "
    "written permission to test. You help security professionals understand attack techniques, "
    "identify vulnerabilities, and perform authorized penetration tests. You always recommend "
    "responsible disclosure and remediation."
)


def format_kb_pairs(kb_data: dict) -> list[dict]:
    """Convert static Q&A pairs to Mistral instruct format."""
    samples = []
    system = kb_data.get("system_prompt", HANCOCK_SYSTEM)
    for pair in kb_data.get("pairs", []):
        sample = {
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": pair["user"]},
                {"role": "assistant", "content": pair["assistant"]},
            ]
        }
        samples.append(sample)
    return samples


def format_mitre_techniques(mitre_data: dict) -> list[dict]:
    """Convert ATT&CK techniques into explain + detect + mitigate Q&A."""
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

        # Truncate very long descriptions
        desc_short = desc[:1200] if len(desc) > 1200 else desc
        det_short = detection[:600] if detection and len(detection) > 600 else detection

        tactic_str = ", ".join(t.replace("-", " ").title() for t in tactics)
        platform_str = ", ".join(platforms) if platforms else "Multiple"

        question = f"Explain the MITRE ATT&CK technique {name} ({mitre_id}) and how defenders can detect and mitigate it."
        answer_parts = [
            f"**{name} ({mitre_id})**\n",
            f"**Tactics:** {tactic_str}  \n**Platforms:** {platform_str}\n\n",
            f"**Description:**\n{desc_short}\n",
        ]
        if det_short:
            answer_parts.append(f"\n**Detection:**\n{det_short}\n")
        answer_parts.append(
            "\n**Mitigation approach:**\n"
            "- Apply least-privilege principles to limit blast radius\n"
            "- Enable detailed logging and forward to SIEM\n"
            "- Implement EDR/XDR with behavioral detection\n"
            "- Refer to MITRE ATT&CK mitigations: https://attack.mitre.org/techniques/"
            + mitre_id.replace(".", "/") + "/"
        )

        sample = {
            "messages": [
                {"role": "system", "content": HANCOCK_SYSTEM},
                {"role": "user", "content": question},
                {"role": "assistant", "content": "".join(answer_parts)},
            ]
        }
        samples.append(sample)

    return samples


def format_cves(cve_list: list) -> list[dict]:
    """Convert CVE data into vulnerability analysis Q&A."""
    samples = []
    for cve in cve_list:
        cve_id = cve.get("cve_id", "")
        desc = cve.get("description", "")
        score = cve.get("cvss_score", 0)
        severity = cve.get("severity", "")
        vector = cve.get("attack_vector", "")
        cwes = cve.get("cwes", [])

        if not cve_id or not desc or len(desc) < 60:
            continue

        cwe_str = ", ".join(cwes) if cwes else "unspecified"
        question = f"Analyze {cve_id} (CVSS {score} {severity}). What is the vulnerability, what is the risk, and how should it be remediated?"

        answer = (
            f"**{cve_id}**  \n"
            f"**Severity:** {severity} (CVSS {score})  \n"
            f"**Attack Vector:** {vector}  \n"
            f"**CWE:** {cwe_str}\n\n"
            f"**Vulnerability Description:**\n{desc}\n\n"
            f"**Risk Assessment:**\n"
        )

        if score >= 9.0:
            answer += (
                "This is a **Critical** severity vulnerability. "
                f"With a CVSS score of {score} and {vector} attack vector, "
                "exploitation may be possible remotely without authentication. "
                "Immediate patching is required.\n\n"
            )
        elif score >= 7.0:
            answer += (
                f"This is a **High** severity vulnerability (CVSS {score}). "
                "Prioritize patching within your standard SLA for high-severity issues (typically 7–14 days).\n\n"
            )
        else:
            answer += (
                f"This is a **Medium** severity vulnerability (CVSS {score}). "
                "Schedule patching within your normal patch cycle.\n\n"
            )

        answer += (
            "**Remediation Steps:**\n"
            "1. Check vendor security advisories for the affected software\n"
            "2. Apply the official patch or update to a non-vulnerable version\n"
            "3. If patching is not immediately possible, apply vendor-recommended workarounds\n"
            "4. Verify patch application and re-scan to confirm resolution\n"
            "5. Monitor for exploitation attempts in logs/SIEM\n\n"
            f"**References:** Search NVD for full details: https://nvd.nist.gov/vuln/detail/{cve_id}"
        )

        sample = {
            "messages": [
                {"role": "system", "content": HANCOCK_SYSTEM},
                {"role": "user", "content": question},
                {"role": "assistant", "content": answer},
            ]
        }
        samples.append(sample)

    return samples


def validate_sample(sample: dict) -> bool:
    """Basic quality filter."""
    msgs = sample.get("messages", [])
    if len(msgs) != 3:
        return False
    roles = [m["role"] for m in msgs]
    if roles != ["system", "user", "assistant"]:
        return False
    user_content = msgs[1].get("content", "")
    asst_content = msgs[2].get("content", "")
    if len(user_content) < 10 or len(asst_content) < 50:
        return False
    return True


def format_all():
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    all_samples = []

    # Load KB
    kb_file = DATA_DIR / "raw_pentest_kb.json"
    if kb_file.exists():
        with open(kb_file) as f:
            kb_data = json.load(f)
        kb_samples = format_kb_pairs(kb_data)
        print(f"[formatter] KB: {len(kb_samples)} samples")
        all_samples.extend(kb_samples)
    else:
        print("[formatter] WARNING: raw_pentest_kb.json not found — run collectors/pentest_kb.py first")

    # Load MITRE ATT&CK
    mitre_file = DATA_DIR / "raw_mitre.json"
    if mitre_file.exists():
        with open(mitre_file) as f:
            mitre_data = json.load(f)
        mitre_samples = format_mitre_techniques(mitre_data)
        print(f"[formatter] MITRE ATT&CK: {len(mitre_samples)} samples")
        all_samples.extend(mitre_samples)
    else:
        print("[formatter] WARNING: raw_mitre.json not found — run collectors/mitre_collector.py first")

    # Load CVEs
    cve_file = DATA_DIR / "raw_cve.json"
    if cve_file.exists():
        with open(cve_file) as f:
            cve_data = json.load(f)
        cve_samples = format_cves(cve_data)
        print(f"[formatter] CVEs: {len(cve_samples)} samples")
        all_samples.extend(cve_samples)
    else:
        print("[formatter] WARNING: raw_cve.json not found — run collectors/nvd_collector.py first")

    # Validate and deduplicate
    valid_samples = [s for s in all_samples if validate_sample(s)]
    # Deduplicate by user message
    seen = set()
    deduped = []
    for s in valid_samples:
        key = s["messages"][1]["content"][:100]
        if key not in seen:
            seen.add(key)
            deduped.append(s)

    print(f"\n[formatter] Total: {len(deduped)} valid samples ({len(all_samples) - len(deduped)} filtered/deduped)")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for sample in deduped:
            f.write(json.dumps(sample, ensure_ascii=False) + "\n")

    print(f"[formatter] ✅ Dataset saved → {OUTPUT_FILE}")
    print(f"[formatter] File size: {OUTPUT_FILE.stat().st_size / 1024:.1f} KB")
    return deduped


if __name__ == "__main__":
    format_all()
