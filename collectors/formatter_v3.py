"""
Dataset Formatter v3 — Converts all raw sources into Mistral chat JSONL
Handles: NVD CVEs, CISA KEV, GHSA, Atomic Red Team, MITRE ATT&CK, pentest/SOC KB

Outputs: data/hancock_v3.jsonl
"""
import json
import random
from pathlib import Path

DATA_DIR    = Path(__file__).parent.parent / "data"
OUTPUT_FILE = DATA_DIR / "hancock_v3.jsonl"

SYSTEM_PENTEST = "You are Hancock, an elite penetration tester and offensive security specialist built by CyberViser. You are methodical, precise, and always operate within authorized scope."
SYSTEM_SOC     = "You are Hancock, an expert SOC Tier-2/3 analyst and incident responder built by CyberViser. You follow PICERL for IR and MITRE ATT&CK for threat mapping."
SYSTEM_AUTO    = "You are Hancock, an elite cybersecurity specialist built by CyberViser. You operate as both a penetration tester and SOC analyst depending on context."


def load_json(path: Path) -> list | dict:
    if not path.exists():
        return []
    with open(path) as f:
        return json.load(f)


def load_jsonl(path: Path) -> list:
    if not path.exists():
        return []
    with open(path) as f:
        return [json.loads(l) for l in f if l.strip()]


# ── CVE formatters ────────────────────────────────────────────────────────────
def format_nvd_cves(cves: list) -> list:
    samples = []
    for cve in cves:
        cid   = cve.get("cve_id", "")
        desc  = cve.get("description", "")
        score = cve.get("cvss_score", 0)
        vec   = cve.get("attack_vector", "")
        cwes  = ", ".join(cve.get("cwes", [])) or "N/A"
        if not cid or not desc or len(desc) < 60:
            continue

        samples.append({"messages": [
            {"role": "system", "content": SYSTEM_AUTO},
            {"role": "user",   "content": f"Explain {cid} and provide detection and remediation guidance."},
            {"role": "assistant", "content":
                f"**{cid}** — CVSS {score} ({vec})\n\n"
                f"**Description:** {desc}\n\n"
                f"**Weakness:** {cwes}\n\n"
                f"**Detection:** Monitor for exploitation indicators: unusual process execution, "
                f"network connections to unexpected destinations, or error patterns in logs related "
                f"to the affected component. Check vendor advisories for specific IOCs.\n\n"
                f"**Remediation:** Apply vendor patches immediately. If unpatched, implement "
                f"compensating controls: WAF rules, network segmentation, or disabling the "
                f"vulnerable feature. Prioritize based on CVSS {score} — {'Critical' if score >= 9 else 'High'} severity."
            }
        ]})

        # Second variant: triage question
        samples.append({"messages": [
            {"role": "system", "content": SYSTEM_SOC},
            {"role": "user",   "content": f"We received an alert possibly related to {cid} exploitation. How do I triage this?"},
            {"role": "assistant", "content":
                f"**Triage for {cid} (CVSS {score})**\n\n"
                f"1. **Identify affected systems** — check which assets run the vulnerable component ({cve.get('description', '')[:100]}...)\n"
                f"2. **Check patch status** — verify if the fix has been applied\n"
                f"3. **Review logs** — look for exploitation patterns: {desc[:200]}\n"
                f"4. **Assess impact** — attack vector is {vec}; {'network-accessible — HIGH PRIORITY' if vec == 'NETWORK' else 'requires local access'}\n"
                f"5. **MITRE mapping** — map to ATT&CK based on CWE: {cwes}\n"
                f"6. **Contain if confirmed** — isolate affected host, block external connections, escalate to IR team"
            }
        ]})
    return samples


def format_kev_entries(kevs: list) -> list:
    samples = []
    for k in kevs:
        cid     = k.get("cve_id", "")
        name    = k.get("name", "")
        desc    = k.get("description", "") or k.get("nvd_description", "")
        vendor  = k.get("vendor", "")
        product = k.get("product", "")
        action  = k.get("action_required", "")
        ransomware = k.get("known_ransomware", "Unknown")
        score   = k.get("cvss_score", 0)
        if not cid or not desc:
            continue

        ransomware_note = " **⚠️ Known ransomware campaigns use this vulnerability.**" if ransomware == "Known" else ""
        samples.append({"messages": [
            {"role": "system", "content": SYSTEM_AUTO},
            {"role": "user",   "content": f"Tell me about {cid} — is it actively exploited?"},
            {"role": "assistant", "content":
                f"**{cid} — {name}** is on the **CISA Known Exploited Vulnerabilities (KEV) catalog** — "
                f"meaning it is actively exploited in the wild.{ransomware_note}\n\n"
                f"**Product:** {vendor} {product}\n"
                f"**CVSS Score:** {score}\n"
                f"**Description:** {desc}\n\n"
                f"**Required Action (CISA):** {action}\n\n"
                f"**Priority:** IMMEDIATE. KEV vulnerabilities must be patched within CISA's mandated timeframe. "
                f"If patching is not possible, isolate affected systems and implement monitoring for exploitation attempts."
            }
        ]})
    return samples


def format_ghsa_advisories(advisories: list) -> list:
    samples = []
    for a in advisories:
        summary  = a.get("summary", "")
        desc     = a.get("description", "")
        eco      = a.get("ecosystem", "")
        pkgs     = ", ".join(a.get("packages", []))
        severity = a.get("severity", "")
        score    = a.get("cvss_score", 0)
        ghsa_id  = a.get("ghsa_id", "")
        cve_id   = a.get("cve_id", "") or ghsa_id
        if not summary or not desc or len(desc) < 50:
            continue

        samples.append({"messages": [
            {"role": "system", "content": SYSTEM_AUTO},
            {"role": "user",   "content": f"Explain the {cve_id} vulnerability in {pkgs or eco} and how to fix it."},
            {"role": "assistant", "content":
                f"**{cve_id} — {summary}**\n\n"
                f"**Severity:** {severity.title()} (CVSS {score})\n"
                f"**Affected:** {pkgs or eco}\n\n"
                f"**Details:** {desc[:600]}\n\n"
                f"**Remediation:** Update to the patched version of {pkgs.split('(')[0].strip() if pkgs else 'the affected package'}. "
                f"Check {ghsa_id} at https://github.com/advisories/{ghsa_id} for exact patched versions. "
                f"Run `npm audit fix` / `pip install --upgrade` / dependency manager equivalent to auto-update."
            }
        ]})
    return samples


def format_atomic_tests(tests: list) -> list:
    samples = []
    for t in tests:
        tid      = t.get("technique_id", "")
        tname    = t.get("technique_name", "")
        test_name = t.get("test_name", "")
        desc     = t.get("description", "")
        commands = t.get("commands", "")
        platforms = t.get("platforms", "")
        if not tid or not desc:
            continue

        # Pentest: "how would an attacker do X"
        samples.append({"messages": [
            {"role": "system", "content": SYSTEM_PENTEST},
            {"role": "user",   "content": f"Explain MITRE ATT&CK {tid} ({tname}) — {test_name}. How is this technique executed in an authorized pentest?"},
            {"role": "assistant", "content":
                f"**{tid} — {tname}: {test_name}**\n\n"
                f"**Description:** {desc}\n\n"
                f"**Platforms:** {platforms}\n\n"
                f"**Execution (authorized scope only):**\n```\n{commands}\n```\n\n"
                f"**Pentest notes:** Document authorization before execution. Capture screenshots and "
                f"outputs for the report. Clean up artifacts after testing using the defined cleanup commands. "
                f"Reference PTES methodology for reporting format."
            }
        ]})

        # SOC: "how do I detect X"
        samples.append({"messages": [
            {"role": "system", "content": SYSTEM_SOC},
            {"role": "user",   "content": f"How do I detect {tid} ({tname}) in my environment?"},
            {"role": "assistant", "content":
                f"**Detecting {tid} — {tname}**\n\n"
                f"**What it does:** {desc[:300]}\n\n"
                f"**Detection approach:**\n"
                f"- Monitor process creation events for unusual parent-child relationships\n"
                f"- Alert on commands matching: `{commands[:150].strip()}`\n"
                f"- Enable Sysmon Event ID 1 (Process Create) and 3 (Network Connect)\n\n"
                f"**Splunk detection:**\n```\n"
                f"index=windows EventCode=4688 \n"
                f"| search CommandLine=* \n"
                f"| eval mitre_technique=\"{tid}\"\n```\n\n"
                f"**MITRE ATT&CK:** https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
            }
        ]})
    return samples


def format_existing_v2(samples: list) -> list:
    """Pass through existing v2 samples unchanged."""
    return [s for s in samples if s.get("messages")]


def format_kb_samples(samples: list) -> list:
    """Pass through pre-formatted KB samples (already have messages structure)."""
    return [s for s in samples if s.get("messages")]


# ── Main formatter ────────────────────────────────────────────────────────────
def format_all():
    print("[fmt-v3] Loading raw data sources...")
    nvd_cves     = load_json(DATA_DIR / "raw_cve.json")
    kev_entries  = load_json(DATA_DIR / "raw_kev.json")
    ghsa_advs    = load_json(DATA_DIR / "raw_ghsa.json")
    atomic_tests = load_json(DATA_DIR / "raw_atomic.json")
    v2_samples   = load_jsonl(DATA_DIR / "hancock_v2.jsonl")

    # New mode knowledge bases — generate fresh on each run
    from collectors.ciso_kb  import generate as gen_ciso
    from collectors.sigma_kb import generate as gen_sigma
    from collectors.yara_kb  import generate as gen_yara
    from collectors.ioc_kb   import generate as gen_ioc
    from collectors.code_kb  import generate as gen_code

    ciso_samples  = gen_ciso()
    sigma_samples = gen_sigma()
    yara_samples  = gen_yara()
    ioc_samples   = gen_ioc()
    code_samples  = gen_code()

    print(f"[fmt-v3]  NVD CVEs:       {len(nvd_cves)}")
    print(f"[fmt-v3]  CISA KEV:       {len(kev_entries)}")
    print(f"[fmt-v3]  GHSA:           {len(ghsa_advs)}")
    print(f"[fmt-v3]  Atomic Tests:   {len(atomic_tests)}")
    print(f"[fmt-v3]  v2 samples:     {len(v2_samples)}")
    print(f"[fmt-v3]  CISO KB:        {len(ciso_samples)}")
    print(f"[fmt-v3]  Sigma KB:       {len(sigma_samples)}")
    print(f"[fmt-v3]  YARA KB:        {len(yara_samples)}")
    print(f"[fmt-v3]  IOC KB:         {len(ioc_samples)}")
    print(f"[fmt-v3]  Code KB:        {len(code_samples)}")

    all_samples = []
    all_samples.extend(format_existing_v2(v2_samples))
    all_samples.extend(format_nvd_cves(nvd_cves))
    all_samples.extend(format_kev_entries(kev_entries))
    all_samples.extend(format_ghsa_advisories(ghsa_advs))
    all_samples.extend(format_atomic_tests(atomic_tests))
    all_samples.extend(format_kb_samples(ciso_samples))
    all_samples.extend(format_kb_samples(sigma_samples))
    all_samples.extend(format_kb_samples(yara_samples))
    all_samples.extend(format_kb_samples(ioc_samples))
    all_samples.extend(format_kb_samples(code_samples))

    # Deduplicate
    seen, unique = set(), []
    for s in all_samples:
        msgs = s.get("messages", [])
        key  = msgs[1]["content"][:100] if len(msgs) > 1 else str(msgs)
        if key not in seen:
            seen.add(key)
            unique.append(s)

    # Shuffle for training
    random.seed(42)
    random.shuffle(unique)

    with open(OUTPUT_FILE, "w") as f:
        for s in unique:
            f.write(json.dumps(s) + "\n")

    size_kb = OUTPUT_FILE.stat().st_size / 1024
    print(f"\n[fmt-v3] ✅ {len(unique):,} samples → {OUTPUT_FILE} ({size_kb:.0f} KB)")
    return unique


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    format_all()
