"""
SOC Data Collectors
1. MITRE ATT&CK detection data (detection guidance from each technique)
2. Sigma rules sample set (detection-as-code examples)
Outputs: data/raw_soc_detections.json
"""
import json
import time
from pathlib import Path
import requests

OUTPUT_FILE = Path(__file__).parent.parent / "data" / "raw_soc_detections.json"
ATT_CK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

# Public Sigma rules from SigmaHQ (lightweight sample set)
SIGMA_RULES_URL = "https://api.github.com/repos/SigmaHQ/sigma/contents/rules/windows/process_creation"

HANCOCK_SYSTEM = (
    "You are Hancock, an expert SOC analyst and detection engineer built by CyberViser. "
    "You write SIEM queries, Sigma rules, and detection logic based on MITRE ATT&CK TTPs."
)


def fetch_mitre_detections() -> list[dict]:
    """Pull detection guidance from ATT&CK techniques for SOC training.
    Falls back to cached raw_mitre.json if live fetch fails or returns empty.
    """
    print("[soc-detections] Fetching MITRE ATT&CK detection data...")
    objects = []

    # First try: reuse cached raw_mitre.json (produced by Phase 1)
    cached = Path(__file__).parent.parent / "data" / "raw_mitre.json"
    if cached.exists():
        with open(cached) as f:
            data = json.load(f)
        # Flatten: may be {"techniques": [...]} or a raw STIX bundle
        if "techniques" in data:
            objects = data["techniques"]
        elif "objects" in data:
            objects = [o for o in data["objects"] if o.get("type") == "attack-pattern"]

    # Second try: live GitHub CTI
    if not objects:
        try:
            resp = requests.get(ATT_CK_URL, timeout=90)
            resp.raise_for_status()
            bundle = resp.json()
            objects = [o for o in bundle.get("objects", []) if o.get("type") == "attack-pattern"]
        except Exception as e:
            print(f"[soc-detections] Live fetch failed: {e}")

    samples = []
    for obj in objects:
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        name = obj.get("name", "")
        # Support both raw STIX and pre-processed technique format
        detection = obj.get("x_mitre_detection", "") or obj.get("detection", "")
        mitre_id = (
            obj.get("mitre_id")
            or next(
                (r["external_id"] for r in obj.get("external_references", [])
                 if r.get("source_name") == "mitre-attack"), ""
            )
        )
        tactics_raw = obj.get("kill_chain_phases", []) if "kill_chain_phases" in obj else obj.get("tactics", [])
        # Handle both raw STIX (list of dicts) and pre-processed (list of strings)
        if tactics_raw and isinstance(tactics_raw[0], dict):
            tactics = [p["phase_name"] for p in tactics_raw]
        else:
            tactics = tactics_raw

        if not detection or len(detection) < 80:
            continue

        tactic_str = ", ".join(t.replace("-", " ").title() for t in tactics) if tactics else "Multiple"

        question = (
            f"As a SOC analyst, how do I detect {name} ({mitre_id}) in my environment? "
            f"What logs should I collect and what SIEM queries should I write?"
        )
        answer = (
            f"**Detecting {name} ({mitre_id})**  \n"
            f"**Tactics:** {tactic_str}\n\n"
            f"**Detection Guidance (MITRE ATT&CK):**\n{detection[:1200]}\n\n"
            f"**Key log sources to enable:**\n"
            f"- Windows: Enable Event ID 4688 (process creation) with command line logging\n"
            f"- Windows: Enable PowerShell Script Block Logging (Event 4104)\n"
            f"- Network: Full packet capture or NetFlow for network-based techniques\n"
            f"- EDR telemetry: Process trees, file events, network connections\n\n"
            f"**SIEM detection approach:**\n"
            f"1. Build a baseline of normal behavior for this technique in your environment\n"
            f"2. Write a Sigma rule targeting the key indicators\n"
            f"3. Test against historical logs to measure false positive rate\n"
            f"4. Deploy at appropriate severity level (start medium, tune to high)\n"
            f"5. Reference: https://attack.mitre.org/techniques/{mitre_id.replace('.', '/')}/"
        )

        samples.append({
            "category": "soc_detection",
            "mitre_id": mitre_id,
            "user": question,
            "assistant": answer,
        })

    print(f"[soc-detections] {len(samples)} techniques with detection guidance")
    return samples


def fetch_sigma_examples() -> list[dict]:
    """Fetch a sample of Sigma rules from GitHub to teach detection-as-code."""
    print("[soc-detections] Fetching Sigma rule examples from SigmaHQ...")
    samples = []

    # Curated Sigma rule examples (hardcoded to avoid rate limits)
    sigma_examples = [
        {
            "name": "Suspicious PowerShell Encoded Command",
            "rule": """title: Suspicious PowerShell Encoded Command
id: b9f5e123-4a67-4b89-9c01-234def567890
status: stable
description: Detects PowerShell execution with -EncodedCommand flag, commonly used to obfuscate malicious scripts
references:
    - https://attack.mitre.org/techniques/T1059/001/
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains:
            - '-EncodedCommand'
            - '-enc '
            - '-ec '
    condition: selection
falsepositives:
    - Legitimate admin scripts using encoded commands (add specific hashes to filter)
level: medium
tags:
    - attack.execution
    - attack.t1059.001""",
            "question": "Write a Sigma rule to detect suspicious PowerShell encoded command usage.",
        },
        {
            "name": "Mimikatz LSASS Access",
            "rule": """title: Mimikatz LSASS Memory Access
id: a7b3c456-d890-1e23-f456-789abc012def
status: stable
description: Detects process access to LSASS which is characteristic of credential dumping tools like Mimikatz
references:
    - https://attack.mitre.org/techniques/T1003/001/
logsource:
    product: windows
    category: process_access
detection:
    selection:
        TargetImage|endswith: '\\lsass.exe'
        GrantedAccess|contains:
            - '0x1010'
            - '0x1410'
            - '0x147a'
            - '0x143a'
    filter_system:
        SourceImage|contains:
            - '\\Windows\\System32\\'
            - '\\Windows\\SysWOW64\\'
    condition: selection and not filter_system
falsepositives:
    - AV/EDR products (add to filter by path)
    - Windows Defender
level: critical
tags:
    - attack.credential_access
    - attack.t1003.001""",
            "question": "Write a Sigma rule to detect Mimikatz-style LSASS credential dumping.",
        },
        {
            "name": "Scheduled Task Creation via schtasks.exe",
            "rule": """title: Scheduled Task Creation via Schtasks Command Line
id: 9e1f2345-6789-0abc-def1-234567890abc
status: stable
description: Detects scheduled task creation via schtasks.exe which may indicate persistence
references:
    - https://attack.mitre.org/techniques/T1053/005/
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\schtasks.exe'
        CommandLine|contains: '/create'
    filter_system_tasks:
        CommandLine|contains:
            - 'Microsoft\\Windows\\'
            - 'MicrosoftEdgeUpdate'
    condition: selection and not filter_system_tasks
falsepositives:
    - Legitimate software installers
    - System administration scripts
level: medium
tags:
    - attack.persistence
    - attack.t1053.005""",
            "question": "Write a Sigma rule to detect scheduled task creation for persistence detection.",
        },
        {
            "name": "WMI Lateral Movement",
            "rule": """title: WMI Remote Command Execution
id: 5e6f7890-1234-5abc-def0-1234567890ab
status: stable
description: Detects WMI usage for remote command execution (lateral movement)
references:
    - https://attack.mitre.org/techniques/T1047/
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\wmic.exe'
        CommandLine|contains:
            - 'process call create'
            - '/node:'
    condition: selection
falsepositives:
    - System administration scripts
    - Software deployment tools (SCCM, etc.)
level: high
tags:
    - attack.lateral_movement
    - attack.execution
    - attack.t1047""",
            "question": "Write a Sigma rule to detect WMI being used for lateral movement and remote execution.",
        },
        {
            "name": "Pass-the-Hash with net use",
            "rule": """title: Pass-The-Hash via Net Use
id: 2b3c4d5e-6f7a-8b9c-0d1e-2f3a4b5c6d7e
status: stable
description: Detects net use commands that may indicate pass-the-hash lateral movement
references:
    - https://attack.mitre.org/techniques/T1550/002/
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\net.exe'
        CommandLine|contains:
            - 'use \\\\'
    filter_legitimate:
        CommandLine|contains: 'delete'
    condition: selection and not filter_legitimate
falsepositives:
    - Legitimate mapped drives in scripts (add subnet filter)
level: medium
tags:
    - attack.lateral_movement
    - attack.t1550.002""",
            "question": "Write a Sigma detection rule for pass-the-hash lateral movement using net use.",
        },
        {
            "name": "Suspicious Base64 Encoded PowerShell",
            "rule": """title: PowerShell Base64 Download Cradle
id: 3c4d5e6f-7890-1abc-2def-3456789abcde
status: stable
description: Detects PowerShell download cradles using Base64 IEX/Invoke-Expression patterns
references:
    - https://attack.mitre.org/techniques/T1059/001/
    - https://attack.mitre.org/techniques/T1105/
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains:
            - 'IEX'
            - 'Invoke-Expression'
            - 'DownloadString'
            - 'WebClient'
    condition: selection
falsepositives:
    - Legitimate remote management (document baselines)
    - Some AV products during scans
level: high
tags:
    - attack.execution
    - attack.command_and_control
    - attack.t1059.001""",
            "question": "Write a Sigma rule to detect PowerShell download cradles (IEX/WebClient patterns).",
        },
        {
            "name": "LSASS Memory Dump via ProcDump",
            "rule": """title: LSASS Memory Dump via Sysinternals ProcDump
id: 4d5e6f7a-8901-bcde-f012-3456789abcde
status: stable
description: Detects the use of Sysinternals ProcDump to dump LSASS memory for credential extraction
references:
    - https://attack.mitre.org/techniques/T1003/001/
logsource:
    product: windows
    category: process_creation
detection:
    selection_name:
        Image|endswith: '\\procdump.exe'
    selection_target:
        CommandLine|contains: 'lsass'
    condition: selection_name or selection_target
falsepositives:
    - Authorized forensic investigations
    - Crash dump collection by IT (use specific account filters)
level: critical
tags:
    - attack.credential_access
    - attack.t1003.001""",
            "question": "Write a Sigma rule to detect LSASS credential dumping via ProcDump.",
        },
        {
            "name": "Ransomware File Extension Change",
            "rule": """title: Ransomware Bulk File Rename Detection
id: 5e6f7a8b-9012-cdef-0123-456789abcdef
status: experimental
description: Detects bulk file rename events characteristic of ransomware encryption
references:
    - https://attack.mitre.org/techniques/T1486/
logsource:
    product: windows
    category: file_rename
detection:
    selection:
        TargetFilename|re: '.*[.](locked|encrypted|crypt|enc|ransom|pays|kraken)$'
    condition: selection | count() > 20
timeframe: 1m
falsepositives:
    - Legitimate bulk file operations (verify by user + process context)
level: critical
tags:
    - attack.impact
    - attack.t1486""",
            "question": "Write a Sigma rule to detect ransomware bulk file encryption/renaming activity.",
        },
        {
            "name": "Certutil Download",
            "rule": """title: Certutil Download From URL
id: 1b2c3d4e-5f6a-7b8c-9d0e-1f2a3b4c5d6e
status: stable
description: Detects certutil.exe being used to download files from URLs (common LOLBin abuse)
references:
    - https://attack.mitre.org/techniques/T1105/
    - https://lolbas-project.github.io/lolbas/Binaries/Certutil/
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\\certutil.exe'
        CommandLine|contains|any:
            - '-urlcache'
            - '-UrlCache'
            - '-decode'
            - '-encode'
    condition: selection
falsepositives:
    - Certificate management operations (add context filter on parent process)
level: high
tags:
    - attack.command_and_control
    - attack.t1105
    - attack.defense_evasion""",
            "question": "Write a Sigma rule to detect certutil.exe being used to download files from the internet.",
        },
    ]

    for ex in sigma_examples:
        answer = (
            f"Here is a Sigma detection rule for **{ex['name']}**:\n\n"
            f"```yaml\n{ex['rule']}\n```\n\n"
            f"**How to deploy this rule:**\n\n"
            f"**Splunk:**\n"
            f"```bash\nsigma convert -t splunk sigma_rule.yml\n```\n\n"
            f"**Elastic/KQL:**\n"
            f"```bash\nsigma convert -t es-qs sigma_rule.yml\n```\n\n"
            f"**Microsoft Sentinel:**\n"
            f"```bash\nsigma convert -t sentinel sigma_rule.yml\n```\n\n"
            f"**Tuning tips:**\n"
            f"- Run against 30 days of historical data to measure false positive rate\n"
            f"- Add environment-specific filters to the `filter_*` condition\n"
            f"- Start at `level: medium`, raise to `high` after tuning\n"
            f"- Track FP/TP ratio monthly and adjust"
        )
        samples.append({
            "category": "sigma_rules",
            "user": ex["question"],
            "assistant": answer,
        })

    print(f"[soc-detections] {len(samples)} Sigma rule examples")
    return samples


def collect():
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    all_samples = []
    all_samples.extend(fetch_mitre_detections())
    all_samples.extend(fetch_sigma_examples())

    with open(OUTPUT_FILE, "w") as f:
        json.dump(all_samples, f, indent=2)

    print(f"[soc-detections] Saved {len(all_samples)} samples → {OUTPUT_FILE}")
    return all_samples


if __name__ == "__main__":
    collect()
