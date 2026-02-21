"""
SOC Analyst Knowledge Base
Hand-crafted Q&A pairs covering all SOC analyst duties.
Covers: alert triage, SIEM queries, log analysis, incident response,
        threat hunting, IOC analysis, malware triage, detection engineering.
Outputs: data/raw_soc_kb.json
"""
import json
from pathlib import Path

OUTPUT_FILE = Path(__file__).parent.parent / "data" / "raw_soc_kb.json"

HANCOCK_SYSTEM = (
    "You are Hancock, an expert SOC (Security Operations Center) analyst and incident responder "
    "built by CyberViser. You triage alerts, analyze logs, hunt threats, and lead incident response. "
    "You write precise SIEM queries (Splunk SPL, Elastic KQL, Microsoft Sentinel KQL), "
    "analyze IOCs, and follow NIST IR and PICERL frameworks. "
    "You are calm under pressure, methodical, and always document your findings."
)

KB = [
    # ─── ALERT TRIAGE ────────────────────────────────────────────────────────
    {
        "category": "alert_triage",
        "user": "Walk me through how to triage a high-severity IDS alert for suspicious PowerShell execution.",
        "assistant": (
            "**Step 1 — Understand the alert context**\n"
            "- What rule triggered? (e.g., 'PowerShell Encoded Command', 'AMSI Bypass')\n"
            "- Which host? What user account? What time?\n"
            "- Is this host a server, workstation, or domain controller?\n\n"
            "**Step 2 — Pull correlated logs (SIEM)**\n"
            "```spl\n# Splunk — last 1hr on that host\nindex=wineventlog host=\"VICTIM-PC\" source=\"WinEventLog:Microsoft-Windows-PowerShell/Operational\"\n| table _time, EventCode, CommandLine, User\n| sort -_time\n```\n"
            "Key Event IDs: 4103 (module logging), 4104 (script block logging — most valuable), 4105/4106\n\n"
            "**Step 3 — Decode the command**\n"
            "```bash\n# If base64 encoded:\necho 'JABjACAAPQAgAC4A...' | base64 -d | iconv -f UTF-16LE\n# Or use CyberChef: https://gchq.github.io/CyberChef/\n```\n\n"
            "**Step 4 — Assess indicators**\n"
            "- `IEX` / `Invoke-Expression` + download → likely dropper\n"
            "- `-EncodedCommand` → obfuscation, high suspicion\n"
            "- `DownloadString`, `WebClient`, `Invoke-WebRequest` → C2 or payload fetch\n"
            "- `Add-MpPreference -ExclusionPath` → AV exclusion (critical escalate)\n\n"
            "**Step 5 — Determine: True Positive or False Positive?**\n"
            "- Check if this is a known admin/automation script\n"
            "- Correlate with change management or IT ticket\n"
            "- If no business justification → escalate as incident\n\n"
            "**Step 6 — Document and act**\n"
            "- Log triage notes in ticketing system\n"
            "- If TP: isolate host, escalate to Tier 2/IR team\n"
            "- If FP: tune the rule to reduce noise"
        ),
    },
    {
        "category": "alert_triage",
        "user": "How do I determine if a brute force login alert is a true positive?",
        "assistant": (
            "**Key data points to collect:**\n\n"
            "1. **Source IP** — Internal (credential stuffing/lateral) or external (internet-facing)?\n"
            "2. **Target account** — Service account? Admin? Real user?\n"
            "3. **Volume + timing** — 10 fails in 1 sec = automated tool; 10 fails in 10 min = manual\n"
            "4. **Geographic anomaly** — Login attempts from unusual country?\n"
            "5. **Did any succeed?** — Event ID 4624 (success) after 4625 failures = critical\n\n"
            "**Splunk query to correlate:**\n"
            "```spl\nindex=wineventlog EventCode=4625 OR EventCode=4624\n| stats count(eval(EventCode=4625)) as failures,\n        count(eval(EventCode=4624)) as successes\n  by src_ip, user, dest\n| where failures > 10\n| sort -failures\n```\n\n"
            "**Verdict logic:**\n"
            "| Pattern | Verdict |\n"
            "|---------|--------|\n"
            "| Many fails, no success, known scanner IP | Likely FP / external noise |\n"
            "| Many fails → success on same account | True Positive — ESCALATE |\n"
            "| Fails on many accounts from one IP | Password spray — True Positive |\n"
            "| Internal source IP | Lateral movement or compromised host |\n\n"
            "**Immediate actions for TP:**\n"
            "- Lock the targeted account (coordinate with IT)\n"
            "- Block source IP at firewall/WAF\n"
            "- Check what the account did after successful login (Event ID 4648, 4672)"
        ),
    },
    {
        "category": "alert_triage",
        "user": "What is alert fatigue and how do SOC analysts manage it?",
        "assistant": (
            "**Alert fatigue** occurs when analysts are overwhelmed by high alert volumes, leading to "
            "critical alerts being missed or ignored.\n\n"
            "**Root causes:**\n"
            "- Poorly tuned detection rules generating excessive false positives\n"
            "- Duplicate alerts from multiple tools (SIEM + EDR + IDS all firing on same event)\n"
            "- Noisy rules with no business context (e.g., any PowerShell = alert)\n\n"
            "**Metrics to measure it:**\n"
            "- False Positive Rate (FPR) — target < 10% per rule\n"
            "- Mean Time to Acknowledge (MTTA) — increasing = fatigue signal\n"
            "- Alert closure rate — low rate = analysts skipping alerts\n\n"
            "**Mitigation strategies:**\n\n"
            "1. **Rule tuning** — Add allowlists for known-good behavior\n"
            "   ```spl\n   # Exclude known admin scripts\n   index=wineventlog EventCode=4104\n   | where NOT like(CommandLine, \"%backup_script%\")\n   ```\n\n"
            "2. **Alert prioritization** — Score alerts by asset criticality + threat intel match\n\n"
            "3. **Aggregation** — Group related alerts into a single incident (SOAR correlation)\n\n"
            "4. **SOAR automation** — Auto-triage low-severity alerts (lookup IP in threat intel, auto-close if clean)\n\n"
            "5. **Regular rule reviews** — Monthly: retire rules with >90% FP rate\n\n"
            "6. **Tiering** — Tier 1 handles triage, Tier 2 handles investigation, Tier 3 handles hunting"
        ),
    },
    # ─── LOG ANALYSIS ─────────────────────────────────────────────────────────
    {
        "category": "log_analysis",
        "user": "What are the most important Windows Event IDs for a SOC analyst to know?",
        "assistant": (
            "**Authentication:**\n"
            "| Event ID | Description | Priority |\n"
            "|----------|-------------|----------|\n"
            "| 4624 | Successful logon | Medium |\n"
            "| 4625 | Failed logon | High (many = brute force) |\n"
            "| 4648 | Logon using explicit credentials (runas) | High |\n"
            "| 4672 | Special privileges assigned (admin logon) | High |\n"
            "| 4720 | User account created | High |\n"
            "| 4728/4732/4756 | User added to security/local/universal group | High |\n"
            "| 4771 | Kerberos pre-auth failed | High (Kerberoasting indicator) |\n"
            "| 4776 | NTLM auth attempt | Medium |\n\n"
            "**Process & Execution:**\n"
            "| Event ID | Description | Priority |\n"
            "|----------|-------------|----------|\n"
            "| 4688 | Process created (enable command line logging!) | Critical |\n"
            "| 4689 | Process terminated | Low |\n"
            "| 4103/4104 | PowerShell module/script block logging | Critical |\n\n"
            "**Object Access & Changes:**\n"
            "| Event ID | Description | Priority |\n"
            "|----------|-------------|----------|\n"
            "| 4663 | File/object access attempted | Medium |\n"
            "| 4698 | Scheduled task created | High |\n"
            "| 4702 | Scheduled task updated | High |\n"
            "| 7045 | New service installed | High |\n\n"
            "**Network:**\n"
            "| Event ID | Description | Priority |\n"
            "|----------|-------------|----------|\n"
            "| 5156 | Windows Firewall allowed connection | Low |\n"
            "| 5158/5447 | WFP filter change | Medium |\n\n"
            "**Tip:** Enable Process Creation logging (4688) with command line — this single change dramatically improves detection coverage."
        ),
    },
    {
        "category": "log_analysis",
        "user": "How do I analyze Apache/Nginx web server logs to detect attacks?",
        "assistant": (
            "**Log location:**\n"
            "- Apache: `/var/log/apache2/access.log`, `/var/log/apache2/error.log`\n"
            "- Nginx: `/var/log/nginx/access.log`, `/var/log/nginx/error.log`\n\n"
            "**Log format (Common Log Format):**\n"
            "```\n127.0.0.1 - admin [21/Feb/2026:10:00:01 +0000] \"GET /admin/config.php HTTP/1.1\" 200 1234\n```\n"
            "`IP - user [timestamp] \"method URI protocol\" status size`\n\n"
            "**Detection patterns:**\n\n"
            "**SQLi attempts:**\n"
            "```bash\ngrep -E \"(union|select|insert|drop|--|\\'|%27|%22)\" access.log -i | head -20\n```\n\n"
            "**Directory traversal:**\n"
            "```bash\ngrep -E \"(\\.\\./|%2e%2e%2f|%252e)\" access.log -i\n```\n\n"
            "**Scanning (many 404s from one IP):**\n"
            "```bash\nawk '$9==404 {print $1}' access.log | sort | uniq -c | sort -rn | head -20\n```\n\n"
            "**Top attackers:**\n"
            "```bash\nawk '{print $1}' access.log | sort | uniq -c | sort -rn | head -20\n```\n\n"
            "**High error rate (potential exploitation):**\n"
            "```bash\nawk '$9>=500 {print $1, $7, $9}' access.log | sort | uniq -c | sort -rn | head\n```\n\n"
            "**Unusual user agents (scanners/tools):**\n"
            "```bash\nawk -F'\"' '{print $6}' access.log | sort | uniq -c | sort -rn | grep -iE '(sqlmap|nikto|nmap|masscan|zgrab|python-requests)'\n```\n\n"
            "**SIEM query (Splunk):**\n"
            "```spl\nindex=web_logs\n| rex field=uri \"(?<sqli_pattern>union|select|drop|%27)\"\n| where isnotnull(sqli_pattern)\n| stats count by src_ip, uri, sqli_pattern\n| sort -count\n```"
        ),
    },
    {
        "category": "log_analysis",
        "user": "How do I detect lateral movement using Windows Event logs?",
        "assistant": (
            "Lateral movement leaves a trail across multiple event logs. Key patterns:\n\n"
            "**1. Pass-the-Hash / Remote logins (Event 4624 Logon Type 3)**\n"
            "```spl\nindex=wineventlog EventCode=4624 Logon_Type=3\n| stats count by src_ip, user, dest, _time\n| where src_ip != dest\n| sort -count\n```\n\n"
            "**2. PsExec / Remote Service execution (Event 7045 + 4688)**\n"
            "```spl\nindex=wineventlog (EventCode=7045 OR EventCode=4688)\n| where match(ServiceFileName, \"(?i)(psexec|\\\\\\\\ADMIN\\$|cmd\\.exe|powershell)\")\n| table _time, host, user, ServiceFileName, CommandLine\n```\n\n"
            "**3. WMI remote execution (Event 4688 + wmiprvse.exe parent)**\n"
            "```spl\nindex=wineventlog EventCode=4688\n| where ParentProcessName=\"wmiprvse.exe\"\n  AND NOT match(NewProcessName, \"(?i)(wmic|wmiadap)\")\n| table _time, host, user, NewProcessName, CommandLine\n```\n\n"
            "**4. SMB lateral movement (unusual ADMIN$ / IPC$ access)**\n"
            "```spl\nindex=wineventlog EventCode=5140\n| where match(ShareName, \"(?i)(ADMIN\\$|C\\$|IPC\\$)\")\n| stats count by src_ip, dest, ShareName, user\n| where count > 5\n```\n\n"
            "**5. Kerberoasting (Event 4769 — RC4 ticket requests)**\n"
            "```spl\nindex=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17\n| stats count by src_ip, user, ServiceName\n| where count > 3\n| sort -count\n```\n\n"
            "**Hunting tip:** Baseline normal admin activity first. "
            "Lateral movement from non-admin accounts or outside business hours is the highest signal."
        ),
    },
    # ─── SIEM QUERIES ─────────────────────────────────────────────────────────
    {
        "category": "siem_queries",
        "user": "Write a Splunk SPL query to detect potential data exfiltration.",
        "assistant": (
            "Data exfiltration shows up as abnormal outbound data volumes or unusual destinations.\n\n"
            "**1. Large outbound transfers (DNS/HTTP/HTTPS):**\n"
            "```spl\nindex=network_traffic direction=outbound\n| stats sum(bytes_out) as total_bytes by src_ip, dest_ip, dest_port\n| where total_bytes > 104857600  | eval total_mb = round(total_bytes/1048576, 2)\n| lookup geoip dest_ip OUTPUT country as dest_country\n| where NOT dest_country=\"United States\"  | sort -total_mb\n| table src_ip, dest_ip, dest_country, dest_port, total_mb\n```\n\n"
            "**2. DNS tunneling (unusually long DNS queries):**\n"
            "```spl\nindex=dns_logs\n| eval query_len = len(query)\n| where query_len > 100\n| stats count, avg(query_len) as avg_len, values(query) as queries by src_ip, domain\n| where count > 20\n| sort -count\n```\n\n"
            "**3. Sensitive file access + outbound connection within 10 min:**\n"
            "```spl\nindex=wineventlog EventCode=4663\n| where match(ObjectName, \"(?i)(\\.xlsx|\\.pdf|\\.doc|secrets|confidential|password)\")\n| eval access_time = _time\n| join src_ip [\n    search index=network_traffic direction=outbound\n    | eval net_time = _time\n  ]\n| where (net_time - access_time) between 0 AND 600\n| table src_ip, user, ObjectName, dest_ip, net_time\n```\n\n"
            "**4. Compressed archive creation + immediate upload:**\n"
            "```spl\nindex=wineventlog EventCode=4688\n| where match(CommandLine, \"(?i)(7z|zip|tar|rar|compress)\")\n| eval compress_time = _time\n| join host [\n    search index=proxy_logs\n    | eval upload_time = _time\n    | where method=\"POST\" AND bytes_out > 1048576\n  ]\n| where abs(upload_time - compress_time) < 300\n```"
        ),
    },
    {
        "category": "siem_queries",
        "user": "Write a Microsoft Sentinel KQL query to detect suspicious Azure AD sign-ins.",
        "assistant": (
            "**1. Impossible travel — sign-ins from two countries within 1 hour:**\n"
            "```kql\nSigninLogs\n| where TimeGenerated > ago(24h)\n| where ResultType == 0  // successful\n| extend Country = tostring(LocationDetails.countryOrRegion)\n| summarize\n    Countries = make_set(Country),\n    IPs       = make_set(IPAddress),\n    Count     = count()\n  by UserPrincipalName, bin(TimeGenerated, 1h)\n| where array_length(Countries) > 1\n| project TimeGenerated, UserPrincipalName, Countries, IPs, Count\n| order by TimeGenerated desc\n```\n\n"
            "**2. Sign-ins from known malicious IPs (TI feed):**\n"
            "```kql\nlet ThreatIPs = ThreatIntelligenceIndicator\n    | where TimeGenerated > ago(7d)\n    | where isnotempty(NetworkIP)\n    | summarize by NetworkIP;\nSigninLogs\n| where TimeGenerated > ago(24h)\n| where IPAddress in (ThreatIPs)\n| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, ResultType\n```\n\n"
            "**3. MFA fatigue attack (many MFA push requests per user):**\n"
            "```kql\nSigninLogs\n| where TimeGenerated > ago(1h)\n| where ResultType == 50074  // MFA required\n    or ResultType == 50076\n| summarize\n    MFA_Requests = count(),\n    IPs = make_set(IPAddress)\n  by UserPrincipalName, bin(TimeGenerated, 1h)\n| where MFA_Requests > 5\n| order by MFA_Requests desc\n```\n\n"
            "**4. Legacy auth protocol usage (no MFA support):**\n"
            "```kql\nSigninLogs\n| where TimeGenerated > ago(7d)\n| where ClientAppUsed in ('Exchange ActiveSync','IMAP4','POP3','SMTP Auth','Other clients')\n| where ResultType == 0\n| summarize count() by UserPrincipalName, ClientAppUsed, IPAddress\n| order by count_ desc\n```"
        ),
    },
    {
        "category": "siem_queries",
        "user": "Write an Elastic KQL query to detect beaconing behavior (C2 communication).",
        "assistant": (
            "Beaconing is characterized by **regular, periodic outbound connections** to the same external IP.\n\n"
            "**Elastic KQL — detect consistent connection intervals:**\n"
            "```kql\nfrom logs-network*\n| where @timestamp > now() - 24h\n| where network.direction == \"outbound\"\n| stats\n    connection_count = count(),\n    avg_bytes        = avg(network.bytes),\n    stddev_time      = std_deviation(event.duration)\n  by source.ip, destination.ip, destination.port\n| where connection_count > 50\n    and stddev_time < 5000        // low variance = periodic\n    and avg_bytes < 10000          // small payload = heartbeat\n| sort connection_count desc\n```\n\n"
            "**Splunk equivalent:**\n"
            "```spl\nindex=network_traffic direction=outbound\n| bin _time span=1m\n| stats count as conn_per_min by src_ip, dest_ip, dest_port, _time\n| stats\n    avg(conn_per_min) as avg_rate,\n    stdev(conn_per_min) as variance,\n    count as time_windows\n  by src_ip, dest_ip, dest_port\n| where time_windows > 60\n    AND variance < 2\n    AND avg_rate between 1 AND 5\n| eval beacon_score = round((time_windows / (variance + 0.1)), 2)\n| sort -beacon_score\n| table src_ip, dest_ip, dest_port, avg_rate, variance, beacon_score\n```\n\n"
            "**What to investigate:**\n"
            "- Resolve destination IP — is it a known CDN or an unregistered VPS?\n"
            "- Check domain age (threat intel)\n"
            "- Look at payload size variance — real beacons have very low variance\n"
            "- Correlate with process on host — what process owns that connection?"
        ),
    },
    # ─── INCIDENT RESPONSE ────────────────────────────────────────────────────
    {
        "category": "incident_response",
        "user": "Walk me through the NIST incident response lifecycle.",
        "assistant": (
            "NIST SP 800-61 defines four phases:\n\n"
            "**Phase 1 — Preparation**\n"
            "- Build and maintain IR playbooks for common scenarios\n"
            "- Deploy detection tooling: EDR, SIEM, network monitoring\n"
            "- Establish communication trees (who to call at 2am)\n"
            "- Train team with tabletop exercises\n"
            "- Maintain asset inventory and network diagrams\n\n"
            "**Phase 2 — Detection & Analysis**\n"
            "- Identify potential incidents from alerts, user reports, threat intel\n"
            "- Triage: Is this a true incident? What type? What's the scope?\n"
            "- Assign severity: Critical / High / Medium / Low\n"
            "- Begin timeline reconstruction\n"
            "- Preserve evidence (log snapshots, memory dumps)\n\n"
            "**Phase 3 — Containment, Eradication & Recovery**\n"
            "- **Containment:** Stop the bleeding — isolate affected systems, revoke credentials\n"
            "- **Eradication:** Remove malware, close access vectors, patch vulnerabilities\n"
            "- **Recovery:** Restore systems from clean backups, verify integrity\n"
            "- Monitor closely for re-compromise during recovery\n\n"
            "**Phase 4 — Post-Incident Activity**\n"
            "- Write incident report (timeline, root cause, impact, actions taken)\n"
            "- Lessons learned meeting within 2 weeks\n"
            "- Update playbooks, detection rules, and security controls\n"
            "- Share IOCs with threat intel community (ISACs, etc.)\n\n"
            "**Key metrics:** MTTD (mean time to detect), MTTR (mean time to respond), dwell time"
        ),
    },
    {
        "category": "incident_response",
        "user": "A user reports their machine is acting strangely. Walk me through the triage steps for a potential malware infection.",
        "assistant": (
            "**Immediate triage (first 5 minutes):**\n\n"
            "**1. Contain first if critical:**\n"
            "- If ransomware indicators: isolate the host immediately (disconnect network, keep powered on)\n"
            "- Otherwise: observe while collecting evidence\n\n"
            "**2. Live system analysis (on the endpoint — EDR or remote shell):**\n"
            "```powershell\n# Running processes — look for unsigned, unusual names, odd paths\nGet-Process | Select Name, Id, Path, Company | Sort Company\n\n# Network connections — look for unknown external IPs\nnetstat -ano | findstr ESTABLISHED\n\n# Startup persistence\nGet-CimInstance Win32_StartupCommand | Select Name, Command, Location\nreg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\nreg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n\n# Scheduled tasks\nschtasks /query /fo CSV /v | ConvertFrom-Csv | where {$_.TaskName -notlike '\\Microsoft*'}\n\n# New services\nGet-Service | where {$_.StartType -eq 'Automatic'} | Sort DisplayName\n```\n\n"
            "**3. Check parent-child process anomalies (EDR)**\n"
            "- `word.exe → cmd.exe` = macro execution (Emotet, Qakbot pattern)\n"
            "- `explorer.exe → powershell.exe -enc` = suspicious\n"
            "- `svchost.exe → cmd.exe` (not from services.exe parent) = injection\n\n"
            "**4. Memory forensics (if available):**\n"
            "```bash\n# Volatility — find injected code\nvol.py -f memory.dmp windows.malfind\nvol.py -f memory.dmp windows.netstat\n```\n\n"
            "**5. Hash suspicious files + check threat intel:**\n"
            "```powershell\nGet-FileHash 'C:\\suspicious\\file.exe' -Algorithm SHA256\n# Submit to VirusTotal, MalwareBazaar, any.run\n```\n\n"
            "**6. Preserve evidence before remediation:**\n"
            "- Memory dump: `winpmem.exe memory.dmp`\n"
            "- Disk image if needed\n"
            "- Export relevant event logs"
        ),
    },
    {
        "category": "incident_response",
        "user": "How do I respond to a ransomware incident?",
        "assistant": (
            "**Ransomware IR — every minute matters.**\n\n"
            "**Phase 1 — IMMEDIATE (0–15 min)**\n"
            "1. **Isolate affected hosts** — unplug network cable / disable NIC (do NOT power off — preserves memory evidence)\n"
            "2. **Identify blast radius** — query SIEM for lateral SMB traffic from patient zero\n"
            "   ```spl\n   index=network src_ip=PATIENT_ZERO dest_port=445 | stats count by dest_ip\n   ```\n"
            "3. **Disable affected Active Directory accounts**\n"
            "4. **Activate IR team + executive notification**\n\n"
            "**Phase 2 — IDENTIFICATION (15–60 min)**\n"
            "1. Identify the ransomware family: check ransom note text at https://id-ransomware.malwarehunterteam.com/\n"
            "2. Determine initial access vector (phishing email? exposed RDP? VPN vuln?)\n"
            "3. Establish infection timeline from logs\n"
            "4. Check if data was exfiltrated before encryption (common in double extortion)\n\n"
            "**Phase 3 — CONTAINMENT**\n"
            "- Block C2 IPs/domains at firewall\n"
            "- Reset ALL domain admin credentials\n"
            "- Force MFA re-enrollment\n"
            "- Check for shadow copy deletion: `vssadmin list shadows`\n\n"
            "**Phase 4 — ERADICATION & RECOVERY**\n"
            "- Rebuild from clean backups (verify backups weren't also encrypted)\n"
            "- Patch the initial access vulnerability FIRST before restoration\n"
            "- Restore in priority order: domain controllers → critical servers → endpoints\n\n"
            "**Phase 5 — POST-INCIDENT**\n"
            "- Law enforcement notification (FBI IC3)\n"
            "- Regulatory notification if PII/PHI affected\n"
            "- Root cause analysis and lessons learned\n\n"
            "**NEVER pay the ransom without legal/executive consultation.**"
        ),
    },
    # ─── THREAT HUNTING ───────────────────────────────────────────────────────
    {
        "category": "threat_hunting",
        "user": "What is threat hunting and how does it differ from alert response?",
        "assistant": (
            "**Alert response** is reactive — you investigate alerts that tools generate.\n\n"
            "**Threat hunting** is proactive — you search for threats that have bypassed your detections. "
            "The hypothesis: *'Assume breach. Look for evidence.'*\n\n"
            "**The PEAK Threat Hunting Framework:**\n\n"
            "1. **Purpose** — Define what you're hunting (e.g., 'Living-off-the-land attacks using LOLBins')\n\n"
            "2. **Engage** — Form a hypothesis based on:\n"
            "   - Threat intel (new TTP from MITRE ATT&CK, CISA advisory)\n"
            "   - Anomalies in your environment\n"
            "   - Crown jewel risk assessment\n\n"
            "3. **Act** — Search logs/EDR for evidence:\n"
            "   ```spl\n   # Hunt for LOLBin usage (certutil, mshta, regsvr32 downloading)\n   index=wineventlog EventCode=4688\n   | where match(NewProcessName, \"(?i)(certutil|mshta|regsvr32|rundll32|wscript)\")\n   | where match(CommandLine, \"(?i)(http|urlcache|download|script)\")\n   | table _time, host, user, CommandLine\n   ```\n\n"
            "4. **Knowledge** — Document findings, create detections, update runbooks\n\n"
            "**Good hunting hypotheses:**\n"
            "- 'Are any hosts communicating with Tor exit nodes?'\n"
            "- 'Is there evidence of Kerberoasting in our AD logs?'\n"
            "- 'Any service accounts running interactive logons?'\n"
            "- 'Are any hosts running LOLBins that never run LOLBins?'"
        ),
    },
    {
        "category": "threat_hunting",
        "user": "How do I hunt for living-off-the-land (LOLBin) attacks in my environment?",
        "assistant": (
            "LOLBins (Living Off the Land Binaries) are legitimate Windows tools abused by attackers "
            "to evade detection.\n\n"
            "**Top LOLBins to hunt:**\n"
            "| Binary | Abuse technique |\n"
            "|--------|----------------|\n"
            "| `certutil.exe` | Download payloads, decode base64 |\n"
            "| `mshta.exe` | Execute HTA/JS/VBScript |\n"
            "| `regsvr32.exe` | Execute DLLs/scripts (Squiblydoo) |\n"
            "| `rundll32.exe` | Execute arbitrary DLLs |\n"
            "| `wscript.exe/cscript.exe` | Execute scripts |\n"
            "| `msiexec.exe` | Install/execute MSI from URL |\n"
            "| `bitsadmin.exe` | Download files |\n"
            "| `powershell.exe -enc` | Obfuscated commands |\n\n"
            "**Hunt query — certutil downloading:**\n"
            "```spl\nindex=wineventlog EventCode=4688 NewProcessName=*certutil*\n| where match(CommandLine, \"(?i)(urlcache|decode|encode|-f http)\")\n| table _time, host, user, CommandLine\n```\n\n"
            "**Hunt query — unusual parent-child chains:**\n"
            "```spl\nindex=wineventlog EventCode=4688\n| where (ParentProcessName=*word* OR ParentProcessName=*excel* OR ParentProcessName=*outlook*)\n  AND match(NewProcessName, \"(?i)(cmd|powershell|mshta|wscript|cscript)\")\n| table _time, host, user, ParentProcessName, NewProcessName, CommandLine\n```\n\n"
            "**Establish baseline first:**\n"
            "- Which machines legitimately use certutil? (IT admins, build servers)\n"
            "- Build allowlist → anything outside it is a hunt lead\n\n"
            "Reference: https://lolbas-project.github.io/ — full LOLBin catalog"
        ),
    },
    {
        "category": "threat_hunting",
        "user": "How do I hunt for Kerberoasting attacks in Active Directory?",
        "assistant": (
            "Kerberoasting extracts service account TGS tickets for offline cracking.\n\n"
            "**How it works:**\n"
            "1. Attacker requests TGS ticket for any SPN-registered service account\n"
            "2. Ticket is encrypted with the service account's NTLM hash\n"
            "3. Attacker cracks offline — no lockout, no noise\n\n"
            "**Detection — Event ID 4769 (Kerberos Service Ticket Requested)**\n"
            "```spl\nindex=wineventlog EventCode=4769\n  Ticket_Encryption_Type=0x17  | eval hour = strftime(_time, \"%H\")\n| where (hour < 7 OR hour > 19)  | stats\n    count as ticket_requests,\n    dc(ServiceName) as unique_services,\n    values(ServiceName) as services\n  by Account_Name, Client_Address\n| where ticket_requests > 3 OR unique_services > 3\n| sort -ticket_requests\n```\n\n"
            "Key indicators:\n"
            "- `Ticket_Encryption_Type=0x17` = RC4-HMAC (weak — modern Kerberoasting)\n"
            "- Multiple different service names from same user in short window\n"
            "- Requests from non-admin accounts\n"
            "- Requests at unusual hours\n\n"
            "**Hunting baseline:**\n"
            "```spl\n# Find service accounts with SPNs (should be small set)\nindex=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17\n| stats count by ServiceName | sort -count\n```\n\n"
            "**Remediation:**\n"
            "- Use AES256 encryption for service accounts (`msDS-SupportedEncryptionTypes`)\n"
            "- Use Group Managed Service Accounts (gMSA) — 120-char auto-rotating passwords\n"
            "- Alert on RC4 ticket requests for sensitive service accounts"
        ),
    },
    # ─── IOC ANALYSIS ─────────────────────────────────────────────────────────
    {
        "category": "ioc_analysis",
        "user": "I have a suspicious IP address. How do I analyze it as an IOC?",
        "assistant": (
            "**IOC enrichment workflow for a suspicious IP:**\n\n"
            "**1. Passive DNS + WHOIS:**\n"
            "```bash\nwhois 185.220.101.50\ndig -x 185.220.101.50  # reverse DNS\n# Historical DNS: https://passivedns.mnemonic.no/\n```\n\n"
            "**2. Threat Intelligence lookups (free):**\n"
            "| Platform | URL |\n"
            "|----------|-----|\n"
            "| VirusTotal | https://www.virustotal.com/gui/ip-address/IP |\n"
            "| AbuseIPDB | https://www.abuseipdb.com/check/IP |\n"
            "| Shodan | https://www.shodan.io/host/IP |\n"
            "| GreyNoise | https://viz.greynoise.io/ip/IP |\n"
            "| IBM X-Force | https://exchange.xforce.ibmcloud.com/ip/IP |\n"
            "| AlienVault OTX | https://otx.alienvault.com/indicator/ip/IP |\n\n"
            "**3. Shodan — what services is this IP running?**\n"
            "```bash\nshodan host 185.220.101.50\n# Shows: open ports, banners, OS, ASN, geolocation\n```\n\n"
            "**4. Context questions to answer:**\n"
            "- Is it a Tor exit node / VPN / proxy? (reduces severity — obfuscation layer)\n"
            "- Is it in a known botnet or C2 infrastructure?\n"
            "- What ASN? Bullet-proof hosting? (Frantech, M247, Shinjiru = high risk)\n"
            "- Has it scanned other organizations recently (GreyNoise)?\n\n"
            "**5. Internal correlation (SIEM):**\n"
            "```spl\nindex=network (src_ip=185.220.101.50 OR dest_ip=185.220.101.50)\n| stats count, sum(bytes) as total_bytes by src_ip, dest_ip, dest_port, app\n| sort -count\n```\n\n"
            "**Verdict framework:**\n"
            "- VT 5+ detections + seen in C2 feeds = confirmed malicious → block + incident\n"
            "- Tor exit node = medium — investigate but may be false alarm\n"
            "- No reputation + just started seeing it = investigate further"
        ),
    },
    {
        "category": "ioc_analysis",
        "user": "How do I analyze a suspicious file hash as an IOC?",
        "assistant": (
            "**Step 1 — Hash the file:**\n"
            "```bash\n# Linux\nsha256sum suspicious_file.exe\nmd5sum suspicious_file.exe\n\n# PowerShell\nGet-FileHash suspicious_file.exe -Algorithm SHA256\nGet-FileHash suspicious_file.exe -Algorithm MD5\n```\n\n"
            "**Step 2 — Check threat intel (start with VT):**\n"
            "```bash\n# VirusTotal API\ncurl -s 'https://www.virustotal.com/api/v3/files/SHA256_HASH' \\\n  -H 'x-apikey: YOUR_VT_KEY' | python3 -m json.tool | grep -E '(malicious|suspicious|last_analysis)'\n```\n"
            "Or simply paste hash at https://www.virustotal.com\n\n"
            "**Step 3 — Static analysis:**\n"
            "```bash\n# File type\nfile suspicious_file.exe\nexiftool suspicious_file.exe  # metadata\n\n# Strings (find URLs, IPs, registry keys)\nstrings suspicious_file.exe | grep -E '(http|cmd|powershell|reg|HKLM|HKCU)'\n\n# PE header analysis\npython3 -c \"import pefile; pe = pefile.PE('suspicious_file.exe'); print(pe.dump_info())\"\n```\n\n"
            "**Step 4 — Dynamic analysis (sandbox):**\n"
            "| Sandbox | URL |\n|---------|-----|\n"
            "| any.run | https://any.run (interactive) |\n"
            "| Joe Sandbox | https://www.joesandbox.com |\n"
            "| Hybrid Analysis | https://www.hybrid-analysis.com |\n"
            "| Triage | https://tria.ge |\n\n"
            "**Step 5 — Check for known malware families:**\n"
            "```bash\n# YARA scan\nyara /etc/yara-rules/ suspicious_file.exe\n\n# ClamAV\nclamscan suspicious_file.exe\n```\n\n"
            "**Document:** Hash, file name, detection names, C2 IPs from sandbox, YARA hits → add to TI platform"
        ),
    },
    # ─── DETECTION ENGINEERING ────────────────────────────────────────────────
    {
        "category": "detection_engineering",
        "user": "How do I write a Sigma rule for detecting a malicious PowerShell download cradle?",
        "assistant": (
            "Sigma is a generic SIEM rule format that can be converted to Splunk SPL, Elastic KQL, "
            "Microsoft Sentinel KQL, and others.\n\n"
            "**Sigma rule — PowerShell download cradle:**\n"
            "```yaml\ntitle: PowerShell Download Cradle Detected\nid: a8b3f2e1-9c4d-4f7b-8e2a-1d5c6b7e8f9a\nstatus: experimental\ndescription: Detects PowerShell commands used to download and execute payloads in memory\nreferences:\n    - https://attack.mitre.org/techniques/T1059/001/\nlogsource:\n    product: windows\n    category: ps_script\ndirection: outbound\ntags:\n    - attack.execution\n    - attack.t1059.001\n    - attack.defense_evasion\n    - attack.t1027\ndetection:\n    selection:\n        EventID: 4104\n        ScriptBlockText|contains|any:\n            - 'IEX'\n            - 'Invoke-Expression'\n            - 'DownloadString'\n            - 'DownloadFile'\n            - 'Invoke-WebRequest'\n            - 'WebClient'\n            - 'Net.WebClient'\n    filter_admin:\n        # Exclude known admin scripts (customize per environment)\n        ScriptBlockText|contains:\n            - 'backup_admin.ps1'\n    condition: selection and not filter_admin\nfalsepositives:\n    - Legitimate software installers\n    - Admin automation scripts (add to filter)\nlevel: high\n```\n\n"
            "**Convert to Splunk:**\n"
            "```bash\nsigma convert -t splunk -r sigma_rule.yml\n# Output: index=wineventlog EventCode=4104 (ScriptBlockText=\"*IEX*\" OR ...)\n```\n\n"
            "**Best practices:**\n"
            "- Always test against known-good traffic before deploying\n"
            "- Start with `level: medium`, tune false positives, then raise to `high`\n"
            "- Use `filter_*` conditions to allowlist known-good patterns"
        ),
    },
    {
        "category": "detection_engineering",
        "user": "What is the MITRE ATT&CK framework and how do SOC teams use it?",
        "assistant": (
            "MITRE ATT&CK is a knowledge base of adversary tactics, techniques, and procedures (TTPs) "
            "observed in real-world attacks. It provides a common language for defenders and attackers.\n\n"
            "**Structure:**\n"
            "- **Tactics** (14): The *why* — Initial Access, Execution, Persistence, Privilege Escalation, "
            "Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, C2, Exfiltration, Impact\n"
            "- **Techniques** (700+): The *how* — e.g., T1059 (Command and Scripting Interpreter)\n"
            "- **Sub-techniques**: More specific implementation, e.g., T1059.001 (PowerShell)\n"
            "- **Procedures**: Real-world malware/actor usage examples\n\n"
            "**SOC use cases:**\n\n"
            "1. **Detection coverage mapping** — Map your SIEM rules to ATT&CK techniques. "
            "Use ATT&CK Navigator to visualize gaps:\n"
            "   https://mitre-attack.github.io/attack-navigator/\n\n"
            "2. **Threat hunting hypotheses** — Pick techniques with no detection coverage and hunt for them\n\n"
            "3. **Alert enrichment** — Tag every alert with ATT&CK technique ID for trend analysis\n"
            "   ```spl\n   index=alerts | eval mitre_technique=case(\n     match(alert_name, \"(?i)powershell\"), \"T1059.001\",\n     match(alert_name, \"(?i)kerberoast\"), \"T1558.003\",\n     true(), \"Unknown\"\n   )\n   ```\n\n"
            "4. **Red/Blue communication** — Shared vocabulary between pentesters and defenders\n\n"
            "5. **Incident reporting** — Map confirmed TTPs observed during incident to ATT&CK\n\n"
            "6. **Vendor evaluation** — Ask vendors: which ATT&CK techniques do you detect?"
        ),
    },
    # ─── MALWARE TRIAGE ───────────────────────────────────────────────────────
    {
        "category": "malware_triage",
        "user": "How do I perform quick static malware triage on a suspicious executable?",
        "assistant": (
            "Static analysis examines the file without executing it. Goal: identify malware family and key capabilities in under 10 minutes.\n\n"
            "**1. File identification:**\n"
            "```bash\nfile malware.exe               # magic bytes — is it really a PE?\nexiftool malware.exe           # metadata, compilation time\nsha256sum malware.exe | xargs  # get hash for TI lookup\n```\n\n"
            "**2. String extraction:**\n"
            "```bash\nstrings malware.exe | grep -E '(http|cmd|powershell|HKLM|HKCU|CreateRemoteThread|VirtualAlloc|LoadLibrary)'\nstrings -el malware.exe  # Unicode strings\n\n# Automated with FLOSS (handles obfuscated strings)\nfloss malware.exe | head -100\n```\n\n"
            "**3. PE header analysis:**\n"
            "```bash\npython3 << 'EOF'\nimport pefile\npe = pefile.PE('malware.exe')\n# Check imports — suspicious if: VirtualAlloc, WriteProcessMemory, CreateRemoteThread\nfor entry in pe.DIRECTORY_ENTRY_IMPORT:\n    print(entry.dll.decode())\n    for imp in entry.imports:\n        print('  ', imp.name.decode() if imp.name else hex(imp.ordinal))\nEOF\n```\n\n"
            "**4. Entropy analysis (packed/encrypted = high entropy ~7-8):**\n"
            "```bash\npython3 -c \"\nimport math, collections\ndata = open('malware.exe','rb').read()\nfreq = collections.Counter(data)\nentropy = -sum((c/len(data))*math.log2(c/len(data)) for c in freq.values())\nprint(f'Entropy: {entropy:.2f}/8.0 — {\\\"PACKED\\\" if entropy>7 else \\\"normal\\\"}')\n\"\n```\n\n"
            "**5. YARA scanning:**\n"
            "```bash\nyara /usr/share/yara-rules/malware/ malware.exe 2>/dev/null\n# Community rules: https://github.com/Yara-Rules/rules\n```\n\n"
            "**Key red flags:** C2 URLs, registry run keys, `CreateRemoteThread` import, high entropy sections, compilation timestamp in the future or very old."
        ),
    },
    # ─── SOC TOOLING ──────────────────────────────────────────────────────────
    {
        "category": "soc_tools",
        "user": "What are the essential tools in a SOC analyst's toolkit?",
        "assistant": (
            "**SIEM Platforms:**\n"
            "| Tool | Strength |\n|------|----------|\n"
            "| Splunk | Most widely deployed, powerful SPL |\n"
            "| Microsoft Sentinel | Native Azure/M365 integration, KQL |\n"
            "| Elastic Security (ELK) | Open source, powerful KQL |\n"
            "| IBM QRadar | Enterprise, good correlation engine |\n\n"
            "**EDR/XDR:**\n"
            "| Tool | Strength |\n|------|----------|\n"
            "| CrowdStrike Falcon | Market leader, excellent hunting |\n"
            "| Microsoft Defender for Endpoint | Deep Windows integration |\n"
            "| SentinelOne | Strong AI-based detection |\n"
            "| Carbon Black | Good process tree visualization |\n\n"
            "**Threat Intelligence:**\n"
            "| Tool | Use |\n|------|-----|\n"
            "| VirusTotal | File/URL/IP/domain reputation |\n"
            "| MISP | Open-source TI platform |\n"
            "| AlienVault OTX | Community IOC feeds |\n"
            "| Recorded Future / ThreatConnect | Commercial intel |\n\n"
            "**Forensics & IR:**\n"
            "| Tool | Use |\n|------|-----|\n"
            "| Volatility | Memory forensics |\n"
            "| Autopsy / FTK | Disk forensics |\n"
            "| Velociraptor | Live IR across fleet |\n"
            "| KAPE | Fast evidence collection |\n\n"
            "**Malware Analysis:**\n"
            "| Tool | Use |\n|------|-----|\n"
            "| any.run | Interactive sandbox |\n"
            "| Ghidra / IDA Pro | Reverse engineering |\n"
            "| FLOSS | String extraction |\n"
            "| Cuckoo | Self-hosted sandbox |\n\n"
            "**Detection Engineering:**\n"
            "- Sigma: https://github.com/SigmaHQ/sigma\n"
            "- YARA: https://github.com/VirusTotal/yara"
        ),
    },
    {
        "category": "soc_tools",
        "user": "What is SOAR and how does it improve SOC operations?",
        "assistant": (
            "**SOAR** (Security Orchestration, Automation and Response) automates repetitive SOC tasks "
            "and orchestrates workflows across security tools.\n\n"
            "**Core capabilities:**\n\n"
            "1. **Playbook automation** — Execute multi-step response workflows automatically:\n"
            "   - Alert fires → auto-enrich IP with VT/Shodan → if malicious, block at firewall → notify analyst\n\n"
            "2. **Tool integration** — Connect SIEM + EDR + TI + ticketing in one workflow\n\n"
            "3. **Case management** — Aggregate related alerts into a single incident with full context\n\n"
            "**Common SOAR platforms:**\n"
            "| Platform | Notes |\n|----------|-------|\n"
            "| Palo Alto XSOAR | Market leader, 700+ integrations |\n"
            "| Splunk SOAR (Phantom) | Strong Splunk integration |\n"
            "| Microsoft Sentinel Logic Apps | Native Azure SOAR |\n"
            "| TheHive + Cortex | Open source, excellent for smaller teams |\n\n"
            "**Example automated playbook — phishing response:**\n"
            "```\n1. Phishing email reported\n2. [Auto] Extract URLs + attachments\n3. [Auto] Check all URLs in VirusTotal + URLScan\n4. [Auto] If malicious → block domain in proxy + firewall\n5. [Auto] Pull all users who received same email from mail gateway\n6. [Auto] Quarantine email from all mailboxes\n7. [Auto] Create ticket with full IOC list\n8. [Human] Analyst reviews, confirms, notifies affected users\n```\n\n"
            "**ROI metrics:** SOAR typically reduces MTTR by 60-80% and frees analysts from repetitive enrichment tasks."
        ),
    },
    # ─── CLOUD SECURITY SOC ──────────────────────────────────────────────────
    {
        "category": "cloud_security_soc",
        "user": "How do I investigate a suspicious AWS CloudTrail event for unauthorized access?",
        "assistant": (
            "CloudTrail is your primary audit log for AWS API activity. Here's how to investigate.\n\n"
            "**Step 1 — Key events to look for:**\n"
            "```\nConsoleLogin              — who logged into the AWS console\nAssumeRole                — role assumption (lateral movement)\nCreateUser / CreateAccessKey — persistence\nPutBucketPolicy           — S3 bucket exposure\nDescribeInstances         — reconnaissance\nGetSecretValue            — secrets access (Secrets Manager)\n```\n\n"
            "**Step 2 — Athena query on CloudTrail (if logs in S3):**\n"
            "```sql\nSELECT eventtime, useridentity.arn, eventname, sourceipaddress, errorcode\nFROM cloudtrail_logs\nWHERE eventtime BETWEEN '2026-02-20' AND '2026-02-21'\n  AND errorcode IS NULL\n  AND eventname IN ('ConsoleLogin','AssumeRole','CreateUser','CreateAccessKey')\nORDER BY eventtime;\n```\n\n"
            "**Step 3 — Red flags:**\n"
            "- API calls from unusual IP/country (check `sourceIPAddress`)\n"
            "- `userAgent: aws-sdk-python / curl` on console-only accounts\n"
            "- `errorCode: AccessDenied` spikes — enumeration attempts\n"
            "- `CreateAccessKey` for IAM user not owned by caller — privilege escalation\n"
            "- `StopLogging` or `DeleteTrail` — attacker covering tracks (critical)\n\n"
            "**Step 4 — Containment:**\n"
            "- Disable compromised IAM user: `aws iam disable-user-access-key`\n"
            "- Attach deny policy to suspected role\n"
            "- Rotate all access keys for affected accounts\n"
            "- Check for any new IAM users, roles, or policies created"
        ),
    },
    {
        "category": "cloud_security_soc",
        "user": "How do I detect and respond to compromised AWS IAM credentials?",
        "assistant": (
            "Compromised IAM credentials are one of the most critical cloud incidents.\n\n"
            "**Detection signals:**\n"
            "- CloudTrail: API calls from unusual IP/geo for that identity\n"
            "- GuardDuty findings: `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`\n"
            "- IAM calls at unusual hours or high volume\n"
            "- `GetCallerIdentity` calls — attacker confirming credential validity\n\n"
            "**Immediate containment (run in order):**\n"
            "```bash\n# 1. Disable the access key (non-destructive — can re-enable)\naws iam update-access-key --access-key-id AKIA... --status Inactive\n\n"
            "# 2. Attach explicit deny policy to stop all API calls\naws iam put-user-policy --user-name compromised-user \\\n  --policy-name DenyAll \\\n  --policy-document '{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Deny\",\"Action\":\"*\",\"Resource\":\"*\"}]}'\n\n"
            "# 3. Revoke all active sessions\naws iam delete-user-session-policies --user-name compromised-user\n```\n\n"
            "**Investigation scope:**\n"
            "```bash\n# What did they do? (last 24h)\naws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=compromised-user \\\n  --start-time 2026-02-20T00:00:00 --max-results 50\n\n"
            "# Did they create new credentials/users/roles?\naws iam list-access-keys\naws iam list-users\naws iam list-roles\n```\n\n"
            "**Recovery:**\n"
            "- Create new access key for legitimate user\n"
            "- Remove attacker-created resources\n"
            "- Enable MFA enforcement, credential rotation policy\n"
            "- Review and tighten IAM policies (least privilege)"
        ),
    },
    # ─── ACTIVE DIRECTORY ATTACKS ────────────────────────────────────────────
    {
        "category": "active_directory_detection",
        "user": "How do I detect Kerberoasting activity in my environment?",
        "assistant": (
            "Kerberoasting generates Kerberos TGS requests for service accounts — detectable via Event ID 4769.\n\n"
            "**Key indicator:** Abnormally high volume of TGS requests with encryption type 0x17 (RC4).\n\n"
            "**Splunk detection:**\n"
            "```spl\nindex=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!=\"krbtgt\"\n| stats count by Account_Name, Client_Address, Service_Name\n| where count > 5\n| sort -count\n```\n\n"
            "**Elastic KQL:**\n"
            "```kql\nevent.code: \"4769\" AND winlog.event_data.TicketEncryptionType: \"0x17\"\nAND NOT winlog.event_data.ServiceName: \"krbtgt\"\n```\n\n"
            "**Sigma rule:**\n"
            "```yaml\ntitle: Kerberoasting - RC4 TGS Request\nlogsource:\n  product: windows\n  service: security\ndetection:\n  selection:\n    EventID: 4769\n    TicketEncryptionType: '0x17'\n  filter:\n    ServiceName: 'krbtgt'\n  condition: selection and not filter\nfalsepositives:\n  - Legacy systems that don't support AES\nlevel: high\n```\n\n"
            "**Response:**\n"
            "- Identify the source account (`Account_Name`) and IP (`Client_Address`)\n"
            "- Verify if legitimate admin activity\n"
            "- Force password reset on targeted service accounts\n"
            "- Enable AES-256 encryption for all service accounts to eliminate RC4 TGS requests"
        ),
    },
    {
        "category": "active_directory_detection",
        "user": "How do I detect a DCSync attack?",
        "assistant": (
            "DCSync abuses AD replication rights to extract all password hashes from a DC "
            "without touching LSASS. Detected via Event ID 4662.\n\n"
            "**Detection — Event ID 4662 (operation performed on object):**\n"
            "```spl\nindex=wineventlog EventCode=4662\n  Properties=\"*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*\"\n  OR Properties=\"*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*\"\n  OR Properties=\"*89e95b76-444d-4c62-991a-0facbeda640c*\"\n| where NOT match(Subject_Account_Name, \"(?i)^(DC1\\$|DC2\\$|.*\\$)$\")\n| table _time, Subject_Account_Name, Subject_Account_Domain, Object_DN\n```\n\n"
            "The GUIDs above are the `DS-Replication-Get-Changes`, `DS-Replication-Get-Changes-All`, "
            "and `DS-Replication-Get-Changes-In-Filtered-Set` rights.\n\n"
            "**Key red flag:** If the account performing replication is NOT a Domain Controller computer account (`$`), it's almost certainly an attack.\n\n"
            "**Network detection:**\n"
            "- Alert on `MS-DRSR` (Directory Replication Service Remote Protocol) traffic from non-DC hosts\n"
            "- NetFlow/packet capture: DCSync uses MS-RPC on port 135 + dynamic RPC ports\n\n"
            "**Immediate response:**\n"
            "1. Isolate the source host\n"
            "2. Assume all domain hashes are compromised — treat as full domain compromise\n"
            "3. Reset `krbtgt` password **twice** (invalidates all Kerberos tickets)\n"
            "4. Reset all privileged account passwords\n"
            "5. Review who has DCSync rights: `Get-DomainObjectAcl -SearchBase 'DC=domain,DC=local' | ?{$_.ObjectAceType -match 'Replication'}`"
        ),
    },
    # ─── RANSOMWARE RESPONSE ─────────────────────────────────────────────────
    {
        "category": "incident_response",
        "user": "Walk me through a ransomware incident response using the PICERL framework.",
        "assistant": (
            "**PREPARE**\n"
            "- Offline backups tested and verified (3-2-1 rule)\n"
            "- IR playbooks documented and practiced\n"
            "- Segmentation in place to limit blast radius\n"
            "- Identify crown jewel assets\n\n"
            "**IDENTIFY**\n"
            "- Scope: how many hosts affected? (`cme smb 10.0.0.0/24 --shares` to find encrypted shares)\n"
            "- Patient zero: earliest encrypted file timestamp / first EDR alert\n"
            "- Ransom note: identifies ransomware family → look up known IoCs, decryptors\n"
            "- Check backup infrastructure — ransomware often targets backups first\n\n"
            "**CONTAIN**\n"
            "```\n1. Network: isolate affected VLANs/segments immediately\n2. AD: disable compromised accounts (attackers often have domain admin)\n3. EDR: isolate all affected hosts (not just encrypted ones)\n4. DO NOT power off hosts — memory forensics may be needed\n5. Preserve: take memory dumps and disk images of key hosts\n```\n\n"
            "**ERADICATE**\n"
            "- Identify and remove all persistence (scheduled tasks, new accounts, backdoors)\n"
            "- Reset krbtgt twice if AD was compromised (golden ticket prevention)\n"
            "- Rebuild from clean images — do not trust encrypted hosts\n"
            "- Patch the initial access vector (vulnerable VPN, RDP, phishing)\n\n"
            "**RECOVER**\n"
            "- Restore from verified clean offline backups\n"
            "- Restore in isolated environment first — validate data integrity\n"
            "- Staged re-connection to network with monitoring\n"
            "- Test business functions before declaring recovery complete\n\n"
            "**LESSONS LEARNED**\n"
            "- Root cause analysis: how did attacker get in?\n"
            "- Dwell time: how long were they in before ransomware deployment?\n"
            "- Detection gaps: why wasn't it caught earlier?\n"
            "- Update playbooks, controls, and awareness training"
        ),
    },
    # ─── MORE DETECTION ENGINEERING ──────────────────────────────────────────
    {
        "category": "detection_engineering",
        "user": "How do I write a Sigma rule to detect a specific attack?",
        "assistant": (
            "Sigma is a vendor-neutral SIEM detection rule format. Here's how to write one.\n\n"
            "**Sigma rule structure:**\n"
            "```yaml\ntitle: Suspicious Process Creation via WMI\nid: a1b2c3d4-e5f6-7890-abcd-ef1234567890\nstatus: experimental\ndescription: Detects process creation via WMI which is commonly used for lateral movement\nreferences:\n  - https://attack.mitre.org/techniques/T1047/\nauthor: Hancock - CyberViser\ndate: 2026/02/21\ntags:\n  - attack.lateral_movement\n  - attack.t1047\nlogsource:\n  category: process_creation\n  product: windows\ndetection:\n  selection:\n    ParentImage|endswith: '\\WmiPrvSE.exe'\n    Image|endswith:\n      - '\\cmd.exe'\n      - '\\powershell.exe'\n      - '\\wscript.exe'\n      - '\\cscript.exe'\nfalsepositives:\n  - Legitimate WMI-based management tools\n  - SCCM / Endpoint management\nlevel: high\n```\n\n"
            "**Convert to SIEM query:**\n"
            "```bash\n# Using sigmac or pySigma\npip install pysigma pysigma-backend-splunk\n\nsigma convert -t splunk rule.yml\n# Output: ParentImage=\"*\\\\WmiPrvSE.exe\" (Image=\"*\\\\cmd.exe\" OR Image=\"*\\\\powershell.exe\")\n```\n\n"
            "**Rule writing tips:**\n"
            "- Use `|contains`, `|startswith`, `|endswith` for flexible matching\n"
            "- Use `condition: all of selection*` for AND logic across multiple filter groups\n"
            "- Test with real log samples before deploying\n"
            "- Set appropriate level: `informational / low / medium / high / critical`\n"
            "- Add `falsepositives` to document known noise sources"
        ),
    },
    {
        "category": "detection_engineering",
        "user": "How do I tune a SIEM rule to reduce false positives without losing detection coverage?",
        "assistant": (
            "False positive reduction is the #1 challenge in detection engineering.\n\n"
            "**Step 1 — Measure your FP rate:**\n"
            "```spl\n# Splunk: how often does this rule fire and what's the TP rate?\nindex=notable_events rule_name=\"Suspicious PowerShell\"\n| stats count by verdict, analyst_name\n| eventstats sum(count) as total\n| eval pct=round(count/total*100,1)\n```\n\n"
            "**Step 2 — Identify FP patterns:**\n"
            "```spl\n# Find common FP characteristics\nindex=wineventlog [your detection query]\n| stats count by ParentImage, User, host\n| sort -count\n| head 20\n```\n"
            "Look for: specific service accounts, known admin tools, scheduled task baselines\n\n"
            "**Step 3 — Add targeted exclusions (not broad ones):**\n"
            "```spl\n# BAD — too broad\nNOT User=\"admin\"\n\n"
            "# GOOD — specific and documented\nNOT (User=\"svc_sccm\" AND ParentImage=\"*\\\\CcmExec.exe\")\nNOT (User=\"backup_svc\" AND CommandLine=\"*backup.ps1*\" AND host=\"BACKUP-SRV-01\")\n```\n\n"
            "**Step 4 — Use risk-based scoring instead of direct alerting:**\n"
            "- Low-confidence detections → add to risk score (RBS)\n"
            "- Alert only when risk score exceeds threshold\n"
            "- Correlate multiple low-confidence signals into one high-confidence alert\n\n"
            "**Step 5 — Document every exclusion:**\n"
            "```yaml\n# In Sigma rule falsepositives field:\nfalsepositives:\n  - SCCM client (CcmExec.exe) spawning PowerShell for patch management\n  - Backup agent on BACKUP-SRV-01 running scheduled backup scripts\n```"
        ),
    },
    # ─── MORE THREAT HUNTING ─────────────────────────────────────────────────
    {
        "category": "threat_hunting",
        "user": "How do I hunt for living-off-the-land (LOL) techniques in Windows environments?",
        "assistant": (
            "Living-off-the-land (LOLBAS) uses legitimate Windows binaries for malicious purposes — "
            "harder to detect because they're whitelisted.\n\n"
            "**Key LOL binaries to hunt:**\n"
            "```\ncertutil.exe  — download files, decode base64, cert operations\nbitsadmin.exe — download/upload files via BITS\nmshta.exe     — execute HTA files (HTML applications)\nregsvr32.exe  — execute DLLs and SCT files (Squiblydoo)\nrundll32.exe  — execute DLLs and JS\nwmic.exe      — lateral movement, process creation\ncsc.exe       — compile C# on-the-fly\n```\n\n"
            "**Hunt queries — Splunk:**\n"
            "```spl\n# certutil downloading content (should NEVER reach internet)\nindex=wineventlog EventCode=4688 \n  (NewProcessName=\"*\\\\certutil.exe\" AND CommandLine=\"*urlcache*\")\n  OR (NewProcessName=\"*\\\\certutil.exe\" AND CommandLine=\"*decode*\")\n| table _time, host, User, CommandLine\n\n"
            "# regsvr32 loading remote scriptlet (Squiblydoo)\nindex=wineventlog EventCode=4688 NewProcessName=\"*\\\\regsvr32.exe\"\n  CommandLine=\"*http*\" OR CommandLine=\"*\\\\\\\\*\"\n| table _time, host, User, CommandLine\n\n"
            "# mshta executing remote HTA\nindex=wineventlog EventCode=4688 NewProcessName=\"*\\\\mshta.exe\"\n  (CommandLine=\"*http*\" OR CommandLine=\"*vbscript*\" OR CommandLine=\"*javascript*\")\n```\n\n"
            "**Reference:** https://lolbas-project.github.io — full list of LOL binaries with examples\n\n"
            "**Baseline approach:**\n"
            "- Certutil should only run from admin accounts for cert operations — alert on any web download\n"
            "- Mshta should never execute remote content in most environments\n"
            "- Build process tree analytics: flag unusual parent-child relationships"
        ),
    },
    {
        "category": "threat_hunting",
        "user": "How do I write a threat hunting hypothesis and execute a structured hunt?",
        "assistant": (
            "Effective threat hunting is hypothesis-driven, not random. Here's the structured approach.\n\n"
            "**Step 1 — Form a hypothesis:**\n"
            "Format: *'I believe [threat actor/technique] may be present because [intelligence/trigger]'*\n\n"
            "Example:\n"
            "> 'I believe an adversary is using scheduled tasks for persistence because we recently saw a "
            "phishing campaign targeting our industry (ref: CISA advisory AA26-042A) and scheduled task "
            "creation spikes in our baseline data.'\n\n"
            "**Step 2 — Identify data sources:**\n"
            "- For scheduled tasks: Windows Security (4698, 4702), Sysmon (Event 11 — file creation in System32\\Tasks)\n\n"
            "**Step 3 — Build and run queries:**\n"
            "```spl\n# Scheduled task creation — who created what, when\nindex=wineventlog EventCode=4698\n| rex field=Message \"Task Name:\\s+(?<task_name>[^\\r\\n]+)\"\n| rex field=Message \"Task Content:\\s+(?<task_xml>.+)\"\n| stats count by host, SubjectUserName, task_name\n| where NOT match(task_name, \"(?i)(microsoft|windows|adobe|google)\")\n| sort -count\n```\n\n"
            "**Step 4 — Analyze and pivot:**\n"
            "- Unexpected creator accounts → pivot on that user's full activity\n"
            "- Unusual task names or paths → examine task XML content\n"
            "- New tasks running from temp dirs (`%TEMP%`, `%APPDATA%`) → high confidence malicious\n\n"
            "**Step 5 — Document the hunt:**\n"
            "| Field | Value |\n"
            "|-------|-------|\n"
            "| Hypothesis | Scheduled task persistence post-phishing |\n"
            "| Data sources | WinEventLog 4698, Sysmon 11 |\n"
            "| Timeframe | 2026-02-14 to 2026-02-21 |\n"
            "| Outcome | No evidence found / 3 suspicious tasks identified on WKSTN-042 |\n"
            "| Actions | Escalated to IR / Tuned detection rule / Created new Sigma rule |"
        ),
    },
    # ─── MORE SIEM QUERIES ────────────────────────────────────────────────────
    {
        "category": "siem_queries",
        "user": "Write me a Microsoft Sentinel KQL query to detect password spray attacks.",
        "assistant": (
            "Password spray = many accounts, few attempts per account, from one or few source IPs.\n\n"
            "**Microsoft Sentinel KQL:**\n"
            "```kql\nSigninLogs\n| where TimeGenerated >= ago(1h)\n| where ResultType != \"0\"  // Failures only\n| summarize\n    FailedAttempts = count(),\n    UniqueAccounts  = dcount(UserPrincipalName),\n    AccountList     = make_set(UserPrincipalName, 20)\n  by IPAddress, bin(TimeGenerated, 10m)\n| where UniqueAccounts >= 10 and FailedAttempts >= 10\n| extend AccountSample = tostring(AccountList)\n| project TimeGenerated, IPAddress, FailedAttempts, UniqueAccounts, AccountSample\n| order by FailedAttempts desc\n```\n\n"
            "**Tuning guidance:**\n"
            "- Adjust `UniqueAccounts >= 10` based on your environment baseline\n"
            "- Add `| where IPAddress !in (known_good_ips)` to exclude internal scanners\n"
            "- Correlate with successful logins after sprays: join with `ResultType == \"0\"` events\n\n"
            "**Elastic KQL equivalent:**\n"
            "```kql\nevent.dataset: \"azure.signinlogs\"\nAND azure.signinlogs.properties.status.error_code: *\nAND NOT azure.signinlogs.properties.status.error_code: \"0\"\n```\n"
            "Then aggregate in Lens or use an Aggregation rule.\n\n"
            "**Response on detection:**\n"
            "1. Identify source IP — internal vs external?\n"
            "2. Block IP at firewall/Conditional Access Named Locations\n"
            "3. Check for any successful auths from that IP\n"
            "4. Enable MFA challenge on targeted accounts"
        ),
    },
    # ─── MORE IOC ANALYSIS ────────────────────────────────────────────────────
    {
        "category": "ioc_analysis",
        "user": "How do I pivot on an IOC to expand my investigation?",
        "assistant": (
            "IOC pivoting turns one indicator into a full threat picture.\n\n"
            "**Starting with a malicious IP:**\n"
            "```bash\n# Step 1 — Reputation\ncurl 'https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4' -H 'x-apikey: VT_KEY'\n\n"
            "# Step 2 — Passive DNS (what domains resolved to this IP?)\ncurl 'https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4/resolutions' -H 'x-apikey: VT_KEY'\n\n"
            "# Step 3 — WHOIS / ASN\nwhois 1.2.3.4\ncurl 'https://ipinfo.io/1.2.3.4/json'\n\n"
            "# Step 4 — Shodan — what services does this IP expose?\ncurl 'https://api.shodan.io/shodan/host/1.2.3.4?key=SHODAN_KEY'\n```\n\n"
            "**Pivot from domain → IP → certificates:**\n"
            "```bash\n# Certificate transparency — find related infrastructure\ncurl 'https://crt.sh/?q=malicious-domain.com&output=json' | jq '.[].name_value'\n\n"
            "# Same TLS cert used on other domains? (Shodan)\ncurl 'https://api.shodan.io/shodan/host/search?key=KEY&query=ssl.cert.subject.cn:malicious-domain.com'\n```\n\n"
            "**Pivot from hash → sandbox report:**\n"
            "```bash\n# VirusTotal behavior\ncurl 'https://www.virustotal.com/api/v3/files/FILE_HASH/behaviours' -H 'x-apikey: VT_KEY'\n\n"
            "# Any.run sandbox — look for C2 beacons, dropped files, network IOCs\n```\n\n"
            "**Document the pivot chain:**\n"
            "```\nInitial IP: 1.2.3.4\n  → pDNS: badactor.xyz, evil-update.net\n  → SSL cert: *.badactor.xyz\n  → Related IPs: 5.6.7.8 (same cert)\n  → Hash dropped by beacon: abc123...\n  → C2 URL: http://badactor.xyz/gate.php\n```"
        ),
    },
    # ─── MALWARE TRIAGE ──────────────────────────────────────────────────────
    {
        "category": "malware_triage",
        "user": "How do I perform static malware analysis on a suspicious executable?",
        "assistant": (
            "Static analysis examines the file without executing it — safe and fast first step.\n\n"
            "**Step 1 — File identification:**\n"
            "```bash\nfile suspicious.exe          # file type, architecture\nmd5sum suspicious.exe        # hash for VT lookup\nsha256sum suspicious.exe\n\n"
            "# VirusTotal check\ncurl 'https://www.virustotal.com/api/v3/files/SHA256' -H 'x-apikey: KEY'\n```\n\n"
            "**Step 2 — PE header analysis:**\n"
            "```bash\n# pecheck / pefile\npython3 -c \"\nimport pefile\npe = pefile.PE('suspicious.exe')\nprint('Compile time:', pe.FILE_HEADER.dump_dict()['TimeDateStamp'])\nfor s in pe.sections:\n    print(s.Name, hex(s.VirtualAddress), s.SizeOfRawData)\n\"\n\n"
            "# pestudio (Windows) — GUI PE analysis\n```\n\n"
            "**Step 3 — String extraction:**\n"
            "```bash\nstrings suspicious.exe | grep -Ei '(http|https|ftp|cmd|powershell|\\\\\\\\|HKEY|password|admin)'\n\n"
            "# For obfuscated strings — floss (FLARE tool)\nfloss suspicious.exe\n```\n\n"
            "**Step 4 — Import table analysis:**\n"
            "```bash\n# Suspicious imports to flag:\n# CreateRemoteThread, VirtualAllocEx → process injection\n# InternetOpenUrl, WSAConnect → network comms\n# RegSetValueEx, CreateService → persistence\n# CryptEncrypt → ransomware\npython3 -c \"import pefile; pe=pefile.PE('suspicious.exe'); [print(e.name) for imp in pe.DIRECTORY_ENTRY_IMPORT for e in imp.imports if e.name]\"\n```\n\n"
            "**Step 5 — Entropy check:**\n"
            "- High entropy (>7) sections → packed/encrypted content\n"
            "```bash\npython3 -c \"import pefile, math; pe=pefile.PE('suspicious.exe');\n[print(s.Name, round(s.get_entropy(),2)) for s in pe.sections]\"\n```\n\n"
            "**Document findings:**\n"
            "- File hash, compile time, size, imphash\n"
            "- Suspicious strings: hardcoded IPs/domains, registry keys, commands\n"
            "- Packed: yes/no, packer signature if known\n"
            "- Verdict: benign / suspicious / malicious — confidence level"
        ),
    },
    # ─── SOC REPORTING ────────────────────────────────────────────────────────
    {
        "category": "soc_reporting",
        "user": "How do I write a security incident report?",
        "assistant": (
            "**Incident Report Structure:**\n\n"
            "**1. Executive Summary** (1 paragraph — for non-technical leadership)\n"
            "> On [date], [type of incident] was detected affecting [systems/data]. "
            "The incident was contained within [timeframe]. "
            "[X] systems were affected. [No/Potential/Confirmed] data exfiltration occurred. "
            "All systems have been restored and additional controls have been implemented.\n\n"
            "**2. Incident Details**\n"
            "- **Incident ID:** INC-2026-0042\n"
            "- **Severity:** Critical / High / Medium / Low\n"
            "- **Type:** Malware / Ransomware / Phishing / Unauthorized Access / Data Breach\n"
            "- **Detection Source:** SIEM alert / User report / EDR / Threat intel\n"
            "- **MITRE ATT&CK TTPs:** T1059.001, T1566.001, T1078\n\n"
            "**3. Timeline**\n"
            "| Time (UTC) | Event |\n"
            "|------------|-------|\n"
            "| 2026-02-21 09:15 | Phishing email received by 3 users |\n"
            "| 2026-02-21 09:47 | User clicked link, malware executed |\n"
            "| 2026-02-21 10:02 | EDR alert triggered on host WKS-042 |\n"
            "| 2026-02-21 10:08 | Analyst began triage |\n"
            "| 2026-02-21 10:22 | Host isolated |\n\n"
            "**4. Technical Analysis**\n"
            "- Root cause, infection chain, affected systems, evidence collected\n\n"
            "**5. Containment & Remediation Actions**\n"
            "- What was done, by whom, at what time\n\n"
            "**6. Impact Assessment**\n"
            "- Systems affected, data exposed, business disruption, estimated cost\n\n"
            "**7. Lessons Learned & Recommendations**\n"
            "- What detection failed? What controls should be added? What playbooks to update?\n\n"
            "**8. IOC Appendix**\n"
            "- All hashes, IPs, domains, email addresses for blocklist/TI sharing"
        ),
    },
]


def build():
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "system_prompt": HANCOCK_SYSTEM,
        "pairs": KB,
        "total": len(KB),
        "categories": list({e["category"] for e in KB}),
    }
    with open(OUTPUT_FILE, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[soc-kb] Built {len(KB)} Q&A pairs across {len(data['categories'])} categories → {OUTPUT_FILE}")
    return data


if __name__ == "__main__":
    build()
