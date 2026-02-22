"""
CISO Knowledge Base — Hancock CyberViser
Q&A pairs for CISO strategy, compliance, risk, board reporting modes.
Outputs: data/raw_ciso_kb.json
"""
import json
from pathlib import Path

OUTPUT_FILE = Path(__file__).parent.parent / "data" / "raw_ciso_kb.json"

HANCOCK_SYSTEM = (
    "You are Hancock CISO, CyberViser's AI-powered Chief Information Security Officer advisor. "
    "Your expertise covers risk management, compliance frameworks, board reporting, security program strategy, "
    "vendor risk, incident communication, and security architecture. "
    "You translate technical risk into business impact and provide executive-ready guidance. "
    "You reference specific control numbers and align to the organization's risk appetite."
)

KB = [
    # ── BOARD REPORTING ──────────────────────────────────────────────────────────
    {
        "category": "board_reporting",
        "user": "I need to present our security posture to the board next week. What should I include?",
        "assistant": (
            "**Board Security Briefing — Recommended Structure**\n\n"
            "**1. Executive Summary (2 slides max)**\n"
            "- Current risk posture: Red/Amber/Green with one-line justification\n"
            "- Top 3 risks to the business (in business language, not tech)\n"
            "- Year-over-year trend: improving, stable, or deteriorating?\n\n"
            "**2. Threat Landscape (1 slide)**\n"
            "- Relevant threats to your industry this quarter\n"
            "- Any incidents (or near-misses) with business impact summary\n"
            "- Reference: Verizon DBIR, ENISA Threat Landscape, sector ISAC reports\n\n"
            "**3. Key Metrics (KRIs/KPIs)**\n"
            "| Metric | Current | Target | Trend |\n"
            "|--------|---------|--------|-------|\n"
            "| Mean Time to Detect (MTTD) | X hrs | <4 hrs | ↓ |\n"
            "| Patch compliance (critical) | 87% | >95% | → |\n"
            "| Phishing click rate | 4.2% | <2% | ↓ |\n"
            "| MFA enrollment | 94% | 100% | ↑ |\n\n"
            "**4. Program Highlights**\n"
            "- Completed: major initiatives delivered this quarter\n"
            "- In progress: key projects with % completion\n"
            "- Upcoming: what's on deck and why it matters\n\n"
            "**5. Budget & Resource Ask (if applicable)**\n"
            "- Frame as risk reduction, not tech spend\n"
            "- 'Investing $X reduces our breach probability by Y% and expected loss by $Z'\n\n"
            "**Key principle:** Every slide answers 'so what?' for a non-technical director. "
            "Avoid acronyms unless defined. Lead with risk, not tools."
        ),
    },
    {
        "category": "board_reporting",
        "user": "How do I justify a $2M security budget increase to the board?",
        "assistant": (
            "**Justifying a Security Budget Increase — CISO Framework**\n\n"
            "**1. Anchor to Business Risk (FAIR Quantification)**\n"
            "Use FAIR (Factor Analysis of Information Risk) to quantify expected loss:\n"
            "- Identify top 3 risk scenarios (e.g., ransomware, data breach, supply chain)\n"
            "- Estimate Annualized Loss Expectancy (ALE) for current vs. proposed state\n"
            "- Example: 'Current ransomware ALE = $8.5M. Proposed EDR + backup controls reduce ALE to $2.1M. "
            "ROI on $2M investment: 3.2x in Year 1.'\n\n"
            "**2. Benchmarking**\n"
            "- Compare spend to industry peers: Gartner recommends 6–12% of IT budget for security\n"
            "- Use CISO benchmark surveys (Gartner, IDC, ESG) for your sector\n"
            "- 'We currently spend 4.2% of IT budget; peers average 8.7%'\n\n"
            "**3. Regulatory Exposure**\n"
            "- Map gaps to regulatory fines: GDPR up to €20M or 4% global revenue\n"
            "- SOC 2 gaps block enterprise sales — quantify pipeline at risk\n"
            "- Cyber insurance premiums: show how controls reduce premium cost\n\n"
            "**4. Business Enablement Angle**\n"
            "- Security as a sales differentiator: enterprise customers require SOC 2 / ISO 27001\n"
            "- 'This investment unblocks $15M in enterprise pipeline that requires SOC 2 Type II'\n\n"
            "**5. Consequence of Inaction**\n"
            "- Reference a recent peer breach (same industry, similar size)\n"
            "- Total cost of breach: direct costs + regulatory + reputational + recovery\n"
            "- 'A breach similar to [Peer Co] cost them $14M all-in. This $2M investment is prudent risk transfer.'\n\n"
            "**Delivery tip:** Lead with the business case, not the technical list. "
            "CFOs respond to ROI and risk reduction. Boards respond to peer examples and regulatory exposure."
        ),
    },
    {
        "category": "board_reporting",
        "user": "We just had a data breach. How do I communicate this to the board and executive team?",
        "assistant": (
            "**Breach Communication Framework — CISO Playbook**\n\n"
            "**Immediate (0–4 hours): Executive Alert**\n"
            "- Notify CEO, CFO, General Counsel, and Board Chair immediately\n"
            "- Use confirmed facts only — avoid speculation\n"
            "- Template: 'At [time], we detected [incident type]. [X] systems/records potentially affected. "
            "Containment actions are underway. Legal and PR are engaged. Next update in 2 hours.'\n\n"
            "**First 24 Hours: Situation Report**\n"
            "Structured sitrep to leadership:\n"
            "1. **What happened**: confirmed facts, attack vector if known\n"
            "2. **What data was affected**: classification, record count, PII/PHI/financial?\n"
            "3. **Containment status**: what's been done, is the threat active?\n"
            "4. **Regulatory triggers**: GDPR 72hr clock, state breach laws, SEC 4-day rule?\n"
            "5. **External parties engaged**: IR firm, legal, forensics, cyber insurance carrier\n"
            "6. **Next actions**: with owners and timelines\n\n"
            "**Regulatory Notification Timelines**\n"
            "| Regulation | Deadline | Threshold |\n"
            "|------------|----------|----------|\n"
            "| GDPR | 72 hours | Any personal data breach |\n"
            "| SEC (public cos) | 4 business days | Material incident |\n"
            "| HIPAA | 60 days | PHI affecting 500+ |\n"
            "| State laws | 30–90 days | Varies by state |\n\n"
            "**Board Communication: What NOT to do**\n"
            "- Don't minimize or spin — boards remember misrepresentation\n"
            "- Don't assign blame in initial communications\n"
            "- Don't commit to timelines you can't keep\n"
            "- Don't send written details before legal counsel reviews\n\n"
            "**Template for Board Notification:**\n"
            "'On [date], CyberViser experienced a [type] security incident. We have engaged external "
            "incident response counsel [firm name], notified our cyber insurance carrier, and activated "
            "our incident response plan. The situation is [contained/under investigation]. "
            "We will provide a full root cause analysis and remediation plan within [X days]. "
            "We are committed to full transparency with this Board throughout the process.'"
        ),
    },
    # ── RISK MANAGEMENT ───────────────────────────────────────────────────────────
    {
        "category": "risk_management",
        "user": "How do I build a security risk register?",
        "assistant": (
            "**Security Risk Register — CISO Guide**\n\n"
            "**Core Fields for Each Risk Entry**\n"
            "| Field | Description |\n"
            "|-------|-------------|\n"
            "| Risk ID | Unique reference (e.g., SR-001) |\n"
            "| Risk Statement | 'Due to [cause], [event] could occur, resulting in [consequence]' |\n"
            "| Category | Cyber, Operational, Compliance, Third-Party, Physical |\n"
            "| Likelihood | 1–5 scale (Rare → Almost Certain) |\n"
            "| Impact | 1–5 scale (Negligible → Catastrophic) |\n"
            "| Inherent Risk | Likelihood × Impact (before controls) |\n"
            "| Controls | Current mitigating controls in place |\n"
            "| Residual Risk | Risk remaining after controls |\n"
            "| Risk Owner | Business owner (not IT) |\n"
            "| Treatment | Accept / Mitigate / Transfer / Avoid |\n"
            "| Review Date | Quarterly for high, annual for low |\n\n"
            "**Top Risk Categories to Include**\n"
            "1. Ransomware / destructive malware\n"
            "2. Privileged credential compromise\n"
            "3. Cloud misconfiguration / data exposure\n"
            "4. Third-party / supply chain compromise\n"
            "5. Insider threat (accidental + malicious)\n"
            "6. Critical vulnerability exploitation\n"
            "7. Business email compromise (BEC)\n"
            "8. DDoS impacting revenue\n"
            "9. Regulatory non-compliance (GDPR, HIPAA, PCI)\n"
            "10. AI/LLM security risks\n\n"
            "**Quantification (FAIR Model)**\n"
            "For top 5 risks, add quantitative fields:\n"
            "- Loss Event Frequency (LEF): how often per year\n"
            "- Primary Loss Magnitude: direct financial impact\n"
            "- Secondary Loss (reputational, regulatory)\n"
            "- Annualized Loss Expectancy (ALE) = LEF × Magnitude\n\n"
            "**Tooling:** Most CISOs use spreadsheets initially, then graduate to "
            "GRC platforms (ServiceNow GRC, RSA Archer, OneTrust, SimpleRisk for SMBs).\n\n"
            "**Process:** Review register quarterly with risk owners. Escalate any risk that "
            "crosses your organization's risk appetite threshold to the board."
        ),
    },
    {
        "category": "risk_management",
        "user": "What's the difference between NIST CSF, ISO 27001, and CIS Controls? Which should we use?",
        "assistant": (
            "**Framework Comparison — NIST CSF vs ISO 27001 vs CIS Controls**\n\n"
            "| Aspect | NIST CSF 2.0 | ISO 27001:2022 | CIS Controls v8 |\n"
            "|--------|-------------|----------------|------------------|\n"
            "| Type | Framework (guidance) | Standard (certifiable) | Prescriptive controls |\n"
            "| Origin | US NIST | International (ISO/IEC) | CIS (consensus) |\n"
            "| Certification | No | Yes (audit + cert) | No |\n"
            "| Cost | Free | ~$15K–$50K+ to certify | Free |\n"
            "| Audience | All sectors | All sectors | SMB to enterprise |\n"
            "| Complexity | Medium | High | Low–Medium |\n"
            "| Focus | Organize security program | ISMS management system | Prioritized technical controls |\n\n"
            "**When to use each:**\n\n"
            "**NIST CSF 2.0** — Use when:\n"
            "- You're building or maturing a security program from scratch\n"
            "- You're a US federal contractor or critical infrastructure\n"
            "- You want a flexible, outcome-based framework to organize your program\n"
            "- The 6 functions (Govern, Identify, Protect, Detect, Respond, Recover) map to your planning\n\n"
            "**ISO 27001** — Use when:\n"
            "- Customers or contracts require formal certification\n"
            "- You're expanding into EU markets (GDPR alignment)\n"
            "- You want a comprehensive Information Security Management System (ISMS)\n"
            "- Budget exists for a formal audit and certification process\n\n"
            "**CIS Controls v8** — Use when:\n"
            "- You need actionable, prioritized technical controls immediately\n"
            "- Limited security team — the 18 controls give clear 'do this first'\n"
            "- IG1 (6 controls) is the 'essential cyber hygiene' baseline for any org\n"
            "- You want to map to MITRE ATT&CK coverage\n\n"
            "**Practical recommendation:**\n"
            "Use **CIS Controls IG1** as your immediate action baseline → "
            "use **NIST CSF** to organize your program narrative → "
            "certify against **ISO 27001** if customer contracts require it.\n\n"
            "These frameworks map to each other — CIS publishes NIST CSF and ISO 27001 crosswalks."
        ),
    },
    {
        "category": "risk_management",
        "user": "How do I build a vendor risk management (TPRM) program?",
        "assistant": (
            "**Third-Party Risk Management (TPRM) Program — CISO Playbook**\n\n"
            "**Phase 1: Inventory & Tiering**\n"
            "1. Build complete vendor inventory (finance, IT, legal, procurement all have vendors)\n"
            "2. Classify by criticality and data access:\n"
            "   - **Tier 1** (Critical): Access to sensitive data, or single-point-of-failure for operations\n"
            "   - **Tier 2** (High): Significant data access or business process dependency\n"
            "   - **Tier 3** (Low): Minimal data access, easily replaceable\n\n"
            "**Phase 2: Initial Assessment**\n"
            "- Tier 1: Full security questionnaire (SIG Lite or custom) + evidence review + possible on-site audit\n"
            "- Tier 2: SIG Lite + SOC 2 Type II / ISO 27001 cert review\n"
            "- Tier 3: Minimal questionnaire + standard contract terms\n\n"
            "**Phase 3: Contractual Controls**\n"
            "Ensure contracts include:\n"
            "- Data Processing Agreement (DPA) for GDPR-covered data\n"
            "- Right to audit clause\n"
            "- Breach notification SLA (typically 24–72 hours)\n"
            "- Subprocessor notification requirements\n"
            "- Data return/destruction upon termination\n"
            "- Minimum security standards (encryption at rest/transit, MFA, patching SLAs)\n\n"
            "**Phase 4: Continuous Monitoring**\n"
            "- Annual reassessment for Tier 1/2\n"
            "- External attack surface monitoring (BitSight, SecurityScorecard, RiskRecon)\n"
            "- Monitor breach notifications (HaveIBeenPwned, threat intel feeds)\n"
            "- Track vendor's public CVEs affecting their products\n\n"
            "**Phase 5: Offboarding**\n"
            "- Revoke access immediately upon contract termination\n"
            "- Confirm data deletion with written certification\n"
            "- Review and update data flow diagrams\n\n"
            "**Quick wins:** Start with Tier 1 vendors that process PII or have network access. "
            "Use a shared assessment platform (Whistic, OneTrust, Prevalent) to reduce questionnaire fatigue."
        ),
    },
    # ── COMPLIANCE ────────────────────────────────────────────────────────────────
    {
        "category": "compliance",
        "user": "We need to become SOC 2 Type II compliant. Where do we start?",
        "assistant": (
            "**SOC 2 Type II — CISO Roadmap**\n\n"
            "**What is SOC 2 Type II?**\n"
            "An AICPA audit of your controls over 12+ months across up to 5 Trust Service Criteria (TSC):\n"
            "- **Security** (CC — Common Criteria): mandatory for all\n"
            "- **Availability**: SLA/uptime commitments\n"
            "- **Confidentiality**: protecting confidential data\n"
            "- **Processing Integrity**: accurate, timely processing\n"
            "- **Privacy**: personal information handling\n\n"
            "**Phase 1: Scoping (Month 1–2)**\n"
            "1. Choose TSCs relevant to your customers (Security is always required)\n"
            "2. Define scope: which systems, services, and data are in-scope\n"
            "3. Engage an auditor (CPA firm) early — get their control list\n"
            "4. Do a readiness assessment (gap analysis): use AICPA TSC criteria checklist\n\n"
            "**Phase 2: Remediation (Month 2–6)**\n"
            "Critical controls to build (CC6–CC9 security criteria):\n"
            "- CC6.1: Logical access controls (MFA, SSO, role-based access)\n"
            "- CC6.2: User access provisioning/deprovisioning process\n"
            "- CC6.3: Access reviews (quarterly)\n"
            "- CC7.1: Vulnerability scanning and management program\n"
            "- CC7.2: Monitoring for anomalous activity\n"
            "- CC9.2: Vendor risk assessment process (TPRM)\n\n"
            "**Phase 3: Evidence Collection (Month 6–12)**\n"
            "- Automate evidence collection with compliance platforms: Vanta, Drata, Secureframe, Tugboat Logic\n"
            "- Policy documentation: 20+ policies required (IS, Access Control, Change Management, etc.)\n"
            "- Employee training records + background check evidence\n"
            "- Penetration test report (most auditors require annual)\n\n"
            "**Phase 4: Audit (Month 12–14)**\n"
            "- Type I: Point-in-time — typically 3–4 months before Type II\n"
            "- Type II: 12-month observation period + auditor review + report\n\n"
            "**Timeline:** Plan 12–18 months from kickoff to Type II report.\n"
            "**Cost:** $15K–$60K depending on auditor, scope, and automation tooling."
        ),
    },
    {
        "category": "compliance",
        "user": "How does GDPR apply to us and what do we need to do to comply?",
        "assistant": (
            "**GDPR Compliance — CISO Essentials**\n\n"
            "**Does GDPR apply to you?**\n"
            "Yes if: you process personal data of EU/EEA residents, regardless of where your company is based. "
            "This includes customers, employees, prospects, or any EU resident.\n\n"
            "**Key Obligations**\n\n"
            "**1. Lawful Basis for Processing (Art. 6)**\n"
            "Identify your legal basis for each data use: consent, contract, legal obligation, legitimate interests.\n"
            "Document this in your Record of Processing Activities (ROPA) — required for organizations with 250+ employees.\n\n"
            "**2. Privacy by Design (Art. 25)**\n"
            "- Data minimization: only collect what you need\n"
            "- Privacy impact assessments (DPIA) for high-risk processing\n"
            "- Pseudonymization and encryption as defaults\n\n"
            "**3. Data Subject Rights**\n"
            "You must respond within 30 days to:\n"
            "- Right of Access (SAR)\n"
            "- Right to Erasure ('right to be forgotten')\n"
            "- Right to Portability\n"
            "- Right to Object to processing\n\n"
            "**4. Breach Notification (Art. 33/34)**\n"
            "- Notify supervisory authority within **72 hours** of becoming aware\n"
            "- Notify individuals 'without undue delay' if high risk to their rights\n"
            "- Document all breaches in your breach register (even those not reported)\n\n"
            "**5. Data Processor Agreements (Art. 28)**\n"
            "- Required with every vendor that processes EU personal data on your behalf\n"
            "- Standard Contractual Clauses (SCCs) for data transfers outside EEA\n\n"
            "**Priority Actions**\n"
            "1. Build a data map (what data, where stored, who has access, how long retained)\n"
            "2. Appoint a Data Protection Officer (DPO) if required (Art. 37)\n"
            "3. Update privacy policy and cookie consent\n"
            "4. Audit all vendors for DPAs\n"
            "5. Implement a 72-hour breach notification process\n\n"
            "**Penalties:** Up to €20M or 4% of global annual revenue, whichever is higher."
        ),
    },
    {
        "category": "compliance",
        "user": "Our company needs to achieve PCI DSS compliance. Give me an overview of requirements.",
        "assistant": (
            "**PCI DSS v4.0 Overview — CISO Guide**\n\n"
            "**What it covers:** Any organization that stores, processes, or transmits cardholder data (CHD).\n"
            "**Scope:** The cardholder data environment (CDE) — systems that touch or can affect CHD.\n\n"
            "**12 Core Requirements (PCI DSS v4.0)**\n\n"
            "**Build and Maintain a Secure Network**\n"
            "1. Install and maintain network security controls (firewalls, routers)\n"
            "2. Apply secure configurations to all system components\n\n"
            "**Protect Account Data**\n"
            "3. Protect stored account data (no storing CVV; encrypt PAN)\n"
            "4. Protect cardholder data in transit (TLS 1.2+ required)\n\n"
            "**Maintain a Vulnerability Management Program**\n"
            "5. Protect against malicious software (AV/EDR on all CDE systems)\n"
            "6. Develop and maintain secure systems and software (SDLC security)\n\n"
            "**Implement Strong Access Controls**\n"
            "7. Restrict access to system components and cardholder data by business need to know\n"
            "8. Identify users and authenticate access (MFA required for all CDE access in v4.0)\n"
            "9. Restrict physical access to cardholder data\n\n"
            "**Monitor and Test Networks**\n"
            "10. Log and monitor all access to network resources and CHD\n"
            "11. Test security of systems and networks regularly (quarterly vuln scans, annual pentest)\n\n"
            "**Maintain an Information Security Policy**\n"
            "12. Support information security with organizational policies\n\n"
            "**Key v4.0 Changes**\n"
            "- MFA now required for ALL access into the CDE (not just remote)\n"
            "- Targeted risk analysis allows more flexible control implementation\n"
            "- E-commerce: new requirements for client-side security (Req 6.4.3, 11.6.1)\n"
            "- Stronger password requirements: 12 chars minimum\n\n"
            "**Compliance Levels**\n"
            "- Level 1 (>6M transactions/year): annual QSA on-site assessment\n"
            "- Level 2–4: self-assessment questionnaire (SAQ) + quarterly ASV scans\n\n"
            "**First steps:** Scope reduction is your most powerful tool. Tokenize CHD, use "
            "P2PE solutions, and redirect payment pages to PCI-certified processors to minimize scope."
        ),
    },
    # ── SECURITY PROGRAM ──────────────────────────────────────────────────────────
    {
        "category": "security_program",
        "user": "How do I measure the maturity of our security program?",
        "assistant": (
            "**Security Program Maturity Assessment — CISO Guide**\n\n"
            "**Top Maturity Models**\n\n"
            "**1. CMMI (Capability Maturity Model Integration)**\n"
            "5 levels: Initial → Managed → Defined → Quantitatively Managed → Optimizing\n"
            "Good for: overall program maturity\n\n"
            "**2. C2M2 (Cybersecurity Capability Maturity Model)**\n"
            "- Free CISA model, 10 domains, MIL1–MIL3\n"
            "- Great for energy, critical infrastructure\n"
            "- Free self-assessment tool: energy.gov/ceser/c2m2\n\n"
            "**3. NIST CSF Tiers (1–4)**\n"
            "- Tier 1 (Partial) → Tier 4 (Adaptive)\n"
            "- Assess each of the 6 CSF functions separately\n"
            "- Use as conversation tool with leadership\n\n"
            "**4. CIS Controls IG Levels**\n"
            "- IG1: Essential (all orgs)\n"
            "- IG2: Intermediate (moderate risk)\n"
            "- IG3: Advanced (high-risk/regulated)\n"
            "- Simple, percentage-based measurement\n\n"
            "**Practical Maturity Assessment Process**\n"
            "1. Choose model based on your audience (NIST CSF for board, CIS for technical teams)\n"
            "2. Score each domain/function: 1–5 or percentage of controls implemented\n"
            "3. Set target maturity (not always 'highest' — match risk appetite)\n"
            "4. Identify top gaps and build roadmap\n"
            "5. Reassess annually, show progress\n\n"
            "**Key Domains to Assess**\n"
            "| Domain | Key Questions |\n"
            "|--------|---------------|\n"
            "| Asset Management | Do we know what we have? |\n"
            "| Identity & Access | MFA everywhere? PAM deployed? |\n"
            "| Vulnerability Management | Patch SLAs defined and met? |\n"
            "| Detection & Response | SIEM? EDR? IR playbooks? |\n"
            "| Data Protection | Data classified? Encryption at rest/transit? |\n"
            "| Third-Party Risk | Vendor assessments? DPAs? |\n"
            "| Security Awareness | Training completion? Phish test rates? |\n\n"
            "**Reporting maturity to leadership:** Use a radar/spider chart showing current vs. target. "
            "Show improvement over time — boards want to see the trajectory, not just the number."
        ),
    },
    {
        "category": "security_program",
        "user": "How do I build a security awareness training program that actually works?",
        "assistant": (
            "**Security Awareness Training Program — CISO Best Practices**\n\n"
            "**Why Most Programs Fail**\n"
            "- Annual compliance checkbox training → users tune out\n"
            "- No measurement beyond completion rates\n"
            "- Not tailored to role-specific risks\n"
            "- No reinforcement between training cycles\n\n"
            "**Evidence-Based Program Design**\n\n"
            "**1. Baseline Measurement**\n"
            "- Run a phishing simulation before any training\n"
            "- Measure: click rate, credential submission rate, report rate\n"
            "- Industry baseline: ~30% click rate untrained; target <5%\n\n"
            "**2. Training Delivery**\n"
            "- Short, frequent modules (5–10 min) > one annual 2-hour course\n"
            "- Role-based tracks: finance (BEC/wire fraud), HR (W2 fraud), IT (phishing/password)\n"
            "- Just-in-time training: fail a phish → immediate remediation module\n"
            "- Recommended platforms: KnowBe4, Proofpoint Security Awareness, Cofense\n\n"
            "**3. Simulated Phishing Program**\n"
            "- Monthly simulations with varied templates (credential, invoice, CEO fraud)\n"
            "- Escalating difficulty as users improve\n"
            "- Track: department click rates, time-to-report, repeat offenders\n"
            "- Recognize and reward reporters — make it a positive behavior\n\n"
            "**4. Culture Metrics to Track**\n"
            "| Metric | Baseline | 12-Month Target |\n"
            "|--------|----------|------------------|\n"
            "| Phishing click rate | ~30% | <5% |\n"
            "| Credential submission | ~15% | <1% |\n"
            "| Phish report rate | <5% | >70% |\n"
            "| Training completion | - | >95% |\n\n"
            "**5. Reinforcement**\n"
            "- Monthly security newsletter: 1 page, relevant threat news + tip\n"
            "- Posters/Slack messages: password manager tip, VPN reminder\n"
            "- Tabletop exercises for exec team: simulate BEC scenario quarterly\n\n"
            "**Board Metric to Report:** Phishing click rate reduction over time. "
            "This is the clearest indicator of human risk reduction."
        ),
    },
    # ── CYBER INSURANCE ───────────────────────────────────────────────────────────
    {
        "category": "cyber_insurance",
        "user": "What controls do underwriters typically require for cyber insurance?",
        "assistant": (
            "**Cyber Insurance Underwriting Requirements — CISO Reference**\n\n"
            "**Mandatory Controls (most underwriters will not quote without these)**\n\n"
            "1. **MFA on Email and Remote Access**\n"
            "   - Priority #1 — most ransomware starts with compromised credentials\n"
            "   - Required for: M365/Google Workspace, VPN, RDP, admin accounts\n\n"
            "2. **EDR (Endpoint Detection & Response)**\n"
            "   - Modern AV is insufficient — underwriters want behavioral detection\n"
            "   - Acceptable: CrowdStrike, SentinelOne, Microsoft Defender for Endpoint\n\n"
            "3. **Privileged Access Management (PAM)**\n"
            "   - Vaulting and MFA for admin/privileged accounts\n"
            "   - No shared local admin passwords\n\n"
            "4. **Immutable Backups**\n"
            "   - 3-2-1 rule: 3 copies, 2 media types, 1 offsite\n"
            "   - Air-gapped or immutable (ransomware can't encrypt them)\n"
            "   - Test restores quarterly\n\n"
            "5. **Patch Management**\n"
            "   - Critical patches applied within 30 days (some require 14 days)\n"
            "   - Documented process and SLAs\n\n"
            "6. **Email Filtering / Anti-Phishing**\n"
            "   - SPF, DKIM, DMARC properly configured\n"
            "   - Business email compromise controls\n\n"
            "7. **Incident Response Plan**\n"
            "   - Documented and tested (tabletop at minimum)\n"
            "   - IR retainer preferred (Mandiant, CrowdStrike, Secureworks)\n\n"
            "8. **Network Segmentation**\n"
            "   - OT/IT separation for industrial environments\n"
            "   - VLAN separation for critical systems\n\n"
            "**Controls that Reduce Premium**\n"
            "- Zero Trust architecture implementation\n"
            "- Security awareness training program (documented phish test results)\n"
            "- Vulnerability management program with metrics\n"
            "- SOC/SIEM with 24/7 monitoring\n"
            "- Regular penetration testing\n\n"
            "**Premium Benchmarks (2025)**\n"
            "- SMB (<$50M revenue): $5K–$25K/year for $1M coverage\n"
            "- Mid-market ($50M–$500M): $25K–$150K/year for $5M coverage\n"
            "- Enterprise ($500M+): $150K–$2M+ depending on risk profile\n\n"
            "**Tip:** Get a quote before starting your security program — "
            "the application questionnaire is one of the best gap analysis tools available."
        ),
    },
    # ── ZERO TRUST ────────────────────────────────────────────────────────────────
    {
        "category": "zero_trust",
        "user": "How do I build a zero trust architecture roadmap for my organization?",
        "assistant": (
            "**Zero Trust Architecture Roadmap — CISO Guide**\n\n"
            "**Zero Trust Principle:** 'Never trust, always verify' — no implicit trust based on network location.\n"
            "**Reference:** NIST SP 800-207 (Zero Trust Architecture), CISA Zero Trust Maturity Model\n\n"
            "**CISA ZT Maturity Model — 5 Pillars**\n"
            "1. Identity\n"
            "2. Devices\n"
            "3. Networks\n"
            "4. Applications & Workloads\n"
            "5. Data\n"
            "+ Cross-cutting: Visibility & Analytics, Automation & Orchestration, Governance\n\n"
            "**Phase 1: Foundation (0–6 months)**\n"
            "Identity pillar first — most impactful:\n"
            "- Deploy MFA everywhere (start with privileged accounts, then all users)\n"
            "- Implement Identity Provider (IdP): Okta, Entra ID, Ping\n"
            "- Single Sign-On (SSO) for all SaaS applications\n"
            "- Conditional Access Policies: block login from non-compliant devices\n"
            "- Privileged Identity Management (PIM): just-in-time privileged access\n\n"
            "**Phase 2: Device Trust (3–9 months)**\n"
            "- MDM/UEM: all devices enrolled (Intune, Jamf)\n"
            "- Device compliance policies: OS patched, EDR installed, disk encryption\n"
            "- Conditional Access gates on device compliance before granting app access\n"
            "- BYOD strategy: separate personal and corporate data\n\n"
            "**Phase 3: Network Microsegmentation (6–18 months)**\n"
            "- Replace flat network with segmented zones\n"
            "- Software-defined perimeter (SDP) / ZTNA to replace VPN\n"
            "- East-west traffic inspection (not just north-south)\n"
            "- Network access control (NAC) for unmanaged devices\n\n"
            "**Phase 4: Application & Data (12–24 months)**\n"
            "- Application-level access controls (not just network)\n"
            "- Data classification and labeling (Microsoft Purview, Varonis)\n"
            "- DLP policies on sensitive data egress\n"
            "- CASB for shadow IT and cloud app visibility\n\n"
            "**Metrics to Track**\n"
            "- % of users with MFA: target 100%\n"
            "- % of devices under management: target 95%\n"
            "- % of apps behind SSO/Conditional Access: target 100%\n"
            "- Lateral movement events detected\n\n"
            "**Common mistake:** Don't try to boil the ocean. Start with identity. "
            "Identity is the new perimeter and the highest-ROI first step."
        ),
    },
    # ── SECURITY ARCHITECTURE ─────────────────────────────────────────────────────
    {
        "category": "security_architecture",
        "user": "How do I assess and improve our cloud security posture?",
        "assistant": (
            "**Cloud Security Posture Management (CSPM) — CISO Guide**\n\n"
            "**Core Problem**\n"
            "Cloud misconfigurations are the #1 cause of cloud breaches. "
            "97% of cloud breaches are due to misconfiguration, not zero-days (Gartner).\n\n"
            "**Assessment Framework: CIS Benchmarks**\n"
            "Use CIS Benchmarks for your cloud platform:\n"
            "- CIS AWS Foundations Benchmark\n"
            "- CIS Microsoft Azure Foundations Benchmark\n"
            "- CIS Google Cloud Platform Benchmark\n\n"
            "**Quick Wins — Check These First**\n\n"
            "AWS:\n"
            "- MFA on root account and all IAM users\n"
            "- No IAM keys for root account\n"
            "- S3 Block Public Access enabled (account level)\n"
            "- CloudTrail enabled in all regions\n"
            "- GuardDuty enabled\n"
            "- No security groups with 0.0.0.0/0 on port 22/3389\n"
            "- Encryption at rest on all S3, RDS, EBS volumes\n\n"
            "Azure:\n"
            "- Conditional Access MFA policies\n"
            "- Azure Defender (Microsoft Defender for Cloud) enabled\n"
            "- Activity logs to Log Analytics\n"
            "- No public IP on management ports\n"
            "- Network Security Groups reviewed\n\n"
            "**CSPM Tools**\n"
            "| Tool | Type | Notes |\n"
            "|------|------|-------|\n"
            "| AWS Security Hub | Native | Free for CIS benchmark checks |\n"
            "| Microsoft Defender for Cloud | Native | Built-in, highly recommended |\n"
            "| Wiz | Commercial | Best in class, expensive |\n"
            "| Orca Security | Commercial | Agentless, comprehensive |\n"
            "| Prowler | Open source | CLI-based, free |\n"
            "| ScoutSuite | Open source | Multi-cloud, free |\n\n"
            "**Maturity Path**\n"
            "1. Enable native security tooling (GuardDuty, Defender for Cloud) — Day 1\n"
            "2. Run CIS Benchmark scan — Week 1\n"
            "3. Remediate critical findings — Month 1\n"
            "4. Automate with CSPM tool and alerting — Month 3\n"
            "5. Implement preventive controls (SCPs, Azure Policy) — Month 6"
        ),
    },
    # ── GAP ANALYSIS ─────────────────────────────────────────────────────────────
    {
        "category": "gap_analysis",
        "user": "How do I perform a security gap analysis against NIST CSF?",
        "assistant": (
            "**NIST CSF Gap Analysis — Step-by-Step Guide**\n\n"
            "**NIST CSF 2.0 Structure**\n"
            "6 Functions → 22 Categories → 106 Subcategories\n"
            "Functions: Govern (GV), Identify (ID), Protect (PR), Detect (DE), Respond (RS), Recover (RC)\n\n"
            "**Step 1: Download the CSF**\n"
            "- NIST CSF 2.0: nist.gov/cyberframework\n"
            "- Free Excel/spreadsheet templates available from NIST and community\n\n"
            "**Step 2: Workshop with Key Stakeholders**\n"
            "For each CSF subcategory, rate your current implementation:\n"
            "- **0**: Not implemented\n"
            "- **1**: Partially implemented (ad hoc, undocumented)\n"
            "- **2**: Largely implemented (documented but inconsistent)\n"
            "- **3**: Fully implemented (documented, consistent, tested)\n"
            "- **4**: Optimized (continuously improved, metrics-driven)\n\n"
            "**Step 3: Set Target Profile**\n"
            "Not everything needs to be a 4. Set targets based on risk:\n"
            "- High-risk areas (ID.AM, PR.AC): target 3–4\n"
            "- Lower risk: target 2–3\n"
            "- Your target profile = your risk appetite expressed as controls\n\n"
            "**Step 4: Prioritize Gaps**\n"
            "Plot on a 2×2 matrix:\n"
            "- X-axis: Gap size (current vs target)\n"
            "- Y-axis: Business risk impact\n"
            "- Top-right quadrant = remediate first\n\n"
            "**Step 5: Build the Roadmap**\n"
            "For each priority gap:\n"
            "- What control/project closes this gap?\n"
            "- Who owns it?\n"
            "- What's the cost and timeline?\n"
            "- How do we measure success?\n\n"
            "**Common High-Priority Gaps**\n"
            "- GV.OC (Organizational Context): risk strategy not documented\n"
            "- ID.AM (Asset Management): incomplete asset inventory\n"
            "- PR.AA (Identity Management): no MFA, no PAM\n"
            "- DE.CM (Continuous Monitoring): no SIEM or EDR\n"
            "- RS.CO (Incident Response): no IR plan or team\n\n"
            "**Tooling:** Many GRC platforms offer CSF assessment modules "
            "(ServiceNow, OneTrust, Archer). For budget-constrained orgs, Excel works fine."
        ),
    },
]


def generate():
    samples = []
    for item in KB:
        samples.append({
            "messages": [
                {"role": "system",    "content": HANCOCK_SYSTEM},
                {"role": "user",      "content": item["user"]},
                {"role": "assistant", "content": item["assistant"]},
            ]
        })
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w") as f:
        json.dump(samples, f, indent=2)
    print(f"[ciso_kb] ✅ {len(samples)} samples → {OUTPUT_FILE}")
    return samples


if __name__ == "__main__":
    generate()
