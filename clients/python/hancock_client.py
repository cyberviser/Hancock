"""
Hancock Python SDK
Backed by NVIDIA NIM (Qwen 2.5 Coder 32B + Mistral 7B)

Usage:
    from hancock_client import HancockClient

    h = HancockClient()                         # reads NVIDIA_API_KEY from env
    print(h.ask("Explain CVE-2021-44228"))
    print(h.code("YARA rule for Emotet dropper", language="yara"))
    print(h.triage("Mimikatz.exe on DC01 at 03:14 UTC"))
    print(h.hunt("lateral movement via PsExec", siem="splunk"))
    print(h.respond("ransomware"))
    print(h.sigma("PowerShell encoded exec", logsource="windows sysmon", technique="T1059.001"))
    print(h.ciso("ISO 27001 gap analysis", output="gap-analysis", context="50-person SaaS, AWS"))
"""

from __future__ import annotations

import os
from typing import Optional
from hancock_constants import OPENAI_IMPORT_ERROR_MSG, require_openai

try:
    from openai import OpenAI
except ImportError:  # allow import; require_openai() enforces dependency in constructor
    OpenAI = None  # type: ignore

# ── Models ──────────────────────────────────────────────────────────────────
MODELS: dict[str, str] = {
    "mistral-7b":   "mistralai/mistral-7b-instruct-v0.3",
    "qwen-coder":   "qwen/qwen2.5-coder-32b-instruct",
    "llama-8b":     "meta/llama-3.1-8b-instruct",
    "mixtral-8x7b": "mistralai/mixtral-8x7b-instruct-v0.1",
}

SECURITY_SYSTEM = (
    "You are Hancock, an elite AI cybersecurity agent built by CyberViser. "
    "Your expertise spans penetration testing, threat intelligence, SOC analysis, "
    "incident response, CISO strategy, and security architecture. "
    "Respond with actionable, technically precise guidance. "
    "Use MITRE ATT&CK framework, CVE data, and industry best practices."
)

SIGMA_SYSTEM = (
    "You are Hancock Sigma, an expert detection engineer. "
    "Write production-ready Sigma YAML rules with correct logsource, detection, tags "
    "(MITRE ATT&CK technique IDs), falsepositives, and severity level. "
    "After the YAML, briefly explain what it detects and tuning notes."
)

CISO_SYSTEM = (
    "You are Hancock CISO, CyberViser's AI-powered CISO advisor. "
    "Your expertise: NIST RMF, ISO 27001, SOC 2, PCI-DSS, HIPAA, GDPR, NIST CSF 2.0, CIS Controls. "
    "Translate technical risk into business impact. Prioritize by likelihood × impact × cost. "
    "Provide executive-ready language referencing specific control IDs where relevant."
)

YARA_SYSTEM = (
    "You are Hancock YARA, CyberViser's expert malware analyst. "
    "Write production-ready YARA rules with meta, string patterns ($hex, $ascii, $regex, $wide), "
    "and condition logic. Use pe/elf modules when appropriate. "
    "After the rule, explain what it detects and known false positive sources."
)

CODE_SYSTEM = (
    "You are Hancock Code, an elite security code specialist built by CyberViser. "
    "You write production-quality security tools in Python, Bash, PowerShell, and Go. "
    "Specialties: SIEM queries (KQL/SPL), YARA/Sigma rules, exploit PoCs, CTF scripts, "
    "secure code review, IDS signatures, threat hunting queries. Always include comments."
)

IOC_SYSTEM = (
    "You are Hancock IOC, CyberViser's threat intelligence analyst. "
    "When given an indicator of compromise (IP, domain, URL, hash, or email), produce a structured "
    "enrichment report: indicator type, threat intel context, associated MITRE ATT&CK techniques, "
    "risk score 1-10 with justification, recommended defensive actions, and relevant CVEs/GHSA."
)


class HancockClient:
    """Synchronous Hancock client backed by NVIDIA NIM."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "mistral-7b",
        coder_model: str = "qwen-coder",
        base_url: str = "https://integrate.api.nvidia.com/v1",
    ):
        require_openai(OpenAI)
        key = api_key or os.environ.get("NVIDIA_API_KEY")
        if not key:
            raise ValueError(
                "NVIDIA_API_KEY not set. Pass api_key= or set the env var."
            )
        self._client = OpenAI(api_key=key, base_url=base_url)
        self.model = MODELS.get(model, model)
        self.coder_model = MODELS.get(coder_model, coder_model)

    # ── Internal ─────────────────────────────────────────────────────────────
    def _complete(
        self,
        system: str,
        user: str,
        model: str,
        temperature: float = 0.7,
        top_p: float = 0.9,
        max_tokens: int = 1024,
    ) -> str:
        resp = self._client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
            temperature=temperature,
            top_p=top_p,
            max_tokens=max_tokens,
            stream=False,
        )
        return resp.choices[0].message.content or ""

    # ── Public API ────────────────────────────────────────────────────────────
    def ask(self, question: str, mode: str = "auto") -> str:
        """General security question — uses Mistral 7B by default."""
        system = SECURITY_SYSTEM
        if mode == "pentest":
            system += " Focus on offensive security and penetration testing."
        elif mode == "soc":
            system += " Focus on SOC operations, alert triage, and incident response."
        return self._complete(system, question, self.model)

    def code(self, task: str, language: Optional[str] = None) -> str:
        """Security code generation — uses Qwen 2.5 Coder 32B."""
        prompt = task
        if language:
            prompt = f"Write {language.upper()} code for the following task:\n{task}"
        return self._complete(
            CODE_SYSTEM, prompt, self.coder_model,
            temperature=0.2, top_p=0.7, max_tokens=2048,
        )

    def triage(self, alert: str) -> str:
        """Triage a SIEM/EDR alert. Returns severity + MITRE mapping."""
        system = SECURITY_SYSTEM + (
            " You are a SOC Tier-2 analyst. Triage the alert: "
            "classify severity (CRITICAL/HIGH/MEDIUM/LOW), "
            "map to MITRE ATT&CK TTPs, and recommend immediate actions."
        )
        return self._complete(system, alert, self.model)

    def hunt(self, target: str, siem: str = "splunk") -> str:
        """Generate threat hunting queries for a TTP."""
        prompt = (
            f"Generate production-ready threat hunting queries for: {target}\n"
            f"SIEM platform: {siem.upper()}. Include query + explanation."
        )
        return self._complete(SECURITY_SYSTEM, prompt, self.model)

    def respond(self, incident: str) -> str:
        """Generate a full PICERL incident response playbook."""
        prompt = (
            f"Generate a full PICERL incident response playbook for: {incident}\n"
            "Cover all 6 phases: Prepare, Identify, Contain, Eradicate, Recover, "
            "Lessons Learned. Be specific with actionable steps."
        )
        return self._complete(SECURITY_SYSTEM, prompt, self.model, max_tokens=2048)

    def sigma(
        self,
        description: str,
        logsource: str = "",
        technique: str = "",
    ) -> str:
        """Generate a Sigma detection rule from a TTP description."""
        hints = []
        if logsource:
            hints.append(f"Target log source: {logsource}.")
        if technique:
            hints.append(f"MITRE ATT&CK technique: {technique} — add to tags field.")
        prompt = (
            f"Write a complete Sigma rule for: {description}\n"
            + (" ".join(hints) + "\n" if hints else "")
            + "Output the full YAML first, then a brief tuning note."
        )
        return self._complete(SIGMA_SYSTEM, prompt, self.model,
                              temperature=0.2, top_p=0.7, max_tokens=2048)

    def ciso(
        self,
        question: str,
        output: str = "advice",
        context: str = "",
    ) -> str:
        """CISO advisor — risk, compliance, board reporting, gap analysis."""
        output_hints = {
            "report":        "Format as a structured risk report: Executive Summary, Findings, Risk Ratings, Recommendations.",
            "gap-analysis":  "Format as a gap analysis table: Control | Current State | Target State | Gap | Priority.",
            "board-summary": "Format as a concise board-ready executive summary (≤300 words, no jargon).",
            "advice":        "",
        }
        ctx_line = f"\n\nOrganisation context: {context}" if context else ""
        hint     = output_hints.get(output, "")
        prompt   = f"{question}{ctx_line}\n\n{hint}".strip()
        return self._complete(CISO_SYSTEM, prompt, self.model,
                              temperature=0.3, top_p=0.95, max_tokens=2048)

    def yara(
        self,
        description: str,
        file_type: str = "",
        sample_hash: str = "",
    ) -> str:
        """Generate a YARA malware detection rule."""
        hints = []
        if file_type:
            hints.append(f"Target file type: {file_type}.")
        if sample_hash:
            hints.append(f"Known sample hash: {sample_hash} — include in rule meta.")
        prompt = (
            f"Write a complete YARA rule for: {description}\n"
            + (" ".join(hints) + "\n" if hints else "")
            + "Output the full rule first, then a brief explanation and false positive notes."
        )
        return self._complete(YARA_SYSTEM, prompt, self.model,
                              temperature=0.2, top_p=0.7, max_tokens=2048)

    def ioc(self, indicator: str, ioc_type: str = "auto", context: str = "") -> str:
        """Threat intelligence enrichment for an IOC (IP, domain, URL, hash, or email)."""
        prompt = f"Indicator: {indicator}\nType: {ioc_type}\n"
        if context:
            prompt += f"Additional context: {context}\n"
        prompt += "\nProvide a full threat intelligence enrichment report."
        return self._complete(IOC_SYSTEM, prompt, self.model,
                              temperature=0.3, top_p=0.9, max_tokens=1000)

    def chat(self, message: str, history: Optional[list] = None, mode: str = "auto") -> str:
        """Multi-turn conversation with history."""
        system = SECURITY_SYSTEM
        messages = [{"role": "system", "content": system}]
        if history:
            messages.extend(history)
        messages.append({"role": "user", "content": message})
        resp = self._client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=0.7,
            top_p=0.9,
            max_tokens=1024,
            stream=False,
        )
        return resp.choices[0].message.content or ""
