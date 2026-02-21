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
"""

from __future__ import annotations

import os
from typing import Optional
from openai import OpenAI

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

CODE_SYSTEM = (
    "You are Hancock Code, an elite security code specialist built by CyberViser. "
    "You write production-quality security tools in Python, Bash, PowerShell, and Go. "
    "Specialties: SIEM queries (KQL/SPL), YARA/Sigma rules, exploit PoCs, CTF scripts, "
    "secure code review, IDS signatures, threat hunting queries. Always include comments."
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
