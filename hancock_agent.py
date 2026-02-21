#!/usr/bin/env python3
# Copyright (c) 2025 CyberViser. All Rights Reserved.
# Licensed under the CyberViser Proprietary License — see LICENSE for details.
# Unauthorized commercial use, redistribution, or AI training is prohibited.
"""
Hancock Agent — NVIDIA NIM Inference Backend
CyberViser | hancock_agent.py

Two modes:
  python hancock_agent.py          → interactive CLI chat
  python hancock_agent.py --server → REST API server (port 5000)

CLI mode commands:
  /mode pentest   — switch to Pentest Specialist persona
  /mode soc       — switch to SOC Analyst persona
  /mode auto      — combined persona (default)
  /clear          — clear conversation history
  /history        — show history
  /model <id>     — switch model
  /exit           — quit

Set your key:
  export NVIDIA_API_KEY="nvapi-..."
  or pass --api-key "nvapi-..."
"""
import argparse
import json
import os
import sys
import readline  # noqa: F401 — enables arrow-key history in CLI

try:
    from openai import OpenAI
except ImportError:
    sys.exit("Run: .venv/bin/pip install openai flask")

# ── Hancock identity ──────────────────────────────────────────────────────────
PENTEST_SYSTEM = """You are Hancock, an elite penetration tester and offensive security specialist built by CyberViser.

Your expertise covers:
- Reconnaissance: OSINT, subdomain enumeration, port scanning (nmap, amass, subfinder)
- Web Application Testing: SQLi, XSS, SSRF, auth bypass, IDOR, JWT attacks (Burp Suite, sqlmap)
- Network Exploitation: Metasploit, lateral movement, credential attacks (CrackMapExec, impacket)
- Post-Exploitation: Privilege escalation (LinPEAS, WinPEAS, GTFOBins), persistence, pivoting
- Vulnerability Analysis: CVE research, CVSS scoring, PoC analysis, patch prioritization
- Reporting: PTES methodology, professional finding write-ups, executive summaries

You operate STRICTLY within authorized scope. You always:
1. Confirm authorization before suggesting active techniques
2. Recommend responsible disclosure and remediation
3. Reference real tools, commands, and CVEs with accuracy
4. Provide actionable, technically precise answers

You are Hancock. You are methodical, precise, and professional."""

SOC_SYSTEM = """You are Hancock, an expert SOC Tier-2/3 analyst and incident responder built by CyberViser.

Your expertise covers:
- Alert Triage: Classify and prioritize SIEM/EDR/IDS/IPS alerts using MITRE ATT&CK mapping
- Log Analysis: Windows Event Logs (4624/4625/4688/7045), Syslog, Apache/Nginx, firewall, DNS
- SIEM Queries: Splunk SPL, Elastic KQL, Microsoft Sentinel KQL — writing precise detection queries
- Incident Response: NIST SP 800-61 / PICERL (Prepare, Identify, Contain, Eradicate, Recover, Lessons Learned)
- Threat Hunting: Hypothesis-driven hunting, IOC sweeps, behavioral analytics, UEBA
- IOC Analysis: Hash analysis, domain/IP reputation, WHOIS, passive DNS, file/process/network pivoting
- Detection Engineering: Sigma rules, YARA rules, custom alerts, tuning FP reduction
- Malware Triage: Static (strings, PE headers, imports) + dynamic (sandbox detonation, behavior analysis)
- Threat Intelligence: MISP, OpenCTI, TAXII/STIX, APT group TTPs, attribution

You always:
1. Follow the PICERL framework for incident response
2. Document findings with timestamps, evidence, and chain of custody
3. Write precise detection logic (Sigma, SPL, KQL) with comments
4. Escalate appropriately and communicate clearly to stakeholders
5. Stay calm under pressure — triage by impact and urgency

You are Hancock. You are methodical, calm, and thorough."""

AUTO_SYSTEM = """You are Hancock, an elite cybersecurity specialist built by CyberViser. You operate as both a penetration tester and SOC analyst, depending on context.

**Pentest Mode:** Reconnaissance, exploitation, post-exploitation, CVE analysis, Metasploit, Burp Suite, authorized engagements only.
**SOC Mode:** Alert triage, SIEM queries (Splunk SPL / Elastic KQL / Sentinel KQL), incident response (PICERL), threat hunting, detection engineering, IOC analysis.

You always:
- Operate within authorized scope
- Follow PICERL for IR and PTES for pentesting
- Provide accurate, actionable technical guidance
- Reference real tools, real CVEs, and real detection logic

You are Hancock. Built by CyberViser."""

SYSTEMS = {"pentest": PENTEST_SYSTEM, "soc": SOC_SYSTEM, "auto": AUTO_SYSTEM}
DEFAULT_MODE = "auto"
# Keep backward-compatible alias
HANCOCK_SYSTEM = AUTO_SYSTEM

NIM_BASE_URL = "https://integrate.api.nvidia.com/v1"
DEFAULT_MODEL = "mistralai/mistral-7b-instruct-v0.3"

BANNER = """
╔══════════════════════════════════════════════════════════╗
║  ██╗  ██╗ █████╗ ███╗   ██╗ ██████╗ ██████╗  ██████╗██╗ ║
║  ██║  ██║██╔══██╗████╗  ██║██╔════╝██╔═══██╗██╔════╝██║ ║
║  ███████║███████║██╔██╗ ██║██║     ██║   ██║██║     ██║ ║
║  ██╔══██║██╔══██║██║╚██╗██║██║     ██║   ██║██║     ██╚╗║
║  ██║  ██║██║  ██║██║ ╚████║╚██████╗╚██████╔╝╚██████╗╚═╝║║
║  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═════╝  ╚═════╝   ║
║          CyberViser — Pentest + SOC Specialist           ║
║            Powered by NVIDIA NIM · Mistral 7B             ║
╚══════════════════════════════════════════════════════════╝
  Commands: /mode pentest|soc|auto  /clear  /history  /model <id>  /exit
"""


def make_client(api_key: str) -> OpenAI:
    return OpenAI(base_url=NIM_BASE_URL, api_key=api_key)


def chat(client: OpenAI, history: list[dict], model: str, stream: bool = True,
         system_prompt: str | None = None) -> str:
    system = system_prompt or HANCOCK_SYSTEM
    messages = [{"role": "system", "content": system}] + history
    if stream:
        response_text = ""
        print("\n\033[1;32mHancock:\033[0m ", end="", flush=True)
        stream_resp = client.chat.completions.create(
            model=model,
            messages=messages,
            max_tokens=1024,
            temperature=0.7,
            top_p=0.95,
            stream=True,
        )
        for chunk in stream_resp:
            if chunk.choices and chunk.choices[0].delta.content:
                delta = chunk.choices[0].delta.content
                print(delta, end="", flush=True)
                response_text += delta
        print()
        return response_text
    else:
        resp = client.chat.completions.create(
            model=model,
            messages=messages,
            max_tokens=1024,
            temperature=0.7,
            top_p=0.95,
        )
        return resp.choices[0].message.content


# ── CLI mode ──────────────────────────────────────────────────────────────────
def run_cli(client: OpenAI, model: str):
    print(BANNER)
    print(f"  Model : {model}")
    print(f"  Endpoint: {NIM_BASE_URL}")
    print(f"  Mode  : auto (Pentest + SOC)")
    print()

    history: list[dict] = []
    current_mode = DEFAULT_MODE

    while True:
        try:
            user_input = input("\033[1;34m[You]\033[0m ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[Hancock] Signing off. Stay in scope.")
            break

        if not user_input:
            continue

        if user_input.lower() in ("/exit", "/quit", "exit", "quit"):
            print("[Hancock] Signing off. Stay in scope.")
            break

        if user_input == "/clear":
            history.clear()
            print("[Hancock] Conversation cleared.")
            continue

        if user_input == "/history":
            for i, m in enumerate(history):
                role = m["role"].upper()
                print(f"  [{i}] {role}: {m['content'][:80]}...")
            continue

        if user_input.startswith("/mode"):
            parts = user_input.split()
            if len(parts) == 2 and parts[1] in SYSTEMS:
                current_mode = parts[1]
                history.clear()
                label = {"pentest": "Pentest Specialist 🔴", "soc": "SOC Analyst 🔵", "auto": "Auto (Pentest+SOC) ⚡"}
                print(f"[Hancock] Switched to {label[current_mode]} — history cleared.")
            else:
                print("[Hancock] Usage: /mode pentest | /mode soc | /mode auto")
            continue

        if user_input.startswith("/model "):
            model = user_input[7:].strip()
            print(f"[Hancock] Switched to model: {model}")
            continue

        history.append({"role": "user", "content": user_input})

        try:
            response = chat(client, history, model, stream=True,
                            system_prompt=SYSTEMS[current_mode])
            history.append({"role": "assistant", "content": response})
        except Exception as e:
            print(f"\033[1;31m[Error]\033[0m {e}")
            history.pop()  # remove failed user message


# ── REST API server mode ──────────────────────────────────────────────────────
def run_server(client: OpenAI, model: str, port: int):
    try:
        from flask import Flask, request, jsonify, Response, stream_with_context
    except ImportError:
        sys.exit("Run: .venv/bin/pip install flask")

    app = Flask("hancock")

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({
            "status": "ok", "agent": "Hancock",
            "model": model, "company": "CyberViser",
            "modes": ["pentest", "soc", "auto"],
            "endpoints": ["/v1/chat", "/v1/ask", "/v1/triage", "/v1/hunt", "/v1/respond"],
        })

    @app.route("/v1/chat", methods=["POST"])
    def chat_endpoint():
        data = request.get_json(force=True)
        user_msg = data.get("message", "")
        history  = data.get("history", [])
        stream   = data.get("stream", False)
        mode     = data.get("mode", "auto")

        if not user_msg:
            return jsonify({"error": "message required"}), 400

        system = SYSTEMS.get(mode, AUTO_SYSTEM)
        history.append({"role": "user", "content": user_msg})
        messages = [{"role": "system", "content": system}] + history

        if stream:
            def generate():
                full = ""
                stream_resp = client.chat.completions.create(
                    model=model, messages=messages, max_tokens=1024,
                    temperature=0.7, top_p=0.95, stream=True,
                )
                for chunk in stream_resp:
                    if chunk.choices and chunk.choices[0].delta.content:
                        delta = chunk.choices[0].delta.content
                        full += delta
                        yield f"data: {json.dumps({'delta': delta})}\n\n"
                yield f"data: {json.dumps({'done': True, 'response': full})}\n\n"
            return Response(stream_with_context(generate()), mimetype="text/event-stream")

        resp = client.chat.completions.create(
            model=model, messages=messages, max_tokens=1024,
            temperature=0.7, top_p=0.95,
        )
        response_text = resp.choices[0].message.content
        return jsonify({"response": response_text, "model": model, "mode": mode})

    @app.route("/v1/ask", methods=["POST"])
    def ask_endpoint():
        """Simple single-shot endpoint — no history needed."""
        data = request.get_json(force=True)
        question = data.get("question", "")
        mode     = data.get("mode", "auto")
        if not question:
            return jsonify({"error": "question required"}), 400

        system = SYSTEMS.get(mode, AUTO_SYSTEM)
        messages = [
            {"role": "system",  "content": system},
            {"role": "user",    "content": question},
        ]
        resp = client.chat.completions.create(
            model=model, messages=messages, max_tokens=1024,
            temperature=0.7, top_p=0.95,
        )
        return jsonify({"answer": resp.choices[0].message.content, "model": model, "mode": mode})

    @app.route("/v1/triage", methods=["POST"])
    def triage_endpoint():
        """SOC alert triage — classify and prioritize a security alert."""
        data  = request.get_json(force=True)
        alert = data.get("alert", "")
        if not alert:
            return jsonify({"error": "alert required"}), 400

        prompt = (
            f"Triage the following security alert. Classify severity (Critical/High/Medium/Low/Info), "
            f"identify the MITRE ATT&CK technique(s), determine if it is a True Positive or likely False "
            f"Positive, list immediate containment actions, and recommend next steps.\n\nAlert:\n{alert}"
        )
        messages = [
            {"role": "system", "content": SOC_SYSTEM},
            {"role": "user",   "content": prompt},
        ]
        resp = client.chat.completions.create(
            model=model, messages=messages, max_tokens=1200,
            temperature=0.4, top_p=0.95,
        )
        return jsonify({"triage": resp.choices[0].message.content, "model": model})

    @app.route("/v1/hunt", methods=["POST"])
    def hunt_endpoint():
        """Threat hunting query generator — generate SIEM queries for a given TTP."""
        data   = request.get_json(force=True)
        target = data.get("target", "")   # e.g. "lateral movement with PsExec"
        siem   = data.get("siem", "splunk")  # splunk | elastic | sentinel
        if not target:
            return jsonify({"error": "target required"}), 400

        prompt = (
            f"Generate a {siem.upper()} threat hunting query for: {target}\n"
            f"Include: the query, what data sources are needed, expected fields to review, "
            f"and MITRE ATT&CK mapping. Add comments to explain the logic."
        )
        messages = [
            {"role": "system", "content": SOC_SYSTEM},
            {"role": "user",   "content": prompt},
        ]
        resp = client.chat.completions.create(
            model=model, messages=messages, max_tokens=1200,
            temperature=0.4, top_p=0.95,
        )
        return jsonify({"query": resp.choices[0].message.content, "siem": siem, "model": model})

    @app.route("/v1/respond", methods=["POST"])
    def respond_endpoint():
        """Incident response guidance — PICERL playbook for an incident type."""
        data          = request.get_json(force=True)
        incident_type = data.get("incident", "")   # e.g. "ransomware", "BEC", "data exfiltration"
        if not incident_type:
            return jsonify({"error": "incident required"}), 400

        prompt = (
            f"Provide a detailed PICERL incident response playbook for: {incident_type}\n"
            f"For each phase (Prepare, Identify, Contain, Eradicate, Recover, Lessons Learned), "
            f"provide specific actions, tools to use, evidence to collect, and stakeholder communication steps."
        )
        messages = [
            {"role": "system", "content": SOC_SYSTEM},
            {"role": "user",   "content": prompt},
        ]
        resp = client.chat.completions.create(
            model=model, messages=messages, max_tokens=1500,
            temperature=0.4, top_p=0.95,
        )
        return jsonify({"playbook": resp.choices[0].message.content, "incident": incident_type, "model": model})

    print(f"\n[CyberViser] Hancock API server starting on port {port}")
    print(f"  POST http://localhost:{port}/v1/chat     — conversational (mode: auto|pentest|soc)")
    print(f"  POST http://localhost:{port}/v1/ask      — single question")
    print(f"  POST http://localhost:{port}/v1/triage   — SOC alert triage")
    print(f"  POST http://localhost:{port}/v1/hunt     — threat hunting query generator")
    print(f"  POST http://localhost:{port}/v1/respond  — IR playbook (PICERL)")
    print(f"  GET  http://localhost:{port}/health      — status check\n")
    app.run(host="0.0.0.0", port=port, debug=False)


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Hancock — CyberViser Pentest AI (NVIDIA NIM)")
    parser.add_argument("--api-key", default=os.getenv("NVIDIA_API_KEY"), help="NVIDIA API key")
    parser.add_argument("--model",   default=DEFAULT_MODEL, help="NIM model ID")
    parser.add_argument("--server",  action="store_true", help="Run as REST API server")
    parser.add_argument("--port",    type=int, default=5000, help="Server port (default: 5000)")
    args = parser.parse_args()

    if not args.api_key:
        sys.exit("ERROR: Set NVIDIA_API_KEY env var or pass --api-key")

    client = make_client(args.api_key)

    if args.server:
        run_server(client, args.model, args.port)
    else:
        run_cli(client, args.model)


if __name__ == "__main__":
    main()
