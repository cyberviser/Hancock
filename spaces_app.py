"""
Hugging Face Spaces demo for Hancock — CyberViser AI Agent
Free hosting at: https://huggingface.co/spaces/cyberviser/hancock

Set these Space Secrets (Settings → Repository secrets):
  HANCOCK_API_URL  →  https://your-oracle-vm-ip  (or Oracle Cloud IP)
  HANCOCK_API_KEY  →  your bearer token (leave blank if auth disabled)
"""

import os
import requests
import gradio as gr

API_URL = os.getenv("HANCOCK_API_URL", "http://localhost:5000")
API_KEY = os.getenv("HANCOCK_API_KEY", "")
HEADERS = {"Content-Type": "application/json"}
if API_KEY:
    HEADERS["Authorization"] = f"Bearer {API_KEY}"


def _post(endpoint: str, payload: dict) -> str:
    try:
        resp = requests.post(f"{API_URL}{endpoint}", json=payload,
                             headers=HEADERS, timeout=90)
        resp.raise_for_status()
        d = resp.json()
        return (d.get("triage") or d.get("answer") or d.get("query") or
                d.get("playbook") or d.get("code") or d.get("advice") or
                d.get("response") or str(d))
    except requests.exceptions.ConnectionError:
        return "❌  Cannot reach Hancock API. Set HANCOCK_API_URL in Space Secrets."
    except requests.exceptions.HTTPError as e:
        return f"❌  API error {e.response.status_code}: {e.response.text[:300]}"
    except Exception as e:
        return f"❌  Error: {e}"


def run_triage(alert: str) -> str:
    if not alert.strip():
        return "⚠️  Please enter an alert."
    return _post("/v1/triage", {"alert": alert})


def run_ask(question: str, mode: str) -> str:
    if not question.strip():
        return "⚠️  Please enter a question."
    return _post("/v1/ask", {"question": question, "mode": mode.lower()})


def run_hunt(target: str, siem: str) -> str:
    if not target.strip():
        return "⚠️  Please enter a hunting target."
    return _post("/v1/hunt", {"target": target, "siem": siem.lower()})


def run_code(task: str, language: str) -> str:
    if not task.strip():
        return "⚠️  Please enter a task."
    return _post("/v1/code", {"task": task, "language": language.lower() if language != "auto" else ""})


def run_ciso(question: str, output_type: str, context: str) -> str:
    if not question.strip():
        return "⚠️  Please enter a question."
    return _post("/v1/ciso", {"question": question, "output": output_type, "context": context})


def run_respond(incident: str) -> str:
    if not incident.strip():
        return "⚠️  Please describe the incident."
    return _post("/v1/respond", {"incident": incident})


CSS = """
.gradio-container { font-family: 'Courier New', monospace !important; }
.tab-nav button { font-family: 'Courier New', monospace !important; }
"""

with gr.Blocks(title="Hancock — CyberViser", theme=gr.themes.Monochrome(), css=CSS) as demo:
    gr.Markdown("""
# 🛡️ Hancock — AI Cybersecurity Agent
**by [CyberViser](https://cyberviser.github.io/Hancock/)** · Mistral 7B · MITRE ATT&CK · NVD/CVE

> Specialised AI for pentest, SOC analysis, threat hunting, incident response, code generation, and CISO advisory.
    """)

    with gr.Tabs():

        with gr.Tab("🔵 SOC Triage"):
            gr.Markdown("Paste a raw SIEM/EDR/IDS alert and get instant MITRE ATT&CK triage.")
            triage_in  = gr.Textbox(lines=4, placeholder="e.g. Mimikatz.exe detected on DC01 at 03:14 UTC...", label="Alert")
            triage_btn = gr.Button("⚡ Triage Alert", variant="primary")
            triage_out = gr.Textbox(lines=14, label="Hancock Triage", interactive=False)
            triage_btn.click(run_triage, triage_in, triage_out)
            gr.Examples([
                ["Failed login from 185.220.101.45 — 47 attempts in 2 min on SSH port 22"],
                ["PowerShell spawned by winword.exe on WORKSTATION01 — command line: IEX (New-Object Net.WebClient).DownloadString(...)"],
                ["Mimikatz.exe executed on DC01, LSASS memory access detected"],
            ], triage_in)

        with gr.Tab("🔴 Pentest / CVE"):
            gr.Markdown("Pentest recon, CVE analysis, exploitation guidance (authorised use only).")
            ask_q    = gr.Textbox(lines=3, placeholder="e.g. Explain CVE-2024-6387 and how to detect it...", label="Question")
            ask_mode = gr.Radio(["pentest", "soc", "auto"], value="pentest", label="Mode")
            ask_btn  = gr.Button("⚡ Ask Hancock", variant="primary")
            ask_out  = gr.Textbox(lines=14, label="Hancock Response", interactive=False)
            ask_btn.click(run_ask, [ask_q, ask_mode], ask_out)
            gr.Examples([
                ["How do I enumerate subdomains during a pentest recon phase?", "pentest"],
                ["CVE-2021-44228 Log4Shell — CVSS score, affected versions, exploitation method", "pentest"],
                ["Write a Sigma rule to detect Kerberoasting attacks", "soc"],
            ], [ask_q, ask_mode])

        with gr.Tab("🎯 Threat Hunting"):
            gr.Markdown("Generate SIEM detection queries for threat hunting hypotheses.")
            hunt_t    = gr.Textbox(lines=2, placeholder="e.g. lateral movement via PsExec", label="Hunting Target / Hypothesis")
            hunt_siem = gr.Dropdown(["splunk", "elastic", "sentinel", "qradar"], value="splunk", label="SIEM")
            hunt_btn  = gr.Button("⚡ Generate Query", variant="primary")
            hunt_out  = gr.Textbox(lines=12, label="Detection Query", interactive=False)
            hunt_btn.click(run_hunt, [hunt_t, hunt_siem], hunt_out)
            gr.Examples([
                ["lateral movement via PsExec", "splunk"],
                ["kerberoasting", "elastic"],
                ["DNS tunnelling exfiltration", "sentinel"],
            ], [hunt_t, hunt_siem])

        with gr.Tab("💻 Security Code"):
            gr.Markdown("Generate YARA rules, Sigma rules, KQL/SPL queries, exploit PoCs, and security scripts.")
            code_task = gr.Textbox(lines=3, placeholder="e.g. YARA rule for Cobalt Strike beacon", label="Task")
            code_lang = gr.Dropdown(["auto", "yara", "sigma", "kql", "spl", "python", "bash", "powershell", "go"], value="auto", label="Language")
            code_btn  = gr.Button("⚡ Generate Code", variant="primary")
            code_out  = gr.Textbox(lines=16, label="Generated Code", interactive=False)
            code_btn.click(run_code, [code_task, code_lang], code_out)
            gr.Examples([
                ["YARA rule to detect Emotet dropper", "yara"],
                ["Splunk SPL query for Pass-the-Hash detection", "spl"],
                ["Python script to parse Windows Security event log 4624", "python"],
            ], [code_task, code_lang])

        with gr.Tab("👔 CISO Advisor"):
            gr.Markdown("Risk management, compliance frameworks (ISO 27001, SOC 2, NIST CSF), board reporting.")
            ciso_q   = gr.Textbox(lines=3, placeholder="e.g. What controls should we prioritise for ISO 27001?", label="Question")
            ciso_out_type = gr.Radio(["advice", "report", "gap-analysis", "board-summary"], value="advice", label="Output Format")
            ciso_ctx = gr.Textbox(lines=2, placeholder="Optional: org size, industry, cloud provider, current frameworks...", label="Context (optional)")
            ciso_btn = gr.Button("⚡ Ask CISO Advisor", variant="primary")
            ciso_out = gr.Textbox(lines=16, label="CISO Advice", interactive=False)
            ciso_btn.click(run_ciso, [ciso_q, ciso_out_type, ciso_ctx], ciso_out)
            gr.Examples([
                ["What is NIST CSF 2.0 and how does it differ from v1.1?", "advice", ""],
                ["Summarise our top 5 risks for the board", "board-summary", "50-person SaaS, AWS, ISO 27001 in progress"],
                ["Gap analysis for PCI-DSS SAQ-D compliance", "gap-analysis", "E-commerce, Stripe payments, 200 employees"],
            ], [ciso_q, ciso_out_type, ciso_ctx])

        with gr.Tab("🚨 IR Playbook"):
            gr.Markdown("Generate PICERL incident response playbooks for any incident type.")
            ir_in  = gr.Textbox(lines=2, placeholder="e.g. ransomware, BEC, data breach, insider threat...", label="Incident Type")
            ir_btn = gr.Button("⚡ Generate Playbook", variant="primary")
            ir_out = gr.Textbox(lines=16, label="PICERL Playbook", interactive=False)
            ir_btn.click(run_respond, ir_in, ir_out)
            gr.Examples([["ransomware"], ["business email compromise"], ["AWS S3 data breach"]], ir_in)

    gr.Markdown("""
---
🔗 [GitHub](https://github.com/cyberviser/Hancock) · [API Docs](https://cyberviser.netlify.app/api) · [CyberViser](https://cyberviser.netlify.app) · contact@cyberviser.ai
    """)

demo.launch()
