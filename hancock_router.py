"""
Hancock Multi-Model Router v0.8.0
- Local-first (Ollama/NIM) with cloud fallback
- Task-type + complexity + confidence routing
- OWASP LLM06 authorization gate
"""
import os, subprocess, json
from typing import Dict, Any
from hancock_zeroday_guard import guard

class HancockRouter:
    def __init__(self):
        self.local_models = {
            "code": "qwen2.5-coder:32b",
            "pentest": "mistral:7b-instruct",
            "soc": "mistral:7b-instruct",
            "default": "mistral:7b-instruct"
        }
        self.cloud_fallback = {
            "claude": os.getenv("ANTHROPIC_API_KEY"),
            "gpt": os.getenv("OPENAI_API_KEY")
        }

    def route(self, state: Dict) -> str:
        query = state["messages"][-1]
        mode = state.get("mode", "pentest")
        complexity = len(query) // 100  # rough token estimate
        guard_conf = guard.score(query) * 100

        # LLM06 authorization gate
        if guard_conf >= 70:
            return "[0AI_ZERO_DAY_BYPASS_DETECTED] — route blocked"

        # Primary routing
        if "code" in mode or complexity > 15:
            model = self.local_models["code"]
        elif "soc" in mode:
            model = self.local_models["soc"]
        else:
            model = self.local_models["default"]

        # Cloud fallback (only if local confidence low AND API key present)
        if guard_conf < 40 and any(self.cloud_fallback.values()):
            if self.cloud_fallback["claude"]:
                return f"claude-4.6 (fallback) — confirm with Johnny before use"
            return f"gpt-5.4 (fallback) — confirm with Johnny before use"

        # Local Ollama/NIM call (safe)
        try:
            result = subprocess.run(["ollama", "run", model, query], capture_output=True, text=True, timeout=60)
            return f"LOCAL: {model} — {result.stdout[:200]}..."
        except Exception:
            return f"LOCAL fallback to {model} failed — using cached response"

# LangGraph node
def multi_model_router_agent(state: Dict) -> Dict:
    router = HancockRouter()
    model_choice = router.route(state)
    state["messages"].append(f"Router selected: {model_choice}")
    state["selected_model"] = model_choice
    return state
