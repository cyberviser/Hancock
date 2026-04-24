from __future__ import annotations

from sandbox.runner import run_tool_safely
from security.intent_guard import gate_actions


class Executor:
    def run(self, state):
        approved = gate_actions(state.actions, state.mode, state.scopes)
        executed = []
        for action in approved:
            if action.get("execute", False):
                result = run_tool_safely(action["tool"], action.get("args", []), action.get("kwargs", {}))
                executed.append({"action": action, "result": result})
        state.findings.extend(executed)
        return state


executor = Executor()
run = executor.run
