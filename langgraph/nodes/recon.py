from __future__ import annotations

from tools.catalog import list_tools


class Recon:
    def __init__(self):
        self._generate = None

    def set_generator(self, generator):
        self._generate = generator

    def run(self, state):
        tools = list_tools(mode=state.mode, scopes=state.scopes, stage="recon")
        if self._generate:
            suggestions = self._generate(
                f"Plan: {state.plan}\nSuggest low-risk authorized recon actions using tools: {tools}",
                mode="recon",
            )
        else:
            suggestions = [f"Review passive recon options with {tool}" for tool in tools]

        state.actions.append({"stage": "recon", "suggestions": suggestions})
        return state


recon = Recon()
run = recon.run
set_generator = recon.set_generator
