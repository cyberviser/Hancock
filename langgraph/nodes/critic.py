from __future__ import annotations


class Critic:
    def __init__(self):
        self._generate = None

    def set_generator(self, generator):
        self._generate = generator

    def run(self, state):
        if self._generate:
            state.risk = self._generate(
                f"Evaluate safety/accuracy and false positives. Findings: {state.findings}",
                mode="critic",
            )
        else:
            state.risk = "Low operational risk: recommendation-only mode (execute=False)."
        return state


critic = Critic()
run = critic.run
set_generator = critic.set_generator
