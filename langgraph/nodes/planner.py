from __future__ import annotations


class Planner:
    def __init__(self):
        self._generate = None

    def set_generator(self, generator):
        self._generate = generator

    def run(self, state):
        prompt = (
            f"Mode: {state.mode}\nGoal: {state.goal}\nHistory: {state.history}\n"
            "Produce a safe, authorized step plan as bullets."
        )
        if self._generate:
            plan_text = self._generate(prompt, mode="plan")
            state.plan = [line.strip("- ").strip() for line in str(plan_text).splitlines() if line.strip()]
        else:
            state.plan = ["Validate scope and collect passive intelligence", "Propose low-risk recon steps"]
        return state


planner = Planner()
run = planner.run
set_generator = planner.set_generator
