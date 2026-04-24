from __future__ import annotations


class Reporter:
    def __init__(self):
        self._generate = None

    def set_generator(self, generator):
        self._generate = generator

    def run(self, state):
        if self._generate:
            state.report = self._generate(
                f"Create concise authorized-scope report. Findings: {state.findings}",
                mode="report",
            )
        else:
            state.report = "Authorized-scope report generated with no active execution actions."
        return state


reporter = Reporter()
run = reporter.run
set_generator = reporter.set_generator
