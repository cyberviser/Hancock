#!/usr/bin/env python3
import atheris
import sys
from typing import TypedDict
from langgraph.graph import END, StateGraph


class AgentState(TypedDict):
    prompt: str


def process_prompt(state: AgentState) -> AgentState:
    return {"prompt": state["prompt"]}


@atheris.instrument_func
def test_fuzz_langgraph(data):
    fdp = atheris.FuzzedDataProvider(data)
    prompt = fdp.ConsumeUnicodeNoSurrogates(1024)

    graph = StateGraph(AgentState)
    graph.add_node("process_prompt", process_prompt)
    graph.set_entry_point("process_prompt")
    graph.add_edge("process_prompt", END)

    app = graph.compile()
    result = app.invoke({"prompt": prompt})

    assert isinstance(result, dict)
    assert "prompt" in result
if __name__ == "__main__":
    atheris.Setup(sys.argv, test_fuzz_langgraph)
    atheris.Fuzz()
