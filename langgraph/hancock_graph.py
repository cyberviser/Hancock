from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from langgraph.nodes import critic, executor, planner, recon, reporter
from security.authz import Scope
from security.intent_guard import verify_intent_and_scope

try:
    from langgraph.graph import END, StateGraph
except Exception:  # pragma: no cover - allows repository to run without optional dependency
    END = "__end__"
    StateGraph = None


class HancockState(BaseModel):
    user_id: str
    scopes: list[Scope] = Field(default_factory=list)
    mode: str
    goal: str
    history: list[Any] = Field(default_factory=list)
    plan: list[str] | None = None
    actions: list[dict[str, Any]] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    report: str | None = None
    risk: str | None = None


def _fallback_invoke(state: HancockState) -> HancockState:
    state = planner.run(state)
    state = recon.run(state)
    state = executor.run(state)
    state = critic.run(state)
    state = reporter.run(state)
    return state


def build_graph():
    if StateGraph is None:
        return None

    graph = StateGraph(HancockState)
    graph.add_node("planner", planner.run)
    graph.add_node("recon", recon.run)
    graph.add_node("executor", executor.run)
    graph.add_node("critic", critic.run)
    graph.add_node("reporter", reporter.run)

    graph.set_entry_point("planner")
    graph.add_edge("planner", "recon")
    graph.add_edge("recon", "executor")
    graph.add_edge("executor", "critic")
    graph.add_edge("critic", "reporter")
    graph.add_edge("reporter", END)
    return graph.compile()


def run_hancock_loop(state: HancockState, llm_generate=None) -> HancockState:
    verify_intent_and_scope(state.goal, state.mode, state.scopes)

    if llm_generate is not None:
        planner.set_generator(llm_generate)
        recon.set_generator(llm_generate)
        critic.set_generator(llm_generate)
        reporter.set_generator(llm_generate)

    compiled = build_graph()
    if compiled is None:
        return _fallback_invoke(state)
    return compiled.invoke(state)
