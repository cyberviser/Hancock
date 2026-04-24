from sandbox.runner import run_tool_safely


def test_runner_blocks_unknown_tool():
    response = run_tool_safely("unknown-tool", [], {})
    assert response["status"] == "blocked"
