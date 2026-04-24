from __future__ import annotations

import shlex
import subprocess

from sandbox.profiles import TOOL_PROFILES


def run_tool_safely(tool: str, args: list, kwargs: dict) -> dict:
    del kwargs
    profile = TOOL_PROFILES.get(tool)
    if not profile:
        return {"status": "blocked", "reason": "tool not whitelisted"}

    docker_cmd = [
        "docker",
        "run",
        "--rm",
        "--network",
        profile["network"],
        "--cpus",
        profile.get("cpus", "1"),
        "--memory",
        profile.get("memory", "512m"),
        "--read-only",
        "--pids-limit",
        "128",
        "--security-opt",
        "no-new-privileges",
        "--cap-drop",
        "ALL",
    ]

    for volume in profile.get("volumes", []):
        docker_cmd.extend(["-v", volume])

    docker_cmd.append(profile["image"])
    entry_cmd = profile["entrypoint"] + " " + " ".join(shlex.quote(str(arg)) for arg in args)

    try:
        result = subprocess.run(
            docker_cmd + shlex.split(entry_cmd),
            capture_output=True,
            text=True,
            timeout=profile.get("timeout", 120),
            check=False,
        )
        return {
            "status": "ok",
            "stdout": result.stdout[-20000:],
            "stderr": result.stderr[-8000:],
            "rc": result.returncode,
        }
    except Exception as exc:  # defensive return for runtime/dependency failures
        return {"status": "error", "error": str(exc)}
