"""Local 0AI runner for an Ollama-backed defensive CLI workflow."""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
import json
import os
from pathlib import Path
import shutil
import sys
from typing import Any
from urllib.parse import urlparse

import requests

try:
    from openai import OpenAI
except ImportError:  # pragma: no cover - exercised only when dependency is absent
    OpenAI = None  # type: ignore


SAFE_SYSTEM_BASE = (
    "You are 0AI, a local defensive cybersecurity assistant used only for "
    "authorized work. Stay within legal and authorized scope. Refuse requests "
    "for unauthorized exploitation, payloads, credential theft, persistence, "
    "or evasion instructions. Prioritize OSINT analysis, threat triage, secure "
    "coding, detections, hardening, reporting, and remediation. When data is "
    "missing, say so plainly and do not invent observations."
)

MODE_GUIDANCE = {
    "auto": "Balance defensive analysis, reporting, and remediation guidance.",
    "osint": (
        "Focus on public-source analysis, indicator correlation, confidence, "
        "and next defensive actions."
    ),
    "soc": (
        "Focus on alert triage, detections, containment, and incident response."
    ),
    "code": "Focus on secure implementation, review, and defensive automation.",
    "ciso": "Focus on executive risk translation, prioritization, and governance.",
}

SUPPORTED_MODES = tuple(MODE_GUIDANCE.keys())


@dataclass(slots=True)
class VerifyResult:
    """Verification state for the local 0AI workflow."""

    base_url: str
    api_base_url: str
    model: str
    modelfile_path: str
    modelfile_exists: bool
    ollama_binary: bool
    live_probe: str
    model_available: bool
    warnings: list[str] = field(default_factory=list)

    @property
    def ready(self) -> bool:
        return bool(self.base_url and self.model and self.modelfile_exists)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["ready"] = self.ready
        return payload


def _normalize_base_url(base_url: str | None = None) -> str:
    configured = (base_url or os.getenv("OLLAMA_BASE_URL") or "http://localhost:11434").strip()
    return configured.rstrip("/")


def _api_base_url(base_url: str | None = None) -> str:
    return _normalize_base_url(base_url) + "/v1"


def _default_model(model: str | None = None) -> str:
    configured = (
        model
        or os.getenv("ZEROAI_MODEL")
        or os.getenv("OLLAMA_MODEL")
        or "0ai"
    )
    return configured.strip()


def _default_mode(mode: str | None = None) -> str:
    configured = (mode or os.getenv("ZEROAI_DEFAULT_MODE") or "osint").strip().lower()
    return configured if configured in MODE_GUIDANCE else "osint"


def _modelfile_path() -> Path:
    return Path(__file__).resolve().with_name("Modelfile.0ai")


def _build_system_prompt(mode: str) -> str:
    normalized = mode.strip().lower()
    guidance = MODE_GUIDANCE.get(normalized, MODE_GUIDANCE["auto"])
    return f"{SAFE_SYSTEM_BASE} {guidance}"


def _make_client(base_url: str) -> OpenAI:
    if OpenAI is None:
        raise RuntimeError(
            "The 'openai' package is required to run the local 0AI CLI."
        )
    return OpenAI(base_url=_api_base_url(base_url), api_key="ollama")


def verify_local_setup(
    *, base_url: str | None = None, model: str | None = None
) -> VerifyResult:
    """Verify the local scaffold and probe Ollama when available."""
    resolved_base_url = _normalize_base_url(base_url)
    parsed = urlparse(resolved_base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("OLLAMA_BASE_URL must be a valid http(s) URL.")

    resolved_model = _default_model(model)
    modelfile = _modelfile_path()
    warnings: list[str] = []
    live_probe = "unavailable"
    model_available = False

    if not modelfile.exists():
        warnings.append("Modelfile.0ai is missing from the repository root.")

    tags_url = f"{resolved_base_url}/api/tags"
    try:
        response = requests.get(tags_url, timeout=2)
        response.raise_for_status()
        live_probe = "ok"
        tags = response.json().get("models", [])
        model_names = {
            str(entry.get("name", "")).strip()
            for entry in tags
            if isinstance(entry, dict)
        }
        model_available = resolved_model in model_names
        if not model_available:
            warnings.append(
                f"Ollama is reachable but model '{resolved_model}' is not installed."
            )
    except requests.RequestException:
        warnings.append(
            "Ollama was not reachable for a live probe; static workflow checks only."
        )

    return VerifyResult(
        base_url=resolved_base_url,
        api_base_url=_api_base_url(resolved_base_url),
        model=resolved_model,
        modelfile_path=str(modelfile),
        modelfile_exists=modelfile.exists(),
        ollama_binary=shutil.which("ollama") is not None,
        live_probe=live_probe,
        model_available=model_available,
        warnings=warnings,
    )


def _chat_once(
    *,
    client: OpenAI,
    model: str,
    mode: str,
    user_input: str,
    history: list[dict[str, str]] | None = None,
    stream: bool = False,
) -> str:
    messages: list[dict[str, str]] = [{"role": "system", "content": _build_system_prompt(mode)}]
    if history:
        messages.extend(history)
    messages.append({"role": "user", "content": user_input})

    response = client.chat.completions.create(
        model=model,
        messages=messages,
        temperature=0.3,
        max_tokens=1024,
        stream=stream,
    )
    if not stream:
        return response.choices[0].message.content or ""

    chunks: list[str] = []
    for chunk in response:
        delta = chunk.choices[0].delta.content or ""
        if delta:
            print(delta, end="", flush=True)
            chunks.append(delta)
    print()
    return "".join(chunks)


def _interactive_loop(*, base_url: str, model: str, mode: str) -> int:
    client = _make_client(base_url)
    history: list[dict[str, str]] = []
    print(
        "\n".join(
            [
                "0AI local defensive CLI",
                f"Base URL: {_api_base_url(base_url)}",
                f"Model: {model}",
                f"Mode: {mode}",
                "Commands: /mode <auto|osint|soc|code|ciso> | /clear | /verify | /exit",
                "",
            ]
        )
    )

    while True:
        try:
            user_input = input(f"[0ai:{mode}] > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting 0AI.")
            return 0

        if not user_input:
            continue
        if user_input in {"/exit", "/quit"}:
            print("Exiting 0AI.")
            return 0
        if user_input == "/clear":
            history = []
            print("Conversation cleared.")
            continue
        if user_input == "/verify":
            print(json.dumps(verify_local_setup(base_url=base_url, model=model).to_dict(), indent=2))
            continue
        if user_input.startswith("/mode "):
            requested_mode = user_input[6:].strip().lower()
            if requested_mode not in SUPPORTED_MODES:
                print(f"Unsupported mode: {requested_mode}")
                continue
            mode = requested_mode
            history = []
            print(f"Mode set to {mode}.")
            continue

        try:
            answer = _chat_once(
                client=client,
                model=model,
                mode=mode,
                user_input=user_input,
                history=history,
                stream=True,
            )
        except Exception as exc:  # pragma: no cover - depends on local Ollama runtime
            print(f"0AI request failed: {exc}")
            return 1

        history.extend(
            [
                {"role": "user", "content": user_input},
                {"role": "assistant", "content": answer},
            ]
        )
        if len(history) > 16:
            history = history[-16:]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ai_agent.py",
        description="Run the local 0AI defensive CLI against Ollama.",
    )
    parser.add_argument("--task", help="Run a single prompt and print the response.")
    parser.add_argument(
        "--mode",
        default=_default_mode(None),
        choices=SUPPORTED_MODES,
        help="Prompt profile to use for the conversation.",
    )
    parser.add_argument(
        "--model",
        default=_default_model(None),
        help="Override the Ollama model name. Defaults to ZEROAI_MODEL, OLLAMA_MODEL, or '0ai'.",
    )
    parser.add_argument(
        "--base-url",
        default=_normalize_base_url(None),
        help="Override the Ollama base URL. Defaults to OLLAMA_BASE_URL or http://localhost:11434.",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Validate the local 0AI scaffold and probe Ollama when available.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit verification output as JSON when used with --verify.",
    )
    args = parser.parse_args(argv)

    if args.verify:
        result = verify_local_setup(base_url=args.base_url, model=args.model)
        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            print(f"0AI verify | ready={str(result.ready).lower()} | live_probe={result.live_probe}")
            print(f"Base URL: {result.base_url}")
            print(f"API Base URL: {result.api_base_url}")
            print(f"Model: {result.model}")
            print(f"Modelfile: {result.modelfile_path}")
            print(f"Ollama binary: {str(result.ollama_binary).lower()}")
            if result.warnings:
                print("Warnings:")
                for warning in result.warnings:
                    print(f"- {warning}")
        return 0 if result.ready else 1

    try:
        client = _make_client(args.base_url)
    except Exception as exc:
        print(
            "Failed to initialize the 0AI client. Install dependencies and ensure Ollama "
            f"is configured. Details: {exc}"
        )
        return 1

    if args.task:
        try:
            answer = _chat_once(
                client=client,
                model=args.model,
                mode=args.mode,
                user_input=args.task,
                stream=False,
            )
        except Exception as exc:  # pragma: no cover - depends on local Ollama runtime
            print(f"0AI request failed: {exc}")
            return 1
        print(answer)
        return 0

    return _interactive_loop(base_url=args.base_url, model=args.model, mode=args.mode)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
