"""Command-line interface for the Hancock Python SDK."""

from __future__ import annotations
import os
import sys
import argparse
from hancock_client import HancockClient, MODELS


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="hancock",
        description="Hancock AI Security Agent — Python CLI",
    )
    parser.add_argument("--mode",  default="security", choices=["security", "code"],
                        help="Interaction mode (default: security)")
    parser.add_argument("--task",  help="One-shot: task or question to answer")
    parser.add_argument("--model", default="mistral-7b",
                        help=f"Model alias. Options: {', '.join(MODELS)}")
    args = parser.parse_args()

    try:
        client = HancockClient(model=args.model)
    except ValueError as e:
        print(f"❌  {e}")
        sys.exit(1)

    if args.task:
        result = client.code(args.task) if args.mode == "code" else client.ask(args.task)
        print(result)
        return

    # Interactive
    print(f"""
╔══════════════════════════════════════════════════════════╗
║   HANCOCK  —  AI Cybersecurity Agent  (Python client)   ║
║   Powered by NVIDIA NIM + CyberViser                    ║
╚══════════════════════════════════════════════════════════╝
Mode: {args.mode} | Model: {args.model}
Commands: /mode security | /mode code | /model <alias> | /exit
Aliases:  {' | '.join(MODELS)}
""")

    mode = args.mode
    history = []

    while True:
        try:
            user_input = input(f"[{mode}] > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            break

        if not user_input:
            continue
        if user_input in ("/exit", "/quit"):
            print("Goodbye.")
            break
        if user_input.startswith("/mode "):
            mode = user_input[6:].strip()
            print(f"Switched to {mode} mode\n")
            history = []
            continue
        if user_input.startswith("/model "):
            alias = user_input[7:].strip()
            client.model = MODELS.get(alias, alias)
            print(f"Model set to {client.model}\n")
            continue

        try:
            if mode == "code":
                answer = client.code(user_input)
            else:
                answer = client.chat(user_input, history=history, mode=mode)
                history.append({"role": "user",      "content": user_input})
                history.append({"role": "assistant",  "content": answer})
                if len(history) > 20:
                    history = history[-20:]
            print(f"\nHancock > {answer}\n")
        except Exception as e:
            print(f"\n⚠️  Error: {e}\n")


if __name__ == "__main__":
    main()
