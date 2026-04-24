#!/usr/bin/env python3
"""CLI for validating and rendering defensive OSINT reports."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from collectors.osint_report_builder import OSINTReportBuilder, ReportValidationError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="osint_report_cli.py",
        description="Validate a defensive OSINT report payload and render it to markdown.",
    )
    parser.add_argument(
        "input",
        help="Path to the source JSON payload.",
    )
    parser.add_argument(
        "--output",
        help="Optional path to write the rendered markdown. Defaults to stdout.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the validated report JSON instead of markdown.",
    )
    args = parser.parse_args(argv)

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Input file not found: {input_path}")
        return 1

    try:
        payload = json.loads(input_path.read_text(encoding="utf-8"))
        builder = OSINTReportBuilder()
        rendered = json.dumps(builder.build_dict(payload), indent=2) if args.json else builder.render_payload(payload)
    except json.JSONDecodeError as exc:
        print(f"Invalid JSON in {input_path}: {exc}")
        return 1
    except ReportValidationError as exc:
        print(f"Report validation failed: {exc}")
        return 1

    if args.output:
        output_path = Path(args.output)
        output_path.write_text(rendered + ("" if rendered.endswith("\n") else "\n"), encoding="utf-8")
        print(f"Wrote {output_path}")
    else:
        print(rendered, end="" if rendered.endswith("\n") else "\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
