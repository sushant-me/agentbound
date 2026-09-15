"""Command-line interface: `agentbound scan <path> [--json]`."""

from __future__ import annotations

import argparse
import json
import sys

from .engine import scan
from . import __version__

_SEVERITY_COLOR = {
    "critical": "\033[1;31m",
    "high": "\033[31m",
    "medium": "\033[33m",
    "low": "\033[36m",
    "info": "\033[37m",
}
_RESET = "\033[0m"


def _human(findings) -> str:
    if not findings:
        return "No findings.\n"
    lines = []
    for f in findings:
        color = _SEVERITY_COLOR.get(f.severity, "")
        lines.append(
            f"{color}{f.severity.upper():8}{_RESET} "
            f"{f.path}:{f.line}  {f.rule}\n"
            f"            {f.message}"
        )
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="agentbound",
        description="Static detector for AI-agent tool-boundary bugs.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    scan_p = sub.add_parser("scan", help="scan a repository")
    scan_p.add_argument("path", help="repository path to scan")
    scan_p.add_argument("--json", action="store_true", help="emit JSON")

    args = parser.parse_args(argv)

    if args.cmd == "scan":
        findings = scan(args.path)
        if args.json:
            json.dump([f.to_dict() for f in findings], sys.stdout, indent=2)
            sys.stdout.write("\n")
        else:
            sys.stdout.write(_human(findings))
        # Exit 1 when findings exist so CI can fail a build.
        return 1 if findings else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
