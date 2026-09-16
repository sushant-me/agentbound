"""Command-line interface: `agentbound scan <path> [--json]`."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

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

# Ordered worst-first. `--fail-on` compares a finding's rank against the
# threshold's, so `--fail-on high` also fails on `critical`.
_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _at_or_above(finding, threshold: str) -> bool:
    """Whether a finding is severe enough to fail the run.

    An unknown severity on either side counts as failing, in the loud direction:
    a rule that starts emitting a novel severity should not silently stop gating
    a build. `none` never fails.
    """
    if threshold == "none":
        return False
    try:
        return _SEVERITY_ORDER.index(finding.severity) <= _SEVERITY_ORDER.index(
            threshold
        )
    except ValueError:
        return True


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
    scan_p.add_argument(
        "--fail-on",
        choices=_SEVERITY_ORDER + ["none"],
        default="low",
        help=(
            "lowest severity that produces a non-zero exit (default: low, so "
            "any finding fails - the original contract). Use `high` for a CI "
            "gate that ignores the residual findings this tool reports at "
            "`low` and `medium`, or `none` to report without ever failing."
        ),
    )

    args = parser.parse_args(argv)

    if args.cmd == "scan":
        target = Path(args.path)
        if not target.exists():
            # Without this, a typo'd path scanned nothing, found nothing, and
            # exited 0 - a clean bill of health for a directory that does not
            # exist. Exit 2 keeps it distinguishable from a real clean scan.
            sys.stderr.write(f"agentbound: no such path: {args.path}\n")
            return 2
        findings = scan(target)
        if args.json:
            json.dump([f.to_dict() for f in findings], sys.stdout, indent=2)
            sys.stdout.write("\n")
        else:
            sys.stdout.write(_human(findings))
        # Exit 1 when a finding meets the threshold, so CI can fail a build.
        # The default is `low`, which preserves "exit 1 when findings exist"
        # for every caller that does not pass the flag.
        return 1 if any(_at_or_above(f, args.fail_on) for f in findings) else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
