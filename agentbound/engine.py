"""Scan engine: walk a directory, run file rules, then project rules."""

from __future__ import annotations

from pathlib import Path

from .findings import Finding
from .rules import FILE_RULES, PROJECT_RULES

# Directory names to skip while walking (deps/build/vendor noise).
_SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__", "build", "dist",
    "_deps", "site-packages", ".mypy_cache", ".pytest_cache", ".tox",
}

# Only run text rules on these extensions (cheap pre-filter).
_SCAN_EXTS = {".py", ".yml", ".yaml"}


def _iter_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        yield path


def scan(root: str | Path) -> list[Finding]:
    root = Path(root)
    files: dict[str, str] = {}
    for path in _iter_files(root):
        if path.suffix not in _SCAN_EXTS:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            rel = str(path.relative_to(root))
        except ValueError:
            rel = str(path)
        files[rel] = text

    findings: list[Finding] = []
    for path, text in files.items():
        for rule in FILE_RULES:
            findings.extend(rule(path, text))

    for rule in PROJECT_RULES:
        findings.extend(rule(files))

    findings.sort(key=lambda f: (f.path, f.line, f.rule))
    return findings
