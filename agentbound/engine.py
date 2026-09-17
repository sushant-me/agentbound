"""Scan engine: walk a directory, run file rules, then project rules."""

from __future__ import annotations

from pathlib import Path

from .findings import Finding
from .masking import mask
from .rules import FILE_RULES, PROJECT_RULES

# Directory names to skip while walking (deps/build/vendor noise).
_SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "__pycache__", "build", "dist",
    "_deps", "site-packages", ".mypy_cache", ".pytest_cache", ".tox",
}

# Only run text rules on these extensions (cheap pre-filter).
_SCAN_EXTS = {".py", ".yml", ".yaml", ".ts", ".tsx", ".js", ".jsx", ".go", ".java"}

# Skip very large files (minified bundles, generated code) — they are noise
# for a static pattern detector and rarely contain hand-written tool wiring.
_MAX_FILE_BYTES = 512 * 1024


def _iter_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        yield path


def scan(root: str | Path) -> list[Finding]:
    """Scan a directory (or a single file) and return its findings.

    A single file is scanned as itself. `rglob` over a file path yields nothing,
    so without this branch `agentbound scan somefile.py` reported a clean result
    by inspecting nothing at all - the failure this whole project is about.
    Callers that need to distinguish "nothing found" from "nothing read" should
    check the path themselves; `cli.main` does, and exits 2.
    """
    root = Path(root)
    if root.is_file():
        paths = [root]
        base = root.parent
    else:
        paths = list(_iter_files(root))
        base = root

    files: dict[str, str] = {}
    for path in paths:
        if path.suffix not in _SCAN_EXTS:
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            rel = str(path.relative_to(base))
        except ValueError:
            rel = str(path)
        # Only what can execute is scanned: a rule matches behaviour, and a
        # comment or a docstring that describes an idiom is prose, not a call.
        # Masking replaces text in place, so reported line numbers are unchanged.
        files[rel] = mask(rel, text)

    findings: list[Finding] = []
    for path, text in files.items():
        for rule in FILE_RULES:
            findings.extend(rule(path, text))

    for rule in PROJECT_RULES:
        findings.extend(rule(files))

    findings.sort(key=lambda f: (f.path, f.line, f.rule))
    return findings
