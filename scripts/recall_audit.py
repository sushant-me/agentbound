#!/usr/bin/env python3
"""Recall audit — does every rule still fire on the code it was derived from?

Precision audits ask "does it report things that are not real". This asks the
opposite question, which nothing else in the repository asks: **does each rule
still detect the class it was written for?** A rule that quietly stopped
matching would look exactly like a rule with no false positives, which is why
recall has to be measured rather than assumed.

Point it at a *local clone* of each origin repository. It reads the committed
tree out of git rather than the working copy, and that is the point of the
script:

    A working copy may be on any branch. For several of the repositories below
    it is on the branch that *fixes* the very thing the rule detects, so the
    rule is correctly silent and reads as a false negative. Pinning to a ref
    removes that whole class of confusion.

Usage:

    git clone --filter=blob:none https://github.com/google/adk-python /tmp/adk-python
    python scripts/recall_audit.py /tmp/adk-python origin/main

`langchain-typesafe` is a package inside a monorepo. The clone is sparse to keep
it small, but the audit still walks the committed tree, so expect this origin to
be slow:

    git clone --filter=blob:none --sparse https://github.com/langchain-ai/langchain /tmp/langchain-typesafe
    (cd /tmp/langchain-typesafe && git sparse-checkout set libs/partners/typesafe)
    python scripts/recall_audit.py /tmp/langchain-typesafe origin/master

Prints one line per repository naming the rules that fired. Every rule in the
table is expected to fire on at least one origin, so an empty result or a
missing rule name is the signal to investigate.

This is a manual tool, not a CI job: it needs clones of other projects, which a
test run should not fetch. `tests/` covers each rule against an inline fixture,
which catches a rule that stops matching its *fixture* but not one that stops
matching reality.
"""

from __future__ import annotations

import collections
import subprocess
import sys

from agentbound.rules import FILE_RULES, PROJECT_RULES

EXTS = (".py", ".ts", ".tsx", ".js", ".jsx", ".go", ".java", ".yml", ".yaml")

# (local clone dir name, rule it was derived from, what that rule must find there)
#
# A list, not a dict: two rules come from adk-python and a dict keyed on the repo
# would silently drop one of them.
ORIGINS: list[tuple[str, str, str, str]] = [
    # (local clone dir, rule function, rule id it emits, what it must find there)
    #
    # A list, not a dict: two rules come from adk-python and a dict keyed on the
    # repo would silently drop one of them. The function name is carried as well
    # as the id so `tests/` can check that every implemented rule is declared
    # here - comparing the two namespaces is what the first version got wrong.
    ("adk-python", "rule_tool_reserved_name_shadowing", "tool-reserved-name-shadowing",
     "set_model_response left out of _RESERVED_TOOL_NAMES"),
    ("adk-python", "rule_tool_dict_last_wins", "tool-dict-last-wins",
     "tools_dict assigned under a logged duplicate"),
    ("adk-python", "rule_confirmation_gate_fails_open", "confirmation-gate-fails-open",
     "an inspect.signature filter that opens the gate for an unrecognised predicate"),
    ("langchain-typesafe", "rule_guard_name_normalization_asymmetry",
     "guard-name-normalization-asymmetry",
     "a tool-name guard that strips the configured names but tests the incoming name raw"),
    ("adk-go", "rule_go_inmodel_tool_unoccupied", "tool-inmodel-name-unoccupied",
     "setTool() without registering the name"),
    ("adk-java", "rule_java_inmodel_tool_unoccupied", "tool-inmodel-name-unoccupied",
     "processLlmRequest without appendTools"),
    ("adk-js", "rule_ts_builtin_tool_silent_replace", "tool-built-in-silent-replace",
     "a callable replacing an in-model tool"),
    ("gemini-cli", "rule_ci_agent_untrusted_issue_content", "ci-agent-untrusted-issue-content",
     "issue text reaching an agent"),
    ("gemini-cli", "rule_ci_agent_missing_author_association", "ci-agent-missing-author-association",
     "an issues arm with no author gate"),
    ("vertex-ai-creative-studio", "rule_ci_agent_missing_author_association",
     "ci-agent-missing-author-association", "the dispatch workflow the rule generalises"),
    ("claude-code", "rule_ci_agent_write_scope_on_untrusted_trigger",
     "ci-agent-write-scope-on-untrusted-trigger",
     "an agent with write scope reachable by any author"),
]


def files_at(repo: str, ref: str) -> dict[str, str]:
    names = subprocess.run(
        ["git", "-C", repo, "ls-tree", "-r", ref, "--name-only"],
        capture_output=True, text=True, check=True,
    ).stdout.split()
    out: dict[str, str] = {}
    for name in names:
        if not name.endswith(EXTS):
            continue
        blob = subprocess.run(
            ["git", "-C", repo, "show", f"{ref}:{name}"],
            capture_output=True, text=True,
        )
        if blob.returncode == 0:
            out[name] = blob.stdout
    return out


def audit(repo: str, ref: str) -> tuple[int, collections.Counter[str]]:
    files = files_at(repo, ref)
    hits: collections.Counter[str] = collections.Counter()
    for path, text in files.items():
        for rule in FILE_RULES:
            try:
                for finding in rule(path, text):
                    hits[finding.rule] += 1
            except Exception as exc:  # a rule that raises is not a passing rule
                hits[f"ERROR:{rule.__name__}:{type(exc).__name__}"] += 1
    for rule in PROJECT_RULES:
        try:
            for finding in rule(files):
                hits[finding.rule] += 1
        except Exception as exc:
            hits[f"ERROR:{rule.__name__}:{type(exc).__name__}"] += 1
    return len(files), hits


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__.strip().splitlines()[0])
        print("usage: recall_audit.py <path-to-local-clone> <git-ref>")
        return 2
    repo, ref = argv[1], argv[2]
    label = repo.rstrip("/").split("/")[-1]
    try:
        count, hits = audit(repo, ref)
    except subprocess.CalledProcessError as exc:
        print(f"{label}: git failed — {exc}")
        return 2
    fired = {k: v for k, v in hits.items() if not k.startswith("ERROR:")}
    errors = {k: v for k, v in hits.items() if k.startswith("ERROR:")}
    print(f"{label}@{ref}: {count} files")
    print(f"  fired: {fired if fired else 'NOTHING — check this'}")
    if errors:
        print(f"  rule errors: {errors}")
    return 1 if errors or not fired else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
