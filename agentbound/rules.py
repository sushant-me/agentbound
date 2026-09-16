"""Detection rules for agent tool-boundary bugs.

Rules come in two shapes:
  * file rules     — `fn(path, text) -> list[Finding]`, one file at a time.
  * project rules  — `fn(files: dict[str, str]) -> list[Finding]`, cross-file.

Every rule below is grounded in a specific, disclosed finding; the docstring
names the CVE/finding it generalises and the framework it first fired on.
"""

from __future__ import annotations

import re

from .findings import Finding

# Framework-owned tool names that a third-party tool must never be able to
# displace. Extend this list as new frameworks are added.
FRAMEWORK_TOOL_WATCHLIST = [
    "set_model_response",  # google/adk-python — final structured answer tool
    "google_search",       # google/adk-js — built-in search tool
    "transfer_to_agent",   # google/adk-python — reserved transfer tool
]

_RESERVED_NAME_RE = re.compile(
    r"(?P<assign>[A-Za-z_]\w*reserved[A-Za-z_]*)\s*=\s*"
    r"(?:frozenset|set|list|tuple)\s*\(\s*\{",
    re.IGNORECASE,
)
_STRING_LITERAL_RE = re.compile(r"[\"']([^\"']+)[\"']")
_IDENTIFIER_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\.\s*__name__\b|\b([A-Za-z_]\w*)\b")


def _find_reserved_sets(text: str) -> list[tuple[int, str, set[str]]]:
    """Return (line, assign_name, member_names) for every reserved-name set.

    Member names are the union of string literals and bare identifiers found
    inside the literal. `foo.__name__` is normalised to `foo`.
    """
    results: list[tuple[int, str, set[str]]] = []
    for m in _RESERVED_NAME_RE.finditer(text):
        start = m.end() - 1  # position of the opening '{'
        depth = 0
        end = start
        for i in range(start, len(text)):
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        body = text[start:end]
        names: set[str] = set(_STRING_LITERAL_RE.findall(body))
        for a, b in _IDENTIFIER_RE.findall(body):
            names.add(a or b)
        line = text.count("\n", 0, m.start()) + 1
        results.append((line, m.group("assign"), names))
    return results


def rule_tool_reserved_name_shadowing(files: dict[str, str]) -> list[Finding]:
    """PROJECT rule — generalises google/adk-python `set_model_response` shadowing.

    Flags a reserved-name set that omits a framework-owned tool name that the
    framework nevertheless registers (detected as a `def <name>(`), letting a
    third-party tool advertising that name displace the framework's own.
    """
    findings: list[Finding] = []
    reserved_by_file: dict[str, list[tuple[int, str, set[str]]]] = {}
    for path, text in files.items():
        if path.endswith(".py"):
            # Only sets that reserve *tool names* are in scope. Other reserved
            # sets (path segments, human-in-the-loop function names, etc.) are
            # a different mechanism and must not be flagged.
            sets = [
                (line, assign, members)
                for line, assign, members in _find_reserved_sets(text)
                if "tool" in assign.lower()
            ]
            if sets:
                reserved_by_file[path] = sets

    if not reserved_by_file:
        return findings

    # A watchlist name is "registered by the framework" if any Python file
    # defines a function/class of that name.
    all_py = "\n".join(t for p, t in files.items() if p.endswith(".py"))
    for name in FRAMEWORK_TOOL_WATCHLIST:
        if not re.search(rf"\bdef\s+{re.escape(name)}\s*\(", all_py):
            continue
        for path, sets in reserved_by_file.items():
            for line, assign, members in sets:
                if name in members:
                    continue
                findings.append(
                    Finding(
                        rule="tool-reserved-name-shadowing",
                        severity="high",
                        path=path,
                        line=line,
                        message=(
                            f"framework-owned tool '{name}' is registered "
                            f"(def {name}) but missing from reserved set "
                            f"'{assign}'; a third-party tool advertising "
                            f"'{name}' can displace the framework's own tool"
                        ),
                    )
                )
    return findings


_INSPECT_SIGNATURE_RE = re.compile(
    r"\bsignature\s*=\s*inspect\.signature\(\s*(?P<arg>[A-Za-z_]\w*)\s*\)"
)
_DICT_FILTER_RE = re.compile(
    r"\{\s*[A-Za-z_]\w*\s*:\s*[A-Za-z_]\w*\s+for\s+[A-Za-z_]\w*\s*,\s*[A-Za-z_]\w*\s+"
    r"in\s+.*?\bif\s+[A-Za-z_]\w*\s+in\s+valid_params"
)


def rule_confirmation_gate_fails_open(path: str, text: str) -> list[Finding]:
    """FILE rule — generalises google/adk-python `require_confirmation` fail-open.

    The confirmation predicate's own signature is used to filter the tool-call
    arguments (`inspect.signature(target)` + `if k in valid_params`), so a
    generic predicate is called with its defaults and returns `False`, opening
    the gate. `FunctionTool` filters by the *tool's* signature and fails closed.
    """
    findings: list[Finding] = []
    if not path.endswith(".py"):
        return findings
    if "signature.parameters" not in text:
        return findings
    for m in _INSPECT_SIGNATURE_RE.finditer(text):
        # Skip when the inspected object is a fixed class/module (e.g.
        # inspect.signature(SomeClass)); only flag when it is a callable
        # parameter such as `target` / `predicate`.
        if not _DICT_FILTER_RE.search(text):
            continue
        line = text.count("\n", 0, m.start()) + 1
        findings.append(
            Finding(
                rule="confirmation-gate-fails-open",
                severity="high",
                path=path,
                line=line,
                message=(
                    f"arguments filtered by the predicate's own signature "
                    f"(inspect.signature({m.group('arg')})); a generic "
                    "confirmation predicate is called with its defaults and "
                    "returns False, opening the gate (fails open)"
                ),
            )
        )
    return findings


_ISSUES_EVENT_RE = re.compile(
    r"(?:github\.event_name\s*==\s*['\"]issues['\"]|event_name\s*==\s*['\"]issues['\"])"
)


_TOOL_DICT_ASSIGN_RE = re.compile(
    r"(?:self\.)?(?P<dict>[A-Za-z_]\w*)\s*\[\s*(?P<key>[^\]]+?)\s*\]\s*=\s*"
)
_DUP_WARN_RE = re.compile(
    r"(?:logging|logger|self\._?logger)\.warning\(\s*[\"']([^\"']*[Dd]uplicate[^\"']*)[\"']"
)


def rule_tool_dict_last_wins(path: str, text: str) -> list[Finding]:
    """FILE rule — generalises the last-wins overwrite in adk-python llm_request.py.

    A tool-name -> tool dict is assigned unconditionally (`tools_dict[name] =
    tool`) while a duplicate is only reported with `logging.warning`, so a later
    tool silently shadows an earlier one of the same name (last-wins).
    """
    findings: list[Finding] = []
    if not path.endswith(".py"):
        return findings
    if not _DUP_WARN_RE.search(text):
        return findings
    for m in _TOOL_DICT_ASSIGN_RE.finditer(text):
        if "tool" not in m.group("dict").lower():
            continue
        line = text.count("\n", 0, m.start()) + 1
        findings.append(
            Finding(
                rule="tool-dict-last-wins",
                severity="medium",
                path=path,
                line=line,
                message=(
                    f"tool dict '{m.group('dict')}' assigned unconditionally on "
                    f"a name key; duplicates are only logged (logging.warning), "
                    "so a later tool silently shadows an earlier one (last-wins)"
                ),
            )
        )
    return findings


_TS_TOOLDICT_ASSIGN_RE = re.compile(
    r"(?:request\.llmRequest\.)?toolsDict\s*\[\s*[^\]]+?\s*\]\s*=\s*"
)
_TS_DUP_GUARD_EXEMPT_RE = re.compile(
    r"!\s*(?:isInModelTool|isBuiltInTool|isInModel|isBuiltIn)\s*\("
)


def rule_ts_builtin_tool_silent_replace(path: str, text: str) -> list[Finding]:
    """FILE rule — generalises google/adk-js `google_search` shadowing.

    A callable tool registers `toolsDict[name] = this` after a duplicate-name
    throw that is gated on `!isInModelTool(...)`. That guard exempts in-model
    (built-in) tools, so a third-party tool advertising a built-in name (e.g.
    `google_search`) silently replaces it instead of erroring.
    """
    findings: list[Finding] = []
    if not path.endswith((".ts", ".tsx", ".js", ".jsx")):
        return findings
    if "Duplicate tool name" not in text and "Duplicate" not in text:
        return findings
    if not _TS_DUP_GUARD_EXEMPT_RE.search(text):
        return findings
    for m in _TS_TOOLDICT_ASSIGN_RE.finditer(text):
        line = text.count("\n", 0, m.start()) + 1
        findings.append(
            Finding(
                rule="tool-built-in-silent-replace",
                severity="high",
                path=path,
                line=line,
                message=(
                    "a callable tool silently replaces an in-model/built-in "
                    "tool: the duplicate-name throw is gated on "
                    "!isInModelTool(...), so a third-party tool advertising a "
                    "built-in name (e.g. google_search) registers without error"
                ),
            )
        )
    return findings


def rule_ci_agent_missing_author_association(path: str, text: str) -> list[Finding]:
    """FILE rule — generalises GoogleCloudPlatform/vertex-ai-creative-studio.

    A workflow that gates other arms on `author_association` has an
    `issues`-triggered arm with no such check, so any GitHub user opening an
    issue reaches that job.

    The check is not always the right remedy: for a triage or deduplication
    agent, running on every new issue is the feature, and gating it on
    `author_association` would disable it. What matters is that the triggering
    text is attacker-controlled, so if the job hands it to an agent that holds
    secrets or an OIDC token, the exposure is indirect prompt injection rather
    than an authorisation gap. The message says that instead of prescribing the
    check, which in this arm would often be wrong.
    """
    findings: list[Finding] = []
    if not (path.endswith((".yml", ".yaml"))):
        return findings
    if "author_association" not in text:
        return findings
    for m in _ISSUES_EVENT_RE.finditer(text):
        line_start = text.rfind("\n", 0, m.start()) + 1
        line_end = text.find("\n", m.end())
        if line_end == -1:
            line_end = len(text)
        line_text = text[line_start:line_end]
        if "author_association" in line_text:
            continue
        line = text.count("\n", 0, m.start()) + 1
        findings.append(
            Finding(
                rule="ci-agent-missing-author-association",
                severity="critical",
                path=path,
                line=line,
                message=(
                    "issue-triggered dispatch arm has no author_association "
                    "check while other arms in this workflow have one, so any "
                    "GitHub user can reach this job. If the job runs an agent, "
                    "the issue text is attacker-controlled input (prompt "
                    "injection) and the agent may hold secrets or an OIDC "
                    "token. Adding the check may not be the right fix if the "
                    "trigger is meant to be public - constrain what the agent "
                    "can reach instead."
                ),
            )
        )
    return findings


# --- Go / Java: in-model tools that never occupy their name ------------------
# google/adk-go and google/adk-java register in-model built-ins (google_search,
# google_maps, ...) by appending straight to the request's config tools, without
# registering the name in the tool map. The duplicate-name guard therefore never
# sees them, so a third-party MCP tool of the same name is accepted and wins
# dispatch.  Confirmed in both ports by local reproduction.

_GO_SETTOOL_RE = re.compile(r"\bsetTool\s*\(")
_GO_NAME_OCCUPIED_RE = re.compile(r"\breq\.Tools\s*\[|\bPackTool\s*\(")


def rule_go_inmodel_tool_unoccupied(path: str, text: str) -> list[Finding]:
    """GO rule — generalises google/adk-go `google_search` shadowing."""
    findings: list[Finding] = []
    if not path.endswith(".go"):
        return findings
    if "ProcessRequest" not in text or not _GO_SETTOOL_RE.search(text):
        return findings
    if _GO_NAME_OCCUPIED_RE.search(text):
        return findings
    line = text.count("\n", 0, text.find("setTool(")) + 1
    findings.append(
        Finding(
            rule="tool-inmodel-name-unoccupied",
            severity="high",
            path=path,
            line=line,
            message=(
                "in-model tool calls setTool() (appends to config tools) but never "
                "registers its name in req.Tools, so a server-provided tool of the "
                "same name can shadow it (google_search class)"
            ),
        )
    )
    return findings


_JAVA_PROCESS_RE = re.compile(r"\bprocessLlmRequest\s*\(")
_JAVA_CONFIG_TOOLS_RE = re.compile(r"configBuilder\.tools\s*\(|\.tools\s*\(")
_JAVA_APPEND_RE = re.compile(r"\bappendTools\s*\(")


def rule_java_inmodel_tool_unoccupied(path: str, text: str) -> list[Finding]:
    """JAVA rule — generalises google/adk-java `google_search` shadowing."""
    findings: list[Finding] = []
    if not path.endswith(".java"):
        return findings
    base = path.replace("\\", "/").rsplit("/", 1)[-1]
    # Skip tests and orchestration classes (they append tools on behalf of others).
    if "/test/" in path or base.endswith("Test.java") or "Flow" in base:
        return findings
    if not _JAVA_PROCESS_RE.search(text):
        return findings
    if not _JAVA_CONFIG_TOOLS_RE.search(text):
        return findings
    if _JAVA_APPEND_RE.search(text):
        return findings
    line = text.count("\n", 0, text.find("processLlmRequest")) + 1
    findings.append(
        Finding(
            rule="tool-inmodel-name-unoccupied",
            severity="high",
            path=path,
            line=line,
            message=(
                "processLlmRequest() appends to config tools without appendTools(), "
                "so the tool never occupies its name and a server-provided tool of "
                "the same name can shadow it (google_search class)"
            ),
        )
    )
    return findings


FILE_RULES = [
    rule_confirmation_gate_fails_open,
    rule_ci_agent_missing_author_association,
    rule_tool_dict_last_wins,
    rule_ts_builtin_tool_silent_replace,
    rule_go_inmodel_tool_unoccupied,
    rule_java_inmodel_tool_unoccupied,
]

PROJECT_RULES = [
    rule_tool_reserved_name_shadowing,
]
