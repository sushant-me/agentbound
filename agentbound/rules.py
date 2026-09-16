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


# A call to a reusable workflow. The agent may live in the called file, so this
# counts as evidence one is reachable from here even when none is inlined.
# Covers the local form (`./.github/workflows/x.yml`) and the cross-repo form
# (`owner/repo/.github/workflows/x.yml@ref`).
_REUSABLE_WORKFLOW_RE = re.compile(
    r"uses:\s*['\"]?(?:\./\.github/workflows/|[\w.-]+/[\w.-]+/\.github/workflows/)",
    re.IGNORECASE,
)

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

    Two conditions were added after this rule produced a critical-severity false
    positive against a repository that only labels issues:

    * The file must show that an agent is reachable from it - by running an agent
      action, or by calling a reusable workflow that may. The origin case does
      the latter: `gemini-dispatch.yml` runs no agent itself, it delegates to
      `./.github/workflows/gemini-triage.yml`. Requiring the action in this file
      would have lost the finding the rule was written for, which is why the
      reusable call counts.

    A second idea was tried and rejected: requiring `author_association` to be
    compared against OWNER/MEMBER/COLLABORATOR, on the theory that a privilege
    gate is distinguishable from a labelling signal. The false-positive file
    contains that list too, in a `github-script` deciding whether to apply a
    label, so the test does not separate the two cases. Only the condition that
    was checked against both is implemented.
    """
    findings: list[Finding] = []
    if not (path.endswith((".yml", ".yaml"))):
        return findings
    if "author_association" not in text:
        return findings
    if not (
        _AI_AGENT_ACTION_RE.search(text) or _REUSABLE_WORKFLOW_RE.search(text)
    ):
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


# --- CI: untrusted issue text reaching an AI agent ---------------------------
#
# The trigger is not the control. A job that *fetches* issue content - a cron
# running `gh issue list --json ...body`, or a step reading
# `github.event.issue.body` - handles text written by anyone whether or not any
# trigger arm is gated. The author_association rule above keys on triggers and
# therefore misses the scheduled variant entirely; this one keys on the flow.

_AI_AGENT_ACTION_RE = re.compile(
    r"uses:\s*[\"']?(?:"
    r"google-github-actions/run-gemini-cli"
    r"|anthropics/claude-code-action"
    r"|anthropics/claude-code-base-action"
    r"|openai/codex-action"
    r"|google-gemini/gemini-cli-action"
    r")",
    re.IGNORECASE,
)

# (label, pattern, requires_event). `requires_event` names the trigger that has
# to be present for the payload to exist at all: on a `schedule`-only workflow
# `github.event.issue` is empty, so flagging it would be a false positive.
_UNTRUSTED_ISSUE_INPUTS: list[tuple[str, re.Pattern[str], str | None]] = [
    (
        "the issue body from the event payload",
        re.compile(r"github\.event\.issue\.body"),
        "issues",
    ),
    (
        "comment text from the event payload",
        re.compile(r"github\.event\.comment\.body"),
        "issue_comment",
    ),
    (
        "issue text fetched with `gh issue list --json ...body`",
        re.compile(r"gh\s+issue\s+list[^\n]*--json[^\n]*\bbody\b"),
        None,
    ),
    (
        "pull-request text fetched with `gh pr view --json ...body`",
        re.compile(r"gh\s+pr\s+view[^\n]*--json[^\n]*\bbody\b"),
        None,
    ),
]


_ON_BLOCK_RE = re.compile(r"^['\"]?on['\"]?\s*:(.*)$", re.MULTILINE)

# Events whose payload text is authored by whoever opened the issue, comment or
# review - i.e. by anyone, on a public repository.
_UNTRUSTED_AUTHOR_EVENTS = frozenset({
    "issues",
    "issue_comment",
    "pull_request_review",
    "pull_request_review_comment",
})

# A job-level `write` grant. `id-token: write` is deliberately absent: it mints
# the OIDC token the agent actions use to authenticate, which is the *safe*
# replacement for a static key, and pairing it with a write scope is normal.
_WRITE_SCOPE_RE = re.compile(
    r"^[ \t]*(?P<scope>contents|issues|pull-requests|actions|packages|"
    r"deployments|security-events|statuses|checks|discussions)"
    r"[ \t]*:[ \t]*write[ \t]*$",
    re.MULTILINE,
)
_PERMISSIONS_KEY_RE = re.compile(r"^([ \t]*)permissions[ \t]*:([ \t]*)(.*)$")
_PERMISSIONS_INLINE_RE = re.compile(
    r"^[ \t]*permissions[ \t]*:[ \t]*\{(?P<body>[^}]*)\}"
)


def _iter_write_scopes(text: str) -> list[tuple[int, str]]:
    """`(line, scope)` for each real `write` grant in the workflow.

    A `scope: write` line grants something only as a child of a `permissions:`
    **mapping**. The identical two lines appear as an action *input*:

        - uses: open-security-tools/ost-simple-sts@<sha>
          with:
            # Linking an upstream issue to a fork branch requires both
            # permissions on one token.
            permissions: |
              contents: write
              issues: write

    That is a credential broker being asked for a narrow, short-lived token -
    the opposite of a grant on the job. Reading it as one flagged
    `astral-sh/uv`'s `issue-triage.yml`, whose top level is `permissions: {}`
    and whose jobs are all read-only. It is the shape of repository that can
    least afford a false positive, because it is the one already doing the work.

    Skipped: a block scalar (`|`, `>`) or any other value on the
    `permissions:` line, a scope line shallower than its key, and a scope line
    with no `permissions:` above it at all. The inline form
    `permissions: {contents: write}` is handled, since missing a real grant is
    worse than the extra branch.
    """
    found: list[tuple[int, str]] = []
    perm_indent: int | None = None
    for number, raw in enumerate(text.split("\n"), start=1):
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())

        inline = _PERMISSIONS_INLINE_RE.match(line)
        if inline:
            for part in inline.group("body").split(","):
                if _WRITE_SCOPE_RE.match(part.strip()):
                    found.append((number, part.split(":")[0].strip()))
            perm_indent = None
            continue

        key = _PERMISSIONS_KEY_RE.match(line)
        if key:
            # Only a bare `permissions:` opens a mapping of scopes. A block
            # scalar, `{}` or any inline value opens nothing.
            perm_indent = len(key.group(1)) if not key.group(3).strip() else None
            continue

        if perm_indent is None:
            continue
        if indent <= perm_indent:
            perm_indent = None  # left the block
            continue
        scope = _WRITE_SCOPE_RE.match(line)
        if scope:
            found.append((number, scope.group("scope")))
    return found

# Agent actions, and whether each refuses a run actor without write permission.
#
# A tuple names the input that opts users in past that check, so a workflow that
# sets it is reachable by an author who does not have write access. `None` means
# the action performs no actor check at all, which leaves the trigger as the only
# thing between an untrusted author and the agent.
#
# Every entry was read from the action's own source, not inferred:
#   claude-code-action      checks the run actor's permission; its suite asserts
#                           "should NOT bypass permission check when
#                           allowed_non_write_users is empty"
#   codex-action            src/checkActorPermissions.ts calls
#                           getCollaboratorPermissionLevel and requires
#                           admin/write/maintain; `allow-users` opts others in
#   run-gemini-cli          516-line composite action, no actor check anywhere
#   gemini-cli-action       composite action, no actor check anywhere
#   claude-code-base-action no actor check and no such input; it is the runner
#                           the wrapper adds the check around
#
# An action not listed here is unknown and is treated as reachable, so a new
# action is loud rather than silently assumed safe.
#
# Each entry names the inputs that opt a user in past that check. Whether the
# input is *present* is not the question - whether it *carries a value* is. Both
# actions say so in their own source:
#
#   claude-code-action  test/permissions.test.ts, "should NOT bypass permission
#                       check when allowed_non_write_users is empty", asserts
#                       checkWritePermissions(..., "", true) === false
#   codex-action        src/checkActorPermissions.ts trims the input and gates
#                       the override on `allowUsersSpec.length > 0`
#
# So `allowed_non_write_users: ""` leaves the check in place. That is the safe
# configuration, and people write it deliberately - `redpanda-data/console` sets
# it empty next to the comment "Only org members with write access can trigger
# via @claude mentions". Matching on presence alone reported that workflow, and
# its `contents: write`, as reachable by anyone.
_AGENT_ACTIONS: dict[str, tuple[str, ...] | None] = {
    "anthropics/claude-code-action": ("allowed_non_write_users",),
    "openai/codex-action": ("allow-users",),
    "google-github-actions/run-gemini-cli": None,
    "google-gemini/gemini-cli-action": None,
    "anthropics/claude-code-base-action": None,
}


def _input_opts_in_any_author(text: str, name: str) -> bool:
    """Whether an input lets an author *without* write access drive the agent.

    Three things are not an opt-out, and each was being counted as one:

    * **Empty.** `allowed_non_write_users: ""` leaves the check in place. Both
      actions say so - claude-code-action asserts
      `checkWritePermissions(..., "", true) === false`, and codex-action gates on
      `allowUsersSpec.length > 0`.
    * **A literal list.** `allow-users: "MathiasGruber"` bypasses the check for
      that account and no other. An arbitrary GitHub user is not that account, so
      the class this rule is about does not apply. The maintainer named them.
    * **A value that is only a comment.**

    What does reach anyone is a `*` and a value the *event* computes.
    `${{ github.event.issue.user.login }}` is the author of the very issue the
    attacker just opened - that is the CVE-2026-44246 vector - and
    `${{ github.actor }}` is whoever triggered the run. A `${{ inputs.x }}` is
    unknown rather than literal, so it stays in the loud direction.
    """
    pattern = re.compile(
        r"^[ \t]*" + re.escape(name) + r"[ \t]*:[ \t]*(?P<value>[^\n#]*)",
        re.MULTILINE,
    )
    for match in pattern.finditer(text):
        value = match.group("value").strip().strip("\"'").strip()
        if not value:
            continue
        if "${{" in value or any(p.strip() == "*" for p in value.split(",")):
            return True
    return False


def _untrusted_author_reaches_agent(text: str) -> bool:
    """Whether a workflow lets an author *without* write access drive the agent.

    This is the precondition both CI-agent rules need and neither can read off
    the trigger. An action that checks the actor's permission refuses an
    untrusted author, so a workflow that never opts out is relying on that gate
    - the safe configuration, and not what these rules are looking for. An
    action with no such check leaves the trigger as the only barrier.
    """
    lowered = text.lower()
    used = [name for name in _AGENT_ACTIONS if name in lowered]
    if not used:
        # Unrecognised action: cannot show it gates, so do not assume it does.
        return bool(_AI_AGENT_ACTION_RE.search(text))
    for name in used:
        opt_outs = _AGENT_ACTIONS[name]
        if opt_outs is None:
            return True
        if any(_input_opts_in_any_author(text, n) for n in opt_outs):
            return True
    return False


# --- job scoping -------------------------------------------------------------
# The CI-agent rules below ask a question about "the workflow", but the unit that
# carries a trigger, a permission grant and an `if:` gate is the **job**. A
# workflow with two agent jobs - one public by design, one gated - answers
# differently per job, and a file-scoped answer attributes the public job's
# precondition to the gated one.
#
# Found by running the rules against nnU-Net's hardened `issue-agent.yml` (the
# CVE-2026-44246 fix). That file has an `auto-triage` job reachable by anyone and
# an `on-demand` job gated on commenter `author_association`; every finding that
# landed inside the second job was wrong, because the gate it prescribes is
# already there. The first job's findings were left alone: they are real, just
# severe for the design.

_JOBS_KEY_RE = re.compile(r"^['\"]?jobs['\"]?[ \t]*:[ \t]*$", re.MULTILINE)
# Job IDs are the only keys at exactly two spaces under `jobs:`; a deeper key has
# a space where the identifier must start, so this cannot match `runs-on:` at
# four. Scanned only after the `jobs:` line, so `on:`'s two-space children
# (`issues:`) are never mistaken for jobs.
_JOB_KEY_RE = re.compile(r"^  ([A-Za-z0-9_-]+)[ \t]*:[ \t]*$", re.MULTILINE)
_STEPS_KEY_RE = re.compile(r"^[ \t]+steps[ \t]*:[ \t]*$", re.MULTILINE)

# `author_association` compared against the associations that imply write or
# review trust. Both orders occur in the wild:
#   github.event.comment.author_association == 'OWNER'
#   contains(fromJSON('["OWNER",...]'), github.event.comment.author_association)
_TRUST_GATE_EQ_RE = re.compile(
    r"author_association\s*==\s*['\"]?(?:OWNER|MEMBER|COLLABORATOR)\b",
    re.IGNORECASE,
)
_TRUST_GATE_CONTAINS_RE = re.compile(
    r"contains\s*\(\s*fromJSON\s*\("
    r"(?=[^)]*(?:OWNER|MEMBER|COLLABORATOR))[^)]*\)"
    r"[^)]*author_association",
    re.IGNORECASE | re.DOTALL,
)


def _iter_jobs(text: str) -> list[tuple[str, int, int, str]]:
    """Split a workflow into `(job_id, first_line, last_line, job_text)`.

    Best effort. An unparseable file yields `[]`, and callers must read "no job
    found" as "cannot show a gate" - never as "gated".
    """
    key = _JOBS_KEY_RE.search(text)
    if key is None:
        return []
    body = text[key.end():]
    first_body_line = text.count("\n", 0, key.end()) + 1
    marks = list(_JOB_KEY_RE.finditer(body))
    jobs: list[tuple[str, int, int, str]] = []
    for index, mark in enumerate(marks):
        stop = marks[index + 1].start() if index + 1 < len(marks) else len(body)
        start_line = first_body_line + body.count("\n", 0, mark.start())
        end_line = first_body_line + body.count("\n", 0, stop) - 1
        jobs.append((mark.group(1), start_line, end_line, body[mark.start():stop]))
    return jobs


def _job_containing(
    jobs: list[tuple[str, int, int, str]], line: int
) -> tuple[str, int, int, str] | None:
    for job in jobs:
        if job[1] <= line <= job[2]:
            return job
    return None


def _job_gates_on_author_association(job_text: str) -> bool:
    """Whether the job's own condition requires a trusted author association.

    Only the job header is searched - everything before its `steps:` - so a gate
    that merely appears somewhere later in a script cannot suppress a finding.
    """
    steps = _STEPS_KEY_RE.search(job_text)
    header = job_text[: steps.start()] if steps else job_text
    return bool(
        _TRUST_GATE_EQ_RE.search(header) or _TRUST_GATE_CONTAINS_RE.search(header)
    )


# --- what the agent is actually allowed to call ------------------------------
# A job-level `write` scope says what the *job* may do; it does not say what the
# agent may do. An agent step that carries a tool allowlist is constrained
# separately, and the later non-agent steps that post results inherit the job's
# credentials regardless. nnU-Net's fix for CVE-2026-44246 is exactly this: the
# write scope stayed (a later step posts the comment) while `gh issue comment`
# and `gh issue edit` were removed from the agent's allowlist.

# The specific flags that restrict which tools an agent may call, and the value
# they carry. `claude_args` is deliberately NOT a pattern on its own: it is a
# container for arbitrary CLI flags, and `claude_args: "--model ..."` says
# nothing about tools. Matching it made a model-selection flag read as a tool
# restriction and dropped `anthropics/claude-code`'s own workflow - this rule's
# origin - from high to low. The inner `--allowedTools` is found wherever it is
# nested, so requiring the flag loses nothing.
#
# Only quoted forms are read; a YAML block scalar under `claude_args: |` is not
# matched, which leaves the agent unconstrained-looking and keeps the full
# severity. That is the conservative direction on purpose.
_TOOL_ALLOWLIST_RE = re.compile(
    r"(?:--allowedTools|--allowed-tools|allowed_tools|allowedTools)"
    r"[ \t]*[:=]?[ \t]*[\"']([^\"']{4,})[\"']",
    re.IGNORECASE,
)

# Commands by which an agent could change the repository rather than describe it.
# `gh issue view` and `gh search issues` are deliberately absent: reading is what
# the hardened configuration still needs.
# One `Bash(...)` entry in an allowlist. The inner text is a command prefix that
# ends at Claude Code's `:*` wildcard.
_BASH_ENTRY_RE = re.compile(r"Bash\((?P<prefix>[^)]*)\)")

# A repository-mutating command, split into the verb and whatever the grant says
# after it. `rest` empty means the grant is unbounded - it stops at the verb.
_MUTATING_VERB_RE = re.compile(
    r"^(?P<verb>gh\s+(?:issue|pr|label|release|workflow|repo|run)\s+"
    r"(?:comment|edit|close|reopen|merge|delete|create|add|remove|transfer|lock)"
    r"|gh\s+api"
    r"|git\s+push)\b(?P<rest>.*)$",
    re.IGNORECASE,
)


def _agent_mutation_reach(job_text: str) -> str:
    """How far the agent's mutating tools reach: one of four answers.

    A `Bash(...)` entry in an allowlist is a command **prefix**: the grant ends at
    Claude Code's `:*` wildcard, so whatever precedes the wildcard is what the
    grant is bounded to.

        Bash(gh issue edit:*)                      -> unbounded
        Bash(gh issue edit 1234:*)                 -> bounded to that issue
        Bash(gh issue edit ${{ inputs.issue }}:*)  -> bounded to the input

    That distinction is the whole of Layer 1 in `docs/mitigations.md`, and it is
    the one thing the permissions-based rule cannot see: two workflows can grant
    an identical `issues: write` and be completely different in what the agent may
    point it at. One of them is the recommendation; the other is the shape this
    project exists to describe.

    Returns `unknown` when no allowlist was readable - callers must read that as
    "cannot show the agent is constrained", never as constrained.
    """
    allowlists = _TOOL_ALLOWLIST_RE.findall(job_text)
    if not allowlists:
        return "unknown"
    reach: set[str] = set()
    for allowlist in allowlists:
        for match in _BASH_ENTRY_RE.finditer(allowlist):
            prefix = re.sub(r":\*$", "", match.group("prefix").strip()).strip()
            verb = _MUTATING_VERB_RE.match(prefix)
            if verb:
                reach.add("bounded" if verb.group("rest").strip() else "unbounded")
    if "unbounded" in reach:
        return "unbounded"
    if "bounded" in reach:
        return "bounded"
    return "none"


def _agent_has_repo_write_tool(job_text: str) -> bool | None:
    """Whether the agent steps' allowlists grant a repository-mutating command.

    `None` means no allowlist was readable, and callers must treat that as
    "cannot show the agent is constrained" - never as constrained. Kept as the
    boolean view of `_agent_mutation_reach` for callers that only need yes/no.
    """
    reach = _agent_mutation_reach(job_text)
    if reach == "unknown":
        return None
    return reach in ("bounded", "unbounded")


def _job_runs_the_agent(job_text: str) -> bool:
    """Whether this job is the one that runs (or delegates) the agent.

    A job-level `write` grant is a token *that job's steps* receive. An agent in
    a different job never holds it, so "an untrusted author can steer an agent
    that holds write access" is not true of it.

    That separation is the recommended architecture, not an accident. The common
    shape is a read-only job that gathers with the agent, then a second job that
    applies labels or posts the comment:

        gather-labels   agent, contents: read
        apply-labels    no agent, issues: write

    Reporting `apply-labels` because the *file* contains an agent was half of
    every high-severity finding this rule produced across a 197-file corpus.
    A reusable-workflow call counts, because the agent may be one file away and
    this file cannot see it.
    """
    return bool(
        _AI_AGENT_ACTION_RE.search(job_text)
        or _REUSABLE_WORKFLOW_RE.search(job_text)
    )


def _job_reachable_by_untrusted_author(job_text: str) -> bool:
    """Whether *this job's* agent can be driven by an author without write access.

    Scoped to the job, because the opt-out is an input on the agent **step**: a
    sibling job setting the wildcard says nothing about a job that never did.
    `OpenNHP/opennhp` is the case - one job sets `allowed_non_write_users: '*'`
    and is read-only, a second holds `contents: write` and never opts out, and
    only the first is reachable by anyone.

    A reusable-workflow call with no inline agent action cannot be judged from
    this file, so it stays in the loud direction. `evcc-io/evcc` is why: its
    caller job holds `contents: write`, and its *called* workflow - a different
    file - sets `allowed_non_write_users: '*'`. Reading the caller alone, going
    quiet here would have been a false negative on the one case where the
    indirection resolves to reachable.
    """
    if _REUSABLE_WORKFLOW_RE.search(job_text) and not _AI_AGENT_ACTION_RE.search(
        job_text
    ):
        return True
    return _untrusted_author_reaches_agent(job_text)


def rule_ci_agent_write_scope_on_untrusted_trigger(
    path: str, text: str
) -> list[Finding]:
    """FILE rule.

    A workflow runs an AI agent action, is triggered by an event whose text
    anyone can author, grants the job a repository **write** scope, **and**
    explicitly opts out of the action's write-permission check for that
    trigger. The agent can then be steered by an untrusted author and has
    something to do with the result.

    This is deliberately narrower than it could be, and it is a separate rule
    from `ci-agent-untrusted-issue-content` rather than an extension of it,
    because the two detect different things:

    * that rule matches the untrusted text **appearing in the workflow** - a
      direct data flow, visible in the file.
    * this rule matches the untrusted text **never appearing**, because the
      agent fetches the issue itself at runtime with the token the job hands it.
      No pattern over the YAML can see that content.

    The fourth condition is the one that was added after this rule produced a
    false positive in the wild. An open trigger plus a write scope is not
    sufficient: `anthropics/claude-code-action` checks the run actor's write
    permission and refuses without it, so a workflow that never mentions
    `allowed_non_write_users` is relying on that gate - the safe configuration,
    not this. Requiring the explicit opt-out is the difference between flagging
    workflows that disabled their gate and flagging workflows that got their
    permissions right.

    The cost is recall, taken knowingly: an agent action whose gate has another
    name, or none at all, will not match. Read-only configurations are also
    excluded, since an agent reading issue text with `contents: read` is the
    pattern done right. Whether a match is otherwise acceptable is still a
    human's call - a triage bot that labels issues on purpose matches too.

    A fifth condition scales the severity rather than the match. A job-level
    `write` scope says what the *job* may do, not what the *agent* may do: an
    agent step carrying a tool allowlist is constrained separately, while the
    later non-agent steps that post results inherit the job's token anyway. When
    that allowlist grants no repository-mutating command, the agent cannot
    exercise the scope and the finding is reported at `low` with the residual
    spelled out instead of at `high`. nnU-Net's fix for CVE-2026-44246 is the
    case: the write scope stayed because a later step posts the comment, while
    `gh issue comment` and `gh issue edit` left the agent's allowlist. The match
    is kept because a steered agent can still write a file that a later step
    posts - dropping it would be indistinguishable from the rule breaking.
    """
    findings: list[Finding] = []
    if not path.endswith((".yml", ".yaml")):
        return findings
    if not (
        _AI_AGENT_ACTION_RE.search(text) or _REUSABLE_WORKFLOW_RE.search(text)
    ):
        return findings
    if not (_workflow_triggers(text) & _UNTRUSTED_AUTHOR_EVENTS):
        return findings
    if not (
        _untrusted_author_reaches_agent(text) or _REUSABLE_WORKFLOW_RE.search(text)
    ):
        # A file whose only agent is one call away still counts: the per-job
        # check below decides reachability, and `_job_reachable_by_untrusted_author`
        # keeps a reusable call in the loud direction.
        return findings

    jobs = _iter_jobs(text)
    for line, scope in _iter_write_scopes(text):
        job = _job_containing(jobs, line)
        if job is not None and not _job_runs_the_agent(job[3]):
            # The grant belongs to a different job than the agent's. Its token
            # never reaches the model, which is the point of splitting them.
            continue
        if job is not None and not _job_reachable_by_untrusted_author(job[3]):
            # The opt-out is an input on the agent step, so it is per **job** as
            # well. A sibling job setting `allowed_non_write_users: '*'` says
            # nothing about this one, whose agent still refuses an actor without
            # write access. `OpenNHP/opennhp` is the case: one job sets the
            # wildcard and is read-only, a second holds `contents: write` and
            # never opts out. Only the first is reachable by anyone.
            continue
        if job is not None and _job_gates_on_author_association(job[3]):
            # The message below prescribes "gate the job on author_association";
            # this job already does. An untrusted author cannot reach it, so the
            # write scope is not steerable by one.
            continue
        # A constrained agent cannot exercise the scope itself. That is not the
        # absence of a finding - a steered agent can still write a file a later
        # step posts - so it is reported at the severity the residual deserves
        # rather than dropped, which is the one thing that would make this
        # indistinguishable from a rule that had stopped working.
        reach = _agent_mutation_reach(job[3]) if job is not None else "unknown"
        if reach == "none":
            findings.append(
                Finding(
                    rule="ci-agent-write-scope-on-untrusted-trigger",
                    severity="low",
                    path=path,
                    line=line,
                    message=(
                        f"an AI agent action runs in a job triggered by "
                        f"issue/comment/review events and the job grants "
                        f"`{scope}: write`, but the agent's own tool allowlist "
                        "grants no repository-mutating command, so the agent "
                        "cannot exercise that scope - the grant exists for the "
                        "workflow's later, non-agent steps. The residual is "
                        "narrower than the grant suggests: a steered agent can "
                        "still write a file that a later step posts, so an "
                        "injection can publish content or apply a label on the "
                        "issue the attacker controls. Confirm the later steps "
                        "take their target and arguments from the event rather "
                        "than from the agent's output."
                    ),
                )
            )
            continue
        if reach == "bounded":
            # The agent keeps the tool but the grant names a target, so it
            # cannot be pointed at a different issue or ref. That is Layer 1 of
            # `docs/mitigations.md`, and it is a real bound - but the pattern is
            # a prefix match on a command string, not a parser, so this is
            # reported rather than passed over in silence.
            findings.append(
                Finding(
                    rule="ci-agent-write-scope-on-untrusted-trigger",
                    severity="medium",
                    path=path,
                    line=line,
                    message=(
                        f"an AI agent action runs in a job triggered by "
                        f"issue/comment/review events and the job grants "
                        f"`{scope}: write`. The agent's mutating tool patterns "
                        "name their target rather than matching any argument, so "
                        "a steered agent cannot be redirected to another issue or "
                        "ref - the grant is bounded. Treat this as a review item "
                        "rather than a finding to suppress: the bound is a prefix "
                        "match on a command string, not a parse, so confirm the "
                        "argument is taken from the event and not from the "
                        "agent's own output."
                    ),
                )
            )
            continue
            continue
        findings.append(
            Finding(
                rule="ci-agent-write-scope-on-untrusted-trigger",
                severity="high",
                path=path,
                line=line,
                message=(
                    f"an AI agent action runs in a job triggered by "
                    f"issue/comment/review events - text anyone can author - "
                    f"and the job grants `{scope}: write`. An untrusted author "
                    "can therefore steer an agent that holds write access, and "
                    "the workflow need not mention the text at all: the agent "
                    "can fetch the issue itself with the token it is given, "
                    "which no scan of this file can see. Either drop the write "
                    "scope (read-only plus a separate credentialed step is the "
                    "usual fix), or gate the job on author_association and keep "
                    "untrusted text out of the instruction channel."
                ),
            )
        )
    return findings


def _workflow_triggers(text: str) -> set[str]:
    """Event names from the workflow's `on:` block, best effort.

    Handles the three shapes GitHub accepts: a scalar (`on: push`), an inline
    list (`on: [push, issues]`), and a mapping of event -> config. Used to avoid
    treating `github.event.issue.*` as untrusted input in a workflow whose
    triggers never populate it, which is the whole point of not repeating the
    mistake the author_association rule makes.
    """
    match = _ON_BLOCK_RE.search(text)
    if not match:
        return set()

    inline = match.group(1).strip()
    if inline:
        return {part.strip().strip("'\"") for part in inline.strip("[]").split(",") if part.strip()}

    # Mapping form: collect keys at the first indent level deeper than `on:`.
    lines = text[match.end():].split("\n")
    indent = None
    events: set[str] = set()
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        current = len(line) - len(line.lstrip())
        if current == 0:
            break
        if indent is None:
            indent = current
        if current < indent:
            break
        if current == indent:
            key = line.strip().split(":")[0].strip().strip("'\"")
            if key:
                events.add(key)
    return events


def rule_ci_agent_untrusted_issue_content(path: str, text: str) -> list[Finding]:
    """FILE rule.

    A workflow runs an AI agent action and also consumes issue or comment text
    written by anyone. Because the text is pulled into the job, gating the
    trigger does not remove the exposure, so this fires on the data flow rather
    than on `author_association`.
    """
    findings: list[Finding] = []
    if not path.endswith((".yml", ".yaml")):
        return findings
    if not (
        _AI_AGENT_ACTION_RE.search(text) or _REUSABLE_WORKFLOW_RE.search(text)
    ):
        return findings
    if not (
        _untrusted_author_reaches_agent(text) or _REUSABLE_WORKFLOW_RE.search(text)
    ):
        return findings

    triggers = _workflow_triggers(text)
    jobs = _iter_jobs(text)

    seen: set[tuple[int, str]] = set()
    for label, pattern, requires_event in _UNTRUSTED_ISSUE_INPUTS:
        if requires_event is not None and requires_event not in triggers:
            # The expression is present but this workflow never fires on the
            # event that populates it, so it is not an input path.
            continue
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            job = _job_containing(jobs, line)
            if job is not None and not _job_reachable_by_untrusted_author(job[3]):
                # Untrusted text in a job whose agent refuses a non-write actor
                # is not an input path, whatever a sibling job opts into.
                continue
            if job is not None and _job_gates_on_author_association(job[3]):
                # The text is authored by whoever triggers the job, and only a
                # trusted association can trigger this one. The untrusted-author
                # premise does not hold here, whatever the file does elsewhere.
                continue
            if (line, label) in seen:
                continue
            seen.add((line, label))
            findings.append(
                Finding(
                    rule="ci-agent-untrusted-issue-content",
                    severity="high",
                    path=path,
                    line=line,
                    message=(
                        f"an AI agent action runs in a job that consumes {label}. "
                        "Issue and comment text is written by anyone, so treat it "
                        "as untrusted input; gating the trigger does not help when "
                        "the job fetches the content itself. Harden the agent "
                        "instead - do not enable trust-workspace mode for "
                        "untrusted data, minimise token permissions and tools, "
                        "avoid long-lived credentials, and keep the text out of "
                        "the instruction channel."
                    ),
                )
            )
    return findings


FILE_RULES = [
    rule_confirmation_gate_fails_open,
    rule_ci_agent_missing_author_association,
    rule_ci_agent_untrusted_issue_content,
    rule_ci_agent_write_scope_on_untrusted_trigger,
    rule_tool_dict_last_wins,
    rule_ts_builtin_tool_silent_replace,
    rule_go_inmodel_tool_unoccupied,
    rule_java_inmodel_tool_unoccupied,
]

PROJECT_RULES = [
    rule_tool_reserved_name_shadowing,
]
