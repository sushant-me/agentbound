"""Unit tests using inline fixtures (self-contained, no network / no repos)."""

from agentbound.rules import (
    rule_tool_reserved_name_shadowing,
    rule_confirmation_gate_fails_open,
    rule_ci_agent_missing_author_association,
    rule_ci_agent_untrusted_issue_content,
    rule_ci_agent_write_scope_on_untrusted_trigger,
    rule_tool_dict_last_wins,
    rule_ts_builtin_tool_silent_replace,
    rule_go_inmodel_tool_unoccupied,
    rule_java_inmodel_tool_unoccupied,
    _iter_jobs,
    _job_containing,
    _job_gates_on_author_association,
    _agent_has_repo_write_tool,
    _iter_write_scopes,
    _untrusted_author_reaches_agent,
)

# --- rule 1: reserved-name shadowing ---------------------------------------

ADK_PY_RESERVED = '''\
_RESERVED_TOOL_NAMES = frozenset({
    REQUEST_EUC_FUNCTION_CALL_NAME,
    REQUEST_CONFIRMATION_FUNCTION_CALL_NAME,
    transfer_to_agent.__name__,
})

def set_model_response() -> str:
    return "ok"
'''

ADK_PY_FIXED = '''\
_RESERVED_TOOL_NAMES = frozenset({
    REQUEST_EUC_FUNCTION_CALL_NAME,
    REQUEST_CONFIRMATION_FUNCTION_CALL_NAME,
    transfer_to_agent.__name__,
    "set_model_response",
})

def set_model_response() -> str:
    return "ok"
'''


def test_reserved_name_shadowing_flags_missing_name():
    findings = rule_tool_reserved_name_shadowing({"mcp_tool.py": ADK_PY_RESERVED})
    rules = {f.rule for f in findings}
    assert "tool-reserved-name-shadowing" in rules
    # transfer_to_agent IS reserved (via .__name__), so only set_model_response.
    msgs = [f.message for f in findings]
    assert any("set_model_response" in m for m in msgs)
    assert not any("transfer_to_agent'" in m for m in msgs)


def test_reserved_name_shadowing_clean_when_name_reserved():
    findings = rule_tool_reserved_name_shadowing({"mcp_tool.py": ADK_PY_FIXED})
    assert findings == []


# --- rule 3: confirmation gate fails open -----------------------------------

ADK_PY_GATE = '''\
def _prepare_callable_args(self, target, args_to_call, tool_context=None):
    args_to_call = args.copy()
    signature = inspect.signature(target)
    valid_params = set(signature.parameters.keys())
    args_to_call = {
        k: v for k, v in args_to_call.items() if k in valid_params
    }
    return args_to_call
'''


def test_confirmation_gate_fails_open_detected():
    findings = rule_confirmation_gate_fails_open("mcp_tool.py", ADK_PY_GATE)
    assert any(f.rule == "confirmation-gate-fails-open" for f in findings)


# --- rule 2: CI dispatch missing author_association -------------------------

GEMINI_DISPATCH_YML = '''\
on:
  issues:
    types: [opened, reopened]
jobs:
  dispatch:
    if: |
      (github.event_name == 'issue_comment' && contains(github.event.comment.body, '@gemini-cli') && contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'), github.event.comment.author_association)) ||
      (github.event_name == 'issues' && contains(fromJSON('["opened","reopened"]'), github.event.action))
    steps:
      - uses: actions/checkout@v4
  triage:
    # The agent lives in the called file, as in the real dispatcher this rule
    # generalises. Without evidence an agent is reachable, the rule stays silent
    # by design, so the fixture has to carry this or the test proves nothing.
    uses: ./.github/workflows/gemini-triage.yml
'''


def test_ci_dispatch_missing_author_association_detected():
    findings = rule_ci_agent_missing_author_association(
        "gemini-dispatch.yml", GEMINI_DISPATCH_YML
    )
    assert any(f.rule == "ci-agent-missing-author-association" for f in findings)


GEMINI_DISPATCH_FIXED = GEMINI_DISPATCH_YML.replace(
    "github.event.action))",
    "github.event.action) && contains(fromJSON('[\"OWNER\",\"MEMBER\",\"COLLABORATOR\"]'), github.event.issue.author_association))",
)


def test_ci_dispatch_clean_when_author_association_added():
    findings = rule_ci_agent_missing_author_association(
        "gemini-dispatch.yml", GEMINI_DISPATCH_FIXED
    )
    assert findings == []


# --- rule 4: tool-dict last-wins --------------------------------------------

LLM_REQUEST_LAST_WINS = '''\
def add_tool(self, tool):
    if tool.name in self.tools_dict:
        logging.warning(
            "Duplicate tool name %r: the previously registered tool is"
            " shadowed and can no longer be called.",
            tool.name,
        )
    self.tools_dict[tool.name] = tool
'''


def test_tool_dict_last_wins_detected():
    findings = rule_tool_dict_last_wins("llm_request.py", LLM_REQUEST_LAST_WINS)
    assert any(f.rule == "tool-dict-last-wins" for f in findings)


def test_tool_dict_last_wins_clean_without_duplicate_warning():
    clean = LLM_REQUEST_LAST_WINS.replace('logging.warning(\n            "Duplicate', 'logging.info(\n            "Registered')
    findings = rule_tool_dict_last_wins("llm_request.py", clean)
    assert findings == []


# --- rule 5: TS built-in tool silent replace --------------------------------

BASE_TOOL_TS = '''\
async processLlmRequest({llmRequest}: ToolProcessLlmRequest): Promise<void> {
    const registered = Object.hasOwn(llmRequest.toolsDict, this.name)
      ? llmRequest.toolsDict[this.name]
      : undefined;
    if (registered && !isInModelTool(registered)) {
      throw new Error(`Duplicate tool name: ${this.name}`);
    }
    llmRequest.toolsDict[this.name] = this;
}
'''


def test_ts_builtin_tool_silent_replace_detected():
    findings = rule_ts_builtin_tool_silent_replace("base_tool.ts", BASE_TOOL_TS)
    assert any(f.rule == "tool-built-in-silent-replace" for f in findings)


def test_ts_builtin_tool_silent_replace_clean_when_guard_covers_inmodel():
    fixed = BASE_TOOL_TS.replace(
        "if (registered && !isInModelTool(registered)) {",
        "if (registered) {",
    )
    findings = rule_ts_builtin_tool_silent_replace("base_tool.ts", fixed)
    assert findings == []




# --- rule 6: Go in-model tool unoccupied ------------------------------------

GO_GOOGLE_SEARCH = '''\
func (s GoogleSearch) ProcessRequest(ctx agent.Context, req *model.LLMRequest) error {
\treturn setTool(req, &genai.Tool{
\t\tGoogleSearch: &genai.GoogleSearch{},
\t})
}
'''


def test_go_inmodel_tool_unoccupied_detected():
    findings = rule_go_inmodel_tool_unoccupied("google_search.go", GO_GOOGLE_SEARCH)
    assert any(f.rule == "tool-inmodel-name-unoccupied" for f in findings)


def test_go_clean_when_name_registered():
    clean = GO_GOOGLE_SEARCH.replace("return setTool(req,", "req.Tools[s.Name()] = s\n\treturn setTool(req,")
    assert rule_go_inmodel_tool_unoccupied("google_search.go", clean) == []


# --- rule 7: Java in-model tool unoccupied ----------------------------------

JAVA_GOOGLE_SEARCH = '''\
  public Completable processLlmRequest(
      LlmRequest.Builder llmRequestBuilder, ToolContext toolContext) {
    GenerateContentConfig.Builder configBuilder =
        llmRequestBuilder.build().config()
            .map(GenerateContentConfig::toBuilder)
            .orElseGet(GenerateContentConfig::builder);
    updatedToolsBuilder.add(Tool.builder().googleSearch(GoogleSearch.builder().build()).build());
    configBuilder.tools(updatedToolsBuilder.build());
    return Completable.complete();
  }
'''


def test_java_inmodel_tool_unoccupied_detected():
    findings = rule_java_inmodel_tool_unoccupied("GoogleSearchTool.java", JAVA_GOOGLE_SEARCH)
    assert any(f.rule == "tool-inmodel-name-unoccupied" for f in findings)


def test_java_clean_when_appendtools_used():
    clean = JAVA_GOOGLE_SEARCH.replace("return Completable.complete();",
                                       "llmRequestBuilder.appendTools(ImmutableList.of(this));\n    return Completable.complete();")
    assert rule_java_inmodel_tool_unoccupied("GoogleSearchTool.java", clean) == []


def test_ci_dispatch_message_names_the_real_risk():
    """The advice must fit the arm: for a public trigger, the risk is untrusted
    input reaching a privileged agent, not a missing authorisation check."""
    findings = rule_ci_agent_missing_author_association(
        "gemini-dispatch.yml", GEMINI_DISPATCH_YML
    )
    assert findings, "expected the public arm to still be reported"
    message = findings[0].message
    assert "attacker-controlled" in message
    assert "prompt injection" in message
    # Must not present the association check as the only remedy.
    assert "may not be the right fix" in message


# --- rule: untrusted issue text reaching an AI agent -------------------------

AGENT_WITH_ISSUE_BODY = '''\
name: triage
on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: google-github-actions/run-gemini-cli@v0
        with:
          prompt: |
            Issue title: ${{ github.event.issue.title }}
            Issue body: ${{ github.event.issue.body }}
'''

AGENT_FETCHING_ISSUES = '''\
name: scheduled triage
on:
  schedule:
    - cron: '0 * * * *'
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - run: gh issue list --repo "$REPO" --search "is:issue is:open" --json number,title,body > issues.json
      - uses: google-github-actions/run-gemini-cli@v0
        with:
          prompt: |
            Read issues.json
'''

NO_AGENT_ACTION = '''\
name: ci
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: gh issue list --json number,title,body > issues.json
'''

AGENT_WITHOUT_ISSUE_TEXT = '''\
name: docs audit
on:
  schedule:
    - cron: '0 0 * * MON'
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: google-github-actions/run-gemini-cli@v0
        with:
          prompt: Audit the documentation in this repository.
'''

AGENT_WITH_LOGINS_ONLY = '''\
name: community report
on:
  schedule:
    - cron: '0 12 * * 1'
jobs:
  report:
    runs-on: ubuntu-latest
    steps:
      - run: gh search issues --repo "$REPO" --json author,isPullRequest --limit 1000 > items.json
      - uses: google-github-actions/run-gemini-cli@v0
        with:
          prompt: Summarise the report.
'''


def test_untrusted_issue_rule_fires_on_event_payload():
    findings = rule_ci_agent_untrusted_issue_content("triage.yml", AGENT_WITH_ISSUE_BODY)
    assert any(f.rule == "ci-agent-untrusted-issue-content" for f in findings)


def test_untrusted_issue_rule_fires_on_fetched_issues_without_any_trigger():
    """The scheduled case has no trigger to gate - it must still be reported."""
    findings = rule_ci_agent_untrusted_issue_content("sched.yml", AGENT_FETCHING_ISSUES)
    assert any(f.rule == "ci-agent-untrusted-issue-content" for f in findings)
    assert all("untrusted" in f.message for f in findings)


def test_untrusted_issue_rule_needs_an_agent_action():
    assert rule_ci_agent_untrusted_issue_content("ci.yml", NO_AGENT_ACTION) == []


def test_untrusted_issue_rule_ignores_trusted_sources():
    assert rule_ci_agent_untrusted_issue_content("docs.yml", AGENT_WITHOUT_ISSUE_TEXT) == []


def test_untrusted_issue_rule_ignores_login_only_aggregation():
    """Usernames are [A-Za-z0-9-]; they cannot carry an instruction."""
    assert rule_ci_agent_untrusted_issue_content("report.yml", AGENT_WITH_LOGINS_ONLY) == []


def test_untrusted_issue_rule_ignores_non_workflow_files():
    assert rule_ci_agent_untrusted_issue_content("main.py", AGENT_WITH_ISSUE_BODY) == []


SCHEDULE_ONLY_WITH_STALE_EVENT_REF = '''\
name: scheduled dedup
on:
  schedule:
    - cron: '0 * * * *'
  workflow_dispatch:
jobs:
  dedup:
    runs-on: ubuntu-latest
    steps:
      - uses: google-github-actions/run-gemini-cli@v0
        env:
          ISSUE_BODY: '${{ github.event.issue.body }}'
        with:
          prompt: Deduplicate the issues.
'''


def test_ignores_event_payload_when_the_trigger_cannot_populate_it():
    """A schedule-only workflow never receives github.event.issue, so a leftover
    reference to it is not an input path - flagging it would be a false positive."""
    assert (
        rule_ci_agent_untrusted_issue_content(
            "sched.yml", SCHEDULE_ONLY_WITH_STALE_EVENT_REF
        )
        == []
    )


def test_fetched_issues_still_fire_on_a_schedule_only_workflow():
    """Unlike the event payload, `gh issue list` really does return content."""
    findings = rule_ci_agent_untrusted_issue_content("sched.yml", AGENT_FETCHING_ISSUES)
    assert findings, "fetched issue text must still be reported"


# --- ci-agent-write-scope-on-untrusted-trigger -----------------------------

AGENT_AUTO_TRIAGE_WITH_WRITE = '''\
name: triage
on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: write
      id-token: write
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          allowed_non_write_users: "*"
          prompt: "/triage-issue ISSUE_NUMBER: ${{ github.event.issue.number }}"
'''

AGENT_AUTO_TRIAGE_READ_ONLY = '''\
name: triage
on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: read
      id-token: write
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: "/triage-issue"
'''

AGENT_ON_PUSH_WITH_WRITE = '''\
name: docs
on:
  push:
    branches: [main]
jobs:
  docs:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: google-github-actions/run-gemini-cli@v0
        with:
          prompt: Summarise the diff.
'''

NO_AGENT_ISSUES_WITH_WRITE = '''\
name: labeler
on:
  issues:
    types: [opened]
jobs:
  label:
    runs-on: ubuntu-latest
    permissions:
      issues: write
    steps:
      - run: gh issue edit "$NUMBER" --add-label triage
'''

AGENT_ISSUES_WITH_ID_TOKEN_ONLY = '''\
name: triage
on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: "/triage-issue"
'''


def test_write_scope_on_untrusted_trigger_detected():
    findings = rule_ci_agent_write_scope_on_untrusted_trigger(
        "triage.yml", AGENT_AUTO_TRIAGE_WITH_WRITE
    )
    assert [f.rule for f in findings] == [
        "ci-agent-write-scope-on-untrusted-trigger"
    ]
    assert findings[0].line == 10  # the `issues: write` line
    assert "issues: write" in findings[0].message


def test_write_scope_rule_stays_off_a_read_only_agent():
    """An agent reading issue text with no write grant is the pattern done right."""
    assert (
        rule_ci_agent_write_scope_on_untrusted_trigger(
            "triage.yml", AGENT_AUTO_TRIAGE_READ_ONLY
        )
        == []
    )


def test_write_scope_rule_needs_an_untrusted_author_event():
    """A push-triggered agent with `contents: write` is not this exposure."""
    assert (
        rule_ci_agent_write_scope_on_untrusted_trigger(
            "docs.yml", AGENT_ON_PUSH_WITH_WRITE
        )
        == []
    )


def test_write_scope_rule_needs_an_agent_action():
    assert (
        rule_ci_agent_write_scope_on_untrusted_trigger(
            "labeler.yml", NO_AGENT_ISSUES_WITH_WRITE
        )
        == []
    )


def test_id_token_write_is_not_a_dangerous_write_scope():
    """`id-token: write` mints the OIDC token the agent authenticates with.

    It is the safe replacement for a static key and appears in hardened
    configurations, so counting it would fire on exactly the setups that got it
    right.
    """
    assert (
        rule_ci_agent_write_scope_on_untrusted_trigger(
            "triage.yml", AGENT_ISSUES_WITH_ID_TOKEN_ONLY
        )
        == []
    )


def test_write_scope_rule_ignores_non_workflow_files():
    assert (
        rule_ci_agent_write_scope_on_untrusted_trigger(
            "main.py", AGENT_AUTO_TRIAGE_WITH_WRITE
        )
        == []
    )


# The real workflow that produced the false positive: browser-use's
# .github/workflows/claude.yml. Write scopes, an open trigger, and no
# `allowed_non_write_users` - it relies on claude-code-action's default
# write-permission check, which is the safe configuration.
AGENT_WRITE_SCOPE_TRUSTING_THE_ACTION_GATE = '''\
name: Claude Code
on:
  issue_comment:
    types: [created]
  issues:
    types: [opened, assigned]
jobs:
  claude:
    if: contains(github.event.comment.body, '@claude')
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: read
      id-token: write
      discussions: write
      issues: write
    steps:
      - uses: anthropics/claude-code-action@beta
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
'''


def test_write_scope_rule_stays_off_a_workflow_trusting_the_action_gate():
    """Regression for a false positive found by scanning real repositories.

    `anthropics/claude-code-action` refuses a run actor without write permission
    unless `allowed_non_write_users` opts out - its own suite asserts "should NOT
    bypass permission check when allowed_non_write_users is empty". A workflow
    that never sets that input is relying on the gate. Firing here would flag a
    repository for getting its permissions right.
    """
    assert (
        rule_ci_agent_write_scope_on_untrusted_trigger(
            "claude.yml", AGENT_WRITE_SCOPE_TRUSTING_THE_ACTION_GATE
        )
        == []
    )


def test_write_scope_rule_fires_once_the_gate_is_disabled():
    """The same shape, plus the explicit opt-out, is the real exposure."""
    text = AGENT_WRITE_SCOPE_TRUSTING_THE_ACTION_GATE.replace(
        "          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}",
        "          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}\n"
        '          allowed_non_write_users: "*"',
    )
    findings = rule_ci_agent_write_scope_on_untrusted_trigger("claude.yml", text)
    # Two write scopes in the fixture (`discussions`, `issues`), so two findings,
    # one per grant a reader has to reconsider.
    assert [f.rule for f in findings] == [
        "ci-agent-write-scope-on-untrusted-trigger",
        "ci-agent-write-scope-on-untrusted-trigger",
    ]
    assert {f.line for f in findings} == {15, 16}


# The precondition is a property of the *action*, not the trigger, so it has to
# be tested per action. These two are the pair that matters: one action checks
# the actor's permission, the other does not.
AGENT_WITH_ISSUE_BODY_GEMINI = '''\
name: triage
on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: google-github-actions/run-gemini-cli@v0
        with:
          prompt: "Triage this: ${{ github.event.issue.body }}"
'''

AGENT_WITH_ISSUE_BODY_CLAUDE_NO_OPTOUT = '''\
name: triage
on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    permissions:
      issues: read
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          prompt: "Triage this: ${{ github.event.issue.body }}"
'''


def test_ungated_action_still_fires_on_the_data_flow():
    """`run-gemini-cli` is a composite action with no actor check.

    This is the original finding's shape. Requiring an opt-out input globally
    would have made it vanish, so the precondition has to be per action.
    """
    findings = rule_ci_agent_untrusted_issue_content(
        "triage.yml", AGENT_WITH_ISSUE_BODY_GEMINI
    )
    assert [f.rule for f in findings] == ["ci-agent-untrusted-issue-content"]


def test_gated_action_without_optout_does_not_fire_on_the_data_flow():
    """`claude-code-action` refuses a run actor without write permission.

    Same data flow as the test above, opposite verdict, because the action
    refuses the author who would supply it.
    """
    assert (
        rule_ci_agent_untrusted_issue_content(
            "triage.yml", AGENT_WITH_ISSUE_BODY_CLAUDE_NO_OPTOUT
        )
        == []
    )


def test_gated_action_with_optout_fires_again():
    text = AGENT_WITH_ISSUE_BODY_CLAUDE_NO_OPTOUT.replace(
        '          prompt:',
        '          allowed_non_write_users: "*"\n          prompt:',
    )
    findings = rule_ci_agent_untrusted_issue_content("triage.yml", text)
    assert [f.rule for f in findings] == ["ci-agent-untrusted-issue-content"]


def test_codex_action_counts_as_gated():
    """`openai/codex-action` calls getCollaboratorPermissionLevel; `allow-users` opts in."""
    gated = AGENT_WITH_ISSUE_BODY_CLAUDE_NO_OPTOUT.replace(
        "anthropics/claude-code-action@v1", "openai/codex-action@v1"
    )
    assert rule_ci_agent_untrusted_issue_content("t.yml", gated) == []
    opted_in = gated.replace(
        '          prompt:', '          allow-users: "*"\n          prompt:'
    )
    assert [
        f.rule
        for f in rule_ci_agent_untrusted_issue_content("t.yml", opted_in)
    ] == ["ci-agent-untrusted-issue-content"]


# The real workflow that produced the false positive: deer-flow's triage.yml.
# A self-contained labeler: no agent action, no reusable call, and
# `author_association` used to decide whether to apply a first-time-contributor
# label. Every condition the old rule checked was satisfied and nothing was
# wrong with it.
LABELER_USING_AUTHOR_ASSOCIATION = '''\
name: Triage
on:
  issues:
    types: [opened]
jobs:
  pr-triage:
    if: github.event_name == 'pull_request_target'
    steps:
      - uses: actions/github-script@v8
        with:
          script: |
            if (['FIRST_TIME_CONTRIBUTOR', 'FIRST_TIMER'].includes(pr.author_association)) {
              toAdd.push('first-time-contributor')
            }
  issue-triage:
    if: github.event_name == 'issues'
    steps:
      - uses: actions/github-script@v8
        with:
          script: |
            await github.rest.issues.addLabels({ owner, repo, issue_number, labels: ['needs-triage'] })
'''


def test_labeler_using_author_association_is_not_reported():
    """Regression for a critical false positive found by scanning real repos.

    The old rule fired whenever `author_association` appeared anywhere in the
    file alongside an `issues` arm. Here it appears in a `github-script` body
    that decides whether to apply a label - no arm is gated, and no agent is
    reachable, so there is no injection path to warn about.
    """
    assert (
        rule_ci_agent_missing_author_association(
            "triage.yml", LABELER_USING_AUTHOR_ASSOCIATION
        )
        == []
    )


def test_the_same_labeler_fires_once_an_agent_is_reachable():
    """Not vacuous: the fix must be the agent condition, not the fixture."""
    text = LABELER_USING_AUTHOR_ASSOCIATION.replace(
        "  issue-triage:",
        "  invoke:\n    uses: ./.github/workflows/agent.yml\n  issue-triage:",
    )
    findings = rule_ci_agent_missing_author_association("triage.yml", text)
    assert [f.rule for f in findings] == ["ci-agent-missing-author-association"]


# --- recall: every rule must declare where it came from ---------------------

def test_every_rule_has_a_declared_origin():
    """A rule with no origin cannot be recall-audited.

    Precision work found four false positives in these rules; this is the
    opposite failure, and it is invisible without a declared expectation. The
    origin table is what `scripts/recall_audit.py` checks against, so a rule
    added without an entry is a rule nobody will ever test for silence.
    """
    import importlib

    recall = importlib.import_module("scripts.recall_audit")
    from agentbound.rules import FILE_RULES, PROJECT_RULES

    declared = {fn for _, fn, _, _ in recall.ORIGINS}
    implemented = {r.__name__ for r in list(FILE_RULES) + list(PROJECT_RULES)}
    missing = implemented - declared
    assert not missing, f"rules with no declared origin: {sorted(missing)}"


def test_origin_entries_are_not_duplicated():
    """Regression: the table was a dict keyed on the repo, which silently
    dropped the second of adk-python's two rules."""
    import importlib

    recall = importlib.import_module("scripts.recall_audit")
    pairs = [(repo, fn) for repo, fn, _, _ in recall.ORIGINS]
    assert len(pairs) == len(set(pairs)), "duplicate (repo, rule) entries"


# --- job scoping: the CVE-2026-44246 fix, nnU-Net `issue-agent.yml` ----------
#
# The first real-world file where the CI-agent rules were wrong in the *safe*
# direction. nnU-Net has two agent jobs: `auto-triage` is reachable by anyone on
# purpose, `on-demand` is gated on commenter `author_association`. The rules
# asked "does this workflow let an untrusted author drive an agent?" and answered
# once for the file, so the public job's precondition was attributed to the gated
# job - and every finding landed in the one job that had already done what the
# rule's own message prescribes.
#
# `auto-triage`'s own findings are deliberately NOT asserted away here. That job
# really is reachable by anyone and really does hold `issues: write`; calling
# that a non-finding would be trading a precision bug for a recall one.

NNUNET_AGENT_YML = '''\
on:
  issues:
    types: [opened]
  issue_comment:
    types: [created]
jobs:
  auto-triage:
    if: github.event_name == 'issues' && github.actor != 'claude[bot]'
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: write
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_non_write_users: ${{ github.event.issue.user.login }}
          claude_args: --allowedTools "Read,Write,Glob,Grep,Bash(gh issue view:*),Bash(gh search issues:*),Bash(grep:*),Bash(ls:*)"
  on-demand:
    if: |
      github.event_name == 'issue_comment' &&
      contains(github.event.comment.body, '@claude') &&
      (github.event.comment.author_association == 'OWNER' ||
       github.event.comment.author_association == 'MEMBER' ||
       github.event.comment.author_association == 'COLLABORATOR')
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: write
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_non_write_users: ${{ github.event.issue.user.login }}
'''

# The positive control: identical except the gate is gone. If the negative test
# below cannot be made to fail by deleting the gate, it proves nothing about the
# gate - it would pass just as well against a rule that never fires at all.
NNUNET_AGENT_YML_UNGATED = NNUNET_AGENT_YML.replace(
    """ &&
      (github.event.comment.author_association == 'OWNER' ||
       github.event.comment.author_association == 'MEMBER' ||
       github.event.comment.author_association == 'COLLABORATOR')""",
    "",
)
assert NNUNET_AGENT_YML_UNGATED != NNUNET_AGENT_YML
assert "author_association" not in NNUNET_AGENT_YML_UNGATED


def test_gated_agent_job_does_not_inherit_the_public_jobs_precondition():
    """Regression: CVE-2026-44246 fix (nnU-Net). The gate the rule prescribes is
    already present in that job, so it is not an input path."""
    findings = rule_ci_agent_untrusted_issue_content(
        "issue-agent.yml", NNUNET_AGENT_YML
    )
    assert findings == []


def test_removing_the_gate_brings_the_same_job_back():
    """The positive control for the test above."""
    findings = rule_ci_agent_untrusted_issue_content(
        "issue-agent.yml", NNUNET_AGENT_YML_UNGATED
    )
    assert any(f.rule == "ci-agent-untrusted-issue-content" for f in findings)


def test_write_scope_skips_only_the_gated_job():
    """`auto-triage` keeps its finding; `on-demand` loses one."""
    hardened = rule_ci_agent_write_scope_on_untrusted_trigger(
        "issue-agent.yml", NNUNET_AGENT_YML
    )
    assert len(hardened) == 1
    ungated = rule_ci_agent_write_scope_on_untrusted_trigger(
        "issue-agent.yml", NNUNET_AGENT_YML_UNGATED
    )
    assert len(ungated) == 2


NNUNET_CVE_YML = '''\
on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: write
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_non_write_users: ${{ github.event.issue.user.login }}
          prompt: |
            TITLE: ${{ github.event.issue.title }}
            BODY: ${{ github.event.issue.body }}
'''


def test_vulnerable_shape_is_still_detected():
    """Recall guard for the same file before its fix: job scoping must not have
    bought precision by going quiet on the vulnerable version."""
    assert any(
        f.rule == "ci-agent-untrusted-issue-content"
        for f in rule_ci_agent_untrusted_issue_content("issue-triage.yml", NNUNET_CVE_YML)
    )
    assert any(
        f.rule == "ci-agent-write-scope-on-untrusted-trigger"
        for f in rule_ci_agent_write_scope_on_untrusted_trigger(
            "issue-triage.yml", NNUNET_CVE_YML
        )
    )


# --- severity tracks what the agent may actually call ------------------------
#
# One repository supplies both directions. nnU-Net's vulnerable revision grants
# the agent `gh issue comment` and `gh issue edit`; the fix leaves the same
# `issues: write` on the job - a later step posts the comment - and removes those
# two commands from the agent's allowlist. Same write scope, different capability,
# and the severity has to follow the capability rather than the permissions block.

NNUNET_AGENT_YML_AGENT_MAY_COMMENT = NNUNET_AGENT_YML.replace(
    '--allowedTools "Read,Write,Glob,Grep,Bash(gh issue view:*)',
    '--allowedTools "Read,Bash(gh issue comment:*),Bash(gh issue edit:*),'
    "Bash(gh issue view:*",
)
assert "gh issue comment" in NNUNET_AGENT_YML_AGENT_MAY_COMMENT


def _auto_triage_finding(text):
    found = [
        f
        for f in rule_ci_agent_write_scope_on_untrusted_trigger(
            "issue-agent.yml", text
        )
        if f.line < 20
    ]
    assert len(found) == 1
    return found[0]


def test_constrained_agent_downgrades_rather_than_disappearing():
    """The fix for CVE-2026-44246 keeps `issues: write` but strips the write
    commands from the agent. The finding must survive as the residual - dropping
    it would be indistinguishable from the rule having broken."""
    finding = _auto_triage_finding(NNUNET_AGENT_YML)
    assert finding.severity == "low"
    assert "no repository-mutating command" in finding.message


def test_the_same_job_is_high_when_the_agent_may_comment():
    """The positive control: one allowlist entry restores the severity."""
    finding = _auto_triage_finding(NNUNET_AGENT_YML_AGENT_MAY_COMMENT)
    assert finding.severity == "high"


NNUNET_AGENT_YML_NO_ALLOWLIST = NNUNET_AGENT_YML.replace(
    '          claude_args: --allowedTools "Read,Write,Glob,Grep,'
    'Bash(gh issue view:*),Bash(gh search issues:*),Bash(grep:*),Bash(ls:*)"\n',
    "",
)
assert "allowedTools" not in NNUNET_AGENT_YML_NO_ALLOWLIST


def test_unreadable_allowlist_keeps_full_severity():
    """No allowlist means 'cannot show the agent is constrained', which is not
    the same as 'constrained'. Assuming the safe case is how a rule goes quiet
    on the workflows that need it."""
    assert _auto_triage_finding(NNUNET_AGENT_YML_NO_ALLOWLIST).severity == "high"


def test_reading_commands_do_not_count_as_write_tools():
    """`gh issue view` and `gh search issues` are what the hardened config still
    needs; treating them as writes would erase the distinction."""
    assert _agent_has_repo_write_tool(
        'claude_args: --allowedTools "Bash(gh issue view:*),Bash(gh search issues:*)"'
    ) is False
    assert _agent_has_repo_write_tool(
        'claude_args: --allowedTools "Bash(gh issue comment:*)"'
    ) is True
    assert _agent_has_repo_write_tool('claude_args: --allowedTools "Read,Grep"') is False
    assert _agent_has_repo_write_tool("runs-on: ubuntu-latest") is None


def test_claude_args_carrying_only_a_model_is_not_a_tool_allowlist():
    """Regression: `anthropics/claude-code`, this rule's origin, sets
    `claude_args: "--model claude-sonnet-4-5-20250929"`. That restricts the model,
    not the tools. Reading `claude_args` as a tool allowlist found no mutating
    command in it and dropped the origin finding from high to low - a false
    negative manufactured by the fix for a false positive, caught by running the
    rule across 10 real agent workflows instead of only the one it was written
    against."""
    assert _agent_has_repo_write_tool(
        'claude_args: "--model claude-sonnet-4-5-20250929"'
    ) is None
    # The nested flag is still found, so requiring it costs no recall.
    assert _agent_has_repo_write_tool(
        'claude_args: --allowedTools "Bash(gh issue view:*)"'
    ) is False


CLAUDE_DEDUPE_YML = '''\
on:
  issues:
    types: [opened]
jobs:
  dedupe:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: write
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_non_write_users: ${{ github.event.issue.user.login }}
          claude_args: "--model claude-sonnet-4-5-20250929"
'''


def test_origin_workflow_keeps_full_severity():
    """The end-to-end form of the regression above."""
    findings = rule_ci_agent_write_scope_on_untrusted_trigger(
        "claude-dedupe-issues.yml", CLAUDE_DEDUPE_YML
    )
    assert [f.severity for f in findings] == ["high"]


# The real allowlist from nnU-Net's fix commit `4e4770b0`, which is not the same
# thing as its fix: labelling moved into a wrapper script and `gh issue edit` was
# dropped, but the agent kept `gh issue comment`. It is a high-severity verdict
# for that revision, and only a later master cleared it. Pinned because the
# wrapper-script path is an unusual token to parse.
NNUNET_FIX_COMMIT_ALLOWLIST = (
    '"Read,Glob,Grep,Bash(.github/scripts/safe-label.sh:*),'
    'Bash(gh issue comment:*),Bash(gh issue view:*),Bash(gh search issues:*),'
    'Bash(grep:*),Bash(rg:*),Bash(ls:*)"'
)


def test_the_fix_commit_is_still_high_because_the_agent_can_still_comment():
    assert _agent_has_repo_write_tool(
        "claude_args: --allowedTools " + NNUNET_FIX_COMMIT_ALLOWLIST
    ) is True


# --- which `scope: write` lines are actually grants --------------------------
#
# Two defects, one in each direction, found by running the rule over a 197-file
# corpus of real agent workflows rather than the fixtures it was written for.

BLOCK_SCALAR_PERMISSIONS_YML = '''\
on:
  issues:
    types: [opened]
permissions: {}
jobs:
  triage:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: read
    steps:
      - name: Get issue context token
        id: token
        uses: open-security-tools/ost-simple-sts@974a63a2daaaa40f7c6dec40d334f3da4421469e
        with:
          repositories: |
            example/repo
          # Linking an upstream issue to a fork branch requires both
          # permissions on one token.
          permissions: |
            contents: write
            issues: write
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_non_write_users: ${{ github.event.issue.user.login }}
'''


def test_permissions_block_scalar_on_an_action_input_is_not_a_grant():
    """Regression: `astral-sh/uv`. A credential broker is *asked* for a scoped
    token; the job is read-only and the top level is `permissions: {}`. Flagging
    that flags the repo already doing the work."""
    assert _iter_write_scopes(BLOCK_SCALAR_PERMISSIONS_YML) == []
    assert rule_ci_agent_write_scope_on_untrusted_trigger(
        "issue-triage.yml", BLOCK_SCALAR_PERMISSIONS_YML
    ) == []


COMMENTED_WRITE_SCOPE_YML = '''\
on:
  issues:
    types: [opened]
jobs:
  triage:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: write # post the triage comment
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_non_write_users: ${{ github.event.issue.user.login }}
          claude_args: --allowedTools "Read,Bash(gh issue comment:*)"
'''


def test_a_trailing_comment_does_not_hide_a_real_grant():
    """Regression, and the more dangerous direction: the old pattern anchored on
    end-of-line, so `issues: write # comment` - an extremely common style -
    matched nothing. 23 real grants across the corpus were being missed."""
    assert _iter_write_scopes(COMMENTED_WRITE_SCOPE_YML) == [(9, "issues")]
    findings = rule_ci_agent_write_scope_on_untrusted_trigger(
        "triage.yml", COMMENTED_WRITE_SCOPE_YML
    )
    assert [f.severity for f in findings] == ["high"]


def test_write_scope_shapes():
    """The four forms, and the three that grant nothing."""
    assert _iter_write_scopes("permissions:\n  issues: write\n") == [(2, "issues")]
    assert _iter_write_scopes("permissions: {contents: write, issues: read}\n") == [
        (1, "contents")
    ]
    assert _iter_write_scopes("permissions: {}\n") == []
    assert _iter_write_scopes("permissions: read-all\n") == []
    # A scope line that is not under a `permissions:` mapping is not a grant.
    assert _iter_write_scopes("with:\n  contents: write\n") == []
    # ...and one shallower than its key has left the block.
    assert _iter_write_scopes("  permissions:\n    issues: read\n  contents: write\n") == []


# --- the opt-out has to carry a value ----------------------------------------
#
# Presence is not the question. Both actions say so in their own source:
# claude-code-action's test/permissions.test.ts asserts
# `checkWritePermissions(..., "", true) === false` under the name "should NOT
# bypass permission check when allowed_non_write_users is empty", and
# codex-action's checkActorPermissions.ts gates the override on
# `allowUsersSpec.length > 0`. An empty value is the safe configuration.

REDPANDA_EMPTY_OPTOUT_YML = '''\
on:
  issues:
    types: [opened]
jobs:
  claude:
    # Only org members with write access can trigger via @claude mentions
    if: github.event_name == 'issues' && contains(github.event.issue.body, '@claude')
    runs-on: ubuntu-latest
    permissions:
      contents: write
      issues: write
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_bots: ""
          allowed_non_write_users: ""
          claude_args: --allowedTools "Bash(gh pr comment:*),Bash(gh issue view:*)"
'''


def test_an_empty_optout_leaves_the_actors_write_check_in_place():
    """Regression: redpanda-data/console. That workflow sets
    `allowed_non_write_users: ""` beside a comment saying only org members with
    write access can trigger. It was reported as reachable by anyone, along with
    its `contents: write`."""
    assert not _untrusted_author_reaches_agent(REDPANDA_EMPTY_OPTOUT_YML)
    assert rule_ci_agent_write_scope_on_untrusted_trigger(
        "claude.yml", REDPANDA_EMPTY_OPTOUT_YML
    ) == []


def test_optout_values_that_do_and_do_not_opt_in():
    """A named account is not an opt-out for *any* author.

    This changed in 0.1.6: `allowed_non_write_users: alice` used to count as
    reachable-by-anyone. The action bypasses its check for `alice` and no one
    else, so an arbitrary GitHub user still cannot trigger the run, and the class
    this rule exists for does not apply. The maintainer named that account.
    """
    base = "uses: anthropics/claude-code-action@v1\n"
    # Not opt-outs: nothing, or a named account.
    assert not _untrusted_author_reaches_agent(base + 'allowed_non_write_users: ""\n')
    assert not _untrusted_author_reaches_agent(base + "allowed_non_write_users: ''\n")
    assert not _untrusted_author_reaches_agent(base + "allowed_non_write_users:\n")
    assert not _untrusted_author_reaches_agent(
        base + 'allowed_non_write_users: ""  # nobody\n'
    )
    assert not _untrusted_author_reaches_agent(base + "allowed_non_write_users: alice\n")
    assert not _untrusted_author_reaches_agent(
        base + "allowed_non_write_users: alice, bob\n"
    )
    # Opt-outs: a wildcard, or a value the event computes.
    assert _untrusted_author_reaches_agent(base + 'allowed_non_write_users: "*"\n')
    assert _untrusted_author_reaches_agent(base + "allowed_non_write_users: alice, *\n")
    assert _untrusted_author_reaches_agent(
        base + "allowed_non_write_users: ${{ github.actor }}\n"
    )
    assert _untrusted_author_reaches_agent(
        base + "allowed_non_write_users: ${{ github.event.issue.user.login }}\n"
    )


def test_codex_allow_users_uses_the_same_semantics():
    base = "uses: openai/codex-action@v1\n"
    assert not _untrusted_author_reaches_agent(base + 'allow-users: ""\n')
    assert not _untrusted_author_reaches_agent(base + 'allow-users: "MathiasGruber"\n')
    assert _untrusted_author_reaches_agent(base + 'allow-users: "*"\n')


# --- the write scope's job has to be the agent's job -------------------------
#
# Half of every high-severity finding this rule produced across a 197-file
# corpus was a write scope on a job that runs no agent. The shape is the
# recommended one: a read-only job gathers with the agent, a second job applies
# the result. The agent never receives the second job's token, so "an untrusted
# author can steer an agent that holds write access" is simply not true of it.

SPLIT_JOBS_YML = '''\
on:
  issues:
    types: [opened]
jobs:
  gather-labels:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: openai/codex-action@v1
        with:
          allow-users: "*"
  apply-labels:
    needs: gather-labels
    runs-on: ubuntu-latest
    permissions:
      contents: read
      issues: write
    steps:
      - uses: actions/github-script@v9
        with:
          script: console.log("apply the labels the agent gathered")
'''

# The control: the same write scope, moved into the job that runs the agent.
JOINED_JOBS_YML = SPLIT_JOBS_YML.replace(
    """    steps:
      - uses: actions/github-script@v9
        with:
          script: console.log("apply the labels the agent gathered")
""",
    "    steps:\n      - uses: openai/codex-action@v1\n"
    "        with:\n          allow-users: \"*\"\n",
)
assert "allow-users" in JOINED_JOBS_YML
assert JOINED_JOBS_YML.count("codex-action") == 2


def test_a_write_scope_on_a_job_without_the_agent_is_not_reported():
    """Regression: dataplat/dbatools and the codex labeler templates."""
    assert rule_ci_agent_write_scope_on_untrusted_trigger(
        "codex.yml", SPLIT_JOBS_YML
    ) == []


def test_the_control_moves_the_agent_into_the_write_job_and_fires():
    findings = rule_ci_agent_write_scope_on_untrusted_trigger(
        "codex.yml", JOINED_JOBS_YML
    )
    assert [f.severity for f in findings] == ["high"]


def test_a_reusable_workflow_passing_the_input_through_still_counts():
    """`${{ inputs.x }}` carries a value even though it may be empty at run time.
    The loud direction is correct: the workflow's safety then depends on every
    caller, which a scan of this file cannot see."""
    assert _untrusted_author_reaches_agent(
        "uses: anthropics/claude-code-action@v1\n"
        "allowed_non_write_users: ${{ inputs.allowed_non_write_users }}\n"
    )






def test_job_splitter_finds_both_jobs_and_ignores_on_block_children():
    jobs = _iter_jobs(NNUNET_AGENT_YML)
    assert [j[0] for j in jobs] == ["auto-triage", "on-demand"]
    # `issues:` under `on:` sits at two spaces; it must not be read as a job.
    assert "issues" not in {j[0] for j in jobs}


def test_job_gate_check_handles_both_orders_and_only_the_header():
    assert _job_gates_on_author_association(
        "  if: github.event.issue.author_association == 'MEMBER'\n  steps:\n"
    )
    assert _job_gates_on_author_association(
        "  if: contains(fromJSON('[\"OWNER\",\"MEMBER\",\"COLLABORATOR\"]'),"
        " github.event.comment.author_association)\n  steps:\n"
    )
    # A gate that only appears inside a later script must not suppress anything.
    assert not _job_gates_on_author_association(
        "  if: github.event_name == 'issues'\n  steps:\n"
        "    - run: echo \"${{ github.event.issue.author_association == 'OWNER' }}\"\n"
    )
    # Lower trust levels are not gates.
    assert not _job_gates_on_author_association(
        "  if: github.event.issue.author_association == 'CONTRIBUTOR'\n  steps:\n"
    )


def test_ungated_text_still_reports_no_job_rather_than_a_gate():
    """An unparseable file must read as 'cannot show a gate', not as 'gated'."""
    assert _iter_jobs("some: yaml\n") == []
    assert _job_containing([], 7) is None

