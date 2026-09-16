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
