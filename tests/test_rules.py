"""Unit tests using inline fixtures (self-contained, no network / no repos)."""

from agentbound.rules import (
    rule_tool_reserved_name_shadowing,
    rule_confirmation_gate_fails_open,
    rule_ci_agent_missing_author_association,
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
