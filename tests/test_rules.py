"""Unit tests using inline fixtures (self-contained, no network / no repos)."""

from agentbound.rules import (
    rule_tool_reserved_name_shadowing,
    rule_confirmation_gate_fails_open,
    rule_ci_agent_missing_author_association,
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
