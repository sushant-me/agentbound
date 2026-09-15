# agentbound

Static detector for **AI-agent tool-boundary bugs** — the framework-side class of
vulnerability where a third-party tool, a confirmation gate, or a CI trigger
crosses a security boundary the framework intended to enforce.

It does *not* fuzz a model or scan MCP servers for prompt injection. It detects
the structural defect in the **framework's own code** that lets tool shadowing
happen in the first place.

## The bug class (why this exists)

Tool-name shadowing is being fixed *independently and repeatedly* across agent
frameworks right now:

| framework | evidence |
|---|---|
| google/adk-python | `set_model_response` missing from `_RESERVED_TOOL_NAMES` → MCP server can receive the agent's structured final answer |
| google/adk-js | a callable tool silently replaces the in-model `google_search` built-in |
| NousResearch/hermes-agent | [PR #95219 "make tool_search wire alias collision-safe"](https://github.com/NousResearch/hermes-agent/pull/95219), [commit "reject memory tools that shadow core tool names"](https://github.com/NousResearch/hermes-agent/commit/92c3bf682bc7db0517d74e445cc3a7d5180d47b7) |
| microsoft/agent-framework | [PR #7090 "name collision warnings for auto-approvals"](https://github.com/microsoft/agent-framework/pull/7090) |
| openai/openai-agents-python | [issue #464 "Duplicate tool names across MCP servers"](https://github.com/openai/openai-agents-python/issues/464) |

It is also a formalised threat: ["Cross-server tool shadowing" MCP-046](https://mcpsafe.io/threats/MCP-046).

Existing scanners ([mcphound](https://pypi.org/project/mcphound/),
[mcp-shield](https://github.com/buildwithabid/mcp-shield)) scan the *server*
side. `agentbound` scans the *framework* side, which no general tool does today.

## Rules

| rule | severity | what it detects |
|---|---|---|
| `tool-reserved-name-shadowing` | high | a reserved-name set omits a framework-owned tool the framework registers (`def <name>(`) |
| `confirmation-gate-fails-open` | high | `inspect.signature(predicate)` filters tool args, so a generic predicate returns `False` and the gate opens |
| `ci-agent-missing-author-association` | critical | an `issues`-triggered dispatch arm with no `author_association` check (used elsewhere in the workflow) |
| `tool-dict-last-wins` | medium | a tool-name→tool dict assigned unconditionally while duplicates are only `logging.warning`-ed (last-wins shadowing) |

Each rule generalises one real, disclosed finding (documented in the rule
docstrings).

## Install & run

```bash
pip install -e .
agentbound scan /path/to/repo
agentbound scan /path/to/repo --json
```

Exit code is `1` when findings exist, so it can gate CI.

## Verify against the real findings

```bash
# google/adk-python: tool shadowing + fail-open confirmation gate
agentbound scan <adk-python checkout>

# GoogleCloudPlatform/vertex-ai-creative-studio: unauth issue dispatch
agentbound scan <vertex-ai-creative-studio checkout>
```

Unit tests (self-contained fixtures, no network):

```bash
python -m pytest tests/
```

## Scope & honesty

The rules are heuristics that surface high-signal locations and explain the
mechanism; they are not a substitute for a human confirming reachability and
impact. The reserved-name watchlist is framework-specific and currently covers
the ADK family; contributions to widen coverage are welcome.

Authored by Sushant Poudel ([@sushant-me](https://github.com/sushant-me)).
