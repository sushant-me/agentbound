# agentbound

[![CI](https://github.com/sushant-me/agentbound/actions/workflows/ci.yml/badge.svg)](https://github.com/sushant-me/agentbound/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%20%7C%203.11%20%7C%203.13-blue)](https://github.com/sushant-me/agentbound/actions/workflows/ci.yml)

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
| `ci-agent-untrusted-issue-content` | high | a workflow runs an AI agent action **and** consumes issue or comment text — from the event payload, or fetched with `gh issue list --json ...body` — so untrusted text reaches the agent regardless of how the run started |
| `ci-agent-write-scope-on-untrusted-trigger` | high | an AI agent action runs in a job triggered by issue/comment/review events — text anyone can author — **and** the job grants a `write` scope. The complement of the rule above: here the untrusted text never appears in the YAML, because the agent fetches the issue itself at runtime with the token the job hands it, so no scan of the file can see it. `id-token: write` is not counted — it mints the OIDC token and is what a hardened setup uses |
| `ci-agent-missing-author-association` | critical | an `issues`-triggered dispatch arm with no `author_association` check while other arms have one, so any user reaches the job; where it runs an agent, the text is attacker-controlled input |
| `tool-dict-last-wins` | medium | a tool-name→tool dict assigned unconditionally while duplicates are only `logging.warning`-ed (last-wins shadowing) |
| `tool-built-in-silent-replace` | high | a callable tool registers `toolsDict[name] = this` after a duplicate throw gated on `!isInModelTool(...)`, silently displacing a built-in |
| `tool-inmodel-name-unoccupied` | high | an in-model tool appends to the request's config tools (Go `setTool()`, Java `processLlmRequest` without `appendTools()`) but never registers its name, so a server-provided tool of the same name shadows it |

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
impact. Python (`.py`), TypeScript/JavaScript (`.ts`/`.tsx`/`.js`/`.jsx`), Go
(`.go`), Java (`.java`) and GitHub Actions (`.yml`/`.yaml`) are scanned. The
reserved-name watchlist is framework-specific and currently covers the ADK
family; contributions to widen coverage are welcome.

Authored by Sushant Poudel ([@sushant-me](https://github.com/sushant-me)).
