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
| `ci-agent-untrusted-issue-content` | high | a workflow runs an AI agent action **and** consumes issue or comment text — from the event payload, or fetched with `gh issue list --json ...body`. Both CI-agent rules also require that an author *without* write access can actually reach the agent: `claude-code-action` and `codex-action` refuse such an actor unless an input opts them in, while `run-gemini-cli` and `gemini-cli-action` perform no actor check at all. The precondition is per action and read from each action's source, and is evaluated per **job**, so a job gated on `author_association` does not inherit it from a public job in the same file (see *Precision* below) |
| `ci-agent-write-scope-on-untrusted-trigger` | high | an AI agent action runs in a job triggered by issue/comment/review events, the job grants a `write` scope, **and** an untrusted author can reach the agent. The complement of the rule above: here the untrusted text never appears in the YAML, because the agent fetches the issue itself at runtime with the token the job hands it, so no scan of the file can see it. `id-token: write` is not counted — it mints the OIDC token and is what a hardened setup uses. Evaluated per job, as above |
| `ci-agent-missing-author-association` | critical | an `issues`-triggered dispatch arm with no `author_association` check while other arms have one, **and** an agent is reachable from the file — either an agent action or a call to a reusable workflow that may hold one. A repository that only labels issues, with no agent anywhere, is not reported |
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

## Does it still find the things it was built for?

Precision is measured in the other direction from this. Every rule here was
generalised from a real finding, so there is a second question worth asking:
**does each rule still fire on the code it came from?** A rule that quietly
stopped matching would be indistinguishable from a rule with a perfect
false-positive record.

`scripts/recall_audit.py` answers it against committed upstream trees:

```bash
git clone --filter=blob:none https://github.com/google/adk-python /tmp/adk-python
python scripts/recall_audit.py /tmp/adk-python origin/main
```

It reads blobs out of git rather than the working copy, deliberately. A working
copy may be sitting on the branch that *fixes* the thing a rule detects — which
is exactly what happened the first time this audit was run by hand, and made a
working rule look broken.

All eight rules fire on at least one origin:

| origin | rule that fires |
|---|---|
| `google/adk-python` | `tool-reserved-name-shadowing`, `tool-dict-last-wins`, `confirmation-gate-fails-open` |
| `google/adk-go` | `tool-inmodel-name-unoccupied` |
| `google/adk-java` | `tool-inmodel-name-unoccupied` |
| `google/adk-js` | `tool-built-in-silent-replace` |
| `google-gemini/gemini-cli` | `ci-agent-untrusted-issue-content`, `ci-agent-missing-author-association` |
| `GoogleCloudPlatform/vertex-ai-creative-studio` | `ci-agent-missing-author-association` |
| `anthropics/claude-code` | `ci-agent-write-scope-on-untrusted-trigger` |

A test asserts every rule has a declared origin, so a new rule cannot be added
without saying what it is supposed to find.

## Precision, measured against someone else's fix

Recall is measured above. Precision needs the opposite kind of input: a file
written by someone who was not trying to make this tool look good. The best one
available is the **fix** for a published CVE.

`CVE-2026-44246` (nnU-Net, agentic workflow injection in
`.github/workflows/issue-triage.yml`, fixed in `v2.4.1`) is that file. Against
the vulnerable revision the rules fire on the CVE's own vector:

| revision | findings |
|---|---|
| vulnerable (pre-`v2.4.1`) | `ci-agent-untrusted-issue-content`@33 (`BODY: ${{ github.event.issue.body }}`), `ci-agent-write-scope-on-untrusted-trigger`@17 |
| hardened (`master`) | `ci-agent-write-scope-on-untrusted-trigger`@49, `ci-agent-missing-author-association`@41 |

The hardening is real and the maintainers did what the message asks for: the
issue text is no longer inlined into the prompt (the agent fetches it as tool
output), `gh issue comment`/`gh issue edit` were removed from the agent's tool
allowlist, and posting moved to later steps whose target comes from
`github.event.issue.number` rather than from model output.

That file has **two** agent jobs, which is what broke the rules. `auto-triage`
is reachable by anyone, by design. `on-demand` is gated:

```yaml
(github.event.comment.author_association == 'OWNER' ||
 github.event.comment.author_association == 'MEMBER' ||
 github.event.comment.author_association == 'COLLABORATOR')
```

Both CI-agent rules asked a question about *the workflow* and answered it once,
so `auto-triage`'s untrusted-author precondition leaked into `on-demand`. Every
finding landed in the one job that had already done what the rule's own message
prescribes. The precondition is now evaluated per job, which removed the two
findings in the gated job:

| finding | before | now |
|---|---|---|
| `ci-agent-untrusted-issue-content`@181 | fired | removed — job is author-gated |
| `ci-agent-write-scope-on-untrusted-trigger`@191 | fired | removed — job is author-gated |

The two findings on `auto-triage` are **kept**, deliberately. That job really is
reachable by anyone and really does grant `issues: write`, so suppressing them
would trade a precision bug for a recall one. They are over-severe for this
file, not false: the rule reads the job's `permissions` block and cannot see
that the agent's `--allowedTools` denies the write commands. Reading the tool
allowlist is the known gap, and the fix for it is not written yet.

`tests/test_rules.py` pins both directions from one fixture: the gated file
yields nothing, and a control with the gate deleted out of it fires again. A
negative test without that control would pass just as well against a rule that
never fires at all.

## Scope & honesty

The rules are heuristics that surface high-signal locations and explain the
mechanism; they are not a substitute for a human confirming reachability and
impact. Python (`.py`), TypeScript/JavaScript (`.ts`/`.tsx`/`.js`/`.jsx`), Go
(`.go`), Java (`.java`) and GitHub Actions (`.yml`/`.yaml`) are scanned. The
reserved-name watchlist is framework-specific and currently covers the ADK
family; contributions to widen coverage are welcome.

Authored by Sushant Poudel ([@sushant-me](https://github.com/sushant-me)).
