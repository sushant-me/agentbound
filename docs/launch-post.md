# Launch post (draft — post under your own account)

> Copy-paste ready. Tune the voice to your own; keep the facts as-is.

---

**Show HN: agentbound — a static detector for the AI-agent "tool shadowing" bug class**

Tool-name shadowing is getting fixed *independently and repeatedly* across agent
frameworks right now — Google's ADK, NousResearch/hermes-agent, Microsoft
agent-framework, and OpenAI's agents SDK have all hit it. It's even a formal
threat: "Cross-server tool shadowing" (MCP-046).

Yet every tool I found scans the **MCP server side** (prompt injection, secrets).
Nobody scans the **framework side** — the structural defect that lets a
third-party tool silently displace a framework's own tool in the first place.

So I built [agentbound](https://github.com/sushant-me/agentbound): a small,
zero-dependency static detector that finds that class. Five rules, each grounded
in a real disclosed finding:

- `tool-reserved-name-shadowing` — a reserved-name set omits a framework tool it
  registers (`def set_model_response` missing from ADK's `_RESERVED_TOOL_NAMES`).
- `confirmation-gate-fails-open` — `inspect.signature(predicate)` filters tool
  args, so a generic predicate returns `False` and the gate opens.
- `ci-agent-missing-author-association` — an `issues`-triggered CI arm with no
  `author_association` check, so any GitHub user can fire a secrets-bearing agent.
- `tool-dict-last-wins` — `tools_dict[name] = tool` with only a warning on
  duplicates (last-wins shadowing).
- `tool-built-in-silent-replace` — `toolsDict[name] = this` after a duplicate
  throw gated on `!isInModelTool(...)`, silently displacing a built-in.

```bash
pip install -e .
agentbound scan /path/to/repo          # exit 1 if anything found
agentbound scan /path/to/repo --json
```

Verified against real code, not synthetic fixtures: it flags the exact
`file:line` of real findings in google/adk-python and google/adk-js, and produces
zero false positives across openai-agents-python and microsoft/agent-framework.

Honest scope: these are heuristics that surface high-signal locations and explain
the mechanism — a human still confirms reachability. The watchlist is currently
ADK-family-shaped; I'd love help widening coverage to more frameworks.

MIT. PRs welcome.

---

## Where to post

- **Hacker News** — "Show HN" (title above).
- **r/LocalLLaMA** — reword the first paragraph, lead with "I built a scanner
  for the tool-shadowing bug class hitting agent frameworks".
- **r/MachineLearning** — weekly "tools" thread, shorter form.

Post from your own account(s); do not claim anything beyond what's above. All of
it is verifiable from the repo's README and rule docstrings.
