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
| `ci-agent-untrusted-issue-content` | high | a workflow runs an AI agent action **and** consumes issue or comment text — from the event payload, or fetched with `gh issue list --json ...body`. Both CI-agent rules also require that an author *without* write access can actually reach the agent: `claude-code-action` and `codex-action` refuse such an actor unless an input opts them in, while `run-gemini-cli` and `gemini-cli-action` perform no actor check at all. The precondition is per action and read from each action's source, and is evaluated per **job**, so a job gated on `author_association` does not inherit it from a public job in the same file (see *Precision* below). The opt-out must also **opt in more than a named account**: both actions bypass their check only for the accounts listed, so `allow-users: "MathiasGruber"` leaves an arbitrary GitHub user unable to reach the agent. What reaches anyone is a `*` or a value the *event* computes — `${{ github.event.issue.user.login }}` is the author of the issue the attacker just opened, which is the CVE's vector. An empty value is likewise no opt-out: `allowed_non_write_users: ""` leaves the write-permission check in place |
| `ci-agent-write-scope-on-untrusted-trigger` | high | an AI agent action runs in a job triggered by issue/comment/review events, the job grants a `write` scope, **and** an untrusted author can reach the agent. The complement of the rule above: here the untrusted text never appears in the YAML, because the agent fetches the issue itself at runtime with the token the job hands it, so no scan of the file can see it. `id-token: write` is not counted — it mints the OIDC token and is what a hardened setup uses. Evaluated per job, as above. Severity scales with how far the agent's **mutating tools** reach, which is a property of the `--allowedTools` patterns and not of the permissions block:

| agent's `Bash(...)` allowlist | severity | why |
|---|---|---|
| no mutating command at all | `low` | the grant exists for the job's later, non-agent steps |
| mutating command **naming its target** — `gh issue edit ${{ github.event.issue.number }}:*` | `medium` | bounded; a prefix match on a command string is not a parser, so it stays visible |
| mutating command matching **any** argument — `gh issue edit:*` | `high` | the agent's reach is broader than its task |
| no readable allowlist | `high` | *cannot show the agent is constrained* is not *constrained* |

Two workflows can grant an identical `issues: write` and differ completely in what the agent may point it at, so the permissions block alone cannot separate them. The grant must also be on the job that **runs the agent**: a read-only agent job beside a `publish`/`apply-labels` job holding `issues: write` is the recommended architecture, and the agent never receives that token. And a `scope: write` line counts only as a child of a `permissions:` **mapping** — the same two lines appearing as an action input, as in a credential broker's `permissions: \|`, are not a grant |
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
`.github/workflows/issue-triage.yml`, fixed in `v2.4.1`, CVSS 7.2 High,
[GHSA-63mx-j37w-gh59](https://github.com/MIC-DKFZ/nnUNet/security/advisories/GHSA-63mx-j37w-gh59))
is that file. Its description names both mechanisms the rules key on — untrusted
issue text embedded in the agent's prompt, and `allowed_non_write_users` letting
any logged-in user reach a command-capable agent. Against the vulnerable
revision the rules fire on the CVE's own vector:

| revision | findings |
|---|---|
| vulnerable (pre-`v2.4.1`) | `ci-agent-untrusted-issue-content`@33 (`BODY: ${{ github.event.issue.body }}`), `ci-agent-write-scope-on-untrusted-trigger`@17 (**high**) |
| hardened (`master`) | `ci-agent-write-scope-on-untrusted-trigger`@49 (**low**), `ci-agent-missing-author-association`@41 |

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
would trade a precision bug for a recall one.

What changed instead is the **severity**, and the same repository supplies both
directions of the evidence. This needs exact revisions, because the hardening
took two steps and the rule is right about both of them:

| revision | agent's `--allowedTools` | `issues: write` | severity |
|---|---|---|---|
| `94300b49` (vulnerable) | `gh issue comment`, `gh issue edit` | yes | **high** |
| `4e4770b0` (the fix) | `gh issue comment` only — labelling moved to a wrapper script | yes | **high** |
| `master` | neither; a later step posts from a file the agent writes | yes | **low** |

The fix commit removed `gh issue edit` and routed labels through
`.github/scripts/safe-label.sh`, but left `Bash(gh issue comment:*)` with the
agent. The permissions block is unchanged across all three; the capability is
not. So the rule reads the tool allowlist, and reports **`low`** only once the
agent has no repository-mutating command left — which is true of `master` and
not of the fix commit.

That distinction was then run across every agent workflow to hand rather than the
one it was written for — **37 workflow files, 10 running an agent action, and
exactly one downgrades**: the nnU-Net file that genuinely constrains its agent.
A refinement that silences findings at scale would be a recall bug wearing a
precision badge, and the way to tell them apart is to count.

**A wider sweep found one defect of each kind.** Searching GitHub for the opt-out
vector — `allowed_non_write_users` and `allow-users` inside `.github/workflows` —
and scanning the **197 workflow files from 132 repositories** that came back
turned up two bugs in the scope matching itself, pointing opposite ways:

* **A false positive.** `astral-sh/uv`'s `issue-triage.yml` was flagged on
  `contents: write`. That line is not a GitHub permission at all: it sits inside a
  `permissions: |` block scalar passed as an *input* to
  `open-security-tools/ost-simple-sts`, a credential broker being asked for a
  narrow, short-lived token. The job is read-only and the workflow's top level is
  `permissions: {}` — a deny-all default. The rule was flagging the shape of
  repository least able to afford it, because it is the one already doing the
  work. A `scope: write` line now counts only as a child of a `permissions:`
  mapping, which is the only place it grants anything.
* **A false negative, in the other direction, present from the start.** The
  pattern anchored on end-of-line, so `issues: write # post the triage comment` —
  an extremely common way to write it — matched **nothing**. 23 real grants
  across the corpus were invisible. Comments are stripped before matching now.

Both guards are mutation-tested: reverting either fails exactly one test.

**A third defect, in the precondition itself.** The corpus also caught the rule
reading the opt-out as a *presence* rather than a *value*. `redpanda-data/console`
sets `allowed_non_write_users: ""` directly above the comment *"Only org members
with write access can trigger via @claude mentions"* — it is relying on the
action's own check, which is the safe configuration. Both actions say so in their
own source: `claude-code-action`'s suite asserts
`checkWritePermissions(..., "", true) === false` under the test name *"should NOT
bypass permission check when allowed_non_write_users is empty"*, and
`codex-action`'s `checkActorPermissions.ts` gates the override on
`allowUsersSpec.length > 0`. The rule was reporting that workflow, including its
`contents: write`, as reachable by anyone. An input now has to carry a non-empty
value to count, and a reusable workflow forwarding `${{ inputs.x }}` still counts,
because its safety then depends on callers this file cannot see.

Dropping the three fixes together took the corpus from **106 findings to 107** —
which is the wrong way to read it. The count barely moved because the fixes
pushed in opposite directions: the `permissions:`-mapping guard removed the four
`astral-sh/uv` false positives, while stripping comments before matching surfaced
eight findings that had been invisible. The count is not the measure; *which*
findings changed is. The genuine `contents: write` set went 6 → 5, and the three
that left were configurations that were already safe.

**Then two more, and this pair was worth half the rule's output.** Splitting the
write scope from the agent was invisible to every earlier check because
`_untrusted_author_reaches_agent` is evaluated once per **file**, while the
`write` scope is a property of a **job**. So a read-only job that gathers with
the agent, plus a second job that applies the result, was reported on the second
job's scope — the arrangement that is the *point* of the split. Of 107
high-severity findings in the corpus, **53 were this**, including
`dataplat/dbatools` and every copy of the codex labeler template. The grant must
now be on the job that runs the agent; a reusable-workflow call still counts,
since the agent may be one file away.

The fifth is the same confusion one level down, in the opt-out's *meaning*:
`allow-users: "MathiasGruber"` names an account, and the action bypasses its
check for that account and no other. What reaches an arbitrary author is a `*` or
a value the event computes. That dropped `studie-tech/TheNinjaRPG`, and the
`contents: write` set is now **3**, all with the agent in the same job.

**In total: 107 → 47 write-scope findings, 50 → 43 untrusted-content, and 6 → 3
`contents: write`.** Everything removed was a configuration that was safe, and
the direction of the error was always the same — the rule was reporting the
recommended architecture as the vulnerability.

**Two more, and then the count went back up — correctly.** The opt-out is an
input on the agent *step*, so it is per **job** as well, and it was still being
read per file. `OpenNHP/opennhp` runs two agent jobs: one sets
`allowed_non_write_users: '*'` and is read-only, the other holds `contents: write`
and never opts out. Only the first is reachable by anyone, and the second was
being reported at `high` because of its sibling. Scoping it correctly took the
corpus to 40.

Then a reusable-workflow caller nearly went quiet, and that is the more
instructive half. `evcc-io/evcc` holds `contents: write` in a job that calls
`./.github/workflows/claude-issue-agent-run.yml` — and the opt-out is in *that*
file, which a scan of the caller cannot see. Scoping reachability to the job
would have silently dropped it, and going and looking showed the called workflow
sets `allowed_non_write_users: '*'` at line 63: the indirection resolves to
**reachable**, so quiet would have been a false negative on the one case where it
mattered. A reusable call with no inline agent action is now treated as unknown
and stays in the loud direction.

**Final: 44 write-scope, 33 untrusted-content, 2 `contents: write`** — from 107,
50 and 6. The count rose from 40 to 44 on the last fix, which is the point: the
number is not the objective.

**Then the last refinement, and the one that separates the mitigation from the
vulnerability.** Everything above reads the *permissions block*. But the question
that decides the outcome is what the agent's `--allowedTools` patterns are bounded
to, and a `Bash(...)` entry is a command **prefix** — the grant ends at Claude
Code's `:*` wildcard, so whatever precedes it is the bound:

```
Bash(gh issue edit:*)                      the agent may edit any issue
Bash(gh issue edit 1234:*)                 bounded to that issue
Bash(gh issue edit ${{ ...number }}:*)     bounded to the input
```

The rule now distinguishes these, and the corpus validated it in **both
directions on real code**. `MHSanaei/3x-ui` writes every mutating pattern as
`Bash(gh issue edit ${{ github.event.issue.number }} --add-label:*)` and friends —
the Layer 1 mitigation from the guide, implemented properly — and is reported at
**`medium`** rather than `high`. `evcc-io/evcc` writes `gh issue edit:*` with a
wildcard opt-out and is reported **`high`**; so is `tokio-rs/toasty`.

That is also a cross-check worth noting: `evcc` was identified by hand, from
reading the two workflow files, and the rule was changed afterwards for unrelated
reasons — and it independently lands on the same repository and the same reason.
A rule and a person agreeing is not proof, but a rule that had disagreed would
have meant one of them was wrong.

The sweep also sizes the class, and the answer is worth stating plainly. Of 132
repositories running an agent with the opt-out set, the great majority grant only
`issues: write` or `pull-requests: write` and use it for what an issue-triage bot
is for — labelling and commenting. That is deliberate configuration, not a
vulnerability, and reporting the hundred-odd intended ones would be noise. Seven
also grant `contents: write`, and that is where the question is worth asking.

It also caught one. `anthropics/claude-code` — this rule's *origin* — sets
`claude_args: "--model claude-sonnet-4-5-20250929"`, which restricts the model,
not the tools. The first version of this check read `claude_args` as a tool
allowlist, found no mutating command inside it, and dropped the origin finding
from `high` to `low`. The fix reads only the flags that actually restrict tools.
Version `0.1.2` shipped that defect; `0.1.3` corrects it, and
`test_claude_args_carrying_only_a_model_is_not_a_tool_allowlist` holds it.

The match is kept rather than dropped because the residual is real: a steered
agent can still write a file that a later step posts, so an injection can
publish content or apply a label on the issue the attacker already controls.
Dropping the finding is indistinguishable from the rule having broken. When no
allowlist is readable the severity stays `high` — *cannot show the agent is
constrained* is not *constrained*, and assuming the safe case is how a rule goes
quiet on the workflows that need it.

`ci-agent-missing-author-association`@41 is also left at `critical`, and is the
one finding here that is **over-severe rather than false**: `auto-triage` is an
`issues`-triggered arm with no `author_association` check, which is exactly what
the rule describes, and it is the deliberate design of a public triage bot.

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
