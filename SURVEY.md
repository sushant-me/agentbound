# Survey: agentbound against 14 real agent frameworks

*Run 2026-09-28. Every finding below was opened and read in the source before it was
graded. A finding that is not verified in the file is not a finding.*

---

## Why this exists

The corpus in `tool-boundary-corpus` is 23 labelled cases and the README reports
precision 1.000 against it. **I wrote that corpus**, so it contains the mistakes I
had already thought of. This is the opposite kind of input: repositories written by
other people, for other reasons, with no knowledge that a detector would read them.

It changed the answer twice.

## The result

| framework | production findings | verified true | verified false |
|---|---|---|---|
| `google/adk-python` | 3 | 3 | 0 |
| `google/adk-go` | 2 | 2 | 0 |
| `google/adk-java` | 8 | 8 | 0 |
| `microsoft/agent-framework` | 3 | 0 | **3** |
| `langchain-ai/langchain` | 2 | 2 | 0 |
| `pydantic/pydantic-ai` | 1 | 0 | **1** |
| `openai/openai-agents-python` | 0 | — | — |
| `langchain-ai/langgraph` | 0 | — | — |
| `run-llama/llama_index` | 0 | — | — |
| `crewAIInc/crewAI` | 0 | — | — |
| `microsoft/autogen` | 0 | — | — |
| `modelcontextprotocol/python-sdk` | 0 | — | — |
| `All-Hands-AI/OpenHands` | 0 | — | — |
| `Significant-Gravitas/AutoGPT` | 0 | — | — |

**19 production findings. 15 verified true, 4 verified false.** Every false one was
a claim I would otherwise have made in public about somebody else's code.

**How each row was verified, precisely — because "true" means different things
here:**

- **`adk-python` (3)** — each finding opened in the file. True.
- **`langchain` (2)** — the normalized set at line 188 and the raw membership test
  at line 223 read directly. True.
- **`adk-go` (2) and `adk-java` (8)** — these are `tool-inmodel-name-unoccupied`
  on the in-model built-ins, and they are **corroborated rather than line-checked**:
  they are the same names the open upstream fixes `adk-go#1606` (14/14) and
  `adk-java#1515` (13/13) were written to cover. Strong evidence, not the same as
  reading each of the ten. Marked that way on purpose.
- **The four false positives** — each opened and disproved in the file, below.

## The four false positives, and what they have in common

### 1. `pydantic-ai` `ci-agent-missing-author-association` — CRITICAL, and wrong

`.github/workflows/at-claude.yml:28`. The rule reports an `issues`-triggered
dispatch arm with no `author_association` check. The check is there, on the **lines
immediately below**:

```yaml
      ) && contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'),
        github.event.comment.author_association ||
        github.event.review.author_association ||
        github.event.issue.author_association)
```

Line 28 is the `issues` arm *inside* a single multi-line `if:` expression; lines
29–32 are its guard. The rule read the arm and stopped. The workflow also sets
`permissions: {}` at the top level, which is the hardened shape, not the vulnerable
one.

**This is the same shape as the bug fixed in v0.1.13** — a rule keying on a line
and missing the structure around it — in a different rule.

### 2. `microsoft/agent-framework` `confirmation-gate-fails-open` — HIGH, twice

`_utils.py:354` and `:733`. The rule fires on `inspect.signature(...)` in the
belief that a confirmation predicate is being introspected. Both are in
`generate_schema_from_serialization_mixin(cls)`, whose job is to build a **JSON
schema** from a dataclass. Annotated types, not a security predicate.

### 3. `microsoft/agent-framework` `guard-name-normalization-asymmetry` — MEDIUM

`_skills.py:4860`. The rule pairs a `.strip()` with an `in` membership test. Here
the `.strip()` is `if not name or not name.strip():` — a non-empty validation — and
the membership test is `if skill.frontmatter.name in seen_names:` — a **duplicate
name check** when loading skills. Neither is a guard, and they are not the same
check.

## The true positive worth naming

`langchain-ai/langchain`, `.../typesafe/experimental/middleware/auto_mode.py`.
The protected set is built normalized and the incoming name is tested raw:

```python
# line 188 -- the set is built with .strip()
(tool if isinstance(tool, str) else tool.name).strip()

# line 223 -- the incoming name is NOT stripped
if request.tool_call["name"] not in self._tool_names:
    return handler(request)
```

A tool name with surrounding whitespace fails the membership test and falls
straight through to `handler(request)`, bypassing the risk classifier entirely.
That is exactly the asymmetry the rule describes, in the direction that fails open.

## What this says

**Precision is per-rule, and fixing one rule says nothing about the others.**
v0.1.13 took `tool-reserved-name-shadowing` from 0.14 to 1.00 on `adk-python`. Two
other rules still sit near zero on this sample, and the README's headline number
does not distinguish them.

**Three of the four false positives are the same defect as the one just fixed:** a
rule that reads locally and cannot see the structure it is judging. A YAML `if:`
spanning five lines; a `signature()` call inside a function whose name says
`schema`; a `strip()` eight lines from a `dedup` set. The v0.1.13 fix narrowed one
rule's *pattern*. It did not give any rule the ability to read context.

**Do not publish unverified findings.** These four were available, wrong, and would
have been stated about Microsoft's, Pydantic's and Google's code by name.

## Next

The honest ordering, since none of this is fixed yet:

1. `confirmation-gate-fails-open` — scope the `inspect.signature` match to a
   function that is actually a gate, or drop the rule to `low` until it can.
2. `ci-agent-missing-author-association` — evaluate the whole `if:` expression
   rather than the arm's line.
3. `guard-name-normalization-asymmetry` — require the normalized set and the
   membership test to be the same identifier, and the set to be built for a
   security decision.

Until those land, the per-rule precision is what the README should report, not one
number for the tool.
