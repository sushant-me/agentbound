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
| `microsoft/agent-framework` | 0 | — | — |
| `langchain-ai/langchain` | 2 | 2 | 0 |
| `pydantic/pydantic-ai` | 0 | — | — |
| `openai/openai-agents-python` | 0 | — | — |
| `langchain-ai/langgraph` | 0 | — | — |
| `run-llama/llama_index` | 0 | — | — |
| `crewAIInc/crewAI` | 0 | — | — |
| `microsoft/autogen` | 0 | — | — |
| `modelcontextprotocol/python-sdk` | 0 | — | — |
| `All-Hands-AI/OpenHands` | 0 | — | — |
| `Significant-Gravitas/AutoGPT` | 0 | — | — |

**15 production findings after the fixes below, and every one is verified true.**
(The first run reported 19. v0.1.14 removed two false ones, v0.1.15 the other two.
Precision on this sample went 15/19 = 0.79 to 15/15 = 1.00, with no true positive lost.) Every false one was
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

### 1. `pydantic-ai` `ci-agent-missing-author-association` — CRITICAL, and wrong — **FIXED in v0.1.15**

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

### 2. `microsoft/agent-framework` `confirmation-gate-fails-open` — HIGH, twice — **FIXED in v0.1.14**

`_utils.py:354` and `:733`. The rule fires on `inspect.signature(...)` in the
belief that a confirmation predicate is being introspected. Both are in
`generate_schema_from_serialization_mixin(cls)`, whose job is to build a **JSON
schema** from a dataclass. Annotated types, not a security predicate.

### 3. `microsoft/agent-framework` `guard-name-normalization-asymmetry` — MEDIUM — **FIXED in v0.1.15**

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


---

## v0.1.14 — what was fixed, and how it was measured

Both `confirmation-gate-fails-open` false positives came from the **same defect
class** as the v0.1.13 fix: a rule reading locally, with no requirement that the
things it correlates belong together.

**Two causes, both confirmed in the code:**

1. **Cross-function correlation.** The three patterns — `x = inspect.signature(y)`,
   `valid = x.parameters`, and a comprehension filtering on `valid` — were matched
   anywhere in the file. In `agent-framework` a *schema generator* called
   `inspect.signature(cls)` and an *unrelated* dict comprehension elsewhere filtered
   a set called `valid_params`. The rule joined them into one finding.
   **Fix:** the three matches must now fall within `_GATE_WINDOW = 1200` characters.
   The reference true positive spans ~110; a module spans tens of thousands.

2. **A regex anchored on a string literal.** Line 733's remaining finding came from
   `_DICT_FILTER_USING_RE`, whose pattern began `\{[^{}]*?\bfor\b…`. That matched the
   `{` inside `input_str.strip().startswith("{")` and then spanned **thirteen lines**
   to an unrelated `for field in common_fields:` / `if field in params:` loop. A loop
   with a membership test is not a dict comprehension.
   **Fix:** the `{` must now open a real comprehension — `\{\s*[A-Za-z_]\w*\s*:` — so
   the key expression has to follow immediately.

**Measured effect:**

| | before v0.1.14 | after |
|---|---|---|
| `microsoft/agent-framework` production findings | 3 | **1** |
| total across the 14-framework survey | 19 | **17** |
| `google/adk-python` production findings | 3 | **3** — unchanged, the gate is still found |
| tests | 137 | **139** |

Two regression tests carry the real shapes: a schema generator beside an unrelated
filter, and the `startswith("{")` deserialization path. Neither can return silently.

**Still open, and next:** `ci-agent-missing-author-association` (evaluate the whole
`if:` expression, not the arm's line) and `guard-name-normalization-asymmetry`
(require the normalized set and the membership test to be the same identifier).


---

## v0.1.15 — the remaining two false positives

**`ci-agent-missing-author-association` (reported CRITICAL on pydantic-ai).** The
rule splits an `if:` on `||` and asks whether *the arm* carries the check. That is
right for the dispatcher shape it was written for and wrong for the shape
pydantic-ai uses, which wraps every arm in one group and chains the gate onto the
group:

```yaml
      (
        (github.event_name == 'issue_comment' && ...) ||
        (github.event_name == 'issues' && ...)
      ) && contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'),
             github.event.comment.author_association || ...)
```

`(A || B) && gate` gates A and B alike, but no arm segment contains `gate`.
**Fix:** if a `)` closes a group that *contains* the arm and an `&&` carrying the
needle follows it, the arm is gated. Two things had to be right and the first
attempt got both wrong: it depended on `_if_block_span`, which returns `None` for
this file, and it stopped at the first enclosing `)` — which is the arm's own
wrapper, not the gated group. It now walks the raw text and continues outwards
through nested groups.

**`guard-name-normalization-asymmetry` (reported MEDIUM on agent-framework).**
`_guarded_names` scanned back 600 characters from *any* `.strip()` and accepted a
`set(...)` constructor found in that window. In `_skills.py` it paired
`seen_names: set[str] = set()` — a dedup accumulator — with a stray `.strip()` a
dozen lines later, and reported `if skill.frontmatter.name in seen_names:` (a
duplicate check) as a security guard.
**Fix:** the normalization must fall *inside* the constructor's own parentheses.
That is what separates `frozenset(x.strip() for x in ...)` from a `set()` that
merely happens to be nearby.

**Final measurement:**

| | first run | v0.1.14 | v0.1.15 |
|---|---|---|---|
| total production findings | 19 | 17 | **15** |
| verified true | 15 | 15 | **15** |
| verified false | 4 | 2 | **0** |
| precision on this sample | 0.79 | 0.88 | **1.00** |
| tests | 129 | 139 | **140** |

**No true positive was lost at any step.** `google/adk-python` still reports its 3
(including the real gate), `langchain` still reports its 2, and `adk-go`/`adk-java`
are unchanged. That is the check that the fixes narrowed the rules rather than
silenced them.
