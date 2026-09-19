"""Blank out comments and docstrings before a pattern rule sees them.

The rules are regexes over source text, and source text contains three kinds of
bytes: code that executes, comments that do not, and prose in a docstring that
does not execute either. Only the first can contain the behaviour a rule is
looking for, so matching the others reports findings against documentation.

That is not hypothetical. This project's own CI contract is that
`agentbound scan agentbound` exits 0, because the package source is clean. It
went red for three commits because `confirmation-gate-fails-open` matched the
comment block in `rules.py` that documents the pattern:

    144: #     signature = inspect.signature(predicate)     # name was required
    145: #     valid_params = signature.parameters.keys()   # name was required
    146: #     {k: v for k, v in kwargs.items() if k in valid_params}

Every matched line was a comment. The same thing happens to any user who writes
a comment or a docstring explaining the idiom they avoided, which is exactly the
kind of codebase a reader of this tool tends to have.

**Not all strings are prose.** `rule_tool_dict_last_wins` requires the word
`duplicate` to appear in the argument of a logging call - the message text is
the evidence - so masking every string literal in Python hides the finding that
rule exists to make. Masking all of them was the first version of this module,
and the repo's `CLI contract - findings exit 1` step caught it immediately by
going green on a fixture that must stay red. A false negative is worse than the
false positive being fixed.

So Python is parsed with `tokenize` and only two things are blanked:

* every `COMMENT` token,
* a `STRING` token that is a statement by itself - a docstring, and
* a `STRING` token that is the entire right-hand side of an assignment - a constant
  holding documentation or an example.

A string that is an *argument* is data and is left alone. Anything unparseable
is returned raw rather than skipped.

Every other language masks whole-line comments only (`#` or `//` at the start of
a line, after optional whitespace). A trailing-comment form is not attempted:
finding the `#` or `//` that is neither a URL nor inside a quoted scalar needs a
parser this project does not have, and guessing would mask real configuration. A
whole-line comment cannot be inside a scalar, so the conservative rule is safe in
the direction that matters - it never hides executable behaviour.

Masking replaces the masked characters with spaces, so every remaining byte keeps
its original offset and line number. A rule that reports line 144 still means
line 144 of the file on disk.
"""

from __future__ import annotations

import io
import tokenize

# Extensions whose comments start with `//`.
_SLASH_COMMENT_EXTS = {".ts", ".tsx", ".js", ".jsx", ".go", ".java"}

# Tokens that carry no syntax of their own, ignored when asking whether a string
# is a statement by itself.
_TRIVIA = frozenset({
    tokenize.NL, tokenize.COMMENT, tokenize.INDENT, tokenize.DEDENT,
    tokenize.ENCODING,
})


def _line_offsets(text: str) -> list[int]:
    """Absolute offset of the start of each line."""
    offsets = []
    position = 0
    for line in text.splitlines(keepends=True):
        offsets.append(position)
        position += len(line)
    return offsets


def _prose_string_indexes(tokens: list[tokenize.TokenInfo]) -> set[int]:
    """Indexes of STRING tokens that are prose rather than a value passed to code.

    Two shapes count as prose:

    * a string expression nothing is done with - a docstring; and
    * a string that is the **entire right-hand side of an assignment** - a module or
      class constant holding documentation, an example, or a message template.

    The second case is here because of a real false positive. `tool-dict-last-wins`
    fired on

        DOCSTRING = \"\"\"
            if tool.name in self.tools_dict:
                logger.warning("duplicate")
            self.tools_dict[tool.name] = tool
        \"\"\"

    at the line inside the string. That file is documentation - untaken string content
    is no more executable than a comment - and the previous rule only recognised a
    *bare* string statement, not one bound to a name.

    A string that is an argument is still left alone, because that is where the
    logging message a rule reads as evidence lives. Only a direct assignment value is
    masked; a string inside `frozenset({...})` or `{"a", "b"}` has a bracket or a comma
    before it and is untouched, which is what keeps the reserved-set rules working.
    """
    significant = [
        (index, token) for index, token in enumerate(tokens)
        if token.type not in _TRIVIA
    ]
    ends_statement = (None, tokenize.NEWLINE, tokenize.ENDMARKER)
    starts_statement = (None, tokenize.NEWLINE, tokenize.INDENT)

    found: set[int] = set()
    for position, (index, token) in enumerate(significant):
        if token.type != tokenize.STRING:
            continue
        before = significant[position - 1][1] if position else None
        after = significant[position + 1][1] if position + 1 < len(significant) else None
        if after is not None and after.type not in ends_statement:
            continue  # a value in a larger expression, not a whole one
        if before is None or before.type in starts_statement:
            found.add(index)  # a docstring
        elif before.type == tokenize.OP and before.string == "=":
            found.add(index)  # a module / class constant, e.g. a documentation block
    return found


def _mask_python(text: str) -> str:
    """Blank comments and docstrings, keeping offsets and line breaks."""
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
        # Unparseable Python is not a reason to skip a file; scan it raw.
        return text

    offsets = _line_offsets(text)

    def absolute(row: int, column: int) -> int:
        # tokenize can report a position one past the last line.
        if row - 1 >= len(offsets):
            return len(text)
        return min(offsets[row - 1] + column, len(text))

    prose = _prose_string_indexes(tokens)

    masked = list(text)
    for index, token in enumerate(tokens):
        if token.type == tokenize.COMMENT or (
            token.type == tokenize.STRING and index in prose
        ):
            for position in range(absolute(*token.start), absolute(*token.end)):
                if masked[position] != "\n":
                    masked[position] = " "
    return "".join(masked)


def _mask_whole_line_comments(text: str, marker: str) -> str:
    """Blank lines whose first non-space character begins a comment."""
    out = []
    for line in text.splitlines(keepends=True):
        if line.lstrip().startswith(marker):
            out.append("".join("\n" if ch == "\n" else " " for ch in line))
        else:
            out.append(line)
    return "".join(out)


def mask(path: str, text: str) -> str:
    """Return `text` with the parts of it that cannot execute blanked out."""
    lower = path.lower()
    if lower.endswith(".py"):
        return _mask_python(text)
    if lower.endswith((".yml", ".yaml")):
        return _mask_whole_line_comments(text, "#")
    if any(lower.endswith(ext) for ext in _SLASH_COMMENT_EXTS):
        return _mask_whole_line_comments(text, "//")
    return text
