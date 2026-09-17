"""Prose is not code: comments and docstrings must not trip a rule.

The rules are regexes over source text, so they can match a comment that
*describes* a pattern as easily as one that *is* the pattern. This project's own
CI contract made that concrete: `agentbound scan agentbound` must exit 0, and it
went red for three commits because `confirmation-gate-fails-open` matched the
comment block in `rules.py` documenting the very idiom it detects.

Both directions matter, and each has a different failure mode:

* a comment or docstring that trips a rule is a **false positive** — the same
  thing hits any user who explains the idiom they avoided;
* masking something a rule genuinely needs is a **false negative**, which is
  worse. `rule_tool_dict_last_wins` requires the word `duplicate` to appear in
  the logging call's message string, so string literals are data here and are
  not masked. That case is pinned below, because masking every string was the
  first version of the fix and it silently disabled that rule.
"""

from __future__ import annotations

from agentbound.engine import scan
from agentbound.masking import mask

# The real shape of the fail-open: a signature bound to a name, its parameters
# bound to another, and a filter reading the second.
_PATTERN_AS_CODE = """\
import inspect


def call(target, **kwargs):
    signature = inspect.signature(target)
    valid_params = signature.parameters.keys()
    return {k: v for k, v in kwargs.items() if k in valid_params}
"""

# The same three lines, as documentation. This is the block that broke CI.
_PATTERN_AS_COMMENT = """\
import inspect


def call(target, **kwargs):
    # The old shape was:
    #
    #     signature = inspect.signature(predicate)
    #     valid_params = signature.parameters.keys()
    #     {k: v for k, v in kwargs.items() if k in valid_params}
    return kwargs
"""

_PATTERN_AS_DOCSTRING = '''\
import inspect


def call(target, **kwargs):
    """The old shape was:

        signature = inspect.signature(predicate)
        valid_params = signature.parameters.keys()
        {k: v for k, v in kwargs.items() if k in valid_params}
    """
    return kwargs
'''

# A rule that needs a string literal, not only code.
_DUPLICATE_VIA_A_STRING_ARGUMENT = """\
import logging


def register(tools_dict, tool):
    logging.warning("Duplicate tool name %r", tool.name)
    tools_dict[tool.name] = tool
"""

# The same call, with the message in a docstring instead of an argument.
_DUPLICATE_ONLY_IN_A_DOCSTRING = '''\
import logging


def register(tools_dict, tool):
    """Warn with "Duplicate tool name" and then assign."""
    tools_dict[tool.name] = tool
'''


def _scan_one(tmp_path, name, body):
    (tmp_path / name).write_text(body, encoding="utf-8")
    return scan(str(tmp_path))


def test_the_pattern_as_code_is_still_a_finding(tmp_path):
    """The control. If masking were too aggressive, everything below passes
    vacuously."""
    findings = _scan_one(tmp_path, "code.py", _PATTERN_AS_CODE)
    assert [f.rule for f in findings] == ["confirmation-gate-fails-open"]


def test_the_pattern_in_a_comment_is_not_a_finding(tmp_path):
    """The regression: this is what turned the self-scan red."""
    assert _scan_one(tmp_path, "comment.py", _PATTERN_AS_COMMENT) == []


def test_the_pattern_in_a_docstring_is_not_a_finding(tmp_path):
    assert _scan_one(tmp_path, "docstring.py", _PATTERN_AS_DOCSTRING) == []


def test_a_string_argument_a_rule_needs_is_not_masked(tmp_path):
    """The false negative this fix nearly introduced.

    `tool-dict-last-wins` reads the logging call's message text, so the string
    literal is evidence. Masking every string in Python made this fixture go
    clean, which is worse than the false positive being fixed.
    """
    findings = _scan_one(tmp_path, "dup.py", _DUPLICATE_VIA_A_STRING_ARGUMENT)
    assert [f.rule for f in findings] == ["tool-dict-last-wins"]


def test_a_duplicate_named_only_in_a_docstring_is_not_a_finding(tmp_path):
    """The other side of the same distinction: prose about the message is not
    the message."""
    assert _scan_one(tmp_path, "dup_doc.py", _DUPLICATE_ONLY_IN_A_DOCSTRING) == []


def test_a_whole_line_yaml_comment_is_not_a_finding(tmp_path):
    """Workflows are the other language these rules read, and a commented-out
    block is the same hazard there."""
    body = (
        "name: ci\n"
        "on: [push]\n"
        "jobs:\n"
        "  a:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "#     - uses: google-github-actions/run-gemini-cli@v1\n"
        "#       with:\n"
        "#         prompt: ${{ github.event.issue.title }}\n"
        "      - run: echo hi\n"
    )
    assert _scan_one(tmp_path, "wf.yml", body) == []


def test_masking_keeps_every_line_number(tmp_path):
    """Offsets are preserved, so a reported line is the line on disk."""
    text = "a = 1  # comment\nb = 2\n"
    masked = mask("x.py", text)
    assert masked.count("\n") == text.count("\n")
    assert len(masked) == len(text)
    assert masked.splitlines()[1] == "b = 2"


def test_masking_does_not_blind_a_rule_to_code_after_a_comment(tmp_path):
    """Masking blanks characters in place rather than deleting lines, so the
    code that follows a masked block is still matched."""
    body = (
        "import inspect\n"
        "\n"
        "\n"
        "#     signature = inspect.signature(predicate)\n"
        "#     valid_params = signature.parameters.keys()\n"
        "def call(target, **kwargs):\n"
        "    signature = inspect.signature(target)\n"
        "    valid_params = signature.parameters.keys()\n"
        "    return {k: v for k, v in kwargs.items() if k in valid_params}\n"
    )
    findings = _scan_one(tmp_path, "mixed.py", body)
    assert [f.rule for f in findings] == ["confirmation-gate-fails-open"]
    assert findings[0].line == 7
