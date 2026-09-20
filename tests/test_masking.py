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


# A documentation block held in a module constant: prose bound to a name rather than a
# bare string statement. Reported by `tool-boundary-corpus` case
# `code-pattern-only-in-comments`, which is a corpus of labelled tool-boundary cases that
# measures this detector's precision.
_PATTERN_IN_AN_ASSIGNED_STRING = '''\
DOCSTRING = """
    if tool.name in self.tools_dict:
        logger.warning("duplicate")
    self.tools_dict[tool.name] = tool
"""


def explain() -> str:
    """Describe the anti-pattern without performing it."""
    return DOCSTRING
'''


def test_the_pattern_in_an_assigned_string_is_not_a_finding(tmp_path):
    """A string bound to a name is documentation too.

    The rule previously recognised a *bare* string statement (a docstring) as prose but
    not one assigned to a variable, so a module constant holding an example was scanned
    as if it were code. Untaken string content is no more executable than a comment.
    """
    assert _scan_one(tmp_path, "assigned.py", _PATTERN_IN_AN_ASSIGNED_STRING) == []


def test_an_assigned_string_does_not_hide_the_pattern_in_real_code(tmp_path):
    """The control: masking prose must not blind the rule to code in the same file."""
    body = _PATTERN_IN_AN_ASSIGNED_STRING + (
        "\n\ndef register(tools_dict, tool):\n"
        '    logger.warning("duplicate tool name")\n'
        "    tools_dict[tool.name] = tool\n"
    )
    findings = _scan_one(tmp_path, "both.py", body)
    assert [f.rule for f in findings] == ["tool-dict-last-wins"]
    assert findings[0].line > 10, "the finding must be the code, not the constant"


def test_a_set_literal_is_still_visible_to_the_reserved_set_rule(tmp_path):
    """Only a direct assignment value is prose. Strings inside a literal are data the
    reserved-set rules read, and masking them would be a false negative."""
    body = (
        "_RESERVED_TOOL_NAMES = {\n"
        '    "finish",\n'
        '    "transfer_to_agent",\n'
        "}\n"
        "\n"
        "\n"
        "def set_model_response(response: str) -> dict:\n"
        "    return {'response': response}\n"
    )
    findings = _scan_one(tmp_path, "reserved.py", body)
    assert "tool-reserved-name-shadowing" in [f.rule for f in findings]


def test_a_message_extracted_into_a_constant_is_still_a_finding(tmp_path):
    """Masking every assignment value erased executable evidence.

    A one-line constant is how real code carries a message, and blanking it deleted the very
    word the rule matches on:

        MSG = "duplicate tool name, overwriting"
        logging.warning(MSG)

    became an assignment with a blank value and a warning call with nothing left to find, so
    the finding disappeared. That is a false NEGATIVE, which this module's own docstring calls
    worse than the false positive the masking exists to remove. Only a multi-line block - what
    a documentation constant actually looks like - is prose.
    """
    body = (
        "import logging\n"
        "\n"
        'MSG = "duplicate tool name, overwriting"\n'
        "\n"
        "\n"
        "def register(tools_dict, tool):\n"
        "    if tool.name in tools_dict:\n"
        "        logging.warning(MSG)\n"
        "    tools_dict[tool.name] = tool\n"
    )
    findings = _scan_one(tmp_path, "refactored.py", body)
    assert [f.rule for f in findings] == ["tool-dict-last-wins"]


def test_a_multi_line_assigned_block_is_still_masked(tmp_path):
    """The control: the false positive the masking was written to remove stays removed."""
    body = (
        'DOCSTRING = """\n'
        "    if tool.name in self.tools_dict:\n"
        '        logger.warning("duplicate")\n'
        "    self.tools_dict[tool.name] = tool\n"
        '"""\n'
    )
    assert _scan_one(tmp_path, "docs.py", body) == []
