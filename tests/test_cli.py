"""Tests for the CLI contract.

The exit code is the product. `agentbound scan` is documented as a CI gate —
"Exit code is 1 when findings exist, so it can gate CI" — which means a
regression that made it always return 0 would turn every user's gate into a
no-op while every existing test stayed green. The scanner's detection is covered
by test_rules.py; what is covered here is the wiring between detection and the
process exit status, in both directions.

The dirty fixture is deliberately tiny. It is the smallest file that trips
`tool-dict-last-wins`: a tool dict assigned on a name key, with duplicates
reported only through `logging.warning`.
"""

from __future__ import annotations

import json

from agentbound.cli import main

DIRTY = """\
import logging


def register(tools_dict, tool):
    logging.warning("Duplicate tool name %r", tool.name)
    tools_dict[tool.name] = tool
"""

CLEAN = "x = 1\n"


def _tree(tmp_path, sweep, body):
    (tmp_path / sweep).write_text(body, encoding="utf-8")
    return str(tmp_path)


def test_a_clean_tree_exits_zero(tmp_path):
    assert main(["scan", _tree(tmp_path, "ok.py", CLEAN)]) == 0


def test_findings_exit_one(tmp_path):
    assert main(["scan", _tree(tmp_path, "dup.py", DIRTY)]) == 1


def test_clean_tree_with_json_exits_zero_and_prints_an_empty_list(tmp_path, capsys):
    rc = main(["scan", _tree(tmp_path, "ok.py", CLEAN), "--json"])
    assert json.loads(capsys.readouterr().out) == []
    assert rc == 0


def test_findings_with_json_still_exit_one(tmp_path, capsys):
    """--json must not become a second code path with its own exit behaviour."""
    rc = main(["scan", _tree(tmp_path, "dup.py", DIRTY), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 1
    assert [f["rule"] for f in payload] == ["tool-dict-last-wins"]
    assert payload[0]["severity"] == "medium"


def test_the_fixture_only_trips_the_expected_rule(tmp_path):
    """Guards the tests above: if the fixture drifted, they could pass vacuously."""
    from agentbound.engine import scan

    findings = scan(_tree(tmp_path, "dup.py", DIRTY))
    assert [f.rule for f in findings] == ["tool-dict-last-wins"]


def test_a_clean_fixture_produces_no_findings(tmp_path):
    from agentbound.engine import scan

    assert scan(_tree(tmp_path, "ok.py", CLEAN)) == []


# --- --fail-on ---------------------------------------------------------------
#
# The rule set grew `low` and `medium` tiers for the residual cases it reports
# deliberately - a bounded tool pattern, a grant that belongs to a later step.
# Failing a build on those by default would make the tool unusable as a gate,
# and *not* offering a threshold would have left users to grep the JSON. The
# default is `low`, which keeps the original "exit 1 when findings exist"
# contract exactly.

DIRTY_SEVERITY = "medium"


def test_the_dirty_fixture_still_trips_at_medium(tmp_path):
    """Guards the threshold tests below against the fixture drifting upward."""
    payload = _findings(tmp_path)
    assert [f["severity"] for f in payload] == [DIRTY_SEVERITY]


def _findings(tmp_path):
    from agentbound.engine import scan

    return [f.to_dict() for f in scan(_tree(tmp_path, "dup.py", DIRTY))]


def test_fail_on_defaults_to_any_finding(tmp_path):
    assert main(["scan", _tree(tmp_path, "dup.py", DIRTY)]) == 1


def test_fail_on_medium_still_catches_a_medium_finding(tmp_path):
    assert main(["scan", _tree(tmp_path, "dup.py", DIRTY), "--fail-on", "medium"]) == 1


def test_fail_on_high_ignores_a_medium_finding(tmp_path):
    assert main(["scan", _tree(tmp_path, "dup.py", DIRTY), "--fail-on", "high"]) == 0


def test_fail_on_none_reports_without_failing(tmp_path, capsys):
    assert main(["scan", _tree(tmp_path, "dup.py", DIRTY), "--fail-on", "none"]) == 0
    # ...but it still reports. `none` is not a silencer.
    assert "tool-dict-last-wins" in capsys.readouterr().out


def test_no_threshold_fails_a_clean_tree(tmp_path):
    for threshold in ("low", "medium", "high", "critical", "none"):
        assert (
            main(["scan", _tree(tmp_path, "ok.py", CLEAN), "--fail-on", threshold])
            == 0
        )


def test_severity_threshold_ordering():
    from agentbound.cli import _at_or_above
    from agentbound.findings import Finding

    def f(severity):
        return Finding(rule="r", severity=severity, path="p", line=1, message="m")

    assert _at_or_above(f("critical"), "high")
    assert _at_or_above(f("high"), "high")
    assert not _at_or_above(f("medium"), "high")
    assert not _at_or_above(f("low"), "high")
    assert _at_or_above(f("low"), "low")
    assert not _at_or_above(f("critical"), "none")
    # An unrecognised severity on either side fails rather than passing quietly:
    # a rule that starts emitting a novel severity must not stop gating builds.
    assert _at_or_above(f("novel"), "high")
    assert _at_or_above(f("high"), "novel")


# --- exit 2: an unreadable input is not a clean scan -------------------------
#
# The documented contract is `0` clean, `1` findings, `2` unreadable input. The
# third was never implemented: a typo'd path walked nothing, found nothing, and
# exited 0, so a misspelled directory produced a clean bill of health. That is
# the failure this whole project exists to write about, in the tool itself.


def test_a_missing_path_exits_two_not_zero(tmp_path, capsys):
    rc = main(["scan", str(tmp_path / "does-not-exist")])
    assert rc == 2
    assert "no such path" in capsys.readouterr().err


def test_a_missing_path_is_not_reported_as_clean(tmp_path):
    """The distinction that matters: 2 must not be 0."""
    assert main(["scan", str(tmp_path / "nope")]) != 0


def test_a_single_file_path_is_scanned_not_ignored(tmp_path):
    """`rglob` over a file path yields nothing, so this used to report clean by
    reading nothing at all."""
    (tmp_path / "dup.py").write_text(DIRTY, encoding="utf-8")
    rc = main(["scan", str(tmp_path / "dup.py")])
    assert rc == 1


def test_a_single_clean_file_exits_zero(tmp_path):
    (tmp_path / "ok.py").write_text(CLEAN, encoding="utf-8")
    assert main(["scan", str(tmp_path / "ok.py")]) == 0


def test_fail_on_none_still_rejects_a_missing_path(tmp_path):
    """`none` silences findings, not errors."""
    assert main(["scan", str(tmp_path / "nope"), "--fail-on", "none"]) == 2
