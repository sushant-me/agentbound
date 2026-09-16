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
