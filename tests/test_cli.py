from __future__ import annotations

import json

from detectforge.cli import main


def _scan(root, *extra):
    return main(["scan", "-r", str(root / "rules"), "--year", "2026", "--no-color",
                 str(root / "samples" / "auth.log"),
                 str(root / "samples" / "endpoint_events.jsonl"), *extra])


def test_scan_samples_detects_attack_chain(root, capsys):
    assert _scan(root, "--output", "json") == 0
    alerts = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    fired = {a["rule_id"] for a in alerts}
    assert fired == {
        "DF-LNX-001", "DF-LNX-002", "DF-LNX-003", "DF-LNX-004", "DF-LNX-005", "DF-LNX-006",
        "DF-LNX-007", "DF-WIN-001", "DF-WIN-002", "DF-WIN-003", "DF-WIN-004", "DF-WIN-005",
    }
    assert len(alerts) == len(fired)  # no duplicate alerts for one burst
    timestamps = [a["last_seen"] for a in alerts]
    assert timestamps == sorted(timestamps)


def test_scan_fail_on_and_min_severity(root, capsys):
    assert _scan(root, "--fail-on", "critical") == 1
    capsys.readouterr()
    assert _scan(root, "--min-severity", "critical", "--output", "json") == 0
    alerts = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert {a["severity"] for a in alerts} == {"critical"}


def test_scan_navigator_layer(root, tmp_path):
    out = tmp_path / "layer.json"
    assert _scan(root, "--output", "navigator", "-o", str(out)) == 0
    layer = json.loads(out.read_text())
    ids = {t["techniqueID"] for t in layer["techniques"]}
    assert {"T1110.001", "T1003.001", "T1059.001"} <= ids
    assert layer["domain"] == "enterprise-attack"


def test_console_output(root, capsys):
    assert _scan(root) == 0
    out = capsys.readouterr().out
    assert "[CRITICAL] DF-LNX-003" in out
    assert "source.ip=203.0.113.50" in out
    assert "host=WS-0142" in out
    assert "12 alert(s) from 12 rule(s) across 43 event(s)" in out


def test_validate_and_test_commands(root, capsys):
    assert main(["validate", str(root / "rules")]) == 0
    assert main(["test", str(root / "rules")]) == 0
    assert "0 failed" in capsys.readouterr().out


def test_missing_input_is_an_error(root, tmp_path):
    assert main(["scan", "-r", str(root / "rules"), str(tmp_path / "nope.log")]) == 2
