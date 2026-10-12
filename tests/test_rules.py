from __future__ import annotations

from datetime import timedelta

import pytest

from detectforge.conditions import RuleError
from detectforge.rules import attack_mapping, build_rule, load_rules, parse_duration
from detectforge.testing import run_rule_tests

VALID = {
    "id": "X-1",
    "title": "t",
    "severity": "low",
    "detection": {"sel": {"a": 1}, "condition": "sel"},
}


def with_(**changes):
    rule = dict(VALID)
    rule.update(changes)
    return rule


@pytest.mark.parametrize(
    ("value", "seconds"), [(30, 30), ("45s", 45), ("5m", 300), ("2h", 7200), ("1d", 86400)]
)
def test_parse_duration(value, seconds):
    assert parse_duration(value) == timedelta(seconds=seconds)


@pytest.mark.parametrize("value", [0, -5, "5x", "", True, None])
def test_parse_duration_rejects(value):
    with pytest.raises(RuleError):
        parse_duration(value)


def test_attack_mapping():
    techniques, tactics = attack_mapping(
        ["attack.t1110", "attack.T1110.001", "attack.credential_access", "custom.tag",
         "attack.t1110"]
    )
    assert techniques == ["T1110", "T1110.001"]
    assert tactics == ["Credential Access"]


@pytest.mark.parametrize(
    "bad",
    [
        with_(id=""),
        with_(severity="urgent"),
        with_(type="fuzzy"),
        with_(detection={"condition": "sel"}),
        with_(detection={"sel": {"a": 1}}),
        with_(detection={"sel": {"a": 1}, "condition": "other"}),
        with_(colour="red"),
        with_(type="threshold"),
        with_(type="threshold", threshold={"count": 0, "window": "1m"}),
        with_(type="threshold", threshold={"count": 2, "window": "1m", "bogus": 1}),
        with_(threshold={"count": 2, "window": "1m"}),
        with_(type="sequence", sequence={"window": "1m", "steps": [{"condition": "sel"}]}),
        with_(tests=[{"events": [], "expect": -1}]),
        "not a mapping",
    ],
)
def test_invalid_rules_are_rejected(bad):
    with pytest.raises(RuleError):
        build_rule(bad)


def test_load_rules_reports_errors_and_duplicates(tmp_path):
    (tmp_path / "a.yml").write_text("id: A\ntitle: a\nseverity: low\n"
                                    "detection: {s: {x: 1}, condition: s}\n")
    (tmp_path / "dup.yml").write_text("id: A\ntitle: dup\nseverity: low\n"
                                      "detection: {s: {x: 1}, condition: s}\n")
    (tmp_path / "broken.yaml").write_text("id: [unclosed\n")
    (tmp_path / "notes.txt").write_text("ignored")
    result = load_rules([tmp_path])
    assert [r.id for r in result.rules] == ["A"]
    assert len(result.errors) == 2
    assert any("duplicate rule id" in e for e in result.errors)


def test_bundled_rules_load_and_pass_their_tests(root):
    result = load_rules([root / "rules"])
    assert result.errors == []
    assert len(result.rules) >= 10
    for rule in result.rules:
        assert rule.techniques, f"{rule.id} has no ATT&CK technique"
        assert rule.tests, f"{rule.id} has no embedded tests"
        failures = [o for o in run_rule_tests(rule) if not o.passed]
        assert not failures, f"{rule.id}: {[(f.name, f.detail) for f in failures]}"


def test_failing_rule_test_is_reported():
    rule = build_rule(with_(tests=[{"name": "wrong", "expect": 2,
                                    "events": [{"@timestamp": "2026-10-12T00:00:00Z", "a": 1}]}]))
    [outcome] = run_rule_tests(rule)
    assert not outcome.passed
    assert "expected 2" in outcome.detail
