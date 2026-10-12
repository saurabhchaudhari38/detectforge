"""Run the unit tests embedded in each rule file (detection-as-code CI)."""

from __future__ import annotations

from dataclasses import dataclass

from .engine import Engine
from .parsers import ParseError, event_from_mapping
from .rules import Rule


@dataclass(slots=True)
class TestOutcome:
    __test__ = False  # not a pytest test class

    rule_id: str
    name: str
    passed: bool
    detail: str = ""


def run_rule_tests(rule: Rule) -> list[TestOutcome]:
    outcomes = []
    for test in rule.tests:
        try:
            events = sorted(
                (event_from_mapping(e, f"{rule.id}:{test.name}") for e in test.events),
                key=lambda e: e.timestamp,
            )
        except ParseError as err:
            outcomes.append(TestOutcome(rule.id, test.name, False, f"bad test event: {err}"))
            continue
        fired = len(list(Engine([rule]).run(events)))
        passed = fired == test.expect
        detail = "" if passed else f"expected {test.expect} alert(s), got {fired}"
        outcomes.append(TestOutcome(rule.id, test.name, passed, detail))
    return outcomes
