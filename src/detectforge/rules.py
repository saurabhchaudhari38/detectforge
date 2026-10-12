"""Load and validate YAML detection rules."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import yaml

from .conditions import Predicate, RuleError, compile_condition, compile_selection
from .models import SEVERITIES

RULE_TYPES = ("single", "threshold", "sequence")
ALLOWED_KEYS = frozenset(
    {
        "id", "title", "description", "author", "date", "modified", "status", "severity",
        "tags", "references", "falsepositives", "logsource", "type", "detection",
        "threshold", "sequence", "tests",
    }
)
_DURATION_RE = re.compile(r"^\s*(\d+)\s*([smhd]?)\s*$")
_UNIT_SECONDS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}
_TECHNIQUE_RE = re.compile(r"^attack\.t(\d{4})(?:\.(\d{3}))?$", re.IGNORECASE)
_TACTIC_RE = re.compile(r"^attack\.([a-z_]+)$", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class ThresholdSpec:
    count: int
    window: timedelta
    group_by: tuple[str, ...]
    distinct: str | None = None


@dataclass(frozen=True, slots=True)
class SequenceStep:
    condition: str
    predicate: Predicate
    count: int = 1


@dataclass(frozen=True, slots=True)
class SequenceSpec:
    window: timedelta
    group_by: tuple[str, ...]
    steps: tuple[SequenceStep, ...]


@dataclass(frozen=True, slots=True)
class RuleTest:
    name: str
    events: list[dict[str, Any]]
    expect: int


@dataclass(slots=True)
class Rule:
    id: str
    title: str
    severity: str
    type: str
    description: str = ""
    author: str = ""
    status: str = "experimental"
    tags: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    logsource: dict[str, Any] = field(default_factory=dict)
    match: Predicate | None = None
    threshold: ThresholdSpec | None = None
    sequence: SequenceSpec | None = None
    tests: list[RuleTest] = field(default_factory=list)
    path: str = ""


@dataclass(slots=True)
class LoadResult:
    rules: list[Rule] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def parse_duration(value: Any) -> timedelta:
    """Accept ``90``, ``"90s"``, ``"5m"``, ``"2h"`` or ``"1d"``."""
    if isinstance(value, bool):
        raise RuleError(f"invalid duration {value!r}")
    if isinstance(value, (int, float)):
        seconds = float(value)
    else:
        match = _DURATION_RE.match(str(value))
        if not match:
            raise RuleError(f"invalid duration {value!r} (use e.g. 30s, 5m, 1h)")
        seconds = int(match.group(1)) * _UNIT_SECONDS[match.group(2)]
    if seconds <= 0:
        raise RuleError(f"duration must be positive, got {value!r}")
    return timedelta(seconds=seconds)


def _str_list(raw: Any, key: str) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list) and all(isinstance(x, (str, int, float)) for x in raw):
        return [str(x) for x in raw]
    raise RuleError(f"'{key}' must be a string or list of strings")


def _positive_int(raw: Any, key: str) -> int:
    if isinstance(raw, bool) or not isinstance(raw, int) or raw < 1:
        raise RuleError(f"'{key}' must be a positive integer")
    return raw


def attack_mapping(tags: list[str]) -> tuple[list[str], list[str]]:
    """Split ``attack.*`` tags into technique IDs and human-readable tactic names."""
    techniques: list[str] = []
    tactics: list[str] = []
    for tag in tags:
        if m := _TECHNIQUE_RE.match(tag):
            tid = f"T{m.group(1)}" + (f".{m.group(2)}" if m.group(2) else "")
            if tid not in techniques:
                techniques.append(tid)
        elif m := _TACTIC_RE.match(tag):
            name = m.group(1).replace("_", " ").title()
            if name not in tactics:
                tactics.append(name)
    return techniques, tactics


def build_rule(data: Any, path: str = "") -> Rule:
    if not isinstance(data, dict):
        raise RuleError("rule must be a YAML mapping")

    unknown = sorted(set(data) - ALLOWED_KEYS)
    if unknown:
        raise RuleError(f"unknown top-level key(s): {', '.join(unknown)}")

    for key in ("id", "title"):
        if not isinstance(data.get(key), str) or not data[key].strip():
            raise RuleError(f"'{key}' is required and must be a non-empty string")

    severity = str(data.get("severity", "")).lower()
    if severity not in SEVERITIES:
        raise RuleError(f"'severity' must be one of {', '.join(SEVERITIES)}")

    rule_type = str(data.get("type", "single")).lower()
    if rule_type not in RULE_TYPES:
        raise RuleError(f"'type' must be one of {', '.join(RULE_TYPES)}")

    detection = data.get("detection")
    if not isinstance(detection, dict):
        raise RuleError("'detection' is required and must be a mapping")
    selections = {
        str(name): compile_selection(str(name), spec)
        for name, spec in detection.items()
        if name != "condition"
    }
    if not selections:
        raise RuleError("'detection' must define at least one selection")

    tags = _str_list(data.get("tags"), "tags")
    techniques, tactics = attack_mapping(tags)
    logsource = data.get("logsource") or {}
    if not isinstance(logsource, dict):
        raise RuleError("'logsource' must be a mapping")

    rule = Rule(
        id=data["id"].strip(),
        title=data["title"].strip(),
        severity=severity,
        type=rule_type,
        description=str(data.get("description") or "").strip(),
        author=str(data.get("author") or ""),
        status=str(data.get("status") or "experimental"),
        tags=tags,
        techniques=techniques,
        tactics=tactics,
        references=_str_list(data.get("references"), "references"),
        falsepositives=_str_list(data.get("falsepositives"), "falsepositives"),
        logsource=logsource,
        path=path,
    )

    if rule_type == "sequence":
        if "threshold" in data:
            raise RuleError("'threshold' is not valid on a sequence rule")
        rule.sequence = _build_sequence(data.get("sequence"), selections)
    else:
        if "condition" not in detection:
            raise RuleError("'detection.condition' is required")
        rule.match = compile_condition(detection["condition"], selections)
        if "sequence" in data:
            raise RuleError("'sequence' is only valid when type is sequence")
        if rule_type == "threshold":
            rule.threshold = _build_threshold(data.get("threshold"))
        elif "threshold" in data:
            raise RuleError("'threshold' is only valid when type is threshold")

    rule.tests = _build_tests(data.get("tests"))
    return rule


def _build_threshold(raw: Any) -> ThresholdSpec:
    if not isinstance(raw, dict):
        raise RuleError("threshold rules need a 'threshold' mapping")
    extra = set(raw) - {"count", "window", "group_by", "distinct"}
    if extra:
        raise RuleError(f"unknown threshold key(s): {', '.join(sorted(extra))}")
    distinct = raw.get("distinct")
    if distinct is not None and not isinstance(distinct, str):
        raise RuleError("'threshold.distinct' must be a field name")
    return ThresholdSpec(
        count=_positive_int(raw.get("count"), "threshold.count"),
        window=parse_duration(raw.get("window")),
        group_by=tuple(_str_list(raw.get("group_by"), "threshold.group_by")),
        distinct=distinct,
    )


def _build_sequence(raw: Any, selections: dict[str, Predicate]) -> SequenceSpec:
    if not isinstance(raw, dict):
        raise RuleError("sequence rules need a 'sequence' mapping")
    extra = set(raw) - {"window", "group_by", "steps"}
    if extra:
        raise RuleError(f"unknown sequence key(s): {', '.join(sorted(extra))}")
    raw_steps = raw.get("steps")
    if not isinstance(raw_steps, list) or len(raw_steps) < 2:
        raise RuleError("'sequence.steps' must list at least two steps")
    steps = []
    for index, step in enumerate(raw_steps, 1):
        if not isinstance(step, dict) or "condition" not in step:
            raise RuleError(f"sequence step {index} needs a 'condition'")
        steps.append(
            SequenceStep(
                condition=str(step["condition"]),
                predicate=compile_condition(step["condition"], selections),
                count=_positive_int(step.get("count", 1), f"sequence step {index} count"),
            )
        )
    return SequenceSpec(
        window=parse_duration(raw.get("window")),
        group_by=tuple(_str_list(raw.get("group_by"), "sequence.group_by")),
        steps=tuple(steps),
    )


def _build_tests(raw: Any) -> list[RuleTest]:
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise RuleError("'tests' must be a list")
    tests = []
    for index, item in enumerate(raw, 1):
        if not isinstance(item, dict):
            raise RuleError(f"test {index} must be a mapping")
        events = item.get("events")
        if not isinstance(events, list) or not all(isinstance(e, dict) for e in events):
            raise RuleError(f"test {index} needs an 'events' list of mappings")
        expect = item.get("expect")
        if isinstance(expect, bool) or not isinstance(expect, int) or expect < 0:
            raise RuleError(f"test {index} needs 'expect' as a non-negative integer")
        tests.append(RuleTest(name=str(item.get("name") or f"test {index}"), events=events,
                              expect=expect))
    return tests


def iter_rule_files(paths: list[str | Path]) -> list[Path]:
    files: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            files.extend(sorted(p for p in path.rglob("*") if p.suffix in (".yml", ".yaml")))
        elif path.is_file():
            files.append(path)
        else:
            raise FileNotFoundError(f"rule path not found: {path}")
    return files


def load_rules(paths: list[str | Path]) -> LoadResult:
    """Load every rule under ``paths``; collect errors instead of stopping at the first."""
    result = LoadResult()
    seen: dict[str, str] = {}
    for file in iter_rule_files(paths):
        try:
            with file.open(encoding="utf-8") as handle:
                data = yaml.safe_load(handle)
            rule = build_rule(data, str(file))
        except (OSError, yaml.YAMLError, RuleError) as err:
            result.errors.append(f"{file}: {err}")
            continue
        if rule.id in seen:
            result.errors.append(f"{file}: duplicate rule id {rule.id!r} (also in {seen[rule.id]})")
            continue
        seen[rule.id] = str(file)
        result.rules.append(rule)
    return result
