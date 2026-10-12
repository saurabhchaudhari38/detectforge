"""Core data types shared across the engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

SEVERITIES = ("informational", "low", "medium", "high", "critical")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}


class _Missing:
    """Sentinel for a field that is absent from an event (distinct from an explicit null)."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "MISSING"

    def __bool__(self) -> bool:
        return False


MISSING: Any = _Missing()


@dataclass(slots=True)
class Event:
    """A single normalized log record.

    Field names follow Elastic Common Schema (ECS) conventions where possible, so the same
    rule works regardless of whether the event came from auth.log, an EDR export or a SIEM.
    """

    data: dict[str, Any]
    timestamp: datetime
    source: str = ""

    def get(self, path: str) -> Any:
        """Resolve a dotted path (``source.ip``) against nested or flat keys."""
        if path in self.data:
            return self.data[path]
        node: Any = self.data
        for part in path.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                return MISSING
        return node


@dataclass(slots=True)
class Alert:
    rule_id: str
    title: str
    severity: str
    first_seen: datetime
    last_seen: datetime
    count: int
    group: dict[str, Any] = field(default_factory=dict)
    techniques: list[str] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "first_seen": _iso(self.first_seen),
            "last_seen": _iso(self.last_seen),
            "count": self.count,
            "group": self.group,
            "attack": {"techniques": self.techniques, "tactics": self.tactics},
            "description": self.description,
            "evidence": self.evidence,
        }


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")
