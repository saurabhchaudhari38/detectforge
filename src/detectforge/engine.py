"""Streaming detection engine with stateful correlation.

Three rule types are supported:

* ``single``    - alert on every matching event.
* ``threshold`` - alert when N matching events (or N *distinct* values of a field) occur
                  inside a sliding time window, per group (e.g. per source IP).
* ``sequence``  - alert when ordered steps occur inside a window, per group
                  (e.g. 5 failed logins *followed by* a successful login).

Events must be fed in timestamp order. State is bounded: correlation buckets that fall
outside their window are purged periodically, so memory stays proportional to the number
of *active* groups rather than the size of the log.
"""

from __future__ import annotations

import json
from collections import deque
from collections.abc import Iterable, Iterator
from datetime import datetime
from typing import Any

from .models import MISSING, Alert, Event
from .rules import Rule

PURGE_INTERVAL = 5_000


def _hashable(value: Any) -> Any:
    if value is MISSING or value is None:
        return None
    if isinstance(value, (list, dict)):
        return json.dumps(value, sort_keys=True, default=str)
    return value


def _group_key(event: Event, fields: tuple[str, ...]) -> tuple[Any, ...]:
    return tuple(_hashable(event.get(f)) for f in fields)


class _Detector:
    def __init__(self, rule: Rule, max_evidence: int):
        self.rule = rule
        self.max_evidence = max(1, max_evidence)

    def process(self, event: Event) -> Alert | None:
        raise NotImplementedError

    def purge(self, now: datetime) -> None:
        """Drop state that can no longer contribute to an alert."""

    def _alert(
        self,
        events: list[Event],
        fields: tuple[str, ...] = (),
        key: tuple[Any, ...] = (),
        count: int | None = None,
    ) -> Alert:
        if len(events) > self.max_evidence:
            # Keep the start of the story and the event that completed it.
            kept = events[: self.max_evidence - 1] + [events[-1]]
        else:
            kept = events
        rule = self.rule
        return Alert(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            first_seen=events[0].timestamp,
            last_seen=events[-1].timestamp,
            count=len(events) if count is None else count,
            group=dict(zip(fields, key, strict=True)),
            techniques=list(rule.techniques),
            tactics=list(rule.tactics),
            evidence=[e.data for e in kept],
            description=rule.description,
        )


class _SingleDetector(_Detector):
    def process(self, event: Event) -> Alert | None:
        assert self.rule.match is not None
        return self._alert([event]) if self.rule.match(event) else None


class _ThresholdDetector(_Detector):
    def __init__(self, rule: Rule, max_evidence: int):
        super().__init__(rule, max_evidence)
        assert rule.threshold is not None and rule.match is not None
        self.spec = rule.threshold
        self.buckets: dict[tuple[Any, ...], deque[Event]] = {}

    def process(self, event: Event) -> Alert | None:
        assert self.rule.match is not None
        if not self.rule.match(event):
            return None
        spec = self.spec
        key = _group_key(event, spec.group_by)
        bucket = self.buckets.setdefault(key, deque())
        bucket.append(event)
        cutoff = event.timestamp - spec.window
        while bucket and bucket[0].timestamp < cutoff:
            bucket.popleft()

        if spec.distinct:
            values = {_hashable(e.get(spec.distinct)) for e in bucket} - {None}
            observed = len(values)
        else:
            observed = len(bucket)

        if observed >= spec.count:
            # Reset after firing so one burst produces one alert, not one per extra event.
            del self.buckets[key]
            return self._alert(list(bucket), spec.group_by, key, count=observed)
        return None

    def purge(self, now: datetime) -> None:
        cutoff = now - self.spec.window
        stale = [k for k, b in self.buckets.items() if not b or b[-1].timestamp < cutoff]
        for key in stale:
            del self.buckets[key]


class _SequenceState:
    __slots__ = ("step", "hits", "evidence", "started")

    def __init__(self) -> None:
        self.step = 0
        self.hits: deque[Event] = deque()
        self.evidence: list[Event] = []
        self.started: datetime | None = None


class _SequenceDetector(_Detector):
    def __init__(self, rule: Rule, max_evidence: int):
        super().__init__(rule, max_evidence)
        assert rule.sequence is not None
        self.spec = rule.sequence
        self.states: dict[tuple[Any, ...], _SequenceState] = {}

    def process(self, event: Event) -> Alert | None:
        spec = self.spec
        matches = [step.predicate(event) for step in spec.steps]
        if not any(matches):
            return None

        key = _group_key(event, spec.group_by)
        state = self.states.get(key) or _SequenceState()
        if state.started is not None and event.timestamp - state.started > spec.window:
            state = _SequenceState()  # Sequence timed out; start over with this event.

        if not matches[state.step]:
            if state.step or state.hits:
                self.states[key] = state
            else:
                self.states.pop(key, None)
            return None

        step = spec.steps[state.step]
        state.hits.append(event)
        if state.step == 0:
            # The first step slides, so a slow trickle of failures never adds up.
            cutoff = event.timestamp - spec.window
            while state.hits and state.hits[0].timestamp < cutoff:
                state.hits.popleft()

        if len(state.hits) >= step.count:
            if state.step == 0:
                state.started = state.hits[0].timestamp
            state.evidence.extend(state.hits)
            state.hits = deque()
            state.step += 1
            if state.step == len(spec.steps):
                self.states.pop(key, None)
                return self._alert(state.evidence, spec.group_by, key)

        self.states[key] = state
        return None

    def purge(self, now: datetime) -> None:
        window = self.spec.window
        stale = []
        for key, state in self.states.items():
            anchor = state.started or (state.hits[-1].timestamp if state.hits else None)
            if anchor is None or now - anchor > window:
                stale.append(key)
        for key in stale:
            del self.states[key]


_DETECTORS: dict[str, type[_Detector]] = {
    "single": _SingleDetector,
    "threshold": _ThresholdDetector,
    "sequence": _SequenceDetector,
}


class Engine:
    """Evaluate a set of rules against an ordered stream of events."""

    def __init__(self, rules: Iterable[Rule], max_evidence: int = 10):
        self.rules = list(rules)
        self.detectors = [_DETECTORS[r.type](r, max_evidence) for r in self.rules]
        self.events_processed = 0

    def process(self, event: Event) -> list[Alert]:
        self.events_processed += 1
        if self.events_processed % PURGE_INTERVAL == 0:
            for detector in self.detectors:
                detector.purge(event.timestamp)
        alerts = []
        for detector in self.detectors:
            alert = detector.process(event)
            if alert is not None:
                alerts.append(alert)
        return alerts

    def run(self, events: Iterable[Event]) -> Iterator[Alert]:
        for event in events:
            yield from self.process(event)
