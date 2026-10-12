from __future__ import annotations

from conftest import make_event
from detectforge.engine import Engine
from detectforge.rules import build_rule

FAIL = {"event": {"action": "login", "outcome": "failure"}}
OK = {"event": {"action": "login", "outcome": "success"}}


def _rule(**overrides):
    base = {
        "id": "T-1",
        "title": "test",
        "severity": "high",
        "tags": ["attack.credential_access", "attack.t1110.001"],
        "detection": {
            "fail": {"event.outcome": "failure"},
            "ok": {"event.outcome": "success"},
            "condition": "fail",
        },
    }
    base.update(overrides)
    return build_rule(base)


def run(rule, events):
    return list(Engine([rule]).run(events))


def test_single_rule_alerts_per_match():
    alerts = run(_rule(), [make_event(0, **FAIL), make_event(1, **OK), make_event(2, **FAIL)])
    assert len(alerts) == 2
    assert alerts[0].techniques == ["T1110.001"]
    assert alerts[0].tactics == ["Credential Access"]


def test_threshold_groups_and_resets_after_firing():
    rule = _rule(type="threshold", threshold={"count": 3, "window": "1m", "group_by": "ip"})
    events = [make_event(i, ip="1.1.1.1", **FAIL) for i in range(7)]
    events += [make_event(i, ip="2.2.2.2", **FAIL) for i in range(2)]
    alerts = run(rule, sorted(events, key=lambda e: e.timestamp))
    # 7 events for 1.1.1.1 -> alerts at #3 and #6; 2.2.2.2 never reaches 3.
    assert [a.group for a in alerts] == [{"ip": "1.1.1.1"}, {"ip": "1.1.1.1"}]
    assert all(a.count == 3 for a in alerts)


def test_threshold_window_slides():
    rule = _rule(type="threshold", threshold={"count": 3, "window": "10s"})
    events = [make_event(t, **FAIL) for t in (0, 8, 15, 30, 35, 38)]
    alerts = run(rule, events)
    assert len(alerts) == 1
    assert alerts[0].first_seen == events[3].timestamp


def test_threshold_distinct_counts_unique_values():
    rule = _rule(
        type="threshold",
        threshold={"count": 3, "window": "5m", "group_by": ["ip"], "distinct": "user"},
    )
    same_user = [make_event(i, ip="x", user="root", **FAIL) for i in range(10)]
    assert run(rule, same_user) == []
    spray = [make_event(i, ip="x", user=f"u{i}", **FAIL) for i in range(3)]
    assert len(run(rule, spray)) == 1


def _sequence_rule(window="5m", fail_count=3):
    return _rule(
        type="sequence",
        detection={"fail": {"event.outcome": "failure"}, "ok": {"event.outcome": "success"}},
        sequence={
            "window": window,
            "group_by": ["ip"],
            "steps": [{"condition": "fail", "count": fail_count}, {"condition": "ok"}],
        },
    )


def test_sequence_fires_in_order():
    events = [make_event(i, ip="a", **FAIL) for i in range(3)] + [make_event(10, ip="a", **OK)]
    alerts = run(_sequence_rule(), events)
    assert len(alerts) == 1
    assert alerts[0].count == 4
    assert alerts[0].group == {"ip": "a"}


def test_sequence_requires_order():
    events = [make_event(0, ip="a", **OK)] + [make_event(i, ip="a", **FAIL) for i in range(1, 4)]
    assert run(_sequence_rule(), events) == []


def test_sequence_times_out_and_can_restart():
    events = [make_event(i, ip="a", **FAIL) for i in range(3)]
    events.append(make_event(400, ip="a", **OK))  # too late, window is 5m
    events += [make_event(500 + i, ip="a", **FAIL) for i in range(3)]
    events.append(make_event(520, ip="a", **OK))
    alerts = run(_sequence_rule(), events)
    assert len(alerts) == 1
    assert alerts[0].first_seen == events[4].timestamp


def test_sequence_first_step_slides():
    # Failures trickle in slower than the window, so they never accumulate to 3.
    events = [make_event(i * 200, ip="a", **FAIL) for i in range(5)]
    events.append(make_event(1000, ip="a", **OK))
    assert run(_sequence_rule(window="5m"), events) == []


def test_evidence_is_capped_but_keeps_trigger():
    events = [make_event(i, ip="a", **FAIL) for i in range(20)] + [make_event(30, ip="a", **OK)]
    alerts = list(Engine([_sequence_rule(fail_count=20)], max_evidence=5).run(events))
    assert len(alerts[0].evidence) == 5
    assert alerts[0].evidence[-1]["event"]["outcome"] == "success"
    assert alerts[0].count == 21


def test_purge_drops_stale_state(monkeypatch):
    import detectforge.engine as engine_module

    monkeypatch.setattr(engine_module, "PURGE_INTERVAL", 10)
    rule = _rule(type="threshold", threshold={"count": 100, "window": "1m", "group_by": "ip"})
    engine = Engine([rule])
    for i in range(10):
        engine.process(make_event(i * 3600, ip=f"10.0.0.{i}", **FAIL))
    assert len(engine.detectors[0].buckets) <= 1
