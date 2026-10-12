from __future__ import annotations

import pytest

from conftest import make_event
from detectforge.conditions import RuleError, compile_condition, compile_field, compile_selection


def field_matches(key, value, **data) -> bool:
    return compile_field(key, value)(make_event(**data))


@pytest.mark.parametrize(
    ("key", "value", "data", "expected"),
    [
        ("process.name", "powershell.exe", {"process": {"name": "PowerShell.EXE"}}, True),
        ("process.name|cased", "powershell.exe", {"process": {"name": "PowerShell.EXE"}}, False),
        ("process.name", "power*.exe", {"process": {"name": "powershell.exe"}}, True),
        ("process.name", "cmd.exe", {"process": {"name": "powershell.exe"}}, False),
        ("event.code", 4625, {"event": {"code": "4625"}}, True),
        ("cmd|contains", "-enc", {"cmd": "powershell -ENC abc"}, True),
        ("cmd|startswith", "certutil", {"cmd": "certutil -urlcache"}, True),
        ("cmd|endswith", ".ps1", {"cmd": "run.ps1"}, True),
        ("cmd|re", r"\d{3}-\d{4}", {"cmd": "call 555-1234"}, True),
        ("source.ip|cidr", "10.0.0.0/8", {"source": {"ip": "10.20.30.40"}}, True),
        ("source.ip|cidr", "10.0.0.0/8", {"source": {"ip": "192.168.1.1"}}, False),
        ("source.ip|cidr", "10.0.0.0/8", {"source": {"ip": "not-an-ip"}}, False),
        ("bytes|gt", 1000, {"bytes": 1500}, True),
        ("bytes|lte", 1000, {"bytes": "1000"}, True),
        ("bytes|gt", 1000, {"bytes": "lots"}, False),
        ("user.name|exists", True, {"user": {"name": "a"}}, True),
        ("user.name|exists", False, {"user": {}}, True),
        ("cmd|contains|all", ["procdump", "lsass"], {"cmd": "procdump -ma lsass.exe"}, True),
        ("cmd|contains|all", ["procdump", "lsass"], {"cmd": "procdump -ma w3wp.exe"}, False),
        ("parent.name", None, {}, True),
        ("tags", "evil", {"tags": ["benign", "EVIL"]}, True),
        ("flag", True, {"flag": True}, True),
        ("flag", True, {"flag": False}, False),
    ],
)
def test_field_operators(key, value, data, expected):
    assert field_matches(key, value, **data) is expected


def test_value_list_is_or():
    pred = compile_field("process.name", ["cmd.exe", "powershell.exe"])
    assert pred(make_event(process={"name": "cmd.exe"}))
    assert not pred(make_event(process={"name": "notepad.exe"}))


def test_missing_field_never_matches():
    assert not field_matches("process.name|contains", "", process={})


def test_flat_dotted_keys_are_supported():
    assert field_matches("source.ip", "1.2.3.4", **{"source.ip": "1.2.3.4"})


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("f|bogus", "x"),
        ("f|contains|re", "x"),
        ("f|re", "("),
        ("f|cidr", "10.0.0.0/33"),
        ("f|gt", "ten"),
        ("f|exists", "yes"),
        ("f", []),
        ("f", {"nested": 1}),
        ("|contains", "x"),
    ],
)
def test_invalid_fields_raise(key, value):
    with pytest.raises(RuleError):
        compile_field(key, value)


def test_selection_list_of_maps_is_or():
    pred = compile_selection("s", [{"a": 1}, {"b": 2}])
    assert pred(make_event(a=1))
    assert pred(make_event(b=2))
    assert not pred(make_event(a=2, b=1))


def test_selection_keywords_search_message():
    pred = compile_selection("s", ["mimikatz", "sekurlsa"])
    assert pred(make_event(message="Running SEKURLSA::logonpasswords"))
    assert not pred(make_event(message="all good"))


SELECTIONS = {
    "sel_a": lambda e: e.get("a") == 1,
    "sel_b": lambda e: e.get("b") == 1,
    "filter": lambda e: e.get("f") == 1,
}


@pytest.mark.parametrize(
    ("expr", "data", "expected"),
    [
        ("sel_a", {"a": 1}, True),
        ("sel_a and sel_b", {"a": 1}, False),
        ("sel_a or sel_b", {"b": 1}, True),
        ("sel_a and not filter", {"a": 1, "f": 1}, False),
        ("sel_a and not filter", {"a": 1}, True),
        ("not not sel_a", {"a": 1}, True),
        ("(sel_a or sel_b) and not filter", {"b": 1}, True),
        ("sel_a or sel_b and filter", {"a": 1}, True),  # 'and' binds tighter than 'or'
        ("1 of sel_*", {"b": 1}, True),
        ("all of sel_*", {"a": 1}, False),
        ("all of sel_*", {"a": 1, "b": 1}, True),
        ("1 of them", {"f": 1}, True),
        ("SEL_A".lower(), {"a": 1}, True),
        ("sel_a AND NOT filter", {"a": 1}, True),
    ],
)
def test_condition_expressions(expr, data, expected):
    assert compile_condition(expr, SELECTIONS)(make_event(**data)) is expected


@pytest.mark.parametrize(
    "expr", ["", "sel_a and", "(sel_a", "sel_a)", "unknown", "1 of nomatch*", "sel_a | sel_b",
             "and sel_a", "sel_a sel_b"]
)
def test_invalid_conditions_raise(expr):
    with pytest.raises(RuleError):
        compile_condition(expr, SELECTIONS)
