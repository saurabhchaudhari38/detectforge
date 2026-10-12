"""Compile Sigma-style selections and condition expressions into fast predicates.

A rule's ``detection`` block contains named *selections* plus a boolean *condition*::

    detection:
      selection:
        process.name: powershell.exe
        process.command_line|contains: [" -enc ", " -encodedcommand "]
      filter_admin:
        user.name: svc_deploy
      condition: selection and not filter_admin

Everything is compiled once at rule-load time; evaluating an event is just a chain of
closures with no parsing or regex compilation on the hot path.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from collections.abc import Callable, Mapping
from typing import Any

from .models import MISSING, Event

Predicate = Callable[[Event], bool]

OPERATORS = frozenset(
    {
        "equals", "contains", "startswith", "endswith", "re", "cidr",
        "gt", "gte", "lt", "lte", "exists",
    }
)
FLAGS = frozenset({"all", "cased"})


class RuleError(ValueError):
    """Raised when a rule is syntactically or semantically invalid."""


# --------------------------------------------------------------------------------------
# Field matchers
# --------------------------------------------------------------------------------------


def _wildcard_regex(pattern: str, cased: bool) -> re.Pattern[str]:
    body = "".join(
        ".*" if ch == "*" else "." if ch == "?" else re.escape(ch) for ch in pattern
    )
    return re.compile(f"^{body}$", re.DOTALL | (0 if cased else re.IGNORECASE))


def _number(value: Any) -> float:
    if isinstance(value, bool):
        raise ValueError("booleans are not numbers")
    return float(value)


def _build_matcher(
    op: str, cased: bool
) -> tuple[Callable[[Any], Any], Callable[[Any, Any], bool]]:
    """Return ``(prepare, test)`` for an operator.

    ``prepare`` runs once per expected value at compile time; ``test`` runs per event.
    """
    fold: Callable[[str], str] = (lambda s: s) if cased else str.casefold

    if op == "equals":

        def prepare(exp: Any) -> tuple[str, Any]:
            if isinstance(exp, bool):
                return ("bool", exp)
            if isinstance(exp, (int, float)):
                return ("num", exp)
            text = str(exp)
            if "*" in text or "?" in text:
                return ("glob", _wildcard_regex(text, cased))
            return ("str", fold(text))

        def test(actual: Any, prepared: tuple[str, Any]) -> bool:
            kind, exp = prepared
            if kind == "glob":
                return exp.match(str(actual)) is not None
            if kind == "bool":
                if isinstance(actual, bool):
                    return actual is exp
                return str(actual).casefold() == str(exp).casefold()
            if kind == "num":
                try:
                    return _number(actual) == exp
                except (TypeError, ValueError):
                    return False
            return fold(str(actual)) == exp

        return prepare, test

    if op in ("contains", "startswith", "endswith"):
        check = {
            "contains": lambda a, e: e in a,
            "startswith": str.startswith,
            "endswith": str.endswith,
        }[op]
        return (lambda exp: fold(str(exp))), (lambda actual, exp: check(fold(str(actual)), exp))

    if op == "re":

        def prepare_re(exp: Any) -> re.Pattern[str]:
            try:
                return re.compile(str(exp), 0 if cased else re.IGNORECASE)
            except re.error as err:
                raise RuleError(f"invalid regex {exp!r}: {err}") from err

        return prepare_re, lambda actual, pattern: pattern.search(str(actual)) is not None

    if op == "cidr":

        def prepare_cidr(exp: Any) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
            try:
                return ipaddress.ip_network(str(exp), strict=False)
            except ValueError as err:
                raise RuleError(f"invalid CIDR {exp!r}: {err}") from err

        def test_cidr(actual: Any, network: Any) -> bool:
            try:
                return ipaddress.ip_address(str(actual)) in network
            except ValueError:
                return False

        return prepare_cidr, test_cidr

    # Numeric comparisons
    compare = {
        "gt": lambda a, e: a > e,
        "gte": lambda a, e: a >= e,
        "lt": lambda a, e: a < e,
        "lte": lambda a, e: a <= e,
    }[op]

    def prepare_num(exp: Any) -> float:
        try:
            return _number(exp)
        except (TypeError, ValueError) as err:
            raise RuleError(f"'{op}' needs a numeric value, got {exp!r}") from err

    def test_num(actual: Any, exp: float) -> bool:
        try:
            return compare(_number(actual), exp)
        except (TypeError, ValueError):
            return False

    return prepare_num, test_num


def compile_field(key: str, value: Any) -> Predicate:
    """Compile ``field|modifier|modifier: value`` into a predicate."""
    name, *mods = (part.strip() for part in key.split("|"))
    if not name:
        raise RuleError(f"empty field name in {key!r}")
    unknown = [m for m in mods if m not in OPERATORS and m not in FLAGS]
    if unknown:
        raise RuleError(f"unknown modifier(s) {unknown} in {key!r}")
    ops = [m for m in mods if m in OPERATORS]
    if len(ops) > 1:
        raise RuleError(f"only one operator allowed per field, got {ops} in {key!r}")
    op = ops[0] if ops else "equals"
    match_all = "all" in mods
    cased = "cased" in mods

    if op == "exists":
        if not isinstance(value, bool):
            raise RuleError(f"'{key}' expects true or false")

        def exists(event: Event) -> bool:
            actual = event.get(name)
            return (actual is not MISSING and actual is not None) == value

        return exists

    expected = value if isinstance(value, list) else [value]
    if not expected:
        raise RuleError(f"empty value list for {key!r}")
    if any(isinstance(v, (dict, list)) for v in expected):
        raise RuleError(f"nested structures are not valid match values in {key!r}")

    if any(v is None for v in expected):
        if op != "equals" or len(expected) != 1:
            raise RuleError(f"null can only be used alone with plain equality in {key!r}")
        return lambda event: event.get(name) in (MISSING, None)

    prepare, test = _build_matcher(op, cased)
    prepared = [prepare(v) for v in expected]

    def predicate(event: Event) -> bool:
        actual = event.get(name)
        if actual is MISSING or actual is None:
            return False
        actuals = actual if isinstance(actual, list) else (actual,)
        hits = (any(test(a, p) for a in actuals) for p in prepared)
        return all(hits) if match_all else any(hits)

    return predicate


def compile_selection(name: str, spec: Any) -> Predicate:
    """A mapping is AND across fields; a list of mappings is OR; a list of strings is a
    case-insensitive keyword search over the raw ``message`` field."""
    try:
        if isinstance(spec, dict):
            if not spec:
                raise RuleError("selection is empty")
            preds = tuple(compile_field(str(k), v) for k, v in spec.items())
            return lambda event: all(p(event) for p in preds)

        if isinstance(spec, list) and spec:
            if all(isinstance(item, dict) for item in spec):
                alternatives = tuple(compile_selection(name, item) for item in spec)
                return lambda event: any(p(event) for p in alternatives)
            if all(isinstance(item, (str, int, float)) for item in spec):
                return compile_field("message|contains", [str(item) for item in spec])
            raise RuleError("list items must be all mappings or all keywords")
    except RuleError as err:
        raise RuleError(f"selection '{name}': {err}") from None

    raise RuleError(f"selection '{name}' must be a mapping or non-empty list")


# --------------------------------------------------------------------------------------
# Condition expressions
# --------------------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"\s*(?:(\()|(\))|([A-Za-z0-9_\-.*?]+))")
_KEYWORDS = frozenset({"and", "or", "not", "of", "them"})


def _tokenize(expr: str) -> list[str]:
    tokens: list[str] = []
    text = expr.strip()
    pos = 0
    while pos < len(text):
        match = _TOKEN_RE.match(text, pos)
        if not match:
            raise RuleError(f"unexpected character {text[pos]!r} in condition {expr!r}")
        tokens.append(match.group(match.lastindex or 0))
        pos = match.end()
    return tokens


class _ConditionParser:
    """Recursive-descent parser.

    Grammar (lowest to highest precedence)::

        expr    := and ('or' and)*
        and     := not ('and' not)*
        not     := 'not' not | primary
        primary := '(' expr ')' | ('1' | 'any' | 'all') 'of' (glob | 'them') | NAME
    """

    def __init__(self, expr: str, selections: Mapping[str, Predicate]):
        self.expr = expr
        self.tokens = _tokenize(expr)
        self.pos = 0
        self.selections = selections
        self.used: set[str] = set()

    def parse(self) -> Predicate:
        if not self.tokens:
            raise RuleError("condition is empty")
        node = self._or()
        if self.pos != len(self.tokens):
            raise RuleError(f"unexpected token {self.tokens[self.pos]!r} in {self.expr!r}")
        return node

    def _peek(self) -> str | None:
        return self.tokens[self.pos].lower() if self.pos < len(self.tokens) else None

    def _next(self) -> str:
        if self.pos >= len(self.tokens):
            raise RuleError(f"unexpected end of condition {self.expr!r}")
        token = self.tokens[self.pos]
        self.pos += 1
        return token

    def _or(self) -> Predicate:
        parts = [self._and()]
        while self._peek() == "or":
            self.pos += 1
            parts.append(self._and())
        if len(parts) == 1:
            return parts[0]
        ors = tuple(parts)
        return lambda event: any(p(event) for p in ors)

    def _and(self) -> Predicate:
        parts = [self._not()]
        while self._peek() == "and":
            self.pos += 1
            parts.append(self._not())
        if len(parts) == 1:
            return parts[0]
        ands = tuple(parts)
        return lambda event: all(p(event) for p in ands)

    def _not(self) -> Predicate:
        if self._peek() == "not":
            self.pos += 1
            inner = self._not()
            return lambda event: not inner(event)
        return self._primary()

    def _primary(self) -> Predicate:
        token = self._next()
        lowered = token.lower()
        if token == "(":
            node = self._or()
            if self._next() != ")":
                raise RuleError(f"expected ')' in {self.expr!r}")
            return node
        if lowered in ("1", "any", "all") and self._peek() == "of":
            self.pos += 1
            preds = self._resolve(self._next())
            if lowered == "all":
                return lambda event: all(p(event) for p in preds)
            return lambda event: any(p(event) for p in preds)
        if token == ")" or lowered in _KEYWORDS:
            raise RuleError(f"unexpected token {token!r} in {self.expr!r}")
        if token not in self.selections:
            raise RuleError(f"condition references unknown selection {token!r}")
        self.used.add(token)
        return self.selections[token]

    def _resolve(self, target: str) -> tuple[Predicate, ...]:
        if target.lower() == "them":
            names = list(self.selections)
        else:
            names = [n for n in self.selections if fnmatch.fnmatchcase(n, target)]
        if not names:
            raise RuleError(f"'{target}' does not match any selection")
        self.used.update(names)
        return tuple(self.selections[n] for n in names)


def compile_condition(expr: str, selections: Mapping[str, Predicate]) -> Predicate:
    if not isinstance(expr, str):
        raise RuleError("condition must be a string")
    return _ConditionParser(expr, selections).parse()
