"""Command-line interface.

    detectforge scan -r rules/ samples/auth.log
    detectforge validate rules/
    detectforge test rules/
    detectforge list rules/
"""

from __future__ import annotations

import argparse
import heapq
import json
import os
import sys
from pathlib import Path

from . import __version__
from .engine import Engine
from .models import SEVERITIES, SEVERITY_RANK, Alert
from .output import navigator_layer, render_console, write_jsonl
from .parsers import FORMATS, ParseError, read_events
from .rules import LoadResult, load_rules
from .testing import run_rule_tests

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


def _load(paths: list[str]) -> LoadResult:
    try:
        return load_rules(paths)
    except FileNotFoundError as err:
        raise SystemExit(f"error: {err}") from None


def _warn(message: str) -> None:
    print(f"warning: {message}", file=sys.stderr)


def cmd_scan(args: argparse.Namespace) -> int:
    loaded = _load(args.rules)
    for error in loaded.errors:
        print(f"rule error: {error}", file=sys.stderr)
    if loaded.errors and not args.ignore_rule_errors:
        return EXIT_ERROR
    min_rank = SEVERITY_RANK[args.min_severity]
    rules = [r for r in loaded.rules if SEVERITY_RANK[r.severity] >= min_rank]
    if not rules:
        print("error: no rules to run", file=sys.stderr)
        return EXIT_ERROR

    on_error = _warn if not args.strict else None
    streams = []
    for raw in args.inputs:
        path = Path(raw)
        if not path.is_file():
            print(f"error: input not found: {path}", file=sys.stderr)
            return EXIT_ERROR
        kwargs = {"on_error": on_error} if on_error else {}
        streams.append(read_events(path, args.format, args.year, **kwargs))

    # Each source is already chronological; a k-way merge keeps memory flat across files.
    events = heapq.merge(*streams, key=lambda e: e.timestamp)
    engine = Engine(rules, max_evidence=args.max_evidence)
    try:
        alerts: list[Alert] = list(engine.run(events))
    except ParseError as err:
        print(f"error: {err}", file=sys.stderr)
        return EXIT_ERROR

    out = open(args.output_file, "w", encoding="utf-8") if args.output_file else sys.stdout
    try:
        if args.output == "json":
            write_jsonl(alerts, out)
        elif args.output == "navigator":
            json.dump(navigator_layer(alerts), out, indent=2)
            out.write("\n")
        else:
            color = not args.no_color and out.isatty() and "NO_COLOR" not in os.environ
            render_console(alerts, out, color, engine.events_processed)
    finally:
        if out is not sys.stdout:
            out.close()

    if args.fail_on:
        threshold = SEVERITY_RANK[args.fail_on]
        if any(SEVERITY_RANK[a.severity] >= threshold for a in alerts):
            return EXIT_FINDINGS
    return EXIT_OK


def cmd_validate(args: argparse.Namespace) -> int:
    loaded = _load(args.rules)
    for error in loaded.errors:
        print(f"FAIL  {error}")
    for rule in loaded.rules:
        warnings = []
        if not rule.techniques:
            warnings.append("no ATT&CK technique tag")
        if not rule.tests:
            warnings.append("no embedded tests")
        if not rule.description:
            warnings.append("no description")
        suffix = f"  (warning: {'; '.join(warnings)})" if warnings else ""
        print(f"ok    {rule.id:<12} {rule.path}{suffix}")
    print(f"\n{len(loaded.rules)} valid, {len(loaded.errors)} invalid")
    return EXIT_FINDINGS if loaded.errors else EXIT_OK


def cmd_test(args: argparse.Namespace) -> int:
    loaded = _load(args.rules)
    for error in loaded.errors:
        print(f"ERROR {error}")
    passed = failed = untested = 0
    for rule in loaded.rules:
        if not rule.tests:
            untested += 1
            continue
        for outcome in run_rule_tests(rule):
            if outcome.passed:
                passed += 1
                if args.verbose:
                    print(f"PASS  {outcome.rule_id}: {outcome.name}")
            else:
                failed += 1
                print(f"FAIL  {outcome.rule_id}: {outcome.name} - {outcome.detail}")
    print(f"\n{passed} passed, {failed} failed, {untested} rule(s) without tests")
    return EXIT_FINDINGS if failed or loaded.errors else EXIT_OK


def cmd_list(args: argparse.Namespace) -> int:
    loaded = _load(args.rules)
    for error in loaded.errors:
        print(f"rule error: {error}", file=sys.stderr)
    rules = sorted(loaded.rules, key=lambda r: (-SEVERITY_RANK[r.severity], r.id))
    for rule in rules:
        print(f"{rule.id:<12} {rule.severity:<9} {rule.type:<9} "
              f"{','.join(rule.techniques):<22} {rule.title}")
    return EXIT_FINDINGS if loaded.errors else EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="detectforge",
        description="Detection-as-code engine: run YAML detection rules over security logs.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="run rules against log files")
    scan.add_argument("inputs", nargs="+", help="log files to scan")
    scan.add_argument("-r", "--rules", action="append", default=None,
                      help="rule file or directory (repeatable, default: ./rules)")
    scan.add_argument("-f", "--format", choices=FORMATS, default="auto")
    scan.add_argument("--year", type=int, help="year for syslog timestamps (default: current)")
    scan.add_argument("--output", choices=("console", "json", "navigator"), default="console")
    scan.add_argument("-o", "--output-file", help="write results to a file instead of stdout")
    scan.add_argument("--min-severity", choices=SEVERITIES, default="informational",
                      help="only run rules at or above this severity")
    scan.add_argument("--fail-on", choices=SEVERITIES,
                      help="exit 1 if any alert at or above this severity fires (for CI)")
    scan.add_argument("--max-evidence", type=int, default=10,
                      help="max events attached to each alert")
    scan.add_argument("--strict", action="store_true", help="abort on unparseable log lines")
    scan.add_argument("--ignore-rule-errors", action="store_true",
                      help="run the valid rules even if some fail to load")
    scan.add_argument("--no-color", action="store_true")
    scan.set_defaults(func=cmd_scan)

    for name, func, help_text in (
        ("validate", cmd_validate, "check rule syntax and metadata"),
        ("test", cmd_test, "run the tests embedded in each rule"),
        ("list", cmd_list, "list loaded rules"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("rules", nargs="*", help="rule files or directories (default: ./rules)")
        if name == "test":
            p.add_argument("-v", "--verbose", action="store_true")
        p.set_defaults(func=func)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.rules:
        args.rules = ["rules"]
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
