"""Turn raw log sources into normalized :class:`Event` objects.

Supported formats:

* ``jsonl``   - one JSON object per line (EDR exports, SIEM dumps, ECS-shaped data).
* ``authlog`` - Linux ``/var/log/auth.log`` / ``/var/log/secure`` (syslog or RFC 3339
                timestamps). sshd, sudo and useradd messages are parsed into ECS fields.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterator
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from .models import Event

ErrorHandler = Callable[[str], None]
TIMESTAMP_KEYS = ("@timestamp", "timestamp", "time", "TimeCreated", "EventTime")


class ParseError(ValueError):
    pass


def _raise(message: str) -> None:
    raise ParseError(message)


def parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        ts = value
    elif isinstance(value, date):
        ts = datetime(value.year, value.month, value.day)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        seconds = value / 1000 if value > 1e12 else value  # epoch millis vs seconds
        ts = datetime.fromtimestamp(seconds, tz=UTC)
    elif isinstance(value, str):
        try:
            ts = datetime.fromisoformat(value.strip())
        except ValueError as err:
            raise ParseError(f"unrecognized timestamp {value!r}") from err
    else:
        raise ParseError(f"unrecognized timestamp {value!r}")
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


def event_from_mapping(data: dict[str, Any], source: str = "") -> Event:
    for key in TIMESTAMP_KEYS:
        if key in data:
            return Event(data=data, timestamp=parse_timestamp(data[key]), source=source)
    raise ParseError(f"no timestamp field (expected one of {', '.join(TIMESTAMP_KEYS)})")


def parse_jsonl(path: Path, on_error: ErrorHandler = _raise) -> Iterator[Event]:
    with path.open(encoding="utf-8", errors="replace") as handle:
        for lineno, line in enumerate(handle, 1):
            if not line.strip():
                continue
            where = f"{path}:{lineno}"
            try:
                data = json.loads(line)
                if not isinstance(data, dict):
                    raise ParseError("line is not a JSON object")
                yield event_from_mapping(data, where)
            except (json.JSONDecodeError, ParseError) as err:
                on_error(f"{where}: {err}")


# --------------------------------------------------------------------------------------
# auth.log
# --------------------------------------------------------------------------------------

_SYSLOG_RE = re.compile(
    r"^(?:(?P<iso>\d{4}-\d{2}-\d{2}T\S+)|(?P<bsd>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}))"
    r"\s+(?P<host>\S+)\s+(?P<proc>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$"
)
_SSH_AUTH_RE = re.compile(
    r"^(?P<result>Failed|Accepted) (?P<method>[\w-]+) for (?P<invalid>invalid user )?"
    r"(?P<user>\S*) from (?P<ip>[\da-fA-F.:]+) port (?P<port>\d+)"
)
_SSH_INVALID_RE = re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>[\da-fA-F.:]+)")
_SUDO_RE = re.compile(
    r"^\s*(?P<user>\S+) : (?:(?P<error>[^;]*?) ; )?TTY=(?P<tty>\S+) ; PWD=(?P<pwd>.*?) ; "
    r"USER=(?P<target>\S+) ; (?:.*?; )?COMMAND=(?P<cmd>.*)$"
)
_USERADD_RE = re.compile(r"^new user: name=(?P<name>[^,]+), UID=(?P<uid>\d+)")


def _parse_message(proc: str, msg: str) -> dict[str, Any]:
    if proc == "sshd":
        if m := _SSH_AUTH_RE.match(msg):
            fields: dict[str, Any] = {
                "event": {
                    "category": "authentication",
                    "action": "ssh_login",
                    "outcome": "success" if m["result"] == "Accepted" else "failure",
                },
                "user": {"name": m["user"]},
                "source": {"ip": m["ip"], "port": int(m["port"])},
                "ssh": {"method": m["method"], "invalid_user": bool(m["invalid"])},
            }
            return fields
        if m := _SSH_INVALID_RE.match(msg):
            return {
                "event": {"category": "authentication", "action": "ssh_invalid_user"},
                "user": {"name": m["user"]},
                "source": {"ip": m["ip"]},
            }
    elif proc == "sudo":
        if m := _SUDO_RE.match(msg):
            return {
                "event": {
                    "category": "process",
                    "action": "sudo",
                    "outcome": "failure" if m["error"] else "success",
                },
                "user": {"name": m["user"], "target": {"name": m["target"]}},
                "process": {"command_line": m["cmd"].strip(), "working_directory": m["pwd"]},
                "sudo": {"tty": m["tty"], "error": (m["error"] or "").strip() or None},
            }
    elif proc in ("useradd", "adduser"):
        if m := _USERADD_RE.match(msg):
            return {
                "event": {"category": "iam", "action": "user_created"},
                "user": {"target": {"name": m["name"].strip(), "id": int(m["uid"])}},
            }
    return {}


def _merge(base: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge(base[key], value)
        else:
            base[key] = value
    return base


def parse_authlog(
    path: Path, year: int | None = None, on_error: ErrorHandler = _raise
) -> Iterator[Event]:
    """Parse auth.log. BSD syslog lines carry no year or zone: ``year`` (default: current)
    is applied and times are treated as UTC."""
    year = year or datetime.now(UTC).year
    with path.open(encoding="utf-8", errors="replace") as handle:
        for lineno, raw in enumerate(handle, 1):
            line = raw.rstrip("\n")
            if not line.strip():
                continue
            where = f"{path}:{lineno}"
            m = _SYSLOG_RE.match(line)
            if not m:
                on_error(f"{where}: not a syslog line")
                continue
            try:
                if m["iso"]:
                    ts = parse_timestamp(m["iso"])
                else:
                    ts = datetime.strptime(f"{year} {m['bsd']}", "%Y %b %d %H:%M:%S")
                    ts = ts.replace(tzinfo=UTC)
            except (ValueError, ParseError) as err:
                on_error(f"{where}: bad timestamp: {err}")
                continue
            data: dict[str, Any] = {
                "@timestamp": ts.isoformat().replace("+00:00", "Z"),
                "host": {"hostname": m["host"]},
                "process": {"name": m["proc"]},
                "message": m["msg"],
                "log": {"original": line, "file": {"path": str(path)}},
            }
            if m["pid"]:
                data["process"]["pid"] = int(m["pid"])
            _merge(data, _parse_message(m["proc"], m["msg"]))
            yield Event(data=data, timestamp=ts, source=where)


FORMATS = ("auto", "jsonl", "authlog")


def detect_format(path: Path) -> str:
    if path.suffix.lower() in (".json", ".jsonl", ".ndjson"):
        return "jsonl"
    return "authlog"


def read_events(
    path: Path, fmt: str = "auto", year: int | None = None, on_error: ErrorHandler = _raise
) -> Iterator[Event]:
    if fmt == "auto":
        fmt = detect_format(path)
    if fmt == "jsonl":
        return parse_jsonl(path, on_error)
    if fmt == "authlog":
        return parse_authlog(path, year, on_error)
    raise ValueError(f"unknown format {fmt!r}")
