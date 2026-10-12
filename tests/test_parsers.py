from __future__ import annotations

from datetime import UTC, datetime

import pytest

from detectforge.models import MISSING
from detectforge.parsers import ParseError, parse_authlog, parse_jsonl, parse_timestamp


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def test_ssh_failed_invalid_user(tmp_path):
    path = _write(tmp_path, "auth.log",
                  "Oct 12 09:00:00 web01 sshd[1400]: Failed password for invalid user oracle "
                  "from 198.51.100.23 port 33001 ssh2\n")
    [event] = parse_authlog(path, year=2026)
    assert event.timestamp == datetime(2026, 10, 12, 9, 0, tzinfo=UTC)
    assert event.get("event.action") == "ssh_login"
    assert event.get("event.outcome") == "failure"
    assert event.get("user.name") == "oracle"
    assert event.get("source.ip") == "198.51.100.23"
    assert event.get("source.port") == 33001
    assert event.get("ssh.invalid_user") is True
    assert event.get("host.hostname") == "web01"
    assert event.get("process.pid") == 1400


def test_ssh_accepted_publickey_ipv6(tmp_path):
    path = _write(tmp_path, "auth.log",
                  "2026-10-12T08:00:01.123456+00:00 web01 sshd[1]: Accepted publickey for alice "
                  "from 2001:db8::5 port 51022 ssh2: ED25519 SHA256:x\n")
    [event] = parse_authlog(path)
    assert event.get("event.outcome") == "success"
    assert event.get("ssh.method") == "publickey"
    assert event.get("source.ip") == "2001:db8::5"


def test_sudo_and_useradd(tmp_path):
    path = _write(tmp_path, "auth.log",
                  "Oct 12 08:11:30 web01 sudo:   deploy : TTY=pts/1 ; PWD=/home/deploy ; "
                  "USER=root ; COMMAND=/bin/bash\n"
                  "Oct 12 08:11:31 web01 sudo:   eve : user NOT in sudoers ; TTY=pts/2 ; "
                  "PWD=/tmp ; USER=root ; COMMAND=/bin/cat /etc/shadow\n"
                  "Oct 12 08:12:02 web01 useradd[1302]: new user: name=sysupdate, UID=0, GID=0\n")
    sudo_ok, sudo_denied, useradd = parse_authlog(path, year=2026)
    assert sudo_ok.get("user.name") == "deploy"
    assert sudo_ok.get("user.target.name") == "root"
    assert sudo_ok.get("process.command_line") == "/bin/bash"
    assert sudo_ok.get("event.outcome") == "success"
    assert sudo_denied.get("event.outcome") == "failure"
    assert sudo_denied.get("sudo.error") == "user NOT in sudoers"
    assert useradd.get("user.target.name") == "sysupdate"
    assert useradd.get("user.target.id") == 0


def test_unparsed_messages_still_produce_events(tmp_path):
    path = _write(tmp_path, "auth.log", "Oct 12 08:30:00 web01 CRON[1350]: session opened\n")
    [event] = parse_authlog(path, year=2026)
    assert event.get("message") == "session opened"
    assert event.get("process.name") == "CRON"
    assert event.get("event.action") is MISSING


def test_bad_lines_are_reported(tmp_path):
    path = _write(tmp_path, "auth.log", "garbage\nOct 12 08:30:00 web01 CRON[1]: ok\n")
    errors = []
    events = list(parse_authlog(path, year=2026, on_error=errors.append))
    assert len(events) == 1
    assert "auth.log:1" in errors[0]
    with pytest.raises(ParseError):
        list(parse_authlog(path, year=2026))


def test_jsonl(tmp_path):
    path = _write(tmp_path, "e.jsonl",
                  '{"@timestamp": "2026-10-12T10:00:00Z", "a": 1}\n\n'
                  '{"timestamp": 1791799200, "a": 2}\n'
                  "[1, 2]\n"
                  '{"no_time": true}\n')
    errors = []
    events = list(parse_jsonl(path, on_error=errors.append))
    assert [e.get("a") for e in events] == [1, 2]
    assert len(errors) == 2


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("2026-10-12T10:00:00Z", datetime(2026, 10, 12, 10, tzinfo=UTC)),
        ("2026-10-12 10:00:00", datetime(2026, 10, 12, 10, tzinfo=UTC)),
        (1791799200, datetime(2026, 10, 12, 10, tzinfo=UTC)),
        (1791799200000, datetime(2026, 10, 12, 10, tzinfo=UTC)),
    ],
)
def test_parse_timestamp(value, expected):
    assert parse_timestamp(value) == expected


def test_parse_timestamp_rejects_garbage():
    with pytest.raises(ParseError):
        parse_timestamp("yesterday")
