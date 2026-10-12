<<<<<<< HEAD
# detectforge

**A detection-as-code engine for security logs.** You write detections as YAML rules in the Sigma style, version them in git, unit-test them in CI, and run them over Linux auth logs or JSON endpoint telemetry. Every alert is mapped to MITRE ATT&CK.

[![CI](https://github.com/OWNER/detectforge/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/detectforge/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

```
$ detectforge scan --year 2026 samples/auth.log samples/endpoint_events.jsonl

[MEDIUM] DF-LNX-001  SSH brute force from a single source
    2026-10-12 08:10:00Z -> 2026-10-12 08:10:20Z  events=5  source.ip=203.0.113.50  host=web01  user=deploy
    ATT&CK: T1110.001  (Credential Access)

[CRITICAL] DF-LNX-003  Successful SSH login after brute force
    2026-10-12 08:10:00Z -> 2026-10-12 08:10:45Z  events=6  source.ip=203.0.113.50  host=web01  user=deploy
    ATT&CK: T1110, T1078  (Credential Access, Initial Access)

[HIGH] DF-LNX-004  Interactive root shell via sudo
    2026-10-12 08:11:30Z  events=1  host=web01  user=deploy
    ATT&CK: T1548.003  (Privilege Escalation)

[CRITICAL] DF-LNX-006  Account created with UID 0
    2026-10-12 08:12:02Z  events=1  host=web01
    ATT&CK: T1136.001, T1078.003  (Persistence, Privilege Escalation)
...
12 alert(s) from 12 rule(s) across 43 event(s)
  critical: 3  high: 7  medium: 2
```

## Why

Single-event pattern matching misses the attacks that matter most. A failed SSH login is noise, and a successful one is normal. **Five failures followed by a success from the same IP within ten minutes** is a compromise. detectforge supports three kinds of rule:

| Type | Fires when | Example |
|---|---|---|
| `single` | one event matches | `certutil -urlcache http://...` |
| `threshold` | N matches, or N **distinct** values of a field, within a sliding window, per group | 5 distinct usernames failing from one IP in 10 min (password spraying) |
| `sequence` | ordered steps complete within a window, per group | ≥5 failed logins **then** a success from the same IP |

The rules are treated as code. Each rule file carries its own positive and negative test cases. `detectforge test` runs them, and CI blocks merges when a detection regresses.

## Features

- **Sigma-style rule language**: field modifiers (`contains`, `startswith`, `endswith`, `re`, `cidr`, `gt`/`lt`, `exists`, `all`, `cased`), wildcards, and a full boolean condition parser (`and`/`or`/`not`, parentheses, `1 of sel_*`, `all of them`)
- **Stateful correlation**: sliding-window thresholds, distinct-value counting, and multi-step sequences grouped by any fields
- **Bounded memory**: stale correlation state is purged periodically, and multiple inputs are k-way merged by timestamp rather than loaded into memory
- **Strict validation**: unknown keys, bad regexes, invalid CIDRs, undefined selections and duplicate IDs are all caught at load time with file-level error messages
- **Log parsers**: Linux `auth.log`/`secure` (sshd, sudo, useradd → ECS fields) and JSON Lines (EDR/SIEM exports)
- **Outputs**: colored console, JSON Lines for SIEM/SOAR ingestion, and an [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) layer that shows coverage as a heatmap
- **CI-friendly**: `--fail-on high` returns exit code 1 when an alert at or above that severity fires
- **One runtime dependency** (PyYAML)

## Quick start

```bash
git clone https://github.com/OWNER/detectforge.git
cd detectforge
pip install -e ".[dev]"

detectforge list                                   # show loaded rules
detectforge validate rules/                        # lint rules
detectforge test rules/ -v                         # run embedded rule tests
detectforge scan --year 2026 samples/auth.log samples/endpoint_events.jsonl
```

Scan your own system (read access to the log is required):

```bash
sudo detectforge scan -r rules/ /var/log/auth.log
```

More scan options:

```bash
# Machine-readable alerts
detectforge scan --output json samples/* > alerts.jsonl

# ATT&CK Navigator heatmap (open layer.json in the Navigator)
detectforge scan --output navigator -o layer.json samples/*

# Only run high/critical rules, fail the pipeline if any fire
detectforge scan --min-severity high --fail-on high /var/log/auth.log
```

With Docker:

```bash
docker build -t detectforge .
docker run --rm -v "$PWD/samples:/data:ro" detectforge \
  scan -r /opt/detectforge/rules --year 2026 auth.log endpoint_events.jsonl
```

## Writing a rule

```yaml
id: DF-LNX-003
title: Successful SSH login after brute force
severity: critical
tags: [attack.credential_access, attack.initial_access, attack.t1110, attack.t1078]
type: sequence
detection:
  failed_login:
    event.action: ssh_login
    event.outcome: failure
  successful_login:
    event.action: ssh_login
    event.outcome: success
sequence:
  window: 10m
  group_by: [source.ip]
  steps:
    - condition: failed_login
      count: 5
    - condition: successful_login
tests:
  - name: success from a different IP does not fire
    expect: 0
    events:
      - {"@timestamp": "2026-10-12T08:10:00Z", event: {action: ssh_login, outcome: failure}, source: {ip: 203.0.113.50}}
      # ...
```

The full rule reference is in [docs/RULES.md](docs/RULES.md).

## Bundled detections

| ID | Severity | Type | ATT&CK | Detection |
|---|---|---|---|---|
| DF-LNX-001 | medium | threshold | T1110.001 | SSH brute force from a single source |
| DF-LNX-002 | high | threshold | T1110.003 | SSH password spraying across many accounts |
| DF-LNX-003 | critical | sequence | T1110, T1078 | Successful SSH login after brute force |
| DF-LNX-004 | high | single | T1548.003 | Interactive root shell via sudo |
| DF-LNX-005 | medium | single | T1136.001 | Local user account created |
| DF-LNX-006 | critical | single | T1136.001, T1078.003 | Account created with UID 0 |
| DF-LNX-007 | high | single | T1059.004, T1105 | Remote script piped directly into a shell |
| DF-WIN-001 | high | single | T1059.001, T1027 | PowerShell launched with an encoded command |
| DF-WIN-002 | high | single | T1105, T1218 | Certutil used to download a file |
| DF-WIN-003 | critical | single | T1003.001 | LSASS memory dump attempt |
| DF-WIN-004 | high | single | T1070.001 | Windows event log cleared |
| DF-WIN-005 | high | single | T1566.001, T1204.002 | Office application spawned a shell or script host |

The sample data in [`samples/`](samples/) contains two complete attack chains: an SSH brute force leading to a root shell and a UID-0 backdoor, and a macro document leading to encoded PowerShell, a certutil download, an LSASS dump and cleared logs. It also contains benign look-alikes, such as a `get.docker.com` installer, `certutil -hashfile` and `wevtutil qe`, which must **not** fire.

## Architecture

```
            ┌──────────────┐     ┌──────────────────────────┐
 auth.log ─▶│              │     │ rules/*.yml               │
 *.jsonl  ─▶│  parsers.py  │     │   └─ rules.py (validate)  │
            │  → ECS Event │     │      └─ conditions.py     │
            └──────┬───────┘     │         (compile → fn)    │
                   │ heapq.merge └────────────┬─────────────┘
                   ▼  by time                  ▼
            ┌───────────────────────────────────────────┐
            │ engine.py                                  │
            │  SingleDetector / ThresholdDetector /      │
            │  SequenceDetector  (per-group state)       │
            └──────────────────┬────────────────────────┘
                               ▼
              output.py: console │ JSON Lines │ ATT&CK Navigator
```

Rules are compiled once into chains of closures. Regexes, CIDRs and wildcards are pre-built, so evaluating an event does no parsing.

## Development

```bash
pip install -e ".[dev]"
ruff check .
pytest --cov=detectforge
```

## Roadmap

- Windows EVTX and Sysmon XML parsers
- Rule-level suppression and allowlists (`suppress: 1h by source.ip`)
- Converting a subset of upstream Sigma rules
- Streaming mode (`tail -f` / stdin) and webhook output

## License

MIT. See [LICENSE](LICENSE).
=======
# detectforge
>>>>>>> 8cc7964c2d635836d3baf3ac7870ee04d908b433
