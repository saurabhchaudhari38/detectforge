# Rule reference

Each rule is one YAML file. `detectforge validate` rejects unknown keys, so a typo such as `treshold:` fails loudly instead of silently disabling the rule.

## Top-level keys

| Key | Required | Notes |
|---|---|---|
| `id` | yes | Unique across the rule set, e.g. `DF-LNX-001` |
| `title` | yes | Short and human-readable |
| `severity` | yes | `informational`, `low`, `medium`, `high`, `critical` |
| `type` | no | `single` (default), `threshold`, `sequence` |
| `detection` | yes | Named selections plus `condition` (not needed for sequence rules) |
| `threshold` | threshold rules | See below |
| `sequence` | sequence rules | See below |
| `tags` | no | `attack.t1110.001` → technique, `attack.credential_access` → tactic |
| `description`, `author`, `status`, `date`, `modified`, `references`, `falsepositives`, `logsource` | no | Metadata |
| `tests` | recommended | Embedded test cases (see below) |

## Selections

A selection is a mapping of `field|modifiers: value`.

- Fields inside one mapping are **AND**ed.
- A list of values is **OR**ed, unless you add the `all` modifier.
- A selection written as a list of mappings ORs those mappings.
- A selection written as a list of plain strings is a keyword search over `message`.

Field names use dotted paths (`process.parent.name`) and resolve against nested JSON or flat dotted keys.

```yaml
detection:
  selection:
    process.name: [powershell.exe, pwsh.exe]          # either value
    process.command_line|contains|all: [-nop, -w hidden] # both substrings
  filter_sccm:
    process.parent.name: ccmexec.exe
  condition: selection and not filter_sccm
```

### Modifiers

| Modifier | Meaning |
|---|---|
| *(none)* | Equality. `*` and `?` are wildcards. Numbers compare numerically (`4625` matches `"4625"`) |
| `contains`, `startswith`, `endswith` | Substring matching |
| `re` | Regular expression (Python syntax, `search` semantics) |
| `cidr` | IP address is inside a network (`10.0.0.0/8`, IPv6 supported) |
| `gt`, `gte`, `lt`, `lte` | Numeric comparison |
| `exists` | `true`/`false`: whether the field is present and non-null |
| `all` | Every listed value must match, instead of any one |
| `cased` | Make the match case-sensitive. All string matching is case-insensitive by default |

`field: null` matches a field that is missing or null.

## Conditions

```
sel_a and not filter
(sel_a or sel_b) and not 1 of filter_*
all of sel_*
1 of them
```

Precedence from highest to lowest is `not`, then `and`, then `or`. Parentheses work as usual. `1 of`/`any of`/`all of` take a selection name glob or `them`.

## Threshold rules

```yaml
type: threshold
threshold:
  count: 5            # fire at this many events (or distinct values)
  window: 60s         # sliding window: 30s, 5m, 1h, 1d or plain seconds
  group_by: [source.ip]
  distinct: user.name # optional: count unique values instead of events
```

After firing, the group's counter resets, so one burst produces one alert rather than one alert per extra event.

## Sequence rules

```yaml
type: sequence
detection:
  failed: {event.outcome: failure}
  success: {event.outcome: success}
sequence:
  window: 10m
  group_by: [source.ip]
  steps:
    - condition: failed
      count: 5
    - condition: success
```

Steps must happen in order and within `window` of the first step completing. Step 1 uses a sliding window, so a slow trickle of failures never adds up. If the window expires, the sequence starts over.

## Embedded tests

```yaml
tests:
  - name: routine sudo command does not fire
    expect: 0
    events:
      - {"@timestamp": "2026-10-12T08:02:10Z", event: {action: sudo}, process: {command_line: /usr/bin/systemctl restart nginx}}
```

Each test runs the rule on its own with fresh state and compares the number of alerts with `expect`. Write at least one test that fires and one look-alike that must not fire. The negative tests are what keep false positives from creeping back in.

Quote timestamps. Unquoted, YAML turns them into dates, which is also accepted, but quoted strings are clearer.
