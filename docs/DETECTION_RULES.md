# Writing SAFE detection rules

SAFE's behavioral engine runs during `safe-analyze --analyze` and combines two
kinds of rule:

- **Native Go rules** — detections that can't be expressed as a per-row test.
  They live in code and are not user-editable. They come in two tiers:
  - **Tier 2 (stateful / correlation)** — run by `behavior.Run`: brute-force and
    password-spray counting, external-IP logon, look-alike local-account
    detection, and the IIS web-shell / ProxyShell / ProxyLogon family.
  - **Tier 3 (timeline sequence)** — run by `tier3.RunEngine`: rules that fire on
    an ordered sequence of timeline events (e.g. a network logon followed shortly
    by a suspicious service creation).
- **Declarative YAML rules** — every row-wise detection: read a CSV column and
  compare it to some strings. These ship as **built-in defaults embedded in the
  binary** and can be **extended or overridden by external files** you drop in a
  rules directory, with no recompile.

This document is the reference for authoring the YAML rules; the full catalog of
the built-in rules (declarative and native) is at the end.

## Where rules come from

At analyze time SAFE loads, in order:

1. The **embedded defaults** (built into `safe-analyze`).
2. Every `*.yml` / `*.yaml` file in the **rules directory**, applied on top.

The rules directory is chosen as:

1. `--rules-dir <path>` if given, else
2. the `SAFE_RULES_DIR` environment variable, else
3. a `rules/` folder next to the `safe-analyze` executable.

The directory is optional — if it doesn't exist, only the built-in defaults run.
Because rules are loaded by globbing the folder, **multiple files coexist**:
two analysts can each drop their own rule file in the same folder and both apply.

### Overlay: override, disable, extend

- A rule whose `id` is **new** is **added**.
- A rule whose `id` **matches a built-in** (or an earlier-loaded file)
  **overrides** it — this is how you tune a shipped rule without editing the
  binary.
- A rule with `enabled: false` **disables** that `id` (use it to switch off a
  built-in you don't want).
- A file that fails to parse is **skipped with a warning** printed to stderr;
  it never aborts the rest of detection.

## File shape

A rule file is either a single rule (fields at the top level) or a list:

```yaml
rules:
  - id: MY-01
    ...
  - id: MY-02
    ...
```

## Rule fields

| Field | Required | Meaning |
|-------|----------|---------|
| `id` | yes | Unique rule id (e.g. `B-01`, `MY-01`). Reusing a built-in id overrides it. |
| `title` | yes | Human-readable rule name (shown as the hit title). |
| `mitre` | no | MITRE ATT&CK technique id, e.g. `T1059`. |
| `severity` | yes* | `HIGH`, `NOTABLE`, or `INFO`. *Not required if `severity_from` is set. |
| `severity_from` | no | Name of a column whose value (`HIGH`/`NOTABLE`/`INFO`) sets the severity per row. A row whose value is none of those is skipped. Use this to inherit an analyzer's own triage tier. |
| `source` | yes* | One CSV path relative to `lab_report/`, literal (`evtx/Security.csv`) or a glob (`userassist/*.csv`). *`source` or `sources` is required. |
| `sources` | yes* | A list of CSV paths/globs (rule fires over all of them). |
| `match` | no | The condition tree (below). Omit to match every row of the source(s). |
| `evidence` | no | Template for the hit's evidence detail. `{column}` tokens are replaced with the row's value. |
| `evidence_source` | no | Template for the hit's evidence-source label. Defaults to the literal `source` (single literal path) or the matched file's base name (glob/multi-source). |
| `timeline_key` | no | Template for the string used to pivot into the timeline. |
| `enabled` | no | `false` disables the rule (default `true`). |

### Templates

`evidence`, `evidence_source`, and `timeline_key` are templates. Tokens:

- `{column_name}` → that column's value in the matching row (case-insensitive
  column lookup; unknown column → empty).
- `{source_file}` → base name of the matched CSV (e.g. `Security.csv`).
- `{source_path}` → the matched CSV's path relative to `lab_report/`.

## The `match` condition tree

A node is **exactly one** of:

- a **leaf** — `field:` plus one operator;
- `all:` — a list of nodes, all must be true (AND);
- `any:` — a list of nodes, at least one true (OR);
- `not:` — a single node, negated.

Combinators nest freely.

### Leaf operators

All string comparisons are **case-insensitive**.

| Operator | Value | True when |
|----------|-------|-----------|
| `equals` | string | column equals value |
| `not_equals` | string | column differs from value |
| `in` | list | column equals one of the values |
| `not_in` | list | column equals none of the values |
| `contains` | string | column contains the substring |
| `not_contains` | string | column does not contain the substring |
| `contains_any` | list | column contains any of the substrings |
| `not_contains_any` | list | column contains none of the substrings |
| `starts_with` | string | column begins with the value |
| `regex` | pattern | column matches the RE2 regex (implicitly case-insensitive; add `(?-i)` to force case) |
| `exists` | bool | `true`: column present in this CSV; `false`: absent |

### Example: a leaf

```yaml
match:
  field: event_id
  equals: "4720"
```

### Example: all / not

```yaml
match:
  all:
    - field: event_id
      equals: "4624"
    - field: event_data
      contains: '"LogonType":10'
    - not:
        field: event_data
        contains_any:
          - '"IpAddress":"127.0.0.1"'
          - '"IpAddress":"::1"'
```

### Example: nested any inside all

```yaml
match:
  all:
    - field: event_id
      equals: "4688"
    - any:
        - all:
            - field: event_data
              contains: vssadmin
            - field: event_data
              contains: 'delete shadows'
        - all:
            - field: event_data
              contains: wmic
            - field: event_data
              contains: 'shadowcopy delete'
```

## A complete custom rule

```yaml
id: MY-CERTUTIL-01
title: Certutil URL Download (Amcache)
mitre: T1105
severity: NOTABLE
source: amcache/amcache.csv
match:
  field: full_path
  contains: certutil.exe
evidence: "certutil present in Amcache: {full_path} (sha1 {sha1})"
timeline_key: "{full_path}"
```

Drop that in your rules directory and re-run `safe-analyze --analyze <case>`.

## Built-in rule catalog (current)

The rules SAFE ships. **Severity** is HIGH / NOTABLE / INFO (see the note on
`severity_from` for rules whose severity is inherited per row).

### Declarative (YAML) built-ins — overridable / disable-able

Embedded from `internal/behavior/defaults/*.yml`. Reuse an `id` in your own file
to override one, or set `enabled: false` to disable it.

| ID | Title | MITRE | Severity | Fires on |
|----|-------|-------|----------|----------|
| B-01 | Suspicious Scheduled Task using LOLBin | T1053.005 | `severity_from: tier` | Scheduled tasks the analyzer triaged HIGH/NOTABLE (LOLBin tasks); LOW rows are skipped |
| B-02 | WMI Event Subscription Persistence | T1546.003 | HIGH | CommandLine/ActiveScript WMI event-consumer persistence |
| B-03 | High-Tier COM Hijack | T1546.015 | HIGH | COM CLSID hijacked by an HKCU user module (triage HIGH) |
| B-04 | Suspicious Script Host Execution | T1059 | NOTABLE | wscript/cscript/mshta prefetch touching `\users`\`\temp`\`\programdata` |
| B-05 | Windows Defender Tampering | T1562.001 | HIGH | Defender 5001/5004, or 5007 naming a protection-disabling value |
| B-06 | Process Elevation (UAC Bypass / Priv-Esc) | T1134 | NOTABLE | 4688 with TokenElevationType `%%1937` (elevated token) |
| B-07 | New Local Account Created | T1136.001 | NOTABLE | Security EventID 4720 |
| B-08 | Remote Interactive Logon (RDP) | T1021.001 | INFO | 4624 LogonType 10 from a non-local IP |
| B-09 | Certutil Used for Download | T1105 | NOTABLE | certutil.exe prefetch touching `\users`\`\temp` or urlcache |
| B-10 | Suspicious ShellBag Path | T1074 | INFO | ShellBags under `\windows\temp`, `\users\public`, or a UNC path |
| B-11 | LOLBin Executed via Explorer | T1204 | NOTABLE | UserAssist records of mshta/regsvr32/wscript/cscript |
| T2-11 | Event Log Clearing (1102/104) | T1070.001 | HIGH | Security/System log-clear events 1102 or 104 |
| T2-12 | Volume Shadow Copy Deletion | T1070.004 | HIGH | 4688 vssadmin/wmic shadow deletion (excludes SAFE's own targeted `/shadow=`) |

### Native Go built-ins — NOT overridable from a file

Their IDs are effectively reserved (a YAML rule reusing one adds a *second*
detection rather than replacing the native one).

**Tier 2 — stateful / correlation (`behavior.Run`):**

| ID | Title | MITRE | Severity | Fires on |
|----|-------|-------|----------|----------|
| SAM-01 | Suspicious Local Account | T1136.001 | HIGH / NOTABLE | Rogue local accounts: look-alike/near-duplicate names (HIGH) or helpdesk/backdoor-keyword names (NOTABLE); RID < 1000 built-ins skipped |
| LOGON-01 | Authentication Brute Force / Password Spray | T1110 | HIGH / NOTABLE | Aggregated 4625 failures; HIGH when external source IPs are involved |
| LOGON-02 | Successful Logon from External IP | T1078 | HIGH | 4624 success from a routable public IP; privileged accounts flagged |
| IIS-01 | Web Shell in IIS Web Root | T1505.003 | HIGH / NOTABLE | Web-shell-flagged script files in `web_files.csv` (parser triage) |
| IIS-02 | Web Shell Accessed Over HTTP | T1505.003 | HIGH / NOTABLE | Flagged web-shell files correlated with real requests in `iis_requests.csv` |
| IIS-03 | LOLBin Referenced in IIS Request | T1059 | NOTABLE | Script-resource requests whose query string carries a LOLBin name |
| IIS-04 | Exchange ProxyShell Autodiscover SSRF | T1190 | HIGH | `autodiscover.json` requests carrying ProxyShell back-end SSRF tokens |
| IIS-05 | Anonymous Exchange PowerShell Access (ProxyShell RCE) | T1190 | HIGH | Anonymous remote requests to the `/powershell` Exchange back end |
| IIS-06 | Anonymous Exchange ECP Access (ProxyLogon) | T1190 | NOTABLE | Anonymous remote requests to the `/ecp/` admin surface |
| IIS-07 | Server Script in Upload/Temp Directory | T1505.003 | HIGH | Server-executable scripts sitting in upload/temp/scratch dirs (path heuristic) |

**Tier 3 — timeline sequence (`tier3.RunEngine`):**

| ID | Title | MITRE | Severity | Fires on |
|----|-------|-------|----------|----------|
| T3-03 | Lateral Movement Followed by Execution | T1543.003 | HIGH | A network (Type 3) 4624 logon followed within ~2 min by a suspicious service creation (7045/4697 with a PsExec-style / LOLBin / temp / UNC image) |
| T3-04 | Suspicious Process Lineage (Office to Shell) | T1059 | HIGH | An Office app run (winword/excel/powerpnt) followed within ~2 min by cmd/powershell/wscript/cscript |

`T3-01` and `T3-02` (execution↔network-connection correlation) exist in code but
are **deliberately disabled** — SAFE ingests no network-connection event source
(no netstat/Sysmon-EID-3 feed), so they could never fire and would read as
coverage that doesn't exist.

## Notes

- **Rules are data, not code.** A rule can only read a column and compare it to
  strings you wrote — there is no scripting. Regular expressions run on Go's RE2
  engine (linear time), so a rule file cannot execute anything or hang the
  analyzer. This is what makes a shared "signature folder" safe.
- **YAML quoting.** Wrap values that contain backslashes, quotes, or leading
  special characters in single quotes (`'\users\'`, `'"LogonType":10'`).
  Single-quoted YAML is literal — no escape processing.
- **Which built-ins are declarative.** `B-01`…`B-11`, `T2-11`, `T2-12` are YAML
  and can be overridden or disabled from a file. The native Go rules — SAM
  (`SAM-01`), logon (`LOGON-01`/`LOGON-02`), IIS/Exchange (`IIS-01`…`IIS-07`), and
  the Tier-3 sequence rules (`T3-03`, `T3-04`) — are **not** overridable from a
  file; their IDs are effectively reserved (reusing one in YAML adds a second,
  separate detection instead of replacing the native one). See the catalog above.
