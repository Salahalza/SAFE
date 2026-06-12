# SAFE

**System for Artifacts Forensic and Examination**

![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)
![Status](https://img.shields.io/badge/status-Phase%201%20complete-brightgreen)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-blue)

SAFE is a Windows forensic acquisition tool built for incident response field
work. It is a single self-contained executable — carried on a USB SSD, run on a
targeted machine — that collects tamper-evident forensic evidence into a case
folder. The case is then taken back to the lab, where SAFE's analysis mode
produces parsed, analyst-ready output.

Written in Go. Cross-compiled to Windows from macOS/Linux. No installer, no
runtime dependencies, no network requirement.

---

## Status

**Phase 1 complete.** The `rapid_triage` collection profile (v0.2.0) is
functional and tested end-to-end against Windows 11. The analyzer foundation
ships with two parsers (UserAssist, Prefetch). The remaining road to v1.0 is
documented as eleven further phases in [`docs/PLAN.md`](docs/PLAN.md).

| Phase | Scope | Status |
|---|---|---|
| 1 | Foundation: `rapid_triage` profile, analyzer foundation, TUI | **Complete** |
| 2 | Extended collection (process memory, full event channels, extended persistence); `endpoint_deep` defined | Planned |
| 3 | Browser artifacts + per-user iteration | Planned |
| 4 | Parser expansion (EVTX, AmCache, ShellBags, ShimCache, Jump Lists, …) | Planned |
| 5 | Timeline generation (plaso supertimeline CSV) | Planned |
| 6 | IOC infrastructure (DFIR-report PDF → STIX 2.x) | Planned |
| 7 | Detection engine (IOC matching + Sigma rule support) | Planned |
| 8 | HTML viewer (local, offline) | Planned |
| 9 | `domain_controller` + `server_role` profiles | Planned |
| 10 | Raw NTFS access (`$MFT`, `$J`, `$LogFile`) | Planned |
| 11 | Detection Tier 3 correlation + multi-case HTML platform | Planned |
| 12 | Production readiness (code signing, validation suite, v1.0) | Planned |

---

## Why SAFE exists

Existing acquisition workflows on the team rely on combinations of KAPE, EZ
Tools, FTK Imager, and ad-hoc scripts. Each analyst runs a slightly different
process, output is inconsistent, and which artifacts get collected depends on
who is on call. Lab analysis is then held up by inconsistent input formats.

SAFE standardizes the field acquisition step: every analyst, every case,
produces the same case folder structure with the same coverage and the same
integrity chain. Lab analysis then operates on a known input format rather than
rebuilding parsing per case.

The longer-term goal is parity with KAPE's SANS_Triage coverage, implemented in
native Go without bundling third-party binaries — eliminating the license
restrictions, supply-chain dependencies, and cross-tool incompatibility of the
current toolchain.

---

## Design principles

1. **Profiles organized around case type, not tool activity.** Profiles are
   named after the investigative question they answer — `rapid_triage` for
   unknown targets, `endpoint_deep` for confirmed workstations,
   `domain_controller` for AD compromise, `server_role` for application servers.
   Capabilities like memory inspection are integrated into the profiles that
   need them, not split into separate "modes."

2. **Order of volatility within a profile.** Modules run most-volatile first.
   Process tables and network connections are captured before event logs and
   registry hives, because volatile state is gone if collection is interrupted
   while static artifacts survive.

3. **Collection on target, parsing in lab.** SAFE is a quiet visitor. Every
   command risks alerting EDR, tripping anti-forensic logic, and polluting the
   evidence with collection noise. The collection profile copies files and runs
   read-only commands only; all parsing is deferred to lab analysis via
   `safe --analyze`.

4. **Tamper-evident output.** Every collected file is SHA-256 hashed, every
   module produces a manifest, and the case ships with a top-level manifest
   covering every file. Verification is offline and works on any machine with
   the `safe` binary.

5. **Self-contained.** One Go binary. No runtime dependencies, no installer, no
   network requirement. Everything ships in the executable.

---

## Profile catalog

| Profile | Use when | Status |
|---|---|---|
| `rapid_triage` | First touch on an unknown target; fast, broadly useful triage to decide if deeper collection is needed | **Built (v0.2.0)** |
| `endpoint_deep` | Confirmed workstation or single-purpose server needing detailed collection (memory inspection, extended channels, per-user artifacts) | Planned (Phases 2–3) |
| `domain_controller` | Target is a domain controller in a suspected domain-compromise case | Planned (Phase 9) |
| `server_role` | Application server (IIS, Exchange, MSSQL, SharePoint, File Server); auto-detects roles | Planned (Phase 9) |

Full profile design, module assignments, and selection guidance live in
[`docs/PROFILES.md`](docs/PROFILES.md).

---

## What's in Phase 1

The `rapid_triage` profile executes nine modules in order of volatility:

| # | Module | Purpose |
|---|---|---|
| 1 | `process_snapshot` | Running processes, services, command lines, parent PIDs |
| 2 | `network_snapshot` | TCP/UDP connections, routes, ARP, DNS cache, firewall config |
| 3 | `system_metadata` | Hostname, OS version, network configuration, user identity |
| 4 | `eventlogs_core` | 8 core event channels (Security, System, Application, PowerShell, TaskScheduler, TerminalServices, WinRM, Defender) |
| 5 | `registry_core` | SAM, SYSTEM, SOFTWARE, SECURITY hives |
| 6 | `persistence_core` | Scheduled tasks, services, Run/RunOnce keys, WMI subscriptions, Winlogon, IFEO, AppInit_DLLs |
| 7 | `amcache_collection` | Amcache.hve + transaction logs (VSS) |
| 8 | `user_hives_collection` | NTUSER.DAT and UsrClass.dat per user, with transaction logs (VSS) |
| 9 | `prefetch_collection` | All `.pf` files from `C:\Windows\Prefetch` (VSS) |

A clean Windows 11 admin run produces roughly 500 artifacts in ~30 seconds, and
the case folder is fully verifiable with `safe --verify`.

The analyzer (`safe --analyze`) currently ships two parsers:

- **UserAssist** — reads collected NTUSER.DAT hives and produces per-user CSVs
  with decoded program execution paths, run counts, focus times, and last-run
  timestamps.
- **Prefetch** — parses collected `.pf` files into structured execution
  evidence.

Future parsers follow the same `Parser` interface and find their source module
via glob.

---

## Architecture

```
cmd/safe/                  CLI entry point
internal/
  module/                  collection modules (one .go per module)
  analyzer/                lab-side parsers (one .go per parser)
  profile/                 collection profile definitions
  engine/                  module orchestration, VSS lifecycle, timing
  vss/                     shadow copy management (creation, mount, cleanup)
  manifest/                integrity chain, verification
  pathfinder/              user profile discovery (Unicode-safe)
  preflight/               pre-collection sanity checks
  tui/                     interactive terminal UI
  casemeta/                case metadata model
```

Key infrastructure:

- **Shared VSS shadow per case.** The engine creates one VSS shadow at the start
  of collection if any module needs locked-file access, and shares it across all
  such modules. This cut amcache collection from ~1.6 s to ~60 ms, with similar
  gains elsewhere.

- **Orphan shadow cleanup.** SAFE identifies its own shadows via matching
  symlinks at `C:\safe_shadow_*` and cleans orphans from interrupted runs at
  every startup. An explicit `--cleanup-shadows` flag is also available.

- **Unicode-safe user profile discovery.** Tested against profiles with Cyrillic
  names (Алексей). Bypasses the ANSI fallback in
  `golang.org/x/sys/windows/registry` that corrupts non-ASCII characters by
  manually decoding UTF-16 LE.

- **Watchdog timeouts.** Per-module timeout + per-profile total budget + hard
  ceiling. A misbehaving module cannot stall collection beyond its budget.

- **Per-module independence.** Each module runs in isolation; a module failure
  does not affect subsequent modules.

- **Manifest chain.** Each module emits a `module.json` with hashes of every
  artifact it produced. The case-level `manifest.json` references and hashes each
  module manifest, and `manifest.sha256` allows external verification of the full
  chain.

---

## Build

```bash
# macOS/Linux development build (for running analyzer mode in the lab)
go build -o safe ./cmd/safe

# Windows production build (cross-compiled)
GOOS=windows GOARCH=amd64 go build -o safe.exe ./cmd/safe
```

The Windows binary is the one carried to a targeted machine. The macOS/Linux
binary is sufficient for running analyzer mode against case folders in the lab.

---

## Usage

### Collection (on the target machine, elevated)

CLI mode:

```
.\safe.exe --case INC-2026-0418 --analyst <name> \
           --target <hostname> --target-class workstation
```

Interactive TUI mode (guided input):

```
.\safe.exe --tui
```

Common flags:

| Flag | Purpose |
|---|---|
| `--case <id>` | Case identifier (required) |
| `--analyst <name>` | Analyst name or initials (required) |
| `--target <hostname>` | Target identifier (required) |
| `--target-class workstation\|server\|unknown` | Target classification |
| `--profile rapid_triage` | Collection profile (default: `rapid_triage`) |
| `--output <dir>` | Case output base directory |
| `--dry-run` | Validate environment without collecting |
| `--list-profiles` | List available profiles |
| `--cleanup-shadows` | Remove SAFE-created VSS shadows from interrupted runs |
| `--skip-preflight` | Skip preflight checks (advanced use only) |

A typical `rapid_triage` run takes ~30 seconds on a healthy Windows 11
workstation. Output is written to `<output>/CASE-<id>_<timestamp>/`.

### Analysis (back in the lab, on the analyst's workstation)

```
safe --analyze <case-folder>
```

Reads the collected case folder and produces parsed output in a
`<case-folder>/lab_report/` subdirectory. The analyzer runs entirely offline;
the target machine is never re-touched.

### Verification

```
safe --verify <case-folder>
```

Walks every file, compares it to its recorded SHA-256, and reports any mismatch.
Useful for chain-of-custody documentation and long-term storage integrity.

---

## What SAFE does NOT do

These are deliberate scope boundaries, documented with rationale in
[`docs/LIMITATIONS.md`](docs/LIMITATIONS.md):

- Full physical memory acquisition (use WinPmem or Magnet RAM Capture)
- Full disk imaging (use FTK Imager, Magnet AXIOM, or `dd`)
- Kernel-mode forensics (use Volatility on external memory dumps)
- Network packet capture (use Wireshark or tcpdump)
- Cross-platform forensics — Windows targets only
- Cloud forensics
- Mobile forensics
- Network-based collection — offline-first design only

SAFE gets the evidence those tools cannot easily get (live state, integrated
collection across artifact types, standardized output). Those tools get the
evidence SAFE does not try to get.

---

## Documentation

| Document | Purpose |
|---|---|
| [`docs/PLAN.md`](docs/PLAN.md) | Master v1.0 plan: scope, artifact coverage, build sequence, timeline |
| [`docs/PROFILES.md`](docs/PROFILES.md) | Profile design, module assignments, selection guidance |
| [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) | Explicit out-of-scope items with rationale |
| [`docs/MODULES_REFERENCE.md`](docs/MODULES_REFERENCE.md) | Per-module command reference for the IR team |
| [`docs/DESIGN_QUESTIONS.md`](docs/DESIGN_QUESTIONS.md) | Open questions and resolution log |
| [`CHANGELOG.md`](CHANGELOG.md) | Development log, per-session updates |

For management review, start with `docs/PLAN.md`. For analyst onboarding, start
with `docs/PROFILES.md` and `docs/MODULES_REFERENCE.md`. For developer
contribution, start with `docs/PLAN.md`, then `docs/PROFILES.md`, then this
README.

---

## Dependencies

Direct dependencies, all permissively licensed (MIT, Apache 2.0, BSD) and
statically compiled into the binary:

| Package | Purpose | License |
|---|---|---|
| `github.com/charmbracelet/bubbletea` | TUI framework | MIT |
| `github.com/charmbracelet/bubbles` | TUI components | MIT |
| `github.com/charmbracelet/lipgloss` | TUI styling | MIT |
| `www.velocidex.com/golang/regparser` | Offline registry hive parsing | Apache 2.0 |
| `www.velocidex.com/golang/go-prefetch` | Offline Prefetch parsing | Apache 2.0 |
| `golang.org/x/sys/windows/registry` | Live registry access (Windows only) | BSD |

Using mature libraries rather than hand-rolling equivalents is deliberate: hive
parsing alone (regparser) represents years of refinement across thousands of
real cases, and replacing it would introduce forensic-correctness risk far worse
than a tightly-scoped permissive dependency. Equally deliberate is *not* bundling
third-party binaries (KAPE, EZ Tools, WinPmem): SAFE ships as one statically
linked Go binary with no external executable dependencies, minimizing license
complexity, attack surface, and update friction.

---

## Internal use

SAFE is currently private to a single IR team and is not yet positioned for
external distribution. Decisions about open-source release, commercial
licensing, or wider internal rollout are deferred until v1.0 is stable.
</content>
</invoke>
