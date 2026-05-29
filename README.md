# SAHM

**System for Artifact Harvesting and Management**

سهم — Arabic for "arrow."

SAHM is a Windows forensic acquisition platform built for incident response field work. A single self-contained executable, carried on a USB SSD, run on a targeted machine to collect tamper-evident forensic evidence into a case folder. The collected case is then taken back to the lab where SAHM's analysis mode produces parsed, analyst-ready output.

Written in Go. Cross-compiled to Windows from Mac/Linux. No installer, no runtime dependencies, no network requirement.

---

## Status

**Phase 1 complete (29 May 2026). v1.0 target: September 2026.**

The `rapid_triage` collection profile is functional and tested end-to-end against Windows 11. Analyzer infrastructure is built with one parser shipping (UserAssist). The remaining v1.0 work is documented in `PLAN.md` as four additional phases.

| Phase | Scope | Status |
|---|---|---|
| Phase 1 | rapid_triage profile + analyzer foundation | Complete |
| Phase 2 | endpoint_deep profile foundation (memory inspection, extended event channels, per-user iteration) | Not started |
| Phase 3 | endpoint_deep completion (browser artifacts, ShimCache parsing, deeper memory inspection) | Not started |
| Phase 4 | Raw NTFS access ($MFT, $J, $LogFile, NTFS metadata) | Not started |
| Phase 5 | domain_controller profile | Not started |
| Phase 6 | server_role profile (IIS, Exchange, MSSQL, SharePoint, File Server) | Not started |
| Phase 7 | Lab analysis mode native parsers | Continuous, parallel to phases 2-6 |
| Phase 8 | Release preparation (code signing, gold master, validation suite) | Not started |

---

## Why SAHM exists

Existing forensic acquisition workflows in our team rely on combinations of KAPE, EZ Tools, FTK Imager, and various ad-hoc scripts. Each analyst runs a slightly different process. Output is inconsistent. Some artifact types are collected, others missed depending on who is on call. Lab analysis is held up by inconsistent input formats.

SAHM standardizes the field acquisition step: every analyst, every case, produces the same case folder structure with the same coverage and the same integrity chain. The lab analysis step then operates on a known input format rather than rebuilding parsing per case.

The longer-term goal is full parity with KAPE's SANS_Triage coverage, implemented in native Go without bundling third-party binaries — eliminating license restrictions, supply-chain dependencies, and cross-tool incompatibility that come with the current toolchain.

---

## Design principles

**1. Profiles are organized around case type, not tool activity.** SAHM does not have separate "memory mode" and "triage mode" and "imaging mode." It has profiles named after the investigative questions they answer: rapid_triage for unknown targets, endpoint_deep for confirmed workstations needing detailed investigation, domain_controller for AD compromise cases, server_role for application servers. Memory inspection and other capabilities are integrated into the profiles where they are needed.

**2. Order of volatility within a profile.** Modules execute in order of data volatility, most volatile first. Process tables and network connections are captured before event logs and registry hives, because volatile state is gone if collection is interrupted while static artifacts survive.

**3. Collection on target, parsing in lab.** SAHM is a quiet visitor on a targeted device. Every command executed risks alerting EDR, triggering anti-forensic logic in malware watching for forensic activity, and polluting evidence with noise from the forensic activity itself. The collection profile copies files and runs read-only commands; it does not parse binary artifact formats, run regex extractions, or do any processing that can be deferred to lab analysis. Parsing runs on the analyst's workstation via `sahm --analyze <case-folder>`.

**4. Tamper-evident output.** Every collected file is hashed; every module produces a manifest; the case folder ships with a top-level SHA-256 manifest covering every file. Verification is offline and works on any machine with the `sahm` binary.

**5. Self-contained.** Single Go binary. No runtime dependencies. No installer. No network requirement. Everything ships in the executable itself.

---

## What SAHM does NOT do

These are deliberate scope boundaries, documented with rationale in `LIMITATIONS.md`:

- Full physical memory acquisition (use WinPmem or Magnet RAM Capture)
- Full disk imaging (use FTK Imager, Magnet AXIOM, or `dd`)
- Kernel-mode forensics (use Volatility on external memory dumps)
- Network packet capture (use Wireshark or tcpdump)
- Cross-platform forensics — Windows targets only
- Cloud forensics
- Mobile forensics
- Network-based collection — offline-first design only

SAHM gets the evidence those tools cannot easily get (live state, integrated collection across artifact types, standardized output). Those tools get the evidence SAHM does not try to get (full disk imaging, full memory dumps, network traffic).

---

## What's in Phase 1

The `rapid_triage` collection profile (currently v0.2.0) executes nine modules in order of volatility:

| # | Module | Purpose |
|---|---|---|
| 1 | process_snapshot | Running processes, services, command lines, parent PIDs |
| 2 | network_snapshot | TCP/UDP connections, routes, ARP, DNS cache, firewall config |
| 3 | system_metadata | Hostname, OS version, network configuration, user identity |
| 4 | eventlogs_core | 8 core event channels (Security, System, Application, PowerShell, TaskScheduler, TerminalServices, WinRM, Defender) |
| 5 | registry_core | SAM, SYSTEM, SOFTWARE, SECURITY hives |
| 6 | persistence_core | Scheduled tasks, services, Run/RunOnce keys, WMI subscriptions, Winlogon, IFEO, AppInit_DLLs |
| 7 | amcache_collection | Amcache.hve + transaction logs (VSS) |
| 8 | user_hives_collection | NTUSER.DAT and UsrClass.dat per user, with transaction logs (VSS) |
| 9 | prefetch_collection | All `.pf` files from `C:\Windows\Prefetch` (VSS) |

A clean Windows 11 admin run produces approximately 500 artifacts in ~30 seconds. The case folder is fully verified by `sahm --verify`.

The analyzer (`sahm --analyze`) currently ships one parser: UserAssist, which reads collected NTUSER.DAT hives and produces per-user CSVs with decoded program execution paths, run counts, focus times, and last-run timestamps. Future parsers will follow the same pattern.

---

## Architecture

```
cmd/sahm/                  CLI entry point
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

Key infrastructure highlights:

- **Shared VSS shadow per case.** The engine creates one VSS shadow at the start of collection if any module needs locked-file access, and shares it across all such modules. Reduced amcache collection from ~1.6 seconds to ~60 milliseconds, with similar gains in user_hives_collection and prefetch_collection.

- **Orphan shadow cleanup.** SAHM identifies its own shadows via matching symlinks at `C:\sahm_shadow_*`. At every startup, it cleans any orphans left from previously interrupted runs. An explicit `--cleanup-shadows` flag is also available.

- **Unicode-safe user profile discovery.** Tested against profiles with Cyrillic names (Алексей). Bypasses the Windows `golang.org/x/sys/windows/registry` ANSI fallback that corrupts non-ASCII characters by manually decoding UTF-16 LE.

- **Watchdog timeouts.** Per-module timeout + per-profile total budget + hard ceiling. A misbehaving module cannot stall collection beyond its budget.

- **Per-module independence.** The engine runs each module in isolation; a module failure does not affect subsequent modules.

- **Manifest chain.** Each module produces a `module.json` manifest with hashes of every artifact it produced. The case-level `manifest.json` references and hashes each module manifest. The case-level `manifest.sha256` allows external verification of the full chain.

---

## Build

```bash
# Mac/Linux development build (for testing analyzer mode)
go build -o sahm ./cmd/sahm

# Windows production build (cross-compiled)
GOOS=windows GOARCH=amd64 go build -o sahm.exe ./cmd/sahm
```

The Windows binary is the one carried to a targeted machine. The Mac/Linux binary is sufficient for running analyzer mode against case folders in the lab.

---

## Usage

### Collection (on the target machine, elevated)

CLI mode:

```
.\sahm.exe --case INC-2026-0418 --analyst <name> \
           --target <hostname> --target-class workstation
```

Interactive TUI mode (for analysts who prefer guided input):

```
.\sahm.exe --tui
```

Common flags:

| Flag | Purpose |
|---|---|
| `--case <id>` | Case identifier (required) |
| `--analyst <name>` | Analyst name or initials (required) |
| `--target <hostname>` | Target identifier (required) |
| `--target-class workstation\|server\|unknown` | Target classification |
| `--profile rapid_triage` | Collection profile (default: rapid_triage) |
| `--output <dir>` | Case output base directory |
| `--dry-run` | Validate environment without collecting |
| `--list-profiles` | List available profiles |
| `--cleanup-shadows` | Remove SAHM-created VSS shadows from interrupted runs |
| `--skip-preflight` | Skip preflight checks (advanced use only) |

A typical rapid_triage run takes ~30 seconds on a healthy Windows 11 workstation. Output is written to `<output>/CASE-<id>_<timestamp>/`.

### Analysis (back in the lab, on the analyst's workstation)

```
sahm --analyze <case-folder>
```

Reads the collected case folder and produces parsed output in a `<case-folder>/lab_report/` subdirectory. The analyzer runs entirely offline; the target machine is never re-touched.

### Verification

To confirm a case folder is unmodified since collection:

```
sahm --verify <case-folder>
```

Walks every file, compares to its recorded SHA-256, reports any mismatch. Useful for chain-of-custody documentation and for verifying long-term storage integrity.

---

## Documentation

The repository ships with the following operational documents:

| Document | Purpose |
|---|---|
| `PLAN.md` | Master v1.0 plan: scope commitment, artifact coverage, build sequence, timeline |
| `PROFILES.md` | Profile design, design principles, module assignments, selection guidance |
| `LIMITATIONS.md` | Explicit out-of-scope items with rationale |
| `MODULES_REFERENCE.md` | Per-module command reference for the IR team |
| `DESIGN_QUESTIONS.md` | Open questions and resolution log |
| `CHANGELOG.md` | Development log, per-session updates |

For management review: start with `PLAN.md`. For analyst onboarding: start with `PROFILES.md` and `MODULES_REFERENCE.md`. For developer contribution: start with `PLAN.md`, then `PROFILES.md`, then this README.

---

## Dependencies

Direct dependencies, all permissively licensed (MIT, Apache 2.0, BSD) and statically compiled into the binary:

| Package | Purpose | License |
|---|---|---|
| `github.com/charmbracelet/bubbletea` | TUI framework | MIT |
| `github.com/charmbracelet/bubbles` | TUI components | MIT |
| `github.com/charmbracelet/lipgloss` | TUI styling | MIT |
| `www.velocidex.com/golang/regparser` | Offline registry hive parsing | Apache 2.0 |
| `golang.org/x/sys/windows/registry` | Live registry access (Windows only) | BSD |

The choice to use libraries rather than write equivalents from scratch is deliberate. Hive parsing alone (regparser) represents years of refinement across thousands of real cases. Replacing it with a hand-written parser would introduce forensic correctness risks far worse than a tightly-scoped permissive-licensed library dependency.

The choice to NOT bundle third-party binaries (KAPE, EZ Tools, WinPmem) is also deliberate. SAHM ships as one statically-linked Go binary with no external executable dependencies. License complexity, attack surface, and update friction are all minimized.

---

## Internal use

SAHM is currently private to a single IR team. It is not yet positioned for external distribution. Decisions about open-source release, commercial licensing, or wider internal rollout are deferred until v1.0 is stable.
