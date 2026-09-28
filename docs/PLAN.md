# SAFE Development Plan

Last updated: 2026-06-10
Status: Phase 1 complete. Phases 2-12 defined.

This document describes the long-range development plan for SAFE. Each phase
is a meaningful chunk of work, typically spanning multiple development
sessions.

For session-level planning, see `docs/ROADMAP.md`.
For open design questions, see `docs/DESIGN_QUESTIONS.md`.

---

## Vision

SAFE is a Windows forensic acquisition and analysis platform for incident
response. The target user is the IR analyst working a real case, often at
incident scene, who needs:

- Fast, reliable evidence collection
- Parsed, analyst-ready output
- Timeline reconstruction
- Threat intelligence integration
- Automated detection against known IOCs and behaviors
- A unified workflow rather than juggling 5-10 separate tools

SAFE is opinionated. It is not trying to replace Velociraptor, KAPE, or
commercial EDR forensics modes. It is designed for specific regional and
team workflows with bilingual identity (سيف / SAFE), self-contained split-binary
deployment, and emphasis on what an IR analyst actually does day-to-day.

---

## Architectural Principles (Reminders)

These come from DEV_HISTORY.md and apply across all phases:

1. **Strict collection/analysis separation** — collection on target, parsing in lab
2. **Order of volatility** — most volatile first within profiles
3. **Shared VSS shadow per case** — one shadow, modules share it
4. **Bulk vs primary artifact distinction** — clarity in artifact counts
5. **Hash everything, manifest everything** — integrity contract
6. **Quality over speed** — never ship something half-correct
7. **Split-binary deployment** — Two self-contained Go-native binaries (safe-collect.exe for target acquisition, and safe-analyze for workstation analysis/TUI report) with no external runtime dependencies.
8. **Unified parsing approach** — Go libraries where excellent, Go-native otherwise

---

## Phase 1 — COMPLETE

### Goal
Establish the foundation. Rapid triage profile, basic analyzer infrastructure,
TUI for collection and viewing.

### Delivered
- 9 collection modules
- 2 analyzer parsers (UserAssist, Prefetch)
- VSS shadow management with orphan cleanup
- IR# / CSI# case metadata
- Bulk vs primary artifact distinction
- TUI with three-option welcome, filepicker, analyze flow, structured
  report viewer
- Manifest infrastructure
- Block-letter banner, status badges, styled cards

### Status: SHIPPED

---

## Phase 2 — Extended Collection

**Goal:** Expand collection coverage beyond rapid_triage.

**Modules to build:**
- `process_memory_inspection` — Per-process memory regions — **DONE**
  (collect-only; 2026-06-12f). Dumps exec/RWX-private regions; analysis is
  lab-side.
- `extended_event_channels` — Bulk-collect full winevt/Logs — **DONE**
  (2026-06-12d).
- `extended_persistence` — BAM/DAM, service registries, ASEPs — **DONE**
  (2026-06-12d). COM hijacks + WMI deferred to lab-side parsing (Phase 4).

**Profile updates:** `endpoint_deep` defined (v0.3.0) and a dedicated LOUD
`memory_triage` profile added — **DONE** (2026-06-12f).

**Estimated effort:** 6-10 my workspace sessions.

### Status: COLLECTION COMPLETE (2026-06-12f)

All Phase 2 collection modules are built and VM-verified. The remaining
Phase-2-scoped items are lab-side analyzers — the `process_memory` analyzer (for
the PMI dumps), the COM-hijack hive-parser, and WMI surfacing — which carry into
Phase 4 (Parser Expansion). The next *collection* phase is Phase 3.

---

## Phase 3 — Browser Artifacts + Per-User Iteration

**Goal:** Per-user artifact collection scaffolding, browser support, and Jump Lists.

**Modules to build:**
- `per_user_iteration` — Shared infrastructure in helpers/context to cleanly iterate discovered profiles, map them to VSS shadow paths, and organize output subdirectories by SID.
- `browser_artifacts` — Collect Google Chrome, Microsoft Edge, and Mozilla Firefox for all human profiles. Collect History, Downloads, Bookmarks, Cookies, Extensions, and Session/Local Storage databases. Also collect DPAPI master keys (`%APPDATA%\Microsoft\Protect\<SID>`) to enable offline decryption.
- `jump_lists` — Collect both `AutomaticDestinations` and `CustomDestinations` directories entirely for all profiles with no caps or filters.

**Profile Integration:**
- Exclude browser and jump list modules from `rapid_triage` due to footprint and collection time. Add them strictly to the `endpoint_deep` profile.

**Estimated effort:** 4-6 my workspace sessions.

### Status: COLLECTION COMPLETE (2026-06-19)

Browser Artifacts (Chrome, Edge, Firefox, DPAPI keys) and Jump Lists collection modules are built, registered under the `endpoint_deep` profile, and VM-verified.

---

## Phase 4 — Parser Expansion
 
**Goal:** Every collected artifact has a corresponding analyzer parser.
 
**Approach:** Go-native parsers, using mature Go libraries where they're
already excellent. Single-binary deployment preserved.
 
**Libraries:**
- `velocidex/regparser` — registry (in use)
- `velocidex/go-prefetch` — Prefetch (in use)
- `velocidex/evtx` — EVTX (DONE — in use)
 
**Parsers to build (priority order):**
1. Event log parser (EVTX) — **DONE** (2026-06-19)
2. AmCache parser
3. ShellBags parser
4. ShimCache (AppCompatCache) parser
5. Jump Lists parser
6. Browser history parser (SQLite-based, simpler)
7. Scheduled Tasks XML parser
8. BAM/DAM parser
9. WMI persistence parser (hardest)
 
**Quality bar:** If a native parser cannot achieve excellent output:
1. Check if a Go library exists and is mature enough
2. If yes, switch to library, contribute upstream where useful
3. If no, document the gap and consider deferring
 
**Estimated effort:** 20-30 my workspace sessions.

### Status: IN PROGRESS (EVTX parser complete)
 
---

## Phase 5 — Timeline Generation

**Goal:** Unified chronological timeline of all parsed events.

**Approach:** Output in plaso supertimeline CSV format. Industry standard.
Compatible with Timeline Explorer, ELK/Splunk ingestion, every DFIR
analyst's existing workflow.

**Format:**
```
date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra
```

SAFE-specific data goes in `extra` column as key=value pairs.

**Deliverables:**
- Timeline aggregator in `internal/analyzer/timeline/`
- Each parser contributes events
- Single `timeline.csv` written to `lab_report/`
- Source attribution on every event

**Estimated effort:** 3-5 my workspace sessions.

---

## Phase 6 — IOC Infrastructure

**Goal:** Ingest threat intelligence from public DFIR reports (PDFs).

### Components

#### `safe ioc-extract` subcommand
Takes a PDF, produces a STIX 2.x bundle.

Pipeline:
1. PDF → text via Go-native PDF extraction
2. Text → IOC candidates via regex extraction
3. Defanging detection and re-fanging
4. Validation layer (RFC1918, well-known services, false positive filters)
5. Context preservation (surrounding sentence)

Output: STIX 2.x JSON bundle in `safe-iocs/<pack-name>.json`

#### IOC pack storage
- Directory: `safe-iocs/` next to binary, or configurable
- Format: STIX 2.x JSON bundles
- Pack metadata: source PDF, extraction date, confidence, vendor

#### IOC loading at analysis time
- Analyzer loads all packs at analysis time
- Builds in-memory index for fast lookup during detection
- Pack confidence weights propagate to detection findings

**Quality requirements:** High standard, essential. False positive rate
documented and below acceptable threshold.

**Estimated effort:** 8-12 my workspace sessions.

---

## Phase 7 — Detection Engine

**Goal:** Automated detection against parsed artifacts.

### Three-tier architecture

#### Tier 1: IOC matching
Walk parsed artifacts, check fields against loaded IOC packs.
- Severity (from pack confidence)
- IOC value and type
- Artifact where matched
- Source attribution

#### Tier 2: Behavioral rules (Sigma compatibility)
Sigma is the industry standard. SAFE imports SigmaHQ rules where they
apply to SAFE's parsed artifact types.

Expected coverage from SigmaHQ:
- ~30-40% of rules apply directly to SAFE's event log output
- ~20-30% apply with adaptation
- ~30-40% don't apply (real-time data SAFE doesn't have)

Also supports SAFE-native rules for things Sigma doesn't cover.

#### Tier 3: Cross-artifact correlation (DEFERRED to Phase 11)
Chains of events. Requires mature timeline + correlation engine.

**Estimated effort (T1+T2):** 10-15 my workspace sessions.

---

## Phase 8 — HTML Viewer

**Goal:** Browser-based viewer that complements the TUI.

**Approach:** Local-only HTML page reading case folder JSON.

**Views:**
- Header card with case metadata
- At-a-glance summary
- Modules table (sortable, filterable)
- Observations grouped by module
- Timeline view (visual, scrubable, filterable)
- Detections view (IOC matches, Sigma findings)
- Drill-down into individual artifacts

**Architecture:**
- Single self-contained HTML page (or small bundle)
- Reads same JSON as TUI
- `safe --serve <case-folder>` for browsers blocking file://
- No external CDN dependencies (offline use)

**Estimated effort:** 8-12 my workspace sessions.

---

## Phase 9 — Domain Controller + Server Roles

**Goal:** Specialized profiles for server forensics.

**Profiles:**
- `domain_controller` — NTDS.dit, DRSUAPI logs, Kerberos cache, GPO state
- `server_role` — auto-detects roles, runs role-specific collection
  (Exchange, MSSQL, SharePoint, IIS, File Server)

**Why deferred to Phase 9:** Building
this after parsing/timeline/detection means server artifacts immediately
participate in the analyst workflow.

**Status (2026-07-08b):** `server_infra` is the auto-detecting server profile;
every role module self-gates via `Applies()` (skips cleanly off-role). AD/DC
(`ad_collection`), IIS (`iis_collection` + analyzer + web-shell rules), and
Exchange (`exchange_collection`) collection are implemented and validated against
the real lab DC/WEB/EXCH hosts, plus an Exchange web-surface hunt
(ProxyLogon/ProxyShell rules IIS-04/05/06). Remaining: MSSQL (deferred — no lab
host to validate against), SharePoint, File Server; and an Exchange transport-log
analyzer.

**Estimated effort:** 6-10 my workspace sessions.

---

## Phase 10 — Raw NTFS

**Goal:** Direct NTFS structure access: `$MFT`, `$J`, `$LogFile`.

**Challenges:** Raw disk access, complex binary formats, large output,
high AV/EDR visibility.

**Estimated effort:** 8-12 my workspace sessions.

---

## Phase 11 — Detection Tier 3

**Goal:** Cross-artifact correlation.

**Tier 3 correlation:** Chains of events across artifacts.

**Estimated effort:** 10-15 my workspace sessions.

---

## Phase 12 — Dead Disk Image Analysis

**Goal:** SAFE must be able to conduct forensic collection and analysis on dead disk images (E01, VHDX, or raw `dd`) in addition to live systems.

**Phase 12-A — Mounted-image support (DONE, 2026-07-08).** After weighing three
options (analyst mounts read-only and SAFE reads the volume; SAFE self-mounts
VHDX via the native Win32 `AttachVirtualDisk`; SAFE natively parses E01/raw with
`go-ewf`+`go-ntfs`), the chosen v1 is **analyst-mounts, SAFE-reads** — it is
format-agnostic (any image the analyst's imager can mount read-only), reuses the
entire existing analysis pipeline unchanged, and avoids reimplementing hardened
NTFS/EWF parsing. Delivered:
- An **evidence-root abstraction** (`Context.Root`/`Live`) replacing the direct
  `ctx.Shadow.MountedPath` reads across all collectors — a live case roots at the
  VSS shadow, a dead image at the mounted volume, one code path.
- A **`LiveOnly` module interface** so volatile/live-command modules are skipped
  for an image source, and a `disk_image` profile of the file/hive-based
  collectors that has no volatile state to capture.
- **`safe-collect --source-root <vol>`** end to end, with casemeta chain-of-custody
  fields.
- **Offline discovery** from the image's own hives (via `regparser`) so user-profile
  and DC/IIS/Exchange role detection target the imaged host, not the analyst's.
- Validated against a real compromised-server VHDX (web-shell intrusion surfaced,
  including IIS-02 shells-accessed correlation) and a live regression.

**Phase 12-B — Native image parsing (deferred).** Read E01/raw *without* a mount
using `go-ewf` + `go-ntfs` (the latter already a dependency), for a fully
self-contained single-binary path and to collect `$MFT`/USN from an image. Also:
native VHDX self-mount via `AttachVirtualDisk`; generalize `mapToRoot` for
multi-volume images.

**Phase 12-C — Memory-dump analysis (deferred to a research spike).** No mature
Go-native memory-forensics library exists (Volatility 3 is Python; wrapping it
breaks the single-binary rule). Scope TBD — likely a research spike before any
build.

**Estimated remaining effort (12-B/12-C):** 10-15 sessions.

---



## Timeline Summary

| Phase | Description | Sessions | Cumulative |
|---|---|---|---|
| 1 | Foundation (DONE) | — | — |
| 2 | Extended collection | 6-10 | 6-10 |
| 3 | Browser + per-user | 4-6 | 10-16 |
| 4 | Parser expansion | 20-30 | 30-46 |
| 5 | Timeline | 3-5 | 33-51 |
| 6 | IOC infrastructure | 8-12 | 41-63 |
| 7 | Detection (T1+T2) | 10-15 | 51-78 |
| 8 | HTML viewer | 8-12 | 59-90 |
| 9 | DC + servers | 6-10 | 65-100 |
| 10 | Raw NTFS | 8-12 | 73-112 |
| 11 | Detection Tier 3 | 10-15 | 83-127 |
| 12 | Dead Disk Image Analysis | 10-15 | 93-142 |

Total estimated sessions: **93-142** with my workspace.

At 3-5 focused sessions per week, this is **6-12 months** to SAFE 1.0
(optimistic). Real number may be 12-24 months. Treat as direction, not
contract.

---

## What This Plan Is Not

- Not a contract — sessions and scope will adjust
- Not exhaustive — small fixes not enumerated
- Not parallel — phases are roughly sequential
- Not a feature race — each phase serves analyst value, not feature parity

SAFE is not trying to disrupt commercial DFIR tools. SAFE is being built
as the IR tool built specifically for actual case work, with regional
and team context shaping decisions. Hold that framing through development.
