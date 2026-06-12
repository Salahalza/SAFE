# SAFE/SAHM Development Plan

Last updated: 2026-06-10
Status: Phase 1 complete. Phases 2-12 defined.

This document describes the long-range development plan for SAFE (currently
named SAHM in code; rename planned). Each phase is a meaningful chunk of
work, typically spanning multiple development sessions.

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
team workflows with bilingual identity (سيف / SAFE), single-binary
deployment, and emphasis on what an IR analyst actually does day-to-day.

---

## Architectural Principles (Reminders)

These come from CLAUDE.md and apply across all phases:

1. **Strict collection/analysis separation** — collection on target, parsing in lab
2. **Order of volatility** — most volatile first within profiles
3. **Shared VSS shadow per case** — one shadow, modules share it
4. **Bulk vs primary artifact distinction** — clarity in artifact counts
5. **Hash everything, manifest everything** — integrity contract
6. **Quality over speed** — never ship something half-correct
7. **Single-binary deployment** — Go-native, no runtime dependencies
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
- `process_memory_inspection` — Targeted process memory regions
- `extended_event_channels` — Bulk-collect full winevt/Logs
- `extended_persistence` — BAM/DAM, COM hijacks, more service registries

**Profile updates:** `endpoint_deep` profile gets defined.

**Estimated effort:** 6-10 Claude Code sessions.

---

## Phase 3 — Browser Artifacts + Per-User Iteration

**Goal:** Per-user artifact collection scaffolding and browser support.

**Modules to build:**
- `per_user_iteration` — Infrastructure for per-user sub-modules
- `browser_artifacts` — Chrome, Edge, Firefox per-user
- `jump_lists` — Per-user jump list collection

**Estimated effort:** 4-6 Claude Code sessions.

---

## Phase 4 — Parser Expansion

**Goal:** Every collected artifact has a corresponding analyzer parser.

**Approach:** Go-native parsers, using mature Go libraries where they're
already excellent. Single-binary deployment preserved.

**Libraries:**
- `velocidex/regparser` — registry (in use)
- `velocidex/go-prefetch` — Prefetch (in use)
- `velocidex/evtx` — EVTX (evaluate maturity first)

**Parsers to build (priority order):**
1. Event log parser (EVTX) — highest analyst value
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

**Estimated effort:** 20-30 Claude Code sessions.

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

**Estimated effort:** 3-5 Claude Code sessions.

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

**Estimated effort:** 8-12 Claude Code sessions.

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

**Estimated effort (T1+T2):** 10-15 Claude Code sessions.

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

**Estimated effort:** 8-12 Claude Code sessions.

---

## Phase 9 — Domain Controller + Server Roles

**Goal:** Specialized profiles for server forensics.

**Profiles:**
- `domain_controller` — NTDS.dit, DRSUAPI logs, Kerberos cache, GPO state
- `server_role` — auto-detects roles, runs role-specific collection
  (Exchange, MSSQL, SharePoint, IIS, File Server)

**Why deferred to Phase 9:** Salah's caseload is server-heavy. Building
this after parsing/timeline/detection means server artifacts immediately
participate in the analyst workflow.

**Estimated effort:** 6-10 Claude Code sessions.

---

## Phase 10 — Raw NTFS

**Goal:** Direct NTFS structure access: `$MFT`, `$J`, `$LogFile`.

**Challenges:** Raw disk access, complex binary formats, large output,
high AV/EDR visibility.

**Estimated effort:** 8-12 Claude Code sessions.

---

## Phase 11 — Detection Tier 3 + HTML Platform (B)

**Goal:** Cross-artifact correlation; multi-case platform.

**Tier 3 correlation:** Chains of events across artifacts.

**HTML platform (B):** Server component, multi-case storage,
authentication, cross-case queries.

**Estimated effort:** 15-25 Claude Code sessions.

---

## Phase 12 — Production Readiness

**Goal:** Ship SAFE 1.0.

**Deliverables:**
- Code signing (authenticode)
- Reproducible builds
- Validation test suite
- Performance benchmarks
- Documented installation and deployment
- Public-facing documentation (if going public)

**Estimated effort:** 6-10 Claude Code sessions.

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
| 11 | T3 + HTML platform | 15-25 | 88-137 |
| 12 | Production | 6-10 | 94-147 |

Total estimated sessions: **94-147** with Claude Code.

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
as the IR tool Salah wishes existed for his actual work, with regional
and team context shaping decisions. Hold that framing through development.
