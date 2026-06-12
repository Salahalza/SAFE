# SAFE Roadmap

Last updated: 2026-06-12 (session 2026-06-12f)

Session-level breakdown of work ahead. Each session is roughly 1-3 hours
of focused Claude Code work. Sessions are sequential by default.

For phase-level vision, see `docs/PLAN.md`.

---

## Immediate (Migration to Claude Code)

| Session | Goal | Effort |
|---|---|---|
| M1 | ASCII character fallback for TUI; test analyze flow end-to-end | 60-90 min |
| M2 | README rewrite for GitHub presentation; profiles section | 60-90 min |
| M3 | SAHM → SAFE rename, atomic — **DONE** (2026-06-12c) | 2-3 hours |

M1–M3 are complete. The project is renamed (SAFE), polished, and ready for
Phase 2.

---

## Phase 2 — Extended Collection — COLLECTION COMPLETE (2026-06-12f)

All Phase 2 *collection* modules are built and VM-verified. Sessions ran out of
table order (the contentious PMI module was resequenced after the two quieter
extended modules — see journal 2026-06-12d). The deferred 2.5 items (COM
hijacks, WMI) and the PMI analyzer are LAB-SIDE parsing work and move to Phase 4.

| Session | Goal | Status |
|---|---|---|
| 2.3 | extended_event_channels module (bulk pattern) | **DONE** (2026-06-12d) |
| 2.4 | extended_persistence — BAM, services, ASEPs | **DONE** (2026-06-12d) |
| 2.1 | Design process_memory_inspection module | **DONE** (2026-06-12e) |
| 2.2 | Implement process_memory_inspection; VM test | **DONE** (2026-06-12f) |
| 2.6 | endpoint_deep profile (v0.3.0) + memory_triage; integration testing | **DONE** (2026-06-12f) |
| 2.7 | Documentation pass | **DONE** (2026-06-12f) |
| 2.5 | extended_persistence — COM, WMI extras | **DEFERRED to Phase 4** (lab-side: per-user CLSID + WMI repository need hive/repo parsing, not on-target reg query) |

Carried into Phase 4 (Parser Expansion): the `process_memory` analyzer (strings
/ PE-carve / RWX triage over PMI dumps), the COM-hijack hive-parser, and WMI
surfacing. The next *collection* phase is Phase 3.

---

## Phase 3 — Browser + Per-User (4-6 sessions)

| Session | Goal | Effort |
|---|---|---|
| 3.1 | per_user_iteration infrastructure module | 2-3 hours |
| 3.2 | browser_artifacts: Chrome + Edge collection | 2-3 hours |
| 3.3 | browser_artifacts: Firefox + decrypt considerations | 2 hours |
| 3.4 | jump_lists collection module | 2 hours |
| 3.5 | endpoint_deep profile updates | 1 hour |
| 3.6 | Documentation + integration testing | 1-2 hours |

---

## Phase 4 — Parser Expansion (20-30 sessions)

| Session | Goal | Effort |
|---|---|---|
| 4.1 | EVTX library evaluation; decision | 1-2 hours |
| 4.2 | EVTX parser — first pass on Security.evtx | 2-3 hours |
| 4.3 | EVTX parser — other channels | 2-3 hours |
| 4.4 | EVTX parser — edge cases | 2-3 hours |
| 4.5 | AmCache parser (using regparser) | 2-3 hours |
| 4.6 | AmCache parser — additional categories | 2 hours |
| 4.7 | ShellBags parser — research and design | 2 hours |
| 4.8 | ShellBags parser — implementation | 3-4 hours |
| 4.9 | ShellBags parser — iteration | 2-3 hours |
| 4.10 | ShimCache (AppCompatCache) parser | 2-3 hours |
| 4.11 | ShimCache iteration | 1-2 hours |
| 4.12 | Jump Lists parser — research and design | 2 hours |
| 4.13 | Jump Lists parser — implementation | 3-4 hours |
| 4.14 | Browser history parser (SQLite, all browsers) | 2-3 hours |
| 4.15 | Browser cookies parser | 2 hours |
| 4.16 | Browser downloads parser | 1-2 hours |
| 4.17 | Scheduled Tasks XML parser | 2 hours |
| 4.18 | BAM/DAM parser | 2 hours |
| 4.19 | WMI persistence parser — design | 2 hours |
| 4.20 | WMI persistence parser — implementation | 3-4 hours |
| 4.21 | Cross-parser polish; common helpers | 2 hours |
| 4.22 | Documentation pass | 2 hours |
| 4.23 | Parser validation against known-good samples | 2-3 hours |

---

## Phase 5 — Timeline (3-5 sessions)

| Session | Goal | Effort |
|---|---|---|
| 5.1 | Timeline aggregator design | 2 hours |
| 5.2 | Per-parser timeline contribution interface | 2 hours |
| 5.3 | Implement aggregator; produce timeline.csv | 2-3 hours |
| 5.4 | Timeline Explorer compatibility verification | 1-2 hours |
| 5.5 | Polish, documentation | 1-2 hours |

---

## Phase 6 — IOC Infrastructure (8-12 sessions)

| Session | Goal | Effort |
|---|---|---|
| 6.1 | PDF library evaluation | 1-2 hours |
| 6.2 | safe ioc-extract subcommand skeleton | 2 hours |
| 6.3 | Regex extraction layer | 3 hours |
| 6.4 | Defanging detection and re-fanging | 2-3 hours |
| 6.5 | Validation layer | 2-3 hours |
| 6.6 | Context preservation | 2 hours |
| 6.7 | STIX 2.x output format | 2-3 hours |
| 6.8 | IOC pack metadata and storage | 1-2 hours |
| 6.9 | IOC loading at analyzer time | 2-3 hours |
| 6.10 | Test against real DFIR reports | 2-3 hours |
| 6.11 | False positive rate analysis and tuning | 2-3 hours |
| 6.12 | Documentation and examples | 1-2 hours |

---

## Phase 7 — Detection Engine T1+T2 (10-15 sessions)

| Session | Goal | Effort |
|---|---|---|
| 7.1 | Detection engine architecture | 2 hours |
| 7.2 | Tier 1: IOC matching | 3 hours |
| 7.3 | Tier 1: confidence weighting | 2 hours |
| 7.4 | Tier 1: findings format and storage | 2 hours |
| 7.5 | Sigma rule research and mapping | 2-3 hours |
| 7.6 | Sigma YAML parser | 2-3 hours |
| 7.7 | Sigma condition evaluator (subset) | 3-4 hours |
| 7.8 | Sigma condition evaluator (more operators) | 3-4 hours |
| 7.9 | Sigma rule pack integration | 2-3 hours |
| 7.10 | SAFE-native rule format | 2-3 hours |
| 7.11 | Detection findings in timeline.csv | 1-2 hours |
| 7.12 | Detection summary in TUI report viewer | 2 hours |
| 7.13 | Testing and iteration | 2-3 hours |
| 7.14 | Documentation; rule writing guide | 2 hours |

---

## Phase 8 — HTML Viewer (8-12 sessions)

| Session | Goal | Effort |
|---|---|---|
| 8.1 | Technology choice; design language | 2 hours |
| 8.2 | safe --serve subcommand | 2 hours |
| 8.3 | Header card and case metadata view | 2-3 hours |
| 8.4 | Modules table view with sort/filter | 2-3 hours |
| 8.5 | Observations view | 2 hours |
| 8.6 | Timeline view (visual, scrubable) | 3-4 hours |
| 8.7 | Timeline view (filtering) | 2-3 hours |
| 8.8 | Detections view | 2-3 hours |
| 8.9 | Drill-down into artifacts | 2-3 hours |
| 8.10 | Responsive design | 2 hours |
| 8.11 | Polish, accessibility | 2 hours |
| 8.12 | Documentation; case packaging | 1-2 hours |

---

## Phases 9-12 — Detailed planning deferred

Phase 9 (DC + servers), Phase 10 (Raw NTFS), Phase 11 (correlation +
platform), Phase 12 (production readiness) will get session-level
breakdowns when Phase 8 is wrapping up.

---

## How to Use This Document

- **Each session:** read the goal, do the work, check it off
- **Between sessions:** update SESSION_HANDOFF.md and write a journal entry
- **When estimates are wrong:** they will be; update next session's estimate
- **When new sessions emerge:** insert them in the right phase

---

## Tracking

Use checkboxes when sessions complete. Add a journal entry filename next
to each completed session.

Format:
```
- [x] 2.1 — Design process_memory_inspection module (journal: 2026-06-12e-pmi-design.md)
```
