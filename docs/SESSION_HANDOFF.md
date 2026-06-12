# SESSION HANDOFF

Last updated: 2026-06-13 (session 2026-06-13 — audit fixes + WMI parser)
Last assistant: Claude Code (VSCode)

This document captures the current state of the project, what's in flight,
and what to do next. Read this at the start of every Claude Code session
to load context.

---

## Where We Are

Phase 1 is complete and **Phase 2 (Extended Collection) collection work is
DONE** as of session 2026-06-12f. All three planned Phase 2 collection modules
are built and VM-verified — `extended_event_channels` and `extended_persistence`
(2026-06-12d) and `process_memory_inspection` (designed 2026-06-12e, implemented
2026-06-12f). The migration sessions M1–M3 are all done; the project is named
**SAFE** end to end (Go module `safe`, `cmd/safe/`, `C:\safe_shadow_*`,
regenerated TUI banner, all docs).

**Phase 2 is now fully complete — collection AND lab.** As of session
2026-06-13 the last deferred Phase 2 lab item, the WMI-subscription parser, is
built and verified (commit 2e1970e). The `process_memory` and `com_hijack`
analyzers landed in 2026-06-12g. There is no remaining Phase 2 debt. The next
*collection* phase is Phase 3 (Browser + Per-User). See "Phase 2 status" below.

The 2026-06-13 session also ran a correctness audit and landed 6 integrity/
reporting/module fixes (commits 4178da0..a8bd1cd, all pushed) — engine panic
recovery, `--verify` reconciliation (now covers lab_report + detects added
files), report collection-provenance, PMI partial-read salvage, SID-pinned
per-user hive dirs, failed-command output reconciliation, and CSV
formula-injection hardening. See docs/journal/2026-06-13-audit-fixes-and-wmi-parser.md.

**What works:**
- Collection via `safe --tui` or CLI flags
- Three profiles: `rapid_triage` (9 modules, v0.2.0), `endpoint_deep`
  (v0.3.0 — rapid_triage superset + process_memory_inspection +
  extended_persistence + extended_event_channels), and `memory_triage`
  (v0.1.0 — the dedicated LOUD profile: process_snapshot + process_memory_inspection)
- Analysis via `safe --analyze <case-folder>` or TUI Option 2
- Report viewing via TUI Option 3 (structured, scrollable, viewport-based)
- All terminal-size-sensitive screens scroll instead of clipping: the
  new-case form (mouse wheel / PgUp / PgDn / focus-follow) and the confirm,
  complete, and analyze-complete summary screens (shared scroll viewport);
  profile options render as a width-aware vertical list
- VSS shadow management with orphan cleanup
- IR# / CSI# case metadata fields
- Bulk vs primary artifact distinction
- 12 collection modules: process, network, system metadata, event logs,
  registry, persistence, amcache, user hives, prefetch, extended event
  channels, extended persistence, process memory inspection
- 5 analyzer parsers: UserAssist, Prefetch, process_memory, com_hijack,
  wmi_subscriptions
- Live data-driven progress bars (collection within-module by files/bytes;
  analysis within-parser), TUI (solid bars) and CLI (ASCII bars)
- Block-letter SAFE banner on welcome screen

**What's broken or ugly:**
- AV false positive on Defender (documented; not a real issue)
- Two duplicate commits in history (cosmetic only)
- Minor cosmetic follow-ups from M1: non-deterministic `stats:` map order
  in the analyze view, and unwrapped analyze-header paths on very narrow
  windows (both tracked in docs/journal/2026-06-12-ascii-fallback.md)

---

## Phase 2 status — Extended Collection (collection DONE)

See docs/PLAN.md for the phase breakdown and docs/ROADMAP.md for session-level
tracking.

**Phase 2 collection modules — all built and VM-verified:**
1. `extended_event_channels` — full winevt/Logs (bulk pattern) — **DONE**
   (2026-06-12d), in `endpoint_deep`.
2. `extended_persistence` — BAM/DAM, service registry, LSA, and other ASEPs —
   **DONE** (2026-06-12d), in `endpoint_deep`.
3. `process_memory_inspection` — collect-only per-process memory — **DONE**
   (designed 2026-06-12e, implemented + VM-verified 2026-06-12f). On-target it
   dumps raw exec/RWX-private region bytes + two index CSVs, zero interpretation.
   In `memory_triage` (v0.1.0, dedicated LOUD profile) AND `endpoint_deep`
   (v0.3.0); never in rapid_triage. First module to use native Windows syscalls
   (build-tagged `_windows.go`/`_other.go`).

**Lab-side work — status (2026-06-12g):**
- `process_memory` analyzer — **DONE** (commit 32601b6). Strings / PE-carve /
  RWX triage over the PMI dumps. The other half of the collect-only PMI design.
- COM-hijack hive-parser (`com_hijack`) — **DONE** (commit 38bf58b). Parses each
  user's UsrClass.dat (NOT NTUSER.DAT — that has no CLSID surface), HKLM SOFTWARE
  as a shadow oracle. Regression fixture: `test-fixtures/com_hijack_planted/`
  (see docs/test-fixtures.md).
- WMI-subscription surfacing (`wmi_subscriptions`) — **DONE** (commit 2e1970e,
  session 2026-06-13). Does NOT parse the binary WMI repository — persistence_core
  already captures the three `Get-CimInstance` Format-List listings
  (consumers/filters/bindings), so the parser reads that text, correlates
  filter↔consumer via bindings, and tiers for T1546.003 (HIGH = live binding
  driving a code-exec consumer; NOTABLE = staged/non-baseline/abused trigger;
  LOW = NTEventLogEventConsumer baseline). Outputs
  `lab_report/wmi_subscriptions/{wmi_subscriptions.csv,summary.txt}`.

## Immediate Next Steps

**Pick next:**
- **Begin Phase 3 (Browser + Per-User)** — the next *collection* phase
  (per_user_iteration infra, browser_artifacts, jump_lists). See ROADMAP 3.x.
  Phase 2 has no remaining debt.
- Optional: a belt-and-suspenders VM `--analyze` glance at the new
  `wmi_subscriptions` output (locally verified; no platform-specific code).
- Optional: address the LOW-tier audit nits captured in
  docs/journal/2026-06-13-audit-fixes-and-wmi-parser.md (none are correctness
  bugs).

Note: MODULES_REFERENCE.md was brought fully current 2026-06-12f — title fixed
(SAFE), all 12 collection modules documented, profile-membership matrix and
execution-order folder structure corrected.

The TUI-scroll work is fully done — the form and all summary screens
(`confirm`, `complete`, `analyze-complete`) scroll instead of clipping.

**Build:** use `make vm` → `test-output/vm/safe.exe` (the only folder the VM
can access). NEVER build the exe to the repo root. For native-syscall modules,
also run `GOOS=windows go vet ./internal/...` — the macOS host vet skips
`_windows.go` files.

**HARD RULE:** never upload/submit safe.exe or its source to any third-party
internet service (VirusTotal, AV vendors, pastebins, etc.). Only destination
is the project's own GitHub. See the opsec section in CLAUDE.md.

---

## Rename: SAHM → SAFE — DONE (Session M3, 2026-06-12c)

The rename is executed. The Go module is `safe`, the entry point is
`cmd/safe/main.go`, the binary is `safe.exe`, VSS shadow symlinks use the
`C:\safe_shadow_*` prefix, the welcome banner spells SAFE, and the JSON
case-metadata version tag is `safe_version`. The acronym now expands to
**System for Artifacts Forensic and Examination**.

Texture and decisions are in docs/journal/2026-06-12c-safe-rename.md.

**External rename follow-up — DONE (2026-06-12c):**
- GitHub repo renamed `SAHM` → `SAFE` in repo settings.
- Local remote updated to `git@github.com:Salahalza/SAFE.git` and
  connectivity verified (`git ls-remote` returns the correct head).

**Deliberately left as-is (historical record):**
- Journal entries before M3 and CHANGELOG entries dated before the rename
  still say SAHM. They describe past state and stay unchanged.

---

## Open Design Questions

These are in docs/DESIGN_QUESTIONS.md and may need resolution before
relevant work starts:

1. **EVTX library evaluation** — resolve before Phase 4 EVTX parser work
2. **IOC extraction PDF library** — resolve before Phase 6
3. **Sigma rule compatibility** — research during Phase 7
4. **HTML viewer technology choice** — resolve at Phase 8 start
5. **Output path ownership** — older question, defer until Phase 11
6. **Interactive Report Viewer (Interpretation C)** — deferred

---

## Tools and Skills

**Languages:** Go (beginner; prior Python/PowerShell)

**Dev environment:**
- macOS for development
- Windows 11 VM in VMware Fusion for testing
- Plain Windows PowerShell, not Windows Terminal

**Version control:**
- Private GitHub repo
- Single branch (`main`)
- No pull requests (single developer)
- No rebase (decision made; see CLAUDE.md)

**Build:**
- `make build` (or `go build ./...`) for local compile check
- `make vm` for the Windows VM binary → `test-output/vm/safe.exe` (the only
  folder the VM can access). NEVER build the exe to the repo root. `make check`
  runs build + vet + vm together.

**Test:**
- VM is the integration test environment
- No unit tests yet (known gap)

---

## Communication With Salah

Read CLAUDE.md for full working style notes. Key points:
- No flattery, no encouragement-speak
- Intellectual honesty over execution speed
- Push back when scope is unclear
- Full file rewrites preferred when ambiguous
- VM tests required before commit on functional changes
- One commit per logical change
- Always update CHANGELOG.md
- Never rebase

Salah is technically sophisticated but a Go beginner. Explain Go-specific
patterns when used. Don't dumb down architectural reasoning.
