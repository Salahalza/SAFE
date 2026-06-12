# SESSION HANDOFF

Last updated: 2026-06-12
Last assistant: Claude Code (VSCode)

This document captures the current state of the project, what's in flight,
and what to do next. Read this at the start of every Claude Code session
to load context.

---

## Where We Are

Phase 1 is complete and **Phase 2 has begun** (session 2026-06-12d). The
migration sessions are all done: M1 (ASCII fallback + analyze-flow testing),
M2 (README restructure), and M3 (SAHM → SAFE rename). The project is named
**SAFE** end to end — Go module `safe`, `cmd/safe/`, `C:\safe_shadow_*`,
regenerated TUI banner, all docs.

First Phase 2 module shipped: `extended_event_channels` (bulk-copies the
full `winevt\Logs` set via VSS), hosted in a new interim `endpoint_deep`
profile. VM-verified. The new-case TUI form was also made scrollable and its
profile selector turned into a wrapping vertical list.

**What works:**
- Collection via `safe --tui` or CLI flags
- Two profiles: `rapid_triage` (9 modules) and `endpoint_deep` (interim
  v0.1.0 — rapid_triage superset + extended_event_channels)
- Analysis via `safe --analyze <case-folder>` or TUI Option 2
- Report viewing via TUI Option 3 (structured, scrollable, viewport-based)
- All terminal-size-sensitive screens scroll instead of clipping: the
  new-case form (mouse wheel / PgUp / PgDn / focus-follow) and the confirm,
  complete, and analyze-complete summary screens (shared scroll viewport);
  profile options render as a width-aware vertical list
- VSS shadow management with orphan cleanup
- IR# / CSI# case metadata fields
- Bulk vs primary artifact distinction
- 10 collection modules: process, network, system metadata, event logs,
  registry, persistence, amcache, user hives, prefetch, extended event
  channels
- 2 analyzer parsers: UserAssist, Prefetch
- Block-letter SAFE banner on welcome screen

**What's broken or ugly:**
- AV false positive on Defender (documented; not a real issue)
- Two duplicate commits in history (cosmetic only)
- Minor cosmetic follow-ups from M1: non-deterministic `stats:` map order
  in the analyze view, and unwrapped analyze-header paths on very narrow
  windows (both tracked in docs/journal/2026-06-12-ascii-fallback.md)

---

## Immediate Next Steps

Phase 2 is underway. See docs/PLAN.md for the full phase breakdown and
docs/ROADMAP.md for session-level estimates.

**Phase 2 modules:**
1. `extended_event_channels` — full winevt/Logs (bulk pattern) — **DONE**
   (2026-06-12d), in `endpoint_deep`.
2. `extended_persistence` — BAM/DAM, service registry, LSA, and other ASEPs —
   **DONE** (2026-06-12d), in `endpoint_deep` (now v0.2.0). COM hijacks
   deferred to a future lab hive-parser.
3. `process_memory_inspection` — targeted process memory regions — NOT
   started. The contentious one (loud, EDR-visible, brushes the
   quiet-visitor principle); roadmap 2.1 is a design session for it.

**Pick next:** design `process_memory_inspection` (have the quiet-visitor
debate — needs explicit go-ahead before opening), or build the deferred COM
lab hive-parser (parses the already-collected SOFTWARE/NTUSER hives).

The TUI-scroll work is fully done — the form and all summary screens
(`confirm`, `complete`, `analyze-complete`) now scroll instead of clipping.

Phase 2 effort estimate: 6-10 sessions.

**Build:** use `make vm` → `test-output/vm/safe.exe` (the only folder the VM
can access). NEVER build the exe to the repo root.

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
