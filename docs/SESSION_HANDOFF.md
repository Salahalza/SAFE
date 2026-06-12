# SESSION HANDOFF

Last updated: 2026-06-12
Last assistant: Claude Code (VSCode)

This document captures the current state of the project, what's in flight,
and what to do next. Read this at the start of every Claude Code session
to load context.

---

## Where We Are

Phase 1 is complete. The migration sessions are all done: M1 (ASCII
fallback + analyze-flow testing), M2 (README restructure), and M3
(SAHM → SAFE rename). The project is now named **SAFE** end to end —
Go module `safe`, `cmd/safe/`, `C:\safe_shadow_*`, regenerated TUI
banner, all docs. The next work is Phase 2 module development.

**What works:**
- Collection via `safe --tui` or CLI flags
- Analysis via `safe --analyze <case-folder>` or TUI Option 2
- Report viewing via TUI Option 3 (structured, scrollable, viewport-based)
- VSS shadow management with orphan cleanup
- IR# / CSI# case metadata fields
- Bulk vs primary artifact distinction
- 9 collection modules: process, network, system metadata, event logs,
  registry, persistence, amcache, user hives, prefetch
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

Phase 1 and all migration loose ends are closed. **Phase 2 begins next.**

### Phase 2 — Extended collection
See docs/PLAN.md for the full phase breakdown and docs/ROADMAP.md for
session-level estimates.

**Phase 2 modules to build:**
1. `process_memory_inspection` — targeted process memory regions
2. `extended_event_channels` — full winevt/Logs (bulk artifact pattern)
3. `extended_persistence` — BAM, COM hijacks, more service registries

Phase 2 effort estimate: 6-10 sessions.

---

## Rename: SAHM → SAFE — DONE (Session M3, 2026-06-12c)

The rename is executed. The Go module is `safe`, the entry point is
`cmd/safe/main.go`, the binary is `safe.exe`, VSS shadow symlinks use the
`C:\safe_shadow_*` prefix, the welcome banner spells SAFE, and the JSON
case-metadata version tag is `safe_version`. The acronym now expands to
**System for Artifacts Forensic and Examination**.

Texture and decisions are in docs/journal/2026-06-12c-safe-rename.md.

**Still outstanding (manual, external — not blocking):**
- Rename the GitHub repo in repo settings.
- Update the local remote URL afterward:
  `git remote set-url origin <new-url>`.

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
- `go build ./...` for local
- Cross-compile to Windows: `GOOS=windows GOARCH=amd64 go build -o safe.exe ./cmd/safe`

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
