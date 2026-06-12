# SESSION HANDOFF

Last updated: 2026-06-12
Last assistant: Claude Code (VSCode)

This document captures the current state of the project, what's in flight,
and what to do next. Read this at the start of every Claude Code session
to load context.

---

## Where We Are

Phase 1 is complete and Session M1 (ASCII fallback + analyze-flow testing)
is done. The project is in a clean, working state on the `main` branch.
All commits are pushed to origin.

**Latest commits** (newest first):
- `85f1c70` journal: session 2026-06-12 — ASCII fallback and TUI width fixes
- `8c784a2` docs: rename the journal notes section heading for clarity
- `473c971` docs: forbid Co-Authored-By and AI references in commit messages
- `586df0e` changelog: Session M1 ASCII fallback and TUI width fixes
- `afb42e6` tui: ASCII-safe rendering for plain Windows PowerShell

**What works:**
- Collection via `sahm --tui` or CLI flags
- Analysis via `sahm --analyze <case-folder>` or TUI Option 2
- Report viewing via TUI Option 3 (structured, scrollable, viewport-based)
- VSS shadow management with orphan cleanup
- IR# / CSI# case metadata fields
- Bulk vs primary artifact distinction
- 9 collection modules: process, network, system metadata, event logs,
  registry, persistence, amcache, user hives, prefetch
- 2 analyzer parsers: UserAssist, Prefetch
- Block-letter SAHM banner on welcome screen

**What's broken or ugly:**
- AV false positive on Defender (documented; not a real issue)
- Two duplicate commits in history (cosmetic only)
- Minor cosmetic follow-ups from M1: non-deterministic `stats:` map order
  in the analyze view, and unwrapped analyze-header paths on very narrow
  windows (both tracked in docs/journal/2026-06-12-ascii-fallback.md)

**Resolved in M1:**
- Plain Windows PowerShell unicode rendering — full `internal/tui/` package
  now ASCII-safe; report-viewer and analyze-view width clipping fixed;
  analyze flow verified end-to-end on the VM

---

## Immediate Next Steps

The migration-focused sessions close Phase 1 loose ends before Phase 2.
See docs/MIGRATION_PLAN.md for detail.

### Session M1: ASCII character fallback + analyze flow testing — DONE (2026-06-12)
Full `internal/tui/` package made ASCII-safe for plain Windows PowerShell,
report-viewer/analyze-view width clipping fixed, analyze flow verified
end-to-end on the VM. Commits `afb42e6`..`85f1c70`. See
docs/journal/2026-06-12-ascii-fallback.md.

### Session M2: README update — CURRENT SESSION
**Priority:** MEDIUM
**Effort:** 60-90 min

Restructure README for GitHub presentation. Add profiles catalog and phase
status.

### Session M3: SAHM → SAFE rename
**Priority:** HIGH (deliberate)
**Effort:** 2-3 hours

Mechanical rename across the codebase. Atomic commit. See "Rename Plan"
below.

After M3, the project is renamed and polished. Phase 2 begins.

---

## Phase 2 Roadmap

See docs/PLAN.md for full phase breakdown and docs/ROADMAP.md for
session-level estimates.

**Phase 2 modules to build:**
1. `process_memory_inspection` — targeted process memory regions
2. `extended_event_channels` — full winevt/Logs (bulk artifact pattern)
3. `extended_persistence` — BAM, COM hijacks, more service registries

Phase 2 effort estimate: 6-10 sessions.

---

## Rename Plan: SAHM → SAFE

Mechanical change. ~2-3 hours including thorough VM testing.

### Pre-rename verification
```bash
git status                              # must be clean
go build ./...                          # must pass
GOOS=windows GOARCH=amd64 go build -o sahm.exe ./cmd/sahm
                                        # must pass
```

### Changes required

**Code identifiers:**
- `go.mod` — `module sahm` → `module safe`
- All Go imports: `sahm/internal/...` → `safe/internal/...`
- Binary build commands: `sahm.exe` → `safe.exe`
- Version variable: `sahmVersion` → `safeVersion`

**Configuration:**
- VSS shadow symlinks: `C:\sahm_shadow_*` → `C:\safe_shadow_*`
- Search for any "sahm" string references in code

**Documentation:**
- `README.md` — rewrite header, references
- `docs/PLAN.md` — references
- `docs/PROFILES.md` — references
- `docs/LIMITATIONS.md` — references
- `docs/MODULES_REFERENCE.md` — references
- `docs/DESIGN_QUESTIONS.md` — references
- `CLAUDE.md` — update project identity section
- `docs/SESSION_HANDOFF.md` — update references

**Visual:**
- `internal/tui/styles.go` — block-letter banner currently spells "SAHM",
  regenerate for "SAFE" (same 5-row block style, same colors)
- All title strings: "SAHM — System..." → "SAFE — System..."
- All status output: "SAHM v0.1.0" → "SAFE v0.1.0"

**External (manual):**
- GitHub repo name rename in repo settings
- Local remote URL update: `git remote set-url origin <new-url>`
- CHANGELOG historical entries stay as-is (they describe past state)

### Verification after rename
```bash
go build ./...
GOOS=windows GOARCH=amd64 go build -o safe.exe ./cmd/safe
# Test all three TUI flows on VM
# Test CLI: safe --tui, safe --analyze, safe --verify
# Confirm output strings reference SAFE not SAHM
```

### Commit strategy
One atomic commit. Easy to revert if anything's wrong.

```bash
git add -A
git commit -m "rename: SAHM → SAFE (System for Artifacts Forensic and Examination)"
git push
```

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
- Cross-compile to Windows for VM testing

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
