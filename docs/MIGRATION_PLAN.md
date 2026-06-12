# Migration Plan: First Three Claude Code Sessions

This document outlines the first three focused sessions in Claude Code.
Each is scoped tightly with clear acceptance criteria. The goal is to
build momentum and confidence in the Claude Code workflow while making
real progress.

---

## Session M1: ASCII character fallback + analyze flow testing

**Goal:** Polish the TUI so it renders correctly on plain Windows
PowerShell, and verify the analyze flow works end-to-end.

**Why this first:** Smallest scope, immediate visible improvement,
exercises the Claude Code workflow without risking complex design
decisions.

**Duration estimate:** 60-90 minutes.

### Steps

1. **Read context** — Open CLAUDE.md and docs/SESSION_HANDOFF.md. Ask
   Claude Code to summarize what it understands. Confirm correct context.

2. **Plan the change** — Ask Claude Code to read `internal/tui/styles.go`
   and `internal/tui/report_render.go`, then propose the specific character
   replacements. Confirm before any editing.

3. **Make the changes** — Update:
   - `internal/tui/styles.go`: card styles use `lipgloss.NormalBorder()`
     instead of `RoundedBorder()`
   - `internal/tui/report_render.go`: severity icons → ASCII
   - Module status icons → ASCII alternatives

4. **Build** — `go build ./...` clean. Then cross-compile.

5. **Test on VM** — All three TUI flows. Confirm:
   - Collection still works
   - Analyze flow works (this is the secondary acceptance criterion)
   - Report viewer renders cleanly with no `?` characters

6. **Commit** — One commit for character fallback, one commit for
   CHANGELOG. Push.

7. **Write journal entry** — docs/journal/YYYY-MM-DD-ascii-fallback.md

8. **Confirm** — `git log --oneline -5` shows all commits landed.

### Acceptance criteria

- Report viewer on plain Windows PowerShell shows clean borders and icons
- Analyze flow works end-to-end via TUI
- All commits pushed to origin
- Journal entry written and committed

### Expected pushback from Claude Code (if any)

May suggest skipping the fallback in favor of "users should use Windows
Terminal." Push back: this is field-deployed tooling, plain PowerShell
is the lowest common denominator.

---

## Session M2: README update + repo polish

**Goal:** Make the GitHub repo look professional. Surface what SAFE/SAHM
actually does for both technical and management audiences.

**Why second:** Documentation is a natural focused session. Doesn't risk
breaking the build. Sets up for the rename in session M3.

**Duration estimate:** 60-90 minutes.

### Steps

1. **Read context** — CLAUDE.md, SESSION_HANDOFF.md, existing README.md,
   PROFILES.md, PLAN.md.

2. **Plan structure** — Ask Claude Code to propose a new README outline.
   Include:
   - Project header with one-line description
   - Status badges (Go version, license, status)
   - One-paragraph "what is this"
   - Architecture overview (2-3 paragraphs)
   - Profile catalog (4 profiles with status)
   - Phase status table
   - Installation instructions
   - Quick start (CLI and TUI)
   - Limitations link
   - License

   Confirm outline before writing.

3. **Write README** — One pass, full rewrite. Salah prefers full file
   replacements over partial edits.

4. **Verify rendering** — Push to GitHub, check the rendered output.
   GitHub renders markdown differently than local previews.

5. **Iterate if needed** — Visual fixes based on actual GitHub rendering.

6. **Commit** — Single commit. Push.

7. **Write journal entry** — docs/journal/YYYY-MM-DD-readme-update.md

### Acceptance criteria

- README has clean GitHub presentation
- Profiles section lists all four with current status
- Phase status table is accurate
- Installation and quick start are actually executable
- No marketing fluff, no "great for security teams" language
- Honest about what SAFE is NOT (per CLAUDE.md)

### Expected pushback from Claude Code (if any)

- May want to add CI badges that don't exist. Push back — don't reference
  CI that isn't set up.
- May suggest adding contributing guide. Push back — single-developer tool.

---

## Session M3: SAHM → SAFE rename — DONE (2026-06-12c)

**Goal:** Execute the deliberate project rename. Atomic, clean, verified.

**Outcome:** Done. See docs/journal/2026-06-12c-safe-rename.md and the
CHANGELOG entry. The steps below are kept as the executed record.

**Why third:** Biggest mechanical change. Best done with the project in
a polished, well-documented state (after sessions M1 and M2). Atomic
commit makes it easy to revert if anything's wrong.

**Duration estimate:** 2-3 hours including thorough testing.

### Steps

1. **Read context** — CLAUDE.md (especially the rename plan in
   SESSION_HANDOFF.md), and confirm clean git state.

2. **Plan the rename** — Ask Claude Code to enumerate every file that
   needs changing. Compare against the list in SESSION_HANDOFF.md. Add
   any missed files.

3. **Update go.mod** — `module sahm` → `module safe`. Then update all
   imports across the codebase via search-and-replace.

4. **Update binary name** — Anywhere the build produces `sahm.exe`,
   change to `safe.exe`. This includes:
   - Build commands
   - Docs that reference the binary
   - The `--verify` command output in case_report.txt

5. **Update VSS shadow prefix** — `C:\sahm_shadow_*` → `C:\safe_shadow_*`
   in the VSS code. Test on VM to confirm orphan cleanup still works.

6. **Regenerate the block-letter banner** — Currently spells "SAHM" in 5
   rows of block characters. Generate equivalent for "SAFE" — same
   character set, same proportions.

7. **Update all docs** — README, PLAN, PROFILES, LIMITATIONS,
   MODULES_REFERENCE, DESIGN_QUESTIONS, CLAUDE, SESSION_HANDOFF,
   MIGRATION_PLAN, ROADMAP.

8. **Build** — `go build ./...` clean.

9. **Cross-compile** — `GOOS=windows GOARCH=amd64 go build -o safe.exe
   ./cmd/safe`.

10. **Test on VM** — All three TUI flows. CLI flags. Verify. Analyze.
    Confirm the banner spells SAFE. Confirm output strings reference SAFE.

11. **Commit** — One atomic commit. Push. Verify.

12. **Rename GitHub repo** — Manual step in repo settings (cannot be
    done from Claude Code).

13. **Update local remote URL** — After GitHub rename:
    `git remote set-url origin <new-url>`.

14. **Write journal entry** — docs/journal/YYYY-MM-DD-rename-to-safe.md

### Acceptance criteria

- `go build ./...` clean
- Cross-compile produces `safe.exe`
- TUI shows SAFE banner, not SAHM
- All output strings reference SAFE
- Documentation consistently uses SAFE
- CHANGELOG entry describes the rename
- GitHub repo renamed
- Local remote points to new URL
- Journal entry committed

### Expected pushback from Claude Code (if any)

May want to leave SAHM references in some files "for historical context."
Push back — be thorough. CHANGELOG history stays as it is (those describe
past commits), but current docs use SAFE.

---

## After Session M3: Phase 2 Begins

Once renamed, the project is ready for Phase 2 module development. See
docs/ROADMAP.md for the session-level breakdown of Phase 2 onward.

---

## General Claude Code Session Pattern

For every session:

1. **Open by reading context** — CLAUDE.md, SESSION_HANDOFF.md, most
   recent journal entry, plus any docs relevant to the task.

2. **Confirm understanding** — Have Claude Code summarize the goal and
   plan. Correct any drift before writing code.

3. **Work in small steps** — One file or one logical change at a time.
   Build after each.

4. **Test on VM** — Before any commit, for any functional change.

5. **Commit atomically** — One logical change per commit. Always update
   CHANGELOG.

6. **Push and verify** — `git log --oneline -5` shows the commit landed.

7. **Write journal entry** — Before closing the session.

8. **Update SESSION_HANDOFF.md** — Mark completed items, add new ones
   that emerged.

9. **Close clean** — Final `git status` should be clean. No stranded
   uncommitted work.

This pattern protects against working-late-and-leaving-mess problems.
