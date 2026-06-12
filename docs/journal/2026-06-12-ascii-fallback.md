# Session Journal: 2026-06-12

Session M1 of the Claude Code migration: ASCII character fallback for the
TUI and end-to-end verification of the analyze flow.

---

## Goal

Make the TUI render correctly on plain Windows PowerShell (legacy conhost)
by replacing Unicode glyphs with ASCII, and verify the analyze flow works
end-to-end on the VM.

## What got done

- ASCII sweep across the entire `internal/tui/` package — 8 files (commit afb42e6):
  - Card borders `RoundedBorder()` -> `NormalBorder()`
  - Severity/status icons -> bracketed scheme (`[+] [!] [x] [-] [?]`, `[i] [*]`)
  - Collection progress spinner: braille frames -> rotating ASCII `| / - \`
  - Nav/hint glyphs: arrows -> `Up/Down/Left/Right`, bullet separators -> `|`,
    selection marker -> `>`, radio `(•)` -> `(*)`
  - Em-dashes in rendered strings -> hyphens (comments untouched)
- Report viewer width fix: size content to `Width - HorizontalFrameSize` so
  the header card's right border isn't truncated (commit afb42e6).
- Analyze view width fix: wrap long parser paths/findings/stats to the
  available width with a hanging indent instead of overflowing (commit afb42e6).
- CHANGELOG entry for Session M1 (commit 586df0e).
- New CLAUDE.md rule: no Co-Authored-By / AI references in commit messages
  (commit 473c971).
- Verified all TUI flows on the Windows 11 VM; analyze flow confirmed
  working end-to-end (UserAssist + Prefetch parsers, lab_report written).
- Build output path moved to `test-output/vm/sahm.exe` (shared folder; the
  VM reads it as `V:\sahm.exe`, no manual copy).

## What got decided

- Scope expanded from the two planned files (`styles.go`, `report_render.go`)
  to the full `internal/tui/` package (Option B) — the codepage constraint
  hits every screen, so fixing only the report viewer would leave the
  welcome/progress/form screens broken. The collection progress spinner in
  particular is the first thing a user sees.
- Bracketed icon scheme over bare single chars — readable and self-aligning
  (all 3 cols wide) for forensic output.
- ASCII spinner `| / - \` over braille — cycles the same way.
- Block-letter SAHM banner left as-is — block characters render fine on
  plain PowerShell.
- Em-dashes changed only in rendered strings, not in code comments (comments
  never reach the terminal).
- No AI attribution anywhere in commits — now a standing CLAUDE.md rule.
- Build artifact now written to `test-output/vm/` (shared folder) rather than
  the repo root.

## What got punted

- `stats:` map iteration order in the analyze view is non-deterministic (Go
  map iteration) — display-only cosmetic, left as-is. Could `sort.Strings`
  the parts for stable output. Tracked here only.
- Analyze-screen header paths (Case / Lab report) are not yet width-wrapped;
  they fit in testing but could overflow on a very narrow window. Tracked here.
- README rewrite — Session M2 (docs/MIGRATION_PLAN.md).
- SAHM -> SAFE rename — Session M3 (docs/MIGRATION_PLAN.md).

## What surprised us

- **The report card's right border stayed clipped after the first width fix.**
  Static reasoning kept concluding "it should fit," which was the tell that
  the layer accounting was wrong. Reading the bubbles viewport v1.0.0 source
  settled it: `View()` renders content into `Width - Style.GetHorizontalFrameSize()`
  and TRUNCATES anything wider via `MaxWidth`. My first fix double-counted —
  set the viewport `Width = termWidth-4` AND kept a 4-col padding frame, so the
  true inner width was `termWidth-8` while `renderReport` was told `termWidth-4`;
  the card (`termWidth-6` total) lost its right 2 columns. The correct fix:
  keep viewport `Width` = full terminal width and derive the report's inner
  width from `GetHorizontalFrameSize()`. Lesson: don't reason about nested
  lipgloss/viewport widths from first principles — read the library's `View()`
  to find where it truncates.
- lipgloss `.Width()` semantics: the set width absorbs padding but border adds
  on top (final = `.Width()` + border). Confirmed by reading style.go.
- Plain PowerShell actually renders em-dashes fine — the analyzer's finding
  message (data-origin, from result.json) showed its `—` correctly. So the
  em-dash-in-source changes were defensive, not strictly required. Harmless.
- A `\n` inside a `.Render()` call in the analyze view was a latent bug
  (lipgloss treated each as a 2-line styled block); fixed while adding wrapping.

## What's next

Session M2 — README rewrite for GitHub presentation (profile catalog, phase
status table, honest "what this is NOT"). See docs/MIGRATION_PLAN.md.

## Notes for the next session

- The scope of any "ASCII / rendering" work is the WHOLE `internal/tui/`
  package, not just one screen — every screen shares the plain-PowerShell
  codepage constraint.
- When debugging nested width/clipping in bubbles + lipgloss, READ the
  viewport `View()` source. It truncates at `Width - HorizontalFrameSize`.
  Don't theorize about the geometry from the outside.
- Build output goes to `test-output/vm/sahm.exe` (gitignored); the VM reads
  it as `V:\sahm.exe`. No manual copy step.
- No AI attribution anywhere in the project — no Co-Authored-By trailers, no
  "generated by" lines, no AI product names in commits/docs/comments. This is
  a CLAUDE.md rule now; don't reintroduce the harness default trailer.
- Don't re-add em-dashes to rendered TUI strings; ASCII hyphens are the
  convention. Em-dashes in code comments are fine (never rendered).
- `stats:` ordering and analyze-header path wrapping are known small follow-ups
  noted under "What got punted" if you want easy wins.
