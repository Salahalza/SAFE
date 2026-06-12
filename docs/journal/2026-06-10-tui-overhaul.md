# Session Journal: 2026-06-10 — TUI overhaul and migration prep

Note: This entry was written retroactively, summarizing the work done in
the web Claude conversation that produced the migration plan and journal
infrastructure.

---

## Goal

Build out the TUI to support running the analyzer and viewing case
reports, with a beautiful structured report viewer. Prepare for migration
to Claude Code in VSCode for future sessions.

## What got done

- Three-option welcome screen (Start case / Analyze / View report)
  (commit 6457ef9, with duplicate 565b23b)
- Block-letter SAHM banner on welcome screen
- Bubbles filepicker integration for case folder selection
- Analyzer launcher with spinner, calling same parsers as CLI
- Structured report viewer with viewport-based scrolling (commit 6867b11)
- Header card with case metadata, status badge, IR/CSI fields
- At-a-glance totals, modules table, observations, verification footer
- AV false-positive note added to LIMITATIONS.md (commit fbd92a9)
- CHANGELOG entries for all of the above (commits db9def3, 70b4afe)
- Bulk vs primary artifact distinction added (Prefetch reports 0
  primary, N bulk; case totals show both)
- Analyzer hardening: status semantics, ParseStats, integrity
  manifest, unknown GUID surfacing
- Migration scaffolding prepared: CLAUDE.md, SESSION_HANDOFF.md,
  MIGRATION_PLAN.md, PLAN.md update, ROADMAP.md, DESIGN_QUESTIONS.md
  additions, journal template, this entry

## What got decided

- Project rename SAHM → SAFE (System for Artifacts Forensic and
  Examination). Not yet executed; planned as session M3 of Claude Code
  migration. Naming history: ATHAR, BASMA, FAHS, SAYF, SWORD considered;
  SAFE chosen for English readability with Arabic phonetic echo (سيف).
- Migrating to Claude Code in VSCode for future sessions. Web Claude
  retained for design discussions if needed.
- Report viewer Interpretation B (structured layout) chosen first;
  Interpretation C (interactive/collapsible) deferred to future session.
- ASCII character fallback chosen over Windows Terminal requirement —
  field tooling must work on plain PowerShell.
- Duplicate TUI commits (6457ef9 + 565b23b) deliberately left in
  history. Rebase declined as risky.
- Parser approach for Phase 4: Go-native using mature Go libraries
  (regparser, go-prefetch, possibly evtx). No external tool wrapping.
- Timeline format for Phase 5: plaso supertimeline CSV. Standardized.
- IOC storage for Phase 6: STIX 2.x JSON bundles.
- Detection engine for Phase 7: three-tier (IOC matching, Sigma rules,
  correlation deferred to Phase 11).
- HTML viewer for Phase 8: local-only first, multi-case platform in
  Phase 11.
- Phase ordering revised. Analyst-value work (parsing, timeline,
  detection) moved before DC and server-role profiles.

## What got punted

- ASCII character fallback for plain PowerShell rendering — Session M1
- README rewrite for GitHub appearance — Session M2
- SAHM → SAFE rename execution — Session M3
- Interactive Report Viewer (Interpretation C) — tracked in
  DESIGN_QUESTIONS.md
- Phase 2 module work — see ROADMAP.md
- VirusTotal verification of binary — explicitly declined by Salah to
  keep binary private
- EVTX library evaluation — must complete before Phase 4 EVTX work
- PDF library choice — must complete before Phase 6
- Sigma compatibility research — Phase 7
- HTML viewer tech choice — Phase 8

## What surprised us

- Defender ML flagged sahm.exe as "Program:Win32/Contebrew.A!ml"
  (Settings Modifier category). False positive caused by legitimate
  forensic behavior. Now documented in LIMITATIONS.md.
- Plain Windows PowerShell renders rounded unicode borders as `?`
  characters. The block-letter banner works (basic Unicode blocks) but
  the rounded corners and severity icons fail. Need ASCII fallback.
- bubbles filepicker uses Enter to select directories (not `.` as I
  initially documented). Fixed mid-session.
- styles.go ended up with duplicate definitions of cardStyle etc.
  during the renderer build. Fixed manually by deleting the older block.
- Two TUI commits ended up duplicated due to a re-add accident. Salah
  declined to rebase; left as cosmetic noise.

## What's next

Session M1 of Claude Code migration: ASCII character fallback for the
TUI report viewer, plus end-to-end test of the analyze flow.

See docs/MIGRATION_PLAN.md for the full first-three-sessions plan.
See docs/ROADMAP.md for Phase 2 onward.

## Notes for the next session

- Do NOT suggest rebasing the duplicate TUI commits (6457ef9, 565b23b).
  Decision made.
- Do NOT upload sahm.exe to VirusTotal. Decision made.
- When in doubt about Salah's working style, read CLAUDE.md. The push-
  back, intellectual honesty, and no-flattery preferences are real
  requirements.
- The Saudi stocks app named SAHM is the reason for the SAFE rename.
  Don't re-litigate this.
- Salah uses plain Windows PowerShell, not Windows Terminal. Test
  rendering there, not in fancy terminals.
- result.json + case.json together have everything needed to render
  the report. Don't parse case_report.txt for the TUI viewer.
- Bulk vs primary artifact distinction: when a module copies many
  files that are conceptually one collection (Prefetch), set
  result.BulkFiles=N and don't append per-file Artifact entries. The
  manifest walker hashes everything regardless.
- Wrapping external tools (KAPE, EZ tools, etc.) is not acceptable —
  it breaks single-binary deployment. Go-native with Go libraries only.
- Salah has Claude Max subscription, so Claude Code sessions can be
  freely run. The constraint is Salah's time, not API budget.
