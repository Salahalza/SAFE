# Session Journal: 2026-06-12d

## Goal

Open Phase 2 with a low-risk extended-collection module, and fix the TUI
form display issues that surfaced once a second profile existed.

## What got done

- New collection module `extended_event_channels` (commit 13f079e):
  bulk-copies every `.evtx` from `C:\Windows\System32\winevt\Logs` via the
  shared VSS shadow. Direct file copy, not per-channel `wevtutil epl` —
  zero new command execution on the target. Follows the bulk-artifact
  pattern (`BulkFiles=N`, no per-file artifacts; manifest hashes each).
- New `endpoint_deep` profile (v0.1.0, interim) hosting it — a superset of
  rapid_triage plus the new module, 45-min budget. Registered in
  `defaults.go`, so it auto-appears in the TUI selector and as
  `--profile endpoint_deep`.
- TUI form: profile options now render as a width-aware **vertical wrapping
  list** instead of one horizontal line that clipped/hid the second profile
  (commit 3576ae7).
- TUI form: wrapped the whole form in a `bubbles/viewport` so it **scrolls**
  (mouse wheel + PgUp/PgDn) instead of clipping on short terminals, with
  **keyboard focus-follow** so Tab keeps the active field visible. Mouse
  enabled program-wide (`tea.WithMouseCellMotion`); keybinding hint moved to
  a persistent footer (commit 3576ae7).
- VM-verified the collection: `endpoint_deep` run collected 192 channels
  (138 MB) in ~1.9s, status=success, manifest hashed all 192, report shows
  the bulk count as one dataset (Bulk files: 192, Artifacts: 0), `--verify`
  path intact. Salah confirmed the form wrapper renders well.

## What got decided

- **Resequenced Phase 2**: built `extended_event_channels` first instead of
  the roadmap's `process_memory_inspection` (2.1). Reason: PMI is the
  riskiest/most contentious module (loud, EDR-visible, brushes the
  quiet-visitor principle); banking a quiet, pattern-reusing win first is
  lower risk. PMI design still pending.
- **endpoint_deep defined as a rapid_triage superset** (not deep-only).
  Reason: it's conceptually the same endpoint, deeper — and a superset gives
  the new module a real, testable execution path now without a throwaway
  profile. Marked interim v0.1.0; full composition lands later in Phase 2.
- **Collect all channels, including the 8 already in eventlogs_core** — no
  dedup. Reason: different collection methods (live `epl` export vs.
  point-in-time shadow snapshot); completeness over cleverness. Overlap is
  noted in a module finding.
- **Time budgets kept at 20 min (module) / 45 min (profile)** despite the
  ~1.9s VM run. Reason: the VM has near-empty logs (138 MB); a real server
  could be multi-GB. Salah chose maximum headroom over trimming.
- **Build target is `test-output/vm/safe.exe`**, the directory the VM reads
  from — not the repo root. Cross-compile straight there.

## What got punted

- `process_memory_inspection` design (roadmap 2.1) — deferred; still the
  next contentious design debate. Tracked in ROADMAP.md / PLAN.md.
- `extended_persistence` module (roadmap 2.4/2.5) — not started.
- Other tall TUI screens (`confirm`, `complete`, `analyze-complete`) can
  still clip on very short terminals. Same viewport pattern will extend to
  them — tracked here and in CHANGELOG.
- Mouse-wheel behavior specifically in plain Windows PowerShell (conhost)
  not separately confirmed; the keyboard scroll path is the guaranteed fix
  regardless.

## What surprised us

- The `extended_event_channels` run was effectively instant (~1.9s) on the
  VM — the budget question is entirely about real-server log volume, not
  the code. Many channels are identical 68 KB empty `.evtx` files (same
  SHA-256), which is expected on a fresh VM.
- The form-clipping bug only became visible once a *second* profile existed
  — the single-profile form happened to fit. Adding endpoint_deep exposed
  both the horizontal profile-list overflow and the vertical form clipping.

## What's next

Continue Phase 2. Either design `process_memory_inspection` (the deferred
2.1, with the quiet-visitor debate) or build `extended_persistence` as the
next quiet win. Optionally extend the scroll viewport to the remaining tall
TUI screens.

## Notes for the next session

- Don't re-litigate the Phase 2 resequencing or the endpoint_deep
  superset/interim decision — both are deliberate (see "What got decided").
- The 20/45 budgets are a deliberate choice for server headroom, not an
  oversight — leave them unless a real large-log run says otherwise.
- Cross-compile to `test-output/vm/safe.exe`, not the repo root.
- The 8-channel overlap between extended_event_channels and eventlogs_core
  is intentional; don't "fix" it with dedup.
