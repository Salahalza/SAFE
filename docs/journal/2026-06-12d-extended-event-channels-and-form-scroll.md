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
- Second Phase 2 module `extended_persistence` (commit 2f707e3): 15 readable
  `reg query` ASEP snapshots persistence_core doesn't cover (BAM/DAM, full
  service registry, LSA, Session Manager, Netsh/Print/Time providers,
  Winlogon, Active Setup, shell extensions, BHO). Reuses `queryRunKey` so
  absent keys are info not errors. Added to `endpoint_deep` (now v0.2.0).
  VM-verified: success, 15 artifacts, 0 errors, ~15s, BAM has real per-SID
  execution data (28 exes), `--verify` OK (635 files).
- Build-path root-cause fix (commit 25d0602): added a `Makefile` (`make vm`
  -> `test-output/vm/safe.exe`) and pointed CLAUDE.md / SESSION_HANDOFF /
  MIGRATION_PLAN at it. The exe kept landing in the repo root because the
  docs themselves documented `go build -o safe.exe` (root). Now the path is
  baked into the Makefile.
- Hard operational-security rule (commit 45c4732): safe.exe and its source
  must never be uploaded/submitted to any third-party internet service; the
  only permitted internet destination is the project's own GitHub repo.
  Prominent DO-NOT-VIOLATE section in CLAUDE.md. Also removed a conflicting
  "submit to Microsoft/AV vendors" line from LIMITATIONS.md and documented
  the new `Trojan:Win32/Bearfoos.A!ml` Defender false positive.
- Scrollable summary screens (commit 9ffce73): the confirm, complete, and
  analyze-complete screens now share a scroll viewport (wheel/PgUp/PgDn/
  arrows/Home-End), with hints in persistent footers. Closes the TUI-scroll
  follow-up flagged earlier in the session. VM-verified by Salah.

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
  from — not the repo root. Now enforced via `make vm` (path baked into the
  Makefile), not memory.
- **extended_persistence scope: comprehensive ASEPs, readable reg-query
  snapshots.** All its data is already in the raw SYSTEM/SOFTWARE/NTUSER
  hives (registry_core + user_hives), so the module's value is triage-grade
  readable snapshots — the same accepted overlap as event channels. COM
  hijacks deferred to a future lab hive-parser (per-user CLSID isn't
  reachable via on-target reg query).
- **No external publication (Salah directive).** safe.exe and source never
  leave the machine except to the project's own GitHub. This corrected an
  earlier misread on my part (I first proposed denying my own web tools);
  the rule is about not publishing the binary/source, not about tool access.

## What got punted

- `process_memory_inspection` design (roadmap 2.1) — deferred; still the
  next contentious design debate. Tracked in ROADMAP.md / PLAN.md.
- COM hijack surfacing — deferred to a future lab hive-parser (parses the
  already-collected SOFTWARE/NTUSER hives); recorded in an
  extended_persistence finding.
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
- The exe-in-root mistake had a documented root cause: CLAUDE.md and other
  dev docs literally prescribed `go build -o safe.exe` (root). Fixing the
  habit meant fixing the docs + a Makefile, not just "remember harder".
- extended_persistence escalated the Defender ML false positive from
  "Settings Modifier" (Contebrew) to "Trojan / Severe" (Bearfoos) — the
  persistence enumeration reads as recon. Collection still completed and
  verified cleanly; it's louder, not broken.

## What's next

Continue Phase 2. The remaining collection module is
`process_memory_inspection` (roadmap 2.1) — the contentious quiet-visitor
design debate, which needs Salah's explicit go-ahead before opening. The
other open item is the deferred COM lab hive-parser (parses the already-
collected SOFTWARE/NTUSER hives). The TUI-scroll work is now fully done
(form + all summary screens).

## Notes for the next session

- Don't re-litigate the Phase 2 resequencing, the endpoint_deep
  superset/interim decision, or the extended_persistence-vs-raw-hives overlap
  — all deliberate (see "What got decided").
- The 20/45 budgets are a deliberate choice for server headroom, not an
  oversight — leave them unless a real large-log run says otherwise.
- Build with `make vm` (-> `test-output/vm/safe.exe`). NEVER build the exe to
  the repo root — the VM can't reach it.
- HARD RULE: never upload/submit safe.exe or its source anywhere on the
  internet except the project's own GitHub (see CLAUDE.md opsec section).
- The 8-channel overlap (extended_event_channels vs eventlogs_core) and the
  COM-deferral are intentional; don't "fix" them.
