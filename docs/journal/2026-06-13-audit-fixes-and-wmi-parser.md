# Session Journal: 2026-06-13

## Goal

Run a correctness audit of the codebase (collection modules, extended modules +
PMI, the UserAssist/Prefetch analyzers, and the engine/manifest/report/casemeta
layer) against real VM output, fix what we agreed on, then build the deferred
WMI-subscription lab parser.

## What got done

- **Read-only audit** across five areas (fanned out to parallel sub-agents),
  cross-checked against real VM cases under `test-output/vm/test-output/`. The
  collected evidence itself reconciled cleanly (the SHA-256 walker hashes every
  byte; manifest math exact). Findings concentrated in engine robustness,
  `--verify` completeness, and report provenance. Headline findings were
  independently re-verified before acting.
- **Audit fixes — 6 logical commits, pushed (a8bd1cd):**
  - `engine` (4178da0) — recover from a module panic (was crashing the process,
    leaking the VSS shadow, losing the case); surface a failed module-manifest
    write (degrade success→partial) instead of swallowing it.
  - `manifest/report` (d204595) — `--verify` is now a full reconciliation: it
    also verifies `lab_report/manifest.sha256` and walks the case dir to flag
    added/planted files (`Extra`), not just an allowlist check. Report gains a
    COLLECTION PROVENANCE section (shadow ID, collected hostname, total bytes,
    profile version) and a collection-time-only note; `case.json` rewritten
    post-run with `profile_version`/`shadow_id`/`ended_at`. Rune-aware truncate.
  - `process_memory_inspection` (efe85b9) — partial `ReadProcessMemory`
    (ERROR_PARTIAL_COPY) now salvages the readable prefix instead of dropping the
    region; zero-byte reads no longer write empty blobs.
  - `user_hives_collection` (ae54f3e) — populate `Username` for readable
    findings; pin the per-user output dir to the SID (the analyzers read that dir
    name back AS the SID).
  - `module/helpers` (a364067) — reconcile a failed command's output with the
    manifest (register non-empty as artifact + warning, drop empty).
  - `analyzer` (a8bd1cd) — neutralize CSV formula injection (`csvSafe`) on
    attacker-influenceable userassist/prefetch columns.
- **WMI-subscription parser** (2e1970e) — new `wmi_subscriptions` analyzer, the
  last deferred Phase 2 lab item. Parses the three `Get-CimInstance` Format-List
  files from persistence_core, correlates filter↔consumer via bindings, tiers for
  T1546.003 (HIGH = live binding driving a code-exec consumer; NOTABLE = staged /
  non-baseline / abused trigger; LOW = NTEventLogEventConsumer baseline). Outputs
  `wmi_subscriptions.csv` + `summary.txt`. Verified against the real VM baseline
  (1 LOW SCM subscription) and a synthetic planted CommandLineEventConsumer
  (HIGH, all flags) + orphan ActiveScriptEventConsumer (NOTABLE).
- Mac-side verification throughout: `go build`/`go vet`/`GOOS=windows go vet`
  clean; `--verify` exercised on a real case copy (clean OK incl. lab_report;
  planted-file + tamper both detected); `--analyze` re-run clean. The
  collection-side report rendering (R1–R4) and case.json fields were VM-confirmed
  by Salah on a fresh endpoint_deep run before the audit commits were pushed.

## What got decided

- **`--verify` is a reconciliation, not an allowlist** — for a chain-of-custody
  tool, files ADDED to evidence must be caught, not just modified/removed ones.
  The only files left legitimately uncovered are the manifests themselves.
- **Per-user hive dir name is a contract = the SID** — the audit found both
  UserAssist and com_hijack read each `user_hives_collection` subdirectory name
  back as the SID for attribution. So we populate `Username` for human text but
  explicitly pin the directory to the SID (the original "name by username" intent
  would have silently broken the analyzers).
- **PMI partial reads are salvaged, not dropped** — the readable prefix of an
  RWX/injected region is usually the evidence that matters; ERROR_PARTIAL_COPY no
  longer discards the whole region.
- **Failed-command output is kept as evidence** — a command's captured error
  text ("Access is denied") is forensically useful, so it is registered as an
  artifact with a warning rather than left as an un-manifested orphan; empty
  captures are removed.
- **Report stays collection-time; analyzer findings are separate** — rather than
  trying to fold IOC results into the collection report, we added an explicit
  note that `--analyze` is required for triage (the report is written before any
  analyzer runs).
- **WMI parser tiers off consumer class + binding** — a CommandLine/ActiveScript
  consumer is the IOC; a binding that drives one is HIGH, a staged (unbound) one
  is NOTABLE, and the log-only NTEventLogEventConsumer baseline is LOW. HKLM-style
  deep heuristics weren't needed — the consumer class is the strong signal.

## What got punted

- **Charter-notice files left uncommitted** — CLAUDE.md, com_hijack.go,
  process_memory.go, process_memory_inspection.go carried pre-existing
  defensive-charter header comments that Salah is handling separately. The one
  entangled file (`process_memory_inspection_windows.go`) shipped its charter
  header with the PMI fix commit; Salah's charter commit should exclude it.
- **LOW-tier audit nits not actioned** — registry_core `Warnings` vs `Findings`
  init, eventlogs optional-channel error masking, persistence_core on-target
  run-key classification (borderline rule-1, raw output preserved), verify
  two-space split brittleness. Tracked here; none are correctness bugs.
- **DFIR coverage gaps (roadmap, not bugs)** — $MFT/USN, SRUM, Shimcache
  surfacing, browser history (Phase 3), raw scheduled-task XML. Consistent with
  the documented phase plan.
- **A persisted WMI regression fixture** — the synthetic positive was validated
  inline (easy to regenerate from text); not saved as a fixture like
  com_hijack's. Recipe is in this journal / the commit message.

## What surprised us

- **The per-user dir name being an analyzer contract** — the "populate Username
  for the dir name" finding looked like a clean fix until checking the analyzers,
  which parse that dir name as the SID. Naming it by username would have silently
  broken UserAssist/com_hijack attribution. Caught before implementing.
- **`--verify` was an allowlist, and its own doc comment over-promised** — it
  claimed "any modification will be detected" while never walking the tree for
  added files and never touching `lab_report/` at all.
- **A module panic would leak the shadow** — the watchdog protects against hangs
  but the goroutine had no `recover()`; a panic unwinds a *different* goroutine
  than the one holding the deferred `Cleanup()`, so the shadow leaks and the case
  is lost. Now recovered.
- **`git add cmd/safe/main.go` prints a gitignore warning but still works** — the
  repo ignores `safe`/`safe.exe`, which the path `cmd/safe` matches; the warning
  is spurious for the already-tracked `main.go` and the file commits correctly
  (confirmed via `git show --stat`).

## What's next

Phase 2 (collection + lab) is now fully complete — 12 collection modules, 5
analyzer parsers. The next collection phase is **Phase 3 (Browser + Per-User)**:
per_user_iteration infra, browser_artifacts, jump_lists (ROADMAP 3.x).

## Notes for the next session

- Don't re-litigate: `--verify` reconciliation (Extra-file detection is
  intentional), the SID-pinned per-user dir (analyzer contract), PMI partial-read
  salvage, or the WMI tiering (consumer class is the signal). All VM-grounded or
  locally verified.
- The 6 audit commits + the WMI commit are pushed. The charter-notice files
  remain in the working tree for Salah to commit separately (see "What got
  punted").
- WMI parser source columns and the `csvSafe` guard are shared analyzer helpers;
  any new analyzer should reuse `csvSafe` for free-text CSV columns.
- To regenerate the WMI HIGH test: append a `CommandLineEventConsumer` block
  (CimClass `ROOT/subscription:CommandLineEventConsumer`, a `CommandLineTemplate`)
  to `*_persistence_core/wmi_event_consumers.txt`, a matching `__EventFilter`, and
  a binding `Consumer : CommandLineEventConsumer (Name = "...")`, then
  `--analyze`.
