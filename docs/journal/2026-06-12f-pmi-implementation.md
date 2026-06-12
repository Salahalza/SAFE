# Session Journal: 2026-06-12f

## Goal

Implement the collect-only `process_memory_inspection` module designed in
2026-06-12e: collection module + profile wiring, VM-tested.

## What got done

- New module `process_memory_inspection` (collect-only per-process memory),
  built as a three-file build-tag set:
  - `internal/module/process_memory_inspection.go` — shared struct, interface
    methods, `Run` scaffolding (delegates to a platform function).
  - `internal/module/process_memory_inspection_windows.go` — the syscall
    implementation: Toolhelp process enumeration → `OpenProcess` →
    `VirtualQueryEx` address-space walk → region filter → `ReadProcessMemory`
    → raw blob write. Writes `processes.csv` + `regions.csv` index files.
  - `internal/module/process_memory_inspection_other.go` — non-Windows stub so
    `go build ./...` stays green on the macOS dev host.
- This is the FIRST module in the codebase to use native Windows syscalls
  rather than shelling out. Verified `golang.org/x/sys/windows` v0.45.0 (already
  a direct dep) exports everything needed — `OpenProcess`, `VirtualQueryEx`,
  `ReadProcessMemory`, `MemoryBasicInformation`, Toolhelp, the page-protection
  constants — by reading the package source in the module cache. The MEM_*
  region-Type constants (PRIVATE/IMAGE/MAPPED/FREE) are NOT exported, so they're
  defined locally in the _windows.go file.
- Region filter: committed + private (non-image/non-mapped) + executable-or-RWX
  protection, guard pages excluded. A protection-flag scope filter, no content
  interpretation (principle #1).
- Output layout: `processes.csv` (one row/process, with open_result) and
  `regions.csv` (one row/selected region) are PRIMARY artifacts; raw region
  bytes go to `dumps/<pid>_<name>/<base>_<size>.bin` as bulk files
  (`result.BulkFiles`), hashed individually by the manifest's recursive walk.
  128 MiB per-region cap; truncation recorded in the index.
- New dedicated LOUD profile `memory_triage` (v0.1.0: process_snapshot +
  process_memory_inspection) and PMI added to `endpoint_deep` (→ v0.3.0, budget
  raised 45→75 min, description marked EDR-visible, PMI at position 02 right
  after process_snapshot per order of volatility). Registered in defaults.go.
  Never added to rapid_triage.
- CHANGELOG updated.
- Builds clean: `go build ./...`, `go vet ./...`, `GOOS=windows go vet`
  (vetted the syscall file under its real build tag), `make vm`.
- VM-verified (elevated, Windows 11). `memory_triage`: status=success; 139
  processes (124 opened, 15 denied — lsass/services/csrss/winlogon correctly
  denied), 84 exec/RWX-private regions (21 RWX + 63 RX) dumped from 14 processes
  (browser/JIT/.NET), 0 read errors, 0 truncations, ~8.8 MiB; `safe --verify`
  OK on 95 files including nested dumps/ blobs. `endpoint_deep`: all 12 modules
  success, PMI at position 02.
- Project-wide documentation sync (Phase 2 collection marked complete):
  SESSION_HANDOFF.md, CLAUDE.md (profile + phase status), ROADMAP.md (Phase 2
  table marked done, 2.5 deferred to Phase 4), PLAN.md (Phase 2 status block),
  PROFILES.md (endpoint_deep → Built v0.3.0, new memory_triage profile,
  renumbered downstream profiles, refreshed build timeline). Flagged
  MODULES_REFERENCE.md as stale (6 of 12 modules, pre-rename "SAHAM" title) —
  needs its own dedicated pass, not done here.

## What got decided

- **Two refinements vs. the 2026-06-12e design, both to fit the existing
  `finalize()` status semantics:**
  1. The EDR-visibility note and per-process denials are emitted as `info`, not
     `warning`. The design said "one warning finding," but `finalize()` degrades
     any warning to `partial` — which would make every clean run falsely report
     partial. Info keeps a clean run `success`, exactly like
     `extended_persistence` treats absent keys. Opening ZERO processes still
     degrades to `partial` (genuine degradation).
  2. `processes.csv` and `regions.csv` are registered as primary artifacts (the
     design implied bulk-only like extended_event_channels). They are a real
     analyst index, so reporting them as primary while the `.bin` dumps stay
     bulk reads truer.
- **Per-region cap = 128 MiB** (impl decision left open by the design). Exec/RWX
  private regions are normally KB–MB; 128 MiB is generous headroom while
  bounding a pathological region. No region hit the cap on the VM.
- **Skip pid 0 (System Idle) and self**; everything else is attempted and its
  open_result recorded (denials are honest data, not silently dropped).

## What got punted

- **Lab-side `process_memory` analyzer** — strings, PE-carve, RWX triage over
  the collected blobs. This is the other half of the collect-only design and is
  its own session. Tracked in ROADMAP 2.2 / the 2026-06-12e design journal.
- **TUI run-time EDR warning on profile select** — the design mentioned
  surfacing a warning on the (scrollable) confirm screen when a PMI-bearing
  profile is chosen. Deferred: the profile Description already carries the
  EDR-visible note (shown in the selector). Cleanly separable TUI work.
- **Operator PID-allowlist "targeted mode"** and **WOW64/32-bit specifics** —
  deferred to a later pass; attempt-all is the default and worked on the VM.

## What surprised us

- Most opened processes have NO exec/RWX-private regions (winlogon: 667 regions,
  0 selected; fontdrvhost: 167, 0). Only 14 of 124 opened processes contributed
  dumps — browsers (msedge/webview2 JIT), explorer, powershell, SystemSettings.
  That is correct: image-backed code is excluded by design (recoverable from
  disk), so the filter naturally surfaces the IR-relevant minority — including
  21 RWX private regions, the classic injection signature.
- `go vet ./...` on the macOS host does NOT vet the `_windows.go` file (wrong
  build tag), so a syscall-file bug would slip past the standard pre-commit
  check. Ran `GOOS=windows go vet ./internal/...` explicitly to cover it. Worth
  remembering for any future syscall module.

## What's next

Build the lab-side `process_memory` analyzer (ROADMAP 2.2): a Parser that globs
`modules/*_process_memory_inspection`, reads `regions.csv` + the `dumps/` blobs,
and produces strings / PE-carve / RWX-triage findings in lab_report/. All the
on-target judgement the module deliberately does NOT do lives here.

## Notes for the next session

- Don't re-litigate the two refinements (info-not-warning status; CSVs as
  primary artifacts) — both are deliberate and VM-verified.
- The module does ZERO interpretation on the target. Keep all analysis in the
  forthcoming lab analyzer; do not push strings/PE-parsing back into the module.
- For any future native-syscall module, remember `GOOS=windows go vet` — the
  host vet skips `_windows.go`.
- PMI stays opt-in (memory_triage + endpoint_deep). Never add it to
  rapid_triage.
