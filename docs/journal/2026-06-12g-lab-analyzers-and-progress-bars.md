# Session Journal: 2026-06-12g

## Goal

Build the two deferred Phase 2 lab-side analyzers (`process_memory`, then
`com_hijack`) to close the Phase 2 lab debt; then, on Salah's request, add real
data-driven progress bars to SAFE across collection and analysis.

## What got done

- **`process_memory` analyzer** (commit 32601b6) — parses the collect-only PMI
  dumps (`regions.csv` + raw blobs) into `lab_report/process_memory/`:
  `regions_triage.csv` (per-region HIGH/NOTABLE/LOW triage), `carved_pe/`
  (PE images carved from MZ/PE-bearing regions), `strings/` (ASCII+UTF-16LE,
  256 KiB/region cap), `summary.txt`. Verified locally against the real VM
  `memory_triage` case + synthetic PE/IOC/truncation positives.
- **`com_hijack` analyzer** (commit 38bf58b) — detects COM-hijack persistence
  (T1546.015) from collected `UsrClass.dat` hives, using HKLM SOFTWARE as a
  shadow oracle. HIGH = a per-user CLSID overriding an HKLM one with a different
  path; NOTABLE = user-writable path / scriptlet / LOLBin / TreatAs. VM-verified
  with a planted true positive ({00021401} ShellLink → C:\Temp\evil.dll = HIGH).
- **Test fixture + docs** — preserved the planted-hijack case locally as
  `test-fixtures/com_hijack_planted/` (gitignored) and documented it +
  the planting recipe + expected output in `docs/test-fixtures.md`. The fixture
  is a self-contained regression: `go run ./cmd/safe --analyze` reproduces the
  HIGH row.
- **Real progress bars** (commit c09c7fc) — collection + analysis, TUI + CLI.
  Solid background-color bars in the TUI (PowerShell-safe, no Unicode); ASCII
  bars in the CLI. Collection advances *within* each module by files/bytes
  actually copied (new throttled `EventModuleProgress` + `module.Context.Progress`
  reporter) with a live "Collected N MB" readout; analysis advances *within*
  each parser (`Parser` gained an optional `ProgressFunc`; com_hijack reports
  milestones across its multi-second HKLM index). The TUI analyze screen now
  streams parser progress instead of showing a bare spinner.
- All three commits pushed to origin/main.

## What got decided

- **process_memory triage tiers** — RWX-private or PE-bearing → HIGH;
  exec region with IOC hits but no PE → NOTABLE; else LOW. IOC API matching uses
  shortest-distinctive stems ("VirtualAlloc" catches VirtualAllocEx) to avoid
  double-counting.
- **process_memory reports `skipped` (not `failed`) when the PMI module is
  absent** — diverges from prefetch/userassist (which error on absence) because
  PMI is opt-in and absent from most cases; "skipped" is the documented status
  for "source module not in case."
- **com_hijack parses `UsrClass.dat`, not NTUSER.DAT** — per-user
  HKCU\Software\Classes lives in UsrClass.dat. NTUSER.DAT has no CLSID surface.
- **com_hijack scope = per-user hijack surface; HKLM is a shadow ORACLE only**
  (membership set + on-demand path resolution), NOT deep-scanned. This was the
  fix for a 3m40s runtime on the 2-core VM (see surprises); it also drops HKLM
  self-anomaly rows, judged acceptable since the threat model is per-user and
  those rows were all benign system noise on a clean host.
- **com_hijack FP tuning** — unqualified-name, LOLBin, and `.ax`/non-DLL flags
  are USER-hive-only or script-extension-denylist, because HKLM system COM is
  full of bare KnownDLL names, rundll32 LocalServers, and `.ax` DirectShow
  filters that are all legitimate.
- **Progress bars: ASCII/background-color, never Unicode block glyphs** — plain
  PowerShell renders block/braille as `?`. TUI bars use ANSI bg color on spaces.
- **Collection progress can never be a true %-of-total-data** (total unknown
  until done). Chose within-module file/byte progress so the bar reflects real
  work and varies per host, anchored to module count for the coarse position.
- **Analysis progress = within-parser, each parser an equal 1/N slice** smooth
  within (mirrors the collection model) rather than byte-weighting across
  heterogeneous parsers.

## What got punted

- **process_memory analyzer not run by safe.exe on Windows** — verified locally
  (Mac) against real VM dumps + synthetic; the shared analyzer/regparser/filepath
  path was separately proven on Windows by com_hijack. Residual Windows risk is
  near-zero. Could do a belt-and-suspenders VM `--analyze` on a PMI case.
- **WMI-subscription surfacing** — the third deferred Phase 2 lab item, not
  started. Tracked in SESSION_HANDOFF.md / ROADMAP (carries to Phase 4).
- **Analysis bar VM glance** — the analyze within-parser bar (com_hijack
  milestones moving during its ~13s) is built + locally verified but not yet
  eyeballed on the VM. Display-only; fix-forward if needed.

## What surprised us

- **com_hijack was 3m40s on the VM** (2-core/8GB) on first cut — the deep walk
  of ~12k HKLM CLSID servers. Profiling showed a one-level CLSID name
  enumeration is ~45 ms but a single targeted `OpenKey` is ~31 ms (re-traverses
  the 6800-entry index), so per-user `OpenKey` would be *worse*. Fix: enumerate
  the GUID set once, resolve HKLM paths on-demand only for confirmed shadows.
- **The first VM hijack test showed HIGH 0 — but it was a flush race, not a
  parser bug.** Live `reg add` to HKCU\Software\Classes isn't flushed to the
  on-disk UsrClass.dat before the VSS snapshot. Fixed the *test* by planting into
  an offline user's hive via `reg load`/`reg unload` (writes to disk immediately).
- **Real OneDrive registers COM servers under AppData** — a naive "AppData =
  suspicious" rule floods NOTABLE. The honest signal is shadows-HKLM, not path.
- **regparser `OpenKey` is case-insensitive** (confirmed), so GUID matching is
  robust regardless of `reg add` casing.

## What's next

Phase 3 (Browser + Per-User collection) is the next collection phase — see
ROADMAP 3.x. Optionally first: a quick VM `--analyze` glance at the analysis
progress bar, and/or the deferred WMI-subscription lab parser.

## Notes for the next session

- Don't re-litigate: com_hijack's shadow-oracle scope (HKLM not deep-scanned),
  the USER-only FP heuristics, or the ASCII/bg-color bar choice (Unicode breaks
  plain PowerShell). All deliberate and VM-grounded.
- The com_hijack regression fixture lives at `test-fixtures/com_hijack_planted/`
  (gitignored) — see `docs/test-fixtures.md` to re-run or regenerate.
- Progress is display-only: `module.Context.Progress`/`ReportProgress`,
  `engine.EventModuleProgress`, `analyzer.ProgressFunc`. Adding progress to a
  new module/parser is opt-in (call ReportProgress / the report func); not
  calling it just means that step advances at its boundary.
- For any new analyzer parser, remember the `Parser.Parse` signature now takes a
  trailing `report ProgressFunc`.
