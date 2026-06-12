# SAFE Changelog

**SAFE — System for Artifacts Forensic and Examination**

*Formerly SAHM (System for Artifact Harvesting and Management). Entries
dated before the 2026-06-12 rename describe the project under its old name
and are left unchanged.*

## 2026-04-23 — Foundation laid

- Go project scaffolded with Mac and Windows cross-compilation build pipelines, version-controlled in git.
- Module contract defined: a standard interface every collection module implements (priority, time budget, execute).
- Supporting types in place: `Priority` (critical/high/normal/optional), `Status` (success/partial/failed/skipped), `Artifact`, `Result`.
- Execution engine: runs modules in sequence, enforces critical-module abort policy, writes structured output per case (numbered module folders, `result.json` at case root).
- First module operational: `system_metadata` (5 artifacts — hostname, OS name, OS version, architecture, system info).
- Verified end-to-end on Windows 11 VM, status=success.



## 2026-04-25 — `rapid_triage` profile started

- Added profile system; `rapid_triage` registered as the first named profile (versioned, with its own time budget).
- Two modules added: `process_snapshot`, `network_snapshot` — bringing the profile to three working modules.
- Graceful fallback for `netstat` when run without admin privileges.
- Admin detection recorded in `environment.json` for every case.
- Verified end-to-end on Windows 11 VM, all modules success.



## 2026-04-26 — `rapid_triage` profile feature-complete

- Three modules added: `eventlogs_core`, `registry_core`, `persistence_core`.
- Profile now covers six modules and ~48 artifacts per collection.
- Engine reports warnings count in its module output line.
- Verified end-to-end on Windows 11 VM, all modules success.



## 2026-04-27 — Project renamed to SAHM

- Project renamed: Acquira → SAHM (System for Artifact Harvesting and Management).
- Arabic: سهم (arrow).
- Go module, import paths, binary names, command directory, build pipeline, and `.gitignore` updated consistently.
- Documentation updated across `CHANGELOG.md`, `MODULES_REFERENCE.md`, and `DESIGN_QUESTIONS.md`.
- Build and Windows VM run verified post-rename: same 48 artifacts produced under the new branding.



## 2026-05-26 — Major foundation session

Several Phase 1 deliverables landed in one day.

**Case metadata and CLI**
- Added flags: `--case`, `--analyst`, `--target`, `--target-class`, `--notes`.
- `case.json` written in every case folder with full case metadata.
- Added `--list-profiles` to enumerate available profiles.
- Exit codes now reflect outcome: 0 success, 1 failed, 3 degraded.

**Preflight checks**
- Verifies OS support, admin privileges, and disk space.
- Added `--skip-preflight` override for advanced use.
- Fixed disk check to work when the output directory doesn't yet exist.

**Manifest and integrity chain**
- Per-module manifest (`module.json` in each module folder).
- Case-level manifest (`manifest.json` + `manifest.sha256` at case root).
- Added `--verify <case-folder>` for offline integrity verification — any analyst with the SHA256 file and standard tools (e.g., `Get-FileHash`, `sha256sum -c`) can confirm a case folder is unmodified.
- Verified end-to-end on Windows 11 VM: 56 files hashed and verified successfully.

**Reliability**
- Watchdog enforcement: per-module and per-profile timeouts via context propagation.
- New module status `timed_out`, distinct from `failed`.
- Content verification: stdout-captured output scanned for known error signatures.
- Per-command MinSize: empty stubs (e.g., absent registry keys) dropped with explicit warnings.

**Output and reporting**
- Added `case_report.txt`: human-readable case summary with inspection priorities. Report is hashed into the manifest for tamper detection.
- `persistence_core` run-key queries now distinguish empty keys from missing keys; each run-key artifact is self-describing with state, header, and timestamp. Forensic statement preserved even when no values are present.

**TUI (initial)**
- Added Bubble Tea TUI: welcome → form → confirm flow.
- Form captures case metadata, validates input, mirrors CLI inputs. Engine integration deferred to the next session.



## 2026-05-27 — TUI wired to engine; severity model; broader content validation

**TUI–engine integration**
- TUI now runs collection after the confirm step (previously exited at "next step: integration").
- Added profile selection radio in the TUI form.
- TUI profiles populated dynamically from the profile registry.
- Verified TUI path produces output identical to CLI path on Windows 11 VM (48 artifacts, manifest, report).

**Severity model**
- Findings now classified as `info`, `warning`, or `critical`.
- Normal observations (Sysmon absent, empty run keys) reclassified as info-only.
- Module status no longer downgraded by info-level findings — clean runs show SUCCESS.
- `case_report.txt` shows separated severity counts and ℹ/⚠/✗ markers per finding.
- Inspection priority section only lists modules with warning or critical findings.
- Engine output line now shows the info/warning/critical breakdown instead of a flat warnings count.

**Positive content checks (MustContain)**
- Added across every module: commands are now validated bidirectionally — expected content must be present, error signatures must be absent.
- Coverage spans `systeminfo`, `whoami`, `ipconfig`, `tasklist`, PowerShell process and network queries, `netstat`, `route`, `arp`, `schtasks`, `sc query`, and registry queries.
- DNS cache check skipped (cache may legitimately be empty on a clean target).
- No false positives observed on the Windows 11 reference VM.

**Dry-run and tools preflight**
- Added `--dry-run` for non-destructive environment validation. Validates case metadata, profile selection, preflight, external tools, and output writability.
- Fixed: `--dry-run` no longer creates the output directory (genuinely non-destructive).
- Added `ToolsCheck` preflight: verifies all 13 required Windows tools are on PATH.



## 2026-05-27 (continued)

- pathfinder: discovered registry.GetStringValue silently corrupts non-ASCII
  characters in REG_EXPAND_SZ values via ANSI codepage fallback.
- Replaced with manual UTF-16 LE decoding via registry.GetValue raw bytes.
- Verified on Cyrillic test user: bytes are now valid UTF-8, os.Stat succeeds,
  profile correctly discovered with Cyrillic path.
- Real-case impact: SAHM now correctly enumerates user profiles with
  non-Latin names (Russian, Czech, Arabic, CJK, etc).



  ## 2026-05-27 (continued)

- TUI: added in-place progress display during collection.
- Per-module status updates flow from engine via progress channel.
- Spinner animation on running modules, status markers (✓ ⚠ ✗ ⏱) on completed.
- Elapsed time and total budget shown at bottom of progress screen.
- Added completion screen with final status, duration, artifact count, output path.
- Engine refactored to emit ProgressEvent messages on optional channel — CLI path
  unchanged when channel is nil.
- TUI no longer returns to plain terminal during collection.


## 2026-05-29 (continued)

- Engine refactored: one VSS shadow per case, shared across all VSS-requiring modules.
- amcache_collection module duration dropped from ~1.6s to ~60ms (25x faster).
- Modules declare VSS dependency via new RequiresVSS() method on Module interface.
- Engine creates shadow once before module loop; cleans up via defer at end.
- VSS-requiring modules skipped with clear error if shadow creation fails;
  non-VSS modules continue normally.
- Module Context now includes Shadow *vss.Shadow field (nil when no module needs it).
- Validated with 5 consecutive runs: 5/5 SUCCESS, zero leaked shadows.


## 2026-05-29 (continued)

- Added user_hives_collection module to rapid_triage.
- Collects NTUSER.DAT and UsrClass.dat plus transaction logs (LOG1, LOG2)
  for every human user profile on the system.
- Uses shared VSS shadow for locked-file access (no own shadow creation).
- Per-user output organized by SID (forensically authoritative identifier).
- Verified on Cyrillic user (Алексей): Unicode paths preserved end-to-end.
- Built-in profiles (LocalSystem, LocalService, NetworkService) skipped.
- Module duration ~130ms for 2 users / 12 artifacts.
- rapid_triage now produces 63 artifacts (up from 48) on clean Windows 11 admin run.


## 2026-05-29 (continued)

- Orphan shadow cleanup: automatic at startup + explicit --cleanup-shadows flag.
- SAHM identifies its own shadows via C:\sahm_shadow_* symlinks; non-SAHM
  shadows (System Restore, third-party backups) are never touched.
- Auto-cleanup silent on success, reports count when orphans were cleaned.
- Verified end-to-end: killed SAHM mid-run leaves orphan → next run auto-cleans
  it → SAHM proceeds normally.
- rapid_triage profile bumped to v0.1.2 (now includes amcache_collection and
  user_hives_collection as part of solid first-touch coverage).


  ## 2026-05-29 (continued)

- Added userassist_collection module — first native parser in SAHM.
- Reads NTUSER.DAT from shared VSS shadow, navigates to UserAssist,
  ROT13-decodes value names, parses binary entry structure.
- Produces per-user userassist.csv with category, decoded path, run count,
  focus count, focus time, and last-run UTC timestamp.
- Filters UEME_ internal counters (session metadata, not user-actionable).
- Uses www.velocidex.com/golang/regparser library for hive parsing.
- Module duration on test VM: ~40ms per user.
- 35 entries collected from active user on test system.
- Skipped Cyrillic user's NTUSER.DAT (no UserAssist data — newly-created profile).
- rapid_triage now produces ~64 artifacts (was 63 before this module).
- This is the first module that produces analyst-ready parsed output rather
  than just collecting raw files. Establishes the pattern for future native
  parsers (ShimCache, AmCache, Jump Lists, ShellBags, etc.)


  ## 2026-05-29 (continued)

- Added prefetch_collection module — collects all .pf files from
  C:\Windows\Prefetch via shared VSS shadow.
- Uses VSS for point-in-time view (avoids capturing prefetch entries
  written during SAHM's own execution).
- Handles disabled-Prefetch case (common on SSDs and Server SKUs) as
  warning rather than failure.
- Skips non-.pf entries and subdirectories.
- Module duration on test VM: ~7s for 436 .pf files.
- rapid_triage now produces 513 total artifacts on a clean Windows 11
  admin run, verified end-to-end with --verify.


  ## 2026-05-29 (refactor)

- Major architectural refactor: enforce strict separation between target-side
  collection and analyst-side parsing.
- All parsing now lives in internal/analyzer/, invoked via "sahm --analyze
  <case-folder>" from the analyst's workstation, not on the target.
- Collection profiles now only copy files and execute commands. No CPU-intensive
  parsing runs on the target device.
- New rationale: every command executed on a target adds noise to event logs,
  may alert EDR, and risks interaction with malware watching for forensic
  activity. SAHM should be a quiet visitor.
- rapid_triage reordered to follow order of volatility: process_snapshot,
  network_snapshot, then system_metadata, then static collection.
- Profile version bumped to 0.2.0.
- Removed userassist_collection module (replaced by analyzer/userassist.go).
- Removed shimcache_collection module (deferred — see LIMITATIONS.md).
- New analyzer infrastructure: Parser interface, Registry, lab_report/
  output directory inside the case folder.
- UserAssist is the first parser in the new analyzer pattern. Verified
  end-to-end: collection produces hives, analyzer reads case folder and
  produces per-user CSVs.
- Future parsers (ShimCache, AmCache, Prefetch parsing, etc.) will follow
  the same pattern.


  ## 2026-06-03

- Added prefetch parser to analyzer (sahm --analyze).
- Reads collected .pf files from prefetch_collection module output.
- Uses www.velocidex.com/golang/go-prefetch (MIT-licensed) for parsing.
  Library handles MAM-compressed (LZ-XPRESS Huffman) Windows 10/11 prefetch
  files transparently.
- Output: lab_report/prefetch/prefetch.csv with columns for executable
  name, kernel path, hash, version, file size, run count, files accessed
  count, plus one row per (.pf file, last-run timestamp) pair so the
  timeline is flat and sortable.
- On test VM: parsed 437 .pf files in 245ms, zero errors.



## 2026-06-03

- Added optional IR# and CSI# fields to case metadata for cross-referencing
  to external ticketing systems.
- New CLI flags: --ir (format IR-####-####), --csi (format CSI-######).
- Both fields are optional. When provided, format is validated; bad formats
  fail with a clear error before collection starts.
- IR# and CSI# appear in case.json (omitted when empty), the startup banner,
  and case_report.txt — only when set.
- Case folder name remains CASE-<case_id>_<timestamp>; IR/CSI do not affect
  filesystem structure, only display.
- PrimaryReference() helper on Case picks the most relevant display ID
  (IR > CSI > CaseID) for future use.


  ## 2026-06-03 (continued)

- Introduced bulk vs primary artifact distinction in module results.
- New BulkFiles field on module.Result tracks files collected via directory
  copies (currently only Prefetch). These files are individually hashed in
  the manifest — integrity is unaffected — but they no longer inflate the
  "Artifacts" count in displays and reports.
- Per-module status line now reads:
    status=success ... artifacts=N bulk_files=N ...
  with bulk_files appearing only when nonzero (other modules unchanged).
- case_report.txt TOTALS section now reads:
    Primary artifacts:     N
    Bulk-collected files:  N    (when nonzero)
    Total files in case:   N    (when bulk files present)
- This separation matters as more bulk-collection modules arrive in Phase 2
  (extended event channels, full winevt/Logs directory) which would otherwise
  produce equally inflated counts.
- Verified: 539 files in case folder, all hashed by manifest, --verify passes.



## 2026-06-03 (continued)

- TUI updated to support IR# and CSI# optional fields.
- Form fields now run: Case ID → IR# (optional) → CSI# (optional) → Analyst
  → Target → Target Class → Profile → Notes → Submit.
- Both new fields validate format when populated; empty values pass.
- Confirm screen shows IR# and CSI# lines only when populated.
- Polished TUI text throughout: form title, confirm prompt, progress
  footer ("Time limit" instead of "Total budget"), complete screen prompt,
  welcome subtitle now reads "Windows forensic acquisition for incident
  response field work".


  ## 2026-06-03 (continued)

- Analyzer hardening across 8 small improvements:
  - Status semantics: parsers now report success/partial/failed/skipped.
    Partial = outputs produced AND errors present.
  - ParseStats field on ParserResult surfaces per-parser counts (e.g.,
    pf_files_parsed=478, total_entries=41).
  - analyzer_result.json written to lab_report/ — same role as collection
    result.json, makes the analyzer run a permanent record.
  - manifest.sha256 written for lab_report/ — every parsed CSV is hashed,
    so post-analysis tampering is detectable.
  - Unknown UserAssist category GUIDs surfaced as errors so they're easy
    to spot in batch runs. New GUIDs from Microsoft over time will trigger
    these reports.
  - Prefetch skips CSV creation when there are no rows to write.
  - Named constants for UserAssist binary entry offsets.
  - DESIGN_QUESTIONS.md notes the output-path-ownership architecture
    question for future cross-source parsers.
- Test run found 4 unknown UserAssist GUIDs on Windows 11 24H2 — to be
  documented and added to guidCategoryNames as authoritative references
  emerge.


  ## 2026-06-03 (continued)

- TUI welcome screen restructured into a three-option menu:
  - Start a new case (existing collection flow)
  - Analyze a case folder (runs sahm --analyze via TUI)
  - View a case report (opens case_report.txt in a scrollable viewer)
- Welcome screen now features a multi-row block-letter "SAHM" banner.
- Filepicker integration (github.com/charmbracelet/bubbles/filepicker)
  for selecting case folders in both Analyze and View Report flows.
- Title styling updated to dark-text-on-blue-bar across all screens for
  stronger visual hierarchy.
- Container padding increased for more spacious feel.
- Analyzer launched from TUI runs same parser registry as --analyze CLI flag.
- Report viewer (current implementation) displays case_report.txt verbatim
  in a scrollable text pane. Beautiful structured rendering planned as a
  follow-up session (see DESIGN_QUESTIONS.md).


## 2026-06-10

- TUI report viewer rebuilt with structured layout (replaces plain text scroll).
- New file internal/tui/report_render.go renders from result.json + case.json
  rather than parsing case_report.txt. Sections include:
  - Bordered header card with case metadata in two-column layout
  - Status badge (colored pill: green/amber/red by status)
  - At-a-glance totals line
  - Critical/warning findings shown in dedicated bordered cards above modules
  - Modules table with status icon, name, duration, artifact and bulk counts
  - Observations grouped by module
  - Verification footer with the sahm --verify command
- Uses bubbles/viewport for terminal-size-aware scrolling.
- WindowSizeMsg handler in tui.go resizes the viewport when the terminal
  resizes.
- LIMITATIONS.md: added "Antivirus interaction" section documenting expected
  false-positive detections (Defender ML "Settings Modifier" category) and
  recommended deployment mitigations (exclusions, code signing).
- Known limitation: rounded unicode borders and some severity icons fall back
  to '?' characters on plain Windows PowerShell. Follow-up commit will swap
  to ASCII-safe character set.


## 2026-06-12 — Session M1: ASCII fallback for plain Windows PowerShell

Closes the known limitation from 2026-06-10: the TUI now renders correctly
on plain Windows PowerShell (legacy conhost), where Unicode glyphs showed
as '?'. Verified end-to-end on the Windows 11 VM across all TUI flows.

**ASCII character sweep across internal/tui/**
- Card borders: RoundedBorder() -> NormalBorder() (sharp box-drawing maps to
  the console codepage; rounded corners did not).
- Severity and module-status icons -> bracketed scheme: [+] success,
  [!] partial/critical, [x] failed, [-] skipped/default-severity, [?] unknown,
  [i] info, [*] warning-severity.
- Collection progress spinner: braille frames -> rotating ASCII | / - \.
- Navigation/hint glyphs: arrow keys -> Up/Down/Left/Right, bullet separators
  -> |, selection marker -> >, radio marker (•) -> (*).
- Em-dashes in rendered strings -> hyphens (em-dashes in code comments left
  as-is; they never reach the terminal).
- The block-letter SAHM banner is unchanged (block characters render fine).

**Two width fixes surfaced during VM testing**
- Report viewer: the header card's right border was truncated. Root cause was
  the bubbles viewport rendering content into (Width - HorizontalFrameSize)
  and clipping anything wider via MaxWidth. initReportViewport now sizes the
  report to that true inner width (derived from GetHorizontalFrameSize) so the
  border fits.
- Analyze view: long parser paths, findings, and stats overflowed the right
  edge. They now wrap to the available width with a hanging indent, so no
  forensic text (paths, finding messages) is lost.


## 2026-06-12 — Session M3: renamed SAHM → SAFE

Mechanical, project-wide rename in a single atomic commit. No behavior
change; the tool does exactly what it did, under a new name.

- Acronym now expands to **System for Artifacts Forensic and Examination**.
- Go module `sahm` → `safe`; all `sahm/internal/...` imports → `safe/internal/...`.
- Entry point `cmd/sahm/main.go` → `cmd/safe/main.go`; binary is now `safe.exe`.
- Identifiers renamed: `sahmVersion` → `safeVersion`, `SAHMVersion` →
  `SAFEVersion`, `sahmBanner` → `safeBanner`, `ListSAHMShadows` →
  `ListSAFEShadows`.
- VSS shadow symlink prefix `C:\sahm_shadow_*` → `C:\safe_shadow_*`
  (orphan-cleanup glob updated to match).
- Case-metadata JSON tag `sahm_version` → `safe_version`. Note: the report
  viewer reads the new tag, so the version field is blank for case folders
  collected under the old SAHM binary.
- Welcome-screen block-letter banner regenerated SAHM → SAFE.
- Write-test sentinel `.sahm-write-test` → `.safe-write-test`; `.gitignore`
  build-artifact rules updated to `safe` / `safe.exe`.
- Docs updated (README, CLAUDE.md, PLAN, PROFILES, LIMITATIONS,
  DESIGN_QUESTIONS, SESSION_HANDOFF). Pre-rename journal entries and the
  CHANGELOG entries above this line keep the SAHM name as historical record.
- Verified end-to-end on the Windows 11 VM: all three TUI flows, plus
  `safe --tui`, `safe --analyze`, and `safe --verify`.


## 2026-06-12 — Phase 2 begins: extended_event_channels + endpoint_deep

First Phase 2 collection module.

- New module `extended_event_channels`: bulk-copies the complete set of
  .evtx channel files from C:\Windows\System32\winevt\Logs via the shared
  VSS shadow. Where `eventlogs_core` exports 8 curated channels with
  `wevtutil epl`, this captures every channel present on the target —
  application- and role-specific logs (Exchange, IIS, MSSQL, AppLocker,
  WMI-Activity, etc.).
- Collection method is a direct shadow file copy, NOT per-channel
  `wevtutil epl`: zero new command execution on the target (quiet-visitor
  principle), and follows the bulk-artifact pattern (BulkFiles=N, no
  per-file artifacts; the manifest still hashes every file).
- The 8 core channels overlap with `eventlogs_core` by design — different
  collection methods (live export vs. point-in-time shadow). Noted in a
  module finding so the analyst understands the duplication.
- New `endpoint_deep` profile (v0.1.0, interim): superset of rapid_triage
  plus extended_event_channels; 45-minute budget. Registered in defaults,
  so it appears in the TUI selector and as `--profile endpoint_deep`. Full
  composition (process_memory_inspection, extended_persistence) lands in a
  later Phase 2 session.
- Verified end-to-end on the Windows 11 VM: 192 channels collected
  (138 MB) in ~1.9s, status=success, manifest hashed all 192, the bulk
  count is reported as one dataset (not 192 inflated artifacts), and
  `--verify` passes.


## 2026-06-12 — New-case form: vertical profile list + scrollable

Two display fixes to the new-case form, both surfaced once a second
profile (endpoint_deep) existed.

- Profile options now render as a wrapping vertical list (one per line),
  scaled to the terminal width, instead of a single horizontal line that
  clipped off the right edge or hid the second profile on a narrow
  terminal.
- The whole form now renders inside a bubbles/viewport so it scrolls
  instead of clipping when the terminal is shorter than the form. Scrolls
  via mouse wheel and PgUp/PgDn, and auto-follows keyboard focus — tabbing
  to a field below the fold scrolls it into view, so Submit is always
  reachable by keyboard even on a small terminal.
- Mouse support enabled program-wide (tea.WithMouseCellMotion); the report
  viewer now also scrolls with the mouse wheel.
- The keybinding hint moved to a persistent footer outside the scroll
  region so it stays visible at all scroll positions.
- Known follow-up: the confirm, complete, and analyze-complete summary
  screens can still clip on very short terminals; the same viewport pattern
  will be extended to them.


## 2026-06-12 — extended_persistence module

Second Phase 2 collection module, added to `endpoint_deep` (now v0.2.0).

- New module `extended_persistence`: 15 readable `reg query` snapshots of
  Auto-Start Extensibility Points (ASEPs) that `persistence_core` does not
  cover — BAM/DAM execution evidence, the full service registry tree
  (ServiceDll/ImagePath/FailureCommand hijack vectors), LSA and
  SecurityProviders, Session Manager (BootExecute/KnownDLLs/AppCertDlls),
  Netsh helpers, Print monitors, Time providers, full Winlogon, Active
  Setup, Shell Extensions Approved, and Browser Helper Objects (+ Wow64).
- Reuses `persistence_core`'s `queryRunKey` helper, so absent keys (e.g.
  legacy BAM, DAM on workstations) are classified as info findings, not
  errors — a clean host does not produce a degraded status.
- No new raw data: registry_core already saves the SYSTEM/SOFTWARE hives
  and user_hives_collection the NTUSER hives, so these are human-readable
  triage snapshots over data already collected (the same deliberate overlap
  as extended_event_channels vs. eventlogs_core). COM hijacks are
  deliberately deferred to a future lab hive-parser (per-user CLSID is not
  reachable via on-target reg query); a finding records this.
- Runs in the static registry/persistence tier (order of volatility), right
  after persistence_core; Priority normal, 5-minute budget.
- Verified end-to-end on the Windows 11 VM: status=success, 15 artifacts,
  0 errors, ~15s; BAM captured real per-SID execution evidence (28
  executables with FILETIME blobs); `safe --verify` passes (635 files).
- AV note: this module's persistence enumeration escalates the Defender ML
  false positive to `Trojan:Win32/Bearfoos.A!ml` (Severe). Documented in
  docs/LIMITATIONS.md; the flagged run still completed and verified.


## 2026-06-12 — Scrollable summary screens

Extends the form-scroll fix to the remaining non-interactive screens, so
nothing clips on a terminal shorter than its content.

- The confirm, collection-complete, and analyze-complete screens now render
  inside a shared scroll viewport. Scroll via mouse wheel, PgUp/PgDn, arrows,
  and Home/End; the proceed-keys (y/n/enter/esc/q) are unchanged and take
  priority.
- Each screen's keybinding hint moved to a persistent footer outside the
  scroll region, so it stays visible at any scroll position.
- Content is set on screen entry (scrolled to top) and re-rendered on resize.
- analyze-complete was the main beneficiary — its parser list grows with the
  number of parsers and previously clipped on short terminals.
- VM-verified on the Windows 11 VM.


## 2026-06-12 — process_memory_inspection module (collect-only)

Third Phase 2 collection module. Native, user-mode, collect-only per-process
memory capture. Design: docs/journal/2026-06-12e-pmi-design.md.

- New module `process_memory_inspection`: enumerates processes (Toolhelp), and
  for each one it can open, walks the address space with `VirtualQueryEx` and
  dumps every committed, private (non-image/non-mapped), executable-or-RWX
  region to disk via `ReadProcessMemory`. Targets injected / unbacked code.
- Collect-only by design (architectural principle #1): the module makes NO
  judgement on the target. The raw region bytes ARE the artifact. All
  interpretation — strings, PE-carve, RWX triage — is deferred to a lab-side
  `process_memory` analyzer (not yet built). Region selection is a
  protection-flag scope filter, not content analysis.
- Output: `processes.csv` and `regions.csv` (primary artifacts — the analyst's
  index) plus raw region blobs under `dumps/<pid>_<name>/<base>_<size>.bin`
  (bulk files, hashed individually by the manifest walker). A single region is
  capped at 128 MiB to bound output; truncation is recorded in the index.
- First module in the codebase to use native Windows syscalls rather than
  shelling out. Implemented as a `_windows.go` / `_other.go` build-tag pair
  (the non-Windows stub keeps `go build ./...` green on the macOS dev host),
  following the existing pathfinder/admin/preflight convention.
- Opt-in only. Added to a new dedicated LOUD profile `memory_triage`
  (process_snapshot + this module, v0.1.0) AND to `endpoint_deep` (now v0.3.0,
  budget raised to 75 min, description marked EDR-visible), running right after
  process_snapshot per order of volatility. NEVER added to rapid_triage.
- Status: per-process `OpenProcess` denials (PPL/protected/system, or EDR) are
  expected and recorded as info, not errors; a clean run stays `success`.
  Opening zero processes degrades to `partial`. Mirrors the absent-key handling
  in `extended_persistence`.
- AV note: this is the loudest module SAFE ships; OpenProcess/ReadProcessMemory
  are exactly what EDR hooks. Expect Defender to escalate and real EDR to
  possibly block or strip handles mid-read. Documented in docs/LIMITATIONS.md.
- Verified end-to-end on the Windows 11 VM (elevated). `memory_triage`:
  status=success; 139 processes (124 opened, 15 denied — lsass/services/csrss/
  winlogon correctly denied as protected; PPL/system expected), 84 exec/RWX-
  private regions dumped (21 RWX + 63 RX) from 14 processes (browser/JIT/.NET),
  0 read errors, 0 truncations, ~8.8 MiB total; `safe --verify` OK on 95 files
  including the nested dumps/ blobs. `endpoint_deep` (now v0.3.0): all 12
  modules success, PMI runs at position 02 right after process_snapshot.


## 2026-06-12 — Lab analyzer: process_memory

- New lab-side analyzer `process_memory` (parser name `process_memory`),
  completing the collect-only PMI feature loop: it performs the interpretation
  the `process_memory_inspection` module deliberately does NOT do on the target.
- Reads the module's `regions.csv` + the raw `dumps/` blobs and produces, under
  `lab_report/process_memory/`:
  - `regions_triage.csv` — one row per dumped region, enriched with a triage
    tier (HIGH/NOTABLE/LOW), PE-header detection (machine, DLL flag), ASCII +
    UTF-16LE string counts, and IOC-hit counts. The analyst's at-a-glance index.
  - `carved_pe/` — PE images carved from regions containing a valid MZ/PE header
    (manually-mapped / reflectively-loaded code). Carves what is present in the
    region; partial when the region is smaller than SizeOfImage.
  - `strings/` — extracted ASCII + UTF-16LE strings, one file per dumped region,
    each capped at 256 KiB (truncation noted; CSV counts stay uncapped).
  - `summary.txt` — human-readable triage with every HIGH region called out.
- Triage: RWX-private memory or a PE-bearing region → HIGH (classic injection /
  manual map); an executable region with IOC hits but no PE → NOTABLE; otherwise
  LOW (commonly benign browser/.NET JIT, which the module's filter surfaces).
- IOC matching uses shortest-distinctive-stem API names (e.g. "VirtualAlloc"
  catches VirtualAllocEx) plus URL / IPv4 / UNC matchers — broad coverage with
  no double-counting.
- Reports `skipped` (not `failed`) when the PMI module is absent from a case, so
  rapid_triage cases don't surface a spurious failure.
- Verified locally against the real VM-collected `memory_triage` case (84
  regions: 21 RWX→HIGH, 63 LOW; strings/PE/IOC true-negative on the clean host)
  and against synthetic positives (planted PE → carved + machine/DLL identified;
  planted URL/IP/UNC/API → counted; 256 KiB cap → truncates correctly).



## 2026-06-12 — Lab analyzer: com_hijack

- New lab-side analyzer `com_hijack` (parser name `com_hijack`), the COM half of
  the deferred Phase 2 lab work. Detects COM-hijacking persistence (MITRE
  T1546.015) by parsing the collected registry hives offline.
- Parses each user's `UsrClass.dat` (the HKCU\Software\Classes backing hive,
  collected by user_hives_collection — NOT NTUSER.DAT, which does not hold the
  per-user CLSID surface) and inventories every CLSID server registration. Uses
  the HKLM SOFTWARE hive (registry_core) as a shadow oracle.
- Triage: a per-user CLSID that SHADOWS an HKLM CLSID with a DIFFERENT module
  path → HIGH (the override-hijack pattern); a server in a user-writable path, a
  script/scriptlet server module (.sct/.js/.vbs/...), a LOLBin server command,
  or a TreatAs redirection → NOTABLE; ordinary per-user shell extensions → LOW.
- Legitimate per-user apps (OneDrive/Teams/Slack) register COM servers under
  AppData; those are user-only and never shadow HKLM, so they land at NOTABLE,
  never HIGH. The summary states this so an AppData path alone is not misread.
- Performance: HKLM is indexed as a one-level GUID set (membership) and an HKLM
  module path is resolved on demand only for the handful of confirmed shadows.
  This replaced an initial deep walk of all ~12k HKLM CLSID servers that cost
  ~3m40s on the 2-core test VM; the shadow-oracle approach runs in seconds.
- Output under `lab_report/com_hijack/`: `com_servers.csv` (per-user server
  index with tier + flags) and `summary.txt` (HIGH/NOTABLE called out, with the
  OneDrive/AppData caveat).
- Verified end-to-end on the Windows 11 VM with a planted true positive: a
  per-user CLSID {00021401-…} (ShellLink) overriding the real HKLM server
  (windows.storage.dll) with C:\Temp\evil.dll was flagged HIGH; planted .sct and
  mshta servers were flagged NOTABLE; the host's real OneDrive CLSIDs stayed
  NOTABLE. Regression fixture + recipe documented in docs/test-fixtures.md.



## 2026-06-12 — Progress bars (real, data-driven) across collection and analysis

- Added live progress bars to both collection and analysis, in the TUI and CLI.
  The TUI bars are solid filled bars rendered with ANSI background colors on
  spaces — no Unicode block glyphs, so they render correctly on plain Windows
  PowerShell (which shows braille/box-drawing as `?`). CLI keeps an ASCII
  `[####----]` bar for its append-only output.
- The bars reflect REAL work, not just step counts:
  - Collection advances *within* each module as files/bytes are actually
    copied. A new throttled `EventModuleProgress` carries intra-module
    file/byte counts; the overall bar is `(completed modules + running module
    fraction) / total`. Bulk-copy modules (prefetch, extended_event_channels,
    amcache, user_hives) report per file; command modules (registry_core,
    eventlogs_core core batch) report per command via `runDirectOutputCommands`.
    A live "Collected  N MB" readout sums bytes across modules. Because real
    file counts drive it, the pacing now varies per host.
  - Analysis advances *within* each parser. The `Parser` interface gained an
    optional `ProgressFunc` reporter; `RunWithProgress` blends each parser's
    intra-parse progress into an overall fraction (each parser an equal slice,
    smooth within). prefetch/userassist/process_memory report per
    file/hive/region; com_hijack reports milestones across its multi-second
    HKLM CLSID index so the bar keeps moving instead of freezing.
- A new `module.Context.Progress` reporter (`ReportProgress` helper) lets
  modules stream progress without each having to nil-check. `engine.ASCIIBar`
  is the shared CLI bar renderer.
- The TUI analyze screen, previously a bare spinner, now streams the analyzer
  parser-by-parser over a channel (mirroring the collection flow) and shows the
  live bar plus the current parser name.
- No change to collected/parsed output or to any artifact — progress reporting
  is display-only. Collection within-module bar VM-verified; analysis
  within-parser bar built on the same streaming path.



## 2026-06-13 — Correctness audit: integrity, reporting, and module fixes

A read-only audit of the collection modules, extended modules + PMI, the
UserAssist/Prefetch analyzers, and the engine/manifest/report/casemeta layer
against real VM output surfaced a set of correctness and robustness gaps. The
evidence itself reconciled cleanly (the SHA-256 walker hashes every collected
byte); the fixes concentrate on engine robustness, `--verify` completeness, and
report provenance.

**Integrity / robustness**
- Engine now recovers from a module panic: instead of crashing the process —
  which would unwind past the deferred VSS shadow cleanup and leak the shadow,
  losing the whole case — a panicking module is recorded as a `failed` result
  and the run continues.
- A failed per-module manifest write is no longer swallowed: it is surfaced on
  the module result and degrades a clean `success` to `partial`, so a case never
  reports success over artifacts that escaped the case-level manifest.
- `--verify` is now a full reconciliation, not an allowlist check:
  - it also verifies `lab_report/manifest.sha256` (analyzer output previously had
    a manifest written but no verification path);
  - it walks the case folder and flags any regular file on disk that no manifest
    covers (added/planted evidence) as `Extra`, failing verification. A file
    dropped into a module dir or the case root is now caught, not silently
    accepted. VM-verified: planted files in both a module dir and `lab_report/`
    are detected, alongside hash mismatches.

**Reporting / provenance (`case_report.txt`, `case.json`)**
- The report now includes a COLLECTION PROVENANCE section with the Volume Shadow
  Copy ID (audit-trail, architectural principle #3), the collected hostname (read
  from `system_metadata`, distinct from the analyst's free-text target label),
  total bytes collected, and the profile version.
- A NOTE makes explicit that the report is collection-time only and that IOC
  triage requires `safe --analyze` — so a "clean" collection report is no longer
  mistaken for "no detections."
- `case.json` is rewritten after the run to record `profile_version`,
  `shadow_id`, and `ended_at` (previously written once, pre-run, missing these).

**Module-level**
- `process_memory_inspection`: a partial `ReadProcessMemory` (ERROR_PARTIAL_COPY,
  an unreadable page mid-region) now salvages the readable prefix — usually the
  bytes that matter on an injected/RWX region — instead of dropping the whole
  region; the row is flagged `partial read` in `regions.csv`. A zero-byte read no
  longer writes an empty blob.
- `user_hives_collection`: the per-user `Username` is now populated (for
  human-readable findings), and the per-user output directory is explicitly
  pinned to the SID — the lab analyzers read that directory name back AS the SID
  for attribution, so it is a contract, not a display choice.
- A failed command's captured output (e.g. "Access is denied") is reconciled with
  the result: a non-empty capture is registered as an artifact with a warning
  (so the manifest and result agree), an empty one is removed (no zero-byte
  orphan).
- UserAssist/Prefetch CSV output neutralizes spreadsheet formula injection on
  attacker-influenceable text columns (program paths, prefetch names): a value
  beginning with `=`/`+`/`-`/`@` is prefixed with a quote so it cannot execute
  when an analyst opens the CSV in Excel.
- Report text truncation is now rune-aware (no split multibyte characters).
