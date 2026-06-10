# SAHM Changelog

**SAHM — System for Artifact Harvesting and Management**

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