# SAHM Changelog

**SAHM — System for Artifact Harvesting and Management**

## 2026-04-24 — Foundation laid

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