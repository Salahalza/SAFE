# Acquira Changelog

## 2026-04-24
- First end-to-end run on Windows 11 VM verified.
- system_metadata module: 5 artifacts collected, status=success.
- Module contract, execution engine, output layout all working as designed.


## 2026-04-25
- Added profile system with rapid_triage as first profile.
- Three working modules: system_metadata, process_snapshot, network_snapshot.
- Graceful fallback for netstat without admin.
- Admin detection in environment.json.
- Verified end-to-end on Windows 11 VM, all modules success.


## 2026-04-26
- Completed rapid_triage profile: 6 modules, ~48 artifacts.
- Added eventlogs_core, registry_core, persistence_core.
- Engine now displays warnings count.
- Verified end-to-end on Windows 11 VM, all modules success.


## 2026-05-26
- Added CLI flags for case metadata (case ID, analyst, target, target class, notes).
- Added case.json output containing full case metadata.
- Added preflight checks: OS support, admin privileges, disk space.
- Added --skip-preflight override for advanced use.
- Added --list-profiles for discovering available profiles.
- Exit codes now reflect outcome (0/1/3 for success/failed/degraded).


## 2026-05-26 (later)
- Added per-module manifest (module.json in each module folder).
- Added case-level manifest (manifest.json + manifest.sha256 at case root).
- Added `--verify <case-folder>` for offline integrity verification.
- Verified end-to-end on Windows VM: 56 files hashed and verified successfully.


## 2026-05-26

Major session. Foundation work for v1.0.

- Added CLI flags for case metadata: --case, --analyst, --target, --target-class, --notes.
- Added case.json output in every case folder with full metadata.
- Added preflight checks: OS support, admin privileges, disk space.
- Added --skip-preflight override for advanced use.
- Added --list-profiles to enumerate available profiles.
- Added per-module manifest (module.json in each module folder).
- Added case-level manifest (manifest.json + manifest.sha256 at case root).
- Added --verify <case-folder> for offline integrity verification.
- Added watchdog enforcement: per-module and per-profile timeouts via context.
- Added new module status: timed_out, distinct from failed.
- Added TUI with Bubble Tea: welcome → form → confirm flow.
- TUI form captures case metadata, validates input, mirrors CLI path.
- Fixed disk preflight to work when output directory doesn't exist yet.
- Exit codes now reflect outcome: 0/1/3 for success/failed/degraded.
- Verified end-to-end on Windows 11 VM: 48 artifacts, manifest, verification all passing.