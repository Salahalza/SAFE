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