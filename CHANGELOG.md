# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-09-28

### Added
- **Initial Public Release of SAFE (System for Artifacts Forensic and Examination).**
- `safe-collect`: A standalone, statically compiled Windows executable for acquiring forensic artifacts (MFT, Registry, EVTX, AmCache, Prefetch, WMI, Browser Data) using raw disk access and Volume Shadow Copies (VSS).
- `safe-analyze`: A standalone cross-platform analyzer for parsing collected artifacts into CSVs and timelines without wrapping external dependencies.
- Embedded HTML Report dashboard with server-side pagination to handle million-row timelines smoothly.
- Behavioral detection engine (Tier 2/Tier 3) using external YAML rules and STIX 2.1 intelligence packs.
- AV-safe payload collection using ZipCrypto (`web_payloads.zip`) to safely acquire web shells and malicious binaries without triggering host EDR quarantines during acquisition.
- Support for offline and dead-disk image analysis.

### Changed
- Refactored entire codebase to `github.com/Salahalza/SAFE` module path for public release.
- Removed internal testing tools and private lab automation scripts from the public tree.
- Migrated all documentation to an open-source standard (added `CONTRIBUTING.md`, `SECURITY.md`).
