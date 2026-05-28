# SAHM v1.0 Master Plan

This document is the single source of truth for what SAHM v1.0 is, what it
contains, and how we get there. Updated as decisions are made.

If something is in this document, it's a commitment. If something is not in
this document, it is either out of scope or deferred to v1.1+.

Companion documents:
- `PROFILES.md` — profile design and module assignments
- `LIMITATIONS.md` — what SAHM intentionally does not do
- `DESIGN_QUESTIONS.md` — open questions and resolution log
- `MODULES_REFERENCE.md` — per-module command reference for IR team
- `CHANGELOG.md` — development log

---

## v1.0 Scope Commitment

SAHM v1.0 is a self-contained Windows forensic acquisition platform that:

1. **Collects evidence in the field** with four profiles tuned to specific
   case types (rapid_triage, endpoint_deep, domain_controller, server_role).

2. **Matches KAPE SANS Triage artifact coverage** for endpoint and server
   targets. Every artifact category KAPE collects, SAHM collects. Implemented
   in native Go without bundling third-party binaries.

3. **Parses collected artifacts in the lab** via a separate analysis mode
   (`sahm --analyze`). Native parsers for major artifact types. When SAHM's
   parsers cannot handle a specific case, EZ Tools serve as fallback. Over
   time, SAHM parser coverage approaches 100%.

4. **Produces tamper-evident output** with full SHA-256 manifest chains,
   per-module integrity records, and offline verification (`sahm --verify`).

5. **Provides an analyst-friendly workflow** via both CLI flags and an
   interactive TUI with progress display.

---

## Profile Design

See `PROFILES.md` for full detail. Summary:

### rapid_triage (built, evolving)
Fast first-touch on unknown targets. ~60-90 seconds. Solid foundation —
not minimal. Includes the high-value execution-history artifacts (AmCache,
UserAssist, Prefetch, NTUSER/UsrClass hives) so even the rapid profile
provides meaningful forensic value.

### endpoint_deep (designing now)
Comprehensive workstation and single-server collection. Matches KAPE
SANS_Triage coverage. Memory inspection integrated. Several minutes runtime.

### domain_controller (planned)
AD-specific collection for domain compromise investigations.

### server_role (planned)
Per-role detection and collection for IIS, Exchange, MSSQL, SharePoint,
File Server.

---

## Artifact Coverage Commitment

SAHM v1.0 collects, at minimum, the following artifact categories with full
KAPE SANS_Triage parity. Some appear in rapid_triage, others in endpoint_deep,
others in role-specific profiles. The categorization is per `PROFILES.md`.

### Execution history
- ShimCache (Application Compatibility Cache) — registry-derived
- AmCache.hve — file copy + hive content
- UserAssist — registry-derived, per user
- Prefetch (.pf files) — directory copy
- Background Activity Moderator (BAM) — registry-derived
- Session Manager AppCompatFlags — registry-derived

### User activity
- Jump Lists (AutomaticDestinations + CustomDestinations) — per user
- LNK files in Recent folders — per user
- ShellBags — registry-derived from NTUSER and UsrClass
- RecentDocs — registry-derived, per user
- Office MRU files — registry-derived, per user
- TypedURLs — registry-derived, per user
- PowerShell history files (ConsoleHost_history.txt) — per user

### Registry
- SAM, SYSTEM, SOFTWARE, SECURITY, DEFAULT hives + transaction logs
- NTUSER.DAT per user + transaction logs
- UsrClass.dat per user + transaction logs
- Amcache.hve + transaction logs
- All registry transaction logs (.LOG1, .LOG2 files)

### Filesystem
- $MFT (raw NTFS read)
- $J (USN Journal — raw NTFS read)
- $LogFile (NTFS transaction log — raw NTFS read)
- $Boot, $Bitmap, $Secure (NTFS metadata — raw NTFS read)
- BCD (Boot Configuration Data)

### Event logs
- All channels in C:\Windows\System32\winevt\Logs (full directory)
- Not selective filtering — collect everything, let lab analysis filter

### Scheduled tasks
- C:\Windows\System32\Tasks (XML definitions)
- C:\Windows\Tasks (legacy)
- Scheduled task registry keys

### Process and network state
- Running processes with full command-line, parent PID, executable path
- Network connections (TCP/UDP), with owning process
- Network configuration (adapters, routes, ARP, DNS cache, hosts file)
- Process memory inspection (RWX regions, loaded module integrity, suspicious
  strings, handles, tokens)

### Persistence locations
- Run/RunOnce (all variants: HKLM, HKCU, Wow6432Node)
- Winlogon keys
- Image File Execution Options
- AppInit_DLLs, AppCertDLLs
- COM hijacking locations (HKLM and HKCU CLSID InprocServer32)
- LSA packages and notification packages
- Office persistence (Outlook plugins, COM addins, Office Test)
- PowerShell profile scripts
- Active Setup
- Shell extensions
- Netsh helpers
- BITS jobs
- Time providers
- Print processors
- Boot Execute
- WMI event subscriptions (consumers, filters, bindings)

### Browser artifacts
- Chrome / Chromium-based browsers (Edge, Brave, Opera, Vivaldi)
- Firefox
- Internet Explorer / Edge Legacy (WebCacheV01.dat, TypedURLs)
- History, downloads, cookies (path only, not decoded), login data,
  bookmarks, extensions

### Server-role specific (in server_role profile)
- IIS: web server logs, application pool config, bindings, web.config files,
  installed modules
- Exchange: message tracking logs, transport logs, role configuration,
  Exchange event channels, mailbox database paths
- MSSQL: error logs, audit logs, SQL Agent jobs, linked servers, failed
  login attempts, database paths
- SharePoint: ULS logs, IIS logs for SharePoint, configuration database
  connection info
- File Server: SMB share inventory, share permissions, file access events
  (5145), FSRM config

### Domain controller specific (in domain_controller profile)
- NTDS.dit handling via VSS snapshot
- SYSVOL inventory (listing with hashes)
- GPO inventory and recent modifications
- FSMO role identification
- AD replication metadata
- Domain trust information
- Directory Service event channel
- DNS Server event channel (if AD-integrated)
- Kerberos KDC events

---

## Lab Analysis Mode

`sahm --analyze <case-folder>` reads a collected case and produces parsed
analyst-ready output in a `lab_report/` subdirectory inside the case folder.

### Native parsers (committed for v1.0 or shortly after)
SAHM will ship native Go parsers for the following artifact types. Parser
quality target: 95%+ coverage of cases the team handles. Edge cases fall
back to EZ Tools manually until SAHM's parser is improved.

- Prefetch (.pf files) — equivalent to PECmd
- AmCache.hve — equivalent to AmCacheParser
- ShimCache (from SYSTEM hive) — equivalent to AppCompatCacheParser
- UserAssist (from NTUSER.DAT) — registry parser + ROT13 decode
- Jump Lists (.automaticDestinations-ms, .customDestinations-ms) — equivalent to JLECmd
- ShellBags (from NTUSER.DAT and UsrClass.dat) — equivalent to SBECmd
- LNK files — equivalent to LECmd
- $MFT — equivalent to MFTECmd
- $J (USN Journal) — equivalent to MFTECmd
- Event logs (.evtx) — equivalent to EvtxECmd
- Registry hive generic reader — equivalent to RECmd

### Fallback workflow
When SAHM's parser fails or produces uncertain output on a specific artifact,
the analyst runs the equivalent EZ Tool manually. SAHM's `lab_report/` records
which artifacts were parsed natively and which need external review. This
keeps the lab workflow honest.

### Parser improvement loop
When a case forces fallback to EZ Tools, the analyst flags the failing
artifact via a new issue in the SAHM repo. Native parser is improved.
SAHM coverage gradually approaches 100% over time.

### Timing for lab analysis mode
Not pinned to v1.0 release. Designed alongside collection work; revealed to
stakeholders when appropriate (per management demo cadence). Implementation
can run in parallel with later-phase collection profiles.

---

## Build Sequence (Updated)

Sequence is logical dependency order. Timeline
estimates are realistic, not aggressive.

### Phase 1: Solid rapid_triage (May 2026)
Status: built, evolving. Add Tier 1 execution-history artifacts:
- AmCache hive copy
- UserAssist registry extraction
- Prefetch directory copy
- NTUSER.DAT and UsrClass.dat copies (gives ShellBags + RecentDocs as bonus)

Expected outcome: rapid_triage runtime grows from ~30s to ~60-90s but
forensic value increases substantially.

### Phase 2: endpoint_deep foundation (June 2026)
- process_memory_inspection module (RWX region detection first)
- Extended event channels (full winevt/Logs directory copy)
- Extended persistence locations (COM hijacking, AppCertDLLs, etc.)
- Per-user iteration via pathfinder (Jump Lists, LNK files, browser paths)

### Phase 3: endpoint_deep completion (June-July 2026)
- Browser artifacts (Chrome/Edge, Firefox, IE/Edge Legacy)
- ShimCache parsing (binary format parser)
- Process memory deeper inspection (loaded module integrity, suspicious
  strings, handles, tokens)

### Phase 4: Raw NTFS access (July 2026)
- $MFT extraction
- $J USN Journal extraction
- $LogFile, $Boot, $Bitmap, $Secure
- This is the hardest implementation work. Likely multi-session.

### Phase 5: domain_controller (July-August 2026)
- NTDS.dit safe extraction (VSS snapshot approach)
- AD-specific event channels
- SYSVOL inventory
- GPO inventory
- FSMO and trust enumeration

### Phase 6: server_role (August-September 2026)
Build in priority order:
1. IIS (web server logs, configuration, bindings)
2. Exchange (transport logs, message tracking, role config)
3. MSSQL (error logs, audit, SQL Agent jobs)
4. SharePoint (ULS logs, configuration)
5. File Server (share inventory, ACLs, access events)

### Phase 7: Lab analysis mode (parallel work)
Can begin any time after Phase 2. Native parsers added incrementally as
collection capabilities mature. First parsers to build: Prefetch, AmCache,
UserAssist (simplest formats, highest value).

### Phase 8: Release preparation (September 2026 or later)
- Code signing certificate procurement (start in May, lead time matters)
- Gold master process formalization
- Validation suite (minimum viable: regression tests against reference VM)
- Two canary SSD deployment

---

## Timeline Discipline

The above sequence is the order things should
be built, not when they must be done. Slippage to later phases is acceptable
if work quality is maintained.

- Not late-night-coding through scope decisions
- Documenting every deferred item in DESIGN_QUESTIONS.md
- Committing complete working state to git frequently


---

## Out of Scope (Hard Limits)

The following will not be in v1.0 and not in v1.1 either. Documented in
LIMITATIONS.md with rationale:

- Full physical memory acquisition (use WinPmem separately)
- Full disk imaging (use FTK Imager separately)
- Kernel-mode forensics (use Volatility on external memory dumps)
- Network packet capture (use Wireshark separately)
- Cross-platform support (Windows only)
- Cloud forensics
- Mobile forensics
- Network-based collection (offline-first design)

---

## Open Strategic Questions

These need answers as the project progresses, not blocking decisions now:

1. **Parser independence target.** When does SAHM stop relying on EZ Tools
   for fallback? Realistic target: by v2.0, native parser coverage exceeds
   99% across all artifact types.

2. **Distribution model.** Self-contained sahm.exe is current design.
   Eventually may need an installer for the lab analysis mode if it grows
   complex enough.

3. **Internal vs broader release.** SAHM is internal to your IR team now.
   Future decision: do you open source it? Sell it? Keep proprietary?
   Each path has different obligations.

4. **Demo cadence.** Management demos at meaningful milestones, not on
   fixed schedule. Build in private until each phase is ready to show.