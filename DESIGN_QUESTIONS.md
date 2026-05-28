# SAHM Design Questions

This document tracks open design questions, deferred decisions, and known
items that need revisiting before pilot deployment or v1.0 release.

Entries are dated. Resolved items remain in the file (marked Resolved) so the
decision trail is preserved.

---

## 2026-05-26: Extended Event Log Channels

**Status:** Open. Deferred to post-rapid_triage profile expansion.

**Question:** Should rapid_triage collect additional event log channels beyond
the current 8 core channels?

**Current scope:**
- Security
- System
- Application
- Microsoft-Windows-PowerShell/Operational
- Microsoft-Windows-TaskScheduler/Operational
- Microsoft-Windows-TerminalServices-LocalSessionManager/Operational
- Microsoft-Windows-WinRM/Operational
- Microsoft-Windows-Windows Defender/Operational
- (Optional) Microsoft-Windows-Sysmon/Operational

**Candidates for inclusion:**
- Microsoft-Windows-WMI-Activity/Operational
- Microsoft-Windows-DNS-Client/Operational
- Microsoft-Windows-Bits-Client/Operational
- Microsoft-Windows-AppLocker/EXE and DLL
- Microsoft-Windows-CodeIntegrity/Operational
- Microsoft-Windows-Kernel-PnP/Configuration
- Microsoft-Windows-LSA/Operational
- Microsoft-Windows-PrintService/Operational
- Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational

**Decision pending:** Each adds collection time and disk space. Need to assess
per-channel value against typical case requirements. Likely candidates for
extended_live profile rather than rapid_triage.

---

## 2026-05-26: Extended Persistence Locations

**Status:** Open. Deferred to extended_live profile.

**Question:** Should persistence_core collect additional persistence locations?

**Current scope:**
- Scheduled tasks
- Services
- WMI event subscriptions (consumers, filters, bindings)
- Startup folders (system and user)
- Winlogon keys
- Image File Execution Options
- AppInit_DLLs
- Run/RunOnce keys (HKLM and HKCU, including Wow6432Node)

**Candidates for inclusion:**
- COM hijacking locations (HKLM and HKCU CLSID InprocServer32)
- AppCertDLLs
- LSA authentication packages and notification packages
- Office persistence (Outlook plugins, Word/Excel COM addins, Office Test)
- PowerShell profile scripts
- Active Setup
- Shell extensions (column handlers, context menus)
- Netsh helpers
- BITS jobs
- Time providers
- Print processors
- Boot Execute (HKLM\System\CurrentControlSet\Control\Session Manager)

**Decision pending:** Each addition increases collection scope and noise.
Should be added to extended_live profile rather than rapid_triage to keep
the rapid profile focused.

---

## 2026-05-26: Browser Artifact Baseline

**Status:** Open. Pending decision on browser support scope.

**Question:** Which browsers should SAHM collect artifacts from, and what
artifacts per browser?

**Considerations:**
- Chrome and Edge (Chromium-based) share the same artifact format
- Firefox uses a different format
- Brave, Opera, Vivaldi are Chromium variants
- Internet Explorer is deprecated but may still be present on older targets
- Per-user collection means iterating discovered profiles via pathfinder

**Candidate artifacts per browser:**
- History (URLs visited)
- Downloads
- Bookmarks
- Login data (paths to credential storage — NOT decrypted credentials, that's
  out of scope for forensic preservation)
- Extensions
- Cookies (file paths only, not decoded values)

**Decision pending:** Likely scope for extended_live profile.

---

## 2026-05-26: $MFT and USN Journal Extraction

**Status:** Open. Required for extended_live profile.

**Question:** How should SAHM extract $MFT (Master File Table) and USN Journal?

**Options:**
1. Use Windows API DeviceIoControl with FSCTL_QUERY_USN_JOURNAL — pure Go,
   no external dependencies
2. Use third-party tool wrapper — same dependency concern as memory acquisition
3. Raw NTFS reading via volume handle — complex, error-prone

**Decision pending:** Option 1 is preferred to maintain self-contained approach.
Implementation complexity is moderate but manageable.

---

## 2026-05-26: SYSVOL Listing for Domain Targets

**Status:** Open. Pending server_infra profile design.

**Question:** Should SAHM enumerate SYSVOL contents on domain controllers?

**Considerations:**
- Useful for finding GPO modifications and scripts left for persistence
- Can be large (multi-GB on busy domains)
- Listing vs. full copy decision needed
- Permission requirements vary

**Decision pending:** Scope for server_infra profile (August timeline).

---

## 2026-05-27: Memory Acquisition Approach

**Status:** Resolved.

**Question:** How should SAHM handle memory acquisition?

**Options considered:**
1. Bundle WinPmem (Apache 2.0) — most direct, requires accepting third-party
   binary in distribution
2. Wrap separately-installed WinPmem (path-discovery via pathfinder) — keeps
   binary external, still depends on third-party tool
3. Build full physical memory acquisition in Go — would require kernel driver,
   multi-year effort, not feasible
4. Build user-mode per-process memory inspection in Go — covers ~80% of IR
   memory analysis cases without kernel access, fully native

**Decision:** Option 4. Build `process_memory_inspection` module in Go.

**Rationale:**
- Aligns with SAHM's "precisely fetch valuable data, not garbage" identity
- No third-party dependencies, no kernel driver, no signing requirements
- Covers the majority of operational IR cases
- Full memory acquisition deferred to LIMITATIONS.md as a known gap

**Tradeoffs:**
- Kernel-mode threats remain invisible to SAHM
- Cases requiring full memory dump must use separate tools
- Documented honestly in LIMITATIONS.md so users/stakeholders know the scope

**Next session:** Begin implementation of process_memory_inspection module.
Initial scope: process enumeration with OpenProcess, RWX memory region
detection. Subsequent sessions add loaded module integrity check, strings
extraction, handle enumeration, token information.

---

## 2026-05-27: Convert Remaining reg query Usage to Registry API

**Status:** Open. Medium priority before pilot.

**Question:** Should persistence_core's registry reads use the Windows registry
API instead of `reg query` text parsing?

**Background:** The pathfinder module was migrated to direct registry API calls
to handle non-Latin characters correctly. Persistence_core still uses
`reg query` for run keys, winlogon keys, IFEO, and AppInit_DLLs.

**Risk:** Low — persistence locations rarely contain non-Latin value names.
But a deliberately-named malware persistence entry could evade SAHM's
collection on some Windows locales.

**Decision pending:** Convert before pilot deployment. Same pattern as
pathfinder: use golang.org/x/sys/windows/registry with manual UTF-16 decoding
for REG_EXPAND_SZ values to avoid the ANSI codepage corruption bug.

---

## 2026-05-27: Severity Levels for Preflight Findings

**Status:** Open. Lower priority.

**Question:** Preflight findings have severity (info/warning/critical) but
the dry-run output doesn't fully use the distinction.

**Current behavior:** Critical findings cause dry-run to FAIL. Warnings are
displayed but don't fail. Info findings are not currently produced by any
preflight check.

**Improvement:** Match the module finding severity model. Add info-level
preflight findings for things like "low but acceptable disk space" or
"running on first boot, some caches may be empty."

**Decision pending:** Implement once a clear use case emerges.

---

## 2026-05-27: Per-Command Positive Content Check Maintenance

**Status:** Open.

**Question:** Positive content checks (MustContain strings) are currently
hardcoded English strings like "Image Name" for tasklist. These could fail
on non-English Windows locales.

**Examples that may break on localized Windows:**
- "Image Name" in tasklist output
- "OS Name" in systeminfo output
- "USER INFORMATION" in whoami output
- "Windows IP Configuration" in ipconfig output
- "Proto" header in netstat output

**Mitigation options:**
1. Add `/E` flag where supported to force English output
2. Maintain locale-specific check strings
3. Use structural validation (line count, column count) instead of string match
4. Skip positive checks on non-English locales, rely on negative checks only

**Decision pending:** Investigate during validation suite work.

---

## 2026-05-27: Automated Regression Test Suite

**Status:** Open. High priority before pilot.

**Question:** SAHM has no automated test suite. All testing is manual,
running on a single Windows 11 VM.

**Risks of current approach:**
- Regression bugs are caught by re-running and observing, not by tests
- Code changes can break existing functionality without notice
- New module additions can't be validated against a baseline
- Output structure changes can silently break downstream tools

**Recommended approach:**
- Maintain a known-state VM (Windows 11, clean install, predictable artifact
  count)
- After every significant change, run rapid_triage against this VM
- Compare artifact count, manifest verification result, and warning count
  against a recorded baseline
- For module-specific testing, capture expected output and compare

**Decision pending:** Build basic baseline-comparison test script before
pilot. Full automated regression suite is post-v1.0 work.

---

## 2026-05-27: Code Signing Certificate Procurement

**Status:** Open. Required for pilot deployment.

**Background:** Unsigned executables trigger SmartScreen warnings, EDR alerts,
and possible execution blocks on hardened targets. SAHM should ship signed
for production use.

**Options:**
1. Standard code signing certificate (~$200-400/year) — works but still
   produces SmartScreen warnings until reputation is established
2. EV (Extended Validation) code signing certificate (~$300-500/year) —
   instant SmartScreen trust, USB hardware token required for signing
3. Sign with organizational certificate authority — requires AD integration
   and is only trusted within the organization

**Decision pending:** Conversation needed with team/management about budget
and procurement process. Lead time for EV certs can be 4-6 weeks due to
identity verification. Start procurement in May to have certificate in hand
by September pilot.

---

## 2026-05-27: Gold Master Process Formalization

**Status:** Open. Required for pilot deployment.

**Question:** How are the 10 SSDs maintained as identical, verified copies?

**Requirements:**
- Gold master SSD (read-only) contains the authoritative SAHM binary, tools,
  and supporting files
- 10 field SSDs are imaged from the gold master at start of rotation
- After each case, field SSDs have Partition B (evidence) wiped and re-imaged
- Periodic full re-image of all field SSDs from gold master (every 10 cases
  or on suspicion)

**Open questions:**
- What imaging tool? (dd, Clonezilla, FTK Imager, custom)
- Verification step — hash the gold master partition, verify on each re-image
- Logging — track which gold master version each field SSD was last imaged from

**Decision pending:** Design before September pilot.

---

## 2026-05-27: Validation Suite (Minimum Viable to Full)

**Status:** Open. Required progressively.

**Question:** What constitutes "validation" before each release?

**Minimum viable (for v1.0):**
- Run rapid_triage against the reference VM
- Verify expected artifact count (currently 48 on clean Windows 11 admin run)
- Verify manifest passes `sahm --verify`
- Verify case_report.txt is generated and well-formed
- Verify expected info-level findings appear (Sysmon channel absent, empty
  run keys)

**Full (for v1.1+):**
- Run all profiles against all supported target classes
- Hostile target tests (slow disk, EDR present, low disk space, network
  isolation)
- Localized Windows tests (non-English locales)
- Multi-user profile discovery tests
- Tampering detection tests (modify output, verify --verify catches it)

**Decision pending:** Build the minimum viable suite as a shell/PowerShell
script before pilot. Full suite is v1.1+ work.

---

## 2026-05-27: Lab Integration (Jira, NetApp)

**Status:** Open. Out of scope for v1.0 per earlier decision.

**Question:** Should SAHM integrate with the lab's case tracking system?

**Current plan:** No. Analysts manually upload case folders to NetApp and
create Jira tickets manually with case metadata.

**Future consideration:** v1.5+ could add a `sahm publish` command that uploads
to NetApp and creates a Jira ticket with case ID, status, and key findings.
This is workflow integration, not collection capability.

**Decision pending:** Revisit after pilot feedback.

---

## 2026-05-27: TUI Expert Mode

**Status:** Open. Deferred to v1.1 or later.

**Question:** Should the TUI support an expert mode for advanced users?

**Capabilities considered:**
- Per-module enable/disable for the selected profile
- Time budget overrides per module
- Ad-hoc collection ordering
- Module-specific parameter overrides (e.g., event log time range)

**Decision pending:** Not valuable with only one profile in v1.0. Revisit
once volatile_capture, extended_live, and server_infra are in place and
analysts have real reasons to override defaults.

---

## 2026-05-27: TUI Branding (Colors, Logo)

**Status:** Open. Polish phase work.

**Question:** Should the TUI receive custom branding?

**Capabilities possible:**
- Custom color schemes (currently using a default cyan/gray palette)
- ASCII or Unicode block-art logo on welcome screen
- Theme support (light/dark/brand)

**Decision pending:** Deferred to polish phase after functional v1.0.
Not blocking pilot deployment.