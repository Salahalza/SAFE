# SAFE — Module Command Reference

Technical brief for the IR team. Covers every collection module SAFE ships,
the artifacts each produces, and why they're in the collection.

Modules are grouped into three parts:

- **Core** — the `rapid_triage` baseline, inherited by `endpoint_deep` and
  largely by `server_infra`.
- **Extended** — the heavier opt-in modules (`endpoint_deep` / `memory_triage`).
- **Server-role** — role collectors (`ad_collection`, `iis_collection`,
  `exchange_collection`) that self-gate via `Applies()` and run in `server_infra`
  and `disk_image`.

The section numbers below are for reference only — the engine numbers each case's
module folders by **execution order within the chosen profile** (see "Output
structure" at the end), which follows the order-of-volatility principle and so
differs from the reading order here.

Everything here is **collection**. No module parses or interprets data on the
target — parsing happens in the lab via `safe-analyze --analyze`. Reads of locked
files ($MFT, hives, web-root scripts) go through **raw NTFS** (the VSS shadow
device on a live host, the mounted volume for a dead image), which issues no
per-file open and so bypasses on-access AV. Gaps and deferred decisions are in
`DESIGN_QUESTIONS.md`.

**Five profiles ship** (list with `safe-collect --list-profiles`):
`rapid_triage`, `endpoint_deep`, `memory_triage`, `server_infra`, and
`disk_image` (auto-selected when `safe-collect` is pointed at a mounted dead
image with `--source-root`; role collectors then classify the image from its own
hives rather than the analyst's host).

---

# Part A — Core modules (rapid_triage baseline)

These ten modules make up `rapid_triage` and are inherited by `endpoint_deep`
(`server_infra` runs all of them too).

## 1. system_metadata

Establishes target identity and runtime context. Critical priority — every
case needs to know what target it came from. Budget: 30 seconds.

| File | Command | What it captures |
|------|---------|------------------|
| `systeminfo.txt` | `systeminfo` | OS name, version, build, install date, hotfixes, hardware summary, locale, BIOS info. Foundational target identification. |
| `hostname.txt` | `hostname` | Computer name. Cheap, but verifies the target identity matches the case metadata. |
| `whoami_all.txt` | `whoami /all` | Current user, SID, group memberships, privileges. Tells you what context SAFE ran under — important when analyzing partial collections. |
| `ipconfig_all.txt` | `ipconfig /all` | All network adapters, IPs, MACs, DNS servers, DHCP info. Network identity of the target at collection time. |
| `environment.json` | (internal) | Hostname, collection timestamp, working directory, **is_admin flag**, OS, architecture. The is_admin flag is critical for interpreting partial results — many modules degrade without admin. |

**Notes:**
- `systeminfo` is naturally slow (3–5s typical). Don't optimize this away — its output is the canonical "what is this machine" record.
- `whoami /all` includes the privileges list, which lets the lab confirm whether collection had the rights it needed.

---

## 2. process_snapshot

Captures running processes and services. Critical priority. Budget: 60 seconds.

| File | Command | What it captures |
|------|---------|------------------|
| `tasklist_verbose.txt` | `tasklist /v /fo list` | Every process with PID, session, memory, status, user context, window title, image name. Verbose format gives broader detail than default. |
| `tasklist_services.txt` | `tasklist /svc /fo list` | Process-to-service mapping. Shows which svchost.exe instance is hosting which services — essential for correlating service-based threats. |
| `processes_powershell.txt` | `Get-CimInstance Win32_Process \| Format-List` | Same as tasklist but with **CommandLine, ParentProcessId, ExecutablePath, CreationDate**. Command line is often the single most important investigative artifact for process-based threats. |
| `services_state.txt` | `Get-CimInstance Win32_Service \| Format-List` | All services with State, StartMode, PathName, StartName (service account). Catches malicious services and unusual service accounts. |

**Why both tasklist and PowerShell:**
- `tasklist` is bulletproof, works on every Windows version, fast.
- `Get-CimInstance Win32_Process` gives the command line — tasklist doesn't.
- Redundancy is intentional. If one fails, the other usually succeeds.

**Watch for in the lab:**
- Processes with no parent (PPID = orphaned)
- Process executables in unusual paths (`%TEMP%`, `\Users\Public\`, `\AppData\`)
- Services with `StartName` that isn't `LocalSystem`, `LocalService`, `NetworkService`, or a known service account
- Mismatched process names vs binary paths

---

## 3. network_snapshot

Captures network state at the moment of collection. Critical priority. Budget: 60 seconds.

| File | Command | What it captures |
|------|---------|------------------|
| `netstat_abno.txt` | `netstat -abno` | TCP/UDP connections + listening ports + **process names + PIDs**. Requires admin (the `-b` flag). |
| `netstat_ano.txt` | `netstat -ano` | Same as above minus process names. **Graceful fallback** — works without admin. |
| `netstat_rn.txt` | `netstat -rn` | Routing table in numeric form. |
| `arp_a.txt` | `arp -a` | ARP cache. Recent IP-to-MAC mappings. Useful for lateral movement context. |
| `route_print.txt` | `route print` | Routing table (Windows-formatted). |
| `dns_cache.txt` | `ipconfig /displaydns` | Cached DNS lookups. Surfaces recently contacted domains, including ones not in browser history. |
| `tcp_connections_powershell.txt` | `Get-NetTCPConnection \| Format-List` | TCP connections with **OwningProcess and CreationTime**. CreationTime is investigatively valuable — netstat doesn't show when a connection was established. |
| `udp_endpoints_powershell.txt` | `Get-NetUDPEndpoint \| Format-List` | UDP listening endpoints with owning process. |
| `firewall_rules_enabled.txt` | `Get-NetFirewallRule -Enabled True \| Format-List` | All enabled firewall rules. Attackers sometimes add rules to allow C2 traffic. |
| `firewall_profiles.txt` | `Get-NetFirewallProfile \| Format-List` | Firewall profile state (Domain/Public/Private). Catches "firewall disabled" findings. |
| `network_adapters.txt` | `Get-NetAdapter; Get-NetIPAddress` | Adapter and IP details, structured. Complements ipconfig. |

**Why two netstat variants:**
The dual-netstat pattern is the model for graceful degradation. If admin is available, the rich version succeeds. If not, the basic version still produces port/PID data. Lab analysis is still possible either way — it just lacks process names in the non-admin case.

**Watch for in the lab:**
- Established connections to unexpected external IPs
- Listening ports on non-standard ranges
- Connections owned by processes that shouldn't be doing network IO (e.g., `notepad.exe` with active TCP connections)
- DNS cache entries to known-bad domains
- Firewall rules created recently or referencing unusual paths

---

## 4. eventlogs_core

Exports core Windows event log channels as `.evtx` files. **No time filter** —
full channel export, supporting retro hunting. High priority. Budget: 10 minutes.

| File | Channel | Why |
|------|---------|-----|
| `Security.evtx` | Security | Authentication, privilege use, account changes, object access. Foundational. |
| `System.evtx` | System | Service starts/stops, driver loads, system state changes. |
| `Application.evtx` | Application | Application crashes, app-specific events. |
| `Microsoft-Windows-PowerShell_Operational.evtx` | PowerShell/Operational | Script block logging if enabled. PowerShell is heavily abused. |
| `Microsoft-Windows-TaskScheduler_Operational.evtx` | TaskScheduler/Operational | Task creation, modification, execution. Persistence and execution evidence. |
| `Microsoft-Windows-TerminalServices-LocalSessionManager_Operational.evtx` | TerminalServices LSM | RDP session events. Lateral movement evidence. |
| `Microsoft-Windows-WinRM_Operational.evtx` | WinRM/Operational | Remote management activity. Lateral movement evidence. |
| `Microsoft-Windows-Windows Defender_Operational.evtx` | Defender/Operational | Built-in AV detections, exclusions, scan history. |
| `Microsoft-Windows-Sysmon_Operational.evtx` | Sysmon/Operational (optional) | Gold standard if installed. Module degrades gracefully if absent. |

**Mechanism:** `wevtutil epl <Channel> <output_file>` produces a complete EVTX
copy of the channel. Lab tools (Hayabusa, EvtxECmd, etc.) parse these natively.

**Why no time filter:**
Retro-hunt cases require all retained events. A 7-day filter is a SOC default,
not an IR default. If an attacker was in for 6 months, recent windows give us
nothing useful.

**Sysmon is optional, not required:**
If the channel doesn't exist (Sysmon not installed), the module logs a warning
and continues. The case still completes successfully.

**Note — overlap with extended_event_channels:** these 8 curated channels are
also captured (by raw shadow copy) by `extended_event_channels` in
`endpoint_deep` / `server_infra`. The overlap is intentional — different methods
(live `epl` export vs. point-in-time shadow snapshot). On a dead image only
`extended_event_channels` runs (there is no live host to `epl` from).

**Watch for in the lab:**
- Event log clearing events (Security 1102, System 104) — anti-forensics
- Gaps in EventRecordID continuity — evidence of selective deletion
- Authentication events from unexpected source IPs
- 4624 logon events with type 3 (network) or type 10 (RemoteInteractive) at unusual hours
- PowerShell 4104 (script block) events with obfuscated payloads
- Defender 1116 (threat detected) and 1117 (action taken) — known-bad executions

---

## 5. registry_core

Saves the four core HKLM hives as binary files. High priority. Budget: 5 minutes.
On a live host it uses `reg save`; on a dead image it copies the hive files
straight from the image.

| File | Hive | What's in it |
|------|------|--------------|
| `HKLM_SYSTEM.hiv` | HKLM\SYSTEM | Driver list, service config, ControlSet, system policy, USB device history (USBSTOR, MountedDevices), AppCompat data. |
| `HKLM_SOFTWARE.hiv` | HKLM\SOFTWARE | Installed software, Run keys, Uninstall data, Office config, .NET versions, app-specific persistence locations. The largest hive — typical 50–150 MB. |
| `HKLM_SAM.hiv` | HKLM\SAM | Local user accounts, password hashes (LM/NTLM if extractable). Requires admin. Feeds the lab-side `sam` parser (rogue-account detection). |
| `HKLM_SECURITY.hiv` | HKLM\SECURITY | LSA secrets, cached domain credentials, audit policy. Requires admin. |

**Why hive copies, not key dumps:**
- Hive files preserve every key, value, and timestamp.
- Lab tools work directly on hives, not on text dumps.
- A `reg query /s` dump loses last-write timestamps and is much harder to analyze.

**SAM and SECURITY require admin (live):**
Without admin, those two `reg save` calls fail. The other two succeed. Module
status goes to `partial`. Lab analyst sees in the result.json which hives are
present and which aren't.

**Watch for in the lab:**
- Recently-modified keys in autorun locations
- Unsigned drivers in HKLM\SYSTEM\CurrentControlSet\Services
- Suspicious entries in SOFTWARE\Microsoft\Windows\CurrentVersion\Run
- USB device history (which devices were attached and when)
- Cached credentials and LSA secrets (if extracted from SECURITY hive)

**Per-user hives** (NTUSER.DAT, UsrClass.dat) are collected separately by
`user_hives_collection`.

---

## 6. persistence_core

Captures common persistence mechanisms. High priority. Budget: 3 minutes. The
raw `reg query` / command output IS the artifact — no interpretation is written
into the collected files (classification stays in the module's Findings).

### Stdout-capture commands

| File | Command | What it captures |
|------|---------|------------------|
| `scheduled_tasks_verbose.txt` | `schtasks /query /fo LIST /v` | Every scheduled task with full detail: triggers, actions, run-as account, last run, next run. |
| `scheduled_tasks_xml.txt` | `schtasks /query /xml ONE` | Same data in XML — preserves nested triggers and conditions that LIST format flattens. |
| `services_qc_all.txt` | `sc query state= all` | All services regardless of state (running, stopped, paused). Complements `process_snapshot` services data. |
| `wmi_event_consumers.txt` | `Get-CimInstance __EventConsumer` | WMI persistence — consumers (what executes). Common in advanced threats. |
| `wmi_event_filters.txt` | `Get-CimInstance __EventFilter` | WMI persistence — filters (when it triggers). |
| `wmi_filter_to_consumer_bindings.txt` | `Get-CimInstance __FilterToConsumerBinding` | Links filters to consumers. The complete WMI persistence triad. |
| `startup_folders.txt` | PowerShell directory listing | Files in `%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp` and per-user equivalent. Old-school but still used. |
| `winlogon_keys.txt` | `reg query HKLM\...\Winlogon` | Shell, Userinit values. Classic persistence. |
| `image_file_execution_options.txt` | `reg query HKLM\...\Image File Execution Options /s` | Debugger hijacks. Common technique to redirect execution. |
| `appinit_dlls.txt` | `reg query HKLM\...\Windows /v AppInit_DLLs` | DLL loaded into every process using user32. Less common now but still exists. |

### Run keys (each queried separately for graceful degradation)

| File | Registry key |
|------|-------------|
| `run_hklm.txt` | `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` |
| `runonce_hklm.txt` | `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce` |
| `run_hklm_wow64.txt` | `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run` |
| `runonce_hklm_wow64.txt` | `HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce` |
| `run_hkcu.txt` | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` |
| `runonce_hkcu.txt` | `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce` |

**Why query Run keys individually:**
A missing Run key (e.g., RunOnce empty on a clean system) causes `reg query`
to return non-zero exit. If we batched them, one missing key would fail the
whole module. Per-key queries let missing keys downgrade to info findings while
preserving artifacts from keys that exist.

**Wow6432Node coverage:**
On 64-bit Windows, 32-bit applications see `Wow6432Node\` keys redirected.
Persistence written there is invisible to a 64-bit registry query of the
non-Wow6432 path. Both must be checked.

**Watch for in the lab:**
- Run/RunOnce values pointing to scripts, encoded commands, or paths in user-writable directories
- Scheduled tasks with `principal` set to SYSTEM but with action paths in user directories
- Tasks with hidden flag set
- WMI bindings linking a filter to a consumer (a complete triad is suspicious by default)
- Services with binary paths in unusual locations
- Image File Execution Options entries with `Debugger` value pointing to non-Microsoft binaries
- AppInit_DLLs with any value (rare on modern systems — almost always suspicious)

**Coverage:** persistence_core covers the most common locations. Additional
ASEPs (BAM/DAM, service registry tree, LSA, Session Manager, BHOs, etc.) are
captured by `extended_persistence` in `endpoint_deep`. COM hijacks are parsed
lab-side by the `com_hijack` analyzer from the collected SOFTWARE/NTUSER hives.

---

## 7. ntfs_metadata

Collects the core NTFS file-system metadata structures directly from the raw
volume. **Critical** priority. Requires VSS (live). Budget: 5 minutes. In every
profile except `memory_triage`.

| Output | Source | What it captures |
|--------|--------|------------------|
| `MFT` | `$MFT` | Master File Table — a record per file/directory with the standard and filename timestamps. The backbone of the file-system timeline (millions of rows on a server). |
| `LogFile` | `$LogFile` | NTFS transaction log — recent metadata operations, useful for recovering deleted/renamed activity. |
| `Boot` | `$Boot` | Volume boot record. |
| `Secure_SDS` | `$Secure:$SDS` | Security descriptors stream. |
| `UsnJrnl_J` | `$Extend\$UsnJrnl:$J` | USN change journal — a running log of file creates/deletes/renames. **Tail-capped at 1 GiB** of recent activity (the journal's logical size can be tens of GB of sparse zeros; only the tail holds live records). |

**Mechanism:** SAFE parses the raw NTFS volume with a Go-native NTFS parser
(`go-ntfs`). On a **live** host the volume is the **VSS shadow device**
(`Shadow.ShadowPath`); on a **dead image** it is the mounted image volume via the
shared raw-NTFS reader (`ctx.Image`). Reading the volume's clusters issues no
per-file open, so **on-access AV cannot gate it** — the same AV-agnostic path the
IIS web-root reader uses. Lab parses with the `mft` / `usn` analyzers (→
`timeline.csv`), or any third-party tool (MFTECmd, Timeline Explorer).

**Degradation on a non-raw image mount:** if the image is mounted as a
file-system redirector rather than a raw block volume (e.g. an FTK Imager "File
System" mount), `$MFT`/`$UsnJrnl` cannot be read via raw NTFS. The module emits a
warning → `partial` (not `failed`, so this critical module does **not** abort the
whole profile) and instructs the analyst to re-mount as a block device / raw
volume. The file- and hive-based collectors still run via OS reads.

**Watch for in the lab:**
- `$MFT`/USN entries for files created in the incident window (staging dirs, dropped tools)
- Timestamp anomalies (timestomping: standard-info vs. filename timestamps diverging)
- File creates/deletes in web roots, `%TEMP%`, `\Users\Public\`

---

## 8. amcache_collection

Collects the AmCache hive and its transaction logs from the shared VSS shadow.
High priority. Requires VSS. Budget: 2 minutes.

| File | Source (via shadow) | What it captures |
|------|---------------------|------------------|
| `Amcache.hve` | `C:\Windows\AppCompat\Programs\Amcache.hve` | Program-execution and installed-application evidence: SHA-1 of executed binaries, full paths, first-execution / compile (PE link) timestamps, publisher metadata. One of the strongest "what ran here" artifacts. |
| `Amcache.hve.LOG1` | same dir | Registry transaction log — lets the lab recover not-yet-flushed entries. Optional; absence is not an error. |
| `Amcache.hve.LOG2` | same dir | Second transaction log. Optional. |

**Mechanism:** direct file copy from the per-case VSS shadow (the hive is locked
on the live volume). Lab parses with the `amcache` analyzer / AmcacheParser.

**Notes:**
- If `Amcache.hve` is absent, the module records an info finding (system may have
  no execution history yet) and a warning that forensic value is reduced; it does
  not fail.
- `SourcePath`/`SourceSize` are recorded per artifact so the lab can tie the copy
  back to its live origin.

**Watch for in the lab:**
- Executables with SHA-1s matching known-bad hashes
- Binaries that ran from `%TEMP%`, `\Users\Public\`, `\AppData\`
- Compile timestamps inconsistent with claimed software age

---

## 9. user_hives_collection

Collects per-user registry hives for every **human** profile on the system, from
the shared VSS shadow. High priority. Requires VSS. Budget: 3 minutes.

Output is one subdirectory per user (sanitized username, or SID if the username
is empty/non-ASCII). Built-in profiles (LocalSystem, LocalService,
NetworkService) are discovered via `pathfinder` and skipped.

| File (per user) | Source (via shadow) | What it captures |
|------|---------------------|------------------|
| `NTUSER.DAT` | profile root | UserAssist (per-user program execution), RecentDocs, TypedURLs, RunMRU, Office MRU, per-user Run keys, ShellBags (NTUSER variant). |
| `NTUSER.DAT.LOG1` / `.LOG2` | profile root | Transaction logs (optional; missing logs are silently skipped). |
| `UsrClass.dat` | `AppData\Local\Microsoft\Windows\` | ShellBags (UsrClass variant — folder-access history), per-user file associations, additional shell activity. |
| `UsrClass.dat.LOG1` / `.LOG2` | same dir | Transaction logs (optional). |

**Mechanism:** profile enumeration via `pathfinder.DiscoverUserProfiles()`, then
each profile path is mapped into the evidence root (shadow on live, image on
dead) and the locked hives are copied out. The UserAssist / ShellBags parsers
(lab-side) consume these.

**Notes:**
- A missing **main** hive for a profile is a warning (profile may be inactive or
  non-standard); missing LOG files are normal and silent.
- Per-user output dir naming falls back to SID when the username is unusable.

**Watch for in the lab:**
- UserAssist entries showing execution of tools from user-writable paths
- ShellBags showing access to folders that no longer exist (staging dirs)
- TypedURLs / RunMRU revealing attacker-typed commands or URLs

---

## 10. prefetch_collection

Bulk-copies all Prefetch (`.pf`) files from `C:\Windows\Prefetch` via the shared
VSS shadow. High priority. Requires VSS. Budget: 3 minutes.

| Output | Source (via shadow) | What it captures |
|------|---------------------|------------------|
| `*.pf` (every Prefetch file) | `C:\Windows\Prefetch\*.pf` | Per-executable run trace: image name + path hash, last 8 run times, total run count, and the files/dirs touched in the first ~10s of execution. Captures programs that ran briefly and were then deleted. |

**Bulk-collection module (principle #4):** individual `.pf` files are copied and
hashed by the manifest walker but are **not** enumerated in `result.Artifacts`.
`result.BulkFiles` records the count, so the analyst's "things to look at" total
isn't inflated by hundreds of files.

**Notes:**
- Prefetch may be disabled (common on SSDs and Server SKUs). If the directory is
  absent the module records a warning and produces zero artifacts rather than
  failing. Non-`.pf` entries (Layout.ini, ReadyBoot/) are skipped.

**Watch for in the lab:**
- `.pf` files for binaries that no longer exist on disk
- Execution of LOLBins (rundll32, mshta, regsvr32) from odd paths
- Run counts / timestamps that place a tool on the host during the incident window

---

# Part B — Extended modules

These are **not** in `rapid_triage`. PMI lives in `endpoint_deep` and
`memory_triage`; extended persistence, browser artifacts, jump lists, and
extended event channels live in `endpoint_deep` (and, minus extended_persistence,
in `disk_image`; `server_infra` adds extended_event_channels).

## 11. process_memory_inspection

Collect-only per-process memory capture. **Optional** priority. No VSS (reads
live process memory). Budget: 30 minutes. **Opt-in only** — `endpoint_deep` and
`memory_triage`, never `rapid_triage`. Live-only (no memory exists in a disk
image).

This is the **loudest module SAFE ships** and uses native Windows syscalls rather
than shelling out. It enumerates processes, and for each one it can open, walks
the address space and dumps the bytes of every **committed, private
(non-image/non-mapped), executable-or-RWX** region.

| Output | What it is |
|------|------------|
| `processes.csv` | One row per process: pid, name, `open_result` (opened / denied / skipped), regions_total, regions_selected, regions_dumped, bytes_dumped. **Primary artifact** (analyst index). |
| `regions.csv` | One row per selected region: pid, name, base_addr, region_size, state, protect (e.g. RX, RWX), type, dumped, bytes, blob_path, note. **Primary artifact.** |
| `dumps/<pid>_<name>/<base>_<size>.bin` | Raw region bytes. **Bulk files** (counted in `result.BulkFiles`, hashed individually by the recursive manifest walk). |

**Mechanism:** `CreateToolhelp32Snapshot` → `OpenProcess(PROCESS_QUERY_INFORMATION
| PROCESS_VM_READ)` → `VirtualQueryEx` walk → protection-flag filter →
`ReadProcessMemory`. Single regions are capped at 128 MiB (truncation recorded in
the index). The System Idle process and SAFE's own process are skipped.

**Region selection is a scope filter, not analysis.** Filtering by protection
flags (committed + private + exec/RWX) is collection scoping — like "only `.evtx`
files" — so the module stays on the right side of principle #1. Image-backed code
is excluded (recoverable from disk); the filter targets injected / unbacked code.

**All interpretation is lab-side** (the `process_memory` analyzer). On the
target, the bytes ARE the artifact.

**Status semantics:** per-process `OpenProcess` denials (PPL/protected/system,
e.g. lsass.exe, services.exe, csrss.exe) are **expected** and recorded as info,
not errors — a clean run stays `success`. Opening **zero** processes degrades to
`partial` (likely not elevated, or EDR stripped every handle).

**AV / EDR reality:** OpenProcess/ReadProcessMemory are exactly what EDR hooks to
catch credential theft and injection scanning. Expect Defender to escalate and
real EDR to flag or block, possibly revoking handles mid-read. That is expected,
not a defect.

**Watch for in the lab:**
- RWX private regions (classic injection signature)
- `MZ`/PE headers at the base of a private region (reflectively-loaded modules)
- Readable C2 strings, config blobs, or decrypted payloads in dumped regions

---

## 12. extended_persistence

Readable `reg query /s` snapshots of extended Auto-Start Extensibility Points
(ASEPs) that `persistence_core` does not cover. **Normal** priority. No VSS.
Budget: 5 minutes. In `endpoint_deep`.

The raw data behind every key here is already collected as hives by
`registry_core` (SYSTEM/SOFTWARE) and `user_hives_collection` (NTUSER). This
module adds **human-readable, point-in-time triage snapshots** — the same
deliberate overlap as `extended_event_channels` vs `eventlogs_core`. The query
output IS the artifact (principle #1 exception: a native command as the
collection method).

| File | Registry key (queried `/s`) | Mechanism / why |
|------|------------------------------|-----------------|
| `bam_user_settings.txt` | `…\Services\bam\State\UserSettings` | BAM — per-user last-execution evidence (program + FILETIME). |
| `bam_user_settings_legacy.txt` | `…\Services\bam\UserSettings` | Older BAM layout. |
| `dam_user_settings.txt` | `…\Services\dam\State\UserSettings` | DAM (Desktop Activity Moderator) execution evidence. |
| `services_registry.txt` | `…\CurrentControlSet\Services` | Full service tree — ImagePath, ServiceDll, Start type, FailureCommand (hijack vectors not in live `sc query`). |
| `lsa.txt` | `…\Control\Lsa` | LSA config — Authentication/Notification packages, credential-persistence vectors. |
| `security_providers.txt` | `…\Control\SecurityProviders` | SSP DLLs loaded into LSASS. |
| `session_manager.txt` | `…\Control\Session Manager` | BootExecute, KnownDLLs, AppCertDlls, SafeDllSearchMode. |
| `netsh_helpers.txt` | `SOFTWARE\Microsoft\Netsh` | Netsh helper DLL persistence. |
| `print_monitors.txt` | `…\Control\Print\Monitors` | Print monitor DLL persistence. |
| `time_providers.txt` | `…\Services\W32Time\TimeProviders` | Time-provider DLL persistence. |
| `winlogon_full.txt` | `…\Windows NT\CurrentVersion\Winlogon` | Full Winlogon key (beyond Shell/Userinit). |
| `active_setup.txt` | `SOFTWARE\Microsoft\Active Setup\Installed Components` | Active Setup StubPath execution. |
| `shell_extensions_approved.txt` | `…\Shell Extensions\Approved` | Approved shell extension CLSIDs. |
| `browser_helper_objects.txt` | `…\Explorer\Browser Helper Objects` | BHOs (legacy IE injection). |
| `browser_helper_objects_wow64.txt` | `…\Wow6432Node\…\Browser Helper Objects` | 32-bit BHOs. |

**Mechanism:** reuses `persistence_core`'s `queryRunKey`, so missing/empty keys
(e.g. AppCertDlls, DAM on workstations) are info findings, not errors — a clean
host stays `success`.

**COM hijacks are deliberately NOT dumped here.** Machine-wide HKLM CLSID is
enormous, and per-user CLSID hijacks live in each user's NTUSER.DAT, which an
on-target `reg query HKCU` cannot reach. COM is handled lab-side by the
`com_hijack` analyzer of the already-collected SOFTWARE/NTUSER hives; a finding
records this so the absence reads as a decision, not a gap.

---

## 13. extended_event_channels

Bulk-copies **every** `.evtx` in `C:\Windows\System32\winevt\Logs` via the shared
VSS shadow. **Normal** priority. Requires VSS. Budget: 20 minutes. In
`endpoint_deep`, `server_infra`, and `disk_image`.

| Output | Source (via shadow) | What it captures |
|------|---------------------|------------------|
| `*.evtx` (every channel) | `C:\Windows\System32\winevt\Logs\*.evtx` | The complete set of event channels present on the target — often hundreds, including application/role-specific channels (Exchange, IIS, MSSQL, AppLocker, WMI-Activity, etc.) too numerous to curate by hand. |

**Bulk-collection module (principle #4):** `.evtx` files are copied and hashed by
the manifest walker but not enumerated in `result.Artifacts`; `result.BulkFiles`
records the count.

**Collection method — direct file copy, not per-channel `wevtutil epl`:**
1. **Quiet(er) visitor:** exporting every channel would spawn hundreds of
   `wevtutil` processes. Copying the locked `.evtx` files from the shadow adds
   zero new command execution on the target.
2. The `.evtx` files ARE the artifact; copying them is collection, not analysis.

**Overlap with eventlogs_core is intentional:** the 8 curated channels appear in
both on a live case. Different methods (live export vs. shadow snapshot);
completeness over dedup. On a dead image this is the *only* event-log collector.

---

## 14. browser_artifacts

Collects user browser history and metadata files for Google Chrome, Microsoft
Edge, and Mozilla Firefox, plus DPAPI master keys, using the shared VSS shadow.
**Normal** priority. Requires VSS. Budget: 5 minutes. In `endpoint_deep` and
`disk_image`.

| Output | Source (via shadow) | What it captures |
|------|---------------------|------------------|
| `Chrome/Local State` | `…\Google\Chrome\User Data\Local State` | Chrome application state and DPAPI-encrypted keys. |
| `Chrome/<Profile>/History` | `…\Google\Chrome\User Data\<Profile>\History` | Chrome user navigation history, search queries, downloads. |
| `Chrome/<Profile>/Cookies` | `…\Google\Chrome\User Data\<Profile>\Cookies` | Chrome session cookies (older versions). |
| `Chrome/<Profile>/Network/Cookies` | `…\Google\Chrome\User Data\<Profile>\Network\Cookies` | Chrome session cookies (modern versions). |
| `Chrome/<Profile>/Web Data` | `…\Google\Chrome\User Data\<Profile>\Web Data` | Auto-fill, search engines, card data. |
| `Chrome/<Profile>/Bookmarks` | `…\Google\Chrome\User Data\<Profile>\Bookmarks` | Bookmarked sites. |
| `Chrome/<Profile>/Preferences` | `…\Google\Chrome\User Data\<Profile>\Preferences` | Browser preferences and settings. |
| `Edge/…` | `…\Microsoft\Edge\User Data\…` | Microsoft Edge browser files (identical structure to Chrome). |
| `Firefox/Profiles/<Profile>/places.sqlite` | `…\Mozilla\Firefox\Profiles\<Profile>\places.sqlite` | Firefox history, bookmarks, downloads. |
| `Firefox/Profiles/<Profile>/cookies.sqlite` | `…\Mozilla\Firefox\Profiles\<Profile>\cookies.sqlite` | Firefox cookies. |
| `Firefox/Profiles/<Profile>/logins.json` | `…\Mozilla\Firefox\Profiles\<Profile>\logins.json` | Firefox saved credentials. |
| `DPAPI/Protect/<SID>/*` | `…\Protect\<SID>\*` | User DPAPI master keys required to decrypt browser databases and cookies offline in the lab. |

**Mechanism:** `IterateUserProfiles` sweeps all human user profiles, locates
active profile directories, maps to the evidence root, and copies targeted files.
The lab-side browser parsers open the collected SQLite DBs read-only (immutable
URI — no WAL sidecars written into evidence).

---

## 15. jump_lists

Bulk-copies Automatic and Custom Jump List destination files for all human users
from the shared VSS shadow. **Normal** priority. Requires VSS. Budget: 3 minutes.
In `endpoint_deep` and `disk_image`.

| Output | Source (via shadow) | What it captures |
|------|---------------------|------------------|
| `Recent/AutomaticDestinations/*.automaticDestinations-ms` | `…\Recent\AutomaticDestinations\*` | Automatically generated jump lists showing application usage history and pinned files. |
| `Recent/CustomDestinations/*.customDestinations-ms` | `…\Recent\CustomDestinations\*` | Application-defined custom jump lists. |

**Bulk-collection module (principle #4):** destination files are copied and
hashed by the manifest walker, but not enumerated individually in
`result.Artifacts`. `result.BulkFiles` records the total count. Lab parses with
the `jumplists` analyzer.

---

# Part C — Server-role modules

These collectors run in `server_infra` and `disk_image`. Each implements the
optional **`Applies()`** interface and **self-gates on role**: the engine
evaluates `Applies()` during planning and cleanly **skips** (`StatusSkipped`, no
case degradation, no forced VSS) a module whose role isn't present. Role
detection is registry-based on a live host (valid before a shadow exists) and
**offline hive-based** on a dead image (the imaged host is classified from its own
SOFTWARE/SYSTEM hives, not the analyst's machine). This lets one server profile
run safely against a DC, an IIS box, an Exchange box, or an unknown server.

## 16. ad_collection

Collects Active Directory artifacts. **High** priority. Requires VSS. Budget: 15
minutes. **Applies only on a Domain Controller** (live: NTDS registry key present;
image: NTDS service present in the SYSTEM hive).

| Output | Source | What it captures |
|------|--------|------------------|
| `SYSTEM` | `…\System32\config\SYSTEM` | The SYSTEM hive — the boot key needed to **decrypt `NTDS.dit` offline** in the lab. |
| `NTDS/ntds.dit` (+ logs) | `…\Windows\NTDS\` | The Active Directory database: every domain account, group, and credential hash. The primary DC artifact. |
| `SYSVOL/*` | `…\Windows\SYSVOL\domain\` | **Bulk** copy of SYSVOL — Group Policy objects, logon scripts, and startup scripts (a common persistence/deployment vector). Counted in `result.BulkFiles`. |

**Notes:** `NTDS.dit` can be tens of GB against the 15-minute budget; the copy
honors cancellation and unwinds cleanly rather than copying to completion past
the deadline. A missing `ntds.dit` records a critical finding.

**Watch for in the lab:** rogue/again-privileged accounts, recently-created
accounts, GPO/script modifications in SYSVOL.

---

## 17. iis_collection

Collects IIS web-server evidence. **High** priority. Requires VSS. Budget: 20
minutes. **Applies only when IIS is installed** (`InetStp`). **Discovery-first:**
it reads the *configured* log directories and site web roots out of
`applicationHost.config` rather than assuming defaults (a relocated install is
exactly the case that matters), with the defaults tried as a fallback.

| Output | Source | What it captures |
|------|--------|------------------|
| `iis_sites.json` | (audit record) | Per-site discovery result: site name/id, resolved live log dir and web root, and per-site copied/skipped counts. |
| IIS config | `applicationHost.config` + siblings | The server configuration — bindings, sites, virtual dirs, auth. |
| W3C request logs | each site's configured log dir | The raw request logs. Feeds the `iis` analyzer → `iis_requests.csv` (what was requested, when, by whom, with what status). |
| Web-root scripts | each site's web root | Server-executable scripts only (`.aspx .asmx .ashx .asax .ascx .cshtml .asp .config .php[3-5] .phtml .jsp .jspx .pl .cgi`), capped at 10 MB/file. These are the potential **web shells**. Feeds the `iis_webfiles` analyzer → `web_files.csv` (triage tiers). |

**Payload-class storage (architectural principle #9).** Web-root scripts are the
one artifact class the analyst's own AV will quarantine on write. They are stored
**raw, inside a per-module ZipCrypto-encrypted container `web_payloads.zip`**
(password: the fixed, non-secret malware-handling convention **`infected`**), so
the host AV can't see inside to quarantine them, while any tool (7-Zip, `unzip`,
Python `zipfile`) can still extract the exact original bytes. The **read** side is
AV-safe too: on a live host the web-root bytes are read through **raw NTFS over
the VSS shadow device** (the same mechanism `ntfs_metadata` uses for `$MFT`), so
an on-access scanner cannot block the read at the source; a dead image reads via
`ctx.Image`. If the raw reader can't be opened, reads fall back to OS reads (a
warning records the lost AV-safety guarantee). The analyzer records each payload's
true SHA-256 in `web_files.csv`; the manifest hashes the container as one file.

**Watch for in the lab:** web shells (see rules `IIS-01`/`IIS-02`/`IIS-07`),
LOLBin-in-query requests (`IIS-03`), and Exchange ProxyShell/ProxyLogon patterns
(`IIS-04`/`IIS-05`/`IIS-06`) — see `DETECTION_RULES.md`.

---

## 18. exchange_collection

Collects Microsoft Exchange transport and management logs. **High** priority.
Requires VSS. Budget: 20 minutes. **Applies only when Exchange is installed**
(`ExchangeServer\v15`). **Discovery-first:** the install root is read from the
Exchange Setup registry key (`MsiInstallPath`), so a relocated install is still
found (defaults to `…\Exchange Server\V15` with a warning if not resolvable).

| Output | Source (install-relative) | What it captures |
|------|---------------------------|------------------|
| `logs/TransportRoles_Logs/*` | `TransportRoles\Logs` | Message tracking and the SMTP/POP/IMAP protocol/connectivity logs — mail-flow evidence. Most incident-relevant, collected first. |
| `logs/Logging/*` | `Logging` | The broad management/health logging tree. |
| `exchange_info.json` | (audit record) | Install path and copied/skipped/budget counts. |

**Bounds:** only `.log` / `.csv` files, ≤ 200 MB each, ≤ 4 GB total (a warning
records how many files were skipped if the total budget is hit) — an active server
with months of retained logs can't balloon the case.

**Note:** Exchange's OWA/ECP **web** surface is IIS-hosted and is collected by
`iis_collection` (which runs in the same server profile), not here. This module is
the transport/logging half.

---

## Cross-module notes

**`Applies()` self-gating (Part C):** the engine evaluates a module's optional
`Applies(ctx)` during planning. A module that doesn't apply is marked
`skipped` — it does not run, does not force VSS, and does not degrade the case.
This is how one `server_infra`/`disk_image` run covers a DC, an IIS box, an
Exchange box, or an unknown server without collecting artifacts that don't exist.

**Dead-image mode:** `safe-collect --source-root <mounted-volume>` (optionally
`--source-image <file>` for the chain-of-custody record) selects the `disk_image`
profile automatically, skips VSS and every live-only module, reads NTFS metadata
and web-root payloads via the shared raw-NTFS reader over the image, and gates the
role collectors on **offline** hive detection.

**Hashing:** every artifact gets SHA-256. The manifest walker hashes
**recursively**, so nested outputs (per-user hive dirs, `dumps/<pid>/*.bin`,
`NTDS/`, `SYSVOL/`, the payload container) are all covered. Hashes are in each
module's `module.json` and the case `manifest.sha256`. `safe-analyze -verify`
re-hashes and compares.

**Output structure** (folders numbered by **execution order within the profile**;
`endpoint_deep` shown — its order is the order-of-volatility superset):
```
CASE-<id>_<timestamp>/
  case.json
  result.json
  case_report.txt
  manifest.json
  manifest.sha256
  modules/
    01_process_snapshot/
    02_process_memory_inspection/
    03_network_snapshot/
    04_system_metadata/
    05_eventlogs_core/
    06_registry_core/
    07_persistence_core/
    08_extended_persistence/
    09_ntfs_metadata/
    10_amcache_collection/
    11_user_hives_collection/
    12_prefetch_collection/
    13_browser_artifacts/
    14_jump_lists/
    15_extended_event_channels/
```
Other profiles run a subset / superset in their own order-of-volatility sequence:
- `rapid_triage` — the core ten (no PMI, no extended, no role modules).
- `memory_triage` — just `process_snapshot` + `process_memory_inspection`.
- `server_infra` — core (minus PMI/extended_persistence) + `extended_event_channels`,
  then the three role collectors (`ad_collection`, `iis_collection`,
  `exchange_collection`) last; whichever roles don't apply are skipped.
- `disk_image` — file/hive collectors only (`registry_core`, `ntfs_metadata`,
  `amcache`, `user_hives`, `prefetch`, `browser_artifacts`, `jump_lists`,
  `extended_event_channels`) + the role collectors; no volatile modules.

**Status semantics:**
- `success` — every command produced expected output; only info findings, if any.
- `partial` — some artifacts produced, some commands failed, or a warning fired. Common cause: missing admin, or a non-raw image mount.
- `failed` — no artifacts produced. Module couldn't run.
- `skipped` — module didn't run (not applicable via `Applies()`, or VSS unavailable).
- `timed_out` — the module's time budget or the case context expired mid-run.

**Priority and engine reaction:**
- `critical` (system_metadata, process_snapshot, network_snapshot, ntfs_metadata): if they fail, the engine aborts the profile. (ntfs_metadata degrades to `partial` rather than `failed` on a non-raw image mount, so it does not abort there.)
- `high` (eventlogs_core, registry_core, persistence_core, amcache_collection, user_hives_collection, prefetch_collection, ad_collection, iis_collection, exchange_collection): failures degrade the case but don't abort.
- `normal` (extended_persistence, extended_event_channels, browser_artifacts, jump_lists): same — degrade, don't abort.
- `optional` (process_memory_inspection): lowest priority; a failure or overrun must never jeopardise the rest of the case.

**Profile membership:**

| Module | rapid_triage | endpoint_deep | memory_triage | server_infra | disk_image |
|--------|:---:|:---:|:---:|:---:|:---:|
| system_metadata | ✓ | ✓ | | ✓ | |
| process_snapshot | ✓ | ✓ | ✓ | ✓ | |
| process_memory_inspection | | ✓ | ✓ | | |
| network_snapshot | ✓ | ✓ | | ✓ | |
| eventlogs_core | ✓ | ✓ | | ✓ | |
| registry_core | ✓ | ✓ | | ✓ | ✓ |
| persistence_core | ✓ | ✓ | | ✓ | |
| extended_persistence | | ✓ | | | |
| ntfs_metadata | ✓ | ✓ | | ✓ | ✓ |
| amcache_collection | ✓ | ✓ | | ✓ | ✓ |
| user_hives_collection | ✓ | ✓ | | ✓ | ✓ |
| prefetch_collection | ✓ | ✓ | | ✓ | ✓ |
| browser_artifacts | | ✓ | | | ✓ |
| jump_lists | | ✓ | | | ✓ |
| extended_event_channels | | ✓ | | ✓ | ✓ |
| ad_collection¹ | | | | ✓ | ✓ |
| iis_collection¹ | | | | ✓ | ✓ |
| exchange_collection¹ | | | | ✓ | ✓ |

¹ Role collectors self-gate via `Applies()` — listed in the profile but skipped
when the target lacks the role.

**What's deliberately excluded from collection today:**
- Full physical memory acquisition (use WinPmem/DumpIt alongside SAFE; process_memory_inspection covers user-mode per-process memory). See `LIMITATIONS.md`.
- Standalone `Recent\*.lnk` shortcut files as a dedicated artifact (jump lists are collected; loose LNK parsing is not yet a separate parser).
- SQL Server role collection — planned; deferred until there is a SQL host to validate the role detector against (the no-ship-blind rule).

These are roadmap items, not gaps. See `PLAN.md` / `ROADMAP.md`.
