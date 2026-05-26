# Acquira — Module Command Reference

Technical brief for the IR team. Covers every command in every module of the
`rapid_triage` profile, what it captures, and why it's in the collection.

This is the v1 baseline. Gaps and deferred decisions are in `DESIGN_QUESTIONS.md`.

---

## 1. system_metadata

Establishes target identity and runtime context. Critical priority — every
case needs to know what target it came from. Budget: 30 seconds.

| File | Command | What it captures |
|------|---------|------------------|
| `systeminfo.txt` | `systeminfo` | OS name, version, build, install date, hotfixes, hardware summary, locale, BIOS info. Foundational target identification. |
| `hostname.txt` | `hostname` | Computer name. Cheap, but verifies the target identity matches the case metadata. |
| `whoami_all.txt` | `whoami /all` | Current user, SID, group memberships, privileges. Tells you what context Acquira ran under — important when analyzing partial collections. |
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
The dual-netstat pattern is the v1 model for graceful degradation. If admin is available, the rich version succeeds. If not, the basic version still produces port/PID data. Lab analysis is still possible either way — it just lacks process names in the non-admin case.

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

| File | Hive | What's in it |
|------|------|--------------|
| `HKLM_SYSTEM.hiv` | HKLM\SYSTEM | Driver list, service config, ControlSet, system policy, USB device history (USBSTOR, MountedDevices), AppCompat data. |
| `HKLM_SOFTWARE.hiv` | HKLM\SOFTWARE | Installed software, Run keys, Uninstall data, Office config, .NET versions, app-specific persistence locations. The largest hive — typical 50–150 MB. |
| `HKLM_SAM.hiv` | HKLM\SAM | Local user accounts, password hashes (LM/NTLM if extractable). Requires admin. |
| `HKLM_SECURITY.hiv` | HKLM\SECURITY | LSA secrets, cached domain credentials, audit policy. Requires admin. |

**Mechanism:** `reg save HKLM\<HIVE> <output_file> /y`. Produces a binary copy
of the live hive. Lab parses with RegistryExplorer, regripper, libregf, etc.

**Why hive copies, not key dumps:**
- Hive files preserve every key, value, and timestamp.
- Lab tools work directly on hives, not on text dumps.
- A `reg query /s` dump loses last-write timestamps and is much harder to analyze.

**SAM and SECURITY require admin:**
Without admin, those two `reg save` calls fail. The other two succeed. Module
status goes to `partial`. Lab analyst sees in the result.json which hives are
present and which aren't.

**Watch for in the lab:**
- Recently-modified keys in autorun locations
- Unsigned drivers in HKLM\SYSTEM\CurrentControlSet\Services
- Suspicious entries in SOFTWARE\Microsoft\Windows\CurrentVersion\Run
- USB device history (which devices were attached and when)
- Cached credentials and LSA secrets (if extracted from SECURITY hive)

**Out of scope for v1:**
- Per-user NTUSER.DAT and UsrClass.DAT hives — needs profile enumeration, separate module.
- HKLM\BCD and HKLM\HARDWARE — rarely useful for IR.

---

## 6. persistence_core

Captures common persistence mechanisms. High priority. Budget: 3 minutes.

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
whole module. Per-key queries let missing keys downgrade to warnings while
preserving artifacts from keys that exist.

**Wow6432Node coverage:**
On 64-bit Windows, 32-bit applications see `Wow6432Node\` keys redirected.
Persistence written there is invisible to a 64-bit registry query of the
non-Wow6432 path. Both must be checked.

**Watch for in the lab:**
- Run/RunOnce values pointing to scripts, encoded commands, or paths in user-writable directories
- Scheduled tasks with `principal` set to SYSTEM but with action paths in user directories
- Tasks with hidden flag set
- WMI bindings linking a filter to a consumer (a binding without both halves is incomplete persistence — but a complete triad is suspicious by default)
- Services with binary paths in unusual locations
- Image File Execution Options entries with `Debugger` value pointing to non-Microsoft binaries
- AppInit_DLLs with any value (rare on modern systems — almost always suspicious)

**Coverage is not complete:**
v1 covers the most common persistence locations. COM hijacking, LSA packages,
PowerShell profiles, Office persistence, and several other locations are
not yet collected. See `DESIGN_QUESTIONS.md` for the full deferred list.

---

## Cross-module notes

**Hashing:**
Every artifact gets SHA-256 at collection time. Hash is in the case `result.json`
under each module's `artifacts` array.

**Output structure:**
```
CASE-<timestamp>/
  result.json
  modules/
    01_system_metadata/
    02_process_snapshot/
    03_network_snapshot/
    04_eventlogs_core/
    05_registry_core/
    06_persistence_core/
```

**Status semantics:**
- `success` — every command produced expected output, zero errors.
- `partial` — some artifacts produced, some commands failed. Common cause: missing admin.
- `failed` — no artifacts produced. Module couldn't run.
- `skipped` — module didn't run (not applicable to current target class).

**Critical vs high priority:**
- `critical` priority modules (system_metadata, process_snapshot, network_snapshot): if they fail, the engine aborts the profile.
- `high` priority modules (eventlogs_core, registry_core, persistence_core): failures degrade the case but don't abort.

**What's deliberately excluded from v1:**
- Memory acquisition (separate `volatile_capture` profile)
- Browser artifacts (separate `extended_live` profile)
- $MFT, USN journal, file system metadata (extended_live)
- Server role-specific collection (server_infra profile)
- Per-user registry hives
- Path discovery for custom installations
- EDR detection and exclusion-aware collection

These are roadmap items, not gaps. v1 is the rapid_triage baseline.