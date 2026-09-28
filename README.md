# SAFE (سيف)

**System for Artifacts Forensic and Examination**

![Go](https://img.shields.io/badge/Go-1.26.2-00ADD8?logo=go&logoColor=white)
![Status](https://img.shields.io/badge/status-Phase%207%20complete-brightgreen)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-blue)

SAFE is a Windows incident-response forensic tool designed for rapid, reliable evidence collection and deep offline analysis. Built with Go, it compiles into two self-contained binaries to ensure optimal operational security (OPSEC) on target endpoints:

1. **`safe-collect.exe`**: The lightweight, target-side acquisition utility. Carried on a USB SSD, it executes on endpoints under administrator privileges to capture volatile state and system artifacts, writing them into an integrity-sealed, SHA-256 hashed case folder.
2. **`safe-analyze`**: The host-side analysis framework and interactive terminal UI (TUI). Run back in the lab (macOS/Linux/Windows), it parses the collected case folder, conducts threat inspections, and compiles analyst-ready reports entirely offline.

No installers, no external runtime dependencies, and no network requirements.

---

## Roadmap & Progress

SAFE is built sequentially in phases. Phases 1 through 5 are fully complete and verified.

| Phase | Description | Status |
|---|---|---|
| **1** | **Foundation:** `rapid_triage` profile (9 modules), TUI welcome, case config, analyzer foundation, UserAssist + Prefetch parsers | **Complete** |
| **2** | **Extended Collection & Lab:** `endpoint_deep` profile, process memory dumps (`process_memory_inspection`), full event channels (`extended_event_channels`), service registry ASEPs (`extended_persistence`). Lab-side WMI subscription, COM hijack, and process memory parsers. | **Complete** |
| **3** | **Browser & Per-User:** Scaffolding `per_user_iteration` by SID, Chrome/Edge/Firefox databases + DPAPI master keys, jump lists. | **Complete** |
| **4** | **Parser Expansion:** EVTX logs, AmCache, ShellBags, ShimCache, Scheduled Tasks XML, BAM/DAM. | **Complete** |
| **5** | **Timeline Generation:** Plaso-compatible supertimeline CSV (`timeline.csv`). | **Complete** |
| **6** | **IOC Infrastructure:** PDF and Plain Text threat-report extraction to STIX 2.1 packs. | **Complete** |
| **7** | **Detection Engine:** Built-in behavioral detections evaluating parsed CSV artifacts with Timeline injection. | **Complete** |
| **8** | **HTML Viewer:** Local, self-contained offline browser viewer. | **Complete** |
| **9** | **Interactive CLI Suite:** Smart auto-inference, interactive folder selection, and automated browser launching. | **Complete** |
| **10** | **Server Forensics:** Dedicated `domain_controller` and `server_role` (Exchange, SQL, IIS) profiles. | Planned |
| **11** | **Raw NTFS:** Direct parsing of `$MFT`, `$J` (USN Journal), and `$LogFile`. | **Complete** |
| **12** | **Detection Tier 3:** Cross-artifact event correlation and multi-case HTML platform. | Planned |
| **13** | **Production Readiness:** Code signing, reproducible builds, validation suite, v1.0 release. | Planned |

---

## Architectural Principles

1. **Strict Collection/Analysis Separation:** Target-side collection (`safe-collect`) does NOT parse or analyze files on the endpoint. This minimizes target footprint, prevents EDR alarms, and preserves forensic integrity. All extraction and triage happen in the lab via `safe-analyze`.
2. **Order of Volatility:** Within any collection profile, modules run from most-volatile to least-volatile (e.g. process and network snapshots are completed before reading registry hives or event logs).
3. **Shared Case-Level VSS Shadow:** A single Volume Shadow Copy is created per case run. Modules that need locked-file access share this shadow, minimizing disk load and system noise.
4. **Tamper-Evident Manifest Chain:** Every file collected is SHA-256 hashed. Each module outputs a `module.json` manifest, which is rolled up into a top-level `manifest.json` and signed in `manifest.sha256` for strict chain-of-custody verification.
5. **Zero External Runtime Dependencies:** Everything is statically compiled into self-contained Go binaries. No wrapping of external executables (e.g., KAPE or EZ Tools).

---

## Collection Profiles

We support three collection profiles, catering to different investigative speeds and EDR footprints:

* **`rapid_triage` (v0.2.0):** Fast first-touch triage of an unknown endpoint. Collects process snapshots, network configuration, event log channels, registry hives, and prefetch folders. Takes ~30 seconds.
* **`endpoint_deep` (v0.3.0):** Deeper capture for confirmed compromised systems. Collects everything in `rapid_triage` plus full Event Log channels, service ASEPs, and per-process executable memory ranges. Takes ~1.5 minutes.
* **`memory_triage` (v0.1.0):** Specialized, EDR-visible memory acquisition. Captures process snapshots and runs targeted process memory dumps.

---

## Active Modules & Parsers

### Collection Modules (Target)
1. `process_snapshot` — Captures active processes, command lines, services, and parent PIDs.
2. `network_snapshot` — Captures TCP/UDP sockets, routing tables, ARP caches, and firewall configurations.
3. `system_metadata` — Collects system info, hostname, ipconfig, and environment details.
4. `eventlogs_core` — Captures 8 core event logs (Security, System, PowerShell, Defender, Task Scheduler, Application, etc.).
5. `registry_core` — Copies SYSTEM, SOFTWARE, SAM, and SECURITY registry hives.
6. `persistence_core` — Collects Scheduled Tasks, Services, Run/RunOnce registry keys, and WMI persistence records.
7. `amcache_collection` — Copies `Amcache.hve` and transaction logs.
8. `user_hives_collection` — Copies `NTUSER.DAT` and `UsrClass.dat` hives for all profiles.
9. `prefetch_collection` — Collects all system `.pf` files.
10. `process_memory_inspection` — Captures executable and RWX private memory pages of running processes.
11. `extended_persistence` — Collects BAM/DAM, LSA, and advanced system ASEPs.
12. `extended_event_channels` — Bulk-collects all system Event Log files (`.evtx`).

### Lab Analyzers (Lab)
* **`userassist`** — Parses `NTUSER.DAT` hives to build CSV timelines of program runs, counts, focus times, and last executed timestamps.
* **`prefetch`** — Parses Prefetch `.pf` files to reconstruct application execution history.
* **`process_memory`** — Triage tool for process memory dumps; carves PE files, dumps readable strings, and highlights suspicious RWX pages.
* **`com_hijack`** — Scans registry hives (specifically `UsrClass.dat` CLSIDs) against HKLM software configurations to expose COM hijacking persistence.
* **`wmi_subscriptions`** — Parses collected WMI text data, correlates Event Consumers with Event Filters, and tiers bindings (High/Notable/Low) to surface persistence payloads.
* **`ioc_extraction`** — Extracts, refangs, and validates threat intelligence (IPs, Domains, URLs, Hashes) from PDF and TXT reports, generating standard STIX 2.1 JSON intelligence packs.
* **`timeline`** — Aggregates all parsed artifact CSVs into a single Plaso-compatible `timeline.csv` (using standard `datetime` column formats) for ingestion into EZ Timeline Explorer.
* **`mft`** — Parses `$MFT` via dual-stream strategy (comprehensive dump + timeline injection) to balance scale and speed.
* **`usn`** — Parses raw USN Journal (`$J`) to uncover critical file creation, modification, and deletion events.
* **`behavior_engine`** — Evaluates parsed artifacts against a suite of offline behavioral rules (e.g., UAC Bypass, ShellBags suspicious browsing, Defender Tampering). Hits are output to `behavior_hits.csv` and injected into the timeline as `ALERT` events.

---

## Build Workflow

Standard compilation checks and cross-compilation are controlled via the root `Makefile`:

```bash
# Compile and vet local packages on development host
make build
make vet

# Build the analyst-side binary for your current OS
make analyze     # Outputs to test-output/host/safe-analyze (or safe-analyze.exe)

# Cross-compile safe-collect.exe for the Windows VM target and sync it over SSH
make vm          # Outputs to test-output/vm/bin/safe-collect.exe
```

---

## Usage Guide

### 1. Acquisition (Target Endpoint)
Execute `safe-collect.exe` as Administrator. 

**CLI Mode:**
```cmd
.\safe-collect.exe --case INC-2026-0618 --analyst SA --target CLIENT-WS-01 --profile rapid_triage --output D:\CaseData
```

**Interactive TUI Mode:**
```cmd
.\safe-collect.exe --tui
```

### 2. Lab Analysis (Analyst Workstation)
Analyze the case folder collected from the endpoint:

```bash
# Run interactively (will prompt for a case folder)
./safe-analyze

# Or provide a case folder directly
./safe-analyze CASE-INC-2026-0618_20260618-120000
```
This produces parsed CSV, summary, and TXT reports under `/path/to/case/lab_report/`. If a case has already been analyzed, `safe-analyze` will automatically start the HTML server (`--serve`) and open your default browser.

### 3. Case Integrity Verification
Verify that no file in the case folder (including the lab reports) has been altered since collection:

```bash
./safe-analyze --verify CASE-INC-2026-0618_20260618-120000
```

---

## Dependencies
* `github.com/charmbracelet/bubbletea` & `lipgloss` (Interactive TUI interface)
* `www.velocidex.com/golang/regparser` (Offline registry parsing)
* `www.velocidex.com/golang/go-prefetch` (Offline Prefetch parsing)
