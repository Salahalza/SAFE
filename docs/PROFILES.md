# SAFE Profiles

This document defines SAFE's collection profiles, what each is for, and when
to use which. It is the canonical reference for profile design decisions.

If you're an analyst deciding which profile to run, start here.
If you're extending SAFE with new modules, this document tells you which
profile your module belongs in.

---

## Design Principles

### Principle 1: Profiles organized around case type, not tool activity

Traditional IR thinking uses three modes — Memory, Triage, Full Image —
named after the tools they invoke. SAFE uses profiles named after the
investigative questions they answer.

This means:
- Memory inspection is integrated into the appropriate profiles, not separated.
- Full disk imaging is intentionally out of scope. Use FTK Imager, Magnet
  AXIOM, or dd for cases requiring full disk acquisition.
- Each profile is justified by a real case type, not by feature count.

### Principle 2: Order of volatility within a profile

Modules within a profile execute in order of data volatility, most volatile
first.

Volatile state (process tables, network connections, memory contents) changes
second by second on a running system. If a collection is interrupted by a
crash, isolation event, or system reboot, volatile data is gone. Static
artifacts on disk (event logs, registry hives, prefetch files) survive.

Therefore: capture volatile data first, durable data last. This minimizes
the loss if collection is cut short and reduces the time between "decision
to collect" and "volatile state captured."

In rapid_triage, this is why process_snapshot and network_snapshot run
before system_metadata and event log collection, even though all three are
fast.

### Principle 3: Collection on target, parsing in lab

SAFE is designed to be a quiet visitor on a targeted device. Every command
executed and every CPU cycle spent on the target risks:

- Alerting EDR or attacker-deployed monitoring
- Triggering anti-forensic logic in malware that watches for forensic activity
- Adding noise to event logs that the analyst then has to filter out of
  their own investigation
- Creating new prefetch entries, registry timestamps, and other artifacts
  that pollute the very evidence we're collecting

Therefore: the collection profile copies files and runs read-only commands.
It does not parse binary artifact formats, run regex extractions, or perform
any processing that can be deferred to lab analysis.

Parsing happens in lab analysis mode (`safe --analyze <case-folder>`),
running on the analyst's workstation. The case folder is the input;
`<case-folder>/lab_report/` is the output. See PLAN.md "Lab Analysis Mode"
for the parser architecture.
---

## Profile 1: rapid_triage

**Status:** Built (v0.2.0).

**Use when:** First touch on an unknown target. You don't yet know what kind
of case this is. You want fast, broadly useful evidence to decide whether
deeper collection is needed.

**Goal:** Fastest possible useful collection. Tells you whether this target
warrants deeper investigation.

**Runtime:** ~30 seconds on healthy hardware.

**Modules (in execution order, following the order-of-volatility principle —
see Design Principle 2 below):**
1. process_snapshot
2. network_snapshot
3. system_metadata
4. eventlogs_core
5. registry_core
6. persistence_core
7. amcache_collection
8. user_hives_collection
9. prefetch_collection

**Output:** ~500 artifacts on a clean Windows 11 admin run.

**What this profile does NOT include:** Process memory inspection, extended
event channels, deep persistence. If you need any of those, use endpoint_deep
or one of the server profiles instead.

**Parsing:** rapid_triage performs no parsing on the target. The collected
case folder is taken back to the lab where `safe --analyze <case-folder>`
produces parsed CSVs in a `lab_report/` subdirectory. See "Design Principle
3" below.
---

## Profile 2: endpoint_deep

**Status:** In design. Building now.

**Use when:** You've decided this workstation or single-purpose server needs
detailed investigation. Replaces the traditional "Triage" step in your
workflow with a deeper, more deliberate collection.

**Goal:** Comprehensive endpoint evidence. Captures everything rapid_triage
captures, plus live process memory inspection and extended artifact coverage.

**Runtime:** Estimated 2-5 minutes depending on process count and event log size.

**Modules (planned, in build order):**
- All rapid_triage modules
- process_memory_inspection
- full_event_logs (entire winevt/Logs directory)
- extended_persistence (COM hijacking, LSA packages, Office, etc.)
- jumplists_collection (per user)
- lnkfiles_collection (Recent folders, per user)
- browser_artifacts (Chrome, Edge, Firefox, IE Legacy)
- shimcache_parsing
- mft_extraction (raw NTFS)
- usn_journal_extraction (raw NTFS)
- ntfs_metadata (LogFile, Boot, Bitmap, Secure)

**Build status:** Module-by-module. First addition is process_memory_inspection.

---

## Profile 3: domain_controller

**Status:** Planned. Build after endpoint_deep is solid.

**Use when:** Target is a domain controller in a case involving suspected
domain compromise.

**Goal:** AD-specific evidence for domain compromise investigation.

**Runtime:** Estimated 3-10 minutes depending on AD size.

**Modules (planned):**
- All rapid_triage modules
- process_memory_inspection (focused on AD-related processes: lsass.exe to
  the extent accessible, dns.exe if DC is AD-integrated DNS, ntfrs.exe or
  dfsr.exe for SYSVOL replication)
- AD-specific event channels (Directory Service, Directory Service Replication,
  DNS Server, Active Directory Web Services, Kerberos Key Distribution Center)
- NTDS.dit handling (via ntdsutil semantic equivalent or VSS snapshot read)
- SYSVOL inventory (listing with hashes, not full copy unless flagged)
- GPO inventory (linked GPOs, recent modifications)
- FSMO role identification
- AD replication metadata
- Domain trust information

**Build complexity:** High. Each AD module requires understanding of specific
AD internals.

---

## Profile 4: server_role

**Status:** Planned. Build after domain_controller.

**Use when:** Target is a server hosting one or more application roles
(IIS, Exchange, MSSQL, SharePoint, file server). Not a domain controller —
use domain_controller for those.

**Goal:** Auto-detect installed roles and collect role-specific artifacts.

**Design approach:** Role detection runs first (similar to pathfinder's user
profile discovery — detect what's installed). Then per-role collection modules
run only for roles that are present.

**Runtime:** Highly variable. Depends on how many roles the server hosts and
log volumes.

**Role coverage for v1.0 (in priority order, based on operational frequency):**

1. **IIS** — Web server logs, application pool configuration, bindings,
   installed modules, recent w3wp.exe behavior, web.config files for
   significant sites.

2. **Exchange** — Message tracking logs, transport logs, IIS logs for OWA
   and EWS, role configuration, mailbox database file paths (not content),
   Exchange-specific event channels.

3. **MSSQL** — Error logs, audit logs (if enabled), SQL Agent jobs,
   linked servers configuration, recent failed login attempts, database
   file paths (not content).

4. **SharePoint** — ULS logs, IIS logs for SharePoint sites, configuration
   database connection info, recent administrative activity.

5. **File Server** — SMB share inventory, share permissions, recent file
   access events (Event ID 5145), File Server Resource Manager configuration
   if enabled.

**Other roles considered but deferred:**
- Hyper-V (declining frequency as cloud workloads migrate)
- WSUS (rarely compromised in our environment)
- Print Server (rarely incident-relevant)
- DNS server (covered by domain_controller if AD-integrated; standalone DNS
  rarely incident-relevant)

These can be added later if a case demonstrates need.

**Build complexity:** Each role is its own sub-module. Role detection logic
must be reliable. Plan for one session per role minimum.

---

## What's Explicitly Out of Scope

These are NOT separate profiles and will not be:

**Memory acquisition (full physical memory dump):** Out of scope per
LIMITATIONS.md. Use WinPmem or Magnet RAM Capture separately if needed.

**Full disk imaging:** Out of scope. Use FTK Imager, Magnet AXIOM, or `dd`.
SAFE gets evidence those tools can't easily get (live state); they get
evidence SAFE doesn't try to get (full disk).

**Network packet capture:** Out of scope. Use Wireshark, tcpdump, or
network appliances.

**Generic "server_infra":** Originally planned but replaced with specific
server_role profile. Generic catch-all profiles tend to do everything poorly.

---

## Profile Selection Guidance

When an analyst is deciding which profile to run, the questions are:

1. **Do I know what I'm dealing with yet?**
   - No → rapid_triage
   - Yes → continue

2. **What is the target?**
   - Workstation → endpoint_deep
   - Domain controller → domain_controller
   - Other server (IIS/Exchange/MSSQL/SharePoint/file server) → server_role
   - Server not in the above list → endpoint_deep (covers the basics)

3. **Special considerations:**
   - Suspected memory-resident malware → endpoint_deep (memory inspection
     included) plus possibly an external memory dump
   - Legal chain-of-custody required → use FTK Imager for full disk;
     SAFE provides the live evidence FTK can't
   - Multi-target deployment scenario → run rapid_triage on all targets
     first, then decide which need deeper collection

---

## Build Sequence and Timeline

1. **Now (May–June 2026):** endpoint_deep, starting with process_memory_inspection
   module. Add extended modules over multiple sessions.

2. **June–July 2026:** Complete endpoint_deep. Pilot internally on workstation
   cases.

3. **July–August 2026:** domain_controller profile. Highest risk piece due to
   AD complexity. Test against an isolated DC in a test forest.

4. **August–September 2026:** server_role profile. Build per-role modules in
   priority order: IIS first, then Exchange, MSSQL, SharePoint, File Server.

5. **September 2026:** Pilot release with all four profiles. Code signing
   completed. Two canary SSDs deployed.

This sequence is aggressive but achievable at the pace we've been working.
Slippage on server_role is the realistic risk; if August runs long, the
fallback is shipping v1.0 with three profiles (rapid_triage, endpoint_deep,
domain_controller) and tagging server_role as v1.1.