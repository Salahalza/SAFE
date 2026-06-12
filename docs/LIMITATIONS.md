# SAFE Known Limitations

This document tracks capabilities SAFE does not currently provide, and the
rationale for each gap. It is updated as scope decisions are made.

The purpose is honesty: SAFE is a focused tool, not a complete forensic suite.
Knowing what SAFE does NOT do is as important as knowing what it does.

---

## Full Physical Memory Acquisition

**Status:** Not implemented. Out of scope for v1.0.

**Rationale:** Acquiring full physical memory (RAM) requires a kernel-mode
driver. Writing, signing, and maintaining a kernel driver is a specialist
multi-year effort with significant compatibility, signing, and stability risk.
Bundling third-party tools (WinPmem, Magnet RAM Capture, etc.) was considered
and deferred pending review of organizational policy on third-party software.

**What SAFE provides instead:** SAFE v1.0 includes per-process memory
inspection (see `process_memory_inspection` module), which covers the majority
of IR scenarios involving memory analysis without requiring kernel access.

**For cases requiring full memory acquisition:** Run WinPmem, Magnet RAM
Capture, or FTK Imager separately, in parallel with SAFE. SAFE's case folder
can hold the resulting dump alongside its own artifacts — copy the dump into
the case folder and re-run `safe --verify` to include it in the manifest.

**What we lose by not having it:**
- Detection of kernel-mode rootkits
- Recovery of decryption keys held only in kernel memory
- Analysis of malware that runs entirely in non-paged kernel pool
- Memory of protected processes (LSASS in newer Windows, AV processes, PPL)

**What we keep:** Per-process memory inspection covers approximately 80% of
real-world IR cases involving memory analysis, in our assessment.

---

## Kernel-Mode Forensics

**Status:** Not implemented. Out of scope indefinitely.

**Rationale:** Kernel-mode analysis (SSDT inspection, IDT inspection, kernel
callback enumeration, driver list integrity) requires the same kernel-mode
driver as full memory acquisition. Same deferral applies.

**For cases requiring this:** Use Volatility or Rekall on a memory dump
acquired with the tools mentioned above.

---

## Third-Party Tool Adapters (KAPE, DFIR-ORC)

**Status:** Removed from roadmap. Out of scope.

**Rationale:** SAFE is built as a self-contained tool with no third-party
binary dependencies. KAPE and DFIR-ORC functionality is partially replicated
by SAFE's native modules in endpoint_deep, domain_controller, and server_role
profiles. For full $MFT and USN journal extraction, see DESIGN_QUESTIONS.md
for the planned native Go implementation.

---

## Network-Based Collection

**Status:** Not implemented. Not planned.

**Rationale:** SAFE is offline-first, designed for physical presence at the
target. Network-based collection (remote PowerShell, WinRM, agent-based) is a
different operational model better served by other tools.

---

## Memory-Only Threats Without Disk Artifacts

**Status:** Partially addressed by `process_memory_inspection` module.

**Rationale:** Threats that exist entirely in memory and never write to disk
require memory-based detection. SAFE's per-process inspection catches most
such threats running in user-mode. Kernel-only memory-resident threats remain
out of scope per the kernel-mode limitation above.

---

## Cloud Forensics

**Status:** Not implemented. Not planned for v1.

**Rationale:** Cloud workload forensics (AWS, Azure, GCP) is a fundamentally
different domain from endpoint forensics. SAFE targets physical Windows
endpoints and servers.

---

## Mobile Forensics

**Status:** Not implemented. Not planned.

**Rationale:** Out of scope. SAFE is Windows-only.

---

## Linux and macOS Targets

**Status:** Not implemented. Not planned for v1.

**Rationale:** SAFE is Windows-focused. Cross-platform support would require
re-architecting the collection modules entirely. Considered for future major
versions if operational need emerges.

---


## Full Disk Imaging

**Status:** Not implemented. Not planned.

**Rationale:** Full disk imaging is well-served by existing tools (FTK Imager,
Magnet AXIOM, dd) that have established legal acceptance and forensic
community trust. SAFE does not attempt to replicate this. SAFE's value is in
acquiring evidence those tools cannot easily get — live process state, current
network connections, fresh memory inspection — not in duplicating disk imaging.

**For cases requiring full disk image:** Use existing imaging tools. SAFE
output can be stored alongside the disk image in the same case folder.


## Antivirus interaction

SAFE performs forensic operations that resemble suspicious behavior to
heuristic AV engines: registry hive copies, VSS shadow creation, process
enumeration, persistence location enumeration. This is unavoidable —
the same behaviors that make SAFE useful for IR also trigger AV ML models.

Observed false-positive detections on Microsoft Defender ML:
- `Program:Win32/Contebrew.A!ml` — category "Settings Modifier".
- `Trojan:Win32/Bearfoos.A!ml` — category "Trojan", alert level Severe.
  First seen 2026-06-12 after the `extended_persistence` module landed. Its
  rapid `reg query` enumeration of BAM, services, LSA, and other ASEPs is
  behaviorally identical to malware reconnaissance, which escalates the ML
  verdict from "Settings Modifier" to "Trojan". Still a false positive (it
  is SAFE's own collection logic) — just a louder one.

Both are false positives. The flagged collection still completes and the
case output verifies cleanly: a flagged `endpoint_deep` run on 2026-06-12
produced 635 files, all hashes matching `safe --verify`.

Deployment recommendations:
- Add SAFE's installation path to AV exclusions before use.
- For long-term deployment, sign safe.exe with an authenticode certificate
  (planned Phase 12).

Do NOT submit safe.exe or its source to VirusTotal, Microsoft, AV vendors,
or any other third-party service for analysis or whitelisting. SAFE is kept
fully isolated from the internet except its own private GitHub repository —
see the operational-security rule in CLAUDE.md. Any whitelisting, if ever
pursued, happens only through channels the project owner explicitly
controls; the binary and source are never uploaded to a public or
third-party scanner.