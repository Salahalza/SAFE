# SAHM Known Limitations

This document tracks capabilities SAHM does not currently provide, and the
rationale for each gap. It is updated as scope decisions are made.

The purpose is honesty: SAHM is a focused tool, not a complete forensic suite.
Knowing what SAHM does NOT do is as important as knowing what it does.

---

## Full Physical Memory Acquisition

**Status:** Not implemented. Out of scope for v1.0.

**Rationale:** Acquiring full physical memory (RAM) requires a kernel-mode
driver. Writing, signing, and maintaining a kernel driver is a specialist
multi-year effort with significant compatibility, signing, and stability risk.
Bundling third-party tools (WinPmem, Magnet RAM Capture, etc.) was considered
and deferred pending review of organizational policy on third-party software.

**What SAHM provides instead:** SAHM v1.0 includes per-process memory
inspection (see `process_memory_inspection` module), which covers the majority
of IR scenarios involving memory analysis without requiring kernel access.

**For cases requiring full memory acquisition:** Run WinPmem, Magnet RAM
Capture, or FTK Imager separately, in parallel with SAHM. SAHM's case folder
can hold the resulting dump alongside its own artifacts — copy the dump into
the case folder and re-run `sahm --verify` to include it in the manifest.

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

**Status:** Considered for v1. Deferred pending organizational review.

**Rationale:** KAPE and DFIR-ORC are widely-used IR collection tools with
established workflows in our industry. Wrapping them would extend SAHM's
collection coverage significantly. However, this conflicts with the design
preference to keep SAHM self-contained and avoid third-party dependencies.

**Decision pending:** Pilot deployment may proceed without these adapters.
If specific cases reveal a need, this decision will be revisited.

---

## Network-Based Collection

**Status:** Not implemented. Not planned.

**Rationale:** SAHM is offline-first, designed for physical presence at the
target. Network-based collection (remote PowerShell, WinRM, agent-based) is a
different operational model better served by other tools.

---

## Memory-Only Threats Without Disk Artifacts

**Status:** Partially addressed by `process_memory_inspection` module.

**Rationale:** Threats that exist entirely in memory and never write to disk
require memory-based detection. SAHM's per-process inspection catches most
such threats running in user-mode. Kernel-only memory-resident threats remain
out of scope per the kernel-mode limitation above.

---

## Cloud Forensics

**Status:** Not implemented. Not planned for v1.

**Rationale:** Cloud workload forensics (AWS, Azure, GCP) is a fundamentally
different domain from endpoint forensics. SAHM targets physical Windows
endpoints and servers.

---

## Mobile Forensics

**Status:** Not implemented. Not planned.

**Rationale:** Out of scope. SAHM is Windows-only.

---

## Linux and macOS Targets

**Status:** Not implemented. Not planned for v1.

**Rationale:** SAHM is Windows-focused. Cross-platform support would require
re-architecting the collection modules entirely. Considered for future major
versions if operational need emerges.