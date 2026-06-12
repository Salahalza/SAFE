package module

import "time"

// ProcessMemoryInspection is a COLLECT-ONLY per-process memory module.
//
// Design: docs/journal/2026-06-12e-pmi-design.md. The strategic decision to
// build native user-mode memory inspection (rather than bundle WinPmem or a
// kernel driver) is recorded in docs/DESIGN_QUESTIONS.md (2026-05-27).
//
// On the target it does exactly one thing: enumerate processes, walk each
// process's committed, private (non-image/non-mapped), executable-or-RWX
// memory regions, and copy those raw bytes to disk alongside a metadata index.
// It makes NO judgement about what is suspicious. RWX triage, strings, and
// PE-carving all happen LAB-SIDE in the process_memory analyzer. This keeps the
// module on the right side of architectural principle #1 (collection, not
// analysis): the region bytes ARE the artifact, exactly like the .evtx files in
// extended_event_channels.
//
// Region selection (committed + private + exec/RWX) is a protection-flag scope
// filter — the same kind of collection scoping as "only .evtx files" — not
// content interpretation. It targets injected / unbacked code, the IR-relevant
// majority, and excludes image-backed code (recoverable from disk).
//
// This is the loudest module SAFE ships. OpenProcess/ReadProcessMemory are
// exactly what EDR hooks to catch credential theft and injection scanning, so
// on a protected target some processes will be undumpable (PPL/protected/
// system) and the whole module may be flagged or blocked. That is expected, not
// a defect. Per-process denials are recorded as info, not errors. For this
// reason the module is OPT-IN ONLY — it lives in the dedicated memory_triage
// profile and in endpoint_deep, never in rapid_triage.
//
// Reporting follows the bulk pattern (principle #4): the two index files
// (processes.csv, regions.csv) are reported as primary artifacts; the raw
// region blobs under dumps/ are counted in result.BulkFiles and hashed
// individually by the manifest walker, not enumerated as separate findings.
type ProcessMemoryInspection struct{}

func (m *ProcessMemoryInspection) Name() string       { return "process_memory_inspection" }
func (m *ProcessMemoryInspection) Priority() Priority { return PriorityOptional }

// TimeBudget is generous: reading many processes' regions can be slow, and the
// server-headroom philosophy (see endpoint_deep) prefers room over trimming.
func (m *ProcessMemoryInspection) TimeBudget() time.Duration { return 30 * time.Minute }

// RequiresVSS is false: this reads live process memory, not locked disk files.
func (m *ProcessMemoryInspection) RequiresVSS() bool { return false }

func (m *ProcessMemoryInspection) Run(ctx *Context) Result {
	started := time.Now().UTC()
	result := Result{
		ModuleName: m.Name(),
		StartedAt:  started,
		Artifacts:  []Artifact{},
		Findings:   []Finding{},
		Errors:     []string{},
	}

	if !prepareOutputDir(&result, ctx.OutputDir, started) {
		return result
	}

	// The actual syscall work is platform-specific (see the _windows.go /
	// _other.go pair). On non-Windows it records an error and collects nothing,
	// so go build ./... stays green on the macOS dev host.
	runMemoryCollection(ctx, &result)

	finalize(&result, started, ctx.Ctx)
	return result
}
