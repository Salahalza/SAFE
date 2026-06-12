package profile

import (
	"safe/internal/module"
	"time"
)

// MemoryTriage is the dedicated, explicitly LOUD profile for capturing
// per-process memory. It exists so an operator can choose memory collection as
// a deliberate, focused act — separate from the broader endpoint_deep sweep —
// fully aware that it is EDR-visible.
//
// It runs the minimum needed: process_snapshot to ground the process list
// (so the dumped PIDs can be correlated to names, parents, and command lines),
// immediately followed by the collect-only process_memory_inspection module.
//
// process_memory_inspection reads process memory via OpenProcess /
// ReadProcessMemory — the exact behaviour EDR hooks to catch credential theft
// and injection scanning. On a protected target it may be flagged or blocked,
// and protected/PPL/system processes will be undumpable. That is expected. PMI
// is NEVER part of rapid_triage; it is opt-in here and in endpoint_deep only.
func MemoryTriage() *Profile {
	return &Profile{
		Name:    "memory_triage",
		Version: "0.1.0",
		Description: "LOUD, EDR-visible: per-process memory capture. Reads process memory via OpenProcess/ReadProcessMemory and will likely be flagged by AV/EDR. Collection only — strings/PE-carve/RWX triage happen in lab via safe --analyze.",
		// process_snapshot is seconds; process_memory_inspection budgets 30 min.
		// Allow headroom on top, in keeping with the server-headroom philosophy.
		TotalBudget: 35 * time.Minute,
		Modules: []module.Module{
			// Ground the process list first, then dump memory (most volatile).
			&module.ProcessSnapshot{},
			&module.ProcessMemoryInspection{},
		},
	}
}
