package profile

import (
	"safe/internal/module"
	"time"
)

// EndpointDeep is the deeper-collection profile for a Windows endpoint or
// server. It is a SUPERSET of rapid_triage: everything rapid_triage collects,
// plus the heavier Phase 2 "extended" modules that trade time for coverage.
//
// v0.3.0: extended_persistence, extended_event_channels, and the collect-only
// process_memory_inspection module are all wired in. PMI makes this profile
// EDR-visible (it reads process memory via OpenProcess/ReadProcessMemory) — an
// operator who wants the quiet sweep without memory should use rapid_triage.
//
// Order of volatility is preserved: process memory is the most volatile artifact
// of all, so process_memory_inspection runs immediately after process_snapshot
// (which grounds the PID list) and before everything else. extended_persistence
// runs with the static registry/persistence tier (it is live reg-query
// collection, same volatility as persistence_core), and the extended
// event-channel bulk copy runs last alongside the other VSS-based,
// least-volatile, on-disk artifacts.
func EndpointDeep() *Profile {
	return &Profile{
		Name:        "endpoint_deep",
		Version:     "0.3.0",
		Description: "Deeper collection for a Windows endpoint or server. Superset of rapid_triage plus per-process memory, extended persistence, and event channels. EDR-visible: reads process memory. Collection only — parsing happens in lab via safe --analyze.",
		// rapid_triage budgets 15 min; the full winevt\Logs bulk copy can be
		// multi-GB on servers and process_memory_inspection budgets 30 min, so
		// allow generous headroom. Tuned on the VM.
		TotalBudget: 75 * time.Minute,
		Modules: []module.Module{
			// Volatile data first (order of volatility principle). Process
			// memory is the most volatile artifact, captured right after the
			// process list that names the PIDs it dumps.
			&module.ProcessSnapshot{},
			&module.ProcessMemoryInspection{},
			&module.NetworkSnapshot{},
			// Static/durable data next.
			&module.SystemMetadata{},
			&module.EventLogsCore{},
			&module.RegistryCore{},
			&module.PersistenceCore{},
			&module.ExtendedPersistence{},
			// VSS-based collection of locked files (least volatile, on-disk).
			&module.AmcacheCollection{},
			&module.UserHivesCollection{},
			&module.PrefetchCollection{},
			// Phase 2 extended bulk collection.
			&module.ExtendedEventChannels{},
		},
	}
}
