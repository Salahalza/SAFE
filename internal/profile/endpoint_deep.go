package profile

import (
	"safe/internal/module"
	"time"
)

// EndpointDeep is the deeper-collection profile for a Windows endpoint or
// server. It is a SUPERSET of rapid_triage: everything rapid_triage collects,
// plus the heavier Phase 2 "extended" modules that trade time for coverage.
//
// INTERIM (v0.1.0): only extended_event_channels is wired in so far. The full
// endpoint_deep composition — process_memory_inspection and extended_persistence
// — is fleshed out in roadmap session 2.6. Until then this profile exists to
// give the extended modules a reachable, VM-testable execution path.
//
// Order of volatility is preserved: the rapid_triage modules keep their order,
// and the extended bulk collection runs last alongside the other VSS-based,
// least-volatile, on-disk artifacts.
func EndpointDeep() *Profile {
	return &Profile{
		Name:        "endpoint_deep",
		Version:     "0.1.0",
		Description: "Deeper collection for a Windows endpoint or server. Superset of rapid_triage plus extended event channels. Collection only — parsing happens in lab via safe --analyze. (Interim: extended modules still being added.)",
		// rapid_triage budgets 15 min for its 9 modules; the full winevt\Logs
		// bulk copy can be multi-GB on servers, so allow generous headroom.
		// Tuned on the VM.
		TotalBudget: 45 * time.Minute,
		Modules: []module.Module{
			// Volatile data first (order of volatility principle).
			&module.ProcessSnapshot{},
			&module.NetworkSnapshot{},
			// Static/durable data next.
			&module.SystemMetadata{},
			&module.EventLogsCore{},
			&module.RegistryCore{},
			&module.PersistenceCore{},
			// VSS-based collection of locked files (least volatile, on-disk).
			&module.AmcacheCollection{},
			&module.UserHivesCollection{},
			&module.PrefetchCollection{},
			// Phase 2 extended bulk collection.
			&module.ExtendedEventChannels{},
		},
	}
}
