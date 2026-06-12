package profile

import (
	"safe/internal/module"
	"time"
)

func RapidTriage() *Profile {
	return &Profile{
		Name:        "rapid_triage",
		Version:     "0.2.0",
		Description: "Fast first-touch assessment of a Windows endpoint or server. Collection only — parsing happens in lab via safe --analyze.",
		TotalBudget: 15 * time.Minute,
		Modules: []module.Module{
			// Volatile data first (order of volatility principle).
			&module.ProcessSnapshot{},
			&module.NetworkSnapshot{},
			// Static/durable data next.
			&module.SystemMetadata{},
			&module.EventLogsCore{},
			&module.RegistryCore{},
			&module.PersistenceCore{},
			// VSS-based collection of locked files.
			&module.AmcacheCollection{},
			&module.UserHivesCollection{},
			&module.PrefetchCollection{},
		},
	}
}
