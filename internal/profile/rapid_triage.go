package profile

import (
	"time"

	"acquira/internal/module"
)

// RapidTriage returns the rapid_triage profile definition.
// Goal: fast first-touch assessment. Target runtime under 10 minutes
// on a healthy machine, 15 minute hard ceiling.
func RapidTriage() *Profile {
	return &Profile{
		Name:        "rapid_triage",
		Description: "Fast first-touch assessment of a Windows endpoint or server.",
		Version:     "0.1.0",
		TotalBudget: 15 * time.Minute,
		Modules: []module.Module{
			&module.SystemMetadata{},
			&module.ProcessSnapshot{},
			&module.NetworkSnapshot{},
			&module.EventLogsCore{},
			&module.RegistryCore{},
			&module.PersistenceCore{},
		},
	}
}
