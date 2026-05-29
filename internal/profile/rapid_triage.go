package profile

import (
	"sahm/internal/module"
	"time"
)

func RapidTriage() *Profile {
	return &Profile{
		Name:        "rapid_triage",
		Version:     "0.1.2",
		Description: "Fast first-touch assessment of a Windows endpoint or server.",
		TotalBudget: 15 * time.Minute,
		Modules: []module.Module{
			&module.SystemMetadata{},
			&module.ProcessSnapshot{},
			&module.NetworkSnapshot{},
			&module.EventLogsCore{},
			&module.RegistryCore{},
			&module.PersistenceCore{},
			&module.AmcacheCollection{},
			&module.UserHivesCollection{},
		},
	}
}
