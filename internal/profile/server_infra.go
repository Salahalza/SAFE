package profile

import (
	"github.com/Salahalza/SAFE/internal/module"
	"time"
)

func ServerInfra() *Profile {
	return &Profile{
		Name:        "server_infra",
		Version:     "0.1.0",
		Description: "Targeted collection for Server Infrastructure (Active Directory, Exchange, IIS, SQL, File Server). Includes rapid triage, NTDS.dit, extended events, and role-specific artifacts.",
		Class:       ClassServer,
		TotalBudget: 45 * time.Minute,
		Modules: []module.Module{
			// Volatile data first (order of volatility principle).
			&module.ProcessSnapshot{},
			&module.NetworkSnapshot{},
			// Static/durable data next.
			&module.SystemMetadata{},
			&module.EventLogsCore{},
			&module.ExtendedEventChannels{},
			&module.RegistryCore{},
			&module.PersistenceCore{},
			// VSS-based collection of locked files.
			&module.NTFSMetadata{},
			&module.AmcacheCollection{},
			&module.UserHivesCollection{},
			&module.PrefetchCollection{},
			// Role specific collection modules. Each self-gates via Applies(),
			// so a module cleanly skips on a server that lacks its role — one
			// profile runs safely against a DC, an IIS box, an Exchange box, or
			// an unknown server triaged blind.
			&module.ADCollection{},
			&module.IISCollection{},
			&module.ExchangeCollection{},
			// TODO: Add a SQL collection module once there is a SQL host to
			// validate its role detector against (no-ship-blind rule).
		},
	}
}
