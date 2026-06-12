package preflight

// AdminCheck verifies the process is running with administrator privileges.
type AdminCheck struct{}

func (c *AdminCheck) Name() string { return "admin_privileges" }

func (c *AdminCheck) Run() *Finding {
	if isElevated() {
		return nil // all good
	}
	return &Finding{
		Check:    c.Name(),
		Severity: SeverityCritical,
		Message:  "SAFE is not running as administrator.",
		Detail:   "Several modules (registry_core, parts of eventlogs_core, parts of network_snapshot) require administrator privileges. Without elevation, collection will be significantly degraded.",
	}
}
