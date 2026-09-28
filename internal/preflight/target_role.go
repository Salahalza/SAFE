package preflight

import (
	"strings"

	"github.com/Salahalza/SAFE/internal/roles"
)

// TargetRoleCheck detects server roles and warns when a server-role target is
// about to be collected with a profile that isn't meant for a server.
type TargetRoleCheck struct {
	// ProfileClass is the class of the profile the analyst selected
	// ("server", "workstation", "any", or ""). A server role paired with a
	// non-server, non-any profile produces a warning: role-specific artifacts
	// (NTDS.dit, SYSVOL, ...) would not be collected.
	ProfileClass string
}

func (c *TargetRoleCheck) Name() string {
	return "target_role"
}

func (c *TargetRoleCheck) Run() *Finding {
	detected := roles.Detect()
	if len(detected) == 0 {
		return nil // No specialized roles detected, nothing to report.
	}

	names := make([]string, 0, len(detected))
	for _, r := range detected {
		names = append(names, string(r))
	}
	roleStr := strings.Join(names, ", ")

	// A server-class profile (or a universal "any" profile) is appropriate for
	// a server role. Anything else means the analyst likely picked the wrong
	// profile for this target and will miss role-specific artifacts.
	if c.ProfileClass != profileClassServer && c.ProfileClass != profileClassAny {
		return &Finding{
			Check:    c.Name(),
			Severity: SeverityWarning,
			Message:  "Target has server role(s) but a server-class profile was not selected; role-specific artifacts (e.g. NTDS.dit, SYSVOL) will not be collected. Consider the server_infra profile.",
			Detail:   "Detected roles: " + roleStr,
		}
	}

	return &Finding{
		Check:    c.Name(),
		Severity: SeverityInfo,
		Message:  "Server role(s) detected; a server-appropriate profile is selected.",
		Detail:   "Detected roles: " + roleStr,
	}
}

// Local copies of the profile class values, kept as untyped constants here so
// this package does not import internal/profile (which imports internal/module)
// just to compare two strings. They must stay in sync with profile.Class*.
const (
	profileClassServer = "server"
	profileClassAny    = "any"
)
