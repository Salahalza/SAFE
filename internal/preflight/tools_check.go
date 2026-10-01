package preflight

import (
	"fmt"
	"os/exec"
	"strings"
)

// ToolsCheck verifies that the external tools SAFE modules depend on
// are reachable on the target system's PATH.
type ToolsCheck struct {
	// Tools is the list of tool names to check.
	// If empty, defaults to the standard set used by the rapid_triage profile.
	Tools []string
}

func (c *ToolsCheck) Name() string { return "external_tools" }

// DefaultRapidTriageTools is the set of executables rapid_triage depends on.
var DefaultRapidTriageTools = []string{
	"powershell",
	"wevtutil",
	"reg",
	"schtasks",
	"sc",
	"netstat",
	"arp",
	"route",
	"ipconfig",
	"tasklist",
	"whoami",
	"hostname",
	"systeminfo",
}

func (c *ToolsCheck) Run() *Finding {
	tools := c.Tools
	if len(tools) == 0 {
		tools = DefaultRapidTriageTools
	}

	var missing []string
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			missing = append(missing, tool)
		}
	}

	if len(missing) == 0 {
		return nil
	}

	// Distinguish "all tools missing" (probably wrong OS) from "some missing"
	// (specific tools unavailable).
	if len(missing) == len(tools) {
		return &Finding{
			Check:    c.Name(),
			Severity: SeverityCritical,
			Message:  "None of the required external tools were found on PATH.",
			Detail:   "This usually means SAFE is running on a non-Windows host, or the tools have been removed from the system.",
		}
	}

	return &Finding{
		Check:    c.Name(),
		Severity: SeverityCritical,
		Message:  fmt.Sprintf("%d required tool(s) not found on PATH: %s", len(missing), strings.Join(missing, ", ")),
		Detail:   "Modules that depend on missing tools will fail or produce incomplete output.",
	}
}
