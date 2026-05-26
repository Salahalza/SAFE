package preflight

import (
	"fmt"
	"runtime"
)

// OSCheck verifies the host operating system is supported by SAHM.
type OSCheck struct{}

func (c *OSCheck) Name() string { return "os_supported" }

func (c *OSCheck) Run() *Finding {
	if runtime.GOOS != "windows" {
		return &Finding{
			Check:    c.Name(),
			Severity: SeverityCritical,
			Message:  fmt.Sprintf("SAHM is designed to run on Windows targets (current OS: %s).", runtime.GOOS),
			Detail:   "SAHM modules collect Windows-specific forensic artifacts. Running on a non-Windows host produces empty or invalid collections.",
		}
	}
	// For now, all Windows hosts are accepted. In a future iteration we can
	// inspect build number, edition, and enforce the supported matrix.
	return nil
}
