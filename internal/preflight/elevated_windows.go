//go:build windows

package preflight

import "os"

// isElevated returns true if the current process has administrator rights.
// On Windows, we check by attempting to open \\.\PHYSICALDRIVE0 — an
// admin-only resource.
func isElevated() bool {
	f, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}
