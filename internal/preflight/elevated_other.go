//go:build !windows

package preflight

import "os"

// isElevated returns true if running as root on non-Windows.
// This file is built on non-Windows platforms only.
func isElevated() bool {
	return os.Geteuid() == 0
}
