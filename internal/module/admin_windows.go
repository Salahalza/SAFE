//go:build windows

package module

import (
	"os"
)

// checkAdminPrivilege returns true if the current process can open
// a handle to a privileged resource. On Windows, opening
// \\.\PHYSICALDRIVE0 requires administrator rights.
func checkAdminPrivilege() bool {
	f, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}
