//go:build !windows

package module

import "os"

// checkAdminPrivilege returns true if running as root on Unix-like systems.
// This file is built on non-Windows platforms only.
func checkAdminPrivilege() bool {
	return os.Geteuid() == 0
}
