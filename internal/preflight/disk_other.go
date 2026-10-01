//go:build !windows

package preflight

import "syscall"

// diskFreeBytes returns free bytes available on the volume containing path.
// Uses statfs on Unix-like systems.
func diskFreeBytes(path string) (uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, err
	}
	return stat.Bavail * uint64(stat.Bsize), nil
}
