//go:build !windows

package pathfinder

import "fmt"

// listProfileSIDs is not implemented on non-Windows platforms.
func listProfileSIDs(profileListKey string) ([]string, error) {
	return nil, fmt.Errorf("pathfinder is Windows-only")
}

// readProfileImagePath is not implemented on non-Windows platforms.
func readProfileImagePath(profileListKey, sid string) (string, error) {
	return "", fmt.Errorf("pathfinder is Windows-only")
}
