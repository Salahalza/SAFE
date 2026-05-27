//go:build windows

package pathfinder

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"
)

// listProfileSIDs returns all subkey names (SIDs) under the given ProfileList key.
func listProfileSIDs(profileListKey string) ([]string, error) {
	cmd := exec.Command("reg", "query", profileListKey)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("reg query failed: %v (output: %s)", err, string(out))
	}

	var sids []string
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Subkeys appear as full paths: HKEY_LOCAL_MACHINE\...\ProfileList\S-1-5-21-...
		// We extract just the trailing component after the last backslash.
		if !strings.Contains(line, "\\") {
			continue
		}
		if !strings.HasPrefix(strings.ToUpper(line), "HKEY_LOCAL_MACHINE") {
			continue
		}
		idx := strings.LastIndex(line, "\\")
		if idx < 0 {
			continue
		}
		sid := line[idx+1:]
		// Only keep things that look like SIDs (start with "S-").
		if strings.HasPrefix(sid, "S-") {
			sids = append(sids, sid)
		}
	}
	return sids, nil
}

// readProfileImagePath returns the ProfileImagePath value for a given SID.
func readProfileImagePath(profileListKey, sid string) (string, error) {
	fullKey := profileListKey + `\` + sid
	cmd := exec.Command("reg", "query", fullKey, "/v", "ProfileImagePath")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("reg query failed: %v", err)
	}

	// Output looks like:
	//
	// HKEY_LOCAL_MACHINE\...\ProfileList\S-1-5-21-...
	//     ProfileImagePath    REG_EXPAND_SZ    C:\Users\Administrator
	//
	// We find the line containing "ProfileImagePath" and extract the path.
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "ProfileImagePath") {
			continue
		}
		// Split on whitespace runs; the path is the last token, but may contain spaces.
		// Better approach: find the type indicator (REG_EXPAND_SZ or REG_SZ) and take
		// everything after it.
		typeIdx := strings.Index(line, "REG_")
		if typeIdx < 0 {
			continue
		}
		// Skip past the type token by finding the next whitespace.
		rest := line[typeIdx:]
		spaceIdx := strings.Index(rest, " ")
		if spaceIdx < 0 {
			continue
		}
		path := strings.TrimSpace(rest[spaceIdx:])
		// Expand %SystemDrive% etc. if needed. For now, return as-is — most
		// systems have already expanded these.
		return path, nil
	}

	return "", fmt.Errorf("ProfileImagePath not found in output: %s", string(out))
}
