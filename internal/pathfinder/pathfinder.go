package pathfinder

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type UserProfile struct {
	SID            string `json:"sid"`
	Username       string `json:"username,omitempty"`
	ProfilePath    string `json:"profile_path"`
	AppDataRoaming string `json:"appdata_roaming"`
	AppDataLocal   string `json:"appdata_local"`
	IsBuiltin      bool   `json:"is_builtin"`
}

type EnvironmentPaths struct {
	SystemRoot      string `json:"system_root"`
	System32        string `json:"system32"`
	ProgramFiles    string `json:"program_files"`
	ProgramFilesX86 string `json:"program_files_x86,omitempty"`
	ProgramData     string `json:"program_data"`
	UserProfile     string `json:"user_profile"`
	Temp            string `json:"temp"`
}

func ResolveEnvironmentPaths() EnvironmentPaths {
	return EnvironmentPaths{
		SystemRoot:      os.Getenv("SystemRoot"),
		System32:        filepath.Join(os.Getenv("SystemRoot"), "System32"),
		ProgramFiles:    os.Getenv("ProgramFiles"),
		ProgramFilesX86: os.Getenv("ProgramFiles(x86)"),
		ProgramData:     os.Getenv("ProgramData"),
		UserProfile:     os.Getenv("USERPROFILE"),
		Temp:            os.Getenv("TEMP"),
	}
}

func (e EnvironmentPaths) Validate() []string {
	var missing []string
	if e.SystemRoot == "" {
		missing = append(missing, "SystemRoot")
	}
	if e.ProgramFiles == "" {
		missing = append(missing, "ProgramFiles")
	}
	if e.ProgramData == "" {
		missing = append(missing, "ProgramData")
	}
	if e.UserProfile == "" {
		missing = append(missing, "USERPROFILE")
	}
	return missing
}

func DiscoverUserProfiles() ([]UserProfile, error) {
	const profileListKey = `HKLM\Software\Microsoft\Windows NT\CurrentVersion\ProfileList`

	sids, err := listProfileSIDs(profileListKey)
	if err != nil {
		return nil, fmt.Errorf("enumerate ProfileList: %w", err)
	}

	profiles := make([]UserProfile, 0, len(sids))
	for _, sid := range sids {
		profilePath, err := readProfileImagePath(profileListKey, sid)
		if err != nil {
			continue
		}

		// ProfileImagePath in the registry often contains unexpanded environment
		// variables like %systemroot%. Expand them before any filesystem ops.
		profilePath = expandWindowsEnvVars(profilePath)

		builtin := isBuiltinSID(sid)

		if _, err := os.Stat(profilePath); err != nil {
			continue
		}

		profiles = append(profiles, UserProfile{
			SID:            sid,
			ProfilePath:    profilePath,
			AppDataRoaming: filepath.Join(profilePath, "AppData", "Roaming"),
			AppDataLocal:   filepath.Join(profilePath, "AppData", "Local"),
			IsBuiltin:      builtin,
		})
	}

	return profiles, nil
}

func isBuiltinSID(sid string) bool {
	builtinPrefixes := []string{
		"S-1-5-18",
		"S-1-5-19",
		"S-1-5-20",
	}
	for _, prefix := range builtinPrefixes {
		if strings.EqualFold(sid, prefix) {
			return true
		}
	}
	if strings.HasSuffix(sid, "-500") || strings.HasSuffix(sid, "-501") {
		return true
	}
	return false
}

// expandWindowsEnvVars replaces %VAR% style references with environment values.
// Case-insensitive variable name matching, to match Windows behavior.
// Unknown variables are left as-is.
func expandWindowsEnvVars(s string) string {
	for {
		start := strings.Index(s, "%")
		if start < 0 {
			break
		}
		end := strings.Index(s[start+1:], "%")
		if end < 0 {
			break
		}
		end += start + 1

		varName := s[start+1 : end]
		value := getEnvCaseInsensitive(varName)
		if value == "" {
			// Unknown variable — keep it in place by replacing % with a
			// marker, then restoring after the loop to avoid infinite recursion.
			s = s[:start] + "\x00" + varName + "\x00" + s[end+1:]
			continue
		}
		s = s[:start] + value + s[end+1:]
	}
	s = strings.ReplaceAll(s, "\x00", "%")
	return s
}

// getEnvCaseInsensitive returns env var value with case-insensitive name match.
func getEnvCaseInsensitive(name string) string {
	upperName := strings.ToUpper(name)
	for _, kv := range os.Environ() {
		eq := strings.Index(kv, "=")
		if eq < 0 {
			continue
		}
		if strings.ToUpper(kv[:eq]) == upperName {
			return kv[eq+1:]
		}
	}
	return ""
}
