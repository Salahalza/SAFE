package pathfinder

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"www.velocidex.com/golang/regparser"
)

// DiscoverUserProfilesFromHive enumerates user profiles from a SOFTWARE hive
// file taken from a mounted disk image, reading the ProfileList key that the
// live DiscoverUserProfiles reads from the running registry.
//
// It deliberately does NOT stat each profile path: those paths (C:\Users\name)
// belong to the imaged host, not the analyst's machine, so a live stat would be
// wrong. The caller maps each ProfilePath under the image root and handles
// absence per-file. Reuses regparser (already a dependency), so it builds on
// every platform.
func DiscoverUserProfilesFromHive(softwareHivePath string) ([]UserProfile, error) {
	f, err := os.Open(softwareHivePath)
	if err != nil {
		return nil, fmt.Errorf("open SOFTWARE hive: %w", err)
	}
	defer f.Close()

	reg, err := regparser.NewRegistry(f)
	if err != nil {
		return nil, fmt.Errorf("parse SOFTWARE hive: %w", err)
	}

	list := reg.OpenKey(`Microsoft\Windows NT\CurrentVersion\ProfileList`)
	if list == nil {
		return nil, fmt.Errorf("ProfileList key not found in SOFTWARE hive")
	}

	var profiles []UserProfile
	for _, sub := range list.Subkeys() {
		sid := sub.Name()
		if len(sid) < 2 || sid[0] != 'S' || sid[1] != '-' {
			continue
		}

		var profilePath string
		for _, v := range sub.Values() {
			if strings.EqualFold(v.ValueName(), "ProfileImagePath") {
				profilePath = strings.TrimRight(v.ValueData().String, "\x00")
				break
			}
		}
		if profilePath == "" {
			continue
		}
		profilePath = expandImageProfilePath(profilePath)

		profiles = append(profiles, UserProfile{
			SID:            sid,
			Username:       filepath.Base(profilePath),
			ProfilePath:    profilePath,
			AppDataRoaming: filepath.Join(profilePath, "AppData", "Roaming"),
			AppDataLocal:   filepath.Join(profilePath, "AppData", "Local"),
			IsBuiltin:      isBuiltinSID(sid),
		})
	}
	return profiles, nil
}

// expandImageProfilePath maps the %SystemDrive% token (the only env token that
// normally appears in a ProfileImagePath) to C:, the OS volume the image root
// represents. Human profiles are usually stored as a literal C:\Users\name and
// pass through unchanged. Other tokens are left intact for the caller to skip.
func expandImageProfilePath(p string) string {
	if strings.HasPrefix(strings.ToLower(p), "%systemdrive%") {
		return "C:" + p[len("%systemdrive%"):]
	}
	return p
}
