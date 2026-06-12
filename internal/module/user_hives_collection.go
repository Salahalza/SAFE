package module

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"safe/internal/pathfinder"
)

type UserHivesCollection struct{}

func (m *UserHivesCollection) Name() string              { return "user_hives_collection" }
func (m *UserHivesCollection) Priority() Priority        { return PriorityHigh }
func (m *UserHivesCollection) TimeBudget() time.Duration { return 3 * time.Minute }
func (m *UserHivesCollection) RequiresVSS() bool         { return true }

// Run collects per-user registry hives (NTUSER.DAT and UsrClass.dat) plus
// their transaction logs for every human user profile on the system.
//
// These hives contain forensically valuable user-activity artifacts:
//   - NTUSER.DAT: UserAssist (program execution by user), RecentDocs, TypedURLs,
//     RunMRU, Office MRU, ShellBags (NTUSER variant), per-user Run keys
//   - UsrClass.dat: ShellBags (UsrClass variant), per-user file associations,
//     additional shell activity records
//
// Built-in system profiles (LocalSystem, LocalService, NetworkService) are
// skipped because they have minimal forensic value for user-activity analysis.
func (m *UserHivesCollection) Run(ctx *Context) Result {
	started := time.Now().UTC()
	result := Result{
		ModuleName: m.Name(),
		StartedAt:  started,
		Artifacts:  []Artifact{},
		Findings:   []Finding{},
		Errors:     []string{},
	}

	if !prepareOutputDir(&result, ctx.OutputDir, started) {
		return result
	}

	if ctx.Shadow == nil {
		result.AddWarning("vss", "no shadow copy available; module should have been skipped by engine")
		result.Errors = append(result.Errors, "no shadow available")
		finalize(&result, started, ctx.Ctx)
		return result
	}

	// Discover all user profiles on the system.
	profiles, err := pathfinder.DiscoverUserProfiles()
	if err != nil {
		result.AddWarning("user_discovery",
			fmt.Sprintf("could not enumerate user profiles: %v", err))
		result.Errors = append(result.Errors, fmt.Sprintf("discover profiles: %v", err))
		finalize(&result, started, ctx.Ctx)
		return result
	}

	humanCount := 0
	skippedBuiltin := 0
	profilesWithHives := 0

	for _, p := range profiles {
		if p.IsBuiltin {
			skippedBuiltin++
			continue
		}
		humanCount++

		// Translate the live profile path (e.g., C:\Users\win11test) to the
		// shadow-mounted path (e.g., C:\safe_shadow_XXX\Users\win11test).
		shadowProfilePath, err := mapToShadowPath(p.ProfilePath, ctx.Shadow.MountedPath)
		if err != nil {
			result.AddWarning(p.Username,
				fmt.Sprintf("could not map profile path to shadow: %v", err))
			result.Errors = append(result.Errors,
				fmt.Sprintf("%s: shadow path mapping: %v", p.SID, err))
			continue
		}

		// Determine a safe directory name for this user inside the output folder.
		// Username might be empty or contain non-ASCII; use SID as fallback.
		userDirName := sanitizeForDirName(p.Username)
		if userDirName == "" {
			userDirName = p.SID
		}
		userOutputDir := filepath.Join(ctx.OutputDir, userDirName)
		if err := os.MkdirAll(userOutputDir, 0o755); err != nil {
			result.AddWarning(p.Username,
				fmt.Sprintf("could not create per-user output dir: %v", err))
			result.Errors = append(result.Errors,
				fmt.Sprintf("%s: mkdir: %v", p.SID, err))
			continue
		}

		// Collect this user's hives.
		collected := collectUserHives(&result, shadowProfilePath, userOutputDir, p)
		if collected > 0 {
			profilesWithHives++
		}
	}

	// Summary findings.
	if humanCount == 0 {
		result.AddWarning("user_hives_collection",
			"no human user profiles found on the system")
	} else {
		result.AddInfo("user_hives_collection",
			fmt.Sprintf("processed %d human profile(s) (%d with hives collected), skipped %d built-in",
				humanCount, profilesWithHives, skippedBuiltin))
	}

	finalize(&result, started, ctx.Ctx)
	return result
}

// collectUserHives copies NTUSER.DAT and UsrClass.dat plus their transaction
// logs from the shadow into the user's output directory. Returns the count of
// successfully collected files (0-6, since each main hive has up to 2 LOG files).
func collectUserHives(result *Result, shadowProfilePath, userOutputDir string, p pathfinder.UserProfile) int {
	// NTUSER.DAT and its transaction logs live directly in the profile root.
	ntuserFiles := []string{
		"NTUSER.DAT",
		"NTUSER.DAT.LOG1",
		"NTUSER.DAT.LOG2",
	}

	// UsrClass.dat lives in AppData\Local\Microsoft\Windows.
	usrclassDir := filepath.Join("AppData", "Local", "Microsoft", "Windows")
	usrclassFiles := []string{
		"UsrClass.dat",
		"UsrClass.dat.LOG1",
		"UsrClass.dat.LOG2",
	}

	collected := 0

	// NTUSER.DAT files.
	for _, name := range ntuserFiles {
		srcPath := filepath.Join(shadowProfilePath, name)
		dstPath := filepath.Join(userOutputDir, name)

		// Original (live) path for the manifest.
		originalPath := filepath.Join(p.ProfilePath, name)

		if collectOneHiveFile(result, srcPath, dstPath, originalPath, name, p.Username) {
			collected++
		}
	}

	// UsrClass.dat files.
	for _, name := range usrclassFiles {
		srcPath := filepath.Join(shadowProfilePath, usrclassDir, name)
		dstPath := filepath.Join(userOutputDir, name)
		originalPath := filepath.Join(p.ProfilePath, usrclassDir, name)

		if collectOneHiveFile(result, srcPath, dstPath, originalPath, name, p.Username) {
			collected++
		}
	}

	return collected
}

// collectOneHiveFile copies a single hive file. Missing LOG files are not
// errors (they're optional). Missing main hives are warnings. Returns true
// if the file was successfully collected.
func collectOneHiveFile(result *Result, srcPath, dstPath, originalPath, name, username string) bool {
	info, err := os.Stat(srcPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Main hive files (without .LOG suffix) being missing is significant.
			// LOG files being missing is normal.
			isMainHive := !strings.HasSuffix(strings.ToUpper(name), ".LOG1") &&
				!strings.HasSuffix(strings.ToUpper(name), ".LOG2")
			if isMainHive {
				result.AddWarning(fmt.Sprintf("%s/%s", username, name),
					"main hive file not found in shadow — user profile may be inactive or path non-standard")
			}
			// Silently skip missing LOG files.
			return false
		}
		result.AddWarning(fmt.Sprintf("%s/%s", username, name),
			fmt.Sprintf("stat failed: %v", err))
		result.Errors = append(result.Errors,
			fmt.Sprintf("%s/%s stat: %v", username, name, err))
		return false
	}

	if err := copyFile(srcPath, dstPath); err != nil {
		result.AddWarning(fmt.Sprintf("%s/%s", username, name),
			fmt.Sprintf("copy failed: %v", err))
		result.Errors = append(result.Errors,
			fmt.Sprintf("%s/%s copy: %v", username, name, err))
		return false
	}

	artifact, err := describeArtifact(dstPath)
	if err != nil {
		result.AddWarning(fmt.Sprintf("%s/%s", username, name),
			fmt.Sprintf("hash failed: %v", err))
		result.Errors = append(result.Errors,
			fmt.Sprintf("%s/%s hash: %v", username, name, err))
		return false
	}

	artifact.SourcePath = originalPath
	artifact.SourceSize = info.Size()
	result.Artifacts = append(result.Artifacts, artifact)
	return true
}

// mapToShadowPath translates a live filesystem path to its equivalent in the
// mounted shadow. For example:
//
//	live:   C:\Users\win11test
//	shadow: C:\safe_shadow_<timestamp>\Users\win11test
//
// Returns an error if the live path does not start with C:\ (we only shadow C:).
func mapToShadowPath(livePath, shadowMountPath string) (string, error) {
	// Normalize separators and case for the prefix check.
	upper := strings.ToUpper(livePath)
	if !strings.HasPrefix(upper, `C:\`) {
		return "", fmt.Errorf("path does not start with C:\\: %s", livePath)
	}
	// Strip the C:\ prefix and join with the shadow mount.
	relative := livePath[len(`C:\`):]
	return filepath.Join(shadowMountPath, relative), nil
}

// sanitizeForDirName makes a username safe for use as a directory name.
// Replaces filesystem-unsafe characters with underscores. Preserves Unicode.
func sanitizeForDirName(name string) string {
	if name == "" {
		return ""
	}
	unsafe := []rune{'\\', '/', ':', '*', '?', '"', '<', '>', '|'}
	result := []rune(name)
	for i, r := range result {
		for _, u := range unsafe {
			if r == u {
				result[i] = '_'
				break
			}
		}
	}
	return string(result)
}
