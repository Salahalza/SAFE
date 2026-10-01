package module

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Salahalza/SAFE/internal/pathfinder"
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

	if ctx.Root == "" {
		result.AddWarning("root", "no evidence root available; module should have been skipped by engine")
		result.Errors = append(result.Errors, "no evidence root available")
		finalize(&result, started, ctx.Ctx)
		return result
	}

	// Discover all user profiles from the correct source (live registry, or the
	// image's SOFTWARE hive for a disk-image case).
	profiles, err := discoverProfiles(ctx)
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

	for i, p := range profiles {
		if ctx.Ctx.Err() != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("user-hive collection cancelled: %v", ctx.Ctx.Err()))
			break
		}
		// Report intra-module progress per profile (bytes = hives collected so
		// far). Hives are recorded as artifacts, so their sizes sum the volume.
		var uhBytes int64
		for _, a := range result.Artifacts {
			uhBytes += a.Size
		}
		ctx.ReportProgress(i, len(profiles), uhBytes)

		if p.IsBuiltin {
			skippedBuiltin++
			continue
		}
		humanCount++

		// Translate the target profile path (e.g., C:\Users\win11test) to its
		// location under the evidence root (e.g., C:\safe_shadow_XXX\Users\win11test
		// for a live shadow, or E:\Users\win11test for a mounted image).
		rootProfilePath, err := mapToRoot(p.ProfilePath, ctx.Root)
		if err != nil {
			result.AddWarning(p.Username,
				fmt.Sprintf("could not map profile path to evidence root: %v", err))
			result.Errors = append(result.Errors,
				fmt.Sprintf("%s: root path mapping: %v", p.SID, err))
			continue
		}

		// The per-user output directory is named by SID, NOT username. The SID is
		// the canonical, collision-free identifier, and — critically — the
		// lab-side analyzers (UserAssist, COM-hijack) read each subdirectory name
		// back AS the SID for attribution (e.g. "<SID>_userassist.csv"). Naming
		// the dir by username would silently break that attribution. Username is
		// populated only for human-readable finding/error text.
		userDirName := sanitizeForDirName(p.SID)
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
		collected := collectUserHives(ctx, &result, rootProfilePath, userOutputDir, p)
		if collected > 0 {
			profilesWithHives++
		}
	}
	var uhBytesFinal int64
	for _, a := range result.Artifacts {
		uhBytesFinal += a.Size
	}
	ctx.ReportProgress(len(profiles), len(profiles), uhBytesFinal)

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
// logs from the evidence root into the user's output directory. Returns the
// count of successfully collected files (0-6, since each main hive has up to 2
// LOG files).
func collectUserHives(ctx *Context, result *Result, rootProfilePath, userOutputDir string, p pathfinder.UserProfile) int {
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
		srcPath := filepath.Join(rootProfilePath, name)
		dstPath := filepath.Join(userOutputDir, name)

		// Original (live) path for the manifest.
		originalPath := filepath.Join(p.ProfilePath, name)

		if collectOneHiveFile(ctx, result, srcPath, dstPath, originalPath, name, p.Username) {
			collected++
		}
	}

	// UsrClass.dat files.
	for _, name := range usrclassFiles {
		srcPath := filepath.Join(rootProfilePath, usrclassDir, name)
		dstPath := filepath.Join(userOutputDir, name)
		originalPath := filepath.Join(p.ProfilePath, usrclassDir, name)

		if collectOneHiveFile(ctx, result, srcPath, dstPath, originalPath, name, p.Username) {
			collected++
		}
	}

	return collected
}

// collectOneHiveFile copies a single hive file. Missing LOG files are not
// errors (they're optional). Missing main hives are warnings. Returns true
// if the file was successfully collected.
func collectOneHiveFile(ctx *Context, result *Result, srcPath, dstPath, originalPath, name, username string) bool {
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

	if err := copyEvidenceFile(ctx, srcPath, dstPath); err != nil {
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

// mapToRoot translates a target-host absolute path to its location under the
// evidence root. The root represents the target's C: volume — the VSS shadow
// mount for a live case, or the read-only-mounted image volume for a dead
// image. For example:
//
//	target: C:\Users\win11test
//	live:   C:\safe_shadow_<timestamp>\Users\win11test   (root = shadow mount)
//	image:  E:\Users\win11test                           (root = mounted image)
//
// Returns an error if the target path does not start with C:\. Only the C:
// volume is captured (a live shadow is of C:, and today's image support treats
// the mounted image as the target's C:), so a path on any other volume (e.g. an
// Exchange install on D:\) cannot be mapped and the caller must warn and skip.
func mapToRoot(targetPath, root string) (string, error) {
	// Normalize case for the prefix check; the drive letter is case-insensitive.
	upper := strings.ToUpper(targetPath)
	if !strings.HasPrefix(upper, `C:\`) {
		return "", fmt.Errorf("path is not on the C: volume, cannot map to evidence root: %s", targetPath)
	}
	// Strip the C:\ prefix and join the remainder under the root.
	relative := targetPath[len(`C:\`):]
	return filepath.Join(root, relative), nil
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
