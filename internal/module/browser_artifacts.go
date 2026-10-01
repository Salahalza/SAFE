package module

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Salahalza/SAFE/internal/pathfinder"
)

type BrowserArtifacts struct{}

func (m *BrowserArtifacts) Name() string              { return "browser_artifacts" }
func (m *BrowserArtifacts) Priority() Priority        { return PriorityNormal }
func (m *BrowserArtifacts) TimeBudget() time.Duration { return 5 * time.Minute }
func (m *BrowserArtifacts) RequiresVSS() bool         { return true }

func (m *BrowserArtifacts) Run(ctx *Context) Result {
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

	errs := IterateUserProfiles(ctx, func(p pathfinder.UserProfile, rootProfilePath string, userOutputDir string) error {
		// Collect Chrome
		chromeDir := filepath.Join(rootProfilePath, "AppData", "Local", "Google", "Chrome", "User Data")
		if info, err := os.Stat(chromeDir); err == nil && info.IsDir() {
			localState := filepath.Join(chromeDir, "Local State")
			collectBrowserFile(ctx, &result, localState, filepath.Join(userOutputDir, "Chrome", "Local State"), filepath.Join(p.ProfilePath, "AppData", "Local", "Google", "Chrome", "User Data", "Local State"))

			entries, err := os.ReadDir(chromeDir)
			if err == nil {
				for _, entry := range entries {
					if !entry.IsDir() {
						continue
					}
					name := entry.Name()
					if name == "Default" || strings.HasPrefix(name, "Profile ") {
						profileShadowDir := filepath.Join(chromeDir, name)
						profileOutputDir := filepath.Join(userOutputDir, "Chrome", name)
						profileOriginalDir := filepath.Join(p.ProfilePath, "AppData", "Local", "Google", "Chrome", "User Data", name)

						targets := []string{
							"History",
							"Web Data",
							"Cookies",
							"Bookmarks",
							"Preferences",
							filepath.Join("Network", "Cookies"),
						}

						for _, t := range targets {
							collectBrowserFile(ctx, &result, filepath.Join(profileShadowDir, t), filepath.Join(profileOutputDir, t), filepath.Join(profileOriginalDir, t))
						}
					}
				}
			}
		}

		// Collect Edge
		edgeDir := filepath.Join(rootProfilePath, "AppData", "Local", "Microsoft", "Edge", "User Data")
		if info, err := os.Stat(edgeDir); err == nil && info.IsDir() {
			localState := filepath.Join(edgeDir, "Local State")
			collectBrowserFile(ctx, &result, localState, filepath.Join(userOutputDir, "Edge", "Local State"), filepath.Join(p.ProfilePath, "AppData", "Local", "Microsoft", "Edge", "User Data", "Local State"))

			entries, err := os.ReadDir(edgeDir)
			if err == nil {
				for _, entry := range entries {
					if !entry.IsDir() {
						continue
					}
					name := entry.Name()
					if name == "Default" || strings.HasPrefix(name, "Profile ") {
						profileShadowDir := filepath.Join(edgeDir, name)
						profileOutputDir := filepath.Join(userOutputDir, "Edge", name)
						profileOriginalDir := filepath.Join(p.ProfilePath, "AppData", "Local", "Microsoft", "Edge", "User Data", name)

						targets := []string{
							"History",
							"Web Data",
							"Cookies",
							"Bookmarks",
							"Preferences",
							filepath.Join("Network", "Cookies"),
						}

						for _, t := range targets {
							collectBrowserFile(ctx, &result, filepath.Join(profileShadowDir, t), filepath.Join(profileOutputDir, t), filepath.Join(profileOriginalDir, t))
						}
					}
				}
			}
		}

		// Collect Firefox
		firefoxDir := filepath.Join(rootProfilePath, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles")
		if info, err := os.Stat(firefoxDir); err == nil && info.IsDir() {
			entries, err := os.ReadDir(firefoxDir)
			if err == nil {
				for _, entry := range entries {
					if !entry.IsDir() {
						continue
					}
					profileName := entry.Name()
					profileShadowDir := filepath.Join(firefoxDir, profileName)
					profileOutputDir := filepath.Join(userOutputDir, "Firefox", "Profiles", profileName)
					profileOriginalDir := filepath.Join(p.ProfilePath, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles", profileName)

					targets := []string{
						"places.sqlite",
						"cookies.sqlite",
						"favicons.sqlite",
						"downloads.sqlite",
						"formhistory.sqlite",
						"logins.json",
					}

					for _, t := range targets {
						collectBrowserFile(ctx, &result, filepath.Join(profileShadowDir, t), filepath.Join(profileOutputDir, t), filepath.Join(profileOriginalDir, t))
					}
				}
			}
		}

		// Collect DPAPI
		dpapiDir := filepath.Join(rootProfilePath, "AppData", "Roaming", "Microsoft", "Protect", p.SID)
		if info, err := os.Stat(dpapiDir); err == nil && info.IsDir() {
			entries, err := os.ReadDir(dpapiDir)
			if err == nil {
				for _, entry := range entries {
					if entry.IsDir() {
						continue
					}
					name := entry.Name()
					collectBrowserFile(ctx, &result, filepath.Join(dpapiDir, name), filepath.Join(userOutputDir, "DPAPI", "Protect", p.SID, name), filepath.Join(p.ProfilePath, "AppData", "Roaming", "Microsoft", "Protect", p.SID, name))
				}
			}
		}

		return nil
	})

	for _, e := range errs {
		result.Errors = append(result.Errors, e.Error())
	}

	if len(result.Artifacts) == 0 {
		result.AddWarning("browser_artifacts", "no browser artifacts or DPAPI keys collected")
	} else {
		result.AddInfo("browser_artifacts", fmt.Sprintf("collected %d browser files / DPAPI keys", len(result.Artifacts)))
	}

	finalize(&result, started, ctx.Ctx)
	return result
}

func collectBrowserFile(ctx *Context, result *Result, srcPath, dstPath, originalPath string) bool {
	info, err := os.Stat(srcPath)
	if err != nil {
		return false // Silently ignore missing optional files
	}

	if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("mkdir %s: %v", filepath.Dir(dstPath), err))
		return false
	}

	if err := copyEvidenceFile(ctx, srcPath, dstPath); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("copy %s: %v", filepath.Base(srcPath), err))
		return false
	}

	artifact, err := describeArtifact(dstPath)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("hash %s: %v", filepath.Base(dstPath), err))
		return false
	}

	artifact.SourcePath = originalPath
	artifact.SourceSize = info.Size()
	result.Artifacts = append(result.Artifacts, artifact)
	return true
}
