package module

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Salahalza/SAFE/internal/pathfinder"
)

type JumpLists struct{}

func (m *JumpLists) Name() string              { return "jump_lists" }
func (m *JumpLists) Priority() Priority        { return PriorityNormal }
func (m *JumpLists) TimeBudget() time.Duration { return 3 * time.Minute }
func (m *JumpLists) RequiresVSS() bool         { return true }

func (m *JumpLists) Run(ctx *Context) Result {
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

	totalCopied := 0
	var totalBytes int64

	errs := IterateUserProfiles(ctx, func(p pathfinder.UserProfile, rootProfilePath string, userOutputDir string) error {
		// AutomaticDestinations
		autoDestDir := filepath.Join(rootProfilePath, "AppData", "Roaming", "Microsoft", "Windows", "Recent", "AutomaticDestinations")
		if info, err := os.Stat(autoDestDir); err == nil && info.IsDir() {
			entries, err := os.ReadDir(autoDestDir)
			if err == nil {
				for _, entry := range entries {
					if entry.IsDir() {
						continue
					}
					name := entry.Name()
					if strings.HasSuffix(strings.ToLower(name), ".automaticdestinations-ms") {
						src := filepath.Join(autoDestDir, name)
						dst := filepath.Join(userOutputDir, "Recent", "AutomaticDestinations", name)
						
						fileInfo, err := os.Stat(src)
						if err == nil {
							if err := os.MkdirAll(filepath.Dir(dst), 0o755); err == nil {
								if err := copyEvidenceFile(ctx, src, dst); err == nil {
									totalCopied++
									totalBytes += fileInfo.Size()
								} else {
									result.Errors = append(result.Errors, fmt.Sprintf("%s/Recent/AutomaticDestinations/%s copy: %v", p.Username, name, err))
								}
							}
						}
					}
				}
			}
		}

		// CustomDestinations
		customDestDir := filepath.Join(rootProfilePath, "AppData", "Roaming", "Microsoft", "Windows", "Recent", "CustomDestinations")
		if info, err := os.Stat(customDestDir); err == nil && info.IsDir() {
			entries, err := os.ReadDir(customDestDir)
			if err == nil {
				for _, entry := range entries {
					if entry.IsDir() {
						continue
					}
					name := entry.Name()
					if strings.HasSuffix(strings.ToLower(name), ".customdestinations-ms") {
						src := filepath.Join(customDestDir, name)
						dst := filepath.Join(userOutputDir, "Recent", "CustomDestinations", name)
						
						fileInfo, err := os.Stat(src)
						if err == nil {
							if err := os.MkdirAll(filepath.Dir(dst), 0o755); err == nil {
								if err := copyEvidenceFile(ctx, src, dst); err == nil {
									totalCopied++
									totalBytes += fileInfo.Size()
								} else {
									result.Errors = append(result.Errors, fmt.Sprintf("%s/Recent/CustomDestinations/%s copy: %v", p.Username, name, err))
								}
							}
						}
					}
				}
			}
		}

		return nil
	})

	for _, e := range errs {
		result.Errors = append(result.Errors, e.Error())
	}

	if totalCopied == 0 {
		result.AddInfo("jump_lists", "no jump list files found or collected")
	} else {
		result.BulkFiles = totalCopied
		result.AddInfo("jump_lists", fmt.Sprintf("collected %d jump list file(s), %d byte(s) total", totalCopied, totalBytes))
	}

	finalize(&result, started, ctx.Ctx)
	return result
}
