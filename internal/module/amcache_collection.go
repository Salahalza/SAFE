package module

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type AmcacheCollection struct{}

func (m *AmcacheCollection) Name() string              { return "amcache_collection" }
func (m *AmcacheCollection) Priority() Priority        { return PriorityHigh }
func (m *AmcacheCollection) TimeBudget() time.Duration { return 2 * time.Minute }
func (m *AmcacheCollection) RequiresVSS() bool         { return true }

// Run collects the AmCache hive and its transaction logs from the shared
// volume shadow copy provided in the module Context. The engine creates the
// shadow once per case and shares it across all VSS-requiring modules.
func (m *AmcacheCollection) Run(ctx *Context) Result {
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
		// Engine should have prevented this, but guard anyway.
		result.AddWarning("root", "no evidence root available; module should have been skipped by engine")
		result.Errors = append(result.Errors, "no evidence root available")
		finalize(&result, started, ctx.Ctx)
		return result
	}

	amcacheDir := filepath.Join("Windows", "AppCompat", "Programs")
	files := []string{
		"Amcache.hve",
		"Amcache.hve.LOG1",
		"Amcache.hve.LOG2",
	}

	mainHiveFound := false
	var amBytes int64

	for i, name := range files {
		ctx.ReportProgress(i, len(files), amBytes)

		srcPath := filepath.Join(ctx.Root, amcacheDir, name)
		dstPath := filepath.Join(ctx.OutputDir, name)

		info, err := os.Stat(srcPath)
		if err != nil {
			if os.IsNotExist(err) {
				if name == "Amcache.hve" {
					result.AddInfo(name,
						"Amcache.hve not present in shadow copy — system may have no execution history yet")
				}
				continue
			}
			result.AddWarning(name, fmt.Sprintf("stat in shadow: %v", err))
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", name, err))
			continue
		}

		if err := copyEvidenceFile(ctx, srcPath, dstPath); err != nil {
			result.AddWarning(name, fmt.Sprintf("copy failed: %v", err))
			result.Errors = append(result.Errors, fmt.Sprintf("%s copy: %v", name, err))
			continue
		}

		artifact, err := describeArtifact(dstPath)
		if err != nil {
			result.AddWarning(name, fmt.Sprintf("hash failed: %v", err))
			result.Errors = append(result.Errors, fmt.Sprintf("%s hash: %v", name, err))
			continue
		}

		artifact.SourcePath = filepath.Join(`C:\`, amcacheDir, name)
		artifact.SourceSize = info.Size()

		result.Artifacts = append(result.Artifacts, artifact)
		amBytes += info.Size()

		if name == "Amcache.hve" {
			mainHiveFound = true
		}
	}
	ctx.ReportProgress(len(files), len(files), amBytes)

	if !mainHiveFound {
		result.AddWarning("amcache_collection",
			"Amcache.hve was not collected — forensic value of this module is reduced")
	} else {
		logCount := 0
		for _, a := range result.Artifacts {
			base := filepath.Base(a.Path)
			if base == "Amcache.hve.LOG1" || base == "Amcache.hve.LOG2" {
				logCount++
			}
		}
		if logCount > 0 {
			result.AddInfo("amcache_collection",
				fmt.Sprintf("collected Amcache.hve and %d transaction log file(s) from shared shadow",
					logCount))
		} else {
			result.AddInfo("amcache_collection",
				"collected Amcache.hve from shared shadow (no transaction logs present)")
		}
	}

	finalize(&result, started, ctx.Ctx)
	return result
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("create destination: %w", err)
	}
	defer out.Close()

	if _, err := copyStream(out, in); err != nil {
		return fmt.Errorf("copy bytes: %w", err)
	}

	return out.Sync()
}
