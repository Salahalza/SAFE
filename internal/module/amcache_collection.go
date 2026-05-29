package module

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"sahm/internal/vss"
)

type AmcacheCollection struct{}

func (m *AmcacheCollection) Name() string              { return "amcache_collection" }
func (m *AmcacheCollection) Priority() Priority        { return PriorityHigh }
func (m *AmcacheCollection) TimeBudget() time.Duration { return 2 * time.Minute }

// Run collects the AmCache hive and its transaction logs via Volume Shadow Copy.
//
// AmCache (Application Compatibility Cache) records executable metadata
// including SHA-1 hash, install date, publisher, and full path for every
// executable that has run on the system. It survives reboots and is one
// of the highest-value forensic artifacts on Windows.
//
// The hive is at C:\Windows\AppCompat\Programs\Amcache.hve but is held open
// by the Windows shell/system, requiring VSS for forensic acquisition.
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

	// Create a shadow copy of C: to access the locked hive.
	shadow, err := vss.CreateShadowWithContext(ctx.Ctx, "C:")
	if err != nil {
		result.AddWarning("vss",
			fmt.Sprintf("could not create shadow copy: %v", err))
		result.Errors = append(result.Errors,
			fmt.Sprintf("VSS unavailable, AmCache not collected: %v", err))
		finalize(&result, started, ctx.Ctx)
		return result
	}
	defer func() {
		if cleanupErr := shadow.Cleanup(); cleanupErr != nil {
			// Log cleanup error but don't downgrade the module status —
			// the collection itself succeeded.
			result.Errors = append(result.Errors,
				fmt.Sprintf("shadow cleanup: %v", cleanupErr))
		}
	}()

	// AmCache file paths (relative to the volume root).
	amcacheDir := filepath.Join("Windows", "AppCompat", "Programs")

	files := []string{
		"Amcache.hve",
		"Amcache.hve.LOG1",
		"Amcache.hve.LOG2",
	}

	mainHiveFound := false

	for _, name := range files {
		srcPath := filepath.Join(shadow.MountedPath, amcacheDir, name)
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

		// Copy from the shadow to our case folder.
		if err := copyFile(srcPath, dstPath); err != nil {
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

		// Record the original source path (the real location, not the shadow).
		artifact.SourcePath = filepath.Join(`C:\`, amcacheDir, name)
		artifact.SourceSize = info.Size()

		result.Artifacts = append(result.Artifacts, artifact)

		if name == "Amcache.hve" {
			mainHiveFound = true
		}
	}

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
				fmt.Sprintf("collected Amcache.hve and %d transaction log file(s) via VSS shadow copy",
					logCount))
		} else {
			result.AddInfo("amcache_collection",
				"collected Amcache.hve via VSS shadow copy (no transaction logs present)")
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
