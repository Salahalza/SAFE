package module

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type PrefetchCollection struct{}

func (m *PrefetchCollection) Name() string              { return "prefetch_collection" }
func (m *PrefetchCollection) Priority() Priority        { return PriorityHigh }
func (m *PrefetchCollection) TimeBudget() time.Duration { return 3 * time.Minute }
func (m *PrefetchCollection) RequiresVSS() bool         { return true }

// Run copies all Prefetch (.pf) files from C:\Windows\Prefetch to the case
// folder via the shared VSS shadow.
//
// Prefetch files are Windows-generated traces created the first time an
// executable runs. Each .pf file records the executable name, hash, last 8
// run times, total run count, and a list of files accessed during the first
// 10 seconds of execution. One of the highest-value Windows execution
// artifacts because it captures programs that ran briefly and were then
// deleted from disk.
//
// On SSDs and Server SKUs, Prefetch may be disabled. The module records
// that fact and produces zero artifacts rather than failing.
//
// Reporting: this is a bulk-collection module. Individual .pf files are
// copied to disk (and hashed by the manifest writer) but they are NOT
// enumerated in result.Artifacts. Instead, result.BulkFiles records the
// count. The case report shows primary artifacts and bulk-collected files
// as separate numbers so the analyst gets a meaningful "things to look at"
// count without Prefetch's hundreds of files inflating it.
func (m *PrefetchCollection) Run(ctx *Context) Result {
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

	// Prefetch directory in the shadow.
	prefetchDir := filepath.Join(ctx.Shadow.MountedPath, "Windows", "Prefetch")

	// Check if Prefetch directory exists.
	stat, err := os.Stat(prefetchDir)
	if err != nil {
		if os.IsNotExist(err) {
			result.AddWarning("prefetch_collection",
				"Prefetch directory not found — may be disabled on this system (common on SSDs and Server SKUs)")
			finalize(&result, started, ctx.Ctx)
			return result
		}
		result.AddWarning("prefetch_collection",
			fmt.Sprintf("could not stat Prefetch directory: %v", err))
		result.Errors = append(result.Errors, fmt.Sprintf("stat: %v", err))
		finalize(&result, started, ctx.Ctx)
		return result
	}
	if !stat.IsDir() {
		result.AddWarning("prefetch_collection",
			"Prefetch path exists but is not a directory")
		finalize(&result, started, ctx.Ctx)
		return result
	}

	// Enumerate .pf files.
	entries, err := os.ReadDir(prefetchDir)
	if err != nil {
		result.AddWarning("prefetch_collection",
			fmt.Sprintf("could not read Prefetch directory: %v", err))
		result.Errors = append(result.Errors, fmt.Sprintf("readdir: %v", err))
		finalize(&result, started, ctx.Ctx)
		return result
	}

	pfCount := 0
	otherCount := 0
	totalBytes := int64(0)
	skipped := 0

	for i, entry := range entries {
		// Report intra-module progress (entries seen / total, bytes copied).
		ctx.ReportProgress(i, len(entries), totalBytes)

		// Skip subdirectories — Windows occasionally has ReadyBoot/, etc.
		if entry.IsDir() {
			skipped++
			continue
		}

		name := entry.Name()
		lowerName := strings.ToLower(name)

		// Only collect .pf files. Layout.ini and other Prefetch directory
		// contents are not high-value forensic artifacts.
		if !strings.HasSuffix(lowerName, ".pf") {
			otherCount++
			continue
		}

		srcPath := filepath.Join(prefetchDir, name)
		dstPath := filepath.Join(ctx.OutputDir, name)

		info, err := os.Stat(srcPath)
		if err != nil {
			result.AddWarning(name,
				fmt.Sprintf("stat failed: %v", err))
			continue
		}

		if err := copyFile(srcPath, dstPath); err != nil {
			result.AddWarning(name,
				fmt.Sprintf("copy failed: %v", err))
			result.Errors = append(result.Errors,
				fmt.Sprintf("%s copy: %v", name, err))
			continue
		}

		// Note: we intentionally do NOT append per-file entries to
		// result.Artifacts. The manifest writer walks the output directory
		// and hashes every file, so integrity is preserved. The display
		// totals stay meaningful because hundreds of .pf files don't
		// inflate the artifact count.
		pfCount++
		totalBytes += info.Size()
	}
	ctx.ReportProgress(len(entries), len(entries), totalBytes)

	// Summary findings and bulk count.
	if pfCount == 0 {
		result.AddInfo("prefetch_collection",
			"Prefetch directory exists but contains no .pf files — likely disabled or recently cleared")
	} else {
		result.BulkFiles = pfCount
		result.AddInfo("prefetch_collection",
			fmt.Sprintf("collected %d .pf file(s), %d byte(s) total; skipped %d non-.pf entries and %d subdirectories",
				pfCount, totalBytes, otherCount, skipped))
	}

	finalize(&result, started, ctx.Ctx)
	return result
}
