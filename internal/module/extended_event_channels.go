package module

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type ExtendedEventChannels struct{}

func (m *ExtendedEventChannels) Name() string              { return "extended_event_channels" }
func (m *ExtendedEventChannels) Priority() Priority        { return PriorityNormal }
func (m *ExtendedEventChannels) TimeBudget() time.Duration { return 20 * time.Minute }
func (m *ExtendedEventChannels) RequiresVSS() bool         { return true }

// Run bulk-copies every .evtx file from C:\Windows\System32\winevt\Logs to the
// case folder via the shared VSS shadow.
//
// Where eventlogs_core exports a curated set of 8 high-value channels with
// `wevtutil epl` (a clean live export), this module captures the COMPLETE set
// of event channels present on the target — often hundreds, including
// application- and role-specific channels (Exchange, IIS, MSSQL, AppLocker,
// WMI-Activity, etc.) that are invaluable on the server-heavy caseload but
// too numerous to curate by hand.
//
// Collection method — deliberately a direct file copy from the VSS shadow, NOT
// `wevtutil epl` per channel. Two reasons:
//
//  1. Quiet visitor (architectural principle #1). Exporting every channel would
//     mean spawning hundreds of wevtutil processes on the target — loud to EDR
//     and slow. Copying the locked .evtx files out of the shared shadow adds
//     ZERO new command execution on the target.
//  2. The .evtx files in winevt\Logs ARE the artifact. Copying them is
//     collection, not analysis. Parsing happens in the lab (Phase 4 EVTX parser).
//
// The 8 core channels collected by eventlogs_core also appear here. That
// redundancy is intentional and accepted: the two are captured by different
// methods (live export vs. point-in-time shadow snapshot), and completeness is
// worth more than dedup cleverness in a forensic context. The overlap is noted
// in a finding so the analyst understands it.
//
// Reporting: this is a bulk-collection module (principle #4). Individual .evtx
// files are copied to disk and hashed by the manifest writer, but they are NOT
// enumerated in result.Artifacts. result.BulkFiles records the count so the
// analyst's "things to look at" total stays meaningful instead of being
// inflated by hundreds of channel files.
func (m *ExtendedEventChannels) Run(ctx *Context) Result {
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

	// Event log directory inside the shadow.
	logsDir := filepath.Join(ctx.Shadow.MountedPath, "Windows", "System32", "winevt", "Logs")

	stat, err := os.Stat(logsDir)
	if err != nil {
		if os.IsNotExist(err) {
			result.AddWarning("extended_event_channels",
				"winevt\\Logs directory not found in shadow — unexpected on a standard Windows install")
			result.Errors = append(result.Errors, "winevt\\Logs not found")
			finalize(&result, started, ctx.Ctx)
			return result
		}
		result.AddWarning("extended_event_channels",
			fmt.Sprintf("could not stat winevt\\Logs directory: %v", err))
		result.Errors = append(result.Errors, fmt.Sprintf("stat: %v", err))
		finalize(&result, started, ctx.Ctx)
		return result
	}
	if !stat.IsDir() {
		result.AddWarning("extended_event_channels",
			"winevt\\Logs path exists but is not a directory")
		result.Errors = append(result.Errors, "winevt\\Logs is not a directory")
		finalize(&result, started, ctx.Ctx)
		return result
	}

	entries, err := os.ReadDir(logsDir)
	if err != nil {
		result.AddWarning("extended_event_channels",
			fmt.Sprintf("could not read winevt\\Logs directory: %v", err))
		result.Errors = append(result.Errors, fmt.Sprintf("readdir: %v", err))
		finalize(&result, started, ctx.Ctx)
		return result
	}

	evtxCount := 0
	otherCount := 0
	totalBytes := int64(0)
	skippedDirs := 0

	for _, entry := range entries {
		// Honour cancellation/timeout mid-copy — winevt\Logs can be large.
		if ctx.Ctx.Err() != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("collection interrupted after %d file(s): %v", evtxCount, ctx.Ctx.Err()))
			break
		}

		// winevt\Logs occasionally contains subdirectories; skip them.
		if entry.IsDir() {
			skippedDirs++
			continue
		}

		name := entry.Name()

		// Only collect .evtx files. The directory may hold transient artifacts
		// the EventLog service uses internally; those are not the artifact.
		if !strings.HasSuffix(strings.ToLower(name), ".evtx") {
			otherCount++
			continue
		}

		srcPath := filepath.Join(logsDir, name)
		dstPath := filepath.Join(ctx.OutputDir, name)

		info, err := os.Stat(srcPath)
		if err != nil {
			result.AddWarning(name, fmt.Sprintf("stat failed: %v", err))
			continue
		}

		if err := copyFile(srcPath, dstPath); err != nil {
			result.AddWarning(name, fmt.Sprintf("copy failed: %v", err))
			result.Errors = append(result.Errors,
				fmt.Sprintf("%s copy: %v", name, err))
			continue
		}

		// Per the bulk pattern we do NOT append per-file entries to
		// result.Artifacts. The manifest writer walks the output directory and
		// hashes every file, so integrity is preserved.
		evtxCount++
		totalBytes += info.Size()
	}

	if evtxCount == 0 {
		result.AddInfo("extended_event_channels",
			"winevt\\Logs exists but no .evtx files were collected")
	} else {
		result.BulkFiles = evtxCount
		result.AddInfo("extended_event_channels",
			fmt.Sprintf("collected %d .evtx channel file(s), %d byte(s) total; skipped %d non-.evtx entries and %d subdirectories",
				evtxCount, totalBytes, otherCount, skippedDirs))
		result.AddInfo("extended_event_channels",
			"includes the 8 channels also exported by eventlogs_core — this overlap is intentional (different collection methods: live export vs. shadow snapshot)")
	}

	finalize(&result, started, ctx.Ctx)
	return result
}
