package analyzer

import (
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	prefetch "www.velocidex.com/golang/go-prefetch"
)

// PrefetchParser reads collected .pf files from the prefetch_collection module
// output and produces a CSV summary of all parsed entries. Prefetch files
// record executable execution traces — name, hash, last 8 run times,
// run count, and files accessed during the first 10 seconds of execution.
//
// One CSV per case (not per user, since Prefetch is system-wide).
// Each .pf file may contain up to 8 last-run timestamps; the parser emits
// one row per (.pf file, run timestamp) pair so the timeline is flat and
// sortable. An additional summary row is included with run_index = -1
// when no run timestamps are available.
type PrefetchParser struct{}

func (p *PrefetchParser) Name() string { return "prefetch" }

func (p *PrefetchParser) Parse(caseDir, labReportDir string, report ProgressFunc) ([]string, ParseStats, []error) {
	stats := ParseStats{}

	// Locate the prefetch_collection module output directory in the case.
	pfGlob := filepath.Join(caseDir, "modules", "*_prefetch_collection")
	matches, err := filepath.Glob(pfGlob)
	if err != nil {
		return nil, nil, []error{fmt.Errorf("glob prefetch_collection dir: %w", err)}
	}
	if len(matches) == 0 {
		return nil, nil, []error{fmt.Errorf("prefetch_collection module not found in case")}
	}
	pfRoot := matches[0]

	// Enumerate .pf files in that directory.
	entries, err := os.ReadDir(pfRoot)
	if err != nil {
		return nil, nil, []error{fmt.Errorf("read prefetch dir: %w", err)}
	}

	// Output directory for this parser.
	outDir := filepath.Join(labReportDir, "prefetch")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, nil, []error{fmt.Errorf("create output dir: %w", err)}
	}

	// First pass: count and parse, accumulate rows in memory so we can decide
	// whether to write a CSV at all (Item 7: skip CSV when no entries).
	type pendingRow []string
	var rows []pendingRow

	var errs []error
	parsedCount := 0
	skippedCount := 0

	for i, entry := range entries {
		if report != nil {
			report(i, len(entries))
		}
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".pf") {
			continue
		}

		pfPath := filepath.Join(pfRoot, name)
		info, err := parsePrefetchFile(pfPath)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			skippedCount++
			continue
		}

		if len(info.LastRunTimes) == 0 {
			rows = append(rows, buildPrefetchRow(name, info, -1, time.Time{}))
		} else {
			for i, runTime := range info.LastRunTimes {
				rows = append(rows, buildPrefetchRow(name, info, i, runTime))
			}
		}
		parsedCount++
	}

	stats["pf_files_parsed"] = parsedCount
	stats["pf_files_skipped"] = skippedCount
	stats["rows_emitted"] = len(rows)

	// If we parsed nothing, don't produce an empty CSV.
	if len(rows) == 0 {
		return nil, stats, errs
	}

	csvPath := filepath.Join(outDir, "prefetch.csv")
	f, err := os.Create(csvPath)
	if err != nil {
		return nil, stats, append(errs, fmt.Errorf("create csv: %w", err))
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	if err := w.Write([]string{
		"prefetch_filename",
		"executable",
		"path",
		"hash",
		"version",
		"file_size",
		"run_count",
		"files_accessed_count",
		"run_index",
		"run_time_utc",
	}); err != nil {
		return nil, stats, append(errs, fmt.Errorf("write header: %w", err))
	}

	for _, row := range rows {
		if err := w.Write(row); err != nil {
			errs = append(errs, fmt.Errorf("write row: %w", err))
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return nil, stats, append(errs, fmt.Errorf("csv flush: %w", err))
	}

	return []string{csvPath}, stats, errs
}

// parsePrefetchFile opens a .pf file and returns the parsed PrefetchInfo.
// The go-prefetch library handles MAM-compressed (LZ-XPRESS Huffman) files
// natively, so Windows 10/11 prefetch files work as-is.
func parsePrefetchFile(path string) (*prefetch.PrefetchInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	info, err := prefetch.LoadPrefetch(f)
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if info == nil {
		return nil, fmt.Errorf("parse returned nil with no error")
	}
	return info, nil
}

func buildPrefetchRow(filename string, info *prefetch.PrefetchInfo, runIndex int, runTime time.Time) []string {
	runTimeStr := ""
	if !runTime.IsZero() {
		runTimeStr = runTime.UTC().Format(time.RFC3339)
	}
	return []string{
		filename,
		info.Executable,
		info.Path,
		info.Hash,
		info.Version,
		fmt.Sprintf("%d", info.FileSize),
		fmt.Sprintf("%d", info.RunCount),
		fmt.Sprintf("%d", len(info.FilesAccessed)),
		fmt.Sprintf("%d", runIndex),
		runTimeStr,
	}
}
