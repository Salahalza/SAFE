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

func (p *PrefetchParser) Parse(caseDir, labReportDir string) ([]string, []error) {
	// Locate the prefetch_collection module output directory in the case.
	pfGlob := filepath.Join(caseDir, "modules", "*_prefetch_collection")
	matches, err := filepath.Glob(pfGlob)
	if err != nil {
		return nil, []error{fmt.Errorf("glob prefetch_collection dir: %w", err)}
	}
	if len(matches) == 0 {
		return nil, []error{fmt.Errorf("prefetch_collection module not found in case")}
	}
	pfRoot := matches[0]

	// Enumerate .pf files in that directory.
	entries, err := os.ReadDir(pfRoot)
	if err != nil {
		return nil, []error{fmt.Errorf("read prefetch dir: %w", err)}
	}

	// Output directory for this parser.
	outDir := filepath.Join(labReportDir, "prefetch")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, []error{fmt.Errorf("create output dir: %w", err)}
	}

	csvPath := filepath.Join(outDir, "prefetch.csv")
	f, err := os.Create(csvPath)
	if err != nil {
		return nil, []error{fmt.Errorf("create csv: %w", err)}
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
		return nil, []error{fmt.Errorf("write header: %w", err)}
	}

	var errs []error
	parsedCount := 0
	skippedCount := 0

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Skip module.json and any non-.pf files.
		if !strings.HasSuffix(strings.ToLower(name), ".pf") {
			continue
		}

		pfPath := filepath.Join(pfRoot, name)
		info, err := parsePrefetchFile(pfPath)
		if err != nil {
			// Per-file errors are recorded but don't abort parsing.
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			skippedCount++
			continue
		}

		// Write one row per run timestamp, or one summary row if no
		// timestamps are present.
		if len(info.LastRunTimes) == 0 {
			row := buildPrefetchRow(name, info, -1, time.Time{})
			if err := w.Write(row); err != nil {
				errs = append(errs, fmt.Errorf("%s row: %w", name, err))
				continue
			}
		} else {
			for i, runTime := range info.LastRunTimes {
				row := buildPrefetchRow(name, info, i, runTime)
				if err := w.Write(row); err != nil {
					errs = append(errs, fmt.Errorf("%s row %d: %w", name, i, err))
					continue
				}
			}
		}
		parsedCount++
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return nil, append(errs, fmt.Errorf("csv flush: %w", err))
	}

	// If we parsed nothing useful, the output file is just a header.
	// Still return it; an empty result is information too.
	_ = parsedCount
	_ = skippedCount

	return []string{csvPath}, errs
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
