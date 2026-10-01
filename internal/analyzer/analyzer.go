// Package analyzer provides parsing and analysis of artifacts collected by
// SAFE, intended to run on an analyst's workstation (not on the targeted
// device).
//
// The collection-side code (in internal/module) does the minimum necessary
// work on the target: file copies, command output captures, registry hive
// copies. The analyzer reads the resulting case folder and produces parsed,
// analyst-ready output in a lab_report/ subdirectory.
//
// This separation matters operationally: every command run on a target adds
// noise to event logs, may trigger EDR, and risks interaction with malware
// watching for forensic activity. SAFE is designed to be a quiet visitor.
package analyzer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Salahalza/SAFE/internal/analyzer/timeline"
	"github.com/Salahalza/SAFE/internal/csvutil"
	"github.com/Salahalza/SAFE/internal/hashutil"
)

// Result describes the outcome of running the analyzer over a case folder.
type Result struct {
	CaseDir      string         `json:"case_dir"`
	LabReportDir string         `json:"lab_report_dir"`
	StartedAt    time.Time      `json:"started_at"`
	EndedAt      time.Time      `json:"ended_at"`
	Duration     time.Duration  `json:"duration_ns"`
	ParsersRun   []ParserResult `json:"parsers_run"`
}

// ParserResult is the outcome of running one parser against the case folder.
type ParserResult struct {
	Name      string        `json:"name"`
	Status    string        `json:"status"`
	Outputs   []string      `json:"outputs,omitempty"`
	Stats     ParseStats    `json:"stats,omitempty"`
	Errors    []string      `json:"errors,omitempty"`
	StartedAt time.Time     `json:"started_at"`
	Duration  time.Duration `json:"duration_ns"`
}

// Parser is what each analyzer module implements.
// ParseStats are optional per-parser statistics surfaced in the report.
// Examples: number of files parsed, number skipped, unknowns encountered.
type ParseStats map[string]int

// ProgressFunc reports a parser's intra-parse progress (work units done /
// total) so the UI can advance a bar while a slow parser runs. A parser may
// call it as coarsely or finely as makes sense, or not at all.
type ProgressFunc func(done, total int)

// Parser is what each analyzer module implements.
type Parser interface {
	// Name returns the parser's identifier.
	Name() string

	// Parse reads relevant artifacts from caseDir and writes parsed output
	// to labReportDir. Returns the list of output files produced, optional
	// stats for inclusion in the report, and any errors encountered.
	// A parser may legitimately produce zero outputs (no source artifacts
	// in the case, etc.) without erroring.
	//
	// report, if non-nil, lets the parser stream intra-parse progress; calling
	// it is optional. Use it for slow parsers so the analyze bar keeps moving.
	Parse(caseDir, labReportDir string, report ProgressFunc) ([]string, ParseStats, []error)
}

// Run executes all registered parsers against the given case folder.
// Output goes to <caseDir>/lab_report/.
func Run(caseDir string, parsers []Parser) (*Result, error) {
	return RunWithProgress(caseDir, parsers, nil)
}

// RunWithProgress is Run with an optional progress callback reporting an
// overall 0..1 fraction and the current parser's name. The fraction blends
// completed parsers with the running parser's own intra-parse progress (each
// parser is an equal 1/N slice, advancing smoothly within), so the bar keeps
// moving even during a slow parser. nil disables it.
func RunWithProgress(caseDir string, parsers []Parser, onProgress func(frac float64, label string)) (*Result, error) {
	started := time.Now().UTC()

	if info, err := os.Stat(caseDir); err != nil {
		return nil, fmt.Errorf("case folder: %w", err)
	} else if !info.IsDir() {
		return nil, fmt.Errorf("not a directory: %s", caseDir)
	}

	labReportDir := filepath.Join(caseDir, "lab_report")
	// Re-analysis fully regenerates lab_report/, so purge any prior output
	// first. Otherwise files from a superseded run (e.g. evtx CSVs written
	// under a channel name an older parser version produced) linger and get
	// double-counted by glob-based consumers like the behavioral rules. Only
	// derived output lives here — analyst-authored tags.json and the collected
	// evidence sit outside lab_report/, and timeline.db is a rebuildable cache.
	if err := os.RemoveAll(labReportDir); err != nil {
		return nil, fmt.Errorf("clear stale lab_report (is the report server still running? stop it and retry): %w", err)
	}
	if err := os.MkdirAll(labReportDir, 0o755); err != nil {
		return nil, fmt.Errorf("create lab_report dir: %w", err)
	}

	result := &Result{
		CaseDir:      caseDir,
		LabReportDir: labReportDir,
		StartedAt:    started,
		ParsersRun:   []ParserResult{},
	}

	n := len(parsers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var completed int

	for _, p := range parsers {
		wg.Add(1)
		go func(parser Parser) {
			defer wg.Done()
			
			// We use a simplified progress report since we are concurrent
			report := ProgressFunc(func(done, total int) {})
			
			pResult := runParser(parser, caseDir, labReportDir, report)
			
			mu.Lock()
			result.ParsersRun = append(result.ParsersRun, pResult)
			completed++
			if onProgress != nil {
				onProgress(float64(completed)/float64(max(n, 1)), "Parsing (Concurrent)")
			}
			mu.Unlock()
		}(p)
	}
	
	wg.Wait()

	// Phase 5: Generate timeline.csv from parsed results
	if onProgress != nil {
		onProgress(0.99, "timeline")
	}
	timelinePath, tlErr := timeline.Generate(labReportDir)
	if tlErr != nil {
		result.ParsersRun = append(result.ParsersRun, ParserResult{
			Name:      "timeline",
			Status:    "failed",
			Errors:    []string{tlErr.Error()},
			StartedAt: time.Now().UTC(),
		})
	} else if timelinePath != "" {
		result.ParsersRun = append(result.ParsersRun, ParserResult{
			Name:      "timeline",
			Status:    "success",
			Outputs:   []string{timelinePath},
			StartedAt: time.Now().UTC(),
		})
	}

	if onProgress != nil {
		onProgress(1.0, "")
	}

	result.EndedAt = time.Now().UTC()
	result.Duration = result.EndedAt.Sub(started)

	// Item 3: write analyzer_result.json so future analysts know what the
	// analyzer did against this case.
	if err := writeAnalyzerResult(labReportDir, result); err != nil {
		return result, fmt.Errorf("write analyzer_result.json: %w", err)
	}

	// Item 2: write a manifest of every file in lab_report/ for tamper
	// detection. Same pattern as the collection-side manifest.sha256.
	// The caller must call WriteLabReportManifest again after any further
	// mutation of lab_report/ (e.g. the behavioral engine injecting alerts
	// into timeline.csv and writing behavior_hits.csv) — this snapshot only
	// covers parser output.
	if err := WriteLabReportManifest(labReportDir); err != nil {
		return result, fmt.Errorf("write lab_report manifest: %w", err)
	}

	return result, nil
}

// writeAnalyzerResult writes the Result struct as JSON in the lab_report
// directory. This mirrors the collection-side result.json — a permanent
// record of what the analyzer did, when, with which parsers, and any
// errors encountered.
func writeAnalyzerResult(labReportDir string, result *Result) error {
	path := filepath.Join(labReportDir, "analyzer_result.json")
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return os.WriteFile(path, data, 0o644)
}

// WriteLabReportManifest creates lab_report/manifest.sha256 listing every
// file in the lab_report directory tree with its SHA-256 hash. The manifest
// itself is excluded. This mirrors the collection-side integrity model:
// if any CSV or analyzer_result.json is modified after the fact, hash
// comparison detects it.
//
// Exported so callers (e.g. cmd/safe-analyze) can regenerate it after
// mutating lab_report/ post-RunWithProgress — the behavioral engine writes
// behavior_hits.csv and appends alerts to timeline.csv after parsing
// finishes, so the manifest must be rewritten once more after that to stay
// accurate.
func WriteLabReportManifest(labReportDir string) error {
	var entries []string

	err := filepath.Walk(labReportDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		// Exclude the manifest itself.
		if filepath.Base(path) == "manifest.sha256" {
			return nil
		}

		hash, err := hashFile(path)
		if err != nil {
			return fmt.Errorf("hash %s: %w", path, err)
		}

		// Use forward slashes for cross-platform consistency in the manifest.
		rel, err := filepath.Rel(labReportDir, path)
		if err != nil {
			return fmt.Errorf("rel path %s: %w", path, err)
		}
		rel = filepath.ToSlash(rel)

		entries = append(entries, fmt.Sprintf("%s  %s", hash, rel))
		return nil
	})
	if err != nil {
		return err
	}

	// Sort for deterministic output.
	sort.Strings(entries)

	manifestPath := filepath.Join(labReportDir, "manifest.sha256")
	content := strings.Join(entries, "\n") + "\n"
	return os.WriteFile(manifestPath, []byte(content), 0o644)
}

// csvSafe neutralizes spreadsheet formula injection in a CSV field. The
// encoding/csv writer quotes delimiters correctly but does nothing about a
// value a spreadsheet (Excel, LibreOffice) would evaluate as a formula — one
// beginning with '=', '+', '-', '@', or a leading tab/CR. Several analyzer
// columns carry attacker-influenceable free text (a program path a malicious
// actor chose to run, a prefetch executable name), so a crafted value like
// "=cmd|'/c calc'!A1" could execute when an analyst opens the CSV. Prefixing
// such a value with a single quote forces the spreadsheet to treat it as literal
// text without changing what a plain text/grep reader sees in any meaningful way.
// Apply only to free-text columns, never to numeric or timestamp columns.
func csvSafe(s string) string {
	return csvutil.CsvSafe(s)
}

// hashFile returns the SHA-256 hex digest of a file's contents, via the single
// shared hasher so collect- and analyze-side hashes cannot drift.
func hashFile(path string) (string, error) {
	return hashutil.SHA256File(path)
}

func runParser(p Parser, caseDir, labReportDir string, report ProgressFunc) ParserResult {
	started := time.Now().UTC()
	r := ParserResult{
		Name:      p.Name(),
		StartedAt: started,
	}

	outputs, stats, errs := p.Parse(caseDir, labReportDir, report)
	r.Outputs = outputs
	r.Stats = stats
	for _, e := range errs {
		r.Errors = append(r.Errors, e.Error())
	}

	// Status semantics:
	//   failed  — no outputs and at least one error
	//   partial — outputs produced but at least one error
	//   success — outputs produced with no errors
	//   skipped — no outputs and no errors (e.g. source module not in case)
	switch {
	case len(errs) > 0 && len(outputs) == 0:
		r.Status = "failed"
	case len(errs) > 0:
		r.Status = "partial"
	case len(outputs) == 0:
		r.Status = "skipped"
	default:
		r.Status = "success"
	}

	r.Duration = time.Since(started)
	return r
}

// Registry holds the set of available parsers.
type Registry struct {
	parsers []Parser
}

func NewRegistry() *Registry {
	return &Registry{}
}

func (r *Registry) Register(p Parser) {
	r.parsers = append(r.parsers, p)
}

func (r *Registry) All() []Parser {
	return r.parsers
}

// firstGlob returns the first match of pattern under base, or "".
func firstGlob(base, pattern string) string {
	matches, err := filepath.Glob(filepath.Join(base, pattern))
	if err != nil || len(matches) == 0 {
		return ""
	}
	return matches[0]
}

