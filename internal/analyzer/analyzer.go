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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
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

// Parser is what each analyzer module implements.
type Parser interface {
	// Name returns the parser's identifier.
	Name() string

	// Parse reads relevant artifacts from caseDir and writes parsed output
	// to labReportDir. Returns the list of output files produced, optional
	// stats for inclusion in the report, and any errors encountered.
	// A parser may legitimately produce zero outputs (no source artifacts
	// in the case, etc.) without erroring.
	Parse(caseDir, labReportDir string) ([]string, ParseStats, []error)
}

// Run executes all registered parsers against the given case folder.
// Output goes to <caseDir>/lab_report/.
func Run(caseDir string, parsers []Parser) (*Result, error) {
	started := time.Now().UTC()

	if info, err := os.Stat(caseDir); err != nil {
		return nil, fmt.Errorf("case folder: %w", err)
	} else if !info.IsDir() {
		return nil, fmt.Errorf("not a directory: %s", caseDir)
	}

	labReportDir := filepath.Join(caseDir, "lab_report")
	if err := os.MkdirAll(labReportDir, 0o755); err != nil {
		return nil, fmt.Errorf("create lab_report dir: %w", err)
	}

	result := &Result{
		CaseDir:      caseDir,
		LabReportDir: labReportDir,
		StartedAt:    started,
		ParsersRun:   []ParserResult{},
	}

	for _, p := range parsers {
		pResult := runParser(p, caseDir, labReportDir)
		result.ParsersRun = append(result.ParsersRun, pResult)
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
	if err := writeLabReportManifest(labReportDir); err != nil {
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

// writeLabReportManifest creates lab_report/manifest.sha256 listing every
// file in the lab_report directory tree with its SHA-256 hash. The manifest
// itself is excluded. This mirrors the collection-side integrity model:
// if any CSV or analyzer_result.json is modified after the fact, hash
// comparison detects it.
func writeLabReportManifest(labReportDir string) error {
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

// hashFile returns the SHA-256 hex digest of a file's contents.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func runParser(p Parser, caseDir, labReportDir string) ParserResult {
	started := time.Now().UTC()
	r := ParserResult{
		Name:      p.Name(),
		StartedAt: started,
	}

	outputs, stats, errs := p.Parse(caseDir, labReportDir)
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
