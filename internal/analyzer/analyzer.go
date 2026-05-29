// Package analyzer provides parsing and analysis of artifacts collected by
// SAHM, intended to run on an analyst's workstation (not on the targeted
// device).
//
// The collection-side code (in internal/module) does the minimum necessary
// work on the target: file copies, command output captures, registry hive
// copies. The analyzer reads the resulting case folder and produces parsed,
// analyst-ready output in a lab_report/ subdirectory.
//
// This separation matters operationally: every command run on a target adds
// noise to event logs, may trigger EDR, and risks interaction with malware
// watching for forensic activity. SAHM is designed to be a quiet visitor.
package analyzer

import (
	"fmt"
	"os"
	"path/filepath"
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
	Status    string        `json:"status"` // success, failed, skipped
	Outputs   []string      `json:"outputs,omitempty"`
	Errors    []string      `json:"errors,omitempty"`
	StartedAt time.Time     `json:"started_at"`
	Duration  time.Duration `json:"duration_ns"`
}

// Parser is what each analyzer module implements.
type Parser interface {
	// Name returns the parser's identifier.
	Name() string

	// Parse reads relevant artifacts from caseDir and writes parsed output
	// to labReportDir. Returns the list of output files produced and any
	// errors encountered. A parser may legitimately produce zero outputs
	// (no source artifacts in the case, etc.) without erroring.
	Parse(caseDir, labReportDir string) ([]string, []error)
}

// Run executes all registered parsers against the given case folder.
// Output goes to <caseDir>/lab_report/.
func Run(caseDir string, parsers []Parser) (*Result, error) {
	started := time.Now().UTC()

	// Verify case folder exists.
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

	return result, nil
}

func runParser(p Parser, caseDir, labReportDir string) ParserResult {
	started := time.Now().UTC()
	r := ParserResult{
		Name:      p.Name(),
		StartedAt: started,
	}

	outputs, errs := p.Parse(caseDir, labReportDir)
	r.Outputs = outputs
	for _, e := range errs {
		r.Errors = append(r.Errors, e.Error())
	}
	if len(errs) > 0 && len(outputs) == 0 {
		r.Status = "failed"
	} else {
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
