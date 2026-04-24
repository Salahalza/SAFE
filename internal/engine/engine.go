package engine

import (
	"fmt"
	"path/filepath"
	"time"

	"acquira/internal/module"
)

// Engine runs a sequence of modules and collects their results.
type Engine struct {
	// CaseDir is the root output directory for this case.
	// Each module gets its own subdirectory under CaseDir/modules/.
	CaseDir string
}

// New creates a new Engine writing output to caseDir.
func New(caseDir string) *Engine {
	return &Engine{CaseDir: caseDir}
}

// CaseResult is the overall outcome of running a profile.
type CaseResult struct {
	CaseDir   string          `json:"case_dir"`
	StartedAt time.Time       `json:"started_at"`
	EndedAt   time.Time       `json:"ended_at"`
	Duration  time.Duration   `json:"duration_ns"`
	Modules   []module.Result `json:"modules"`
	Status    string          `json:"status"`
}

// Run executes every module in order and returns the overall result.
func (e *Engine) Run(modules []module.Module) CaseResult {
	started := time.Now().UTC()
	result := CaseResult{
		CaseDir:   e.CaseDir,
		StartedAt: started,
		Modules:   []module.Result{},
	}

	for i, m := range modules {
		fmt.Printf("[%d/%d] Running module: %s (priority=%s, budget=%s)\n",
			i+1, len(modules), m.Name(), m.Priority(), m.TimeBudget())

		// Each module gets its own numbered subdirectory.
		// Format: 01_system_metadata, 02_process_snapshot, etc.
		moduleDir := filepath.Join(
			e.CaseDir,
			"modules",
			fmt.Sprintf("%02d_%s", i+1, m.Name()),
		)

		ctx := &module.Context{
			OutputDir: moduleDir,
		}

		modResult := m.Run(ctx)
		result.Modules = append(result.Modules, modResult)

		fmt.Printf("      status=%s duration=%s artifacts=%d errors=%d\n",
			modResult.Status, modResult.Duration,
			len(modResult.Artifacts), len(modResult.Errors))

		// Stop the profile early if a critical module failed.
		if modResult.Status == module.StatusFailed && m.Priority() == module.PriorityCritical {
			fmt.Printf("      critical module failed — aborting profile\n")
			break
		}
	}

	result.EndedAt = time.Now().UTC()
	result.Duration = result.EndedAt.Sub(started)
	result.Status = summarize(result.Modules)

	return result
}

// summarize returns an overall status based on module outcomes.
func summarize(results []module.Result) string {
	hasFailed := false
	hasPartial := false
	for _, r := range results {
		switch r.Status {
		case module.StatusFailed:
			hasFailed = true
		case module.StatusPartial:
			hasPartial = true
		}
	}
	switch {
	case hasFailed:
		return "degraded"
	case hasPartial:
		return "partial"
	default:
		return "success"
	}
}
