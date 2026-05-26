package engine

import (
	"fmt"
	"path/filepath"
	"time"

	"sahm/internal/manifest"
	"sahm/internal/module"
	"sahm/internal/profile"
)

// Engine runs the modules of a profile and collects their results.
type Engine struct {
	// CaseDir is the root output directory for this case.
	CaseDir string
}

// New creates a new Engine writing output to caseDir.
func New(caseDir string) *Engine {
	return &Engine{CaseDir: caseDir}
}

// CaseResult is the overall outcome of running a profile.
type CaseResult struct {
	CaseDir     string          `json:"case_dir"`
	ProfileName string          `json:"profile_name"`
	StartedAt   time.Time       `json:"started_at"`
	EndedAt     time.Time       `json:"ended_at"`
	Duration    time.Duration   `json:"duration_ns"`
	Modules     []module.Result `json:"modules"`
	Status      string          `json:"status"`
}

// Run executes the given profile and returns the overall result.
func (e *Engine) Run(p *profile.Profile) CaseResult {
	started := time.Now().UTC()
	result := CaseResult{
		CaseDir:     e.CaseDir,
		ProfileName: p.Name,
		StartedAt:   started,
		Modules:     []module.Result{},
	}

	fmt.Printf("Profile: %s (v%s) — %s\n", p.Name, p.Version, p.Description)
	fmt.Printf("Total budget: %s\n\n", p.TotalBudget)

	for i, m := range p.Modules {
		fmt.Printf("[%d/%d] Running module: %s (priority=%s, budget=%s)\n",
			i+1, len(p.Modules), m.Name(), m.Priority(), m.TimeBudget())

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

		fmt.Printf("      status=%s duration=%s artifacts=%d warnings=%d errors=%d\n",
			modResult.Status, modResult.Duration,
			len(modResult.Artifacts), len(modResult.Warnings), len(modResult.Errors))

		// Write per-module manifest. If this fails, warn but continue —
		// the case manifest writer will detect the missing module.json.
		if _, err := manifest.WriteModuleManifest(moduleDir, m.Name()); err != nil {
			fmt.Printf("      warning: failed to write module manifest: %v\n", err)
		}

		// Stop the profile early if a critical module failed.
		if modResult.Status == module.StatusFailed && m.Priority() == module.PriorityCritical {
			fmt.Printf("      critical module failed — aborting profile\n")
			break
		}

		// Check total budget after each module.
		if time.Since(started) > p.TotalBudget {
			fmt.Printf("      profile total budget exceeded — aborting\n")
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
