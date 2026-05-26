package engine

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"sahm/internal/manifest"
	"sahm/internal/module"
	"sahm/internal/profile"
)

type Engine struct {
	CaseDir string
}

func New(caseDir string) *Engine {
	return &Engine{CaseDir: caseDir}
}

type CaseResult struct {
	CaseDir     string          `json:"case_dir"`
	ProfileName string          `json:"profile_name"`
	StartedAt   time.Time       `json:"started_at"`
	EndedAt     time.Time       `json:"ended_at"`
	Duration    time.Duration   `json:"duration_ns"`
	Modules     []module.Result `json:"modules"`
	Status      string          `json:"status"`
}

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

	// Profile-level context with total budget timeout.
	profileCtx, profileCancel := context.WithTimeout(context.Background(), p.TotalBudget)
	defer profileCancel()

	for i, m := range p.Modules {
		fmt.Printf("[%d/%d] Running module: %s (priority=%s, budget=%s)\n",
			i+1, len(p.Modules), m.Name(), m.Priority(), m.TimeBudget())

		moduleDir := filepath.Join(
			e.CaseDir,
			"modules",
			fmt.Sprintf("%02d_%s", i+1, m.Name()),
		)

		// Module-level context with per-module timeout, derived from profile context.
		modCtx, modCancel := context.WithTimeout(profileCtx, m.TimeBudget())

		ctx := &module.Context{
			OutputDir: moduleDir,
			Ctx:       modCtx,
		}

		modResult := runModuleWithWatchdog(m, ctx, m.TimeBudget())
		modCancel()

		result.Modules = append(result.Modules, modResult)

		fmt.Printf("      status=%s duration=%s artifacts=%d warnings=%d errors=%d\n",
			modResult.Status, modResult.Duration,
			len(modResult.Artifacts), len(modResult.Warnings), len(modResult.Errors))

		if _, err := manifest.WriteModuleManifest(moduleDir, m.Name()); err != nil {
			fmt.Printf("      warning: failed to write module manifest: %v\n", err)
		}

		// Priority-based abort logic.
		if modResult.Status == module.StatusFailed && m.Priority() == module.PriorityCritical {
			fmt.Printf("      critical module failed — aborting profile\n")
			break
		}
		if modResult.Status == module.StatusTimedOut && m.Priority() == module.PriorityCritical {
			fmt.Printf("      critical module timed out — aborting profile\n")
			break
		}

		// Profile-level budget check.
		if profileCtx.Err() != nil {
			fmt.Printf("      profile total budget exceeded — aborting\n")
			break
		}
	}

	result.EndedAt = time.Now().UTC()
	result.Duration = result.EndedAt.Sub(started)
	result.Status = summarize(result.Modules)

	return result
}

// runModuleWithWatchdog runs m.Run in a goroutine and enforces the time budget
// with a hard ceiling. If the module exceeds the budget, the context is cancelled,
// which propagates to any exec.CommandContext calls inside the module.
//
// Note: this only enforces cancellation for code paths that honor ctx.Done().
// A module that ignores its context can still block forever — design contract
// requires modules to respect ctx.Done().
func runModuleWithWatchdog(m module.Module, ctx *module.Context, budget time.Duration) module.Result {
	resultCh := make(chan module.Result, 1)
	started := time.Now().UTC()

	go func() {
		resultCh <- m.Run(ctx)
	}()

	// Hard ceiling slightly beyond the budget — gives the module a brief grace
	// period to clean up after context cancellation.
	hardCeiling := budget + 10*time.Second

	select {
	case res := <-resultCh:
		return res
	case <-time.After(hardCeiling):
		// Module exceeded even the grace period. Return a synthetic timeout result.
		// The goroutine still leaks until the module returns, but the engine moves on.
		return module.Result{
			ModuleName: m.Name(),
			Status:     module.StatusTimedOut,
			StartedAt:  started,
			EndedAt:    time.Now().UTC(),
			Duration:   time.Since(started),
			Errors:     []string{fmt.Sprintf("module exceeded hard ceiling of %s (budget was %s)", hardCeiling, budget)},
			Artifacts:  []module.Artifact{},
		}
	}
}

func summarize(results []module.Result) string {
	hasFailed := false
	hasPartial := false
	hasTimedOut := false
	for _, r := range results {
		switch r.Status {
		case module.StatusFailed:
			hasFailed = true
		case module.StatusPartial:
			hasPartial = true
		case module.StatusTimedOut:
			hasTimedOut = true
		}
	}
	switch {
	case hasFailed || hasTimedOut:
		return "degraded"
	case hasPartial:
		return "partial"
	default:
		return "success"
	}
}
