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

	// ProgressCh, if set, receives ProgressEvent values as collection runs.
	// If nil, the engine prints progress to stdout (CLI mode).
	ProgressCh chan<- ProgressEvent
}

// ProgressEvent is one update emitted during collection.
type ProgressEvent struct {
	Kind        EventKind
	ModuleIndex int // 0-based
	ModuleName  string
	TotalCount  int           // total number of modules in the profile
	Result      module.Result // populated for EventModuleDone
	Duration    time.Duration // populated for EventCaseDone (total elapsed)
	Status      string        // populated for EventCaseDone ("success" / "partial" / "degraded")
}

// EventKind identifies the type of progress event.
type EventKind int

const (
	EventCaseStart EventKind = iota
	EventModuleStart
	EventModuleDone
	EventCaseDone
)

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

	e.emitOrPrint(ProgressEvent{Kind: EventCaseStart, TotalCount: len(p.Modules)},
		fmt.Sprintf("Profile: %s (v%s) — %s\nTotal budget: %s\n\n", p.Name, p.Version, p.Description, p.TotalBudget))

	profileCtx, profileCancel := context.WithTimeout(context.Background(), p.TotalBudget)
	defer profileCancel()

	for i, m := range p.Modules {
		e.emitOrPrint(
			ProgressEvent{
				Kind:        EventModuleStart,
				ModuleIndex: i,
				ModuleName:  m.Name(),
				TotalCount:  len(p.Modules),
			},
			fmt.Sprintf("[%d/%d] Running module: %s (priority=%s, budget=%s)\n",
				i+1, len(p.Modules), m.Name(), m.Priority(), m.TimeBudget()),
		)

		moduleDir := filepath.Join(
			e.CaseDir,
			"modules",
			fmt.Sprintf("%02d_%s", i+1, m.Name()),
		)

		modCtx, modCancel := context.WithTimeout(profileCtx, m.TimeBudget())

		ctx := &module.Context{
			OutputDir: moduleDir,
			Ctx:       modCtx,
		}

		modResult := runModuleWithWatchdog(m, ctx, m.TimeBudget())
		modCancel()

		result.Modules = append(result.Modules, modResult)

		info, warning, critical := modResult.CountBySeverity()
		e.emitOrPrint(
			ProgressEvent{
				Kind:        EventModuleDone,
				ModuleIndex: i,
				ModuleName:  m.Name(),
				TotalCount:  len(p.Modules),
				Result:      modResult,
			},
			fmt.Sprintf("      status=%s duration=%s artifacts=%d info=%d warning=%d critical=%d errors=%d\n",
				modResult.Status, modResult.Duration,
				len(modResult.Artifacts), info, warning, critical, len(modResult.Errors)),
		)

		if _, err := manifest.WriteModuleManifest(moduleDir, m.Name()); err != nil {
			if e.ProgressCh == nil {
				fmt.Printf("      warning: failed to write module manifest: %v\n", err)
			}
		}

		if modResult.Status == module.StatusFailed && m.Priority() == module.PriorityCritical {
			if e.ProgressCh == nil {
				fmt.Printf("      critical module failed — aborting profile\n")
			}
			break
		}
		if modResult.Status == module.StatusTimedOut && m.Priority() == module.PriorityCritical {
			if e.ProgressCh == nil {
				fmt.Printf("      critical module timed out — aborting profile\n")
			}
			break
		}

		if profileCtx.Err() != nil {
			if e.ProgressCh == nil {
				fmt.Printf("      profile total budget exceeded — aborting\n")
			}
			break
		}
	}

	result.EndedAt = time.Now().UTC()
	result.Duration = result.EndedAt.Sub(started)
	result.Status = summarize(result.Modules)

	e.emitOrPrint(
		ProgressEvent{
			Kind:     EventCaseDone,
			Duration: result.Duration,
			Status:   result.Status,
		},
		"",
	)

	return result
}

// emitOrPrint sends event to the progress channel if set, otherwise prints
// the provided fallback string to stdout (CLI mode).
func (e *Engine) emitOrPrint(event ProgressEvent, cliFallback string) {
	if e.ProgressCh != nil {
		e.ProgressCh <- event
		return
	}
	if cliFallback != "" {
		fmt.Print(cliFallback)
	}
}

func runModuleWithWatchdog(m module.Module, ctx *module.Context, budget time.Duration) module.Result {
	resultCh := make(chan module.Result, 1)
	started := time.Now().UTC()

	go func() {
		resultCh <- m.Run(ctx)
	}()

	hardCeiling := budget + 10*time.Second

	select {
	case res := <-resultCh:
		return res
	case <-time.After(hardCeiling):
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
