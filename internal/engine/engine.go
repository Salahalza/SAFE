package engine

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"safe/internal/manifest"
	"safe/internal/module"
	"safe/internal/profile"
	"safe/internal/vss"
)

// ASCIIBar renders a fixed-width ASCII progress bar with a trailing percentage,
// e.g. "[######--------------]  30%". ASCII-only (no Unicode blocks) so it
// renders correctly on plain Windows PowerShell, matching the TUI's ASCII
// status markers. Shared by the CLI collection output, the TUI collection and
// analyze screens, and the CLI analyzer so every progress display looks alike.
func ASCIIBar(done, total, width int) string {
	if total <= 0 {
		total = 1
	}
	if done < 0 {
		done = 0
	}
	if done > total {
		done = total
	}
	frac := float64(done) / float64(total)
	filled := int(frac*float64(width) + 0.5)
	if filled > width {
		filled = width
	}
	pct := int(frac*100 + 0.5)
	return fmt.Sprintf("[%s%s] %3d%%", strings.Repeat("#", filled), strings.Repeat("-", width-filled), pct)
}

type Engine struct {
	CaseDir string

	// ProgressCh, if set, receives ProgressEvent values as collection runs.
	// If nil, the engine prints progress to stdout (CLI mode).
	ProgressCh chan<- ProgressEvent
}

type ProgressEvent struct {
	Kind        EventKind
	ModuleIndex int
	ModuleName  string
	TotalCount  int
	Result      module.Result
	Duration    time.Duration
	Status      string

	// Intra-module progress (Kind == EventModuleProgress): SubDone/SubTotal are
	// work units processed within the current module (files or commands);
	// SubBytes is cumulative bytes written so far by this module.
	SubDone  int
	SubTotal int
	SubBytes int64
}

type EventKind int

const (
	EventCaseStart EventKind = iota
	EventModuleStart
	EventModuleProgress
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
	ShadowID    string          `json:"shadow_id,omitempty"`
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
		fmt.Sprintf("Profile: %s (v%s) — %s\nTotal budget: %s\n\n",
			p.Name, p.Version, p.Description, p.TotalBudget))

	profileCtx, profileCancel := context.WithTimeout(context.Background(), p.TotalBudget)
	defer profileCancel()

	// Determine if any module needs VSS. If so, create one shadow for the case.
	var sharedShadow *vss.Shadow
	var shadowErr error

	if anyModuleRequiresVSS(p.Modules) {
		if e.ProgressCh == nil {
			fmt.Println("Creating Volume Shadow Copy for locked-file access...")
		}
		// Use a generous timeout for shadow creation (up to 60s on busy systems).
		shadowCtx, shadowCancel := context.WithTimeout(profileCtx, 60*time.Second)
		sharedShadow, shadowErr = vss.CreateShadowWithContext(shadowCtx, "C:")
		shadowCancel()

		if shadowErr != nil {
			if e.ProgressCh == nil {
				fmt.Printf("WARNING: VSS shadow creation failed: %v\n", shadowErr)
				fmt.Println("VSS-dependent modules will be skipped.")
			}
		} else {
			result.ShadowID = sharedShadow.ShadowID
			if e.ProgressCh == nil {
				fmt.Printf("Shadow created: %s -> %s\n\n",
					sharedShadow.ShadowID, sharedShadow.MountedPath)
			}
			// Ensure cleanup runs regardless of how Run exits.
			defer func() {
				if err := sharedShadow.Cleanup(); err != nil {
					if e.ProgressCh == nil {
						fmt.Printf("WARNING: shadow cleanup error: %v\n", err)
					}
				}
			}()
		}
	}

	for i, m := range p.Modules {
		e.emitOrPrint(
			ProgressEvent{
				Kind:        EventModuleStart,
				ModuleIndex: i,
				ModuleName:  m.Name(),
				TotalCount:  len(p.Modules),
			},
			fmt.Sprintf("%s  [%d/%d] Running module: %s (priority=%s, budget=%s)\n",
				ASCIIBar(i, len(p.Modules), 20), i+1, len(p.Modules), m.Name(), m.Priority(), m.TimeBudget()),
		)

		// If this module requires VSS but shadow creation failed, skip it
		// with a clear failure record.
		if m.RequiresVSS() && sharedShadow == nil {
			started := time.Now().UTC()
			modResult := module.Result{
				ModuleName: m.Name(),
				Status:     module.StatusFailed,
				StartedAt:  started,
				EndedAt:    started,
				Duration:   0,
				Artifacts:  []module.Artifact{},
				Findings:   []module.Finding{},
				Errors: []string{
					fmt.Sprintf("module requires VSS but shadow creation failed: %v", shadowErr),
				},
			}
			result.Modules = append(result.Modules, modResult)
			e.emitOrPrint(
				ProgressEvent{
					Kind:        EventModuleDone,
					ModuleIndex: i,
					ModuleName:  m.Name(),
					TotalCount:  len(p.Modules),
					Result:      modResult,
				},
				"      status=skipped reason=VSS unavailable\n",
			)
			continue
		}

		moduleDir := filepath.Join(
			e.CaseDir,
			"modules",
			fmt.Sprintf("%02d_%s", i+1, m.Name()),
		)

		modCtx, modCancel := context.WithTimeout(profileCtx, m.TimeBudget())

		// Intra-module progress reporter. Forwards file/byte progress to the UI,
		// time-throttled so a module copying thousands of files doesn't flood
		// the channel; the final (done==total) report always goes through so the
		// bar completes the module. CLI mode (ProgressCh nil) prints nothing for
		// these — the per-module step bar already covers it.
		idx, total := i, len(p.Modules)
		var lastEmit time.Time
		progressFn := func(done, subTotal int, bytes int64) {
			now := time.Now()
			if done < subTotal && now.Sub(lastEmit) < 60*time.Millisecond {
				return
			}
			lastEmit = now
			e.emitOrPrint(ProgressEvent{
				Kind:        EventModuleProgress,
				ModuleIndex: idx,
				ModuleName:  m.Name(),
				TotalCount:  total,
				SubDone:     done,
				SubTotal:    subTotal,
				SubBytes:    bytes,
			}, "")
		}

		ctx := &module.Context{
			OutputDir: moduleDir,
			Ctx:       modCtx,
			Shadow:    sharedShadow,
			Progress:  progressFn,
		}

		modResult := runModuleWithWatchdog(m, ctx, m.TimeBudget())
		modCancel()

		// Write the per-module SHA-256 manifest immediately. The case-level
		// manifest is built by globbing these module.json files, so if this write
		// fails the module's artifacts never roll up into the case manifest and
		// escape the integrity contract entirely. A silent log line is not enough:
		// surface it on the result and degrade a clean success to partial so the
		// case never reports "success" over unhashed evidence.
		if _, err := manifest.WriteModuleManifest(moduleDir, m.Name()); err != nil {
			modResult.Errors = append(modResult.Errors,
				fmt.Sprintf("module manifest write failed — artifacts not hashed at case level: %v", err))
			if modResult.Status == module.StatusSuccess {
				modResult.Status = module.StatusPartial
			}
			if e.ProgressCh == nil {
				fmt.Printf("      warning: failed to write module manifest: %v\n", err)
			}
		}

		result.Modules = append(result.Modules, modResult)

		info, warning, critical := modResult.CountBySeverity()
		statusLine := fmt.Sprintf("      status=%s duration=%s artifacts=%d",
			modResult.Status, modResult.Duration, len(modResult.Artifacts))
		if modResult.BulkFiles > 0 {
			statusLine += fmt.Sprintf(" bulk_files=%d", modResult.BulkFiles)
		}
		statusLine += fmt.Sprintf(" info=%d warning=%d critical=%d errors=%d\n",
			info, warning, critical, len(modResult.Errors))

		e.emitOrPrint(
			ProgressEvent{
				Kind:        EventModuleDone,
				ModuleIndex: i,
				ModuleName:  m.Name(),
				TotalCount:  len(p.Modules),
				Result:      modResult,
			},
			statusLine,
		)

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

// anyModuleRequiresVSS returns true if any module in the list needs VSS.
func anyModuleRequiresVSS(mods []module.Module) bool {
	for _, m := range mods {
		if m.RequiresVSS() {
			return true
		}
	}
	return false
}

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
		// Recover from a module panic so one misbehaving module degrades to a
		// failed result instead of crashing the whole process. A crash here would
		// be especially damaging: the deferred VSS shadow cleanup lives on Run's
		// goroutine, so a panic on this goroutine would unwind past it and leak
		// the shadow, and no manifest/result would be written for the case.
		// resultCh is buffered (cap 1) so this send never blocks even if the
		// watchdog has already returned on the hard-ceiling path.
		defer func() {
			if r := recover(); r != nil {
				resultCh <- module.Result{
					ModuleName: m.Name(),
					Status:     module.StatusFailed,
					StartedAt:  started,
					EndedAt:    time.Now().UTC(),
					Duration:   time.Since(started),
					Errors:     []string{fmt.Sprintf("module panicked: %v", r)},
					Artifacts:  []module.Artifact{},
					Findings:   []module.Finding{},
				}
			}
		}()
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
