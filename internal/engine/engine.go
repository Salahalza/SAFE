package engine

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/Salahalza/SAFE/internal/manifest"
	"github.com/Salahalza/SAFE/internal/module"
	"github.com/Salahalza/SAFE/internal/profile"
	"github.com/Salahalza/SAFE/internal/vss"
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

	// SourceRoot, when non-empty, switches the engine into dead-image mode: it
	// collects from this read-only-mounted disk-image volume root (e.g. "E:\")
	// instead of the live host. In this mode no VSS shadow is created (the image
	// is already a static snapshot) and modules that require a live host are
	// skipped. Empty means a normal live collection.
	SourceRoot string

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

	// EvidenceSource records where this case's evidence came from: "live" for a
	// running host, or "disk_image" for a mounted dead disk image.
	EvidenceSource string `json:"evidence_source,omitempty"`
	// SourceRoot is the mounted image volume root the collection read from, when
	// EvidenceSource is "disk_image". Empty for a live case.
	SourceRoot string `json:"source_root,omitempty"`
}

func (e *Engine) Run(p *profile.Profile) CaseResult {
	started := time.Now().UTC()
	result := CaseResult{
		CaseDir:     e.CaseDir,
		ProfileName: p.Name,
		StartedAt:   started,
		Modules:     []module.Result{},
	}

	// Determine the evidence source. In dead-image mode the engine reads from a
	// pre-mounted, read-only image volume instead of the live host: no VSS shadow
	// is taken (the image is already static) and live-only modules are skipped.
	imageMode := e.SourceRoot != ""
	live := !imageMode
	if imageMode {
		result.EvidenceSource = "disk_image"
		result.SourceRoot = e.SourceRoot
	} else {
		result.EvidenceSource = "live"
	}

	e.emitOrPrint(ProgressEvent{Kind: EventCaseStart, TotalCount: len(p.Modules)},
		fmt.Sprintf("Profile: %s (v%s) — %s\nTotal budget: %s\n\n",
			p.Name, p.Version, p.Description, p.TotalBudget))

	profileCtx, profileCancel := context.WithTimeout(context.Background(), p.TotalBudget)
	defer profileCancel()

	// Evaluate module applicability once, up front, before anything runs. A
	// role-specific module (e.g. ad_collection on a non-DC) declares itself not
	// applicable via the optional Applicable interface; it is then cleanly
	// skipped and must not force VSS creation or count as a failure. Applies is
	// evaluated here, before any shadow exists, so implementations rely only on
	// live host state (the registry), never on ctx.Shadow.
	applies := make([]bool, len(p.Modules))
	skipReason := make([]string, len(p.Modules))
	for i, m := range p.Modules {
		applies[i] = true
		if a, ok := m.(module.Applicable); ok {
			applies[i], skipReason[i] = a.Applies(&module.Context{Ctx: profileCtx, Root: e.SourceRoot, Live: live})
		}
	}

	// Determine if any APPLICABLE module needs VSS. If so, create one shadow for
	// the case. A not-applicable VSS module (e.g. ad_collection on a member
	// server) must not trigger shadow creation on its own. In dead-image mode no
	// shadow is ever created — the image is already a static point-in-time copy,
	// and its evidence root is e.SourceRoot.
	var sharedShadow *vss.Shadow
	var shadowErr error

	if !imageMode && anyModuleRequiresVSS(p.Modules, applies) {
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

	// Root is the filesystem root modules resolve target paths against. In
	// dead-image mode it is the mounted image volume; in live mode it is the
	// shared shadow's mount (empty if shadow creation failed, which skips
	// root-requiring modules below).
	rootPath := e.SourceRoot
	if !imageMode {
		rootPath = ""
		if sharedShadow != nil {
			rootPath = sharedShadow.MountedPath
		}
	}

	// In dead-image mode, set up a raw-NTFS reader over the mounted volume so
	// collectors read file content directly off the volume's clusters, bypassing
	// on-access AV/EDR that would otherwise block reading flagged evidence (a web
	// shell, a dropped tool) from a compromised image. If the source root is not a
	// raw drive-letter volume or the volume can't be opened, fall back to OS reads
	// and warn that AV may interfere.
	var imgReader *module.ImageReader
	if imageMode {
		r, err := module.NewImageReader(e.SourceRoot)
		if err != nil {
			if e.ProgressCh == nil {
				fmt.Printf("WARNING: raw-NTFS reader unavailable (%v).\n"+
					"         The image is not mounted as a raw block volume, so $MFT/$UsnJrnl cannot be\n"+
					"         collected and file reads fall back to the OS filesystem (on-access AV/EDR may\n"+
					"         block flagged evidence). Re-mount as a BLOCK DEVICE / raw volume — not a\n"+
					"         file-system mount — and run elevated. In FTK Imager: Mount Method =\n"+
					"         'Block Device / Read Only'.\n\n", err)
			}
		} else {
			imgReader = r
			defer imgReader.Close()
			if e.ProgressCh == nil {
				fmt.Printf("Dead-image reads use raw NTFS on %s (bypasses on-access AV/EDR).\n\n", imgReader.Volume())
			}
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

		// If this module declared itself not applicable to this target, skip it
		// cleanly. This is a normal outcome (e.g. an AD collector on a non-DC),
		// not a failure — it does not degrade the case.
		if !applies[i] {
			started := time.Now().UTC()
			modResult := module.Result{
				ModuleName: m.Name(),
				Status:     module.StatusSkipped,
				StartedAt:  started,
				EndedAt:    started,
				Duration:   0,
				Artifacts:  []module.Artifact{},
				Findings:   []module.Finding{},
			}
			modResult.AddInfo(m.Name(), "not applicable to this target: "+skipReason[i])
			result.Modules = append(result.Modules, modResult)
			e.emitOrPrint(
				ProgressEvent{
					Kind:        EventModuleDone,
					ModuleIndex: i,
					ModuleName:  m.Name(),
					TotalCount:  len(p.Modules),
					Result:      modResult,
				},
				fmt.Sprintf("      status=skipped reason=not applicable (%s)\n", skipReason[i]),
			)
			continue
		}

		// In dead-image mode, skip any module that can only collect from a live
		// host (volatile state or live OS commands). Running it would capture the
		// analyst's own workstation, not the imaged host — a silent case
		// contamination. This is a clean skip, not a failure.
		if imageMode && requiresLiveHost(m) {
			started := time.Now().UTC()
			modResult := module.Result{
				ModuleName: m.Name(),
				Status:     module.StatusSkipped,
				StartedAt:  started,
				EndedAt:    started,
				Duration:   0,
				Artifacts:  []module.Artifact{},
				Findings:   []module.Finding{},
			}
			modResult.AddInfo(m.Name(), "not applicable to a disk image: module requires a live host")
			result.Modules = append(result.Modules, modResult)
			e.emitOrPrint(
				ProgressEvent{
					Kind:        EventModuleDone,
					ModuleIndex: i,
					ModuleName:  m.Name(),
					TotalCount:  len(p.Modules),
					Result:      modResult,
				},
				"      status=skipped reason=requires a live host (disk-image source)\n",
			)
			continue
		}

		// If this module requires an evidence root but none is available (live
		// shadow creation failed), skip it with a clear failure record.
		if m.RequiresVSS() && rootPath == "" {
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
			Root:      rootPath,
			Live:      live,
			Image:     imgReader,
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

// anyModuleRequiresVSS returns true if any APPLICABLE module in the list needs
// VSS. applies[i] gates module i: a module that declared itself not applicable
// to this target must not trigger shadow creation.
func anyModuleRequiresVSS(mods []module.Module, applies []bool) bool {
	for i, m := range mods {
		if applies[i] && m.RequiresVSS() {
			return true
		}
	}
	return false
}

// requiresLiveHost reports whether a module declared itself live-only via the
// optional LiveOnly interface. A module that does not implement it is assumed to
// work against any evidence root (live shadow or mounted image).
func requiresLiveHost(m module.Module) bool {
	if lo, ok := m.(module.LiveOnly); ok {
		return lo.RequiresLiveHost()
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
