package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Salahalza/SAFE/internal/casemeta"
	"github.com/Salahalza/SAFE/internal/engine"
	"github.com/Salahalza/SAFE/internal/manifest"
	"github.com/Salahalza/SAFE/internal/pathfinder"
	"github.com/Salahalza/SAFE/internal/preflight"
	"github.com/Salahalza/SAFE/internal/profile"
	"github.com/Salahalza/SAFE/internal/tui"
	"github.com/Salahalza/SAFE/internal/vss"
)

const safeVersion = "0.1.0"

func main() {
	var (
		caseID         = flag.String("case", "", "Case identifier (e.g. INC-2026-0418). Required unless --tui.")
		analyst        = flag.String("analyst", "", "Analyst name or initials. Required unless --tui.")
		target         = flag.String("target", "", "Target identifier (hostname, asset tag, IP). Required unless --tui.")
		targetClass    = flag.String("target-class", "unknown", "Target class: workstation, server, or unknown.")
		profileName    = flag.String("profile", "rapid_triage", "Profile to run.")
		outputDir      = flag.String("output", "./test-output", "Output base directory.")
		notes          = flag.String("notes", "", "Optional analyst notes.")
		listProfiles   = flag.Bool("list-profiles", false, "List available profiles and exit.")
		skipPreflight  = flag.Bool("skip-preflight", false, "Skip preflight checks (advanced use only).")
		tuiMode        = flag.Bool("tui", false, "Launch the interactive terminal UI.")
		dryRun         = flag.Bool("dry-run", false, "Validate environment without performing collection.")
		cleanupShadows = flag.Bool("cleanup-shadows", false, "Clean up SAFE-created shadow copies left from previous interrupted runs, then exit.")
		irNumber       = flag.String("ir", "", "Optional IR ticket number (format: IR-####-####).")
		csiNumber      = flag.String("csi", "", "Optional CSI ticket number (format: CSI-######).")
		versionFlag    = flag.Bool("version", false, "Print the SAFE version and exit.")
		sourceRoot     = flag.String("source-root", "", "Analyze a mounted dead disk image instead of the live host. Give the read-only-mounted image volume root (e.g. E:\\ or a directory). Skips VSS and live-only modules; defaults the profile to disk_image.")
		sourceImage    = flag.String("source-image", "", "Optional path to the original disk-image file (E01/VHDX/raw) the --source-root volume was mounted from. Recorded in case.json for chain of custody.")
	)

	flag.Parse()

	// When collecting from a mounted image, default the profile to disk_image
	// unless the analyst explicitly chose one. Detect an explicit -profile via
	// flag.Visit (the flag package has no "was set" query otherwise).
	profileExplicit := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "profile" {
			profileExplicit = true
		}
	})
	if *sourceRoot != "" && !profileExplicit {
		*profileName = "disk_image"
	}

	if *versionFlag {
		fmt.Printf("SAFE Collector v%s\n", safeVersion)
		os.Exit(0)
	}

	if flag.NFlag() == 0 && flag.NArg() == 0 {
		*tuiMode = true
	}

	// --cleanup-shadows: explicit cleanup mode, run and exit.
	if *cleanupShadows {
		runShadowCleanup()
		os.Exit(0)
	}

	registry := profile.NewRegistry()
	if err := profile.RegisterDefaults(registry); err != nil {
		fatalf("failed to register profiles: %v", err)
	}

	if *listProfiles {
		fmt.Println("Available profiles:")
		for _, name := range registry.Names() {
			p, _ := registry.Get(name)
			fmt.Printf("  %s (v%s) — %s\n", p.Name, p.Version, p.Description)
		}
		os.Exit(0)
	}

	if !*skipPreflight {
		// Resolve the selected profile's class so the role check can tell whether
		// a server-role target is being collected with a server-appropriate
		// profile. In TUI mode the profile is chosen interactively after this
		// point, so this reflects the default; the form itself surfaces any
		// class/target mismatch there.
		selectedProfileClass := ""
		if p, err := registry.Get(*profileName); err == nil {
			selectedProfileClass = string(p.Class)
		}
		checks := []preflight.Check{
			&preflight.OSCheck{},
			&preflight.AdminCheck{},
			&preflight.DiskCheck{OutputPath: *outputDir},
		}
		// The target-role check compares the LIVE host's roles against the
		// profile's class. That is meaningless when collecting from a mounted
		// image (the imaged host's role has nothing to do with the analyst's
		// box), so skip it in image mode.
		if *sourceRoot == "" {
			checks = append(checks, &preflight.TargetRoleCheck{ProfileClass: selectedProfileClass})
		}
		report := preflight.Run(checks)
		if len(report.Findings) > 0 {
			fmt.Print(report.Format())
			fmt.Println()
		}
		if report.HasCritical() {
			fmt.Fprintln(os.Stderr, "Preflight failed with critical findings. Fix the issues above, or rerun with --skip-preflight to override.")
			os.Exit(2)
		}
	}

	// Silently clean orphan SAFE shadows before an actual collection, guarding
	// against interrupted-run leaks. This is a mutating VSS operation, so it must
	// NOT run for the documented read-only flags: --list-profiles has already
	// exited above, and --dry-run is excluded here (it is handled further down).
	// Previously this ran unconditionally at startup, so both read-only flags
	// deleted host shadows before doing their read-only work.
	if !*dryRun {
		runAutoShadowCleanup()
	}

	// --- TUI mode: collection runs inside the TUI ---
	if *tuiMode {
		populateTUIProfiles(registry)

		runFn := func(c *casemeta.Case, p *profile.Profile, progressCh chan<- engine.ProgressEvent) engine.CaseResult {
			c.SAFEVersion = safeVersion
			c.ProfileVersion = p.Version
			caseDir := filepath.Join(*outputDir, c.CaseDirName())
			_ = c.WriteToCase(caseDir)
			eng := engine.New(caseDir)
			eng.ProgressCh = progressCh
			result := eng.Run(p)

			// Rewrite case.json now that the run is done, recording the shadow ID
			// (audit trail, principle #3) and end time that weren't known up front.
			c.ShadowID = result.ShadowID
			c.EndedAt = result.EndedAt
			_ = c.WriteToCase(caseDir)

			resultPath := filepath.Join(caseDir, "result.json")
			if data, err := json.MarshalIndent(result, "", "  "); err == nil {
				_ = os.WriteFile(resultPath, data, 0o644)
			}
			summary := buildCaseSummary(c, result, safeVersion, p.Version, caseDir)
			_ = manifest.WriteCaseReport(caseDir, summary)
			_ = manifest.WriteCaseManifest(caseDir, c.CaseID)
			return result
		}

		runRes, err := tui.RunWithCollection(registry, runFn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "TUI error: %v\n", err)
			os.Exit(1)
		}
		if runRes == nil {
			fmt.Println("Collection cancelled.")
			os.Exit(0)
		}
		if runRes.Collection != nil {
			switch runRes.Collection.Result.Status {
			case "failed":
				os.Exit(1)
			case "degraded":
				os.Exit(3)
			default:
				os.Exit(0)
			}
		}
		os.Exit(0)
	}

	// --- CLI mode: build case from flags ---
	c := &casemeta.Case{
		CaseID:           *caseID,
		IRNumber:         *irNumber,
		CSINumber:        *csiNumber,
		Analyst:          *analyst,
		TargetIdentifier: *target,
		TargetClass:      *targetClass,
		Notes:            *notes,
		ProfileName:      *profileName,
		CreatedAt:        time.Now().UTC(),
		SAFEVersion:      safeVersion,
	}
	if *sourceRoot != "" {
		c.EvidenceSource = "disk_image"
		c.SourceRoot = *sourceRoot
		c.SourceImage = *sourceImage
	}

	p, _ := registry.Get(c.ProfileName)


	// --- dry-run ---
	if *dryRun {
		passed := runDryRun(c, p, *outputDir, *skipPreflight)
		if passed {
			os.Exit(0)
		}
		os.Exit(2)
	}

	if err := c.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
		flag.Usage()
		os.Exit(2)
	}


	if p == nil {
		fmt.Fprintf(os.Stderr, "Error: profile %q not found\n", c.ProfileName)
		fmt.Fprintf(os.Stderr, "Run with --list-profiles to see available profiles.\n")
		os.Exit(2)
	}

	caseDir := filepath.Join(*outputDir, c.CaseDirName())

	fmt.Printf("SAFE v%s — System for Artifacts Forensic and Examination\n", safeVersion)
	fmt.Println()
	fmt.Printf("Case ID:    %s\n", c.CaseID)
	if c.IRNumber != "" {
		fmt.Printf("IR#:        %s\n", c.IRNumber)
	}
	if c.CSINumber != "" {
		fmt.Printf("CSI#:       %s\n", c.CSINumber)
	}
	fmt.Printf("Analyst:    %s\n", c.Analyst)
	fmt.Printf("Target:     %s (%s)\n", c.TargetIdentifier, c.TargetClass)
	fmt.Printf("Profile:    %s\n", c.ProfileName)
	if c.EvidenceSource == "disk_image" {
		fmt.Printf("Source:     dead disk image mounted at %s\n", c.SourceRoot)
		if c.SourceImage != "" {
			fmt.Printf("Image file: %s\n", c.SourceImage)
		}
	}
	fmt.Printf("Output:     %s\n", caseDir)
	if c.Notes != "" {
		fmt.Printf("Notes:      %s\n", c.Notes)
	}
	fmt.Println()

	c.ProfileVersion = p.Version
	if err := c.WriteToCase(caseDir); err != nil {
		fatalf("write case metadata: %v", err)
	}

	eng := engine.New(caseDir)
	eng.SourceRoot = *sourceRoot
	result := eng.Run(p)

	// Rewrite case.json now that the run is done, recording the shadow ID
	// (audit trail, principle #3) and end time that weren't known up front.
	c.ShadowID = result.ShadowID
	c.EndedAt = result.EndedAt
	if err := c.WriteToCase(caseDir); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to rewrite case.json: %v\n", err)
	}

	fmt.Println()
	fmt.Printf("Final status:  %s\n", result.Status)
	fmt.Printf("Duration:      %s\n", result.Duration)

	resultPath := filepath.Join(caseDir, "result.json")
	data, _ := json.MarshalIndent(result, "", "  ")
	if err := os.WriteFile(resultPath, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to write result.json: %v\n", err)
	}

	summary := buildCaseSummary(c, result, safeVersion, p.Version, caseDir)
	if err := manifest.WriteCaseReport(caseDir, summary); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to write case report: %v\n", err)
	} else {
		fmt.Printf("Report:        %s\n", filepath.Join(caseDir, "case_report.txt"))
	}

	if err := manifest.WriteCaseManifest(caseDir, c.CaseID); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to write case manifest: %v\n", err)
	} else {
		fmt.Printf("Manifest:      %s\n", filepath.Join(caseDir, "manifest.json"))
		fmt.Printf("SHA256 file:   %s\n", filepath.Join(caseDir, "manifest.sha256"))
	}

	fmt.Printf("Result file:   %s\n", resultPath)
	fmt.Printf("Case folder:   %s\n", caseDir)

	switch result.Status {
	case "failed":
		os.Exit(1)
	case "degraded":
		os.Exit(3)
	default:
		os.Exit(0)
	}
}

func populateTUIProfiles(r *profile.Registry) {
	names := r.Names()
	opts := make([]tui.ProfileOption, 0, len(names))
	for _, n := range names {
		p, _ := r.Get(n)
		opts = append(opts, tui.ProfileOption{
			Value: p.Name,
			Label: p.Description,
			Class: string(p.Class),
		})
	}
	if len(opts) > 0 {
		tui.AvailableProfiles = opts
	}
}

func buildCaseSummary(c *casemeta.Case, result engine.CaseResult, version, profileVersion, caseDir string) manifest.CaseSummary {
	mods := make([]manifest.ModuleSummary, 0, len(result.Modules))
	for _, m := range result.Modules {
		findings := make([]manifest.FindingSummary, 0, len(m.Findings))
		for _, f := range m.Findings {
			findings = append(findings, manifest.FindingSummary{
				Severity: string(f.Severity),
				Source:   f.Source,
				Message:  f.Message,
			})
		}
		mods = append(mods, manifest.ModuleSummary{
			Name:          m.ModuleName,
			Status:        string(m.Status),
			Duration:      m.Duration,
			ArtifactCount: len(m.Artifacts),
			BulkFiles:     m.BulkFiles,
			Findings:      findings,
			Errors:        m.Errors,
		})
	}
	return manifest.CaseSummary{
		CaseID:         c.CaseID,
		IRNumber:       c.IRNumber,
		CSINumber:      c.CSINumber,
		Analyst:        c.Analyst,
		Target:         c.TargetIdentifier,
		TargetClass:    c.TargetClass,
		Notes:          c.Notes,
		Profile:        c.ProfileName,
		ProfileVersion: profileVersion,
		SAFEVersion:    version,
		CollectedHost:  collectedHostname(caseDir),
		ShadowID:       result.ShadowID,
		TotalBytes:     caseModuleBytes(caseDir),
		StartedAt:      result.StartedAt,
		EndedAt:        result.EndedAt,
		Duration:       result.Duration,
		Status:         result.Status,
		Modules:        mods,
	}
}

// caseModuleBytes returns the total size on disk of all collected module
// artifacts (everything under <caseDir>/modules). Computed by walking the
// filesystem rather than summing reported artifact sizes, so it stays accurate
// even for bulk-collected files whose individual sizes the result does not
// carry. Best-effort: returns what it can sum, ignoring walk errors.
func caseModuleBytes(caseDir string) int64 {
	var total int64
	modulesDir := filepath.Join(caseDir, "modules")
	_ = filepath.Walk(modulesDir, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return total
}

// collectedHostname returns the hostname captured by the system_metadata
// module, distinct from the analyst's free-text target label. Best-effort:
// returns "" if the artifact is absent or unreadable. The module index prefix
// (e.g. 04_) varies by profile, so the directory is matched by glob.
func collectedHostname(caseDir string) string {
	matches, _ := filepath.Glob(filepath.Join(caseDir, "modules", "*_system_metadata", "hostname.txt"))
	for _, m := range matches {
		data, err := os.ReadFile(m)
		if err != nil {
			continue
		}
		if host := strings.TrimSpace(string(data)); host != "" {
			// hostname.txt may carry a trailing newline or multiple lines; take
			// the first non-empty line.
			if idx := strings.IndexAny(host, "\r\n"); idx >= 0 {
				host = strings.TrimSpace(host[:idx])
			}
			if host != "" {
				return host
			}
		}
	}
	return ""
}

func runDryRun(c *casemeta.Case, p *profile.Profile, outputDir string, skipPreflight bool) bool {
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("SAFE DRY-RUN")
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println()
	fmt.Println("Validating environment and configuration. No artifacts will be written.")
	fmt.Println()

	allPassed := true

	fmt.Print("[1] Case metadata: ")
	if err := c.Validate(); err != nil {
		fmt.Printf("✗ FAIL — %v\n", err)
		allPassed = false
	} else {
		fmt.Println("✓ OK")
	}

	fmt.Print("[2] Profile selection: ")
	if p == nil {
		fmt.Printf("✗ FAIL — profile %q not found\n", c.ProfileName)
		allPassed = false
	} else {
		fmt.Printf("✓ OK (%s, %d modules, total budget %s)\n",
			p.Name, len(p.Modules), p.TotalBudget)
	}

	fmt.Println("[3] Preflight checks:")
	if skipPreflight {
		fmt.Println("    (skipped via --skip-preflight)")
	} else {
		profileClass := ""
		if p != nil {
			profileClass = string(p.Class)
		}
		checks := []preflight.Check{
			&preflight.OSCheck{},
			&preflight.AdminCheck{},
			&preflight.DiskCheck{OutputPath: outputDir},
			&preflight.TargetRoleCheck{ProfileClass: profileClass},
		}
		report := preflight.Run(checks)
		if len(report.Findings) == 0 {
			fmt.Println("    ✓ all preflight checks passed silently")
		} else {
			for _, f := range report.Findings {
				marker := "ℹ"
				if f.Severity == preflight.SeverityWarning {
					marker = "⚠"
				} else if f.Severity == preflight.SeverityCritical {
					marker = "✗"
				}
				fmt.Printf("    %s [%s] %s\n", marker, strings.ToUpper(string(f.Severity)), f.Message)
				if f.Detail != "" {
					fmt.Printf("           %s\n", f.Detail)
				}
			}
			if report.HasCritical() {
				allPassed = false
			}
		}
	}

	fmt.Println("[4] External tools:")
	toolsCheck := &preflight.ToolsCheck{}
	if finding := toolsCheck.Run(); finding != nil {
		fmt.Printf("    ✗ [%s] %s\n", strings.ToUpper(string(finding.Severity)), finding.Message)
		if finding.Detail != "" {
			fmt.Printf("           %s\n", finding.Detail)
		}
		if finding.Severity == preflight.SeverityCritical {
			allPassed = false
		}
	} else {
		fmt.Printf("    ✓ all %d required tools available on PATH\n", len(preflight.DefaultRapidTriageTools))
	}

	fmt.Print("[5] Output directory writability: ")
	if err := checkWritable(outputDir); err != nil {
		fmt.Printf("✗ FAIL — %v\n", err)
		allPassed = false
	} else {
		fmt.Println("✓ OK")
	}

	if p != nil {
		fmt.Println("[6] Collection plan:")
		for i, m := range p.Modules {
			fmt.Printf("    %d/%d  %-20s  priority=%-8s  budget=%s\n",
				i+1, len(p.Modules), m.Name(), m.Priority(), m.TimeBudget())
		}
	}

	fmt.Println("[7] Environment paths:")
	envPaths := pathfinder.ResolveEnvironmentPaths()
	if missing := envPaths.Validate(); len(missing) > 0 {
		fmt.Printf("    ⚠ missing environment variables: %s\n", strings.Join(missing, ", "))
	} else {
		fmt.Println("    ✓ all critical environment paths present")
	}
	fmt.Printf("       SystemRoot:    %s\n", envPaths.SystemRoot)
	fmt.Printf("       ProgramFiles:  %s\n", envPaths.ProgramFiles)
	fmt.Printf("       ProgramData:   %s\n", envPaths.ProgramData)
	fmt.Printf("       UserProfile:   %s\n", envPaths.UserProfile)

	fmt.Println("[8] User profile discovery:")
	profiles, err := pathfinder.DiscoverUserProfiles()
	if err != nil {
		fmt.Printf("    ⚠ could not enumerate user profiles: %v\n", err)
	} else if len(profiles) == 0 {
		fmt.Println("    ⚠ no user profiles found")
	} else {
		humanCount := 0
		for _, p := range profiles {
			if !p.IsBuiltin {
				humanCount++
			}
		}
		fmt.Printf("    ✓ %d profile(s) discovered (%d human, %d built-in)\n",
			len(profiles), humanCount, len(profiles)-humanCount)
		for _, p := range profiles {
			label := "human"
			if p.IsBuiltin {
				label = "built-in"
			}
			fmt.Printf("       [%s] %s\n", label, p.ProfilePath)
		}
	}

	fmt.Println()
	fmt.Println(strings.Repeat("=", 70))
	if allPassed {
		fmt.Println("DRY-RUN RESULT: ✓ PASSED")
		fmt.Println()
		fmt.Println("A real collection should succeed on this target.")
		fmt.Println("Rerun without --dry-run to perform the collection.")
	} else {
		fmt.Println("DRY-RUN RESULT: ✗ FAILED")
		fmt.Println()
		fmt.Println("One or more checks failed. Fix the issues above before running")
		fmt.Println("a real collection, or override with --skip-preflight if appropriate.")
	}
	fmt.Println(strings.Repeat("=", 70))

	return allPassed
}

func checkWritable(dir string) error {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("cannot resolve path: %w", err)
	}

	testDir := absDir
	for {
		info, err := os.Stat(testDir)
		if err == nil && info.IsDir() {
			break
		}
		parent := filepath.Dir(testDir)
		if parent == testDir {
			return fmt.Errorf("no existing ancestor directory found for %s", absDir)
		}
		testDir = parent
	}

	testPath := filepath.Join(testDir, ".safe-write-test")
	if err := os.WriteFile(testPath, []byte("test"), 0o644); err != nil {
		return fmt.Errorf("cannot write in %s: %w", testDir, err)
	}
	if err := os.Remove(testPath); err != nil {
		return fmt.Errorf("cannot remove test file in %s: %w", testDir, err)
	}
	return nil
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "Fatal: "+format+"\n", args...)
	os.Exit(2)
}

// runShadowCleanup performs an explicit cleanup of SAFE-created shadows
// invoked via --cleanup-shadows flag. Reports what was found and what was
// cleaned, returns explicit exit status.
func runShadowCleanup() {
	fmt.Println("Scanning for SAFE-created shadow copies...")
	fmt.Println()

	infos, err := vss.ListSAFEShadows()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to list shadows: %v\n", err)
		os.Exit(2)
	}

	if len(infos) == 0 {
		fmt.Println("No SAFE-created shadow copies found. System is clean.")
		return
	}

	fmt.Printf("Found %d SAFE-created shadow(s):\n", len(infos))
	for _, info := range infos {
		fmt.Printf("  - %s\n", info.SymlinkPath)
		fmt.Printf("    Shadow ID: %s\n", info.ShadowID)
		fmt.Printf("    Created:   %s\n", info.CreatedAt.Format(time.RFC3339))
	}
	fmt.Println()
	fmt.Println("Cleaning up...")

	cleaned, errs := vss.CleanupOrphans()
	fmt.Printf("Cleaned: %d shadow(s)\n", cleaned)
	if len(errs) > 0 {
		fmt.Printf("Errors during cleanup: %d\n", len(errs))
		for _, e := range errs {
			fmt.Fprintf(os.Stderr, "  %v\n", e)
		}
	}
	fmt.Println()
	fmt.Println("Cleanup complete.")
}

// runAutoShadowCleanup performs silent orphan cleanup at SAFE startup.
// Only reports problems; success is silent so the analyst's output isn't
// cluttered with "0 shadows cleaned" messages on every run.
func runAutoShadowCleanup() {
	cleaned, errs := vss.CleanupOrphans()
	if cleaned > 0 {
		fmt.Printf("Auto-cleaned %d orphan shadow(s) from previous runs.\n\n", cleaned)
	}
	if len(errs) > 0 {
		// Don't fatal on auto-cleanup errors; collection should still proceed.
		fmt.Fprintf(os.Stderr, "Auto-cleanup encountered %d issue(s) (continuing):\n", len(errs))
		for _, e := range errs {
			fmt.Fprintf(os.Stderr, "  %v\n", e)
		}
		fmt.Fprintln(os.Stderr)
	}
}


