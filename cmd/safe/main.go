package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"safe/internal/analyzer"
	"safe/internal/casemeta"
	"safe/internal/engine"
	"safe/internal/manifest"
	"safe/internal/pathfinder"
	"safe/internal/preflight"
	"safe/internal/profile"
	"safe/internal/tui"
	"safe/internal/vss"
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
		verifyDir      = flag.String("verify", "", "Verify integrity of a case folder. Specify the case folder path.")
		tuiMode        = flag.Bool("tui", false, "Launch the interactive terminal UI.")
		dryRun         = flag.Bool("dry-run", false, "Validate environment without performing collection.")
		cleanupShadows = flag.Bool("cleanup-shadows", false, "Clean up SAFE-created shadow copies left from previous interrupted runs, then exit.")
		analyzeDir     = flag.String("analyze", "", "Run analyzer parsers against a collected case folder. Specify the case folder path.")
		irNumber       = flag.String("ir", "", "Optional IR ticket number (format: IR-####-####).")
		csiNumber      = flag.String("csi", "", "Optional CSI ticket number (format: CSI-######).")
	)

	flag.Parse()
	// --cleanup-shadows: explicit cleanup mode, run and exit.
	if *cleanupShadows {
		runShadowCleanup()
		os.Exit(0)
	}

	// Auto-cleanup at startup: silently clean any orphan SAFE shadows.
	// This protects against accumulating leaks from interrupted runs.
	runAutoShadowCleanup()

	// --- verify mode ---
	if *verifyDir != "" {
		fmt.Printf("Verifying: %s\n\n", *verifyDir)
		result, err := manifest.Verify(*verifyDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Verification failed: %v\n", err)
			os.Exit(2)
		}
		fmt.Printf("Files checked: %d\n", result.FilesChecked)
		if result.OK {
			fmt.Println("Status: OK — every file matches its recorded hash.")
			os.Exit(0)
		}
		fmt.Println("Status: FAILED")
		if len(result.Missing) > 0 {
			fmt.Println("\nMissing files (in manifest, not on disk):")
			for _, m := range result.Missing {
				fmt.Printf("  %s\n", m)
			}
		}
		if len(result.Mismatches) > 0 {
			fmt.Println("\nHash mismatches:")
			for _, m := range result.Mismatches {
				fmt.Printf("  %s\n", m)
			}
		}
		if len(result.Extra) > 0 {
			fmt.Println("\nExtra files (on disk, not in any manifest — possible tampering):")
			for _, e := range result.Extra {
				fmt.Printf("  %s\n", e)
			}
		}
		os.Exit(1)
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

		runRes, err := tui.RunWithCollection(registry, runFn, runAnalyzerFromTUI)
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

	p, _ := registry.Get(c.ProfileName)

	// --analyze: run lab-side parsers against a collected case.
	if *analyzeDir != "" {
		runAnalyzer(*analyzeDir)
		os.Exit(0)
	}

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

	if !*skipPreflight {
		checks := []preflight.Check{
			&preflight.OSCheck{},
			&preflight.AdminCheck{},
			&preflight.DiskCheck{OutputPath: *outputDir},
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
		checks := []preflight.Check{
			&preflight.OSCheck{},
			&preflight.AdminCheck{},
			&preflight.DiskCheck{OutputPath: outputDir},
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

func runAnalyzer(caseDir string) {
	fmt.Printf("SAFE Analyzer — parsing case folder\n")
	fmt.Printf("Case: %s\n\n", caseDir)

	registry := analyzer.NewRegistry()
	registry.Register(&analyzer.UserAssistParser{})
	registry.Register(&analyzer.PrefetchParser{})
	registry.Register(&analyzer.ProcessMemoryParser{})
	registry.Register(&analyzer.ComHijackParser{})
	registry.Register(&analyzer.WmiSubscriptionParser{})

	lastLabel := ""
	onProgress := func(frac float64, label string) {
		// Print a bar line when the parser changes (append-only CLI; the
		// fraction streams finely but per-parser lines keep the output clean).
		if label != "" && label != lastLabel {
			lastLabel = label
			fmt.Printf("%s  %s\n", engine.ASCIIBar(int(frac*100), 100, 20), label)
		}
	}
	result, err := analyzer.RunWithProgress(caseDir, registry.All(), onProgress)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Analyzer failed: %v\n", err)
		os.Exit(2)
	}

	fmt.Printf("Lab report: %s\n", result.LabReportDir)
	fmt.Printf("Duration:   %s\n\n", result.Duration)

	for _, p := range result.ParsersRun {
		fmt.Printf("[%s] %s (%s)\n",
			strings.ToUpper(p.Status), p.Name, p.Duration.Round(time.Millisecond))
		for _, out := range p.Outputs {
			fmt.Printf("  → %s\n", out)
		}
		if len(p.Stats) > 0 {
			// Sort keys for stable output.
			keys := make([]string, 0, len(p.Stats))
			for k := range p.Stats {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			var parts []string
			for _, k := range keys {
				parts = append(parts, fmt.Sprintf("%s=%d", k, p.Stats[k]))
			}
			fmt.Printf("  stats: %s\n", strings.Join(parts, ", "))
		}
		for _, e := range p.Errors {
			fmt.Printf("  ⚠ %s\n", e)
		}
	}
}

// runAnalyzerFromTUI is the analyzer entry point passed to the TUI. It
// wraps the same analyzer infrastructure used by the --analyze CLI flag.
func runAnalyzerFromTUI(caseDir string, onProgress func(frac float64, label string)) (*analyzer.Result, error) {
	registry := analyzer.NewRegistry()
	registry.Register(&analyzer.UserAssistParser{})
	registry.Register(&analyzer.PrefetchParser{})
	registry.Register(&analyzer.ProcessMemoryParser{})
	registry.Register(&analyzer.ComHijackParser{})
	registry.Register(&analyzer.WmiSubscriptionParser{})
	return analyzer.RunWithProgress(caseDir, registry.All(), onProgress)
}
