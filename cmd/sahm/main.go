package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sahm/internal/casemeta"
	"sahm/internal/engine"
	"sahm/internal/manifest"
	"sahm/internal/preflight"
	"sahm/internal/profile"
	"sahm/internal/tui"
)

const sahmVersion = "0.1.0"

func main() {
	var (
		caseID        = flag.String("case", "", "Case identifier (e.g. INC-2026-0418). Required unless --tui.")
		analyst       = flag.String("analyst", "", "Analyst name or initials. Required unless --tui.")
		target        = flag.String("target", "", "Target identifier (hostname, asset tag, IP). Required unless --tui.")
		targetClass   = flag.String("target-class", "unknown", "Target class: workstation, server, or unknown.")
		profileName   = flag.String("profile", "rapid_triage", "Profile to run.")
		outputDir     = flag.String("output", "./test-output", "Output base directory.")
		notes         = flag.String("notes", "", "Optional analyst notes.")
		listProfiles  = flag.Bool("list-profiles", false, "List available profiles and exit.")
		skipPreflight = flag.Bool("skip-preflight", false, "Skip preflight checks (advanced use only).")
		verifyDir     = flag.String("verify", "", "Verify integrity of a case folder. Specify the case folder path.")
		tuiMode       = flag.Bool("tui", false, "Launch the interactive terminal UI.")
		dryRun        = flag.Bool("dry-run", false, "Validate environment without performing collection.")
	)
	flag.Parse()

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
			fmt.Println("\nMissing files:")
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

	var c *casemeta.Case

	if *tuiMode {
		populateTUIProfiles(registry)

		tuiCase, err := tui.Run()
		if err != nil {
			fmt.Fprintf(os.Stderr, "TUI error: %v\n", err)
			os.Exit(1)
		}
		if tuiCase == nil {
			fmt.Println("Collection cancelled.")
			os.Exit(0)
		}
		tuiCase.CreatedAt = time.Now().UTC()
		tuiCase.SAHMVersion = sahmVersion
		c = tuiCase
	} else {
		c = &casemeta.Case{
			CaseID:           *caseID,
			Analyst:          *analyst,
			TargetIdentifier: *target,
			TargetClass:      *targetClass,
			Notes:            *notes,
			ProfileName:      *profileName,
			CreatedAt:        time.Now().UTC(),
			SAHMVersion:      sahmVersion,
		}
	}

	// Look up the profile.
	p, _ := registry.Get(c.ProfileName)

	// Handle --dry-run: validate everything, perform no collection.
	if *dryRun {
		passed := runDryRun(c, p, *outputDir, *skipPreflight)
		if passed {
			os.Exit(0)
		}
		os.Exit(2)
	}

	// From here on: real collection path.

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

	fmt.Printf("SAHM v%s — System for Artifact Harvesting and Management\n", sahmVersion)
	fmt.Println()
	fmt.Printf("Case ID:    %s\n", c.CaseID)
	fmt.Printf("Analyst:    %s\n", c.Analyst)
	fmt.Printf("Target:     %s (%s)\n", c.TargetIdentifier, c.TargetClass)
	fmt.Printf("Profile:    %s\n", c.ProfileName)
	fmt.Printf("Output:     %s\n", caseDir)
	if c.Notes != "" {
		fmt.Printf("Notes:      %s\n", c.Notes)
	}
	fmt.Println()

	if err := c.WriteToCase(caseDir); err != nil {
		fatalf("write case metadata: %v", err)
	}

	eng := engine.New(caseDir)
	result := eng.Run(p)

	fmt.Println()
	fmt.Printf("Final status:  %s\n", result.Status)
	fmt.Printf("Duration:      %s\n", result.Duration)

	resultPath := filepath.Join(caseDir, "result.json")
	data, _ := json.MarshalIndent(result, "", "  ")
	if err := os.WriteFile(resultPath, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to write result.json: %v\n", err)
	}

	summary := buildCaseSummary(c, result, sahmVersion)
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

func buildCaseSummary(c *casemeta.Case, result engine.CaseResult, version string) manifest.CaseSummary {
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
			Findings:      findings,
			Errors:        m.Errors,
		})
	}
	return manifest.CaseSummary{
		CaseID:      c.CaseID,
		Analyst:     c.Analyst,
		Target:      c.TargetIdentifier,
		TargetClass: c.TargetClass,
		Notes:       c.Notes,
		Profile:     c.ProfileName,
		SAHMVersion: version,
		StartedAt:   result.StartedAt,
		EndedAt:     result.EndedAt,
		Duration:    result.Duration,
		Status:      result.Status,
		Modules:     mods,
	}
}

func runDryRun(c *casemeta.Case, p *profile.Profile, outputDir string, skipPreflight bool) bool {
	fmt.Println(strings.Repeat("=", 70))
	fmt.Println("SAHM DRY-RUN")
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

// checkWritable verifies SAHM could write to the output directory.
// Truly non-destructive: doesn't create the directory if it doesn't exist.
// If the directory exists, tests by creating/removing a small file.
// If it doesn't exist, tests writability of the nearest existing ancestor.
func checkWritable(dir string) error {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return fmt.Errorf("cannot resolve path: %w", err)
	}

	// Find the nearest existing ancestor.
	testDir := absDir
	for {
		info, err := os.Stat(testDir)
		if err == nil && info.IsDir() {
			break // found an existing directory
		}
		parent := filepath.Dir(testDir)
		if parent == testDir {
			return fmt.Errorf("no existing ancestor directory found for %s", absDir)
		}
		testDir = parent
	}

	// Test write access on the existing directory.
	testPath := filepath.Join(testDir, ".sahm-write-test")
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
