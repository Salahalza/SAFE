package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
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
		caseID        = flag.String("case", "", "Case identifier (e.g. INC-2026-0418). Required.")
		analyst       = flag.String("analyst", "", "Analyst name or initials. Required.")
		target        = flag.String("target", "", "Target identifier (hostname, asset tag, IP). Required.")
		targetClass   = flag.String("target-class", "unknown", "Target class: workstation, server, or unknown.")
		profileName   = flag.String("profile", "rapid_triage", "Profile to run.")
		outputDir     = flag.String("output", "./test-output", "Output base directory.")
		notes         = flag.String("notes", "", "Optional analyst notes.")
		listProfiles  = flag.Bool("list-profiles", false, "List available profiles and exit.")
		skipPreflight = flag.Bool("skip-preflight", false, "Skip preflight checks (advanced use only).")
		verifyDir     = flag.String("verify", "", "Verify integrity of a case folder. Specify the case folder path.")
		tuiMode       = flag.Bool("tui", false, "Launch the interactive terminal UI.")
	)
	flag.Parse()

	if *tuiMode {
		c, err := tui.Run()
		if err != nil {
			fmt.Fprintf(os.Stderr, "TUI error: %v\n", err)
			os.Exit(1)
		}
		if c == nil {
			fmt.Println("Collection cancelled.")
			os.Exit(0)
		}
		fmt.Println("Case metadata captured:")
		fmt.Printf("  Case ID:    %s\n", c.CaseID)
		fmt.Printf("  Analyst:    %s\n", c.Analyst)
		fmt.Printf("  Target:     %s (%s)\n", c.TargetIdentifier, c.TargetClass)
		if c.Notes != "" {
			fmt.Printf("  Notes:      %s\n", c.Notes)
		}
		fmt.Println()
		fmt.Println("Next step: integration with collection engine.")
		os.Exit(0)
	}

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

	c := &casemeta.Case{
		CaseID:           *caseID,
		Analyst:          *analyst,
		TargetIdentifier: *target,
		TargetClass:      *targetClass,
		Notes:            *notes,
		ProfileName:      *profileName,
		CreatedAt:        time.Now().UTC(),
		SAHMVersion:      sahmVersion,
	}

	if err := c.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
		flag.Usage()
		os.Exit(2)
	}

	p, err := registry.Get(c.ProfileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
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

func buildCaseSummary(c *casemeta.Case, result engine.CaseResult, version string) manifest.CaseSummary {
	mods := make([]manifest.ModuleSummary, 0, len(result.Modules))
	for _, m := range result.Modules {
		mods = append(mods, manifest.ModuleSummary{
			Name:          m.ModuleName,
			Status:        string(m.Status),
			Duration:      m.Duration,
			ArtifactCount: len(m.Artifacts),
			Warnings:      m.Warnings,
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

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "Fatal: "+format+"\n", args...)
	os.Exit(2)
}
