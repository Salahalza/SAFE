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
	"sahm/internal/preflight"
	"sahm/internal/profile"
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
	)
	flag.Parse()

	// Register profiles.
	registry := profile.NewRegistry()
	if err := profile.RegisterDefaults(registry); err != nil {
		fatalf("failed to register profiles: %v", err)
	}

	// Handle --list-profiles.
	if *listProfiles {
		fmt.Println("Available profiles:")
		for _, name := range registry.Names() {
			p, _ := registry.Get(name)
			fmt.Printf("  %s (v%s) — %s\n", p.Name, p.Version, p.Description)
		}
		os.Exit(0)
	}

	// Preflight checks before anything else touches disk.
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

	// Build case metadata.
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

	// Look up the profile.
	p, err := registry.Get(c.ProfileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fmt.Fprintf(os.Stderr, "Run with --list-profiles to see available profiles.\n")
		os.Exit(2)
	}

	// Build case directory.
	caseDir := filepath.Join(*outputDir, c.CaseDirName())

	// Print header.
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

	// Write case.json before running modules.
	if err := c.WriteToCase(caseDir); err != nil {
		fatalf("write case metadata: %v", err)
	}

	// Run the profile.
	eng := engine.New(caseDir)
	result := eng.Run(p)

	// Print summary.
	fmt.Println()
	fmt.Printf("Final status:  %s\n", result.Status)
	fmt.Printf("Duration:      %s\n", result.Duration)

	// Write result.json.
	resultPath := filepath.Join(caseDir, "result.json")
	data, _ := json.MarshalIndent(result, "", "  ")
	if err := os.WriteFile(resultPath, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to write result.json: %v\n", err)
	}
	fmt.Printf("Result file:   %s\n", resultPath)
	fmt.Printf("Case folder:   %s\n", caseDir)

	// Exit code reflects outcome.
	switch result.Status {
	case "failed":
		os.Exit(1)
	case "degraded":
		os.Exit(3)
	default:
		os.Exit(0)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "Fatal: "+format+"\n", args...)
	os.Exit(2)
}
