package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"saham/internal/engine"
	"saham/internal/profile"
)

func main() {
	fmt.Println("Acquira v0.1.0 — profile test run")

	// Set up the profile registry with built-in profiles.
	registry := profile.NewRegistry()
	if err := profile.RegisterDefaults(registry); err != nil {
		fmt.Fprintf(os.Stderr, "failed to register profiles: %v\n", err)
		os.Exit(1)
	}

	// For now, hardcoded to rapid_triage.
	// Next step will accept this from the command line.
	profileName := "rapid_triage"

	p, err := registry.Get(profileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "profile error: %v\n", err)
		fmt.Fprintf(os.Stderr, "available profiles: %v\n", registry.Names())
		os.Exit(1)
	}

	caseID := fmt.Sprintf("CASE-%s", time.Now().UTC().Format("20060102-150405"))
	caseDir := filepath.Join(".", "test-output", caseID)

	fmt.Printf("Case: %s\n", caseID)
	fmt.Printf("Output: %s\n\n", caseDir)

	eng := engine.New(caseDir)
	result := eng.Run(p)

	fmt.Printf("\nFinal status: %s\n", result.Status)
	fmt.Printf("Duration: %s\n", result.Duration)

	resultPath := filepath.Join(caseDir, "result.json")
	data, _ := json.MarshalIndent(result, "", "  ")
	_ = os.WriteFile(resultPath, data, 0o644)
	fmt.Printf("Full result written to: %s\n", resultPath)

	if result.Status == "failed" {
		os.Exit(1)
	}
}
