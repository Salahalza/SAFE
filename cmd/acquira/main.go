package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"acquira/internal/engine"
	"acquira/internal/module"
)

func main() {
	fmt.Println("Acquira v0.1.0 — engine test run")

	// Build a case directory name from the current timestamp.
	// Real case IDs will come from user input later.
	caseID := fmt.Sprintf("CASE-%s", time.Now().UTC().Format("20060102-150405"))
	caseDir := filepath.Join(".", "test-output", caseID)

	fmt.Printf("Case: %s\n", caseID)
	fmt.Printf("Output: %s\n\n", caseDir)

	// Profile: for now, just a single module.
	// Next step will be a real profile with multiple modules.
	modules := []module.Module{
		&module.SystemMetadata{},
		&module.ProcessSnapshot{},
		&module.NetworkSnapshot{},
	}

	eng := engine.New(caseDir)
	result := eng.Run(modules)

	// Print final summary.
	fmt.Printf("\nFinal status: %s\n", result.Status)
	fmt.Printf("Duration: %s\n", result.Duration)

	// Write the full result as JSON to the case directory.
	resultPath := filepath.Join(caseDir, "result.json")
	data, _ := json.MarshalIndent(result, "", "  ")
	_ = os.WriteFile(resultPath, data, 0o644)
	fmt.Printf("Full result written to: %s\n", resultPath)

	if result.Status == "failed" {
		os.Exit(1)
	}
}
