package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"acquira/internal/module"
)

func main() {
	fmt.Println("Acquira v0.1.0 — test run")

	// Create a temporary output directory.
	outDir := filepath.Join(".", "test-output", "system_metadata")

	ctx := &module.Context{
		OutputDir: outDir,
	}

	m := &module.SystemMetadata{}
	fmt.Printf("Running module: %s (priority=%s, budget=%s)\n",
		m.Name(), m.Priority(), m.TimeBudget())

	result := m.Run(ctx)

	// Print the result as JSON so we can see what happened.
	data, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(data))

	if result.Status == module.StatusFailed {
		os.Exit(1)
	}
}
