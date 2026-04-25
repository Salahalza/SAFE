package module

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// SystemMetadata collects basic system information from the target.
type SystemMetadata struct{}

func (m *SystemMetadata) Name() string              { return "system_metadata" }
func (m *SystemMetadata) Priority() Priority        { return PriorityCritical }
func (m *SystemMetadata) TimeBudget() time.Duration { return 30 * time.Second }

func (m *SystemMetadata) Run(ctx *Context) Result {
	started := time.Now().UTC()
	result := Result{
		ModuleName: m.Name(),
		StartedAt:  started,
		Artifacts:  []Artifact{},
		Warnings:   []string{},
		Errors:     []string{},
	}

	if !prepareOutputDir(&result, ctx.OutputDir, started) {
		return result
	}

	commands := []Command{
		{Filename: "systeminfo.txt", Name: "systeminfo"},
		{Filename: "hostname.txt", Name: "hostname"},
		{Filename: "whoami_all.txt", Name: "whoami", Args: []string{"/all"}},
		{Filename: "ipconfig_all.txt", Name: "ipconfig", Args: []string{"/all"}},
	}
	runCommands(ctx.OutputDir, commands, &result)

	// Also write an environment.json with basic runtime info.
	envPath := filepath.Join(ctx.OutputDir, "environment.json")
	if err := writeEnvironmentJSON(envPath); err != nil {
		result.Warnings = append(result.Warnings,
			"environment.json: "+err.Error())
	} else if artifact, err := describeArtifact(envPath); err == nil {
		result.Artifacts = append(result.Artifacts, artifact)
	}

	finalize(&result, started)
	return result
}

func writeEnvironmentJSON(path string) error {
	hostname, _ := os.Hostname()
	wd, _ := os.Getwd()
	env := map[string]any{
		"hostname":     hostname,
		"collected_at": time.Now().UTC().Format(time.RFC3339),
		"working_dir":  wd,
	}
	data, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}
