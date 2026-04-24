package module

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// SystemMetadata collects basic system information from the target.
// It runs native Windows commands and captures their output.
type SystemMetadata struct{}

// Name implements Module.
func (m *SystemMetadata) Name() string {
	return "system_metadata"
}

// Priority implements Module. System metadata is critical —
// every case needs to know what target it came from.
func (m *SystemMetadata) Priority() Priority {
	return PriorityCritical
}

// TimeBudget implements Module.
func (m *SystemMetadata) TimeBudget() time.Duration {
	return 30 * time.Second
}

// Run implements Module.
func (m *SystemMetadata) Run(ctx *Context) Result {
	started := time.Now().UTC()
	result := Result{
		ModuleName: m.Name(),
		StartedAt:  started,
		Artifacts:  []Artifact{},
		Warnings:   []string{},
		Errors:     []string{},
	}

	// Ensure output directory exists.
	if err := os.MkdirAll(ctx.OutputDir, 0o755); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("create output dir: %v", err))
		result.Status = StatusFailed
		result.EndedAt = time.Now().UTC()
		result.Duration = result.EndedAt.Sub(started)
		return result
	}

	// Commands to run. Each produces a text file in the output directory.
	commands := []struct {
		filename string
		name     string
		args     []string
	}{
		{"systeminfo.txt", "systeminfo", nil},
		{"hostname.txt", "hostname", nil},
		{"whoami_all.txt", "whoami", []string{"/all"}},
		{"ipconfig_all.txt", "ipconfig", []string{"/all"}},
	}

	for _, c := range commands {
		outPath := filepath.Join(ctx.OutputDir, c.filename)
		if err := runAndCapture(c.name, c.args, outPath); err != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("%s: %v", c.name, err))
			continue
		}
		artifact, err := describeArtifact(outPath)
		if err != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("hash %s: %v", c.filename, err))
			continue
		}
		result.Artifacts = append(result.Artifacts, artifact)
	}

	// Also write an environment.json with basic runtime info.
	envPath := filepath.Join(ctx.OutputDir, "environment.json")
	if err := writeEnvironmentJSON(envPath); err != nil {
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("environment.json: %v", err))
	} else {
		if artifact, err := describeArtifact(envPath); err == nil {
			result.Artifacts = append(result.Artifacts, artifact)
		}
	}

	// Determine final status.
	result.EndedAt = time.Now().UTC()
	result.Duration = result.EndedAt.Sub(started)

	switch {
	case len(result.Errors) == 0:
		result.Status = StatusSuccess
	case len(result.Artifacts) > 0:
		result.Status = StatusPartial
	default:
		result.Status = StatusFailed
	}

	return result
}

// runAndCapture runs a command and writes stdout+stderr to outPath.
func runAndCapture(name string, args []string, outPath string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Still write what we captured, but report the error.
		_ = os.WriteFile(outPath, out, 0o644)
		return fmt.Errorf("command failed: %w", err)
	}
	return os.WriteFile(outPath, out, 0o644)
}

// describeArtifact returns an Artifact describing a file on disk.
func describeArtifact(path string) (Artifact, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Artifact{}, err
	}
	hash, err := sha256File(path)
	if err != nil {
		return Artifact{}, err
	}
	return Artifact{
		Path:   path,
		Size:   info.Size(),
		SHA256: hash,
	}, nil
}

// sha256File computes the SHA-256 hash of a file as a hex string.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// writeEnvironmentJSON writes a small JSON file describing the runtime.
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
