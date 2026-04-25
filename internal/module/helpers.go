package module

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// Command describes one external command a module wants to run
// and the file its output should be saved to.
type Command struct {
	Filename string   // e.g. "tasklist_verbose.txt"
	Name     string   // e.g. "tasklist"
	Args     []string // e.g. ["/v", "/fo", "list"]
}

// runCommands executes a slice of Commands inside outputDir.
// For each command it captures stdout+stderr to the named file,
// hashes the result, and appends to the result's artifacts/errors.
// Modules pass in their own *Result so this function can update it directly.
func runCommands(outputDir string, commands []Command, result *Result) {
	for _, c := range commands {
		outPath := filepath.Join(outputDir, c.Filename)
		if err := runOne(c.Name, c.Args, outPath); err != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("%s: %v", c.Name, err))
			continue
		}
		artifact, err := describeArtifact(outPath)
		if err != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("hash %s: %v", c.Filename, err))
			continue
		}
		result.Artifacts = append(result.Artifacts, artifact)
	}
}

// runOne runs a single command and writes combined output to outPath.
func runOne(name string, args []string, outPath string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
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

// finalize sets the EndedAt, Duration, and Status fields on a Result
// based on the artifacts and errors it accumulated.
func finalize(result *Result, started time.Time) {
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
}

// prepareOutputDir creates the module's output directory and returns
// an error string slice ready to attach to the result on failure.
// Returns true if the dir was created successfully.
func prepareOutputDir(result *Result, outputDir string, started time.Time) bool {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		result.Errors = append(result.Errors,
			fmt.Sprintf("create output dir: %v", err))
		result.Status = StatusFailed
		result.EndedAt = time.Now().UTC()
		result.Duration = result.EndedAt.Sub(started)
		return false
	}
	return true
}
