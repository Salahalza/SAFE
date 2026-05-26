package module

import (
	"context"
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
	Filename string
	Name     string
	Args     []string
}

// DirectCommand describes a command whose output goes directly to a file
// the command itself creates, not captured from stdout.
type DirectCommand struct {
	Filename string
	Name     string
	Args     []string
}

// runCommands executes a slice of Commands inside outputDir.
// Honors the provided context for cancellation.
func runCommands(ctx context.Context, outputDir string, commands []Command, result *Result) {
	for _, c := range commands {
		if ctx.Err() != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("%s: skipped (context cancelled: %v)", c.Name, ctx.Err()))
			continue
		}
		outPath := filepath.Join(outputDir, c.Filename)
		if err := runOne(ctx, c.Name, c.Args, outPath); err != nil {
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

// runOne runs a single command with context-aware timeout and writes
// combined output to outPath.
func runOne(ctx context.Context, name string, args []string, outPath string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		_ = os.WriteFile(outPath, out, 0o644)
		if ctx.Err() != nil {
			return fmt.Errorf("cancelled: %w", ctx.Err())
		}
		return fmt.Errorf("command failed: %w", err)
	}
	return os.WriteFile(outPath, out, 0o644)
}

// runDirectOutputCommands executes commands that write their own output files.
// Honors the provided context for cancellation.
func runDirectOutputCommands(ctx context.Context, outputDir string, commands []DirectCommand, result *Result) {
	for _, c := range commands {
		if ctx.Err() != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("%s: skipped (context cancelled: %v)", c.Name, ctx.Err()))
			continue
		}
		outPath := filepath.Join(outputDir, c.Filename)

		args := make([]string, len(c.Args))
		for i, a := range c.Args {
			if a == "{OUTPUT}" {
				args[i] = outPath
			} else {
				args[i] = a
			}
		}

		cmd := exec.CommandContext(ctx, c.Name, args...)
		stderr, err := cmd.CombinedOutput()
		if err != nil {
			if ctx.Err() != nil {
				result.Errors = append(result.Errors,
					fmt.Sprintf("%s: cancelled: %v", c.Name, ctx.Err()))
			} else {
				result.Errors = append(result.Errors,
					fmt.Sprintf("%s: %v (stderr: %s)", c.Name, err, string(stderr)))
			}
			continue
		}

		info, statErr := os.Stat(outPath)
		if statErr != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("%s: output file not created: %v", c.Name, statErr))
			continue
		}
		if info.Size() == 0 {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("%s: output file is empty", c.Filename))
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

// finalize sets the EndedAt, Duration, and Status fields on a Result.
// If ctx was cancelled and no artifacts were produced, status becomes timed_out.
func finalize(result *Result, started time.Time, ctx context.Context) {
	result.EndedAt = time.Now().UTC()
	result.Duration = result.EndedAt.Sub(started)

	// Context cancelled = timeout. If we got any artifacts, partial; if not, timed_out.
	if ctx.Err() != nil {
		if len(result.Artifacts) > 0 {
			result.Status = StatusPartial
		} else {
			result.Status = StatusTimedOut
		}
		return
	}

	switch {
	case len(result.Errors) == 0:
		result.Status = StatusSuccess
	case len(result.Artifacts) > 0:
		result.Status = StatusPartial
	default:
		result.Status = StatusFailed
	}
}

// prepareOutputDir creates the module's output directory.
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
