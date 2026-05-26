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

	// MinSize, if > 0, is the minimum file size (in bytes) for the output
	// to be kept as an artifact. Files below this are dropped with a warning.
	// 0 means don't drop based on size.
	MinSize int64

	// Check is an optional content verification step.
	Check *ContentCheck

	// SkipChecks bypasses all content verification (but MinSize still applies).
	SkipChecks bool
}

// DirectCommand describes a command whose output goes directly to a file
// the command itself creates, not captured from stdout.
type DirectCommand struct {
	Filename string
	Name     string
	Args     []string

	// Check is an optional content verification step.
	Check *ContentCheck

	// SkipChecks bypasses all content verification.
	SkipChecks bool
}

// runCommands executes a slice of Commands inside outputDir.
// Honors the provided context for cancellation.
// After each command, runs ContentCheck if defined.
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

		// Per-command minimum size check. Default (0) = no minimum.
		if c.MinSize > 0 {
			info, statErr := os.Stat(outPath)
			if statErr == nil && info.Size() < c.MinSize {
				_ = os.Remove(outPath)
				result.Warnings = append(result.Warnings,
					fmt.Sprintf("%s: output (%d bytes) below expected minimum (%d) — artifact dropped",
						c.Filename, info.Size(), c.MinSize))
				continue
			}
		}

		// Content verification.
		if !c.SkipChecks {
			check := c.Check
			if check == nil {
				check = &ContentCheck{MustNotContain: commonErrorSignatures}
			}
			if issues := check.verifyContent(outPath); len(issues) > 0 {
				for _, issue := range issues {
					result.Warnings = append(result.Warnings,
						fmt.Sprintf("%s: %s", c.Filename, issue))
				}
			}
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

		// Run content check if defined (default checks don't apply to direct
		// commands because binary outputs like .evtx aren't scannable text).
		if !c.SkipChecks && c.Check != nil {
			if issues := c.Check.verifyContent(outPath); len(issues) > 0 {
				for _, issue := range issues {
					result.Warnings = append(result.Warnings,
						fmt.Sprintf("%s: %s", c.Filename, issue))
				}
			}
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
func finalize(result *Result, started time.Time, ctx context.Context) {
	result.EndedAt = time.Now().UTC()
	result.Duration = result.EndedAt.Sub(started)

	if ctx.Err() != nil {
		if len(result.Artifacts) > 0 {
			result.Status = StatusPartial
		} else {
			result.Status = StatusTimedOut
		}
		return
	}

	// New: if there are warnings (including content warnings) but no errors,
	// status is partial — analyst should be aware something needs review.
	switch {
	case len(result.Errors) > 0 && len(result.Artifacts) == 0:
		result.Status = StatusFailed
	case len(result.Errors) > 0 || len(result.Warnings) > 0:
		result.Status = StatusPartial
	default:
		result.Status = StatusSuccess
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
