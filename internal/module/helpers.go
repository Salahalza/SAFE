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

type Command struct {
	Filename   string
	Name       string
	Args       []string
	MinSize    int64
	Check      *ContentCheck
	SkipChecks bool
}

type DirectCommand struct {
	Filename   string
	Name       string
	Args       []string
	Check      *ContentCheck
	SkipChecks bool
}

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

		// Per-command minimum size check.
		if c.MinSize > 0 {
			info, statErr := os.Stat(outPath)
			if statErr == nil && info.Size() < c.MinSize {
				_ = os.Remove(outPath)
				result.AddWarning(c.Filename,
					fmt.Sprintf("output (%d bytes) below expected minimum (%d) — artifact dropped",
						info.Size(), c.MinSize))
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
					result.AddWarning(c.Filename, issue)
				}
			}
		}

		artifact, err := describeArtifact(outPath)
		if err != nil {
			result.AddWarning(c.Filename, fmt.Sprintf("hash failed: %v", err))
			continue
		}
		result.Artifacts = append(result.Artifacts, artifact)
	}
}

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

func runDirectOutputCommands(mctx *Context, commands []DirectCommand, result *Result) {
	var bytes int64
	for i, c := range commands {
		// Report intra-module progress (commands run / total, bytes produced).
		mctx.ReportProgress(i, len(commands), bytes)

		if mctx.Ctx.Err() != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("%s: skipped (context cancelled: %v)", c.Name, mctx.Ctx.Err()))
			continue
		}
		outPath := filepath.Join(mctx.OutputDir, c.Filename)

		args := make([]string, len(c.Args))
		for i, a := range c.Args {
			if a == "{OUTPUT}" {
				args[i] = outPath
			} else {
				args[i] = a
			}
		}

		cmd := exec.CommandContext(mctx.Ctx, c.Name, args...)
		stderr, err := cmd.CombinedOutput()
		if err != nil {
			if mctx.Ctx.Err() != nil {
				result.Errors = append(result.Errors,
					fmt.Sprintf("%s: cancelled: %v", c.Name, mctx.Ctx.Err()))
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
			result.AddWarning(c.Filename, "output file is empty")
		}
		bytes += info.Size()

		if !c.SkipChecks && c.Check != nil {
			if issues := c.Check.verifyContent(outPath); len(issues) > 0 {
				for _, issue := range issues {
					result.AddWarning(c.Filename, issue)
				}
			}
		}

		artifact, err := describeArtifact(outPath)
		if err != nil {
			result.AddWarning(c.Filename, fmt.Sprintf("hash failed: %v", err))
			continue
		}
		result.Artifacts = append(result.Artifacts, artifact)
	}
	mctx.ReportProgress(len(commands), len(commands), bytes)
}

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

// finalize sets status based on errors, findings, and context state.
// New rule: only critical findings or errors cause "partial"/"failed".
// Info findings don't degrade status.
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

	_, warningCount, criticalCount := result.CountBySeverity()

	switch {
	case len(result.Errors) > 0 && len(result.Artifacts) == 0:
		result.Status = StatusFailed
	case len(result.Errors) > 0:
		result.Status = StatusPartial
	case criticalCount > 0:
		result.Status = StatusPartial
	case warningCount > 0:
		result.Status = StatusPartial
	default:
		// Info findings are fine — status stays success.
		result.Status = StatusSuccess
	}
}

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

// copyStream copies bytes from src to dst with a fixed buffer to bound
// memory use. Returns total bytes copied and any error encountered.
//
// Used by file-copy modules to handle large artifacts (registry hives,
// $MFT, etc.) without loading them into memory.
func copyStream(dst io.Writer, src io.Reader) (int64, error) {
	return io.Copy(dst, src)
}
