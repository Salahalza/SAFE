package module

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Salahalza/SAFE/internal/hashutil"
	"github.com/Salahalza/SAFE/internal/pathfinder"
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
			// runOne writes whatever the command emitted before failing (often a
			// useful diagnostic like "Access is denied"). That file is on disk and
			// the manifest walker WILL hash it, so it must not be silently absent
			// from result.Artifacts — otherwise the manifest lists a file the
			// result disowns. Register the non-empty capture as an artifact with a
			// warning that it is failed-command output; drop an empty one so a
			// zero-byte orphan is not left behind.
			registerFailedOutput(result, c.Filename, outPath)
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

// registerFailedOutput reconciles the file a failed command left on disk with
// the result. A non-empty capture is kept (it is the command's error output,
// which is itself forensically useful) and registered as an artifact with a
// warning so the manifest and result.Artifacts agree. An empty capture carries
// no value and is removed so no zero-byte orphan is hashed into the case.
func registerFailedOutput(result *Result, filename, outPath string) {
	info, statErr := os.Stat(outPath)
	if statErr != nil {
		return // command never wrote a file; nothing to reconcile
	}
	if info.Size() == 0 {
		_ = os.Remove(outPath)
		return
	}
	if artifact, err := describeArtifact(outPath); err == nil {
		result.Artifacts = append(result.Artifacts, artifact)
	}
	result.AddWarning(filename,
		"command failed; file contains the command's error output, not a clean artifact")
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
	return hashutil.SHA256File(path)
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

// copyEvidenceFile is the single content-copy chokepoint every collector uses.
// For a dead-image case with a raw-NTFS reader available (ctx.Image) it reads
// the source file's content directly off the volume's clusters, so on-access
// AV/EDR cannot block or quarantine the read — the collector gets the evidence
// even when Defender flags it as malware. For a live case (or an image root that
// is not a raw volume) it falls back to an ordinary OS copy. src is the full path
// under ctx.Root; dst is the case-folder destination.
func copyEvidenceFile(ctx *Context, src, dst string) error {
	if ctx != nil && ctx.Image != nil {
		return ctx.Image.copyFile(src, dst)
	}
	return copyFile(src, dst)
}

// readEvidenceBytes reads the full content of src for storage in a payload
// container, off the raw volume clusters wherever possible so on-access AV/EDR
// cannot block or quarantine the read of a web shell:
//
//   - dead-image case: ctx.Image reads by drive-letter path off the mounted image;
//   - live case: ctx.PayloadReader reads by shadow-root-relative path off the VSS
//     shadow device (src is under ctx.Root, the shadow mount, so the relative path
//     into the shadow's NTFS is src minus Root);
//   - otherwise (or if the raw read fails, e.g. a web root on a volume the shadow
//     does not cover): an ordinary OS read, which an on-access scanner may block.
//
// Used for payload-class artifacts (web-root scripts), which are small and
// size-capped, so reading into memory is fine. The raw bytes are stored unmodified
// inside the encrypted per-case container (internal/evidence); the artifact's true
// hash is recorded by the analyzer.
func readEvidenceBytes(ctx *Context, src string) ([]byte, error) {
	if ctx != nil && ctx.Image != nil {
		return ctx.Image.readAll(src)
	}
	if ctx != nil && ctx.PayloadReader != nil {
		if rel := rootRelativePath(src, ctx.Root); rel != "" {
			if b, err := ctx.PayloadReader.readAllRel(rel); err == nil {
				return b, nil
			}
			// Raw read failed (path not on the shadowed volume, or not found in the
			// snapshot). Fall through to an OS read as a best effort.
		}
	}
	return os.ReadFile(src)
}

// rootRelativePath returns src as a volume-root-relative path (leading "\") when
// src is under root, else "". Used to turn a shadow-mount path (root + subpath)
// into the path go-ntfs expects into the shadow's NTFS. E.g. root
// "C:\safe_shadow_1", src "C:\safe_shadow_1\inetpub\x.aspx" -> "\inetpub\x.aspx".
func rootRelativePath(src, root string) string {
	if root == "" {
		return ""
	}
	rel, err := filepath.Rel(root, src)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return ""
	}
	return `\` + rel
}

// discoverProfiles enumerates user profiles from the correct source for the
// evidence: the live registry for a live host, or the image's SOFTWARE hive
// (ProfileList) for a disk image. Every profile collector goes through this so
// it targets the imaged host's users, not the analyst's own.
func discoverProfiles(ctx *Context) ([]pathfinder.UserProfile, error) {
	if ctx.Live {
		return pathfinder.DiscoverUserProfiles()
	}
	softwareHive := filepath.Join(ctx.Root, "Windows", "System32", "config", "SOFTWARE")
	return pathfinder.DiscoverUserProfilesFromHive(softwareHive)
}

// IterateUserProfiles discovers all human user profiles on the system, maps
// their target paths to the active evidence root (VSS shadow mount or mounted
// image), creates a dedicated output directory for each user (named by SID),
// and calls the provided function fn. It reports progress via the Context and
// accumulates any errors. Built-in system profiles are skipped.
func IterateUserProfiles(mctx *Context, fn func(p pathfinder.UserProfile, rootProfilePath string, userOutputDir string) error) []error {
	var errs []error

	if mctx.Root == "" {
		return []error{fmt.Errorf("IterateUserProfiles requires an evidence root")}
	}

	profiles, err := discoverProfiles(mctx)
	if err != nil {
		return []error{fmt.Errorf("discover profiles: %w", err)}
	}

	for i, p := range profiles {
		// Report progress via Context (using dummy byte count for now, actual modules
		// should update their own artifact sizes later).
		mctx.ReportProgress(i, len(profiles), 0)

		if mctx.Ctx.Err() != nil {
			errs = append(errs, fmt.Errorf("skipped profile %s (context cancelled: %v)", p.SID, mctx.Ctx.Err()))
			continue
		}

		if p.IsBuiltin {
			continue
		}

		rootProfilePath, err := mapToRoot(p.ProfilePath, mctx.Root)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: root path mapping: %v", p.SID, err))
			continue
		}

		userDirName := sanitizeForDirName(p.SID)
		if userDirName == "" {
			userDirName = p.SID
		}
		userOutputDir := filepath.Join(mctx.OutputDir, userDirName)
		if err := os.MkdirAll(userOutputDir, 0o755); err != nil {
			errs = append(errs, fmt.Errorf("%s: mkdir: %v", p.SID, err))
			continue
		}

		if err := fn(p, rootProfilePath, userOutputDir); err != nil {
			errs = append(errs, fmt.Errorf("%s: %v", p.SID, err))
		}
	}
	
	mctx.ReportProgress(len(profiles), len(profiles), 0)
	return errs
}

// copyDir recursively copies a directory tree from src to dst, reading file
// content via copyEvidenceFile so a dead-image copy bypasses on-access AV.
// It returns the number of files copied, total bytes copied, and any errors.
func copyDir(ctx *Context, src string, dst string) (int, int64, []error) {
	var errs []error
	var count int
	var bytes int64

	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		// Honor the module's time budget / cancellation: a large tree (e.g.
		// SYSVOL) must be able to stop promptly when the context is cancelled
		// instead of copying to completion regardless.
		if ctxErr := ctx.Ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("walk access %s: %v", path, err))
			return nil
		}

		relPath, err := filepath.Rel(src, path)
		if err != nil {
			errs = append(errs, fmt.Errorf("rel path %s: %v", path, err))
			return nil
		}

		dstPath := filepath.Join(dst, relPath)

		if info.IsDir() {
			if err := os.MkdirAll(dstPath, 0o755); err != nil {
				errs = append(errs, fmt.Errorf("mkdir %s: %v", dstPath, err))
			}
			return nil
		}

		if !info.Mode().IsRegular() {
			return nil // Skip symlinks and other irregular files
		}

		if err := copyEvidenceFile(ctx, path, dstPath); err != nil {
			errs = append(errs, fmt.Errorf("copy %s: %v", path, err))
			return nil
		}

		count++
		bytes += info.Size()
		return nil
	})

	if err != nil {
		errs = append(errs, fmt.Errorf("walk %s: %v", src, err))
	}

	return count, bytes, errs
}
