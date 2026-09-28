package module

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"www.velocidex.com/golang/go-ntfs/parser"
)

type NTFSMetadata struct{}

func (m *NTFSMetadata) Name() string              { return "ntfs_metadata" }
func (m *NTFSMetadata) Priority() Priority        { return PriorityCritical }
func (m *NTFSMetadata) TimeBudget() time.Duration { return 5 * time.Minute }
func (m *NTFSMetadata) RequiresVSS() bool         { return true }

// NTFSMetadata is NOT live-only: it parses $MFT/$UsnJrnl/etc. from a raw NTFS
// volume. On a live host that raw volume is the VSS shadow device; for a dead
// disk image it is the mounted image volume via the shared raw-NTFS reader
// (ctx.Image). Either way, reading the volume's clusters bypasses on-access AV.

func (m *NTFSMetadata) Run(ctx *Context) Result {
	started := time.Now().UTC()
	result := Result{
		ModuleName: m.Name(),
		StartedAt:  started,
		Artifacts:  []Artifact{},
		Findings:   []Finding{},
		Errors:     []string{},
	}

	if !prepareOutputDir(&result, ctx.OutputDir, started) {
		return result
	}

	// maxTailBytes caps how much of a target is collected, reading the LAST
	// maxTailBytes (0 = whole file). $UsnJrnl:$J is a sparse stream whose logical
	// size can be tens of GB while only the tail holds live records (old entries
	// are deallocated as the journal trims). Copying it whole materialises many GB
	// of sparse zeros, so collect only the recent tail — where the forensically
	// useful activity is. $MFT/$LogFile/$Secure/$Boot are dense and collected whole.
	const usnTailCap = 1 << 30 // 1 GiB of recent USN activity
	targets := []struct {
		vssPath      string
		outputName   string
		description  string
		maxTailBytes int64
	}{
		{
			vssPath:     `$MFT`,
			outputName:  `MFT`,
			description: "Master File Table",
		},
		{
			vssPath:     `$LogFile`,
			outputName:  `LogFile`,
			description: "NTFS Transaction Log",
		},
		{
			vssPath:     `$Boot`,
			outputName:  `Boot`,
			description: "Volume Boot Record",
		},
		{
			vssPath:     `$Secure:$SDS`,
			outputName:  `Secure_SDS`,
			description: "Security Descriptors",
		},
		{
			vssPath:      `$Extend\$UsnJrnl:$J`,
			outputName:   `UsnJrnl_J`,
			description:  "Update Sequence Number Journal",
			maxTailBytes: usnTailCap,
		},
	}

	// Acquire the parsed NTFS volume. Live: parse the raw VSS shadow device.
	// Dead image: reuse the shared raw-NTFS reader already opened over the mounted
	// image volume (ctx.Image), which reads clusters directly and so also bypasses
	// on-access AV.
	var ntfsCtx *parser.NTFSContext
	if ctx.Live {
		if ctx.Shadow == nil {
			result.AddWarning("vss", "no shadow copy available; module requires VSS on a live host")
			result.Errors = append(result.Errors, "no shadow available")
			finalize(&result, started, ctx.Ctx)
			return result
		}
		fd, err := os.Open(ctx.Shadow.ShadowPath)
		if err != nil {
			result.AddWarning(m.Name(), fmt.Sprintf("failed to open raw shadow volume: %v", err))
			result.Errors = append(result.Errors, fmt.Sprintf("volume open: %v", err))
			finalize(&result, started, ctx.Ctx)
			return result
		}
		defer fd.Close()

		// Windows raw volume handles require sector-aligned reads.
		// PagedReader provides buffered, aligned reading.
		pagedReader, err := parser.NewPagedReader(fd, 1024*1024, 100)
		if err != nil {
			result.AddWarning(m.Name(), fmt.Sprintf("failed to create paged reader: %v", err))
			result.Errors = append(result.Errors, fmt.Sprintf("paged reader: %v", err))
			finalize(&result, started, ctx.Ctx)
			return result
		}

		ntfsCtx, err = parser.GetNTFSContext(pagedReader, 0)
		if err != nil {
			result.AddWarning(m.Name(), fmt.Sprintf("failed to parse NTFS on shadow volume: %v", err))
			result.Errors = append(result.Errors, fmt.Sprintf("ntfs parse: %v", err))
			finalize(&result, started, ctx.Ctx)
			return result
		}
	} else {
		if ctx.Image == nil || ctx.Image.ntfsCtx == nil {
			// The image mounted, but not as a raw block volume (e.g. an FTK Imager
			// "File System" mount, which presents a filesystem redirector rather than
			// the raw NTFS volume), so $MFT/$UsnJrnl cannot be read via raw NTFS. This
			// is a degradation, not a fatal error: the file/hive collectors can still
			// run via OS reads. Emit a warning (→ StatusPartial via finalize) rather
			// than an error (→ StatusFailed), so this critical module does NOT abort the
			// whole profile — the analyst gets whatever else is collectable in one run,
			// plus a clear instruction to re-mount for full fidelity.
			result.AddWarning(m.Name(), "$MFT/$UsnJrnl not collected: the mounted image is not a raw block volume. Re-mount as a block device / raw volume (not a file-system mount) — e.g. FTK Imager 'Block Device / Read Only' — to collect NTFS metadata and enable AV-agnostic reads.")
			finalize(&result, started, ctx.Ctx)
			return result
		}
		ntfsCtx = ctx.Image.ntfsCtx
	}

	var totalBytes int64

	for i, t := range targets {
		ctx.ReportProgress(i, len(targets), totalBytes)

		if ctx.Ctx.Err() != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: skipped (context cancelled)", t.outputName))
			continue
		}

		dstPath := filepath.Join(ctx.OutputDir, t.outputName)

		// Parse the NTFS artifact directly from the raw shadow volume
		readerAt, err := parser.GetDataForPath(ntfsCtx, `\`+t.vssPath)
		if err != nil {
			result.AddWarning(t.outputName, fmt.Sprintf("NTFS parse failed: %v", err))
			result.Errors = append(result.Errors, fmt.Sprintf("%s parse: %v", t.outputName, err))
			if t.outputName == "MFT" {
				result.AddCritical(m.Name(), "Critical NTFS metadata file ($MFT) could not be parsed")
			}
			continue
		}

		size := parser.RangeSize(readerAt)

		// Collect only the recent tail of a capped (sparse) target like $UsnJrnl:$J
		// so we don't materialise tens of GB of sparse zeros.
		readOffset := int64(0)
		readLen := size
		if t.maxTailBytes > 0 && size > t.maxTailBytes {
			readOffset = size - t.maxTailBytes
			readLen = t.maxTailBytes
			result.AddInfo(t.outputName, fmt.Sprintf(
				"%s logical size is %d bytes (sparse journal); collected the last %d bytes of recent activity",
				t.outputName, size, t.maxTailBytes))
		}
		reader := io.NewSectionReader(readerAt, readOffset, readLen)

		out, err := os.Create(dstPath)
		if err != nil {
			result.AddWarning(t.outputName, fmt.Sprintf("create failed: %v", err))
			result.Errors = append(result.Errors, fmt.Sprintf("%s create: %v", t.outputName, err))
			continue
		}

		if _, err := io.Copy(out, reader); err != nil {
			out.Close()
			result.AddWarning(t.outputName, fmt.Sprintf("copy failed: %v", err))
			result.Errors = append(result.Errors, fmt.Sprintf("%s copy: %v", t.outputName, err))
			continue
		}
		out.Close()

		artifact, err := describeArtifact(dstPath)
		if err != nil {
			result.AddWarning(t.outputName, fmt.Sprintf("hash failed: %v", err))
			continue
		}

		artifact.SourcePath = `C:\` + t.vssPath
		artifact.SourceSize = size

		result.Artifacts = append(result.Artifacts, artifact)
		totalBytes += readLen
	}

	ctx.ReportProgress(len(targets), len(targets), totalBytes)

	if len(result.Artifacts) == 0 {
		result.AddInfo(m.Name(), "failed to collect any NTFS metadata artifacts")
	} else if len(result.Artifacts) < len(targets) {
		result.AddInfo(m.Name(), fmt.Sprintf("collected %d/%d NTFS metadata artifacts", len(result.Artifacts), len(targets)))
	} else {
		result.AddInfo(m.Name(), "successfully collected all core NTFS metadata structures")
	}

	finalize(&result, started, ctx.Ctx)
	return result
}
