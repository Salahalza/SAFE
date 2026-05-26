package preflight

import (
	"fmt"
)

// DiskCheck verifies there's enough free space at the output directory.
type DiskCheck struct {
	// OutputPath is the directory where SAHM will write evidence.
	OutputPath string

	// MinimumBytes is the minimum free space required.
	// Default: 5 GB if zero.
	MinimumBytes uint64
}

func (c *DiskCheck) Name() string { return "disk_space" }

func (c *DiskCheck) Run() *Finding {
	if c.MinimumBytes == 0 {
		c.MinimumBytes = 5 * 1024 * 1024 * 1024 // 5 GB default
	}

	free, err := diskFreeBytes(c.OutputPath)
	if err != nil {
		return &Finding{
			Check:    c.Name(),
			Severity: SeverityWarning,
			Message:  "Could not determine free disk space.",
			Detail:   fmt.Sprintf("Path: %s, Error: %v", c.OutputPath, err),
		}
	}

	if free < c.MinimumBytes {
		return &Finding{
			Check:    c.Name(),
			Severity: SeverityCritical,
			Message:  fmt.Sprintf("Insufficient free disk space (have %s, need %s).", humanBytes(free), humanBytes(c.MinimumBytes)),
			Detail:   fmt.Sprintf("Output path: %s. Free up space or use a different output location.", c.OutputPath),
		}
	}

	// Warn if we're under 20 GB but above the minimum — enough to start, but
	// extended profiles will fill it fast.
	const warnThreshold = 20 * 1024 * 1024 * 1024
	if free < warnThreshold {
		return &Finding{
			Check:    c.Name(),
			Severity: SeverityWarning,
			Message:  fmt.Sprintf("Low free disk space (%s available).", humanBytes(free)),
			Detail:   "Extended profiles or memory captures may exhaust this space.",
		}
	}

	return nil
}

// humanBytes formats a byte count as a human-readable string (e.g. "1.5 GB").
func humanBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
