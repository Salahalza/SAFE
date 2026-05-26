package preflight

import (
	"fmt"
	"os"
	"path/filepath"
)

// DiskCheck verifies there's enough free space at the output directory.
type DiskCheck struct {
	OutputPath   string
	MinimumBytes uint64
}

func (c *DiskCheck) Name() string { return "disk_space" }

func (c *DiskCheck) Run() *Finding {
	if c.MinimumBytes == 0 {
		c.MinimumBytes = 5 * 1024 * 1024 * 1024 // 5 GB default
	}

	// Resolve to an existing ancestor directory. The output dir may not
	// exist yet — we still want to check the volume's free space.
	checkPath, err := resolveExistingAncestor(c.OutputPath)
	if err != nil {
		return &Finding{
			Check:    c.Name(),
			Severity: SeverityWarning,
			Message:  "Could not resolve a valid path for disk space check.",
			Detail:   fmt.Sprintf("Path: %s, Error: %v", c.OutputPath, err),
		}
	}

	free, err := diskFreeBytes(checkPath)
	if err != nil {
		return &Finding{
			Check:    c.Name(),
			Severity: SeverityWarning,
			Message:  "Could not determine free disk space.",
			Detail:   fmt.Sprintf("Path: %s, Error: %v", checkPath, err),
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

// resolveExistingAncestor walks up from path until it finds an existing
// directory. Returns the first existing ancestor, or the absolute root
// if none of the path components exist.
func resolveExistingAncestor(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}

	current := abs
	for {
		info, err := os.Stat(current)
		if err == nil && info.IsDir() {
			return current, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			// Reached the root without finding anything.
			return current, nil
		}
		current = parent
	}
}

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
