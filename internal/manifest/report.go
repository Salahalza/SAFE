package manifest

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type CaseSummary struct {
	CaseID      string
	IRNumber    string
	CSINumber   string
	Analyst     string
	Target      string
	TargetClass string
	Notes       string
	Profile     string
	// ProfileVersion pins which version of the profile ran (the same profile
	// name can collect different modules across releases).
	ProfileVersion string
	SAFEVersion    string
	// CollectedHost is the hostname read from the collected system metadata,
	// distinct from Target (which is the analyst's free-text label). Empty if
	// it could not be determined.
	CollectedHost string
	// ShadowID is the Volume Shadow Copy used for this case, surfaced as
	// collection provenance. Empty if no module required VSS.
	ShadowID string
	// TotalBytes is the total size on disk of collected module artifacts.
	TotalBytes int64
	StartedAt  time.Time
	EndedAt    time.Time
	Duration   time.Duration
	Status     string
	Modules    []ModuleSummary
}

// FindingSummary is one observation classified by severity.
type FindingSummary struct {
	Severity string
	Source   string
	Message  string
}

type ModuleSummary struct {
	Name          string
	Status        string
	Duration      time.Duration
	ArtifactCount int
	BulkFiles     int
	Findings      []FindingSummary
	Errors        []string
}

// InfoCount returns the count of info-severity findings.
func (m ModuleSummary) InfoCount() int {
	count := 0
	for _, f := range m.Findings {
		if f.Severity == "info" {
			count++
		}
	}
	return count
}

// WarningCount returns the count of warning-severity findings.
func (m ModuleSummary) WarningCount() int {
	count := 0
	for _, f := range m.Findings {
		if f.Severity == "warning" {
			count++
		}
	}
	return count
}

// CriticalCount returns the count of critical-severity findings.
func (m ModuleSummary) CriticalCount() int {
	count := 0
	for _, f := range m.Findings {
		if f.Severity == "critical" {
			count++
		}
	}
	return count
}

func WriteCaseReport(caseDir string, s CaseSummary) error {
	var b strings.Builder

	b.WriteString(strings.Repeat("=", 70) + "\n")
	b.WriteString(fmt.Sprintf("SAFE CASE REPORT — %s\n", s.CaseID))
	b.WriteString(strings.Repeat("=", 70) + "\n\n")
	b.WriteString(fmt.Sprintf("Case ID:      %s\n", s.CaseID))
	if s.IRNumber != "" {
		b.WriteString(fmt.Sprintf("IR#:          %s\n", s.IRNumber))
	}
	if s.CSINumber != "" {
		b.WriteString(fmt.Sprintf("CSI#:         %s\n", s.CSINumber))
	}
	b.WriteString(fmt.Sprintf("Analyst:      %s\n", s.Analyst))
	b.WriteString(fmt.Sprintf("Target:       %s (%s)\n", s.Target, s.TargetClass))
	if s.CollectedHost != "" {
		b.WriteString(fmt.Sprintf("Collected host: %s\n", s.CollectedHost))
	}
	if s.Notes != "" {
		b.WriteString(fmt.Sprintf("Notes:        %s\n", s.Notes))
	}
	if s.ProfileVersion != "" {
		b.WriteString(fmt.Sprintf("Profile:      %s (v%s)\n", s.Profile, s.ProfileVersion))
	} else {
		b.WriteString(fmt.Sprintf("Profile:      %s\n", s.Profile))
	}
	b.WriteString(fmt.Sprintf("SAFE:         v%s\n", s.SAFEVersion))
	b.WriteString(fmt.Sprintf("Started:      %s\n", s.StartedAt.Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("Ended:        %s\n", s.EndedAt.Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("Duration:     %s\n", s.Duration))
	b.WriteString(fmt.Sprintf("Status:       %s\n\n", strings.ToUpper(s.Status)))

	b.WriteString(statusGuidance(s.Status))
	b.WriteString("\n")

	b.WriteString(strings.Repeat("-", 70) + "\n")
	b.WriteString("MODULE SUMMARY\n")
	b.WriteString(strings.Repeat("-", 70) + "\n\n")

	totalArtifacts := 0
	totalBulkFiles := 0
	totalInfo := 0
	totalWarnings := 0
	totalCritical := 0
	totalErrors := 0

	for _, m := range s.Modules {
		totalArtifacts += m.ArtifactCount
		totalBulkFiles += m.BulkFiles
		totalInfo += m.InfoCount()
		totalWarnings += m.WarningCount()
		totalCritical += m.CriticalCount()
		totalErrors += len(m.Errors)

		b.WriteString(fmt.Sprintf("[%s] %s\n", strings.ToUpper(m.Status), m.Name))
		b.WriteString(fmt.Sprintf("  Duration:  %s\n", m.Duration))
		b.WriteString(fmt.Sprintf("  Artifacts: %d\n", m.ArtifactCount))
		if m.BulkFiles > 0 {
			b.WriteString(fmt.Sprintf("  Bulk files: %d\n", m.BulkFiles))
		}

		if len(m.Errors) > 0 {
			b.WriteString(fmt.Sprintf("  Errors:    %d\n", len(m.Errors)))
			for _, e := range m.Errors {
				b.WriteString(fmt.Sprintf("    ✗ %s\n", truncate(e, 200)))
			}
		}

		// Show critical first, then warnings, then info — most important first.
		printed := false
		for _, sev := range []string{"critical", "warning", "info"} {
			label := map[string]string{
				"critical": "Critical:  ",
				"warning":  "Warnings:  ",
				"info":     "Info:      ",
			}[sev]
			marker := map[string]string{
				"critical": "✗",
				"warning":  "⚠",
				"info":     "ℹ",
			}[sev]

			count := 0
			for _, f := range m.Findings {
				if f.Severity == sev {
					count++
				}
			}
			if count == 0 {
				continue
			}
			if !printed {
				printed = true
			}
			b.WriteString(fmt.Sprintf("  %s%d\n", label, count))
			for _, f := range m.Findings {
				if f.Severity != sev {
					continue
				}
				if f.Source != "" {
					b.WriteString(fmt.Sprintf("    %s %s: %s\n", marker, f.Source, truncate(f.Message, 200)))
				} else {
					b.WriteString(fmt.Sprintf("    %s %s\n", marker, truncate(f.Message, 200)))
				}
			}
		}

		b.WriteString("\n")
	}

	b.WriteString(strings.Repeat("-", 70) + "\n")
	b.WriteString("TOTALS\n")
	b.WriteString(strings.Repeat("-", 70) + "\n\n")
	b.WriteString(fmt.Sprintf("Modules run:           %d\n", len(s.Modules)))
	b.WriteString(fmt.Sprintf("Primary artifacts:     %d\n", totalArtifacts))
	if totalBulkFiles > 0 {
		b.WriteString(fmt.Sprintf("Bulk-collected files:  %d\n", totalBulkFiles))
		b.WriteString(fmt.Sprintf("Total collected files: %d\n", totalArtifacts+totalBulkFiles))
	}
	if s.TotalBytes > 0 {
		b.WriteString(fmt.Sprintf("Total bytes collected: %s\n", humanBytes(s.TotalBytes)))
	}
	b.WriteString(fmt.Sprintf("Critical:              %d\n", totalCritical))
	b.WriteString(fmt.Sprintf("Warnings:              %d\n", totalWarnings))
	b.WriteString(fmt.Sprintf("Info observations:     %d\n", totalInfo))
	b.WriteString(fmt.Sprintf("Errors:                %d\n", totalErrors))
	b.WriteString("\n")

	b.WriteString(strings.Repeat("-", 70) + "\n")
	b.WriteString("INSPECTION PRIORITY\n")
	b.WriteString(strings.Repeat("-", 70) + "\n\n")
	b.WriteString(buildInspectionList(s.Modules))
	b.WriteString("\n")
	b.WriteString("NOTE: This is a collection-time report. Priorities above reflect the\n")
	b.WriteString("collection run only — they do NOT include analyzer (IOC) findings. Run\n")
	b.WriteString("`safe --analyze <case>` for UserAssist/Prefetch/COM-hijack/process-memory\n")
	b.WriteString("triage; review lab_report/ for any HIGH/NOTABLE detections.\n")
	b.WriteString("\n")

	b.WriteString(strings.Repeat("-", 70) + "\n")
	b.WriteString("COLLECTION PROVENANCE\n")
	b.WriteString(strings.Repeat("-", 70) + "\n\n")
	if s.ShadowID != "" {
		b.WriteString(fmt.Sprintf("Volume Shadow Copy: %s\n", s.ShadowID))
		b.WriteString("  Locked-file artifacts (registry hives, Amcache, prefetch, user hives)\n")
		b.WriteString("  were read from this point-in-time snapshot of C:.\n")
	} else {
		b.WriteString("Volume Shadow Copy: none (no module required VSS for this profile).\n")
	}
	b.WriteString("\n")

	b.WriteString(strings.Repeat("-", 70) + "\n")
	b.WriteString("VERIFICATION\n")
	b.WriteString(strings.Repeat("-", 70) + "\n\n")
	b.WriteString("To verify case integrity:\n")
	b.WriteString(fmt.Sprintf("  safe --verify %s\n\n", filepath.Base(caseDir)))
	b.WriteString("Every collected artifact and module manifest is hashed in manifest.sha256;\n")
	b.WriteString("analyzer output (once --analyze has run) is hashed in lab_report/manifest.sha256.\n")
	b.WriteString("--verify recomputes every hash and reconciles against the filesystem, so any\n")
	b.WriteString("modification, removal, OR addition of a file in this folder is detected.\n")

	reportPath := filepath.Join(caseDir, "case_report.txt")
	return os.WriteFile(reportPath, []byte(b.String()), 0o644)
}

func statusGuidance(status string) string {
	switch strings.ToLower(status) {
	case "success":
		return "✓ All modules completed successfully. Standard analysis can proceed.\n"
	case "partial":
		return "⚠ Some modules completed with warnings or critical findings.\n" +
			"  Check the per-module breakdown below — review critical and warning items\n" +
			"  before trusting specific artifacts. Info-level observations are normal\n" +
			"  and do not require investigation.\n"
	case "degraded":
		return "⚠ One or more modules failed entirely. Collection is incomplete. Check the\n" +
			"  errors below — common causes are missing administrator privileges, EDR\n" +
			"  interference, or unsupported target configurations. Re-collection may be\n" +
			"  needed depending on which modules failed.\n"
	default:
		return fmt.Sprintf("Status %q — see module details below.\n", status)
	}
}

func buildInspectionList(modules []ModuleSummary) string {
	type entry struct {
		priority int
		module   string
		reason   string
	}

	var entries []entry
	for _, m := range modules {
		switch strings.ToLower(m.Status) {
		case "failed":
			entries = append(entries, entry{0, m.Name, "entire module failed — re-collection may be needed"})
		case "timed_out":
			entries = append(entries, entry{1, m.Name, "module exceeded time budget — partial output may be present"})
		case "partial":
			critical := m.CriticalCount()
			warning := m.WarningCount()
			if critical > 0 {
				entries = append(entries, entry{2, m.Name,
					fmt.Sprintf("%d critical finding(s) — inspect immediately", critical)})
			} else if warning > 0 {
				entries = append(entries, entry{3, m.Name,
					fmt.Sprintf("%d warning(s) — inspect for dropped or suspicious artifacts", warning)})
			}
		}
	}

	if len(entries) == 0 {
		return "No specific inspection priorities — modules completed cleanly.\n" +
			"Info-level observations may be present but do not require action.\n"
	}

	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].priority < entries[j].priority
	})

	var b strings.Builder
	b.WriteString("Review in this order:\n\n")
	for i, e := range entries {
		b.WriteString(fmt.Sprintf("  %d. %s\n     → %s\n", i+1, e.module, e.reason))
	}
	return b.String()
}

func truncate(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	// Truncate on a rune boundary so a multibyte character at the cut point is
	// not split into invalid UTF-8 (registry/path text can contain non-ASCII).
	r := []rune(s)
	if len(r) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return string(r[:maxLen])
	}
	return string(r[:maxLen-3]) + "..."
}

// humanBytes formats a byte count as a human-readable string (e.g. "1.4 GB").
// Uses binary units (1024) to match how Windows reports file sizes.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
