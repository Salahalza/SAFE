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
	SAHMVersion string
	StartedAt   time.Time
	EndedAt     time.Time
	Duration    time.Duration
	Status      string
	Modules     []ModuleSummary
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
	b.WriteString(fmt.Sprintf("SAHM CASE REPORT — %s\n", s.CaseID))
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
	if s.Notes != "" {
		b.WriteString(fmt.Sprintf("Notes:        %s\n", s.Notes))
	}
	b.WriteString(fmt.Sprintf("Profile:      %s\n", s.Profile))
	b.WriteString(fmt.Sprintf("SAHM:         v%s\n", s.SAHMVersion))
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
		b.WriteString(fmt.Sprintf("Total files in case:   %d\n", totalArtifacts+totalBulkFiles))
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

	b.WriteString(strings.Repeat("-", 70) + "\n")
	b.WriteString("VERIFICATION\n")
	b.WriteString(strings.Repeat("-", 70) + "\n\n")
	b.WriteString("To verify case integrity:\n")
	b.WriteString(fmt.Sprintf("  sahm --verify %s\n\n", filepath.Base(caseDir)))
	b.WriteString("All artifacts and module manifests are hashed in manifest.sha256.\n")
	b.WriteString("Any modification to files in this folder will be detected.\n")

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
	return s[:maxLen-3] + "..."
}
