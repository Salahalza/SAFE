package manifest

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// CaseSummary is the input the report generator needs.
// Built from the engine's CaseResult, passed to WriteCaseReport.
type CaseSummary struct {
	CaseID      string
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

// ModuleSummary captures what one module did, for reporting purposes.
type ModuleSummary struct {
	Name          string
	Status        string
	Duration      time.Duration
	ArtifactCount int
	Warnings      []string
	Errors        []string
}

// WriteCaseReport produces a human-readable case_report.txt at the case root.
// It's the first file a lab analyst should open — gives a 30-second
// overview of what happened, what to inspect, and where the issues are.
func WriteCaseReport(caseDir string, s CaseSummary) error {
	var b strings.Builder

	// Header.
	b.WriteString(strings.Repeat("=", 70) + "\n")
	b.WriteString(fmt.Sprintf("SAHM CASE REPORT — %s\n", s.CaseID))
	b.WriteString(strings.Repeat("=", 70) + "\n\n")

	// Case identity.
	b.WriteString(fmt.Sprintf("Case ID:      %s\n", s.CaseID))
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

	// Status interpretation.
	b.WriteString(statusGuidance(s.Status))
	b.WriteString("\n")

	// Per-module summary.
	b.WriteString(strings.Repeat("-", 70) + "\n")
	b.WriteString("MODULE SUMMARY\n")
	b.WriteString(strings.Repeat("-", 70) + "\n\n")

	totalArtifacts := 0
	totalWarnings := 0
	totalErrors := 0

	for _, m := range s.Modules {
		totalArtifacts += m.ArtifactCount
		totalWarnings += len(m.Warnings)
		totalErrors += len(m.Errors)

		b.WriteString(fmt.Sprintf("[%s] %s\n", strings.ToUpper(m.Status), m.Name))
		b.WriteString(fmt.Sprintf("  Duration:  %s\n", m.Duration))
		b.WriteString(fmt.Sprintf("  Artifacts: %d\n", m.ArtifactCount))

		if len(m.Errors) > 0 {
			b.WriteString(fmt.Sprintf("  Errors:    %d\n", len(m.Errors)))
			for _, e := range m.Errors {
				b.WriteString(fmt.Sprintf("    ✗ %s\n", truncate(e, 200)))
			}
		}

		if len(m.Warnings) > 0 {
			b.WriteString(fmt.Sprintf("  Warnings:  %d\n", len(m.Warnings)))
			for _, w := range m.Warnings {
				b.WriteString(fmt.Sprintf("    ⚠ %s\n", truncate(w, 200)))
			}
		}

		b.WriteString("\n")
	}

	// Totals.
	b.WriteString(strings.Repeat("-", 70) + "\n")
	b.WriteString("TOTALS\n")
	b.WriteString(strings.Repeat("-", 70) + "\n\n")
	b.WriteString(fmt.Sprintf("Modules run:       %d\n", len(s.Modules)))
	b.WriteString(fmt.Sprintf("Artifacts:         %d\n", totalArtifacts))
	b.WriteString(fmt.Sprintf("Warnings:          %d\n", totalWarnings))
	b.WriteString(fmt.Sprintf("Errors:            %d\n", totalErrors))
	b.WriteString("\n")

	// Inspection guidance.
	b.WriteString(strings.Repeat("-", 70) + "\n")
	b.WriteString("INSPECTION PRIORITY\n")
	b.WriteString(strings.Repeat("-", 70) + "\n\n")
	b.WriteString(buildInspectionList(s.Modules))
	b.WriteString("\n")

	// Verification hint.
	b.WriteString(strings.Repeat("-", 70) + "\n")
	b.WriteString("VERIFICATION\n")
	b.WriteString(strings.Repeat("-", 70) + "\n\n")
	b.WriteString("To verify case integrity:\n")
	b.WriteString(fmt.Sprintf("  sahm --verify %s\n\n", filepath.Base(caseDir)))
	b.WriteString("All artifacts and module manifests are hashed in manifest.sha256.\n")
	b.WriteString("Any modification to files in this folder will be detected.\n")

	// Write file.
	reportPath := filepath.Join(caseDir, "case_report.txt")
	return os.WriteFile(reportPath, []byte(b.String()), 0o644)
}

// statusGuidance returns a one-paragraph interpretation of what the
// overall status means for the lab analyst.
func statusGuidance(status string) string {
	switch strings.ToLower(status) {
	case "success":
		return "✓ All modules completed successfully. Standard analysis can proceed.\n"
	case "partial":
		return "⚠ Some modules completed with warnings. Review the warnings below — they\n" +
			"  indicate artifacts that were dropped, fell back to alternates, or contain\n" +
			"  unexpected content. The collection is usable, but specific files need\n" +
			"  analyst attention before being trusted.\n"
	case "degraded":
		return "⚠ One or more modules failed entirely. Collection is incomplete. Check the\n" +
			"  errors below — common causes are missing administrator privileges, EDR\n" +
			"  interference, or unsupported target configurations. Re-collection may be\n" +
			"  needed depending on which modules failed.\n"
	default:
		return fmt.Sprintf("Status %q — see module details below.\n", status)
	}
}

// buildInspectionList produces an ordered list of what the lab should look at first.
// Failed and timed-out modules come first, then partial, then successful.
func buildInspectionList(modules []ModuleSummary) string {
	type entry struct {
		priority int // lower = higher priority for review
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
			entries = append(entries, entry{2, m.Name, fmt.Sprintf("%d warning(s) — inspect for dropped or suspicious artifacts", len(m.Warnings))})
		}
	}

	if len(entries) == 0 {
		return "No specific inspection priorities — all modules completed cleanly.\n"
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

// truncate cuts a string at maxLen and adds ellipsis if needed.
func truncate(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
