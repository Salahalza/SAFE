package tui

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// reportData holds the parsed case data we need to render the structured
// report view. It's a TUI-side struct so we don't pull in dependencies on
// the engine/casemeta packages just for rendering — we re-parse from JSON.
type reportData struct {
	CaseID      string
	IRNumber    string
	CSINumber   string
	Analyst     string
	Target      string
	TargetClass string
	Profile     string
	SAHMVersion string
	Notes       string
	CreatedAt   time.Time

	Status    string
	StartedAt time.Time
	EndedAt   time.Time
	Duration  time.Duration
	CaseDir   string

	Modules []reportModule
}

type reportModule struct {
	Name      string
	Status    string
	Duration  time.Duration
	Artifacts int
	BulkFiles int
	Findings  []reportFinding
	Errors    []string
}

type reportFinding struct {
	Severity string
	Source   string
	Message  string
}

// loadReportData reads case.json and result.json from a case folder and
// produces a unified view ready for rendering.
func loadReportData(caseDir string) (*reportData, error) {
	// case.json — user-supplied metadata
	caseJSON := filepath.Join(caseDir, "case.json")
	caseBytes, err := os.ReadFile(caseJSON)
	if err != nil {
		return nil, fmt.Errorf("read case.json: %w", err)
	}
	var caseRaw struct {
		CaseID           string    `json:"case_id"`
		IRNumber         string    `json:"ir_number"`
		CSINumber        string    `json:"csi_number"`
		Analyst          string    `json:"analyst"`
		TargetIdentifier string    `json:"target_identifier"`
		TargetClass      string    `json:"target_class"`
		Notes            string    `json:"notes"`
		ProfileName      string    `json:"profile_name"`
		CreatedAt        time.Time `json:"created_at"`
		SAHMVersion      string    `json:"sahm_version"`
	}
	if err := json.Unmarshal(caseBytes, &caseRaw); err != nil {
		return nil, fmt.Errorf("parse case.json: %w", err)
	}

	// result.json — engine output
	resultJSON := filepath.Join(caseDir, "result.json")
	resultBytes, err := os.ReadFile(resultJSON)
	if err != nil {
		return nil, fmt.Errorf("read result.json: %w", err)
	}
	var resultRaw struct {
		CaseDir     string        `json:"case_dir"`
		ProfileName string        `json:"profile_name"`
		StartedAt   time.Time     `json:"started_at"`
		EndedAt     time.Time     `json:"ended_at"`
		Duration    time.Duration `json:"duration_ns"`
		Status      string        `json:"status"`
		Modules     []struct {
			ModuleName string        `json:"module_name"`
			Status     string        `json:"status"`
			Duration   time.Duration `json:"duration_ns"`
			Artifacts  []any         `json:"artifacts"`
			BulkFiles  int           `json:"bulk_files"`
			Findings   []struct {
				Severity string `json:"severity"`
				Source   string `json:"source"`
				Message  string `json:"message"`
			} `json:"findings"`
			Errors []string `json:"errors"`
		} `json:"modules"`
	}
	if err := json.Unmarshal(resultBytes, &resultRaw); err != nil {
		return nil, fmt.Errorf("parse result.json: %w", err)
	}

	rd := &reportData{
		CaseID:      caseRaw.CaseID,
		IRNumber:    caseRaw.IRNumber,
		CSINumber:   caseRaw.CSINumber,
		Analyst:     caseRaw.Analyst,
		Target:      caseRaw.TargetIdentifier,
		TargetClass: caseRaw.TargetClass,
		Profile:     caseRaw.ProfileName,
		SAHMVersion: caseRaw.SAHMVersion,
		Notes:       caseRaw.Notes,
		CreatedAt:   caseRaw.CreatedAt,
		Status:      resultRaw.Status,
		StartedAt:   resultRaw.StartedAt,
		EndedAt:     resultRaw.EndedAt,
		Duration:    resultRaw.Duration,
		CaseDir:     resultRaw.CaseDir,
	}

	for _, m := range resultRaw.Modules {
		mod := reportModule{
			Name:      m.ModuleName,
			Status:    m.Status,
			Duration:  m.Duration,
			Artifacts: len(m.Artifacts),
			BulkFiles: m.BulkFiles,
			Errors:    m.Errors,
		}
		for _, f := range m.Findings {
			mod.Findings = append(mod.Findings, reportFinding{
				Severity: f.Severity,
				Source:   f.Source,
				Message:  f.Message,
			})
		}
		rd.Modules = append(rd.Modules, mod)
	}

	return rd, nil
}

// renderReport produces the styled report content for the viewport.
// The width parameter is the available content width inside the viewport.
func renderReport(rd *reportData, width int) string {
	var b strings.Builder

	b.WriteString(renderHeaderCard(rd, width))
	b.WriteString("\n")

	b.WriteString(renderAtAGlance(rd))
	b.WriteString("\n\n")

	// Critical and warning findings get a prominent section on top.
	criticals, warnings := collectFindings(rd)
	if len(criticals) > 0 {
		b.WriteString(renderCriticalSection(criticals, width))
		b.WriteString("\n")
	}
	if len(warnings) > 0 {
		b.WriteString(renderWarningSection(warnings, width))
		b.WriteString("\n")
	}

	b.WriteString(renderModulesTable(rd))
	b.WriteString("\n\n")

	b.WriteString(renderObservations(rd))
	b.WriteString("\n")

	b.WriteString(renderVerificationFooter(rd))

	return b.String()
}

// renderHeaderCard creates the bordered metadata card at the top.
func renderHeaderCard(rd *reportData, width int) string {
	var rows []string

	// Title line
	rows = append(rows, lipgloss.NewStyle().
		Foreground(lipgloss.Color("#7DD3FC")).
		Bold(true).
		Render("CASE REPORT"))
	rows = append(rows, "")

	// Build the metadata grid — two columns of label/value pairs.
	left := []labelValuePair{
		{"Case ID", rd.CaseID},
	}
	if rd.IRNumber != "" {
		left = append(left, labelValuePair{"IR#", rd.IRNumber})
	}
	if rd.CSINumber != "" {
		left = append(left, labelValuePair{"CSI#", rd.CSINumber})
	}
	left = append(left, labelValuePair{"Target", fmt.Sprintf("%s (%s)", rd.Target, rd.TargetClass)})
	left = append(left, labelValuePair{"Analyst", rd.Analyst})

	right := []labelValuePair{
		{"Status", statusBadgeStyle(rd.Status)},
		{"Duration", rd.Duration.Round(time.Millisecond).String()},
		{"Profile", rd.Profile},
		{"Started", rd.StartedAt.UTC().Format("2006-01-02 15:04 UTC")},
	}

	// Render side by side, padding to longest column count.
	rows = append(rows, renderTwoColumnGrid(left, right))

	if rd.Notes != "" {
		rows = append(rows, "")
		rows = append(rows, metadataLabelStyle.Render("Notes:")+" "+metadataValueStyle.Render(rd.Notes))
	}

	content := strings.Join(rows, "\n")

	// Width the card to the viewport (minus border characters).
	cardWidth := width - 4
	if cardWidth < 40 {
		cardWidth = 40
	}
	return cardStyle.Width(cardWidth).Render(content)
}

type labelValuePair struct {
	label string
	value string
}

// renderTwoColumnGrid renders pairs of labels and values in two columns.
// Both columns are padded to the same height.
func renderTwoColumnGrid(left, right []labelValuePair) string {
	maxRows := len(left)
	if len(right) > maxRows {
		maxRows = len(right)
	}

	var leftLines, rightLines []string
	for i := 0; i < maxRows; i++ {
		if i < len(left) {
			leftLines = append(leftLines, formatLabelValue(left[i], 10))
		} else {
			leftLines = append(leftLines, "")
		}
		if i < len(right) {
			rightLines = append(rightLines, formatLabelValue(right[i], 10))
		} else {
			rightLines = append(rightLines, "")
		}
	}

	leftCol := lipgloss.NewStyle().Width(40).Render(strings.Join(leftLines, "\n"))
	rightCol := lipgloss.NewStyle().Render(strings.Join(rightLines, "\n"))

	return lipgloss.JoinHorizontal(lipgloss.Top, leftCol, rightCol)
}

func formatLabelValue(p labelValuePair, labelWidth int) string {
	label := metadataLabelStyle.Width(labelWidth).Render(p.label)
	return label + " " + metadataValueStyle.Render(p.value)
}

// renderAtAGlance is the dense single-line summary of totals.
func renderAtAGlance(rd *reportData) string {
	var primary, bulk, critical, warning, info int
	for _, m := range rd.Modules {
		primary += m.Artifacts
		bulk += m.BulkFiles
		for _, f := range m.Findings {
			switch f.Severity {
			case "critical":
				critical++
			case "warning":
				warning++
			case "info":
				info++
			}
		}
	}

	title := reportSectionTitleStyle.Render("At a glance")
	row1 := fmt.Sprintf("  %d modules   %d primary artifacts   %d bulk files",
		len(rd.Modules), primary, bulk)
	row2 := fmt.Sprintf("  %d critical   %d warnings   %d info observations",
		critical, warning, info)

	return title + "\n" + row1 + "\n" + row2
}

// renderModulesTable renders each module as a row with status, name, timing, counts.
func renderModulesTable(rd *reportData) string {
	title := reportSectionTitleStyle.Render("Modules")
	var lines []string

	// Column widths
	const nameWidth = 24
	const durationWidth = 8

	for _, m := range rd.Modules {
		icon, iconStyle := moduleStatusIcon(m.Status)
		marker := iconStyle.Render(icon)

		nameCol := lipgloss.NewStyle().Width(nameWidth).Foreground(lipgloss.Color("#E2E8F0")).Render(m.Name)
		durationCol := lipgloss.NewStyle().Width(durationWidth).Foreground(lipgloss.Color("#94A3B8")).Render(
			m.Duration.Round(time.Millisecond).String())

		// Counts segment
		counts := fmt.Sprintf("%d artifacts", m.Artifacts)
		if m.BulkFiles > 0 {
			counts += fmt.Sprintf("   %d bulk", m.BulkFiles)
		}

		// Findings summary
		var findingsSummary string
		var critCount, warnCount, infoCount int
		for _, f := range m.Findings {
			switch f.Severity {
			case "critical":
				critCount++
			case "warning":
				warnCount++
			case "info":
				infoCount++
			}
		}
		if critCount > 0 {
			findingsSummary += lipgloss.NewStyle().Foreground(lipgloss.Color("#F87171")).Render(
				fmt.Sprintf("   %d critical", critCount))
		}
		if warnCount > 0 {
			findingsSummary += lipgloss.NewStyle().Foreground(lipgloss.Color("#FCD34D")).Render(
				fmt.Sprintf("   %d warning", warnCount))
		}
		if infoCount > 0 {
			findingsSummary += lipgloss.NewStyle().Foreground(lipgloss.Color("#94A3B8")).Render(
				fmt.Sprintf("   %d info", infoCount))
		}

		countsCol := lipgloss.NewStyle().Foreground(lipgloss.Color("#94A3B8")).Render(counts)

		line := fmt.Sprintf(" %s  %s %s   %s%s", marker, nameCol, durationCol, countsCol, findingsSummary)
		lines = append(lines, line)
	}

	return title + "\n" + strings.Join(lines, "\n")
}

func moduleStatusIcon(status string) (string, lipgloss.Style) {
	switch status {
	case "success":
		return "[+]", moduleSuccessStyle
	case "partial":
		return "[!]", moduleWarnStyle
	case "failed", "timed_out":
		return "[x]", moduleFailStyle
	case "skipped":
		return "[-]", moduleSkipStyle
	default:
		return "[?]", moduleSkipStyle
	}
}

// renderObservations groups info-level findings by module.
func renderObservations(rd *reportData) string {
	title := reportSectionTitleStyle.Render("Observations")
	var sections []string

	for _, m := range rd.Modules {
		var lines []string
		for _, f := range m.Findings {
			if f.Severity != "info" {
				continue // critical and warnings shown elsewhere
			}
			icon, style := findingSeverityStyle(f.Severity)
			msg := f.Message
			if f.Source != "" && f.Source != m.Name {
				msg = fmt.Sprintf("%s - %s", f.Source, msg)
			}
			lines = append(lines, "    "+style.Render(icon)+"  "+msg)
		}
		if len(lines) == 0 {
			continue
		}
		moduleLabel := lipgloss.NewStyle().
			Foreground(lipgloss.Color("#E2E8F0")).
			Bold(true).
			Render("  " + m.Name)
		sections = append(sections, moduleLabel+"\n"+strings.Join(lines, "\n"))
	}

	if len(sections) == 0 {
		return title + "\n  " + metadataLabelStyle.Render("(none - modules completed cleanly)")
	}

	return title + "\n" + strings.Join(sections, "\n\n")
}

// renderCriticalSection shows critical findings in a prominent red-bordered card.
func renderCriticalSection(findings []reportFinding, width int) string {
	title := lipgloss.NewStyle().Foreground(lipgloss.Color("#F87171")).Bold(true).Render("[!] CRITICAL FINDINGS")
	var lines []string
	for _, f := range findings {
		icon, style := findingSeverityStyle(f.Severity)
		msg := f.Message
		if f.Source != "" {
			msg = fmt.Sprintf("%s - %s", f.Source, msg)
		}
		lines = append(lines, style.Render(icon)+"  "+msg)
	}
	content := title + "\n\n" + strings.Join(lines, "\n")

	cardWidth := width - 4
	if cardWidth < 40 {
		cardWidth = 40
	}
	return criticalCardStyle.Width(cardWidth).Render(content)
}

// renderWarningSection shows warning findings in an amber-bordered card.
func renderWarningSection(findings []reportFinding, width int) string {
	title := lipgloss.NewStyle().Foreground(lipgloss.Color("#FCD34D")).Bold(true).Render("[!] WARNINGS")
	var lines []string
	for _, f := range findings {
		icon, style := findingSeverityStyle(f.Severity)
		msg := f.Message
		if f.Source != "" {
			msg = fmt.Sprintf("%s - %s", f.Source, msg)
		}
		lines = append(lines, style.Render(icon)+"  "+msg)
	}
	content := title + "\n\n" + strings.Join(lines, "\n")

	cardWidth := width - 4
	if cardWidth < 40 {
		cardWidth = 40
	}
	return attentionCardStyle.Width(cardWidth).Render(content)
}

// collectFindings returns separated critical and warning findings across all modules.
func collectFindings(rd *reportData) (criticals, warnings []reportFinding) {
	for _, m := range rd.Modules {
		for _, f := range m.Findings {
			withSource := f
			if withSource.Source == "" {
				withSource.Source = m.Name
			}
			switch f.Severity {
			case "critical":
				criticals = append(criticals, withSource)
			case "warning":
				warnings = append(warnings, withSource)
			}
		}
	}
	// Sort by source name for stable display
	sort.Slice(criticals, func(i, j int) bool { return criticals[i].Source < criticals[j].Source })
	sort.Slice(warnings, func(i, j int) bool { return warnings[i].Source < warnings[j].Source })
	return criticals, warnings
}

// renderVerificationFooter shows the integrity verification command.
func renderVerificationFooter(rd *reportData) string {
	title := reportSectionTitleStyle.Render("Verification")
	cmd := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#94A3B8")).
		Render("  sahm --verify " + filepath.Base(rd.CaseDir))
	hint := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#64748B")).
		Italic(true).
		Render("  Every file in this case folder is hashed.")
	hint2 := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#64748B")).
		Italic(true).
		Render("  Any modification will be detected by the command above.")
	return title + "\n" + cmd + "\n" + hint + "\n" + hint2
}
