package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// updateAnalyzePicker drives the filepicker for choosing a case folder
// to analyze.
func (m model) updateAnalyzePicker(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "esc":
			m.screen = screenWelcome
			return m, nil
		}
	}

	var cmd tea.Cmd
	m.analyzePicker, cmd = m.analyzePicker.Update(msg)

	// DidSelectFile also fires for directories when DirAllowed=true.
	if didSelect, path := m.analyzePicker.DidSelectFile(msg); didSelect {
		m.analyzeCaseDir = path
		m.screen = screenAnalyzeProgress
		return m, m.startAnalyzeCmd()
	}

	return m, cmd
}

func (m model) analyzePickerView() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("Pick a case folder to analyze"))
	b.WriteString("\n\n")

	b.WriteString(labelStyle.Render("Current path: "))
	b.WriteString(m.analyzePicker.CurrentDirectory)
	b.WriteString("\n\n")

	b.WriteString(m.analyzePicker.View())

	b.WriteString("\n")
	hint := hintStyle.Render("Up / Down navigate   |   Enter to open or select   |   Esc back")
	b.WriteString(hint)

	return containerStyle.Render(b.String())
}

// analyzeProgressView shows a live progress bar while the analyzer runs,
// advancing parser-by-parser. Some parsers (e.g. com_hijack on a large hive)
// take several seconds, so the bar and current-parser name give real feedback.
func (m model) analyzeProgressView() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("Analyzing..."))
	b.WriteString("\n\n")

	b.WriteString(labelStyle.Render("Case: "))
	b.WriteString(m.analyzeCaseDir)
	b.WriteString("\n\n")

	b.WriteString(labelStyle.Render("Progress "))
	b.WriteString(styledBarFrac(m.analyzeFrac, 28))
	b.WriteString("\n\n")

	spinner := spinnerFrames[m.analyzeSpinTick%len(spinnerFrames)]
	current := m.analyzeLabel
	if current == "" {
		current = "finishing..."
	}
	body := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#7DD3FC")).
		Render(fmt.Sprintf("%s  %s", spinner, current))
	b.WriteString(body)
	b.WriteString("\n\n")

	b.WriteString(hintStyle.Render("Ctrl+C to cancel."))

	return containerStyle.Render(b.String())
}

// updateAnalyzeComplete handles keys on the analyze complete screen.
func (m model) updateAnalyzeComplete(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "enter", "esc":
			// Go back to welcome — analyst can run another or exit.
			m.screen = screenWelcome
			m.welcomeCursor = welcomeStartCollection
			m.analyzeResult = nil
			m.analyzeErr = nil
			m.analyzeCaseDir = ""
			return m, nil
		case "q":
			return m, tea.Quit
		}
	}
	if handled, cmd := m.scrollStatic(msg); handled {
		return m, cmd
	}
	return m, nil
}

func (m model) analyzeCompleteBody() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("Analysis complete"))
	b.WriteString("\n\n")

	if m.analyzeErr != nil {
		b.WriteString(errorStyle.Render("[x] Analyzer failed"))
		b.WriteString("\n")
		b.WriteString(m.analyzeErr.Error())
		b.WriteString("\n")
		return containerStyle.Render(b.String())
	}

	r := m.analyzeResult
	if r == nil {
		b.WriteString("Analyzer returned no result.\n")
		return containerStyle.Render(b.String())
	}

	b.WriteString(fmt.Sprintf("%s  %s\n", labelStyle.Render("Case:        "), r.CaseDir))
	b.WriteString(fmt.Sprintf("%s  %s\n", labelStyle.Render("Lab report:  "), r.LabReportDir))
	b.WriteString(fmt.Sprintf("%s  %s\n", labelStyle.Render("Duration:    "), r.Duration.Round(time.Millisecond)))
	b.WriteString("\n")

	b.WriteString(labelStyle.Render("Parsers"))
	b.WriteString("\n")

	// Wrap long parser sub-lines (paths, findings, stats) to the available
	// width so they don't overflow and clip on the right edge. containerStyle
	// has Padding(2,6) = 12 cols of horizontal frame; reserve 2 more as a
	// gutter. PaddingLeft(4) gives wrapped continuation lines a hanging indent
	// aligned under the prefix.
	avail := m.termWidth - 14
	if avail < 40 {
		avail = 40
	}
	subLine := func(color, prefix, text string) string {
		return lipgloss.NewStyle().
			Foreground(lipgloss.Color(color)).
			Width(avail).
			PaddingLeft(4).
			Render(prefix + text)
	}

	for _, p := range r.ParsersRun {
		statusColor := lipgloss.Color("#86EFAC") // green
		switch p.Status {
		case "partial":
			statusColor = lipgloss.Color("#FCD34D") // amber
		case "failed":
			statusColor = lipgloss.Color("#F87171") // red
		case "skipped":
			statusColor = lipgloss.Color("#94A3B8") // gray
		}
		marker := lipgloss.NewStyle().Foreground(statusColor).Bold(true).Render(
			fmt.Sprintf("  [%s]", strings.ToUpper(p.Status)))
		duration := lipgloss.NewStyle().Foreground(lipgloss.Color("#64748B")).Render(
			fmt.Sprintf("(%s)", p.Duration.Round(time.Millisecond)))
		b.WriteString(fmt.Sprintf("%s %s %s\n", marker, p.Name, duration))

		for _, out := range p.Outputs {
			b.WriteString(subLine("#94A3B8", "-> ", out))
			b.WriteString("\n")
		}
		if len(p.Stats) > 0 {
			var parts []string
			for k, v := range p.Stats {
				parts = append(parts, fmt.Sprintf("%s=%d", k, v))
			}
			b.WriteString(subLine("#64748B", "stats: ", strings.Join(parts, ", ")))
			b.WriteString("\n")
		}
		for _, e := range p.Errors {
			b.WriteString(subLine("#FCD34D", "[!] ", e))
			b.WriteString("\n")
		}
	}

	return containerStyle.Render(b.String())
}
