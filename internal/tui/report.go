package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// reportViewerHeight is how many lines of report content we show at once.
// Anything beyond requires scrolling.
const reportViewerHeight = 20

// updateReportPicker drives the filepicker for choosing a case folder
// whose case_report.txt we'll display.
func (m model) updateReportPicker(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "esc":
			m.screen = screenWelcome
			return m, nil
		}
	}

	var cmd tea.Cmd
	m.reportPicker, cmd = m.reportPicker.Update(msg)

	if didSelect, path := m.reportPicker.DidSelectFile(msg); didSelect {
		reportPath := filepath.Join(path, "case_report.txt")
		m.reportPath = reportPath
		// Load asynchronously so the picker can transition smoothly.
		return m, loadReportCmd(reportPath)
	}

	return m, cmd
}

func loadReportCmd(path string) tea.Cmd {
	return func() tea.Msg {
		data, err := os.ReadFile(path)
		if err != nil {
			return reportLoadedMsg{err: fmt.Errorf("read case_report.txt: %w", err)}
		}
		return reportLoadedMsg{content: string(data)}
	}
}

func (m model) reportPickerView() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("Pick a case folder to view its report"))
	b.WriteString("\n\n")

	b.WriteString(labelStyle.Render("Current path: "))
	b.WriteString(m.reportPicker.CurrentDirectory)
	b.WriteString("\n\n")

	b.WriteString(m.reportPicker.View())

	b.WriteString("\n")
	hint := hintStyle.Render("↑ / ↓ navigate   •   Enter to open or select   •   Esc back")
	b.WriteString(hint)

	return containerStyle.Render(b.String())
}

// updateReportViewer handles scrolling and exit in the report viewer.
func (m model) updateReportViewer(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}

	switch key.String() {
	case "esc":
		m.screen = screenWelcome
		m.reportContent = ""
		m.reportErr = nil
		m.reportPath = ""
		m.reportScrollY = 0
		return m, nil
	case "q":
		return m, tea.Quit
	case "up", "k":
		if m.reportScrollY > 0 {
			m.reportScrollY--
		}
		return m, nil
	case "down", "j":
		lines := strings.Split(m.reportContent, "\n")
		maxScroll := len(lines) - reportViewerHeight
		if maxScroll < 0 {
			maxScroll = 0
		}
		if m.reportScrollY < maxScroll {
			m.reportScrollY++
		}
		return m, nil
	case "pgup":
		m.reportScrollY -= reportViewerHeight
		if m.reportScrollY < 0 {
			m.reportScrollY = 0
		}
		return m, nil
	case "pgdown", " ":
		lines := strings.Split(m.reportContent, "\n")
		maxScroll := len(lines) - reportViewerHeight
		if maxScroll < 0 {
			maxScroll = 0
		}
		m.reportScrollY += reportViewerHeight
		if m.reportScrollY > maxScroll {
			m.reportScrollY = maxScroll
		}
		return m, nil
	case "home", "g":
		m.reportScrollY = 0
		return m, nil
	case "end", "G":
		lines := strings.Split(m.reportContent, "\n")
		maxScroll := len(lines) - reportViewerHeight
		if maxScroll < 0 {
			maxScroll = 0
		}
		m.reportScrollY = maxScroll
		return m, nil
	}
	return m, nil
}

func (m model) reportViewerView() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("Case Report"))
	b.WriteString("\n")
	b.WriteString(subtitleStyle.Render(m.reportPath))

	if m.reportErr != nil {
		b.WriteString(errorStyle.Render("✗ " + m.reportErr.Error()))
		b.WriteString("\n\n")
		b.WriteString(hintStyle.Render("Esc to go back   •   q to quit"))
		return containerStyle.Render(b.String())
	}

	// Show a windowed slice of the report content.
	lines := strings.Split(m.reportContent, "\n")
	total := len(lines)
	end := m.reportScrollY + reportViewerHeight
	if end > total {
		end = total
	}

	visible := lines[m.reportScrollY:end]

	// Apply minimal styling — preserving the text as-is. Session 2 will
	// replace this with a structured visual layout. For now the goal is
	// "show the report, allow scrolling."
	reportBody := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#E2E8F0")).
		Render(strings.Join(visible, "\n"))
	b.WriteString(reportBody)
	b.WriteString("\n")

	// Footer with scroll position.
	scrollInfo := fmt.Sprintf("Lines %d–%d of %d", m.reportScrollY+1, end, total)
	b.WriteString(hintStyle.Render(scrollInfo))
	b.WriteString("\n")
	b.WriteString(hintStyle.Render("↑ / ↓ scroll line   •   PgUp / PgDn scroll page   •   g top   •   G bottom   •   Esc back   •   q quit"))

	return containerStyle.Render(b.String())
}
