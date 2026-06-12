package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
)

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
		m.reportPath = path
		return m, loadReportCmd(path)
	}

	return m, cmd
}

// loadReportCmd reads case.json and result.json from the chosen case folder
// and returns the parsed reportData via a reportLoadedMsg.
func loadReportCmd(caseDir string) tea.Cmd {
	return func() tea.Msg {
		rd, err := loadReportData(caseDir)
		if err != nil {
			return reportLoadedMsg{err: fmt.Errorf("load report: %w", err)}
		}
		return reportLoadedMsg{data: rd}
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
	hint := hintStyle.Render("Up / Down navigate   |   Enter to open or select   |   Esc back")
	b.WriteString(hint)

	return containerStyle.Render(b.String())
}

// updateReportViewer handles scroll input on the viewport.
func (m model) updateReportViewer(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "esc":
			m.screen = screenWelcome
			m.reportData = nil
			m.reportErr = nil
			m.reportPath = ""
			return m, nil
		case "q":
			return m, tea.Quit
		}
	}

	var cmd tea.Cmd
	m.reportViewport, cmd = m.reportViewport.Update(msg)
	return m, cmd
}

func (m model) reportViewerView() string {
	if m.reportErr != nil {
		var b strings.Builder
		b.WriteString(titleStyle.Render("Case Report"))
		b.WriteString("\n\n")
		b.WriteString(errorStyle.Render("[x] " + m.reportErr.Error()))
		b.WriteString("\n\n")
		b.WriteString(hintStyle.Render("Esc to go back   |   q to quit"))
		return containerStyle.Render(b.String())
	}

	if m.reportData == nil {
		var b strings.Builder
		b.WriteString(titleStyle.Render("Case Report"))
		b.WriteString("\n\n")
		b.WriteString("Loading...")
		return containerStyle.Render(b.String())
	}

	var b strings.Builder
	b.WriteString(m.reportViewport.View())
	b.WriteString("\n")

	scrollPct := int(m.reportViewport.ScrollPercent() * 100)
	scrollInfo := fmt.Sprintf("Scroll: %d%%", scrollPct)
	footer := hintStyle.Render(scrollInfo + "   |   Up / Down scroll   |   PgUp / PgDn scroll page   |   Esc back   |   q quit")
	b.WriteString(footer)

	return b.String()
}

// initReportViewport creates a viewport sized to the given dimensions,
// loads the rendered report content into it, and returns the viewport.
func initReportViewport(width, height int, rd *reportData) viewport.Model {
	vp := viewport.New(width, height)
	vp.Style = vp.Style.Padding(1, 2)
	// The viewport renders content into (Width - horizontal frame size) and
	// TRUNCATES anything wider — see bubbles viewport View(), which does
	// contentWidth = Width - Style.GetHorizontalFrameSize() then
	// MaxWidth(contentWidth). Size the report to that true inner width so the
	// header card's right border isn't truncated off. Deriving it from
	// GetHorizontalFrameSize keeps this correct if the padding ever changes.
	inner := vp.Width - vp.Style.GetHorizontalFrameSize()
	if inner < 40 {
		inner = 40
	}
	content := renderReport(rd, inner)
	vp.SetContent(content)
	return vp
}
