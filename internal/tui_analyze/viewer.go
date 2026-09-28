package tui_analyze

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/filepicker"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
)

type screen int

const (
	screenPicker screen = iota
	screenViewer
)

type model struct {
	screen     screen
	caseDir    string
	reportData *reportData
	reportErr  error
	picker     filepicker.Model
	viewport   viewport.Model
	termWidth  int
	termHeight int
}

func initialModel(caseDir string) model {
	fp := filepicker.New()
	fp.DirAllowed = true
	fp.FileAllowed = false
	fp.ShowHidden = false
	fp.ShowPermissions = false
	fp.ShowSize = false
	fp.AutoHeight = false
	fp.SetHeight(15)

	m := model{
		caseDir:  caseDir,
		picker:   fp,
		viewport: viewport.New(80, 20),
	}

	if caseDir != "" {
		m.screen = screenViewer
	} else {
		m.screen = screenPicker
	}

	return m
}

func (m model) Init() tea.Cmd {
	if m.caseDir != "" {
		return loadReportCmd(m.caseDir)
	}
	return m.picker.Init()
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok && k.String() == "ctrl+c" {
		return m, tea.Quit
	}

	if sz, ok := msg.(tea.WindowSizeMsg); ok {
		m.termWidth = sz.Width
		m.termHeight = sz.Height
		m.viewport.Width = sz.Width
		m.picker.SetHeight(sz.Height - 8)
		vpHeight := sz.Height - 3
		if vpHeight < 5 {
			vpHeight = 5
		}
		m.viewport.Height = vpHeight

		if m.reportData != nil {
			m.viewport = initReportViewport(sz.Width, vpHeight, m.reportData)
		}
	}

	switch msg := msg.(type) {
	case reportLoadedMsg:
		m.reportData = msg.data
		m.reportErr = msg.err
		if msg.err == nil && msg.data != nil {
			vpHeight := m.termHeight - 3
			if vpHeight < 5 {
				vpHeight = 5
			}
			m.viewport = initReportViewport(m.termWidth, vpHeight, msg.data)
		}
		m.screen = screenViewer
		return m, nil
	}

	switch m.screen {
	case screenPicker:
		if key, ok := msg.(tea.KeyMsg); ok && key.String() == "esc" {
			return m, tea.Quit
		}
		var cmd tea.Cmd
		m.picker, cmd = m.picker.Update(msg)
		if didSelect, path := m.picker.DidSelectFile(msg); didSelect {
			m.caseDir = path
			return m, loadReportCmd(path)
		}
		return m, cmd

	case screenViewer:
		if key, ok := msg.(tea.KeyMsg); ok {
			switch key.String() {
			case "esc":
				if m.caseDir == "" || m.reportErr != nil {
					m.screen = screenPicker
					m.reportData = nil
					m.reportErr = nil
					m.caseDir = ""
					return m, m.picker.Init()
				} else {
					return m, tea.Quit
				}
			case "q":
				return m, tea.Quit
			}
		}
		var cmd tea.Cmd
		m.viewport, cmd = m.viewport.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m model) View() string {
	switch m.screen {
	case screenPicker:
		var b strings.Builder
		b.WriteString(titleStyle.Render("Pick a case folder to view its report"))
		b.WriteString("\n\n")
		b.WriteString(labelStyle.Render("Current path: "))
		b.WriteString(m.picker.CurrentDirectory)
		b.WriteString("\n\n")
		b.WriteString(m.picker.View())
		b.WriteString("\n")
		hint := hintStyle.Render("Up / Down navigate   |   Enter to open or select   |   Esc or Ctrl+C to quit")
		b.WriteString(hint)
		return containerStyle.Render(b.String())

	case screenViewer:
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
		b.WriteString(m.viewport.View())
		b.WriteString("\n")
		scrollPct := int(m.viewport.ScrollPercent() * 100)
		scrollInfo := fmt.Sprintf("Scroll: %d%%", scrollPct)
		footer := hintStyle.Render(scrollInfo + "   |   Up / Down scroll   |   PgUp / PgDn scroll page   |   Esc back   |   q quit")
		b.WriteString(footer)
		return b.String()
	}
	return ""
}

// RunWithViewer launches the TUI report viewer program.
func RunWithViewer(caseDir string) error {
	p := tea.NewProgram(
		initialModel(caseDir),
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)
	_, err := p.Run()
	return err
}

type reportLoadedMsg struct {
	data *reportData
	err  error
}

func loadReportCmd(caseDir string) tea.Cmd {
	return func() tea.Msg {
		rd, err := loadReportData(caseDir)
		if err != nil {
			return reportLoadedMsg{err: fmt.Errorf("load report: %w", err)}
		}
		return reportLoadedMsg{data: rd}
	}
}
