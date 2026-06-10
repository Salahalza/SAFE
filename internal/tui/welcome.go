package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// updateWelcome handles keystrokes on the welcome screen.
func (m model) updateWelcome(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}

	switch key.String() {
	case "q", "esc":
		return m, tea.Quit
	case "up", "k":
		if m.welcomeCursor > 0 {
			m.welcomeCursor--
		} else {
			m.welcomeCursor = numWelcomeChoices - 1
		}
		return m, nil
	case "down", "j":
		m.welcomeCursor = (m.welcomeCursor + 1) % numWelcomeChoices
		return m, nil
	case "1":
		m.welcomeCursor = welcomeStartCollection
		return m.activateWelcomeChoice()
	case "2":
		m.welcomeCursor = welcomeRunAnalyzer
		return m.activateWelcomeChoice()
	case "3":
		m.welcomeCursor = welcomeViewReport
		return m.activateWelcomeChoice()
	case "enter":
		return m.activateWelcomeChoice()
	}
	return m, nil
}

// activateWelcomeChoice routes to the appropriate screen based on cursor position.
func (m model) activateWelcomeChoice() (tea.Model, tea.Cmd) {
	switch m.welcomeCursor {
	case welcomeStartCollection:
		m.screen = screenForm
		m.form.focus(0)
		return m, nil
	case welcomeRunAnalyzer:
		if m.analyzeFn == nil {
			return m, nil
		}
		m.screen = screenAnalyzePicker
		return m, m.analyzePicker.Init()
	case welcomeViewReport:
		m.screen = screenReportPicker
		return m, m.reportPicker.Init()
	}
	return m, nil
}

func welcomeView(cursor welcomeChoice) string {
	banner := brandStyle.Render(sahmBanner)
	tagline := subtitleStyle.Render("System for Artifact Harvesting and Management")
	subtitle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#94A3B8")).
		MarginBottom(2).
		Render("Windows forensic acquisition for incident response field work")

	options := []struct {
		shortcut string
		label    string
		desc     string
	}{
		{"1", "Start a new case", "Collect forensic evidence from a target machine"},
		{"2", "Analyze a case folder", "Parse a collected case to produce analyst-ready output"},
		{"3", "View a case report", "Open a collected case and review its summary"},
	}

	var b strings.Builder
	for i, opt := range options {
		selected := welcomeChoice(i) == cursor

		marker := "    "
		labelStyleToUse := lipgloss.NewStyle().Foreground(lipgloss.Color("#E2E8F0"))
		descStyleToUse := lipgloss.NewStyle().Foreground(lipgloss.Color("#64748B"))

		if selected {
			marker = lipgloss.NewStyle().Foreground(lipgloss.Color("#7DD3FC")).Bold(true).Render("  ▶ ")
			labelStyleToUse = lipgloss.NewStyle().Foreground(lipgloss.Color("#7DD3FC")).Bold(true)
		}

		shortcut := lipgloss.NewStyle().Foreground(lipgloss.Color("#94A3B8")).Render("[" + opt.shortcut + "]")
		line := fmt.Sprintf("%s%s  %s", marker, shortcut, labelStyleToUse.Render(opt.label))
		b.WriteString(line)
		b.WriteString("\n")
		b.WriteString(descStyleToUse.Render(fmt.Sprintf("         %s", opt.desc)))
		b.WriteString("\n\n")
	}

	hint := hintStyle.Render("↑ / ↓ or j / k to move   •   1 / 2 / 3 to jump   •   Enter to select   •   q to quit")
	footer := hintStyle.Render("\nv0.1.0  •  Internal IR use only")

	return containerStyle.Render(
		banner + "\n" + tagline + "\n" + subtitle + "\n\n" + b.String() + "\n" + hint + footer,
	)
}
