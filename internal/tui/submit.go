package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

func (m model) updateConfirm(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "y", "Y", "enter":
			m.submitted = true
			// If runner is set, transition to progress screen and start collection.
			if m.runner != nil && m.registry != nil {
				m.screen = screenProgress
				return m, m.startCollectionCmd()
			}
			// Otherwise (legacy path with no runner), just quit so main.go runs collection.
			return m, tea.Quit
		case "n", "N", "esc":
			m.screen = screenForm
			m.refreshFormViewport(true)
			return m, nil
		}
	}
	if handled, cmd := m.scrollStatic(msg); handled {
		return m, cmd
	}
	return m, nil
}

func (m model) confirmBody() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("Review before collection starts"))
	b.WriteString("\n\n")

	b.WriteString(fmt.Sprintf("%s  %s\n", labelStyle.Render("Case ID:    "), m.form.caseID.Value()))
	if m.form.irNumber.Value() != "" {
		b.WriteString(fmt.Sprintf("%s  %s\n", labelStyle.Render("IR#:        "), m.form.irNumber.Value()))
	}
	if m.form.csiNumber.Value() != "" {
		b.WriteString(fmt.Sprintf("%s  %s\n", labelStyle.Render("CSI#:       "), m.form.csiNumber.Value()))
	}
	b.WriteString(fmt.Sprintf("%s  %s\n", labelStyle.Render("Analyst:    "), m.form.analyst.Value()))
	b.WriteString(fmt.Sprintf("%s  %s\n", labelStyle.Render("Target:     "), m.form.target.Value()))
	b.WriteString(fmt.Sprintf("%s  %s\n", labelStyle.Render("Class:      "), m.form.targetClass))
	b.WriteString(fmt.Sprintf("%s  %s\n", labelStyle.Render("Profile:    "), m.form.profile))
	if m.form.notes.Value() != "" {
		b.WriteString(fmt.Sprintf("%s  %s\n", labelStyle.Render("Notes:      "), m.form.notes.Value()))
	}

	b.WriteString("\n")
	b.WriteString(successStyle.Render("Start collection now?"))
	b.WriteString("\n")

	return containerStyle.Render(b.String())
}
