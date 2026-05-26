package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// updateConfirm handles the final confirmation screen.
func (m model) updateConfirm(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "y", "Y", "enter":
			m.submitted = true
			return m, tea.Quit
		case "n", "N", "esc":
			m.screen = screenForm
			return m, nil
		}
	}
	return m, nil
}

func (m model) confirmView() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("Confirm Case"))
	b.WriteString("\n\n")

	b.WriteString(fmt.Sprintf("%s  %s\n", labelStyle.Render("Case ID:    "), m.form.caseID.Value()))
	b.WriteString(fmt.Sprintf("%s  %s\n", labelStyle.Render("Analyst:    "), m.form.analyst.Value()))
	b.WriteString(fmt.Sprintf("%s  %s\n", labelStyle.Render("Target:     "), m.form.target.Value()))
	b.WriteString(fmt.Sprintf("%s  %s\n", labelStyle.Render("Class:      "), m.form.targetClass))
	if m.form.notes.Value() != "" {
		b.WriteString(fmt.Sprintf("%s  %s\n", labelStyle.Render("Notes:      "), m.form.notes.Value()))
	}

	b.WriteString("\n")
	b.WriteString(successStyle.Render("Proceed with collection?"))
	b.WriteString("\n")

	hint := hintStyle.Render("\n[y] confirm  •  [n/Esc] go back  •  [Ctrl+C] quit")
	b.WriteString(hint)

	return containerStyle.Render(b.String())
}
