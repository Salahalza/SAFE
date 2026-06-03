package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

func (m model) updateComplete(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "enter", "q", "esc":
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m model) completeView() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("Collection complete"))
	b.WriteString("\n\n")

	r := m.collectionResult
	if r == nil {
		b.WriteString("Collection ended without producing a result. Check the logs for details.\n")
		return containerStyle.Render(b.String())
	}

	statusStyle := successStyle
	switch r.Status {
	case "degraded":
		statusStyle = errorStyle
	case "partial":
		statusStyle = errorStyle // could add a warning style
	}

	b.WriteString(fmt.Sprintf("%s  %s\n", labelStyle.Render("Status:    "), statusStyle.Render(strings.ToUpper(r.Status))))
	b.WriteString(fmt.Sprintf("%s  %s\n", labelStyle.Render("Duration:  "), r.Duration.String()))

	totalArtifacts := 0
	for _, mod := range r.Modules {
		totalArtifacts += len(mod.Artifacts)
	}
	b.WriteString(fmt.Sprintf("%s  %d\n", labelStyle.Render("Artifacts: "), totalArtifacts))
	b.WriteString(fmt.Sprintf("%s  %s\n", labelStyle.Render("Output:    "), r.CaseDir))

	b.WriteString("\n")
	b.WriteString(hintStyle.Render("Press Enter to close, or q to quit."))

	return containerStyle.Render(b.String())
}
