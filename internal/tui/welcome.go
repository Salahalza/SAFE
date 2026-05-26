package tui

import tea "github.com/charmbracelet/bubbletea"

// updateWelcome handles keystrokes on the welcome screen.
func (m model) updateWelcome(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "q":
			return m, tea.Quit
		case "enter":
			m.screen = screenForm
			m.form.focus(0)
			return m, nil
		}
	}
	return m, nil
}

func welcomeView() string {
	title := titleStyle.Render("SAHM — System for Artifact Harvesting and Management")
	subtitle := subtitleStyle.Render("Windows field forensic acquisition")
	body := "Press Enter to begin a new case.\n\n" +
		"  Enter   begin\n" +
		"  q       quit"
	hint := hintStyle.Render("\nv0.1.0  •  internal IR use only")

	return containerStyle.Render(
		title + "\n" + subtitle + "\n" + body + "\n" + hint,
	)
}
