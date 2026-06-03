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
	subtitle := subtitleStyle.Render("Windows Forensic Acquisition")
	body := "Press one of the following:\n\n" +
		"  Enter   Start a new case\n" +
		"  q       Quit"
	hint := hintStyle.Render("\nv0.1.0 ")

	return containerStyle.Render(
		title + "\n" + subtitle + "\n" + body + "\n" + hint,
	)
}
