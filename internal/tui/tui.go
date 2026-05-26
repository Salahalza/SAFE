package tui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Run launches the TUI. Blocks until the user exits.
func Run() error {
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("tui error: %w", err)
	}
	return nil
}

// model is the entire UI state. As the TUI grows, this will hold
// case metadata, current screen, form inputs, progress, etc.
// For now, just a screen indicator.
type model struct {
	screen screen
}

// screen is which "page" the user is on in the guided flow.
type screen int

const (
	screenWelcome screen = iota
	screenExit
)

// initialModel returns the starting state for the TUI.
func initialModel() model {
	return model{
		screen: screenWelcome,
	}
}

// Init implements tea.Model. Returns the initial command (none for now).
func (m model) Init() tea.Cmd {
	return nil
}

// Update implements tea.Model. Handles all incoming messages.
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

// handleKey routes keystrokes based on the current screen.
func (m model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Universal: q or Ctrl+C quits from anywhere.
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	}

	// Screen-specific handling.
	switch m.screen {
	case screenWelcome:
		if msg.Type == tea.KeyEnter {
			m.screen = screenExit
			return m, tea.Quit
		}
	}
	return m, nil
}

// View implements tea.Model. Returns the string to render to the terminal.
func (m model) View() string {
	switch m.screen {
	case screenWelcome:
		return welcomeView()
	case screenExit:
		return exitView()
	}
	return ""
}

// Styles
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#7DD3FC")).
			MarginBottom(1)

	subtitleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#94A3B8")).
			MarginBottom(2)

	hintStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#64748B")).
			Italic(true)

	containerStyle = lipgloss.NewStyle().
			Padding(2, 4).
			MarginTop(2)
)

// welcomeView is the first screen the analyst sees.
func welcomeView() string {
	title := titleStyle.Render("SAHM — System for Artifact Harvesting and Management")
	subtitle := subtitleStyle.Render("Windows field forensic acquisition")
	body := "Welcome. Press Enter to begin a new case.\n\n" +
		"  Enter   begin\n" +
		"  q       quit"
	hint := hintStyle.Render("\nv0.1.0  •  internal IR use only")

	return containerStyle.Render(
		title + "\n" + subtitle + "\n" + body + "\n" + hint,
	)
}

// exitView is shown briefly when the user quits.
func exitView() string {
	return containerStyle.Render("Exiting SAHM…\n")
}
