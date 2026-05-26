package tui

import (
	"fmt"

	"sahm/internal/casemeta"

	tea "github.com/charmbracelet/bubbletea"
)

// Run launches the TUI. Returns the captured case metadata on success.
// Returns nil if the user quit without completing the form.
func Run() (*casemeta.Case, error) {
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	finalModel, err := p.Run()
	if err != nil {
		return nil, fmt.Errorf("tui error: %w", err)
	}

	m, ok := finalModel.(model)
	if !ok {
		return nil, fmt.Errorf("unexpected model type")
	}

	if m.submitted {
		return m.buildCase(), nil
	}
	return nil, nil
}

// screen is which "page" the user is on.
type screen int

const (
	screenWelcome screen = iota
	screenForm
	screenConfirm
)

// model is the entire UI state.
type model struct {
	screen    screen
	form      formModel
	submitted bool
}

func initialModel() model {
	return model{
		screen: screenWelcome,
		form:   newFormModel(),
	}
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		// Universal quit: Ctrl+C always exits.
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	}

	switch m.screen {
	case screenWelcome:
		return m.updateWelcome(msg)
	case screenForm:
		return m.updateForm(msg)
	case screenConfirm:
		return m.updateConfirm(msg)
	}
	return m, nil
}

func (m model) View() string {
	switch m.screen {
	case screenWelcome:
		return welcomeView()
	case screenForm:
		return m.form.View()
	case screenConfirm:
		return m.confirmView()
	}
	return ""
}

// buildCase converts the captured form data into a casemeta.Case.
// Used after the user confirms submission.
func (m model) buildCase() *casemeta.Case {
	return &casemeta.Case{
		CaseID:           m.form.caseID.Value(),
		Analyst:          m.form.analyst.Value(),
		TargetIdentifier: m.form.target.Value(),
		TargetClass:      m.form.targetClass,
		Notes:            m.form.notes.Value(),
	}
}
