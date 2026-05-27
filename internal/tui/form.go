package tui

import (
	"strings"

	"sahm/internal/casemeta"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type formField int

const (
	fieldCaseID formField = iota
	fieldAnalyst
	fieldTarget
	fieldTargetClass
	fieldProfile
	fieldNotes
	fieldSubmit
	numFormFields
)

type targetClassOption struct {
	value string
	label string
}

var targetClassOptions = []targetClassOption{
	{"workstation", "Workstation"},
	{"server", "Server"},
	{"unknown", "Unknown / Other"},
}

// ProfileOption is one selectable profile shown in the TUI form.
// Exported so main.go can populate AvailableProfiles before launching.
type ProfileOption struct {
	Value string
	Label string
}

// AvailableProfiles is set by main.go before launching the TUI.
var AvailableProfiles = []ProfileOption{
	{Value: "rapid_triage", Label: "Rapid Triage"},
}

type formModel struct {
	caseID      textinput.Model
	analyst     textinput.Model
	target      textinput.Model
	notes       textinput.Model
	targetClass string
	profile     string
	focused     formField
	errMessage  string
}

func newFormModel() formModel {
	mk := func(placeholder string) textinput.Model {
		t := textinput.New()
		t.Placeholder = placeholder
		t.CharLimit = 200
		t.Width = 50
		return t
	}

	defaultProfile := "rapid_triage"
	if len(AvailableProfiles) > 0 {
		defaultProfile = AvailableProfiles[0].Value
	}

	f := formModel{
		caseID:      mk("INC-2026-0418"),
		analyst:     mk("Your name or initials"),
		target:      mk("Hostname, asset tag, or IP"),
		notes:       mk("Optional notes about this collection"),
		targetClass: "workstation",
		profile:     defaultProfile,
		focused:     fieldCaseID,
	}
	return f
}

func (f *formModel) focus(field formField) {
	f.caseID.Blur()
	f.analyst.Blur()
	f.target.Blur()
	f.notes.Blur()

	f.focused = field
	switch field {
	case fieldCaseID:
		f.caseID.Focus()
	case fieldAnalyst:
		f.analyst.Focus()
	case fieldTarget:
		f.target.Focus()
	case fieldNotes:
		f.notes.Focus()
	}
}

func (f *formModel) nextField() {
	next := (f.focused + 1) % numFormFields
	f.focus(next)
}

func (f *formModel) prevField() {
	prev := f.focused - 1
	if prev < 0 {
		prev = numFormFields - 1
	}
	f.focus(prev)
}

func (f *formModel) validate() error {
	c := &casemeta.Case{
		CaseID:           f.caseID.Value(),
		Analyst:          f.analyst.Value(),
		TargetIdentifier: f.target.Value(),
		TargetClass:      f.targetClass,
	}
	return c.Validate()
}

func (m model) updateForm(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			m.screen = screenWelcome
			return m, nil
		case "tab", "down":
			m.form.nextField()
			return m, nil
		case "shift+tab", "up":
			m.form.prevField()
			return m, nil
		case "enter":
			if m.form.focused == fieldSubmit {
				if err := m.form.validate(); err != nil {
					m.form.errMessage = err.Error()
					return m, nil
				}
				m.form.errMessage = ""
				m.screen = screenConfirm
				return m, nil
			}
			m.form.nextField()
			return m, nil
		case "left", "right":
			if m.form.focused == fieldTargetClass {
				idx := indexOfTargetClass(m.form.targetClass)
				if msg.String() == "left" {
					idx--
					if idx < 0 {
						idx = len(targetClassOptions) - 1
					}
				} else {
					idx = (idx + 1) % len(targetClassOptions)
				}
				m.form.targetClass = targetClassOptions[idx].value
				return m, nil
			}
			if m.form.focused == fieldProfile {
				idx := indexOfProfile(m.form.profile)
				if msg.String() == "left" {
					idx--
					if idx < 0 {
						idx = len(AvailableProfiles) - 1
					}
				} else {
					idx = (idx + 1) % len(AvailableProfiles)
				}
				m.form.profile = AvailableProfiles[idx].Value
				return m, nil
			}
		}
	}

	switch m.form.focused {
	case fieldCaseID:
		m.form.caseID, cmd = m.form.caseID.Update(msg)
	case fieldAnalyst:
		m.form.analyst, cmd = m.form.analyst.Update(msg)
	case fieldTarget:
		m.form.target, cmd = m.form.target.Update(msg)
	case fieldNotes:
		m.form.notes, cmd = m.form.notes.Update(msg)
	}

	return m, cmd
}

func indexOfTargetClass(value string) int {
	for i, o := range targetClassOptions {
		if o.value == value {
			return i
		}
	}
	return 0
}

func indexOfProfile(value string) int {
	for i, o := range AvailableProfiles {
		if o.Value == value {
			return i
		}
	}
	return 0
}

func (f formModel) View() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("New Case"))
	b.WriteString("\n\n")

	b.WriteString(f.renderTextField("Case ID", f.caseID, fieldCaseID))
	b.WriteString(f.renderTextField("Analyst", f.analyst, fieldAnalyst))
	b.WriteString(f.renderTextField("Target", f.target, fieldTarget))
	b.WriteString(f.renderTargetClass())
	b.WriteString(f.renderProfile())
	b.WriteString(f.renderTextField("Notes", f.notes, fieldNotes))
	b.WriteString(f.renderSubmit())

	if f.errMessage != "" {
		b.WriteString(errorStyle.Render("✗ " + f.errMessage))
		b.WriteString("\n")
	}

	hint := hintStyle.Render("\nTab/↓ next  •  Shift+Tab/↑ prev  •  ←/→ change selection  •  Esc back  •  Ctrl+C quit")
	b.WriteString(hint)

	return containerStyle.Render(b.String())
}

func (f formModel) renderTextField(label string, ti textinput.Model, field formField) string {
	style := labelStyle
	if f.focused == field {
		style = focusedLabelStyle
	}
	return style.Render(label) + "\n" + ti.View() + "\n\n"
}

func (f formModel) renderTargetClass() string {
	style := labelStyle
	if f.focused == fieldTargetClass {
		style = focusedLabelStyle
	}
	label := style.Render("Target Class")

	var parts []string
	for _, o := range targetClassOptions {
		marker := "( )"
		if o.value == f.targetClass {
			marker = "(•)"
		}
		text := marker + " " + o.label
		if f.focused == fieldTargetClass && o.value == f.targetClass {
			text = lipgloss.NewStyle().Foreground(lipgloss.Color("#7DD3FC")).Render(text)
		}
		parts = append(parts, text)
	}

	return label + "\n" + strings.Join(parts, "   ") + "\n\n"
}

func (f formModel) renderProfile() string {
	style := labelStyle
	if f.focused == fieldProfile {
		style = focusedLabelStyle
	}
	label := style.Render("Profile")

	var parts []string
	for _, o := range AvailableProfiles {
		marker := "( )"
		if o.Value == f.profile {
			marker = "(•)"
		}
		text := marker + " " + o.Label
		if f.focused == fieldProfile && o.Value == f.profile {
			text = lipgloss.NewStyle().Foreground(lipgloss.Color("#7DD3FC")).Render(text)
		}
		parts = append(parts, text)
	}

	return label + "\n" + strings.Join(parts, "   ") + "\n\n"
}

func (f formModel) renderSubmit() string {
	text := "[ Begin Collection ]"
	if f.focused == fieldSubmit {
		text = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#0F172A")).
			Background(lipgloss.Color("#7DD3FC")).
			Bold(true).
			Padding(0, 2).
			Render("Begin Collection")
	}
	return text + "\n"
}
