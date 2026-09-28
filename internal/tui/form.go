package tui

import (
	"fmt"
	"strings"

	"github.com/Salahalza/SAFE/internal/casemeta"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type formField int

const (
	fieldCaseID formField = iota
	fieldIRNumber
	fieldCSINumber
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
	// Class is the profile's target class ("workstation", "server", "any").
	// Used to default and order profiles by the selected target class.
	Class string
}

// AvailableProfiles is set by main.go before launching the TUI.
var AvailableProfiles = []ProfileOption{
	{Value: "rapid_triage", Label: "Rapid Triage", Class: "any"},
}

// profileClass returns the class of the profile with the given value, or "" if
// it is not in AvailableProfiles.
func profileClass(value string) string {
	for _, o := range AvailableProfiles {
		if o.Value == value {
			return o.Class
		}
	}
	return ""
}

// defaultProfileForClass returns the profile that should be selected by default
// for a given target class: the first profile whose class matches exactly,
// falling back to the first "any" profile, then to the first profile overall.
// This is what makes selecting a target class surface the right profile (e.g.
// class=server defaults to server_infra) instead of leaving a mismatch.
func defaultProfileForClass(class string) string {
	if len(AvailableProfiles) == 0 {
		return ""
	}
	for _, o := range AvailableProfiles {
		if o.Class == class {
			return o.Value
		}
	}
	for _, o := range AvailableProfiles {
		if o.Class == "any" {
			return o.Value
		}
	}
	return AvailableProfiles[0].Value
}

// classFitsTarget reports whether a profile of profClass is appropriate for a
// target of targetClass. A universal ("any") profile fits anything; an "unknown"
// target class is treated as no constraint. Otherwise the classes must match.
func classFitsTarget(profClass, targetClass string) bool {
	if profClass == "any" || targetClass == "unknown" || targetClass == "" {
		return true
	}
	return profClass == targetClass
}

type formModel struct {
	caseID      textinput.Model
	irNumber    textinput.Model
	csiNumber   textinput.Model
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

	const defaultClass = "workstation"

	f := formModel{
		caseID:      mk("e.g. INC-2026-0418"),
		irNumber:    mk("e.g. IR-2026-0418 (optional)"),
		csiNumber:   mk("e.g. CSI-123456 (optional)"),
		analyst:     mk("Your name or initials"),
		target:      mk("Hostname, asset tag, or IP address"),
		notes:       mk("Anything you want to remember about this case (optional)"),
		targetClass: defaultClass,
		profile:     defaultProfileForClass(defaultClass),
		focused:     fieldCaseID,
	}
	return f
}

func (f *formModel) focus(field formField) {
	f.caseID.Blur()
	f.irNumber.Blur()
	f.csiNumber.Blur()
	f.analyst.Blur()
	f.target.Blur()
	f.notes.Blur()

	f.focused = field
	switch field {
	case fieldCaseID:
		f.caseID.Focus()
	case fieldIRNumber:
		f.irNumber.Focus()
	case fieldCSINumber:
		f.csiNumber.Focus()
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
		IRNumber:         f.irNumber.Value(),
		CSINumber:        f.csiNumber.Value(),
		Analyst:          f.analyst.Value(),
		TargetIdentifier: f.target.Value(),
		TargetClass:      f.targetClass,
	}
	return c.Validate()
}

func (m model) updateForm(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.MouseMsg:
		// Mouse wheel scrolls the form without disturbing field focus.
		m.formViewport, cmd = m.formViewport.Update(msg)
		return m, cmd

	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			return m, tea.Quit
		case "pgup":
			m.formViewport.PageUp()
			return m, nil
		case "pgdown":
			m.formViewport.PageDown()
			return m, nil
		case "tab", "down":
			m.form.nextField()
			m.refreshFormViewport(true)
			return m, nil
		case "shift+tab", "up":
			m.form.prevField()
			m.refreshFormViewport(true)
			return m, nil
		case "enter":
			if m.form.focused == fieldSubmit {
				if err := m.form.validate(); err != nil {
					m.form.errMessage = err.Error()
					m.refreshFormViewport(true)
					return m, nil
				}
				m.form.errMessage = ""
				m.screen = screenConfirm
				m.setStaticContent(m.confirmBody())
				m.staticVP.GotoTop()
				return m, nil
			}
			m.form.nextField()
			m.refreshFormViewport(true)
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
				// Changing target class re-defaults the profile only when the
				// current selection doesn't fit the new class — this fixes a
				// mismatch (e.g. class flipped to server while an endpoint
				// profile was selected) without clobbering a deliberate,
				// in-class choice.
				if !classFitsTarget(profileClass(m.form.profile), m.form.targetClass) {
					m.form.profile = defaultProfileForClass(m.form.targetClass)
				}
				m.refreshFormViewport(true)
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
				m.refreshFormViewport(true)
				return m, nil
			}
		}
	}

	switch m.form.focused {
	case fieldCaseID:
		m.form.caseID, cmd = m.form.caseID.Update(msg)
	case fieldIRNumber:
		m.form.irNumber, cmd = m.form.irNumber.Update(msg)
	case fieldCSINumber:
		m.form.csiNumber, cmd = m.form.csiNumber.Update(msg)
	case fieldAnalyst:
		m.form.analyst, cmd = m.form.analyst.Update(msg)
	case fieldTarget:
		m.form.target, cmd = m.form.target.Update(msg)
	case fieldNotes:
		m.form.notes, cmd = m.form.notes.Update(msg)
	}

	// Typing changed the field content — re-render so the viewport reflects it,
	// keeping the active field in view.
	m.refreshFormViewport(true)
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

// render builds the form body and reports the line offset and height of the
// currently focused field within that body. The offsets let the parent model
// keep the focused field visible while scrolling (see followFormFocus). The
// keybinding hint is intentionally NOT included here — it lives in a persistent
// footer outside the scroll region so it stays visible at all times.
func (f formModel) render(width int) (body string, focusStart, focusHeight int) {
	var b strings.Builder
	curLine := 0
	focusStart, focusHeight = 0, 1

	// write appends a field block and, if it is the focused field, records
	// where it starts and how tall it is (measured in lines).
	write := func(field formField, s string) {
		lines := strings.Count(s, "\n")
		if field == f.focused {
			focusStart = curLine
			if lines < 1 {
				lines = 1
			}
			focusHeight = lines
		}
		b.WriteString(s)
		curLine += strings.Count(s, "\n")
	}

	title := titleStyle.Render("Start a new case") + "\n\n"
	b.WriteString(title)
	curLine += strings.Count(title, "\n")

	write(fieldCaseID, f.renderTextField("Case ID", f.caseID, fieldCaseID))
	write(fieldIRNumber, f.renderTextField("IR# (optional)", f.irNumber, fieldIRNumber))
	write(fieldCSINumber, f.renderTextField("CSI# (optional)", f.csiNumber, fieldCSINumber))
	write(fieldAnalyst, f.renderTextField("Analyst", f.analyst, fieldAnalyst))
	write(fieldTarget, f.renderTextField("Target", f.target, fieldTarget))
	write(fieldTargetClass, f.renderTargetClass())
	write(fieldProfile, f.renderProfile(width))
	write(fieldNotes, f.renderTextField("Notes (optional)", f.notes, fieldNotes))
	write(fieldSubmit, f.renderSubmit())

	if f.errMessage != "" {
		b.WriteString(errorStyle.Render("[x] " + f.errMessage))
		b.WriteString("\n")
	}

	return b.String(), focusStart, focusHeight
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
	label := style.Render("Target class")

	var parts []string
	for _, o := range targetClassOptions {
		marker := "( )"
		if o.value == f.targetClass {
			marker = "(*)"
		}
		text := marker + " " + o.label
		if f.focused == fieldTargetClass && o.value == f.targetClass {
			text = lipgloss.NewStyle().Foreground(lipgloss.Color("#7DD3FC")).Render(text)
		}
		parts = append(parts, text)
	}

	return label + "\n" + strings.Join(parts, "   ") + "\n\n"
}

func (f formModel) renderProfile(width int) string {
	style := labelStyle
	if f.focused == fieldProfile {
		style = focusedLabelStyle
	}
	label := style.Render("Collection profile")

	// Render one profile per line, wrapped to the terminal width, instead of
	// joining them horizontally — profile labels are full descriptions and
	// would clip off the right edge or hide on a narrow terminal. Mirrors the
	// wrap math used in the analyze view: containerStyle has Padding(2,6) = 12
	// cols of horizontal frame; reserve 2 more as a gutter.
	if width <= 0 {
		width = 80 // before the first WindowSizeMsg arrives
	}
	avail := width - 14
	if avail < 30 {
		avail = 30
	}

	// The marker prefix "(*) " is 4 columns wide. Wrap the label to the
	// remaining width, then hang the continuation lines under the text so
	// wrapped lines line up instead of running back to the left margin.
	const indent = "    "
	labelWidth := avail - len(indent)
	if labelWidth < 20 {
		labelWidth = 20
	}

	var lines []string
	for _, o := range AvailableProfiles {
		marker := "( )"
		if o.Value == f.profile {
			marker = "(*)"
		}

		wrapped := lipgloss.NewStyle().Width(labelWidth).Render(o.Label)
		wlines := strings.Split(wrapped, "\n")
		for i := range wlines {
			if i == 0 {
				wlines[i] = marker + " " + wlines[i]
			} else {
				wlines[i] = indent + wlines[i]
			}
		}
		block := strings.Join(wlines, "\n")

		if f.focused == fieldProfile && o.Value == f.profile {
			block = lipgloss.NewStyle().Foreground(lipgloss.Color("#7DD3FC")).Render(block)
		}
		lines = append(lines, block)
	}

	body := label + "\n" + strings.Join(lines, "\n")

	// Surface a mismatch between the selected profile's class and the target
	// class so the analyst notices before collecting (e.g. a server target with
	// an endpoint profile selected — role artifacts like NTDS.dit would be
	// missed). "any" profiles and an "unknown" target class never mismatch.
	if pc := profileClass(f.profile); !classFitsTarget(pc, f.targetClass) {
		hint := lipgloss.NewStyle().Foreground(lipgloss.Color("#FCD34D")).Render(
			fmt.Sprintf("    ! this profile targets %s, but the target class is %s", pc, f.targetClass))
		body += "\n" + hint
	}

	return body + "\n\n"
}

func (f formModel) renderSubmit() string {
	text := "[ Start collection ]"
	if f.focused == fieldSubmit {
		text = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#0F172A")).
			Background(lipgloss.Color("#7DD3FC")).
			Bold(true).
			Padding(0, 2).
			Render("Start collection")
	}
	return text + "\n"
}
