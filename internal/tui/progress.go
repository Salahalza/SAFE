package tui

import (
	"fmt"
	"strings"
	"time"

	"sahm/internal/engine"
	"sahm/internal/module"

	"github.com/charmbracelet/lipgloss"
)

// moduleState tracks one module's progress in the TUI display.
type moduleState struct {
	name      string
	status    string // "pending", "running", "done"
	result    *module.Result
	startedAt time.Time
}

// progressModel holds the state of the in-progress collection screen.
type progressModel struct {
	caseID      string
	target      string
	profileName string
	modules     []moduleState
	startedAt   time.Time
	elapsed     time.Duration
	totalBudget time.Duration
	done        bool
	finalResult *engine.CaseResult
	spinnerTick int
}

// spinnerFrames are simple braille-like characters that rotate to show activity.
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// progressTickMsg is sent periodically to update the elapsed time and spinner.
type progressTickMsg time.Time

// progressEventMsg wraps an engine.ProgressEvent so it flows through tea.Msg.
type progressEventMsg engine.ProgressEvent

func newProgressModel(caseID, target, profileName string, totalBudget time.Duration) progressModel {
	return progressModel{
		caseID:      caseID,
		target:      target,
		profileName: profileName,
		totalBudget: totalBudget,
		startedAt:   time.Now(),
	}
}

// applyEvent updates the progress model based on an event from the engine.
func (p *progressModel) applyEvent(ev engine.ProgressEvent) {
	switch ev.Kind {
	case engine.EventCaseStart:
		// Initialize the module list with placeholders.
		p.modules = make([]moduleState, ev.TotalCount)
		// We don't know the names yet; they come in EventModuleStart.

	case engine.EventModuleStart:
		// Ensure slot exists.
		for len(p.modules) <= ev.ModuleIndex {
			p.modules = append(p.modules, moduleState{})
		}
		p.modules[ev.ModuleIndex] = moduleState{
			name:      ev.ModuleName,
			status:    "running",
			startedAt: time.Now(),
		}

	case engine.EventModuleDone:
		if ev.ModuleIndex < len(p.modules) {
			p.modules[ev.ModuleIndex].status = "done"
			r := ev.Result
			p.modules[ev.ModuleIndex].result = &r
		}

	case engine.EventCaseDone:
		p.done = true
	}
}

func (p progressModel) View() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("SAHM — Collection in Progress"))
	b.WriteString("\n\n")

	b.WriteString(labelStyle.Render("Case:    "))
	b.WriteString(p.caseID)
	b.WriteString("\n")
	b.WriteString(labelStyle.Render("Target:  "))
	b.WriteString(p.target)
	b.WriteString("\n")
	b.WriteString(labelStyle.Render("Profile: "))
	b.WriteString(p.profileName)
	b.WriteString("\n\n")

	spinner := spinnerFrames[p.spinnerTick%len(spinnerFrames)]

	for _, m := range p.modules {
		var marker string
		var nameStyle lipgloss.Style
		var detail string

		switch m.status {
		case "":
			marker = "⏸"
			nameStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#64748B"))
			detail = "pending"
		case "running":
			marker = spinner
			nameStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#7DD3FC")).Bold(true)
			detail = fmt.Sprintf("running (%s)", time.Since(m.startedAt).Round(time.Second))
		case "done":
			if m.result != nil {
				switch m.result.Status {
				case module.StatusSuccess:
					marker = "✓"
					nameStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#86EFAC"))
				case module.StatusPartial:
					marker = "⚠"
					nameStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FCD34D"))
				case module.StatusFailed:
					marker = "✗"
					nameStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#F87171"))
				case module.StatusTimedOut:
					marker = "⏱"
					nameStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#F87171"))
				default:
					marker = "?"
					nameStyle = lipgloss.NewStyle()
				}
				detail = fmt.Sprintf("(%s)  %d artifacts", m.result.Duration.Round(time.Millisecond), len(m.result.Artifacts))
			}
		}

		line := fmt.Sprintf("  %s  %s  %s\n",
			marker,
			nameStyle.Render(fmt.Sprintf("%-22s", m.name)),
			lipgloss.NewStyle().Foreground(lipgloss.Color("#94A3B8")).Render(detail),
		)
		b.WriteString(line)
	}

	b.WriteString("\n")
	footer := fmt.Sprintf("Elapsed: %s  •  Total budget: %s",
		p.elapsed.Round(time.Second), p.totalBudget)
	b.WriteString(hintStyle.Render(footer))
	b.WriteString("\n")
	b.WriteString(hintStyle.Render("Ctrl+C to abort"))

	return containerStyle.Render(b.String())
}
