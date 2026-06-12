package tui

import (
	"fmt"
	"strings"
	"time"

	"safe/internal/engine"
	"safe/internal/module"

	"github.com/charmbracelet/lipgloss"
)

// moduleState tracks one module's progress in the TUI display.
type moduleState struct {
	name      string
	status    string // "pending", "running", "done"
	result    *module.Result
	startedAt time.Time

	// Intra-module progress, updated by EventModuleProgress: work units done /
	// total within the module, and cumulative bytes the module has written.
	subDone  int
	subTotal int
	subBytes int64
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

// spinnerFrames are simple ASCII characters that rotate to show activity.
// ASCII-only so they render on plain Windows PowerShell (no Unicode braille).
var spinnerFrames = []string{"|", "/", "-", "\\"}

// barFillStyle / barEmptyStyle render a real (solid) progress bar using ANSI
// BACKGROUND colors on plain spaces — no Unicode block glyphs, so it renders
// correctly on plain Windows PowerShell while still looking like a filled bar
// rather than ASCII text.
var (
	barFillStyle  = lipgloss.NewStyle().Background(lipgloss.Color("#22D3EE")) // cyan
	barEmptyStyle = lipgloss.NewStyle().Background(lipgloss.Color("#334155")) // slate
	barPctStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#E2E8F0")).Bold(true)
)

// styledBar renders a solid filled progress bar of the given cell width with a
// trailing percentage, e.g. a cyan fill over a slate track followed by " 42%".
func styledBar(done, total, width int) string {
	if total <= 0 {
		total = 1
	}
	return styledBarFrac(float64(done)/float64(total), width)
}

// styledBarFrac renders the bar from a 0..1 fraction directly — used by the
// collection screen where the fraction blends completed modules with the
// running module's intra-module progress.
func styledBarFrac(frac float64, width int) string {
	if frac < 0 {
		frac = 0
	}
	if frac > 1 {
		frac = 1
	}
	filled := int(frac*float64(width) + 0.5)
	if filled > width {
		filled = width
	}
	bar := barFillStyle.Render(strings.Repeat(" ", filled)) +
		barEmptyStyle.Render(strings.Repeat(" ", width-filled))
	return bar + barPctStyle.Render(fmt.Sprintf(" %3d%%", int(frac*100+0.5)))
}

// humanBytes formats a byte count as a short human-readable string (e.g.
// "238 MB") for the live "data collected" readout.
func humanBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

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

	case engine.EventModuleProgress:
		if ev.ModuleIndex < len(p.modules) {
			p.modules[ev.ModuleIndex].subDone = ev.SubDone
			p.modules[ev.ModuleIndex].subTotal = ev.SubTotal
			p.modules[ev.ModuleIndex].subBytes = ev.SubBytes
		}

	case engine.EventModuleDone:
		if ev.ModuleIndex < len(p.modules) {
			p.modules[ev.ModuleIndex].status = "done"
			r := ev.Result
			p.modules[ev.ModuleIndex].result = &r
			// For modules that didn't stream intra-module byte progress (the
			// small command/snapshot modules), credit their collected volume to
			// the live "data collected" total from their recorded artifacts, so
			// the readout reflects every module, not just the bulk-copy ones.
			if p.modules[ev.ModuleIndex].subBytes == 0 {
				var b int64
				for _, a := range r.Artifacts {
					b += a.Size
				}
				p.modules[ev.ModuleIndex].subBytes = b
			}
		}

	case engine.EventCaseDone:
		p.done = true
	}
}

func (p progressModel) View() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("Collecting..."))
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
			marker = "[ ]"
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
					marker = "[+]"
					nameStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#86EFAC"))
				case module.StatusPartial:
					marker = "[!]"
					nameStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FCD34D"))
				case module.StatusFailed:
					marker = "[x]"
					nameStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#F87171"))
				case module.StatusTimedOut:
					marker = "[t]"
					nameStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#F87171"))
				default:
					marker = "[?]"
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

	// Overall progress: completed modules plus the running module's own
	// intra-module fraction, so the bar advances with real file/byte counts
	// rather than only stepping at module boundaries. Also sum bytes collected
	// so far across all modules for a live "data collected" readout.
	done := 0
	var totalBytes int64
	runFrac := 0.0
	for _, m := range p.modules {
		totalBytes += m.subBytes
		if m.status == "done" {
			done++
		} else if m.status == "running" && m.subTotal > 0 {
			runFrac = float64(m.subDone) / float64(m.subTotal)
		}
	}
	overall := 0.0
	if len(p.modules) > 0 {
		overall = (float64(done) + runFrac) / float64(len(p.modules))
	}

	b.WriteString("\n")
	b.WriteString(labelStyle.Render("Progress "))
	b.WriteString(styledBarFrac(overall, 28))
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#94A3B8")).Render(
		fmt.Sprintf("   %d/%d modules", done, len(p.modules))))
	b.WriteString("\n")
	b.WriteString(labelStyle.Render("Collected "))
	b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#86EFAC")).Render(humanBytes(totalBytes)))
	b.WriteString("\n\n")

	footer := fmt.Sprintf("Elapsed: %s   |   Time limit: %s",
		p.elapsed.Round(time.Second), p.totalBudget)
	b.WriteString(hintStyle.Render(footer))
	b.WriteString("\n")
	b.WriteString(hintStyle.Render("Ctrl+C to cancel"))

	return containerStyle.Render(b.String())
}
