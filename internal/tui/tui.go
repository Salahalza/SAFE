package tui

import (
	"fmt"
	"time"

	"sahm/internal/casemeta"
	"sahm/internal/engine"
	"sahm/internal/profile"

	tea "github.com/charmbracelet/bubbletea"
)

// CollectionResult is what Run returns when collection completed inside the TUI.
type CollectionResult struct {
	Case   *casemeta.Case
	Result *engine.CaseResult
}

// RunResult is what we return to main.go.
type RunResult struct {
	Case       *casemeta.Case
	Collection *CollectionResult
}

// Runner is what the TUI uses to actually execute a collection.
type Runner interface {
	Run(c *casemeta.Case, p *profile.Profile, progressCh chan<- engine.ProgressEvent) engine.CaseResult
}

type runnerFunc func(c *casemeta.Case, p *profile.Profile, progressCh chan<- engine.ProgressEvent) engine.CaseResult

func (f runnerFunc) Run(c *casemeta.Case, p *profile.Profile, progressCh chan<- engine.ProgressEvent) engine.CaseResult {
	return f(c, p, progressCh)
}

// RunWithCollection launches the TUI and runs collection inside it.
func RunWithCollection(
	registry ProfileLookup,
	runFn func(c *casemeta.Case, p *profile.Profile, progressCh chan<- engine.ProgressEvent) engine.CaseResult,
) (*RunResult, error) {
	p := tea.NewProgram(initialModelWithRunner(registry, runnerFunc(runFn)), tea.WithAltScreen())
	finalModel, err := p.Run()
	if err != nil {
		return nil, fmt.Errorf("tui error: %w", err)
	}

	m, ok := finalModel.(model)
	if !ok {
		return nil, fmt.Errorf("unexpected model type")
	}

	if !m.submitted {
		return nil, nil
	}

	res := &RunResult{Case: m.buildCase()}
	if m.collectionResult != nil {
		res.Collection = &CollectionResult{
			Case:   m.buildCase(),
			Result: m.collectionResult,
		}
	}
	return res, nil
}

type ProfileLookup interface {
	Get(name string) (*profile.Profile, error)
}

type screen int

const (
	screenWelcome screen = iota
	screenForm
	screenConfirm
	screenProgress
	screenComplete
)

// progressDoneMsg signals the progress channel has closed.
type progressDoneMsg struct{}

// collectionFinishedMsg carries the final result from the engine goroutine.
type collectionFinishedMsg struct {
	result engine.CaseResult
}

type model struct {
	screen           screen
	form             formModel
	progress         progressModel
	submitted        bool
	collectionResult *engine.CaseResult
	registry         ProfileLookup
	runner           Runner
	progressCh       chan engine.ProgressEvent
}

func initialModelWithRunner(registry ProfileLookup, r Runner) model {
	return model{
		screen:   screenWelcome,
		form:     newFormModel(),
		registry: registry,
		runner:   r,
	}
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
	if k, ok := msg.(tea.KeyMsg); ok && k.String() == "ctrl+c" {
		return m, tea.Quit
	}

	switch ev := msg.(type) {
	case progressEventMsg:
		m.progress.applyEvent(engine.ProgressEvent(ev))
		return m, listenForProgress(m.progressCh)
	case progressTickMsg:
		if m.screen == screenProgress {
			m.progress.spinnerTick++
			m.progress.elapsed = time.Since(m.progress.startedAt)
			return m, tickEvery(100 * time.Millisecond)
		}
	case collectionFinishedMsg:
		r := ev.result
		m.collectionResult = &r
		m.screen = screenComplete
		return m, nil
	case progressDoneMsg:
		// Channel closed, wait for collectionFinishedMsg.
		return m, nil
	}

	switch m.screen {
	case screenWelcome:
		return m.updateWelcome(msg)
	case screenForm:
		return m.updateForm(msg)
	case screenConfirm:
		return m.updateConfirm(msg)
	case screenComplete:
		return m.updateComplete(msg)
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
	case screenProgress:
		return m.progress.View()
	case screenComplete:
		return m.completeView()
	}
	return ""
}

func (m model) buildCase() *casemeta.Case {
	return &casemeta.Case{
		CaseID:           m.form.caseID.Value(),
		Analyst:          m.form.analyst.Value(),
		TargetIdentifier: m.form.target.Value(),
		TargetClass:      m.form.targetClass,
		ProfileName:      m.form.profile,
		Notes:            m.form.notes.Value(),
	}
}

func (m *model) startCollectionCmd() tea.Cmd {
	c := m.buildCase()
	c.CreatedAt = time.Now().UTC()

	p, err := m.registry.Get(c.ProfileName)
	if err != nil {
		return tea.Quit
	}

	m.progress = newProgressModel(c.CaseID, c.TargetIdentifier, c.ProfileName, p.TotalBudget)
	m.progressCh = make(chan engine.ProgressEvent, 32)
	resultCh := make(chan engine.CaseResult, 1)

	go func(ch chan engine.ProgressEvent, resCh chan engine.CaseResult, runner Runner, c *casemeta.Case, p *profile.Profile) {
		result := runner.Run(c, p, ch)
		close(ch)
		resCh <- result
		close(resCh)
	}(m.progressCh, resultCh, m.runner, c, p)

	return tea.Batch(
		listenForProgress(m.progressCh),
		waitForResult(resultCh),
		tickEvery(100*time.Millisecond),
	)
}

func listenForProgress(ch <-chan engine.ProgressEvent) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-ch
		if !ok {
			return progressDoneMsg{}
		}
		return progressEventMsg(ev)
	}
}

func waitForResult(ch <-chan engine.CaseResult) tea.Cmd {
	return func() tea.Msg {
		result, ok := <-ch
		if !ok {
			return collectionFinishedMsg{}
		}
		return collectionFinishedMsg{result: result}
	}
}

func tickEvery(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg {
		return progressTickMsg(t)
	})
}

// Run is the legacy entry point.
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
