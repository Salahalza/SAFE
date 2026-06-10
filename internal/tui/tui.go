package tui

import (
	"fmt"
	"time"

	"sahm/internal/analyzer"
	"sahm/internal/casemeta"
	"sahm/internal/engine"
	"sahm/internal/profile"

	"github.com/charmbracelet/bubbles/filepicker"
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

// AnalyzerRunner is what the TUI uses to run analysis on a case folder.
type AnalyzerRunner func(caseDir string) (*analyzer.Result, error)

// RunWithCollection launches the TUI and runs collection inside it.
// This is the entry point invoked by main.go when --tui is passed.
func RunWithCollection(
	registry ProfileLookup,
	runFn func(c *casemeta.Case, p *profile.Profile, progressCh chan<- engine.ProgressEvent) engine.CaseResult,
	analyzeFn AnalyzerRunner,
) (*RunResult, error) {
	p := tea.NewProgram(
		initialModelWithRunner(registry, runnerFunc(runFn), analyzeFn),
		tea.WithAltScreen(),
	)
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
	// Collection flow
	screenForm
	screenConfirm
	screenProgress
	screenComplete
	// Analyze flow
	screenAnalyzePicker
	screenAnalyzeProgress
	screenAnalyzeComplete
	// Report viewer flow
	screenReportPicker
	screenReportViewer
)

// progressDoneMsg signals the progress channel has closed.
type progressDoneMsg struct{}

// collectionFinishedMsg carries the final result from the engine goroutine.
type collectionFinishedMsg struct {
	result engine.CaseResult
}

// analyzeFinishedMsg carries the analyzer result.
type analyzeFinishedMsg struct {
	result *analyzer.Result
	err    error
}

// reportLoadedMsg carries the loaded case_report.txt contents.
type reportLoadedMsg struct {
	content string
	err     error
}

type welcomeChoice int

const (
	welcomeStartCollection welcomeChoice = iota
	welcomeRunAnalyzer
	welcomeViewReport
	numWelcomeChoices
)

type model struct {
	screen screen

	// Collection state
	form             formModel
	progress         progressModel
	submitted        bool
	collectionResult *engine.CaseResult
	registry         ProfileLookup
	runner           Runner
	progressCh       chan engine.ProgressEvent

	// Welcome state
	welcomeCursor welcomeChoice

	// Analyzer state
	analyzeFn       AnalyzerRunner
	analyzePicker   filepicker.Model
	analyzeCaseDir  string
	analyzeResult   *analyzer.Result
	analyzeErr      error
	analyzeSpinTick int

	// Report viewer state
	reportPicker  filepicker.Model
	reportPath    string
	reportContent string
	reportErr     error
	reportScrollY int
}

func initialModelWithRunner(registry ProfileLookup, r Runner, analyzeFn AnalyzerRunner) model {
	return model{
		screen:        screenWelcome,
		form:          newFormModel(),
		registry:      registry,
		runner:        r,
		analyzeFn:     analyzeFn,
		analyzePicker: newCaseFolderPicker(),
		reportPicker:  newCaseFolderPicker(),
	}
}

// newCaseFolderPicker creates a filepicker configured for selecting case folders.
// Case folders are directories named CASE-<id>_<timestamp>/. The picker allows
// directory selection, hides regular files for clarity, and starts in the
// current working directory.
func newCaseFolderPicker() filepicker.Model {
	fp := filepicker.New()
	fp.DirAllowed = true
	fp.FileAllowed = false
	fp.ShowHidden = false
	fp.ShowPermissions = false
	fp.ShowSize = false
	fp.AutoHeight = false
	fp.SetHeight(15)
	return fp
}

func initialModel() model {
	return model{
		screen: screenWelcome,
		form:   newFormModel(),
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(
		m.analyzePicker.Init(),
		m.reportPicker.Init(),
	)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok && k.String() == "ctrl+c" {
		return m, tea.Quit
	}

	// Global messages that apply regardless of screen.
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
		if m.screen == screenAnalyzeProgress {
			m.analyzeSpinTick++
			return m, tickEvery(100 * time.Millisecond)
		}
	case collectionFinishedMsg:
		r := ev.result
		m.collectionResult = &r
		m.screen = screenComplete
		return m, nil
	case progressDoneMsg:
		return m, nil
	case analyzeFinishedMsg:
		m.analyzeResult = ev.result
		m.analyzeErr = ev.err
		m.screen = screenAnalyzeComplete
		return m, nil
	case reportLoadedMsg:
		m.reportContent = ev.content
		m.reportErr = ev.err
		m.reportScrollY = 0
		m.screen = screenReportViewer
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
	case screenAnalyzePicker:
		return m.updateAnalyzePicker(msg)
	case screenAnalyzeComplete:
		return m.updateAnalyzeComplete(msg)
	case screenReportPicker:
		return m.updateReportPicker(msg)
	case screenReportViewer:
		return m.updateReportViewer(msg)
	}
	return m, nil
}

func (m model) View() string {
	switch m.screen {
	case screenWelcome:
		return welcomeView(m.welcomeCursor)
	case screenForm:
		return m.form.View()
	case screenConfirm:
		return m.confirmView()
	case screenProgress:
		return m.progress.View()
	case screenComplete:
		return m.completeView()
	case screenAnalyzePicker:
		return m.analyzePickerView()
	case screenAnalyzeProgress:
		return m.analyzeProgressView()
	case screenAnalyzeComplete:
		return m.analyzeCompleteView()
	case screenReportPicker:
		return m.reportPickerView()
	case screenReportViewer:
		return m.reportViewerView()
	}
	return ""
}

func (m model) buildCase() *casemeta.Case {
	return &casemeta.Case{
		CaseID:           m.form.caseID.Value(),
		IRNumber:         m.form.irNumber.Value(),
		CSINumber:        m.form.csiNumber.Value(),
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

// startAnalyzeCmd kicks off the analyzer against the chosen case folder.
// The analyzer is fast enough today that we don't bother with a progress
// channel — we show a spinner and wait for the analyzeFinishedMsg.
func (m *model) startAnalyzeCmd() tea.Cmd {
	caseDir := m.analyzeCaseDir
	analyzeFn := m.analyzeFn

	return tea.Batch(
		func() tea.Msg {
			result, err := analyzeFn(caseDir)
			return analyzeFinishedMsg{result: result, err: err}
		},
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

// Run is the legacy entry point for collection-only flow.
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
