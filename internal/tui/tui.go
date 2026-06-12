package tui

import (
	"fmt"
	"time"

	"safe/internal/analyzer"
	"safe/internal/casemeta"
	"safe/internal/engine"
	"safe/internal/profile"

	"github.com/charmbracelet/bubbles/filepicker"
	"github.com/charmbracelet/bubbles/viewport"
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
		tea.WithMouseCellMotion(), // enable mouse wheel scrolling
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

// reportLoadedMsg carries the loaded and parsed report data.
type reportLoadedMsg struct {
	data *reportData
	err  error
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
	reportPicker   filepicker.Model
	reportPath     string
	reportData     *reportData
	reportErr      error
	reportViewport viewport.Model

	// formViewport wraps the new-case form so it can scroll (mouse wheel /
	// PgUp / PgDn) instead of clipping when the terminal is shorter than the
	// form. Content is refreshed on every form update; see refreshFormViewport.
	formViewport viewport.Model

	// Terminal dimensions (set by WindowSizeMsg)
	termWidth  int
	termHeight int
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
		formViewport:  viewport.New(80, 20),
	}
}

// newCaseFolderPicker creates a filepicker configured for selecting case folders.
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
		screen:       screenWelcome,
		form:         newFormModel(),
		formViewport: viewport.New(80, 20),
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

	// Track terminal size for viewport sizing.
	if sz, ok := msg.(tea.WindowSizeMsg); ok {
		m.termWidth = sz.Width
		m.termHeight = sz.Height
		// Size the form viewport to the terminal, reserving 3 lines for the
		// persistent footer. Refresh its content if the form is on screen.
		m.formViewport.Width = sz.Width
		formHeight := sz.Height - 3
		if formHeight < 5 {
			formHeight = 5
		}
		m.formViewport.Height = formHeight
		if m.screen == screenForm {
			m.refreshFormViewport(true)
		}
		// If the report viewport already exists, resize it.
		if m.reportData != nil {
			vpHeight := sz.Height - 3
			if vpHeight < 10 {
				vpHeight = 10
			}
			m.reportViewport = initReportViewport(sz.Width, vpHeight, m.reportData)
		}
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
		m.reportData = ev.data
		m.reportErr = ev.err
		if ev.err == nil && ev.data != nil {
			// Size viewport to terminal, leaving room for footer (3 lines).
			vpHeight := m.termHeight - 3
			if vpHeight < 10 {
				vpHeight = 10
			}
			vpWidth := m.termWidth
			if vpWidth < 60 {
				vpWidth = 80
			}
			m.reportViewport = initReportViewport(vpWidth, vpHeight, ev.data)
		}
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

// formViewerView renders the scrollable form plus a persistent footer that
// stays visible regardless of scroll position.
func (m model) formViewerView() string {
	footer := hintStyle.Render("Tab / Down next field   |   Shift+Tab / Up previous   |   Left / Right change selection   |   PgUp / PgDn or mouse wheel to scroll   |   Esc back   |   Ctrl+C quit")
	return m.formViewport.View() + "\n" + footer
}

// refreshFormViewport re-renders the form body into the viewport. When follow
// is true it also scrolls so the focused field stays visible — used after any
// keyboard navigation, but NOT after a mouse-wheel scroll (which should stay
// where the user put it).
func (m *model) refreshFormViewport(follow bool) {
	body, focusStart, focusHeight := m.form.render(m.termWidth)
	m.formViewport.SetContent(containerStyle.Render(body))
	if follow {
		m.followFormFocus(focusStart, focusHeight)
	}
}

// followFormFocus scrolls the form viewport just enough to keep the focused
// field within view. focusStart/focusHeight are in body-content coordinates;
// containerStyle adds MarginTop(1)+PaddingTop(2) = 3 lines above the body, so
// shift by that to land in viewport coordinates.
func (m *model) followFormFocus(focusStart, focusHeight int) {
	const topOffset = 3
	start := focusStart + topOffset
	end := start + focusHeight
	top := m.formViewport.YOffset
	bottom := top + m.formViewport.Height
	switch {
	case start < top:
		m.formViewport.SetYOffset(start)
	case end > bottom:
		m.formViewport.SetYOffset(end - m.formViewport.Height)
	}
}

func (m model) View() string {
	switch m.screen {
	case screenWelcome:
		return welcomeView(m.welcomeCursor)
	case screenForm:
		return m.formViewerView()
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
	p := tea.NewProgram(initialModel(), tea.WithAltScreen(), tea.WithMouseCellMotion())
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
