package tui

import (
	tea "github.com/charmbracelet/bubbletea"
)

// This file provides scrolling for the non-interactive summary screens
// (confirm, complete, analyze-complete) so their content scrolls instead of
// clipping when the terminal is shorter than the content. They share one
// viewport (staticVP) because only one is ever shown at a time.
//
// Each of those screens exposes a *Body() function returning its rendered
// content (without the keybinding hint — that lives in a persistent footer).
// The body is loaded into staticVP when the screen is entered and on resize;
// the screen's update handler routes scroll input via scrollStatic and keeps
// its own proceed-keys (enter/esc/q/y/n).

// setStaticContent sizes the shared viewport to the terminal (reserving 3 lines
// for the footer) and loads the given body. Does not reset scroll position —
// callers entering a screen should follow with m.staticVP.GotoTop().
func (m *model) setStaticContent(body string) {
	m.staticVP.Width = m.termWidth
	h := m.termHeight - 3
	if h < 5 {
		h = 5
	}
	m.staticVP.Height = h
	m.staticVP.SetContent(body)
}

// currentStaticBody returns the body for whichever static screen is active,
// or ("", false) if the current screen is not one of them. Used on resize to
// re-render at the new width.
func (m model) currentStaticBody() (string, bool) {
	switch m.screen {
	case screenConfirm:
		return m.confirmBody(), true
	case screenComplete:
		return m.completeBody(), true
	}
	return "", false
}

// scrollStatic routes scroll input (mouse wheel and PgUp/PgDn/arrows/Home/End)
// to the shared viewport. Returns true if it consumed the message, so callers
// can fall through to their own proceed-key handling otherwise.
func (m *model) scrollStatic(msg tea.Msg) (bool, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.MouseMsg:
		var cmd tea.Cmd
		m.staticVP, cmd = m.staticVP.Update(msg)
		return true, cmd
	case tea.KeyMsg:
		switch msg.String() {
		case "up":
			m.staticVP.ScrollUp(1)
		case "down":
			m.staticVP.ScrollDown(1)
		case "pgup":
			m.staticVP.PageUp()
		case "pgdown":
			m.staticVP.PageDown()
		case "home":
			m.staticVP.GotoTop()
		case "end":
			m.staticVP.GotoBottom()
		default:
			return false, nil
		}
		return true, nil
	}
	return false, nil
}

// staticView renders the shared viewport plus a persistent footer that stays
// visible regardless of scroll position.
func (m model) staticView(footer string) string {
	return m.staticVP.View() + "\n" + hintStyle.Render(footer)
}
