package tui

import "github.com/charmbracelet/lipgloss"

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
			MarginTop(1)

	labelStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#94A3B8")).
			Bold(true)

	focusedLabelStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#7DD3FC")).
				Bold(true)

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F87171")).
			Bold(true).
			MarginTop(1)

	successStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#86EFAC")).
			Bold(true).
			MarginTop(1)
)
