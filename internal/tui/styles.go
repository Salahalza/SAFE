package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Color palette
//
// Primary cyan (#06B6D4): brand color, used for active elements and emphasis.
// Indigo accent (#6366F1): secondary accent for depth.
// Gray scale: #F3F4F6 (light text), #9CA3AF (medium text), #6B7280 (dim text).
// Status: #10B981 emerald, #F59E0B amber, #EF4444 red.
// Background accent: #0B0F19 (deep space), used as title bar background.

var (
	// titleStyle is for screen titles. Background-filled, bold, padded.
	// Visually heavier than body text without growing into multiple rows.
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#0B0F19")).
			Background(lipgloss.Color("#06B6D4")).
			Padding(0, 2).
			MarginBottom(2)

	subtitleStyle = lipgloss.NewStyle(). //nolint:unused
			Foreground(lipgloss.Color("#9CA3AF")).
			Italic(true).
			MarginBottom(2)

	hintStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6B7280")).
			Italic(true).
			MarginTop(1)

	// containerStyle gives every screen breathing room around the edges.
	// Larger padding here translates directly into a more spacious feel.
	containerStyle = lipgloss.NewStyle().
			Padding(2, 6).
			MarginTop(1)

	labelStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#9CA3AF")).
			Bold(true)

	focusedLabelStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#06B6D4")).
				Bold(true)

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#EF4444")).
			Bold(true).
			MarginTop(1)

	successStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#10B981")).
			Bold(true).
			MarginTop(1)

	// brandStyle renders the multi-row block-letter SAFE banner.
	// Used only on the welcome screen.
	brandStyle = lipgloss.NewStyle(). //nolint:unused
			Foreground(lipgloss.Color("#06B6D4")).
			Bold(true).
			MarginBottom(1)

	// sectionLabelStyle is for non-title section headers within a screen
	// (e.g., "Parsers" in the analyze complete view). Bold, no background,
	// underlined for visual weight without taking extra rows.
	sectionLabelStyle = lipgloss.NewStyle(). //nolint:unused
				Foreground(lipgloss.Color("#E2E8F0")).
				Bold(true).
				Underline(true).
				MarginTop(1).
				MarginBottom(1)
)

// Card styles for the report viewer

// statusBadgeColors returns the appropriate background color for a status badge.
func statusBadgeColors(status string) (bg lipgloss.Color) { //nolint:unused
	switch strings.ToUpper(status) {
	case "SUCCESS":
		return lipgloss.Color("#86EFAC")
	case "PARTIAL":
		return lipgloss.Color("#FCD34D")
	case "FAILED", "DEGRADED":
		return lipgloss.Color("#F87171")
	default:
		return lipgloss.Color("#94A3B8")
	}
}




// Card styles for the report viewer

// cardStyle is the bordered container for the metadata header card.
var cardStyle = lipgloss.NewStyle(). //nolint:unused
	Border(lipgloss.NormalBorder()).
	BorderForeground(lipgloss.Color("#7DD3FC")).
	Padding(1, 2).
	MarginBottom(1)

// attentionCardStyle highlights the critical/warning findings section.
var attentionCardStyle = lipgloss.NewStyle(). //nolint:unused
	Border(lipgloss.NormalBorder()).
	BorderForeground(lipgloss.Color("#FCD34D")).
	Padding(1, 2).
	MarginBottom(1)

// criticalCardStyle for critical findings — red border.
var criticalCardStyle = lipgloss.NewStyle(). //nolint:unused
	Border(lipgloss.NormalBorder()).
	BorderForeground(lipgloss.Color("#F87171")).
	Padding(1, 2).
	MarginBottom(1)

// reportSectionTitleStyle is the heading inside a report section.
var reportSectionTitleStyle = lipgloss.NewStyle(). //nolint:unused
	Foreground(lipgloss.Color("#7DD3FC")).
	Bold(true).
	MarginBottom(1)

// metadataLabelStyle styles labels like "Case ID", "Target", "Analyst".
var metadataLabelStyle = lipgloss.NewStyle(). //nolint:unused
	Foreground(lipgloss.Color("#64748B"))

// metadataValueStyle styles the corresponding values.
var metadataValueStyle = lipgloss.NewStyle(). //nolint:unused
	Foreground(lipgloss.Color("#E2E8F0"))

// module status icon styles
var (
	moduleSuccessStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#86EFAC")).Bold(true) //nolint:unused
	moduleWarnStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#FCD34D")).Bold(true) //nolint:unused
	moduleFailStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#F87171")).Bold(true) //nolint:unused
	moduleSkipStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#64748B")) //nolint:unused
)

// findingSeverityStyle returns the icon and style for a severity level.
func findingSeverityStyle(severity string) (icon string, style lipgloss.Style) { //nolint:unused
	switch severity {
	case "critical":
		return "[!]", lipgloss.NewStyle().Foreground(lipgloss.Color("#F87171")).Bold(true)
	case "warning":
		return "[*]", lipgloss.NewStyle().Foreground(lipgloss.Color("#FCD34D"))
	case "info":
		return "[i]", lipgloss.NewStyle().Foreground(lipgloss.Color("#94A3B8"))
	default:
		return "[-]", lipgloss.NewStyle().Foreground(lipgloss.Color("#94A3B8"))
	}
}

// statusBadgeStyle returns a styled status pill (SUCCESS / PARTIAL / FAILED / DEGRADED).
func statusBadgeStyle(status string) string { //nolint:unused
	upper := strings.ToUpper(status)
	var bg lipgloss.Color
	switch upper {
	case "SUCCESS":
		bg = lipgloss.Color("#86EFAC")
	case "PARTIAL":
		bg = lipgloss.Color("#FCD34D")
	case "FAILED", "DEGRADED":
		bg = lipgloss.Color("#F87171")
	default:
		bg = lipgloss.Color("#94A3B8")
	}
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color("#0F172A")).
		Background(bg).
		Bold(true).
		Padding(0, 1).
		Render("* " + upper)
}
