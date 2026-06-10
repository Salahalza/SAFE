package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Color palette
//
// Primary blue (#7DD3FC): brand color, used for active elements and emphasis.
// Gray scale: #E2E8F0 (light text), #94A3B8 (medium text), #64748B (dim text).
// Status: #86EFAC green, #FCD34D amber, #F87171 red.
// Background accent: #0F172A (deep navy), used as title bar background.

var (
	// titleStyle is for screen titles. Background-filled, bold, padded.
	// Visually heavier than body text without growing into multiple rows.
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#0F172A")).
			Background(lipgloss.Color("#7DD3FC")).
			Padding(0, 2).
			MarginBottom(2)

	subtitleStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#94A3B8")).
			Italic(true).
			MarginBottom(2)

	hintStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#64748B")).
			Italic(true).
			MarginTop(1)

	// containerStyle gives every screen breathing room around the edges.
	// Larger padding here translates directly into a more spacious feel.
	containerStyle = lipgloss.NewStyle().
			Padding(2, 6).
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

	// brandStyle renders the multi-row block-letter SAHM banner.
	// Used only on the welcome screen.
	brandStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7DD3FC")).
			Bold(true).
			MarginBottom(1)

	// sectionLabelStyle is for non-title section headers within a screen
	// (e.g., "Parsers" in the analyze complete view). Bold, no background,
	// underlined for visual weight without taking extra rows.
	sectionLabelStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#E2E8F0")).
				Bold(true).
				Underline(true).
				MarginTop(1).
				MarginBottom(1)
)

// Card styles for the report viewer

// cardStyle is the bordered container for the metadata header card.
// Uses rounded unicode corners; falls back gracefully on terminals that
// don't render the corner glyphs by showing them as their nearest ASCII.
var cardStyle = lipgloss.NewStyle().
	Border(lipgloss.RoundedBorder()).
	BorderForeground(lipgloss.Color("#7DD3FC")).
	Padding(1, 2).
	MarginBottom(1)

// attentionCardStyle highlights the critical/warning findings section.
// Amber border draws the eye without being alarming.
var attentionCardStyle = lipgloss.NewStyle().
	Border(lipgloss.RoundedBorder()).
	BorderForeground(lipgloss.Color("#FCD34D")).
	Padding(1, 2).
	MarginBottom(1)

// criticalCardStyle for actual critical findings — red border.
var criticalCardStyle = lipgloss.NewStyle().
	Border(lipgloss.RoundedBorder()).
	BorderForeground(lipgloss.Color("#F87171")).
	Padding(1, 2).
	MarginBottom(1)

// reportSectionTitleStyle is the heading inside a report section.
// Bold, brand color, with a small bottom margin.
var reportSectionTitleStyle = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#7DD3FC")).
	Bold(true).
	MarginBottom(1)

// statusBadgeStyle is the colored status pill (SUCCESS/PARTIAL/FAILED/DEGRADED).
// Background-filled with dark text for high contrast.
var statusBadgeStyle = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#0F172A")).
	Padding(0, 1).
	Bold(true)

// metadataLabelStyle styles labels like "Case ID", "Target", "Analyst".
var metadataLabelStyle = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#64748B"))

// metadataValueStyle styles the corresponding values.
var metadataValueStyle = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#E2E8F0"))

// moduleSuccessStyle / moduleFailedStyle / etc — module status icons.
var (
	moduleSuccessStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#86EFAC")).Bold(true)
	moduleWarnStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#FCD34D")).Bold(true)
	moduleFailStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#F87171")).Bold(true)
	moduleSkipStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#64748B"))
)

// findingSeverityStyle returns the appropriate icon and style for a severity.
func findingSeverityStyle(severity string) (icon string, style lipgloss.Style) {
	switch severity {
	case "critical":
		return "✗", lipgloss.NewStyle().Foreground(lipgloss.Color("#F87171")).Bold(true)
	case "warning":
		return "⚠", lipgloss.NewStyle().Foreground(lipgloss.Color("#FCD34D"))
	case "info":
		return "ℹ", lipgloss.NewStyle().Foreground(lipgloss.Color("#94A3B8"))
	default:
		return "•", lipgloss.NewStyle().Foreground(lipgloss.Color("#94A3B8"))
	}
}

// statusBadgeColors returns the appropriate background color for a status badge.
func statusBadgeColors(status string) (bg lipgloss.Color) {
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

// sahmBanner is the multi-row block-letter SAHM logo. Five rows tall,
// rendered with solid block characters. Used as a brand element on the
// welcome screen only.
const sahmBanner = `███████  █████  ██   ██ ███    ███
██      ██   ██ ██   ██ ████  ████
███████ ███████ ███████ ██ ████ ██
     ██ ██   ██ ██   ██ ██  ██  ██
███████ ██   ██ ██   ██ ██      ██`
