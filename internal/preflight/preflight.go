package preflight

import (
	"fmt"
	"strings"
)

// Severity describes how serious a preflight finding is.
type Severity string

const (
	// SeverityInfo is purely informational, no action implied.
	SeverityInfo Severity = "info"

	// SeverityWarning means the analyst should know about this, but
	// collection can proceed. Examples: optional channel absent, EDR detected.
	SeverityWarning Severity = "warning"

	// SeverityCritical means collection will produce significantly degraded
	// or invalid output. The analyst should fix the issue before proceeding.
	// Examples: not running as admin, disk full.
	SeverityCritical Severity = "critical"
)

// Finding is the result of one preflight check.
type Finding struct {
	Check    string   `json:"check"`
	Severity Severity `json:"severity"`
	Message  string   `json:"message"`
	Detail   string   `json:"detail,omitempty"`
}

// Check is the contract every preflight check must implement.
type Check interface {
	// Name returns the unique check name.
	Name() string

	// Run executes the check and returns a finding.
	// Returning nil means "this check has nothing to report" (all good).
	Run() *Finding
}

// Report is the result of running all preflight checks.
type Report struct {
	Findings []Finding `json:"findings"`
}

// HasCritical returns true if any finding is critical severity.
func (r *Report) HasCritical() bool {
	for _, f := range r.Findings {
		if f.Severity == SeverityCritical {
			return true
		}
	}
	return false
}

// HasWarnings returns true if any finding is warning severity.
func (r *Report) HasWarnings() bool {
	for _, f := range r.Findings {
		if f.Severity == SeverityWarning {
			return true
		}
	}
	return false
}

// Format returns a human-readable string representation of the report.
func (r *Report) Format() string {
	if len(r.Findings) == 0 {
		return "All preflight checks passed.\n"
	}
	var b strings.Builder
	b.WriteString("Preflight findings:\n")
	for _, f := range r.Findings {
		b.WriteString(fmt.Sprintf("  [%s] %s: %s\n",
			strings.ToUpper(string(f.Severity)), f.Check, f.Message))
		if f.Detail != "" {
			b.WriteString(fmt.Sprintf("         %s\n", f.Detail))
		}
	}
	return b.String()
}

// Run executes all registered checks and returns a consolidated report.
func Run(checks []Check) *Report {
	report := &Report{
		Findings: []Finding{},
	}
	for _, c := range checks {
		if f := c.Run(); f != nil {
			report.Findings = append(report.Findings, *f)
		}
	}
	return report
}
