package module

import (
	"context"
	"sahm/internal/vss"
	"time"
)

// Priority determines how the engine reacts when a module fails or overruns.
type Priority string

const (
	PriorityCritical Priority = "critical"
	PriorityHigh     Priority = "high"
	PriorityNormal   Priority = "normal"
	PriorityOptional Priority = "optional"
)

// Status represents the outcome of a module run.
type Status string

const (
	StatusSuccess  Status = "success"
	StatusPartial  Status = "partial"
	StatusFailed   Status = "failed"
	StatusSkipped  Status = "skipped"
	StatusTimedOut Status = "timed_out"
)

// Severity describes how serious a finding is, from informational to critical.
type Severity string

const (
	// SeverityInfo: a normal observation the analyst should know about but
	// which does NOT indicate a problem. Examples: optional channel not present,
	// registry key exists but is empty.
	SeverityInfo Severity = "info"

	// SeverityWarning: something the analyst should look at. The collection
	// is still usable, but specific files need verification. Examples:
	// content check fired on an artifact, an artifact was dropped due to size.
	SeverityWarning Severity = "warning"

	// SeverityCritical: collection was significantly degraded. Examples:
	// module failed entirely, EDR blocked execution, critical timeout.
	// Note: these are typically tracked in Errors, not here.
	SeverityCritical Severity = "critical"
)

// Finding is one observation made during a module run.
type Finding struct {
	Severity Severity `json:"severity"`
	Source   string   `json:"source,omitempty"` // e.g. filename or component
	Message  string   `json:"message"`
}

// Artifact is a single file produced by a module.
type Artifact struct {
	Name       string    `json:"name"`
	Path       string    `json:"path"`
	SHA256     string    `json:"sha256"`
	Size       int64     `json:"size_bytes"`
	CreatedAt  time.Time `json:"created_at"`
	SourcePath string    `json:"source_path,omitempty"`
	SourceSize int64     `json:"source_size_bytes,omitempty"`
}

// Result is what a module returns when it finishes.
type Result struct {
	ModuleName string        `json:"module_name"`
	Status     Status        `json:"status"`
	StartedAt  time.Time     `json:"started_at"`
	EndedAt    time.Time     `json:"ended_at"`
	Duration   time.Duration `json:"duration_ns"`
	Artifacts  []Artifact    `json:"artifacts"`
	Findings   []Finding     `json:"findings,omitempty"`
	Errors     []string      `json:"errors,omitempty"`

	// Warnings is kept for backwards compatibility but populated from Findings.
	// Will be removed in a future version.
	Warnings []string `json:"warnings,omitempty"`
}

// AddInfo adds an info-severity finding.
func (r *Result) AddInfo(source, message string) {
	r.Findings = append(r.Findings, Finding{
		Severity: SeverityInfo,
		Source:   source,
		Message:  message,
	})
}

// AddWarning adds a warning-severity finding.
func (r *Result) AddWarning(source, message string) {
	r.Findings = append(r.Findings, Finding{
		Severity: SeverityWarning,
		Source:   source,
		Message:  message,
	})
	// Backwards compat — keep populating the flat Warnings slice for now.
	if source != "" {
		r.Warnings = append(r.Warnings, source+": "+message)
	} else {
		r.Warnings = append(r.Warnings, message)
	}
}

// AddCritical adds a critical-severity finding.
func (r *Result) AddCritical(source, message string) {
	r.Findings = append(r.Findings, Finding{
		Severity: SeverityCritical,
		Source:   source,
		Message:  message,
	})
}

// CountBySeverity returns the count of findings at each severity level.
func (r *Result) CountBySeverity() (info, warning, critical int) {
	for _, f := range r.Findings {
		switch f.Severity {
		case SeverityInfo:
			info++
		case SeverityWarning:
			warning++
		case SeverityCritical:
			critical++
		}
	}
	return
}

// Module is the contract every collection module must satisfy.
type Module interface {
	Name() string
	Priority() Priority
	TimeBudget() time.Duration
	RequiresVSS() bool
	Run(ctx *Context) Result
}

// Context is what the engine passes to a module when it runs.
type Context struct {
	OutputDir string
	Ctx       context.Context

	// Shadow is the volume shadow copy for this case, if any module
	// in the profile required VSS. Nil if no module needs it.
	// Modules that require VSS read locked files from Shadow.MountedPath.
	Shadow *vss.Shadow
}
