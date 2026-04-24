package module

import "time"

// Priority determines how the engine reacts when a module fails or overruns.
// This maps to the priority rules from the Acquira spec.
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
	StatusSuccess Status = "success"
	StatusPartial Status = "partial"
	StatusFailed  Status = "failed"
	StatusSkipped Status = "skipped"
)

// Artifact is a single file produced by a module.
type Artifact struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Result is what a module returns when it finishes.
type Result struct {
	ModuleName string        `json:"module_name"`
	Status     Status        `json:"status"`
	StartedAt  time.Time     `json:"started_at"`
	EndedAt    time.Time     `json:"ended_at"`
	Duration   time.Duration `json:"duration_ns"`
	Artifacts  []Artifact    `json:"artifacts"`
	Warnings   []string      `json:"warnings,omitempty"`
	Errors     []string      `json:"errors,omitempty"`
}

// Module is the contract every collection module must satisfy.
type Module interface {
	// Name returns the unique module name, e.g. "system_metadata".
	Name() string

	// Priority returns this module's priority within the profile.
	Priority() Priority

	// TimeBudget returns the maximum time this module is allowed to run.
	TimeBudget() time.Duration

	// Run executes the module. It receives a Context with everything
	// the module needs (output paths, adapters, cancellation signal).
	// It returns a Result describing what happened.
	Run(ctx *Context) Result
}

// Context is what the engine passes to a module when it runs.
// For now it only holds the output directory. We'll add more as we need it.
type Context struct {
	// OutputDir is where this module should write its artifacts.
	OutputDir string
}
