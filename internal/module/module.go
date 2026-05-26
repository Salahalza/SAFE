package module

import (
	"context"
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
	Name() string
	Priority() Priority
	TimeBudget() time.Duration
	Run(ctx *Context) Result
}

// Context is what the engine passes to a module when it runs.
type Context struct {
	// OutputDir is where this module should write its artifacts.
	OutputDir string

	// Ctx carries cancellation and deadline information for the module.
	// Modules MUST honor ctx.Done() to support the watchdog.
	Ctx context.Context
}
