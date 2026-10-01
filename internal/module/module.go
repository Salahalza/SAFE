package module

import (
	"context"
	"github.com/Salahalza/SAFE/internal/vss"
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
	// BulkFiles is the count of secondary files collected by bulk operations
	// like directory copies. These files are individually hashed in the manifest
	// but conceptually represent one collection action, not many distinct
	// forensic artifacts. Example: Prefetch copies every .pf file in
	// C:\Windows\Prefetch — analyst treats it as one collected dataset, not
	// hundreds of separate findings.
	//
	// When BulkFiles > 0, the corresponding entry in Artifacts is typically the
	// directory or a summary descriptor, not the individual files.
	BulkFiles int `json:"bulk_files,omitempty"`

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

// Applicable is an optional interface a Module may implement to declare that it
// only applies to certain targets — e.g. a role-specific collector that should
// cleanly no-op on a host lacking that role rather than run and emit criticals
// for missing artifacts. A Module that does not implement Applicable always
// runs.
//
// The engine evaluates Applies during collection planning, BEFORE any shadow
// copy exists, so an implementation must rely only on live host state (e.g. the
// registry) and must not read ctx.Shadow. When Applies returns false the engine
// records a StatusSkipped result carrying the reason and moves on; a skip is not
// a failure and does not degrade the case, and a not-applicable module never
// forces VSS shadow creation.
type Applicable interface {
	Applies(ctx *Context) (applies bool, reason string)
}

// LiveOnly is an optional interface a Module may implement to declare that it
// can only collect from a live, running host. A module is live-only when it
// captures volatile state that exists only in a running system (the process
// list, network connections, process memory) or shells out to live OS commands
// whose output reflects the running machine rather than an arbitrary filesystem
// root (reg save, tasklist, wevtutil export, netstat).
//
// When the case evidence source is a static disk image (ctx.Live == false) the
// engine skips a live-only module with a StatusSkipped result — running it would
// capture the analyst's own workstation state, not the imaged host, silently
// contaminating the case. A Module that does not implement LiveOnly is assumed
// to read its evidence from ctx.Root and therefore works against either a live
// VSS shadow or a mounted image.
type LiveOnly interface {
	RequiresLiveHost() bool
}

// Context is what the engine passes to a module when it runs.
type Context struct {
	OutputDir string
	Ctx       context.Context

	// Root is the filesystem root a module resolves target paths against —
	// the volume that holds the operating system under examination. A module
	// that reads locked or system files (registry hives, prefetch, event logs)
	// must join its paths onto Root rather than a hardcoded "C:\".
	//
	// For a live case Root is the VSS shadow's mount (Shadow.MountedPath), so
	// locked files are read from a stable point-in-time copy. For a dead disk
	// image Root is the read-only-mounted image volume (e.g. "E:\") and Shadow
	// is nil — the image is already a static snapshot, so no shadow is needed.
	// Root is empty only when a required root could not be established (e.g.
	// live shadow creation failed); the engine skips root-requiring modules in
	// that case, so a module seeing an empty Root should treat it as an error.
	Root string

	// Live reports whether this case is being collected from a live running
	// host (true) or from a static evidence source such as a mounted disk
	// image (false). Modules that can only work against a running OS — the live
	// process list, network state, live registry queries — declare
	// RequiresLiveHost and are skipped by the engine when Live is false.
	Live bool

	// Image, when non-nil, reads collected file content directly from the mounted
	// disk image's raw NTFS volume, bypassing the OS filesystem API so on-access
	// AV/EDR cannot block or quarantine evidence (e.g. a web shell on a
	// compromised image). Set only for dead-image cases whose source root is a
	// drive-letter volume; nil for live cases and for image roots that are not
	// raw volumes, which fall back to OS reads. Collectors must copy file content
	// via copyEvidenceFile so this is honoured uniformly.
	Image *ImageReader

	// PayloadReader, when non-nil, reads live payload-class content (web-root
	// scripts) directly off the VSS shadow's clusters via raw NTFS, so an
	// on-access AV/EDR cannot block or quarantine the read of a live web shell.
	// It is the live-case counterpart to Image (which serves dead-image cases):
	// a collector sets it from Shadow.ShadowPath for the duration of its payload
	// read and clears it afterwards. readEvidenceBytes honours it. Nil for
	// dead-image cases (Image is used instead) and when no raw shadow is available.
	PayloadReader *ImageReader

	// Shadow is the volume shadow copy for this case, if any module
	// in the profile required VSS on a live host. Nil when no module needs it,
	// and always nil for a dead-image case (Root points at the image instead).
	// A module that needs the raw shadow device path (not just a directory
	// root) reads it from Shadow directly; such modules only work on a live
	// host with VSS.
	Shadow *vss.Shadow

	// Progress, if set, lets a module report intra-module progress so the UI
	// can advance a bar with real file/byte counts (rather than only stepping
	// per module). done/total are work units within the module (files or
	// commands processed / total); bytes is the cumulative bytes written so far
	// by this module. Reported from the module's own goroutine; the engine
	// throttles forwarding. Use ReportProgress so a nil Progress is a no-op.
	Progress func(done, total int, bytes int64)
}

// ReportProgress forwards intra-module progress to the UI when a reporter is
// set, and is a no-op otherwise — modules can call it unconditionally.
func (c *Context) ReportProgress(done, total int, bytes int64) {
	if c != nil && c.Progress != nil {
		c.Progress(done, total, bytes)
	}
}
