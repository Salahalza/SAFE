package module

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// ProcessSnapshot captures the running processes on the target.
type ProcessSnapshot struct{}

// Name implements Module.
func (m *ProcessSnapshot) Name() string {
	return "process_snapshot"
}

// Priority implements Module. Process state is critical —
// understanding what was running is foundational to any investigation.
func (m *ProcessSnapshot) Priority() Priority {
	return PriorityCritical
}

// TimeBudget implements Module.
func (m *ProcessSnapshot) TimeBudget() time.Duration {
	return 60 * time.Second
}

// Run implements Module.
func (m *ProcessSnapshot) Run(ctx *Context) Result {
	started := time.Now().UTC()
	result := Result{
		ModuleName: m.Name(),
		StartedAt:  started,
		Artifacts:  []Artifact{},
		Warnings:   []string{},
		Errors:     []string{},
	}

	if err := os.MkdirAll(ctx.OutputDir, 0o755); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("create output dir: %v", err))
		result.Status = StatusFailed
		result.EndedAt = time.Now().UTC()
		result.Duration = result.EndedAt.Sub(started)
		return result
	}

	// Native commands for process state.
	// PowerShell is preferred where wmic would have been used —
	// wmic is deprecated and removed on newer Windows builds.
	commands := []struct {
		filename string
		name     string
		args     []string
	}{
		{
			"tasklist_verbose.txt",
			"tasklist",
			[]string{"/v", "/fo", "list"},
		},
		{
			"tasklist_services.txt",
			"tasklist",
			[]string{"/svc", "/fo", "list"},
		},
		{
			"processes_powershell.txt",
			"powershell",
			[]string{
				"-NoProfile",
				"-Command",
				"Get-CimInstance Win32_Process | Select-Object Name,ProcessId,ParentProcessId,CommandLine,ExecutablePath,CreationDate | Format-List",
			},
		},
		{
			"services_state.txt",
			"powershell",
			[]string{
				"-NoProfile",
				"-Command",
				"Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName,StartName | Format-List",
			},
		},
	}

	for _, c := range commands {
		outPath := filepath.Join(ctx.OutputDir, c.filename)
		if err := runAndCaptureCmd(c.name, c.args, outPath); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", c.name, err))
			continue
		}
		artifact, err := describeArtifact(outPath)
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("hash %s: %v", c.filename, err))
			continue
		}
		result.Artifacts = append(result.Artifacts, artifact)
	}

	result.EndedAt = time.Now().UTC()
	result.Duration = result.EndedAt.Sub(started)

	switch {
	case len(result.Errors) == 0:
		result.Status = StatusSuccess
	case len(result.Artifacts) > 0:
		result.Status = StatusPartial
	default:
		result.Status = StatusFailed
	}

	return result
}

// runAndCaptureCmd is a near-duplicate of runAndCapture in system_metadata.go.
// Kept separate for now; we'll factor these into a shared helper in the next refactor.
func runAndCaptureCmd(name string, args []string, outPath string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		_ = os.WriteFile(outPath, out, 0o644)
		return fmt.Errorf("command failed: %w", err)
	}
	return os.WriteFile(outPath, out, 0o644)
}
