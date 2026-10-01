package module

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type PersistenceCore struct{}

func (m *PersistenceCore) Name() string              { return "persistence_core" }
func (m *PersistenceCore) Priority() Priority        { return PriorityHigh }
func (m *PersistenceCore) TimeBudget() time.Duration { return 3 * time.Minute }
func (m *PersistenceCore) RequiresVSS() bool         { return false }

// RequiresLiveHost is true: this collects persistence via live registry queries
// against the running host. Image persistence is recovered lab-side from the
// collected registry hives instead.
func (m *PersistenceCore) RequiresLiveHost() bool { return true }

func (m *PersistenceCore) Run(ctx *Context) Result {
	started := time.Now().UTC()
	result := Result{
		ModuleName: m.Name(),
		StartedAt:  started,
		Artifacts:  []Artifact{},
		Findings:   []Finding{},
		Errors:     []string{},
	}

	if !prepareOutputDir(&result, ctx.OutputDir, started) {
		return result
	}

	stdoutCommands := []Command{
		{
			Filename: "scheduled_tasks_verbose.txt",
			Name:     "schtasks",
			Args:     []string{"/query", "/fo", "LIST", "/v"},
			Check:    &ContentCheck{MustContain: []string{"TaskName"}, MustNotContain: commonErrorSignatures},
		},
		{
			Filename: "scheduled_tasks_xml.txt",
			Name:     "schtasks",
			Args:     []string{"/query", "/xml", "ONE"},
			Check:    &ContentCheck{MustContain: []string{"<Task"}, MustNotContain: commonErrorSignatures},
		},
		{
			Filename: "services_qc_all.txt",
			Name:     "sc",
			Args:     []string{"query", "state=", "all"},
			Check:    &ContentCheck{MustContain: []string{"SERVICE_NAME"}, MustNotContain: commonErrorSignatures},
		},
		{
			Filename:   "wmi_event_consumers.txt",
			Name:       "powershell",
			Args:       []string{"-NoProfile", "-Command", "Get-CimInstance -Namespace root\\subscription -ClassName __EventConsumer | Format-List *"},
			SkipChecks: true,
		},
		{
			Filename:   "wmi_event_filters.txt",
			Name:       "powershell",
			Args:       []string{"-NoProfile", "-Command", "Get-CimInstance -Namespace root\\subscription -ClassName __EventFilter | Format-List *"},
			SkipChecks: true,
		},
		{
			Filename:   "wmi_filter_to_consumer_bindings.txt",
			Name:       "powershell",
			Args:       []string{"-NoProfile", "-Command", "Get-CimInstance -Namespace root\\subscription -ClassName __FilterToConsumerBinding | Format-List *"},
			SkipChecks: true,
		},
		{
			Filename: "startup_folders.txt",
			Name:     "powershell",
			Args: []string{
				"-NoProfile",
				"-Command",
				`$paths = @(
					"$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
					"$env:AppData\Microsoft\Windows\Start Menu\Programs\Startup"
				); foreach ($p in $paths) { Write-Output "=== $p ==="; if (Test-Path $p) { Get-ChildItem -Path $p -Force | Format-List FullName,Length,LastWriteTime,CreationTime } else { Write-Output "(path not present)" } }`,
			},
			SkipChecks: true,
		},
		{
			Filename: "winlogon_keys.txt",
			Name:     "reg",
			Args:     []string{"query", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"},
			Check:    &ContentCheck{MustContain: []string{"Winlogon"}, MustNotContain: commonErrorSignatures},
		},
		{
			Filename: "image_file_execution_options.txt",
			Name:     "reg",
			Args:     []string{"query", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", "/s"},
			Check:    &ContentCheck{MustContain: []string{"Image File Execution Options"}, MustNotContain: commonErrorSignatures},
		},
		{Filename: "appinit_dlls.txt", Name: "reg", Args: []string{"query", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", "/v", "AppInit_DLLs"}, SkipChecks: true},
	}
	runCommands(ctx.Ctx, ctx.OutputDir, stdoutCommands, &result)

	runKeys := []struct {
		filename string
		key      string
	}{
		{"run_hklm.txt", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
		{"runonce_hklm.txt", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"},
		{"run_hklm_wow64.txt", "HKLM\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"},
		{"runonce_hklm_wow64.txt", "HKLM\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"},
		{"run_hkcu.txt", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
		{"runonce_hkcu.txt", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"},
	}

	for _, k := range runKeys {
		outPath := filepath.Join(ctx.OutputDir, k.filename)
		state, content, qErr := queryRunKey(ctx.Ctx, k.key)

		// Write whatever reg produced — including its raw "unable to find"/error
		// text — so the collected file is the faithful command output even on a
		// genuine failure (matching runOne). The state classification is recorded
		// as a Finding below, never mixed into the file.
		if content != "" {
			if err := os.WriteFile(outPath, []byte(content), 0o644); err != nil {
				result.Errors = append(result.Errors,
					fmt.Sprintf("write %s: %v", k.filename, err))
				continue
			}
			if artifact, err := describeArtifact(outPath); err == nil {
				result.Artifacts = append(result.Artifacts, artifact)
			} else {
				result.AddWarning(k.filename, fmt.Sprintf("hash failed: %v", err))
			}
		}

		if qErr != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("run key %s: %v", k.filename, qErr))
			continue
		}

		switch state {
		case runKeyMissing:
			result.AddInfo(k.filename, "key does not exist on this target")
		case runKeyEmpty:
			result.AddInfo(k.filename, "key exists but contains no values")
		}
	}

	finalize(&result, started, ctx.Ctx)
	return result
}

type runKeyState int

const (
	runKeyHasValues runKeyState = iota
	runKeyEmpty
	runKeyMissing
)

// queryRunKey runs `reg query <key> /s` and returns the raw command output plus a
// classification of the key's state (present-with-values / empty / missing).
//
// The returned content is EXACTLY what reg emitted — no header, timestamp, or
// interpretive text ("this is normal", "found unused at collection time") is mixed
// into it. Those belong in the module's Findings (the caller records the state as
// an Info finding), never in the evidence bytes: the collected file must stay a
// raw command artifact, exactly like every other command output in this package
// (runOne writes raw CombinedOutput). A key that is simply absent is not an error
// (reg exits non-zero) — that is runKeyMissing with a nil err; a genuine reg
// failure returns the raw output AND an error so the caller can still preserve
// what reg wrote and surface the failure.
func queryRunKey(ctx context.Context, key string) (runKeyState, string, error) {
	cmd := exec.CommandContext(ctx, "reg", "query", key, "/s")
	out, err := cmd.CombinedOutput()
	output := string(out)

	if err != nil {
		lower := strings.ToLower(output)
		if strings.Contains(lower, "unable to find") || strings.Contains(lower, "cannot find") {
			return runKeyMissing, output, nil
		}
		return runKeyHasValues, output, fmt.Errorf("reg query failed: %v", err)
	}

	if trimmed := strings.TrimSpace(output); trimmed == "" || isOnlyKeyHeader(trimmed) {
		return runKeyEmpty, output, nil
	}
	return runKeyHasValues, output, nil
}

func isOnlyKeyHeader(s string) bool {
	lines := strings.Split(s, "\n")
	nonEmptyLines := 0
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			nonEmptyLines++
		}
	}
	return nonEmptyLines <= 1
}
