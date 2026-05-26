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

func (m *PersistenceCore) Run(ctx *Context) Result {
	started := time.Now().UTC()
	result := Result{
		ModuleName: m.Name(),
		StartedAt:  started,
		Artifacts:  []Artifact{},
		Warnings:   []string{},
		Errors:     []string{},
	}

	if !prepareOutputDir(&result, ctx.OutputDir, started) {
		return result
	}

	stdoutCommands := []Command{
		{Filename: "scheduled_tasks_verbose.txt", Name: "schtasks", Args: []string{"/query", "/fo", "LIST", "/v"}},
		{Filename: "scheduled_tasks_xml.txt", Name: "schtasks", Args: []string{"/query", "/xml", "ONE"}},
		{Filename: "services_qc_all.txt", Name: "sc", Args: []string{"query", "state=", "all"}},
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
		{Filename: "winlogon_keys.txt", Name: "reg", Args: []string{"query", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"}},
		{Filename: "image_file_execution_options.txt", Name: "reg", Args: []string{"query", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", "/s"}},
		{Filename: "appinit_dlls.txt", Name: "reg", Args: []string{"query", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", "/v", "AppInit_DLLs"}, SkipChecks: true},
	}
	runCommands(ctx.Ctx, ctx.OutputDir, stdoutCommands, &result)

	// Run keys use a special handler that distinguishes empty keys from missing keys.
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
		state, content, err := queryRunKey(ctx.Ctx, k.key)
		if err != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("run key %s: %v", k.filename, err))
			continue
		}

		// Write the artifact with appropriate content based on state.
		if err := os.WriteFile(outPath, []byte(content), 0o644); err != nil {
			result.Errors = append(result.Errors,
				fmt.Sprintf("write %s: %v", k.filename, err))
			continue
		}

		// Hash and record the artifact regardless of state — the file is now
		// always meaningful (either has content, or explicitly states why not).
		artifact, err := describeArtifact(outPath)
		if err != nil {
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("hash %s: %v", k.filename, err))
			continue
		}
		result.Artifacts = append(result.Artifacts, artifact)

		// Note the state in warnings when it's not "present with values".
		switch state {
		case runKeyMissing:
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("%s: key does not exist on this target", k.filename))
		case runKeyEmpty:
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("%s: key exists but contains no values", k.filename))
		}
	}

	finalize(&result, started, ctx.Ctx)
	return result
}

// runKeyState describes what was found at a registry key location.
type runKeyState int

const (
	runKeyHasValues runKeyState = iota // key exists with one or more values
	runKeyEmpty                        // key exists but has no values
	runKeyMissing                      // key does not exist
)

// queryRunKey runs `reg query <key> /s` and interprets the result.
// Returns the state, the content to write to the artifact file, and any
// execution error (not registry errors — those become state values).
func queryRunKey(ctx context.Context, key string) (runKeyState, string, error) {
	cmd := exec.CommandContext(ctx, "reg", "query", key, "/s")
	out, err := cmd.CombinedOutput()
	output := string(out)

	// Build a header that's identical for all three states, so the artifact
	// is self-describing.
	header := fmt.Sprintf("Query: reg query %s /s\nTimestamp: %s\n\n",
		key, time.Now().UTC().Format(time.RFC3339))

	if err != nil {
		// reg query exits non-zero when the key doesn't exist.
		// Confirm by inspecting output for the well-known error.
		lower := strings.ToLower(output)
		if strings.Contains(lower, "unable to find") || strings.Contains(lower, "cannot find") {
			body := fmt.Sprintf("RESULT: KEY NOT FOUND\n\nThe specified registry key does not exist on this target.\nThis is normal for systems where this persistence mechanism has never been used.\n\nRaw output:\n%s",
				output)
			return runKeyMissing, header + body, nil
		}
		// Some other execution error — return it so it gets logged as an error.
		return runKeyHasValues, "", fmt.Errorf("reg query failed: %v (stderr: %s)", err, output)
	}

	// reg query succeeded. Determine if the key has values or is empty.
	trimmed := strings.TrimSpace(output)
	if trimmed == "" || isOnlyKeyHeader(trimmed) {
		body := fmt.Sprintf("RESULT: KEY EMPTY\n\nThe specified registry key exists but contains no values or subkeys.\nThis means the persistence location was checked and found unused at collection time.\n\nRaw output:\n%s",
			output)
		return runKeyEmpty, header + body, nil
	}

	body := fmt.Sprintf("RESULT: KEY HAS VALUES\n\n%s", output)
	return runKeyHasValues, header + body, nil
}

// isOnlyKeyHeader returns true if the output is just the key path with
// no actual values listed. `reg query` on an empty key sometimes outputs
// just "HKEY_LOCAL_MACHINE\Software\..." with nothing else.
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
