package module

import "time"

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
			Filename: "wmi_event_consumers.txt",
			Name:     "powershell",
			Args: []string{
				"-NoProfile",
				"-Command",
				"Get-CimInstance -Namespace root\\subscription -ClassName __EventConsumer | Format-List *",
			},
		},
		{
			Filename: "wmi_event_filters.txt",
			Name:     "powershell",
			Args: []string{
				"-NoProfile",
				"-Command",
				"Get-CimInstance -Namespace root\\subscription -ClassName __EventFilter | Format-List *",
			},
		},
		{
			Filename: "wmi_filter_to_consumer_bindings.txt",
			Name:     "powershell",
			Args: []string{
				"-NoProfile",
				"-Command",
				"Get-CimInstance -Namespace root\\subscription -ClassName __FilterToConsumerBinding | Format-List *",
			},
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
		},
		{Filename: "winlogon_keys.txt", Name: "reg", Args: []string{"query", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"}},
		{Filename: "image_file_execution_options.txt", Name: "reg", Args: []string{"query", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", "/s"}},
		{Filename: "appinit_dlls.txt", Name: "reg", Args: []string{"query", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", "/v", "AppInit_DLLs"}},
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
		filename := k.filename
		captured := Result{
			Artifacts: []Artifact{},
			Errors:    []string{},
			Warnings:  []string{},
		}
		runCommands(ctx.Ctx, ctx.OutputDir, []Command{{
			Filename: filename,
			Name:     "reg",
			Args:     []string{"query", k.key, "/s"},
		}}, &captured)

		result.Artifacts = append(result.Artifacts, captured.Artifacts...)
		for _, e := range captured.Errors {
			result.Warnings = append(result.Warnings,
				"run key absent or unreadable: "+e)
		}
	}

	finalize(&result, started, ctx.Ctx)
	return result
}
