package module

import "time"

type ProcessSnapshot struct{}

func (m *ProcessSnapshot) Name() string              { return "process_snapshot" }
func (m *ProcessSnapshot) Priority() Priority        { return PriorityCritical }
func (m *ProcessSnapshot) TimeBudget() time.Duration { return 60 * time.Second }

func (m *ProcessSnapshot) Run(ctx *Context) Result {
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

	commands := []Command{
		{
			Filename: "tasklist_verbose.txt",
			Name:     "tasklist",
			Args:     []string{"/v", "/fo", "list"},
			Check:    &ContentCheck{MustContain: []string{"Image Name"}, MustNotContain: commonErrorSignatures},
		},
		{
			Filename: "tasklist_services.txt",
			Name:     "tasklist",
			Args:     []string{"/svc", "/fo", "list"},
			Check:    &ContentCheck{MustContain: []string{"Image Name"}, MustNotContain: commonErrorSignatures},
		},
		{
			Filename: "processes_powershell.txt",
			Name:     "powershell",
			Args: []string{
				"-NoProfile",
				"-Command",
				"Get-CimInstance Win32_Process | Select-Object Name,ProcessId,ParentProcessId,CommandLine,ExecutablePath,CreationDate | Format-List",
			},
			Check: &ContentCheck{MustContain: []string{"ProcessId"}, MustNotContain: commonErrorSignatures},
		},
		{
			Filename: "services_state.txt",
			Name:     "powershell",
			Args: []string{
				"-NoProfile",
				"-Command",
				"Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName,StartName | Format-List",
			},
			Check: &ContentCheck{MustContain: []string{"DisplayName"}, MustNotContain: commonErrorSignatures},
		},
	}
	runCommands(ctx.Ctx, ctx.OutputDir, commands, &result)

	finalize(&result, started, ctx.Ctx)
	return result
}
