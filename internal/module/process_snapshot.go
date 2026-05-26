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
		Warnings:   []string{},
		Errors:     []string{},
	}

	if !prepareOutputDir(&result, ctx.OutputDir, started) {
		return result
	}

	commands := []Command{
		{Filename: "tasklist_verbose.txt", Name: "tasklist", Args: []string{"/v", "/fo", "list"}},
		{Filename: "tasklist_services.txt", Name: "tasklist", Args: []string{"/svc", "/fo", "list"}},
		{
			Filename: "processes_powershell.txt",
			Name:     "powershell",
			Args: []string{
				"-NoProfile",
				"-Command",
				"Get-CimInstance Win32_Process | Select-Object Name,ProcessId,ParentProcessId,CommandLine,ExecutablePath,CreationDate | Format-List",
			},
		},
		{
			Filename: "services_state.txt",
			Name:     "powershell",
			Args: []string{
				"-NoProfile",
				"-Command",
				"Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName,StartName | Format-List",
			},
		},
	}
	runCommands(ctx.Ctx, ctx.OutputDir, commands, &result)

	finalize(&result, started, ctx.Ctx)
	return result
}
