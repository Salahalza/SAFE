package module

import "time"

type EventLogsCore struct{}

func (m *EventLogsCore) Name() string              { return "eventlogs_core" }
func (m *EventLogsCore) Priority() Priority        { return PriorityHigh }
func (m *EventLogsCore) TimeBudget() time.Duration { return 10 * time.Minute }
func (m *EventLogsCore) RequiresVSS() bool         { return false }

func (m *EventLogsCore) Run(ctx *Context) Result {
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

	coreChannels := []string{
		"Security",
		"System",
		"Application",
		"Microsoft-Windows-PowerShell/Operational",
		"Microsoft-Windows-TaskScheduler/Operational",
		"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
		"Microsoft-Windows-WinRM/Operational",
		"Microsoft-Windows-Windows Defender/Operational",
	}

	optionalChannels := []string{
		"Microsoft-Windows-Sysmon/Operational",
	}

	var coreCommands []DirectCommand
	for _, channel := range coreChannels {
		coreCommands = append(coreCommands, DirectCommand{
			Filename: channelToFilename(channel),
			Name:     "wevtutil",
			Args:     []string{"epl", channel, "{OUTPUT}"},
		})
	}
	runDirectOutputCommands(ctx.Ctx, ctx.OutputDir, coreCommands, &result)

	for _, channel := range optionalChannels {
		filename := channelToFilename(channel)
		optResult := Result{
			Artifacts: []Artifact{},
			Errors:    []string{},
			Findings:  []Finding{},
		}
		runDirectOutputCommands(ctx.Ctx, ctx.OutputDir, []DirectCommand{{
			Filename: filename,
			Name:     "wevtutil",
			Args:     []string{"epl", channel, "{OUTPUT}"},
		}}, &optResult)

		result.Artifacts = append(result.Artifacts, optResult.Artifacts...)

		// Optional channels — failures are informational, not warnings.
		if len(optResult.Errors) > 0 {
			result.AddInfo(filename,
				"optional channel not present on this target — this is normal unless the corresponding tool is installed")
		}
	}

	finalize(&result, started, ctx.Ctx)
	return result
}

func channelToFilename(channel string) string {
	out := make([]byte, 0, len(channel)+5)
	for i := 0; i < len(channel); i++ {
		c := channel[i]
		if c == '/' || c == '\\' || c == ':' {
			out = append(out, '_')
		} else {
			out = append(out, c)
		}
	}
	return string(out) + ".evtx"
}
