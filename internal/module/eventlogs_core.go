package module

import "time"

// EventLogsCore exports the core Windows event log channels.
// Outputs are .evtx files, copied via wevtutil epl.
//
// Per the spec: full channel export, no time filter — retro hunting requires
// access to all retained events, not just recent ones.
type EventLogsCore struct{}

func (m *EventLogsCore) Name() string              { return "eventlogs_core" }
func (m *EventLogsCore) Priority() Priority        { return PriorityHigh }
func (m *EventLogsCore) TimeBudget() time.Duration { return 10 * time.Minute }

func (m *EventLogsCore) Run(ctx *Context) Result {
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

	// Core channels — present on every supported Windows version.
	// Optional channels (Sysmon, etc.) handled separately so missing
	// channels degrade gracefully rather than failing.
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

	// Build commands for required channels.
	var coreCommands []DirectCommand
	for _, channel := range coreChannels {
		coreCommands = append(coreCommands, DirectCommand{
			Filename: channelToFilename(channel),
			Name:     "wevtutil",
			Args:     []string{"epl", channel, "{OUTPUT}"},
		})
	}
	runDirectOutputCommands(ctx.OutputDir, coreCommands, &result)

	// Optional channels: run them, but downgrade errors to warnings
	// since their absence is expected on some machines.
	for _, channel := range optionalChannels {
		filename := channelToFilename(channel)
		optResult := Result{
			Artifacts: []Artifact{},
			Errors:    []string{},
			Warnings:  []string{},
		}
		runDirectOutputCommands(ctx.OutputDir, []DirectCommand{{
			Filename: filename,
			Name:     "wevtutil",
			Args:     []string{"epl", channel, "{OUTPUT}"},
		}}, &optResult)

		// Promote successful artifacts; demote errors to warnings.
		result.Artifacts = append(result.Artifacts, optResult.Artifacts...)
		for _, e := range optResult.Errors {
			result.Warnings = append(result.Warnings,
				"optional channel skipped: "+e)
		}
	}

	finalize(&result, started)
	return result
}

// channelToFilename converts a channel name like
// "Microsoft-Windows-PowerShell/Operational" into a safe filename
// like "Microsoft-Windows-PowerShell_Operational.evtx".
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
