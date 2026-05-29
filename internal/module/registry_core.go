package module

import "time"

type RegistryCore struct{}

func (m *RegistryCore) Name() string              { return "registry_core" }
func (m *RegistryCore) Priority() Priority        { return PriorityHigh }
func (m *RegistryCore) TimeBudget() time.Duration { return 5 * time.Minute }
func (m *RegistryCore) RequiresVSS() bool         { return false }

func (m *RegistryCore) Run(ctx *Context) Result {
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

	hives := []struct {
		filename string
		key      string
	}{
		{"HKLM_SYSTEM.hiv", "HKLM\\SYSTEM"},
		{"HKLM_SOFTWARE.hiv", "HKLM\\SOFTWARE"},
		{"HKLM_SAM.hiv", "HKLM\\SAM"},
		{"HKLM_SECURITY.hiv", "HKLM\\SECURITY"},
	}

	commands := make([]DirectCommand, 0, len(hives))
	for _, h := range hives {
		commands = append(commands, DirectCommand{
			Filename: h.filename,
			Name:     "reg",
			Args:     []string{"save", h.key, "{OUTPUT}", "/y"},
		})
	}
	runDirectOutputCommands(ctx.Ctx, ctx.OutputDir, commands, &result)

	finalize(&result, started, ctx.Ctx)
	return result
}
