package module

import (
	"path/filepath"
	"time"
)

// RegistryCore saves the core system registry hives using `reg save`.
// These hives are the foundation of most registry-based forensic analysis:
// system configuration, installed software, accounts, and security policy.
//
// Per-user hives (NTUSER.DAT, UsrClass.DAT) are handled separately because
// they require enumerating user profiles — different module, later.
type RegistryCore struct{}

func (m *RegistryCore) Name() string              { return "registry_core" }
func (m *RegistryCore) Priority() Priority        { return PriorityHigh }
func (m *RegistryCore) TimeBudget() time.Duration { return 5 * time.Minute }

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

	// reg save HKLM\<HIVE> <output_path> /y
	// /y forces overwrite if the file exists (shouldn't happen, but safe).
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
	runDirectOutputCommands(ctx.OutputDir, commands, &result)

	// Also save the SAM and SECURITY hives' .LOG files when present —
	// reg save sometimes splits the hive across multiple files.
	// Quick check: list what we ended up with.
	for _, h := range hives {
		path := filepath.Join(ctx.OutputDir, h.filename)
		if _, err := describeArtifact(path); err != nil {
			// Already recorded as error in runDirectOutputCommands.
			continue
		}
	}

	finalize(&result, started)
	return result
}
