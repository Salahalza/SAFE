package module

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type RegistryCore struct{}

func (m *RegistryCore) Name() string              { return "registry_core" }
func (m *RegistryCore) Priority() Priority        { return PriorityHigh }
func (m *RegistryCore) TimeBudget() time.Duration { return 5 * time.Minute }
func (m *RegistryCore) RequiresVSS() bool         { return false }

// hklmHive names an HKLM registry hive and the file it produces. The output
// filename is the contract the lab-side registry analyzers glob for
// (modules/*_registry_core/HKLM_SOFTWARE.hiv, etc.), so it must be identical for
// both the live and disk-image collection paths.
type hklmHive struct {
	filename string // output name the analyzers expect
	key      string // live registry key for `reg save`
	config   string // on-disk hive filename under Windows\System32\config
}

var hklmHives = []hklmHive{
	{"HKLM_SYSTEM.hiv", "HKLM\\SYSTEM", "SYSTEM"},
	{"HKLM_SOFTWARE.hiv", "HKLM\\SOFTWARE", "SOFTWARE"},
	{"HKLM_SAM.hiv", "HKLM\\SAM", "SAM"},
	{"HKLM_SECURITY.hiv", "HKLM\\SECURITY", "SECURITY"},
}

func (m *RegistryCore) Run(ctx *Context) Result {
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

	// Dead-image mode: the live registry is the analyst's own host, not the
	// imaged one, so `reg save` would collect the wrong machine. Instead copy the
	// HKLM hive FILES straight out of the image at Windows\System32\config. They
	// are unlocked in a static image, so no VSS/`reg save` is needed. Produces the
	// same HKLM_*.hiv filenames the analyzers expect.
	if !ctx.Live {
		m.collectFromImage(ctx, &result)
		finalize(&result, started, ctx.Ctx)
		return result
	}

	commands := make([]DirectCommand, 0, len(hklmHives))
	for _, h := range hklmHives {
		commands = append(commands, DirectCommand{
			Filename: h.filename,
			Name:     "reg",
			Args:     []string{"save", h.key, "{OUTPUT}", "/y"},
		})
	}
	runDirectOutputCommands(ctx, commands, &result)

	finalize(&result, started, ctx.Ctx)
	return result
}

// collectFromImage copies the four HKLM hive files from a mounted image's
// config directory into the module output, naming them exactly as the live path
// would so the downstream analyzers are source-agnostic. Transaction logs are
// not replayed here; the base hive is what the analyzers parse.
func (m *RegistryCore) collectFromImage(ctx *Context, result *Result) {
	if ctx.Root == "" {
		result.AddWarning("root", "no evidence root available; module should have been skipped by engine")
		result.Errors = append(result.Errors, "no evidence root available")
		return
	}
	configDir := filepath.Join(ctx.Root, "Windows", "System32", "config")
	for i, h := range hklmHives {
		ctx.ReportProgress(i, len(hklmHives), 0)
		src := filepath.Join(configDir, h.config)
		dst := filepath.Join(ctx.OutputDir, h.filename)

		info, err := os.Stat(src)
		if err != nil {
			result.AddWarning(h.config, fmt.Sprintf("hive not found in image: %v", err))
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", h.config, err))
			continue
		}
		if err := copyEvidenceFile(ctx, src, dst); err != nil {
			result.AddWarning(h.config, fmt.Sprintf("copy failed: %v", err))
			result.Errors = append(result.Errors, fmt.Sprintf("%s copy: %v", h.config, err))
			continue
		}
		artifact, err := describeArtifact(dst)
		if err != nil {
			result.AddWarning(h.config, fmt.Sprintf("hash failed: %v", err))
			result.Errors = append(result.Errors, fmt.Sprintf("%s hash: %v", h.config, err))
			continue
		}
		artifact.SourcePath = filepath.Join(`C:\`, "Windows", "System32", "config", h.config)
		artifact.SourceSize = info.Size()
		result.Artifacts = append(result.Artifacts, artifact)
	}
	ctx.ReportProgress(len(hklmHives), len(hklmHives), 0)
	if len(result.Artifacts) == 0 {
		result.AddWarning(m.Name(), "no HKLM hives collected from image — verify the mounted volume is the OS volume")
	} else {
		result.AddInfo(m.Name(), fmt.Sprintf("collected %d HKLM hive file(s) from image", len(result.Artifacts)))
	}
}
