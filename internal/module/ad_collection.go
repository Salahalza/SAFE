package module

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Salahalza/SAFE/internal/roles"
)

// ADCollection collects Active Directory artifacts, specifically NTDS.dit
// and the SYSTEM registry hive needed to decrypt it offline.
type ADCollection struct{}

func (m *ADCollection) Name() string              { return "ad_collection" }
func (m *ADCollection) Priority() Priority        { return PriorityHigh }
func (m *ADCollection) TimeBudget() time.Duration { return 15 * time.Minute }
func (m *ADCollection) RequiresVSS() bool         { return true }

// Applies reports whether this target is a Domain Controller. NTDS.dit and
// SYSVOL only exist on a DC, so on any other host (a member server, an IIS or
// SQL box, a workstation) this module cleanly no-ops instead of failing to find
// ntds.dit and emitting criticals. This lets a single server profile run
// safely against a server of unknown role.
func (m *ADCollection) Applies(ctx *Context) (bool, string) {
	if !ctx.Live {
		if roles.IsDomainControllerImage(ctx.Root) {
			return true, ""
		}
		return false, "image is not a Domain Controller (NTDS service absent in SYSTEM hive)"
	}
	if roles.IsDomainController() {
		return true, ""
	}
	return false, "target is not a Domain Controller (NTDS registry key absent)"
}

func (m *ADCollection) Run(ctx *Context) Result {
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

	if ctx.Root == "" {
		result.AddWarning("root", "no evidence root available; module requires an evidence root")
		result.Errors = append(result.Errors, "no evidence root available")
		finalize(&result, started, ctx.Ctx)
		return result
	}

	totalBytes := int64(0)
	ctx.ReportProgress(0, 3, totalBytes) // Approximate steps: SYSTEM, NTDS, SYSVOL

	// 1. SYSTEM Hive
	sysSrc := filepath.Join(ctx.Root, "Windows", "System32", "config", "SYSTEM")
	sysDst := filepath.Join(ctx.OutputDir, "SYSTEM")
	sysInfo, err := os.Stat(sysSrc)
	if err != nil {
		result.AddWarning("SYSTEM", fmt.Sprintf("stat failed: %v", err))
		result.Errors = append(result.Errors, fmt.Sprintf("SYSTEM stat: %v", err))
		result.AddCritical(m.Name(), "Failed to locate SYSTEM hive")
	} else if err := copyEvidenceFile(ctx, sysSrc, sysDst); err != nil {
		result.AddWarning("SYSTEM", fmt.Sprintf("copy failed: %v", err))
		result.Errors = append(result.Errors, fmt.Sprintf("SYSTEM copy: %v", err))
		result.AddCritical(m.Name(), "Failed to collect SYSTEM hive")
	} else {
		if artifact, err := describeArtifact(sysDst); err == nil {
			result.Artifacts = append(result.Artifacts, artifact)
			totalBytes += sysInfo.Size()
		}
	}
	ctx.ReportProgress(1, 3, totalBytes)

	// 2. NTDS Directory
	ntdsFound := false
	ntdsSrcDir := filepath.Join(ctx.Root, "Windows", "NTDS")
	ntdsDstDir := filepath.Join(ctx.OutputDir, "NTDS")

	if err := os.MkdirAll(ntdsDstDir, 0o755); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("NTDS mkdir: %v", err))
	} else {
		entries, err := os.ReadDir(ntdsSrcDir)
		if err != nil {
			result.AddWarning("NTDS", fmt.Sprintf("readdir failed: %v", err))
			result.Errors = append(result.Errors, fmt.Sprintf("NTDS readdir: %v", err))
			result.AddCritical(m.Name(), "Active Directory database (NTDS) directory could not be read")
		} else {
			for _, entry := range entries {
				// NTDS.dit can be tens of GB against a 15-minute budget; honor
				// cancellation so the module can unwind instead of copying to
				// completion regardless of the deadline.
				if ctx.Ctx.Err() != nil {
					result.AddWarning(m.Name(), fmt.Sprintf("NTDS collection cancelled: %v", ctx.Ctx.Err()))
					break
				}
				if entry.IsDir() {
					continue
				}
				name := entry.Name()
				srcPath := filepath.Join(ntdsSrcDir, name)
				dstPath := filepath.Join(ntdsDstDir, name)

				info, err := os.Stat(srcPath)
				if err != nil {
					continue
				}

				if err := copyEvidenceFile(ctx, srcPath, dstPath); err != nil {
					result.AddWarning(name, fmt.Sprintf("copy failed: %v", err))
					continue
				}

				if name == "ntds.dit" {
					ntdsFound = true
				}

				if artifact, err := describeArtifact(dstPath); err == nil {
					result.Artifacts = append(result.Artifacts, artifact)
					totalBytes += info.Size()
				}
			}
		}
	}

	if !ntdsFound {
		result.AddCritical(m.Name(), "Active Directory database (ntds.dit) could not be found or copied")
	}
	ctx.ReportProgress(2, 3, totalBytes)

	// 3. SYSVOL (Bulk Collection)
	sysvolSrcDir := filepath.Join(ctx.Root, "Windows", "SYSVOL", "domain")
	sysvolDstDir := filepath.Join(ctx.OutputDir, "SYSVOL")

	count, bytes, errs := copyDir(ctx, sysvolSrcDir, sysvolDstDir)
	if len(errs) > 0 {
		result.AddWarning("SYSVOL", fmt.Sprintf("encountered %d errors during SYSVOL collection, first: %v", len(errs), errs[0]))
		for _, e := range errs {
			result.Errors = append(result.Errors, fmt.Sprintf("SYSVOL: %v", e))
		}
	}

	if count > 0 {
		result.BulkFiles += count
		totalBytes += bytes
		result.AddInfo("SYSVOL", fmt.Sprintf("collected %d file(s) from SYSVOL (%d bytes)", count, bytes))
	} else {
		result.AddInfo("SYSVOL", "SYSVOL directory was empty or not found")
	}

	ctx.ReportProgress(3, 3, totalBytes)

	if len(result.Artifacts) == 0 {
		result.AddInfo(m.Name(), "failed to collect core AD artifacts")
	} else {
		result.AddInfo(m.Name(), fmt.Sprintf("collected %d core AD artifact(s) and %d SYSVOL file(s)", len(result.Artifacts), count))
	}

	finalize(&result, started, ctx.Ctx)
	return result
}
