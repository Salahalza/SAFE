package analyzer

import (
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"www.velocidex.com/golang/regparser"
)

// BamDamParser parses BAM and DAM execution entries from HKLM_SYSTEM.hiv registry hive.
type BamDamParser struct{}

func (p *BamDamParser) Name() string { return "bam_dam" }

type bamDamEntry struct {
	ControlSet string
	Source     string // BAM or DAM
	SID        string
	UserType   string
	RawPath    string
	NormPath   string
	LastExec   string
	Tier       string
	Flags      string
}

var bamLolbins = []string{
	"powershell.exe", "pwsh.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
	"wscript.exe", "cscript.exe", "cmd.exe", "certutil.exe", "bitsadmin.exe",
	"msbuild.exe", "installutil.exe", "wmic.exe", "schtasks.exe", "curl.exe", "msiexec.exe",
}


// Parse walks through HKLM_SYSTEM.hiv, extracts Background Activity Moderator and
// Desktop Activity Moderator execution metadata, applies threat classification, and writes to CSV.
func (p *BamDamParser) Parse(caseDir, labReportDir string, report ProgressFunc) ([]string, ParseStats, []error) {
	stats := ParseStats{}
	var errs []error

	registryGlob := filepath.Join(caseDir, "modules", "*_registry_core")
	matches, err := filepath.Glob(registryGlob)
	if err != nil {
		return nil, stats, []error{fmt.Errorf("glob registry core: %w", err)}
	}
	if len(matches) == 0 {
		return nil, stats, nil
	}
	registryRoot := matches[0]

	systemHivePath := filepath.Join(registryRoot, "HKLM_SYSTEM.hiv")
	if _, err := os.Stat(systemHivePath); err != nil {
		return nil, stats, nil
	}

	f, err := os.Open(systemHivePath)
	if err != nil {
		return nil, stats, []error{fmt.Errorf("open HKLM_SYSTEM.hiv: %w", err)}
	}
	defer f.Close()

	reg, err := regparser.NewRegistry(f)
	if err != nil {
		return nil, stats, []error{fmt.Errorf("new registry: %w", err)}
	}

	outDir := filepath.Join(labReportDir, "bam_dam")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, stats, []error{fmt.Errorf("create output dir: %w", err)}
	}

	controlSets := []string{"ControlSet001", "ControlSet002"}
	var entries []bamDamEntry

	totalSteps := len(controlSets) * 4 // 2 control sets * 4 paths each
	step := 0
	advance := func() {
		step++
		if report != nil {
			report(step, totalSteps)
		}
	}

	for _, cs := range controlSets {
		// Enumerate BAM and DAM paths
		subPaths := []struct {
			source string
			path   string
		}{
			{"BAM", fmt.Sprintf(`%s\Control\Session Manager\AppCompatCache\BAM\UserSettings`, cs)}, // Alternative or legacy paths
			{"BAM", fmt.Sprintf(`%s\Services\Bam\State\UserSettings`, cs)},
			{"BAM", fmt.Sprintf(`%s\Services\Bam\UserSettings`, cs)},
			{"DAM", fmt.Sprintf(`%s\Services\Dam\State\UserSettings`, cs)},
		}

		for _, sp := range subPaths {
			advance()
			k := reg.OpenKey(sp.path)
			if k == nil {
				continue
			}

			for _, subkey := range k.Subkeys() {
				sid := subkey.Name()
				userType := resolveSIDType(sid)

				for _, val := range subkey.Values() {
					name := val.ValueName()
					lowerName := strings.ToLower(name)
					if lowerName == "version" || lowerName == "sequencenumber" {
						continue
					}

					vData := val.ValueData()
					if vData.Type != 3 || len(vData.Data) < 8 { // REG_BINARY, min 8 bytes
						continue
					}

					ft := binary.LittleEndian.Uint64(vData.Data[0:8])
					if ft == 0 {
						continue
					}

					lastExecStr := filetimeToTime(ft).Format(time.RFC3339)

					normPath := normalizeDevicePath(name)
					tier, flags := triageBamDam(normPath, sid)

					entries = append(entries, bamDamEntry{
						ControlSet: cs,
						Source:     sp.source,
						SID:        sid,
						UserType:   userType,
						RawPath:    name,
						NormPath:   normPath,
						LastExec:   lastExecStr,
						Tier:       tier,
						Flags:      flags,
					})
				}
			}
		}
	}

	stats["entries_total"] = len(entries)
	if len(entries) == 0 {
		return nil, stats, errs
	}

	csvPath := filepath.Join(outDir, "bam_dam.csv")
	csvFile, err := os.Create(csvPath)
	if err != nil {
		return nil, stats, append(errs, fmt.Errorf("create bam_dam.csv: %w", err))
	}
	defer csvFile.Close()

	w := csv.NewWriter(csvFile)
	defer w.Flush()

	header := []string{
		"tier", "control_set", "source", "sid", "user_type",
		"normalized_path", "raw_path", "last_execution_utc", "flags",
	}
	if err := w.Write(header); err != nil {
		return nil, stats, append(errs, fmt.Errorf("write csv header: %w", err))
	}

	high := 0
	notable := 0
	low := 0

	for _, e := range entries {
		switch e.Tier {
		case "HIGH":
			high++
		case "NOTABLE":
			notable++
		default:
			low++
		}

		if err := w.Write([]string{
			e.Tier,
			e.ControlSet,
			e.Source,
			e.SID,
			e.UserType,
			csvSafe(e.NormPath),
			csvSafe(e.RawPath),
			e.LastExec,
			e.Flags,
		}); err != nil {
			errs = append(errs, fmt.Errorf("write csv row: %w", err))
		}
	}

	stats["entries_high"] = high
	stats["entries_notable"] = notable
	stats["entries_low"] = low

	return []string{csvPath}, stats, errs
}

// filetimeToUTC is removed; use the package-level filetimeToTime helper (helpers.go).

func resolveSIDType(sid string) string {
	switch sid {
	case "S-1-5-18":
		return "SYSTEM"
	case "S-1-5-19":
		return "LOCAL SERVICE"
	case "S-1-5-20":
		return "NETWORK SERVICE"
	}
	// Well-known relative identifiers (last component of domain SID).
	switch {
	case strings.HasSuffix(sid, "-500"):
		return "Administrator"
	case strings.HasSuffix(sid, "-501"):
		return "Guest"
	case strings.HasSuffix(sid, "-502"):
		return "KRBTGT"
	case strings.HasSuffix(sid, "-503"):
		return "DefaultAccount"
	case strings.HasSuffix(sid, "-504"):
		return "WDAGUtilityAccount"
	}
	return "User Account"
}

func normalizeDevicePath(p string) string {
	lower := strings.ToLower(p)
	const devicePrefix = `\device\harddiskvolume`
	if strings.HasPrefix(lower, devicePrefix) {
		// Extract the volume number and the remainder of the path.
		// We preserve the volume number rather than hard-coding C: because the
		// system drive may be on a different volume on multi-drive systems.
		rem := p[len(devicePrefix):]
		idx := strings.Index(rem, `\`)
		if idx >= 0 {
			volNum := rem[:idx] // e.g. "3"
			rest := rem[idx:]   // e.g. "\Windows\..."
			return `\Device\HarddiskVolume` + volNum + rest
		}
	}
	return p
}

func triageBamDam(path string, sid string) (string, string) {
	var flags []string
	tier := "LOW"

	norm := strings.ToLower(path)
	hasSuspiciousPath := false
	for _, hint := range suspiciousExecPaths {
		if strings.Contains(norm, hint) {
			hasSuspiciousPath = true
			flags = append(flags, "runs from suspicious path: "+hint)
			break
		}
	}

	hasLolbin := false
	base := strings.ToLower(filepath.Base(path))
	for _, lol := range bamLolbins {
		if strings.Contains(base, lol) {
			hasLolbin = true
			flags = append(flags, "LOLBin: "+lol)
			break
		}
	}

	if hasSuspiciousPath {
		tier = "HIGH"
	} else if hasLolbin {
		tier = "NOTABLE"
	}

	if len(flags) == 0 {
		return "LOW", "standard execution"
	}
	return tier, strings.Join(flags, "; ")
}
