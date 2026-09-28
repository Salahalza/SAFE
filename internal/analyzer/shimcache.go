package analyzer

import (
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"www.velocidex.com/golang/regparser"
)

// ShimCacheParser parses ShimCache entries from HKLM_SYSTEM.hiv registry hive.
type ShimCacheParser struct{}

func (p *ShimCacheParser) Name() string { return "shimcache" }

type shimcacheEntry struct {
	ControlSet string
	EntryIndex int
	Path       string
	LastModUTC string
	Execution  uint32
}

func (p *ShimCacheParser) Parse(caseDir, labReportDir string, report ProgressFunc) ([]string, ParseStats, []error) {
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
		// Hive doesn't exist, skip
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

	outDir := filepath.Join(labReportDir, "shimcache")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, stats, []error{fmt.Errorf("create output dir: %w", err)}
	}

	// We look under ControlSet001 and ControlSet002
	controlSets := []string{"ControlSet001", "ControlSet002"}
	var entries []shimcacheEntry

	for _, cs := range controlSets {
		// Key fallback paths
		keyPaths := []string{
			fmt.Sprintf(`%s\Control\Session Manager\AppCompatCache`, cs),
			fmt.Sprintf(`%s\Control\Session Manager\AppCompatibility\AppCompatCache`, cs),
		}

		var k *regparser.CM_KEY_NODE
		for _, kp := range keyPaths {
			k = reg.OpenKey(kp)
			if k != nil {
				break
			}
		}

		if k == nil {
			continue
		}

		var val *regparser.CM_KEY_VALUE
		for _, v := range k.Values() {
			if v.ValueName() == "AppCompatCache" {
				val = v
				break
			}
		}
		if val == nil {
			continue
		}

		data := val.ValueData().Data
		if len(data) < 12 {
			continue
		}

		offsetToRecords := binary.LittleEndian.Uint32(data[0:4])
		index := int(offsetToRecords)
		entryIndex := 0

		for index+12 <= len(data) {
			signature := string(data[index : index+4])
			if signature != "10ts" {
				break
			}

			size := binary.LittleEndian.Uint32(data[index+8 : index+12])
			if size == 0 {
				break
			}

			nextIndex := index + 12 + int(size)
			if nextIndex > len(data) {
				break
			}

			entryData := data[index+12 : nextIndex]
			if len(entryData) < 2 {
				break
			}

			pathSize := binary.LittleEndian.Uint16(entryData[0:2])
			if 2+int(pathSize) > len(entryData) {
				break
			}

			pathBytes := entryData[2 : 2+pathSize]
			pathRunes := make([]rune, pathSize/2)
			for i := 0; i < len(pathBytes); i += 2 {
				pathRunes[i/2] = rune(binary.LittleEndian.Uint16(pathBytes[i : i+2]))
			}
			pathStr := string(pathRunes)

			lastModOffset := 2 + int(pathSize)
			var lastModTime time.Time
			if lastModOffset+8 <= len(entryData) {
				ftVal := binary.LittleEndian.Uint64(entryData[lastModOffset : lastModOffset+8])
				if ftVal > 0 {
					lastModTime = filetimeToTime(ftVal)
				}
			}

			dataSizeOffset := lastModOffset + 8
			var dataSize uint32
			if dataSizeOffset+4 <= len(entryData) {
				dataSize = binary.LittleEndian.Uint32(entryData[dataSizeOffset : dataSizeOffset+4])
			}

			executionFlag := uint32(0)
			if dataSize > 0 {
				executionOffset := dataSizeOffset + 4
				if executionOffset+int(dataSize) <= len(entryData) {
					if dataSize >= 4 {
						execFlagOffset := executionOffset + int(dataSize) - 4
						executionFlag = binary.LittleEndian.Uint32(entryData[execFlagOffset : execFlagOffset+4])
					}
				}
			}

			lastModStr := ""
			if !lastModTime.IsZero() {
				lastModStr = lastModTime.UTC().Format(time.RFC3339)
			}

			entries = append(entries, shimcacheEntry{
				ControlSet: cs,
				EntryIndex: entryIndex,
				Path:       pathStr,
				LastModUTC: lastModStr,
				Execution:  executionFlag,
			})

			entryIndex++
			index = nextIndex
		}
	}

	if report != nil {
		report(1, 1)
	}

	if len(entries) == 0 {
		stats["total_entries"] = 0
		return nil, stats, nil
	}

	csvPath := filepath.Join(outDir, "shimcache.csv")
	if err := writeShimcacheCSV(csvPath, entries); err != nil {
		return nil, stats, append(errs, fmt.Errorf("write shimcache.csv: %w", err))
	}

	stats["total_entries"] = len(entries)
	return []string{csvPath}, stats, nil
}

func writeShimcacheCSV(path string, entries []shimcacheEntry) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	header := []string{
		"control_set", "entry_index", "path", "last_modified_utc", "execution_flag",
	}
	if err := w.Write(header); err != nil {
		return err
	}

	for _, e := range entries {
		if err := w.Write([]string{
			e.ControlSet,
			fmt.Sprintf("%d", e.EntryIndex),
			csvSafe(e.Path),
			e.LastModUTC,
			fmt.Sprintf("%d", e.Execution),
		}); err != nil {
			return err
		}
	}
	w.Flush()
	return w.Error()
}
