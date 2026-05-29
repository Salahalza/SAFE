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

// UserAssistParser reads collected NTUSER.DAT hives from the user_hives_collection
// module output and parses UserAssist entries for each user, producing per-user CSVs
// in the lab_report folder.
type UserAssistParser struct{}

func (p *UserAssistParser) Name() string { return "userassist" }

type userAssistEntry struct {
	GUID         string
	Category     string
	OriginalName string
	DecodedPath  string
	SessionID    uint32
	RunCount     uint32
	FocusCount   uint32
	FocusTimeMs  uint32
	LastRun      time.Time
	HasLastRun   bool
}

var guidCategoryNames = map[string]string{
	"{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}": "Executable",
	"{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}": "Shortcut",
	"{5E6AB780-7743-11CF-A12B-00AA004AE837}": "Toolbar/Taskbar Button (legacy)",
	"{75048700-EF1F-11D0-9888-006097DEACF9}": "ActiveDesktop (legacy)",
	"{9E04CAB2-CC14-11DF-BB8C-A2F1DED72085}": "Settings",
	"{B267E3AD-A825-4A09-82B9-EEC22AA3B847}": "Windows.System app",
	"{BCB48336-4DDD-48FF-BB0B-D3190DACB3E2}": "Recently used",
}

func (p *UserAssistParser) Parse(caseDir, labReportDir string) ([]string, []error) {
	// The hives we want are in modules/<NN>_user_hives_collection/<SID>/NTUSER.DAT.
	// We don't know the module number prefix in advance, so glob for it.
	hivesGlob := filepath.Join(caseDir, "modules", "*_user_hives_collection")
	matches, err := filepath.Glob(hivesGlob)
	if err != nil {
		return nil, []error{fmt.Errorf("glob hives dir: %w", err)}
	}
	if len(matches) == 0 {
		return nil, []error{fmt.Errorf("user_hives_collection module not found in case")}
	}

	hivesRoot := matches[0]

	// Each subdirectory is a per-user folder (named by SID).
	userDirs, err := os.ReadDir(hivesRoot)
	if err != nil {
		return nil, []error{fmt.Errorf("read hives root: %w", err)}
	}

	// Create our output subdirectory.
	outDir := filepath.Join(labReportDir, "userassist")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, []error{fmt.Errorf("create output dir: %w", err)}
	}

	var outputs []string
	var errs []error

	for _, ud := range userDirs {
		if !ud.IsDir() {
			continue
		}
		sid := ud.Name()
		ntuserPath := filepath.Join(hivesRoot, sid, "NTUSER.DAT")

		// Check that the hive exists.
		if _, err := os.Stat(ntuserPath); err != nil {
			// Missing hive is not an error — just skip this user.
			continue
		}

		entries, err := parseUserAssistFromHive(ntuserPath)
		if err != nil {
			// Per-user parse failures are recorded but don't abort the parser.
			errs = append(errs, fmt.Errorf("%s: %w", sid, err))
			continue
		}

		if len(entries) == 0 {
			continue
		}

		// Write per-user CSV.
		csvPath := filepath.Join(outDir, fmt.Sprintf("%s_userassist.csv", sid))
		if err := writeUserAssistCSV(csvPath, entries, sid); err != nil {
			errs = append(errs, fmt.Errorf("%s csv: %w", sid, err))
			continue
		}
		outputs = append(outputs, csvPath)
	}

	return outputs, errs
}

func parseUserAssistFromHive(ntuserPath string) ([]userAssistEntry, error) {
	f, err := os.Open(ntuserPath)
	if err != nil {
		return nil, fmt.Errorf("open hive: %w", err)
	}
	defer f.Close()

	reg, err := regparser.NewRegistry(f)
	if err != nil {
		return nil, fmt.Errorf("parse hive: %w", err)
	}

	const userAssistPath = `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`
	root := reg.OpenKey(userAssistPath)
	if root == nil {
		return nil, fmt.Errorf("UserAssist key not found")
	}

	var entries []userAssistEntry

	for _, guidKey := range root.Subkeys() {
		guidName := guidKey.Name()
		category, known := guidCategoryNames[guidName]
		if !known {
			category = "Unknown"
		}

		var countKey *regparser.CM_KEY_NODE
		for _, sub := range guidKey.Subkeys() {
			if strings.EqualFold(sub.Name(), "Count") {
				countKey = sub
				break
			}
		}
		if countKey == nil {
			continue
		}

		for _, val := range countKey.Values() {
			rawName := val.ValueName()
			decoded := rot13Decode(rawName)

			// Skip UEME_ internal counters.
			if strings.HasPrefix(decoded, "UEME_") {
				continue
			}

			entry := userAssistEntry{
				GUID:         guidName,
				Category:     category,
				OriginalName: rawName,
				DecodedPath:  decoded,
			}

			data := val.ValueData()
			if data != nil && data.Data != nil {
				parseUserAssistBinary(&entry, data.Data)
			}

			entries = append(entries, entry)
		}
	}

	return entries, nil
}

func parseUserAssistBinary(entry *userAssistEntry, data []byte) {
	if len(data) >= 4 {
		entry.SessionID = binary.LittleEndian.Uint32(data[0:4])
	}
	if len(data) >= 8 {
		entry.RunCount = binary.LittleEndian.Uint32(data[4:8])
	}
	if len(data) >= 12 {
		entry.FocusCount = binary.LittleEndian.Uint32(data[8:12])
	}
	if len(data) >= 16 {
		entry.FocusTimeMs = binary.LittleEndian.Uint32(data[12:16])
	}
	if len(data) >= 68 {
		ft := binary.LittleEndian.Uint64(data[60:68])
		if ft > 0 {
			entry.LastRun = filetimeToTime(ft)
			entry.HasLastRun = true
		}
	}
}

func rot13Decode(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			b[i] = 'a' + (c-'a'+13)%26
		case c >= 'A' && c <= 'Z':
			b[i] = 'A' + (c-'A'+13)%26
		}
	}
	return string(b)
}

func filetimeToTime(ft uint64) time.Time {
	const filetimeEpochToUnix = 11644473600
	seconds := int64(ft/10_000_000) - filetimeEpochToUnix
	nanos := int64((ft % 10_000_000) * 100)
	return time.Unix(seconds, nanos).UTC()
}

func writeUserAssistCSV(path string, entries []userAssistEntry, sid string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	if err := w.Write([]string{
		"sid", "category", "guid", "decoded_path", "original_value_name",
		"session_id", "run_count", "focus_count", "focus_time_ms", "last_run_utc",
	}); err != nil {
		return err
	}

	for _, e := range entries {
		lastRun := ""
		if e.HasLastRun {
			lastRun = e.LastRun.Format(time.RFC3339)
		}
		if err := w.Write([]string{
			sid, e.Category, e.GUID, e.DecodedPath, e.OriginalName,
			fmt.Sprintf("%d", e.SessionID),
			fmt.Sprintf("%d", e.RunCount),
			fmt.Sprintf("%d", e.FocusCount),
			fmt.Sprintf("%d", e.FocusTimeMs),
			lastRun,
		}); err != nil {
			return err
		}
	}

	w.Flush()
	return w.Error()
}
