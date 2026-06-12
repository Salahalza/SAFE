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

func (p *UserAssistParser) Parse(caseDir, labReportDir string, report ProgressFunc) ([]string, ParseStats, []error) {
	stats := ParseStats{}

	hivesGlob := filepath.Join(caseDir, "modules", "*_user_hives_collection")
	matches, err := filepath.Glob(hivesGlob)
	if err != nil {
		return nil, nil, []error{fmt.Errorf("glob hives dir: %w", err)}
	}
	if len(matches) == 0 {
		return nil, nil, []error{fmt.Errorf("user_hives_collection module not found in case")}
	}

	hivesRoot := matches[0]

	userDirs, err := os.ReadDir(hivesRoot)
	if err != nil {
		return nil, nil, []error{fmt.Errorf("read hives root: %w", err)}
	}

	outDir := filepath.Join(labReportDir, "userassist")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, nil, []error{fmt.Errorf("create output dir: %w", err)}
	}

	var outputs []string
	var errs []error

	usersProcessed := 0
	usersWithData := 0
	totalEntries := 0
	unknownGUIDs := map[string]bool{} // dedupe across users

	for i, ud := range userDirs {
		if report != nil {
			report(i, len(userDirs))
		}
		if !ud.IsDir() {
			continue
		}
		sid := ud.Name()
		ntuserPath := filepath.Join(hivesRoot, sid, "NTUSER.DAT")

		if _, err := os.Stat(ntuserPath); err != nil {
			continue
		}
		usersProcessed++

		entries, unknowns, err := parseUserAssistFromHive(ntuserPath)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", sid, err))
			continue
		}
		for guid := range unknowns {
			unknownGUIDs[guid] = true
		}

		if len(entries) == 0 {
			continue
		}

		csvPath := filepath.Join(outDir, fmt.Sprintf("%s_userassist.csv", sid))
		if err := writeUserAssistCSV(csvPath, entries, sid); err != nil {
			errs = append(errs, fmt.Errorf("%s csv: %w", sid, err))
			continue
		}
		outputs = append(outputs, csvPath)
		usersWithData++
		totalEntries += len(entries)
	}

	stats["users_processed"] = usersProcessed
	stats["users_with_data"] = usersWithData
	stats["total_entries"] = totalEntries
	stats["unknown_guids"] = len(unknownGUIDs)

	// Surface unknown GUIDs as errors so they appear in the analyzer output.
	// These aren't true errors — they're "new Microsoft GUIDs we should
	// add to the known list." Reporting them helps the project grow its
	// coverage over time.
	for guid := range unknownGUIDs {
		errs = append(errs, fmt.Errorf("unknown UserAssist category GUID %s — please report to update guidCategoryNames", guid))
	}

	return outputs, stats, errs
}

// parseUserAssistFromHive opens a NTUSER.DAT hive and extracts UserAssist
// entries. The second return value is the set of GUIDs encountered that
// are not in guidCategoryNames — surfaced so the project can add support
// for new Microsoft categories as they appear.
func parseUserAssistFromHive(ntuserPath string) ([]userAssistEntry, map[string]bool, error) {
	f, err := os.Open(ntuserPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open hive: %w", err)
	}
	defer f.Close()

	reg, err := regparser.NewRegistry(f)
	if err != nil {
		return nil, nil, fmt.Errorf("parse hive: %w", err)
	}

	const userAssistPath = `Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`
	root := reg.OpenKey(userAssistPath)
	if root == nil {
		return nil, nil, fmt.Errorf("UserAssist key not found")
	}

	var entries []userAssistEntry
	unknowns := map[string]bool{}

	for _, guidKey := range root.Subkeys() {
		guidName := guidKey.Name()
		category, known := guidCategoryNames[guidName]
		if !known {
			category = "Unknown"
			unknowns[guidName] = true
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

	return entries, unknowns, nil
}

// UserAssist binary entry layout. Documented across multiple forensic
// references (Mandiant, SANS, EZ Tools). The full entry structure is 72 bytes;
// shorter entries (typically 16 bytes for Windows XP-era data) are partially
// populated as the data allows.
const (
	userAssistSessionIDOffset  = 0
	userAssistRunCountOffset   = 4
	userAssistFocusCountOffset = 8
	userAssistFocusTimeOffset  = 12
	userAssistLastRunOffset    = 60
	userAssistFullEntrySize    = 68 // we need at least this many bytes to read FILETIME
)

func parseUserAssistBinary(entry *userAssistEntry, data []byte) {
	if len(data) >= userAssistRunCountOffset {
		entry.SessionID = binary.LittleEndian.Uint32(data[userAssistSessionIDOffset:userAssistRunCountOffset])
	}
	if len(data) >= userAssistFocusCountOffset {
		entry.RunCount = binary.LittleEndian.Uint32(data[userAssistRunCountOffset:userAssistFocusCountOffset])
	}
	if len(data) >= userAssistFocusTimeOffset {
		entry.FocusCount = binary.LittleEndian.Uint32(data[userAssistFocusCountOffset:userAssistFocusTimeOffset])
	}
	if len(data) >= 16 {
		entry.FocusTimeMs = binary.LittleEndian.Uint32(data[userAssistFocusTimeOffset:16])
	}
	if len(data) >= userAssistFullEntrySize {
		ft := binary.LittleEndian.Uint64(data[userAssistLastRunOffset:userAssistFullEntrySize])
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
			sid, e.Category, e.GUID, csvSafe(e.DecodedPath), csvSafe(e.OriginalName),
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
