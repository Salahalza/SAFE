package module

import (
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"sahm/internal/pathfinder"

	"www.velocidex.com/golang/regparser"
)

type UserAssistCollection struct{}

func (m *UserAssistCollection) Name() string              { return "userassist_collection" }
func (m *UserAssistCollection) Priority() Priority        { return PriorityHigh }
func (m *UserAssistCollection) TimeBudget() time.Duration { return 3 * time.Minute }
func (m *UserAssistCollection) RequiresVSS() bool         { return true }

// UserAssist entry as parsed from the registry value.
// The binary structure inside HKCU\Software\Microsoft\Windows\CurrentVersion\
// Explorer\UserAssist\<GUID>\Count\<rot13-path> is:
//
//	Bytes 0-3:   Session ID (uint32)
//	Bytes 4-7:   Run count (uint32)
//	Bytes 8-11:  Focus count (uint32)
//	Bytes 12-15: Focus time, in milliseconds (uint32)
//	Bytes 16-59: Reserved / unused
//	Bytes 60-67: Last run time, FILETIME (uint64, 100-ns intervals since 1601)
//	Bytes 68-71: Reserved
//
// Total: 72 bytes. Entries less than 72 bytes are typically Windows XP-era
// shorter format and we record what we can.
type userAssistEntry struct {
	GUID         string
	Category     string
	OriginalName string // raw value name (still ROT13-encoded)
	DecodedPath  string // ROT13-decoded path
	SessionID    uint32
	RunCount     uint32
	FocusCount   uint32
	FocusTimeMs  uint32
	LastRun      time.Time
	HasLastRun   bool // false when entry was too short to contain a timestamp
}

// guidCategoryNames maps known UserAssist GUID subkeys to human-readable
// category names. Unknown GUIDs are recorded by their raw GUID.
//
// Source: documented across multiple forensic references (Mandiant, SANS,
// EZ Tools). Updated as new GUIDs emerge in newer Windows versions.
var guidCategoryNames = map[string]string{
	"{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}": "Executable",
	"{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}": "Shortcut",
	"{5E6AB780-7743-11CF-A12B-00AA004AE837}": "Toolbar/Taskbar Button (legacy)",
	"{75048700-EF1F-11D0-9888-006097DEACF9}": "ActiveDesktop (legacy)",
	"{9E04CAB2-CC14-11DF-BB8C-A2F1DED72085}": "Settings",
	"{B267E3AD-A825-4A09-82B9-EEC22AA3B847}": "Windows.System app",
	"{BCB48336-4DDD-48FF-BB0B-D3190DACB3E2}": "Recently used",
}

func (m *UserAssistCollection) Run(ctx *Context) Result {
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

	if ctx.Shadow == nil {
		result.AddWarning("vss", "no shadow copy available; module should have been skipped by engine")
		result.Errors = append(result.Errors, "no shadow available")
		finalize(&result, started, ctx.Ctx)
		return result
	}

	profiles, err := pathfinder.DiscoverUserProfiles()
	if err != nil {
		result.AddWarning("user_discovery",
			fmt.Sprintf("could not enumerate user profiles: %v", err))
		result.Errors = append(result.Errors, fmt.Sprintf("discover profiles: %v", err))
		finalize(&result, started, ctx.Ctx)
		return result
	}

	humanCount := 0
	usersWithData := 0
	totalEntries := 0

	for _, p := range profiles {
		if p.IsBuiltin {
			continue
		}
		humanCount++

		// Build the shadow-mounted path to this user's NTUSER.DAT.
		shadowProfilePath, err := mapToShadowPath(p.ProfilePath, ctx.Shadow.MountedPath)
		if err != nil {
			result.AddWarning(p.SID,
				fmt.Sprintf("could not map profile path to shadow: %v", err))
			continue
		}
		ntuserPath := filepath.Join(shadowProfilePath, "NTUSER.DAT")

		// Per-user output directory (matches user_hives_collection pattern: SID-based).
		userDirName := p.SID
		userOutputDir := filepath.Join(ctx.OutputDir, userDirName)
		if err := os.MkdirAll(userOutputDir, 0o755); err != nil {
			result.AddWarning(p.SID,
				fmt.Sprintf("could not create per-user output dir: %v", err))
			continue
		}

		entries, err := parseUserAssist(ntuserPath)
		if err != nil {
			// Common case: NTUSER.DAT not present (rare profile state) or
			// UserAssist key missing (very new profile that hasn't accumulated data).
			// Both are info-level, not failures.
			result.AddInfo(p.SID,
				fmt.Sprintf("could not parse UserAssist from NTUSER.DAT: %v", err))
			continue
		}

		if len(entries) == 0 {
			result.AddInfo(p.SID, "UserAssist key present but contained no entries")
			continue
		}

		// Write entries as CSV.
		csvPath := filepath.Join(userOutputDir, "userassist.csv")
		if err := writeUserAssistCSV(csvPath, entries, p); err != nil {
			result.AddWarning(p.SID,
				fmt.Sprintf("could not write CSV: %v", err))
			result.Errors = append(result.Errors,
				fmt.Sprintf("%s csv write: %v", p.SID, err))
			continue
		}

		artifact, err := describeArtifact(csvPath)
		if err != nil {
			result.AddWarning(p.SID,
				fmt.Sprintf("could not hash CSV: %v", err))
			continue
		}
		artifact.SourcePath = filepath.Join(p.ProfilePath, "NTUSER.DAT")
		result.Artifacts = append(result.Artifacts, artifact)

		usersWithData++
		totalEntries += len(entries)
	}

	if humanCount == 0 {
		result.AddWarning("userassist_collection",
			"no human user profiles found on the system")
	} else {
		result.AddInfo("userassist_collection",
			fmt.Sprintf("processed %d human profile(s); %d had UserAssist data (%d total entries)",
				humanCount, usersWithData, totalEntries))
	}

	finalize(&result, started, ctx.Ctx)
	return result
}

// parseUserAssist opens an NTUSER.DAT hive and extracts all UserAssist entries.
// Returns an empty slice (not error) if the UserAssist key exists but has no
// entries; returns an error only on fundamental parsing failure.
func parseUserAssist(ntuserPath string) ([]userAssistEntry, error) {
	f, err := os.Open(ntuserPath)
	if err != nil {
		return nil, fmt.Errorf("open NTUSER.DAT: %w", err)
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

	// Each subkey under UserAssist is a GUID representing a category.
	for _, guidKey := range root.Subkeys() {
		guidName := guidKey.Name()
		category, known := guidCategoryNames[guidName]
		if !known {
			category = "Unknown"
		}

		// Inside each GUID is a "Count" subkey containing the actual entries.
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

			// Skip UEME_ counters — these are internal UserAssist metadata, not
			// program executions. The timestamp field contains session tracking
			// data that is not a meaningful last-run time.
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
			if data == nil || data.Data == nil {
				entries = append(entries, entry)
				continue
			}

			parseUserAssistBinary(&entry, data.Data)
			entries = append(entries, entry)
		}
	}

	return entries, nil
}

// parseUserAssistBinary extracts run count, focus count, focus time, and
// last-run timestamp from the value's binary data. Entries shorter than
// expected are partially populated as far as the data allows.
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
		filetime := binary.LittleEndian.Uint64(data[60:68])
		if filetime > 0 {
			entry.LastRun = filetimeToTime(filetime)
			entry.HasLastRun = true
		}
	}
}

// rot13Decode applies ROT13 to ASCII letters; passes through other characters
// unchanged. UserAssist value names are ROT13-encoded paths.
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

// filetimeToTime converts a Windows FILETIME (100-nanosecond intervals
// since January 1, 1601 UTC) to a Go time.Time.
func filetimeToTime(ft uint64) time.Time {
	// FILETIME epoch: 1601-01-01 UTC
	// Unix epoch:     1970-01-01 UTC
	// Difference:     11644473600 seconds
	const filetimeEpochToUnix = 11644473600
	seconds := int64(ft/10_000_000) - filetimeEpochToUnix
	nanos := int64((ft % 10_000_000) * 100)
	return time.Unix(seconds, nanos).UTC()
}

// writeUserAssistCSV writes parsed UserAssist entries to a CSV file with
// a header row. Times are ISO 8601 UTC; empty for entries without timestamps.
func writeUserAssistCSV(path string, entries []userAssistEntry, p pathfinder.UserProfile) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create csv: %w", err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	if err := w.Write([]string{
		"sid",
		"profile_path",
		"category",
		"guid",
		"decoded_path",
		"original_value_name",
		"session_id",
		"run_count",
		"focus_count",
		"focus_time_ms",
		"last_run_utc",
	}); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	for _, e := range entries {
		lastRun := ""
		if e.HasLastRun {
			lastRun = e.LastRun.Format(time.RFC3339)
		}
		row := []string{
			p.SID,
			p.ProfilePath,
			e.Category,
			e.GUID,
			e.DecodedPath,
			e.OriginalName,
			fmt.Sprintf("%d", e.SessionID),
			fmt.Sprintf("%d", e.RunCount),
			fmt.Sprintf("%d", e.FocusCount),
			fmt.Sprintf("%d", e.FocusTimeMs),
			lastRun,
		}
		if err := w.Write(row); err != nil {
			return fmt.Errorf("write row: %w", err)
		}
	}

	w.Flush()
	return w.Error()
}
