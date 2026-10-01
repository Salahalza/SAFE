package timeline

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Salahalza/SAFE/internal/csvutil"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// Event represents a Plaso-compatible supertimeline event.
type Event struct {
	Date       string // YYYY-MM-DD
	Time       string // HH:MM:SS.000000
	Timezone   string // UTC
	MACB       string // 4-character flag (e.g., "M...", ".A..", "..C.", "...B")
	Source     string // Registry, Prefetch, File, Browser, EventLog, etc.
	SourceType string // UserAssist, Prefetch, BAM/DAM, ShimCache, ShellBags, etc.
	Type       string // Description of event type (e.g., "Last Run", "File Modified")
	User       string // User SID or Username
	Host       string // Target Hostname
	Short      string // Short summary of the event
	Desc       string // Verbose description details
	Version    string // Plaso schema version (always "2")
	Filename   string // Source artifact file or registry key
	Inode      string // Empty
	Notes      string // Additional context
	Format     string // always "safe"
	Extra      string // Key-value pairs (key1=val1;key2=val2)
}

// Generate aggregates all parsed CSV files in the lab report folder into timeline.csv.
func Generate(labReportDir string) (string, error) {
	var events []Event

	// 1. Process UserAssist
	uaMatches, _ := filepath.Glob(filepath.Join(labReportDir, "userassist", "*_userassist.csv"))
	for _, path := range uaMatches {
		if err := processUserAssist(path, &events); err != nil {
			// Log error but proceed
			fmt.Fprintf(os.Stderr, "timeline: failed to parse UserAssist CSV %s: %v\n", path, err)
		}
	}

	// 2. Process Prefetch
	pfPath := filepath.Join(labReportDir, "prefetch", "prefetch.csv")
	if _, err := os.Stat(pfPath); err == nil {
		if err := processPrefetch(pfPath, &events); err != nil {
			fmt.Fprintf(os.Stderr, "timeline: failed to parse Prefetch CSV: %v\n", err)
		}
	}

	// 3. Process BAM/DAM
	bdPath := filepath.Join(labReportDir, "bam_dam", "bam_dam.csv")
	if _, err := os.Stat(bdPath); err == nil {
		if err := processBamDam(bdPath, &events); err != nil {
			fmt.Fprintf(os.Stderr, "timeline: failed to parse BAM/DAM CSV: %v\n", err)
		}
	}

	// 4. Process ShimCache
	scPath := filepath.Join(labReportDir, "shimcache", "shimcache.csv")
	if _, err := os.Stat(scPath); err == nil {
		if err := processShimCache(scPath, &events); err != nil {
			fmt.Fprintf(os.Stderr, "timeline: failed to parse ShimCache CSV: %v\n", err)
		}
	}

	// 5. Process ShellBags
	sbPath := filepath.Join(labReportDir, "shellbags", "shellbags.csv")
	if _, err := os.Stat(sbPath); err == nil {
		if err := processShellBags(sbPath, &events); err != nil {
			fmt.Fprintf(os.Stderr, "timeline: failed to parse ShellBags CSV: %v\n", err)
		}
	}

	// 6. Process JumpLists
	jlPath := filepath.Join(labReportDir, "jump_lists", "jumplists.csv")
	if _, err := os.Stat(jlPath); err == nil {
		if err := processJumpLists(jlPath, &events); err != nil {
			fmt.Fprintf(os.Stderr, "timeline: failed to parse JumpLists CSV: %v\n", err)
		}
	}

	// 7. Process Browser History
	bhPath := filepath.Join(labReportDir, "browser", "history.csv")
	if _, err := os.Stat(bhPath); err == nil {
		if err := processBrowserHistory(bhPath, &events); err != nil {
			fmt.Fprintf(os.Stderr, "timeline: failed to parse Browser History CSV: %v\n", err)
		}
	}

	// 8. Process Browser Downloads
	bdlPath := filepath.Join(labReportDir, "browser", "downloads.csv")
	if _, err := os.Stat(bdlPath); err == nil {
		if err := processBrowserDownloads(bdlPath, &events); err != nil {
			fmt.Fprintf(os.Stderr, "timeline: failed to parse Browser Downloads CSV: %v\n", err)
		}
	}

	// 9. Process EVTX logs
	evtxMatches, _ := filepath.Glob(filepath.Join(labReportDir, "evtx", "*.csv"))
	for _, path := range evtxMatches {
		if err := processEvtx(path, &events); err != nil {
			fmt.Fprintf(os.Stderr, "timeline: failed to parse EVTX CSV %s: %v\n", path, err)
		}
	}

	// 10. Process Amcache (file entries only — programs lack precise timestamps)
	acPath := filepath.Join(labReportDir, "amcache", "amcache_files.csv")
	if _, err := os.Stat(acPath); err == nil {
		if err := processAmcache(acPath, &events); err != nil {
			fmt.Fprintf(os.Stderr, "timeline: failed to parse Amcache CSV: %v\n", err)
		}
	}

	// 11. Process Scheduled Tasks (HIGH and NOTABLE tier only)
	stPath := filepath.Join(labReportDir, "scheduled_tasks", "tasks.csv")
	if _, err := os.Stat(stPath); err == nil {
		if err := processScheduledTasks(stPath, &events); err != nil {
			fmt.Fprintf(os.Stderr, "timeline: failed to parse ScheduledTasks CSV: %v\n", err)
		}
	}

	// 12. Process MFT (extracted high-value NTFS entries)
	mftPath := filepath.Join(labReportDir, "mft_timeline.csv")
	if _, err := os.Stat(mftPath); err == nil {
		if err := processMft(mftPath, &events); err != nil {
			fmt.Fprintf(os.Stderr, "timeline: failed to parse mft CSV: %v\n", err)
		}
	}

	// 13. Process USN Journal
	usnPath := filepath.Join(labReportDir, "usn.csv")
	if _, err := os.Stat(usnPath); err == nil {
		if err := processUsn(usnPath, &events); err != nil {
			fmt.Fprintf(os.Stderr, "timeline: failed to parse usn CSV: %v\n", err)
		}
	}

	// 14. Process IIS web-shell access. IIS request logs are far too voluminous
	// to fold into the supertimeline wholesale, so only requests that reached a
	// script flagged as a web shell (from web_files.csv) are injected — placing
	// the actual shell interaction at its real timestamp instead of relying on
	// the futuristic behavioral ALERT rows.
	iisReqPath := filepath.Join(labReportDir, "iis", "iis_requests.csv")
	iisWebPath := filepath.Join(labReportDir, "iis", "web_files.csv")
	if _, err := os.Stat(iisReqPath); err == nil {
		if err := processIISShellAccess(iisReqPath, iisWebPath, &events); err != nil {
			fmt.Fprintf(os.Stderr, "timeline: failed to parse IIS requests CSV: %v\n", err)
		}
	}

	// Ensure no events have empty date/time to prevent UI sorting bugs
	for i := range events {
		if events[i].Date == "" {
			events[i].Date = "1970-01-01"
		}
		if events[i].Time == "" {
			events[i].Time = "00:00:00.000000"
		}
	}

	// Sort events chronologically (date, then time)
	sort.Slice(events, func(i, j int) bool {
		if events[i].Date != events[j].Date {
			return events[i].Date < events[j].Date
		}
		return events[i].Time < events[j].Time
	})

	// Output file path
	outPath := filepath.Join(labReportDir, "timeline.csv")
	f, err := os.Create(outPath)
	if err != nil {
		return "", fmt.Errorf("create timeline.csv: %w", err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	// Write header row
	header := []string{
		"datetime", "timezone", "MACB", "source", "sourcetype",
		"type", "user", "host", "short", "desc", "version",
		"filename", "inode", "notes", "format", "extra",
	}
	if err := w.Write(header); err != nil {
		return "", fmt.Errorf("write header: %w", err)
	}

	for _, e := range events {
		row := []string{
			e.Date + " " + e.Time, e.Timezone, e.MACB, e.Source, e.SourceType,
			e.Type, e.User, e.Host, csvSafe(e.Short), csvSafe(e.Desc), e.Version,
			e.Filename, e.Inode, e.Notes, e.Format, e.Extra,
		}
		if err := w.Write(row); err != nil {
			return "", fmt.Errorf("write event row: %w", err)
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return "", fmt.Errorf("csv flush: %w", err)
	}

	return outPath, nil
}

// csvSafe neutralizes spreadsheet formula injection in a CSV field. It delegates
// to the single shared implementation so the analyzer, timeline, and behavior
// packages all quote identically.
func csvSafe(s string) string {
	return csvutil.CsvSafe(s)
}

// parseTimestamp converts various UTC timestamp formats into Date and Time components.
func parseTimestamp(s string) (string, string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "1970-01-01", "00:00:00.000000", false
	}
	// Try RFC3339 layout (e.g. 2026-06-19T21:30:12Z)
	t, err := time.Parse(time.RFC3339, s)
	if err == nil {
		return t.Format("2006-01-02"), t.Format("15:04:05.000000"), true
	}
	// Try RFC3339Nano
	t, err = time.Parse(time.RFC3339Nano, s)
	if err == nil {
		return t.Format("2006-01-02"), t.Format("15:04:05.000000"), true
	}
	// Try standard SQL/General format (e.g. 2026-06-19 21:30:12)
	t, err = time.Parse("2006-01-02 15:04:05", s)
	if err == nil {
		return t.Format("2006-01-02"), t.Format("15:04:05.000000"), true
	}
	return "1970-01-01", "00:00:00.000000", false
}

// safeIndex safely retrieves an element from a string slice.
func safeIndex(row []string, idx int) string {
	if idx >= 0 && idx < len(row) {
		return row[idx]
	}
	return ""
}

// Stream opens the timeline.csv file, parses it row by row, and sends Event
// objects to the provided channel. The channel is closed when reading completes
// or an error occurs.
func Stream(path string, ch chan<- Event) error {
	defer close(ch)

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1 // Allow flexibility

	header, err := r.Read()
	if err != nil {
		return err
	}

	dateIdx := csvutil.GetColIndex(header, "datetime")
	tzIdx := csvutil.GetColIndex(header, "timezone")
	macbIdx := csvutil.GetColIndex(header, "MACB")
	srcIdx := csvutil.GetColIndex(header, "source")
	srcTypeIdx := csvutil.GetColIndex(header, "sourcetype")
	typeIdx := csvutil.GetColIndex(header, "type")
	userIdx := csvutil.GetColIndex(header, "user")
	hostIdx := csvutil.GetColIndex(header, "host")
	shortIdx := csvutil.GetColIndex(header, "short")
	descIdx := csvutil.GetColIndex(header, "desc")
	verIdx := csvutil.GetColIndex(header, "version")
	fileIdx := csvutil.GetColIndex(header, "filename")
	inodeIdx := csvutil.GetColIndex(header, "inode")
	notesIdx := csvutil.GetColIndex(header, "notes")
	fmtIdx := csvutil.GetColIndex(header, "format")
	extraIdx := csvutil.GetColIndex(header, "extra")

	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// "datetime" contains "YYYY-MM-DD HH:MM:SS.000000"
		dt := safeIndex(row, dateIdx)
		parts := strings.SplitN(dt, " ", 2)
		d := ""
		t := ""
		if len(parts) == 2 {
			d = parts[0]
			t = parts[1]
		} else if len(parts) == 1 {
			d = parts[0]
		}

		ch <- Event{
			Date:       d,
			Time:       t,
			Timezone:   safeIndex(row, tzIdx),
			MACB:       safeIndex(row, macbIdx),
			Source:     safeIndex(row, srcIdx),
			SourceType: safeIndex(row, srcTypeIdx),
			Type:       safeIndex(row, typeIdx),
			User:       safeIndex(row, userIdx),
			Host:       safeIndex(row, hostIdx),
			Short:      safeIndex(row, shortIdx),
			Desc:       safeIndex(row, descIdx),
			Version:    safeIndex(row, verIdx),
			Filename:   safeIndex(row, fileIdx),
			Inode:      safeIndex(row, inodeIdx),
			Notes:      safeIndex(row, notesIdx),
			Format:     safeIndex(row, fmtIdx),
			Extra:      safeIndex(row, extraIdx),
		}
	}

	return nil
}

// 1. UserAssist CSV Adapter
func processUserAssist(path string, events *[]Event) error {
	return csvutil.ReadCSVHelper(path, func(header []string, row []string) error {
		tsIdx := csvutil.GetColIndex(header, "last_run_utc")
		pathIdx := csvutil.GetColIndex(header, "decoded_path")
		sidIdx := csvutil.GetColIndex(header, "sid")
		rcIdx := csvutil.GetColIndex(header, "run_count")
		ftIdx := csvutil.GetColIndex(header, "focus_time_ms")

		if tsIdx == -1 || pathIdx == -1 {
			return nil
		}

		tsStr := row[tsIdx]
		date, timePart, ok := parseTimestamp(tsStr)
		if !ok {
			return nil
		}

		sid := ""
		if sidIdx != -1 {
			sid = row[sidIdx]
		}
		runPath := row[pathIdx]

		runCount := ""
		if rcIdx != -1 {
			runCount = row[rcIdx]
		}
		focusTime := ""
		if ftIdx != -1 {
			focusTime = row[ftIdx]
		}

		*events = append(*events, Event{
			Date:       date,
			Time:       timePart,
			Timezone:   "UTC",
			MACB:       "..C.",
			Source:     "Registry",
			SourceType: "UserAssist",
			Type:       "Last Run",
			User:       sid,
			Short:      fmt.Sprintf("Run: %s", filepath.Base(runPath)),
			Desc:       fmt.Sprintf("UserAssist run of %s (RunCount: %s, FocusTime: %sms)", runPath, runCount, focusTime),
			Version:    "2",
			Filename:   "NTUSER.DAT",
			Format:     "safe",
			Extra:      fmt.Sprintf("run_count=%s;focus_time_ms=%s", runCount, focusTime),
		})
		return nil
	})
}

// 2. Prefetch CSV Adapter
func processPrefetch(path string, events *[]Event) error {
	return csvutil.ReadCSVHelper(path, func(header []string, row []string) error {
		tsIdx := csvutil.GetColIndex(header, "run_time_utc")
		pathIdx := csvutil.GetColIndex(header, "path")
		exeIdx := csvutil.GetColIndex(header, "executable")
		rcIdx := csvutil.GetColIndex(header, "run_count")
		pfIdx := csvutil.GetColIndex(header, "prefetch_filename")
		baselineIdx := csvutil.GetColIndex(header, "is_baseline")

		if tsIdx == -1 || exeIdx == -1 {
			return nil
		}

		tsStr := row[tsIdx]
		date, timePart, ok := parseTimestamp(tsStr)
		if !ok {
			return nil
		}

		exeName := row[exeIdx]
		runPath := ""
		if pathIdx != -1 {
			runPath = row[pathIdx]
		}
		runCount := ""
		if rcIdx != -1 {
			runCount = row[rcIdx]
		}
		pfName := ""
		if pfIdx != -1 {
			pfName = row[pfIdx]
		}
		isBaseline := ""
		if baselineIdx != -1 {
			isBaseline = row[baselineIdx]
		}

		*events = append(*events, Event{
			Date:       date,
			Time:       timePart,
			Timezone:   "UTC",
			MACB:       "M...", // Fix #3: Prefetch last-run maps to Modified time
			Source:     "Prefetch",
			SourceType: "Prefetch",
			Type:       "Last Run",
			Short:      fmt.Sprintf("Run: %s", exeName),
			Desc:       fmt.Sprintf("Prefetch run of %s from %s (RunCount: %s, PrefetchFile: %s)", exeName, runPath, runCount, pfName),
			Version:    "2",
			Filename:   pfName,
			Format:     "safe",
			Extra:      fmt.Sprintf("run_count=%s;is_baseline=%s", runCount, isBaseline),
		})
		return nil
	})
}

// 3. BAM/DAM CSV Adapter
func processBamDam(path string, events *[]Event) error {
	return csvutil.ReadCSVHelper(path, func(header []string, row []string) error {
		tsIdx := csvutil.GetColIndex(header, "last_execution_utc")
		pathIdx := csvutil.GetColIndex(header, "normalized_path")
		sidIdx := csvutil.GetColIndex(header, "sid")
		sourceIdx := csvutil.GetColIndex(header, "source")

		if tsIdx == -1 || pathIdx == -1 {
			return nil
		}

		tsStr := row[tsIdx]
		date, timePart, ok := parseTimestamp(tsStr)
		if !ok {
			return nil
		}

		sid := ""
		if sidIdx != -1 {
			sid = row[sidIdx]
		}
		runPath := row[pathIdx]
		source := "BAM/DAM"
		if sourceIdx != -1 {
			source = row[sourceIdx]
		}

		*events = append(*events, Event{
			Date:       date,
			Time:       timePart,
			Timezone:   "UTC",
			MACB:       "M...", // Fix #3: BAM/DAM stores last-execution in a registry value's data → Modified
			Source:     "Registry",
			SourceType: source,
			Type:       "Last Run",
			User:       sid,
			Short:      fmt.Sprintf("Run: %s", filepath.Base(runPath)),
			Desc:       fmt.Sprintf("BAM/DAM execution trace of %s", runPath),
			Version:    "2",
			Filename:   "SYSTEM",
			Format:     "safe",
		})
		return nil
	})
}

// 4. ShimCache CSV Adapter
func processShimCache(path string, events *[]Event) error {
	return csvutil.ReadCSVHelper(path, func(header []string, row []string) error {
		tsIdx := csvutil.GetColIndex(header, "last_modified_utc")
		pathIdx := csvutil.GetColIndex(header, "path")
		execIdx := csvutil.GetColIndex(header, "execution_flag")

		if tsIdx == -1 || pathIdx == -1 {
			return nil
		}

		tsStr := row[tsIdx]
		date, timePart, ok := parseTimestamp(tsStr)
		if !ok {
			return nil
		}

		runPath := row[pathIdx]
		execFlag := ""
		if execIdx != -1 {
			execFlag = row[execIdx]
		}

		*events = append(*events, Event{
			Date:       date,
			Time:       timePart,
			Timezone:   "UTC",
			MACB:       "M...",
			Source:     "Registry",
			SourceType: "ShimCache",
			Type:       "Last Modified",
			Short:      fmt.Sprintf("ShimCache: %s", filepath.Base(runPath)),
			Desc:       fmt.Sprintf("ShimCache entry for %s (ExecutionFlag: %s)", runPath, execFlag),
			Version:    "2",
			Filename:   "SYSTEM",
			Format:     "safe",
			Extra:      fmt.Sprintf("execution_flag=%s", execFlag),
		})
		return nil
	})
}

// 5. ShellBags CSV Adapter
func processShellBags(path string, events *[]Event) error {
	return csvutil.ReadCSVHelper(path, func(header []string, row []string) error {
		tsIdx := csvutil.GetColIndex(header, "last_write_utc")
		folderIdx := csvutil.GetColIndex(header, "folder_path")
		sidIdx := csvutil.GetColIndex(header, "sid")
		mruIdx := csvutil.GetColIndex(header, "mru_path")
		hiveIdx := csvutil.GetColIndex(header, "source_hive")

		if tsIdx == -1 || folderIdx == -1 {
			return nil
		}

		tsStr := row[tsIdx]
		date, timePart, ok := parseTimestamp(tsStr)
		if !ok {
			return nil
		}

		sid := ""
		if sidIdx != -1 {
			sid = row[sidIdx]
		}
		folderPath := row[folderIdx]
		mruPath := ""
		if mruIdx != -1 {
			mruPath = row[mruIdx]
		}
		hiveName := "UsrClass.dat"
		if hiveIdx != -1 {
			hiveName = row[hiveIdx]
		}

		*events = append(*events, Event{
			Date:       date,
			Time:       timePart,
			Timezone:   "UTC",
			MACB:       "M...", // Fix #3: ShellBag timestamp is the registry key last-write → Modified
			Source:     "Registry",
			SourceType: "ShellBags",
			Type:       "Folder Accessed",
			User:       sid,
			Short:      fmt.Sprintf("Access Folder: %s", filepath.Base(folderPath)),
			Desc:       fmt.Sprintf("User browsed folder %s (MRU: %s)", folderPath, mruPath),
			Version:    "2",
			Filename:   hiveName,
			Format:     "safe",
		})
		return nil
	})
}

// 6. JumpLists CSV Adapter
func processJumpLists(path string, events *[]Event) error {
	return csvutil.ReadCSVHelper(path, func(header []string, row []string) error {
		sidIdx := csvutil.GetColIndex(header, "sid")
		pathIdx := csvutil.GetColIndex(header, "path")
		argsIdx := csvutil.GetColIndex(header, "arguments")
		typeIdx := csvutil.GetColIndex(header, "type")
		appIdx := csvutil.GetColIndex(header, "app_id")

		lastAccessIdx := csvutil.GetColIndex(header, "last_accessed_utc")
		lnkCreatedIdx := csvutil.GetColIndex(header, "lnk_created_utc")
		lnkModifiedIdx := csvutil.GetColIndex(header, "lnk_modified_utc")
		lnkAccessedIdx := csvutil.GetColIndex(header, "lnk_accessed_utc")

		if pathIdx == -1 {
			return nil
		}

		targetPath := row[pathIdx]
		sid := ""
		if sidIdx != -1 {
			sid = row[sidIdx]
		}
		args := ""
		if argsIdx != -1 {
			args = row[argsIdx]
		}
		jlType := ""
		if typeIdx != -1 {
			jlType = row[typeIdx]
		}
		appID := ""
		if appIdx != -1 {
			appID = row[appIdx]
		}

		fullCmd := targetPath
		if args != "" {
			fullCmd += " " + args
		}

		// Helper to add jump list event
		addEvent := func(tsStr, macb, evType string) {
			date, timePart, ok := parseTimestamp(tsStr)
			if !ok {
				return
			}
			*events = append(*events, Event{
				Date:       date,
				Time:       timePart,
				Timezone:   "UTC",
				MACB:       macb,
				Source:     "File",
				SourceType: "JumpList",
				Type:       evType,
				User:       sid,
				Short:      fmt.Sprintf("JumpList: %s", filepath.Base(targetPath)),
				Desc:       fmt.Sprintf("JumpList entry (%s) appID %s targets: %s", jlType, appID, fullCmd),
				Version:    "2",
				Filename:   jlType + " DestList",
				Format:     "safe",
				Extra:      fmt.Sprintf("app_id=%s;type=%s", jlType, appID),
			})
		}

		if lastAccessIdx != -1 {
			addEvent(row[lastAccessIdx], "..C.", "Last Accessed")
		}
		if lnkCreatedIdx != -1 {
			addEvent(row[lnkCreatedIdx], "...B", "Link Created")
		}
		if lnkModifiedIdx != -1 {
			addEvent(row[lnkModifiedIdx], "M...", "Link Modified")
		}
		if lnkAccessedIdx != -1 {
			addEvent(row[lnkAccessedIdx], ".A..", "Link Accessed")
		}

		return nil
	})
}

// 7. Browser History CSV Adapter
func processBrowserHistory(path string, events *[]Event) error {
	return csvutil.ReadCSVHelper(path, func(header []string, row []string) error {
		tsIdx := csvutil.GetColIndex(header, "last_visit_utc")
		urlIdx := csvutil.GetColIndex(header, "url")
		titleIdx := csvutil.GetColIndex(header, "title")
		sidIdx := csvutil.GetColIndex(header, "sid")
		browserIdx := csvutil.GetColIndex(header, "browser")
		profileIdx := csvutil.GetColIndex(header, "profile")
		vcIdx := csvutil.GetColIndex(header, "visit_count")

		if tsIdx == -1 || urlIdx == -1 {
			return nil
		}

		tsStr := row[tsIdx]
		date, timePart, ok := parseTimestamp(tsStr)
		if !ok {
			return nil
		}

		urlVal := row[urlIdx]
		title := ""
		if titleIdx != -1 {
			title = row[titleIdx]
		}
		sid := ""
		if sidIdx != -1 {
			sid = row[sidIdx]
		}
		browser := ""
		if browserIdx != -1 {
			browser = row[browserIdx]
		}
		profile := ""
		if profileIdx != -1 {
			profile = row[profileIdx]
		}
		visitCount := ""
		if vcIdx != -1 {
			visitCount = row[vcIdx]
		}

		*events = append(*events, Event{
			Date:       date,
			Time:       timePart,
			Timezone:   "UTC",
			MACB:       "..C.",
			Source:     "Browser",
			SourceType: browser + " History",
			Type:       "Visit",
			User:       sid,
			Short:      fmt.Sprintf("Visited: %s", title),
			Desc:       fmt.Sprintf("User visited URL %s (Browser: %s, Profile: %s, VisitCount: %s)", urlVal, browser, profile, visitCount),
			Version:    "2",
			Filename:   browser + " History DB",
			Format:     "safe",
			Extra:      fmt.Sprintf("browser=%s;profile=%s;visit_count=%s", browser, profile, visitCount),
		})
		return nil
	})
}

// 8. Browser Downloads CSV Adapter
func processBrowserDownloads(path string, events *[]Event) error {
	return csvutil.ReadCSVHelper(path, func(header []string, row []string) error {
		tsIdx := csvutil.GetColIndex(header, "start_time_utc")
		destIdx := csvutil.GetColIndex(header, "target_path")
		urlIdx := csvutil.GetColIndex(header, "url")
		sidIdx := csvutil.GetColIndex(header, "sid")
		browserIdx := csvutil.GetColIndex(header, "browser")
		profileIdx := csvutil.GetColIndex(header, "profile")
		bytesIdx := csvutil.GetColIndex(header, "total_bytes")

		if tsIdx == -1 || destIdx == -1 {
			return nil
		}

		tsStr := row[tsIdx]
		date, timePart, ok := parseTimestamp(tsStr)
		if !ok {
			return nil
		}

		destPath := row[destIdx]
		urlVal := ""
		if urlIdx != -1 {
			urlVal = row[urlIdx]
		}
		sid := ""
		if sidIdx != -1 {
			sid = row[sidIdx]
		}
		browser := ""
		if browserIdx != -1 {
			browser = row[browserIdx]
		}
		profile := ""
		if profileIdx != -1 {
			profile = row[profileIdx]
		}
		totalBytes := ""
		if bytesIdx != -1 {
			totalBytes = row[bytesIdx]
		}

		*events = append(*events, Event{
			Date:       date,
			Time:       timePart,
			Timezone:   "UTC",
			MACB:       "...B",
			Source:     "Browser",
			SourceType: browser + " Downloads",
			Type:       "Downloaded",
			User:       sid,
			Short:      fmt.Sprintf("Download: %s", filepath.Base(destPath)),
			Desc:       fmt.Sprintf("Downloaded %s from %s (Browser: %s, Profile: %s, Size: %s bytes)", destPath, urlVal, browser, profile, totalBytes),
			Version:    "2",
			Filename:   browser + " History DB",
			Format:     "safe",
			Extra:      fmt.Sprintf("browser=%s;profile=%s;total_bytes=%s", browser, profile, totalBytes),
		})
		return nil
	})
}

// shortChannelName converts a full Windows event log channel path to a concise
// label that EZ Timeline Explorer can recognise and colour correctly.
// e.g. "Microsoft-Windows-PowerShell/Operational" → "PowerShell/Operational"
func shortChannelName(channel string) string {
	// Strip well-known long prefixes so EZ sees clean category names.
	prefixes := []string{
		"Microsoft-Windows-",
		"Microsoft-",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(channel, p) {
			return channel[len(p):]
		}
	}
	return channel
}

// extractEventDataField parses a JSON-encoded EventData string and returns the
// value of the requested field, or "" if missing / not parseable.
func extractEventDataField(eventData, field string) string {
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(eventData), &m); err != nil {
		return ""
	}
	if v, ok := m[field]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// 9. EVTX EventLog CSV Adapter
func processEvtx(path string, events *[]Event) error {
	return csvutil.ReadCSVHelper(path, func(header []string, row []string) error {
		tsIdx := csvutil.GetColIndex(header, "time_created_utc")
		idIdx := csvutil.GetColIndex(header, "event_id")
		provIdx := csvutil.GetColIndex(header, "provider")
		channelIdx := csvutil.GetColIndex(header, "channel")
		computerIdx := csvutil.GetColIndex(header, "computer")
		dataIdx := csvutil.GetColIndex(header, "event_data")

		if tsIdx == -1 || idIdx == -1 || dataIdx == -1 {
			return nil
		}

		tsStr := row[tsIdx]
		date, timePart, ok := parseTimestamp(tsStr)
		if !ok {
			return nil
		}

		eventID := row[idIdx]
		provider := ""
		if provIdx != -1 {
			provider = row[provIdx]
		}
		channel := ""
		if channelIdx != -1 {
			channel = row[channelIdx]
		}
		computer := ""
		if computerIdx != -1 {
			computer = row[computerIdx]
		}
		eventData := row[dataIdx]

		// Fix #4: populate user field from EventData JSON.
		// Prefer TargetUserName (the account being acted upon); fall back to
		// SubjectUserName (the actor). Skip machine accounts (ending in '$')
		// and placeholder values ('-', 'SYSTEM').
		userVal := ""
		for _, field := range []string{"TargetUserName", "SubjectUserName"} {
			v := extractEventDataField(eventData, field)
			if v != "" && v != "-" && v != "SYSTEM" && !strings.HasSuffix(v, "$") {
				userVal = v
				break
			}
		}

		// Fix #5: shorten channel name so EZ Timeline Explorer can colour it.
		sourceType := shortChannelName(channel)

		*events = append(*events, Event{
			Date:       date,
			Time:       timePart,
			Timezone:   "UTC",
			MACB:       "..C.",
			Source:     "EventLog",
			SourceType: sourceType,
			Type:       fmt.Sprintf("EventID: %s", eventID),
			User:       userVal,
			Host:       computer,
			Short:      fmt.Sprintf("Evtx: ID %s (%s)", eventID, provider),
			Desc:       fmt.Sprintf("Provider: %s, EventData: %s", provider, eventData),
			Version:    "2",
			Filename:   filepath.Base(path),
			Format:     "safe",
			Extra:      fmt.Sprintf("event_id=%s;provider=%s", eventID, provider),
		})
		return nil
	})
}

// 10. Amcache Files CSV Adapter
// Uses last_write_utc (the timestamp the Amcache key was last updated, which
// strongly correlates with when the binary was first seen on the system).
func processAmcache(path string, events *[]Event) error {
	return csvutil.ReadCSVHelper(path, func(header []string, row []string) error {
		tsIdx := csvutil.GetColIndex(header, "last_write_utc")
		pathIdx := csvutil.GetColIndex(header, "path")
		nameIdx := csvutil.GetColIndex(header, "name")
		sha1Idx := csvutil.GetColIndex(header, "file_id") // Amcache stores SHA-1 in file_id (without leading zeros)
		pubIdx := csvutil.GetColIndex(header, "publisher")
		verIdx := csvutil.GetColIndex(header, "version")
		osIdx := csvutil.GetColIndex(header, "is_os_component")

		if tsIdx == -1 || pathIdx == -1 {
			return nil
		}

		tsStr := row[tsIdx]
		date, timePart, ok := parseTimestamp(tsStr)
		if !ok {
			return nil
		}

		filePath := row[pathIdx]
		name := filepath.Base(filePath)
		if nameIdx != -1 && row[nameIdx] != "" {
			name = row[nameIdx]
		}
		publisher := ""
		if pubIdx != -1 {
			publisher = row[pubIdx]
		}
		version := ""
		if verIdx != -1 {
			version = row[verIdx]
		}
		sha1 := ""
		if sha1Idx != -1 {
			sha1 = strings.TrimLeft(row[sha1Idx], "0") // Amcache file_id has leading zeros stripped
		}
		isOS := ""
		if osIdx != -1 {
			isOS = row[osIdx]
		}

		descParts := []string{fmt.Sprintf("Amcache first-seen entry for %s", filePath)}
		if publisher != "" {
			descParts = append(descParts, fmt.Sprintf("Publisher: %s", publisher))
		}
		if version != "" {
			descParts = append(descParts, fmt.Sprintf("Version: %s", version))
		}
		if sha1 != "" {
			descParts = append(descParts, fmt.Sprintf("SHA1: %s", sha1))
		}

		*events = append(*events, Event{
			Date:       date,
			Time:       timePart,
			Timezone:   "UTC",
			MACB:       "..C.", // Amcache key write = Change (first seen, not execution)
			Source:     "Registry",
			SourceType: "Amcache",
			Type:       "First Seen",
			Short:      fmt.Sprintf("Amcache: %s", name),
			Desc:       strings.Join(descParts, ", "),
			Version:    "2",
			Filename:   "Amcache.hve",
			Format:     "safe",
			Extra:      fmt.Sprintf("is_os_component=%s;sha1=%s", isOS, sha1),
		})
		return nil
	})
}

// 11. Scheduled Tasks CSV Adapter
// Only HIGH and NOTABLE tier tasks are included — LOW tier is baseline noise.
func processScheduledTasks(path string, events *[]Event) error {
	return csvutil.ReadCSVHelper(path, func(header []string, row []string) error {
		tierIdx := csvutil.GetColIndex(header, "tier")
		nameIdx := csvutil.GetColIndex(header, "task_name")
		cmdIdx := csvutil.GetColIndex(header, "command")
		argsIdx := csvutil.GetColIndex(header, "arguments")
		userIdx := csvutil.GetColIndex(header, "user_id")
		enabledIdx := csvutil.GetColIndex(header, "enabled")
		descIdx := csvutil.GetColIndex(header, "description")
		flagsIdx := csvutil.GetColIndex(header, "flags")

		if tierIdx == -1 || nameIdx == -1 {
			return nil
		}

		tier := strings.ToUpper(row[tierIdx])
		if tier != "HIGH" && tier != "NOTABLE" {
			return nil // skip LOW and BASELINE tasks
		}

		taskName := row[nameIdx]
		cmd := ""
		if cmdIdx != -1 {
			cmd = row[cmdIdx]
		}
		args := ""
		if argsIdx != -1 {
			args = row[argsIdx]
		}
		userID := ""
		if userIdx != -1 {
			userID = row[userIdx]
		}
		enabled := ""
		if enabledIdx != -1 {
			enabled = row[enabledIdx]
		}
		description := ""
		if descIdx != -1 {
			description = row[descIdx]
		}
		flags := ""
		if flagsIdx != -1 {
			flags = row[flagsIdx]
		}

		fullCmd := cmd
		if args != "" {
			fullCmd += " " + args
		}

		descStr := fmt.Sprintf("ScheduledTask %s | Cmd: %s | Enabled: %s | Flags: %s",
			taskName, fullCmd, enabled, flags)
		if description != "" {
			descStr += fmt.Sprintf(" | Description: %s", description)
		}

		// Scheduled tasks don't carry a precise creation timestamp in our output;
		// use the zero time sentinel and let the investigator note the analysis time.
		analysisTime := time.Now().UTC()
		date := analysisTime.Format("2006-01-02")
		timePart := analysisTime.Format("15:04:05.000000")

		*events = append(*events, Event{
			Date:       date,
			Time:       timePart,
			Timezone:   "UTC",
			MACB:       "...B", // Born — task registration event
			Source:     "File",
			SourceType: "ScheduledTasks",
			Type:       fmt.Sprintf("%s Task", cases.Title(language.English).String(strings.ToLower(tier))),
			User:       userID,
			Short:      fmt.Sprintf("Task: %s", filepath.Base(taskName)),
			Desc:       descStr,
			Version:    "2",
			Filename:   "tasks.csv",
			Format:     "safe",
			Extra:      fmt.Sprintf("tier=%s;enabled=%s", tier, enabled),
		})
		return nil
	})
}

// AppendBehaviorToTimeline reads the behavior_hits.csv (generated after timeline)
// and appends them to the end of timeline.csv with a futuristic date so they
// float to the top/bottom when sorted in Timeline Explorer as persistent alerts.
func AppendBehaviorToTimeline(labReportDir string) error {
	hitsPath := filepath.Join(labReportDir, "behavior_hits.csv")
	tlPath := filepath.Join(labReportDir, "timeline.csv")
	
	if _, err := os.Stat(hitsPath); os.IsNotExist(err) {
		return nil
	}

	hitsFile, err := os.Open(hitsPath)
	if err != nil {
		return err
	}
	defer hitsFile.Close()

	r := csv.NewReader(hitsFile)
	rows, err := r.ReadAll()
	if err != nil || len(rows) <= 1 {
		return err
	}

	tlFile, err := os.OpenFile(tlPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer tlFile.Close()

	w := csv.NewWriter(tlFile)
	defer w.Flush()

	// header: rule_id, severity, mitre_technique, title, evidence_source, evidence_detail
	for i, row := range rows {
		if i == 0 {
			continue // skip header
		}
		if len(row) < 6 {
			continue
		}
		
		event := Event{
			Date:       "9999-12-31", // Futuristic so it floats in analysis tools
			Time:       "23:59:59.999999",
			Timezone:   "UTC",
			MACB:       "....",
			Source:     "Behavior",
			SourceType: "DetectionEngine",
			Type:       "ALERT",
			User:       "SYSTEM",
			Short:      fmt.Sprintf("[%s] %s (%s)", row[1], row[3], row[0]), // [SEVERITY] Title (RuleID)
			Desc:       fmt.Sprintf("Evidence: %s | Source: %s | MITRE: %s", row[5], row[4], row[2]),
			Version:    "2",
			Format:     "safe",
		}
		
		// Short/Desc embed rule evidence text that echoes attacker-controlled
		// strings (task names, command lines, file paths from the compromised
		// host), so quote them exactly like Generate does for every regular
		// timeline row — otherwise these injected ALERT rows are a CSV
		// formula-injection vector when the analyst opens timeline.csv in Excel.
		_ = w.Write([]string{
			event.Date + " " + event.Time, event.Timezone, event.MACB, event.Source,
			event.SourceType, event.Type, event.User, event.Host, csvSafe(event.Short),
			csvSafe(event.Desc), event.Version, event.Filename, event.Inode, event.Notes,
			event.Format, event.Extra,
		})
	}
	return nil
}

// 14. IIS Web-Shell Access Adapter. Loads the set of script files flagged above
// INFO in web_files.csv, then injects one timeline event per request that
// reached one of them — so the shell's actual use appears at its real time. If
// no files were flagged, nothing is added (a full request log would swamp the
// timeline). web_files.csv may legitimately be absent (no web content collected),
// in which case there is nothing to correlate against and the adapter no-ops.
func processIISShellAccess(reqPath, webPath string, events *[]Event) error {
	flagged := map[string]bool{}
	_ = csvutil.ReadCSVHelper(webPath, func(header, row []string) error {
		nameIdx := csvutil.GetColIndex(header, "filename")
		triageIdx := csvutil.GetColIndex(header, "triage")
		if nameIdx == -1 || triageIdx == -1 {
			return nil
		}
		if t := strings.ToUpper(row[triageIdx]); t == "HIGH" || t == "NOTABLE" {
			flagged[strings.ToLower(row[nameIdx])] = true
		}
		return nil
	})
	if len(flagged) == 0 {
		return nil
	}

	return csvutil.ReadCSVHelper(reqPath, func(header, row []string) error {
		tsIdx := csvutil.GetColIndex(header, "datetime_utc")
		stemIdx := csvutil.GetColIndex(header, "uri_stem")
		methodIdx := csvutil.GetColIndex(header, "method")
		queryIdx := csvutil.GetColIndex(header, "uri_query")
		statusIdx := csvutil.GetColIndex(header, "protocol_status")
		clientIdx := csvutil.GetColIndex(header, "client_ip")
		uaIdx := csvutil.GetColIndex(header, "user_agent")
		hostIdx := csvutil.GetColIndex(header, "host")
		if tsIdx == -1 || stemIdx == -1 {
			return nil
		}

		stem := row[stemIdx]
		base := timelineURIBase(stem)
		if base == "" || !flagged[strings.ToLower(base)] {
			return nil
		}

		date, timePart, ok := parseTimestamp(row[tsIdx])
		if !ok {
			return nil
		}

		method := safeIndex(row, methodIdx)
		query := safeIndex(row, queryIdx)
		status := safeIndex(row, statusIdx)
		client := safeIndex(row, clientIdx)
		ua := safeIndex(row, uaIdx)
		host := safeIndex(row, hostIdx)

		*events = append(*events, Event{
			Date:       date,
			Time:       timePart,
			Timezone:   "UTC",
			MACB:       "..C.",
			Source:     "IIS",
			SourceType: "WebShellAccess",
			Type:       method,
			User:       client,
			Host:       host,
			Short:      fmt.Sprintf("Web shell hit: %s %s (%s)", method, stem, status),
			Desc:       fmt.Sprintf("Request to flagged script %s from %s (status %s, query: %s, UA: %s)", stem, client, status, query, ua),
			Version:    "2",
			Filename:   safeIndex(row, csvutil.GetColIndex(header, "source_log")),
			Format:     "safe",
			Extra:      fmt.Sprintf("client_ip=%s;status=%s", client, status),
		})
		return nil
	})
}

// timelineURIBase returns the final path segment of a request URI stem.
func timelineURIBase(stem string) string {
	stem = strings.TrimRight(stem, "/")
	if stem == "" {
		return ""
	}
	if i := strings.LastIndex(stem, "/"); i >= 0 {
		return stem[i+1:]
	}
	return stem
}

// 12. MFT CSV Adapter
func processMft(path string, events *[]Event) error {
	return csvutil.ReadCSVHelper(path, func(header []string, row []string) error {
		fileIdx := csvutil.GetColIndex(header, "filename")
		crIdx := csvutil.GetColIndex(header, "creation_time")
		modIdx := csvutil.GetColIndex(header, "modified_time")
		mftIdx := csvutil.GetColIndex(header, "mft_modified_time")
		accIdx := csvutil.GetColIndex(header, "accessed_time")

		if fileIdx == -1 {
			return nil
		}

		filename := row[fileIdx]

		addMftEvent := func(tsStr, action string) {
			if tsStr == "" { return }
			date, timeStr, ok := parseTimestamp(tsStr)
			if !ok { return }

			*events = append(*events, Event{
				Date:       date,
				Time:       timeStr,
				Timezone:   "UTC",
				MACB:       "M...", // Simplified MACB
				Source:     "FILE",
				SourceType: "mft_timeline.csv",
				Type:       action,
				User:       "-",
				Host:       "-",
				Short:      filename,
				Desc:       fmt.Sprintf("$MFT Record: %s", filename),
				Version:    "2",
			})
		}

		addMftEvent(safeIndex(row, crIdx), "File Creation")
		addMftEvent(safeIndex(row, modIdx), "File Modified")
		addMftEvent(safeIndex(row, mftIdx), "MFT Record Modified")
		addMftEvent(safeIndex(row, accIdx), "File Accessed")

		return nil
	})
}

// 13. USN CSV Adapter
func processUsn(path string, events *[]Event) error {
	return csvutil.ReadCSVHelper(path, func(header []string, row []string) error {
		tsIdx := csvutil.GetColIndex(header, "timestamp")
		fileIdx := csvutil.GetColIndex(header, "filename")
		reasonIdx := csvutil.GetColIndex(header, "reason")

		if tsIdx == -1 || fileIdx == -1 || reasonIdx == -1 {
			return nil
		}

		tsStr := row[tsIdx]
		if tsStr == "" { return nil }
		date, timeStr, ok := parseTimestamp(tsStr)
		if !ok { return nil }

		filename := row[fileIdx]
		reason := row[reasonIdx]

		var action string
		if strings.Contains(reason, "FILE_DELETE") {
			action = "File Deleted"
		} else if strings.Contains(reason, "FILE_CREATE") {
			action = "File Created"
		} else {
			action = "File Modified"
		}

		*events = append(*events, Event{
			Date:       date,
			Time:       timeStr,
			Timezone:   "UTC",
			MACB:       "M...",
			Source:     "USN",
			SourceType: "usn.csv",
			Type:       action,
			User:       "-",
			Host:       "-",
			Short:      filename,
			Desc:       fmt.Sprintf("USN Record: %s (%s)", filename, reason),
			Version:    "2",
		})
		return nil
	})
}

