package analyzer

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/evtx"
)

// EvtxParser reads collected Windows Event Log (.evtx) files from both
// the core and extended event channel modules and produces parsed CSV summaries.
//
// One CSV file is created per unique event channel (e.g. Security.csv).
// To prevent duplicate entries when both modules collect the same channel,
// file-level de-duplication is performed based on the sanitized channel name.
type EvtxParser struct{}

// Name returns the parser's identifier.
func (p *EvtxParser) Name() string { return "evtx" }

// EventDataRow represents a structured event log record.
type EventDataRow struct {
	TimeCreatedUTC string
	EventID        string
	Provider       string
	Channel        string
	Computer       string
	Level          string
	EventData      string
}

// Parse locates and processes all .evtx files in the case directory.
func (p *EvtxParser) Parse(caseDir, labReportDir string, report ProgressFunc) ([]string, ParseStats, []error) {
	stats := ParseStats{}
	var errs []error
	var outputFiles []string

	// Locate .evtx files in both collection directories.
	var evtxPaths []string

	coreGlob := filepath.Join(caseDir, "modules", "*_eventlogs_core", "*.evtx")
	coreMatches, err := filepath.Glob(coreGlob)
	if err == nil {
		evtxPaths = append(evtxPaths, coreMatches...)
	} else {
		errs = append(errs, fmt.Errorf("glob eventlogs_core: %w", err))
	}

	extendedGlob := filepath.Join(caseDir, "modules", "*_extended_event_channels", "*.evtx")
	extendedMatches, err := filepath.Glob(extendedGlob)
	if err == nil {
		evtxPaths = append(evtxPaths, extendedMatches...)
	} else {
		errs = append(errs, fmt.Errorf("glob extended_event_channels: %w", err))
	}

	if len(evtxPaths) == 0 {
		return nil, stats, errs
	}

	// Create output sub-directory.
	outDir := filepath.Join(labReportDir, "evtx")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, stats, append(errs, fmt.Errorf("create output dir: %w", err))
	}

	processedChannels := make(map[string]bool)
	parsedFilesCount := 0
	skippedFilesCount := 0 // channels de-duplicated or legitimately empty
	failedFilesCount := 0  // genuine parse failures (surfaced in errs too)
	totalChunkErrors := 0  // corrupted chunks skipped within otherwise-parsed files
	totalEventsParsed := 0

	for i, path := range evtxPaths {
		if report != nil {
			report(i, len(evtxPaths))
		}

		filename := filepath.Base(path)
		cleanName := cleanChannelName(filename)

		if processedChannels[cleanName] {
			skippedFilesCount++
			continue
		}

		rows, chunkErrors, err := parseEvtxFile(path)
		totalChunkErrors += chunkErrors
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", filename, err))
			failedFilesCount++
			continue
		}

		if len(rows) == 0 {
			skippedFilesCount++
			continue
		}

		csvPath := filepath.Join(outDir, cleanName+".csv")
		if err := writeRowsToCSV(csvPath, rows); err != nil {
			errs = append(errs, fmt.Errorf("write csv for %s: %w", cleanName, err))
			skippedFilesCount++
			continue
		}

		processedChannels[cleanName] = true
		outputFiles = append(outputFiles, csvPath)
		parsedFilesCount++
		totalEventsParsed += len(rows)
	}

	stats["evtx_files_parsed"] = parsedFilesCount
	stats["evtx_files_skipped"] = skippedFilesCount
	stats["evtx_files_failed"] = failedFilesCount
	stats["evtx_chunk_parse_errors"] = totalChunkErrors
	stats["total_events_parsed"] = totalEventsParsed

	return outputFiles, stats, errs
}

// cleanChannelName normalizes an EVTX filename to a safe, unique channel identifier
// for use as a CSV filename stem.
//
// The Windows Event Log service encodes the '/' separator in a channel's path
// as the literal two-character token "%4" when naming the .evtx file on disk —
// this is a fixed legacy substitution, not generic %XX percent-encoding, so the
// token is always exactly two characters ('%' then '4'):
//
//	Microsoft-Windows-Kernel-PnP%4Configuration.evtx
//	  → Microsoft-Windows-Kernel-PnP_Configuration
//
// Confirmed against real Windows Server 2022 extended-channel collection
// (AAD%4Operational, DNSServer%4Audit, SMBServer%4Security, etc.) — treating
// this as a %XX two-hex-digit token instead consumes the first character of
// the following segment (e.g. producing "_perational" instead of
// "_Operational").
func cleanChannelName(filename string) string {
	name := strings.TrimSuffix(filename, filepath.Ext(filename))
	name = strings.ReplaceAll(name, "%4", "_")
	// Also replace path separators that slipped through.
	name = strings.NewReplacer("/", "_", "\\", "_", ":", "_").Replace(name)
	return name
}

// parseEvtxFile reads a single .evtx file and extracts event rows. It returns
// the rows, the number of chunks that failed to parse (a partial-corruption
// signal — the good chunks are still returned), and a hard error.
//
// evtx.GetChunks returns a non-nil error ONLY for genuine file-level failures —
// a header that can't be read (truncated file), a wrong magic, or an unsupported
// EVTX version. A valid file that simply has no chunk data (a channel that never
// fired) returns an empty slice with a nil error. So any error from GetChunks is
// a real parse failure and must be surfaced — treating it as "zero rows" would
// make a corrupted or deliberately tampered log indistinguishable from a channel
// that legitimately never fired, which is a meaningful blind spot given that
// clearing/corrupting an event log is a known anti-forensic technique.
func parseEvtxFile(path string) ([]EventDataRow, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	chunks, err := evtx.GetChunks(f)
	if err != nil {
		return nil, 0, fmt.Errorf("get chunks: %w", err)
	}
	if len(chunks) == 0 {
		return nil, 0, nil // valid file, no chunk data — zero rows, not an error
	}

	var rows []EventDataRow
	chunkErrors := 0
	for _, chunk := range chunks {
		records, err := chunk.Parse(int(chunk.Header.FirstEventRecID))
		if err != nil {
			// A corrupted chunk (e.g. a partially wiped log) — count it so the
			// loss is visible in stats, and continue with the other chunks.
			chunkErrors++
			continue
		}
		for _, rec := range records {
			if rec.Event == nil {
				continue
			}
			dict, ok := rec.Event.(*ordereddict.Dict)
			if !ok {
				continue
			}

			rows = append(rows, EventDataRow{
				TimeCreatedUTC: getTimeCreated(dict),
				EventID:        getEventID(dict),
				Provider:       getProvider(dict),
				Channel:        getChannel(dict),
				Computer:       getComputer(dict),
				Level:          getLevel(dict),
				EventData:      getEventData(dict),
			})
		}
	}
	return rows, chunkErrors, nil
}

// writeRowsToCSV writes the parsed rows into the target CSV file.
func writeRowsToCSV(csvPath string, rows []EventDataRow) error {
	f, err := os.Create(csvPath)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	header := []string{
		"time_created_utc",
		"event_id",
		"provider",
		"channel",
		"computer",
		"level",
		"event_data",
	}
	if err := w.Write(header); err != nil {
		return err
	}

	for _, row := range rows {
		csvRow := []string{
			row.TimeCreatedUTC,
			row.EventID,
			csvSafe(row.Provider),
			csvSafe(row.Channel),
			csvSafe(row.Computer),
			row.Level,
			csvSafe(row.EventData),
		}
		if err := w.Write(csvRow); err != nil {
			return err
		}
	}

	w.Flush()
	return w.Error()
}

// getEventID extracts EventID safely from the record's System dict.
func getEventID(dict *ordereddict.Dict) string {
	val, ok := ordereddict.GetAny(dict, "Event.System.EventID")
	if !ok {
		return ""
	}
	switch v := val.(type) {
	case float64:
		return fmt.Sprintf("%.0f", v)
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case string:
		return v
	case *ordereddict.Dict:
		if value, found := v.Get("Value"); found {
			switch val2 := value.(type) {
			case float64:
				return fmt.Sprintf("%.0f", val2)
			case int:
				return strconv.Itoa(val2)
			case int64:
				return strconv.FormatInt(val2, 10)
			case string:
				return val2
			default:
				return fmt.Sprintf("%v", val2)
			}
		}
	}
	return fmt.Sprintf("%v", val)
}

// getTimeCreated extracts TimeCreated SystemTime as UTC timestamp.
func getTimeCreated(dict *ordereddict.Dict) string {
	val, ok := ordereddict.GetAny(dict, "Event.System.TimeCreated.SystemTime")
	if !ok {
		return ""
	}
	switch v := val.(type) {
	case float64:
		sec := int64(v)
		nsec := int64((v - float64(sec)) * 1e9)
		t := time.Unix(sec, nsec).UTC()
		return t.Format(time.RFC3339Nano)
	case string:
		return v
	case int64:
		return time.Unix(v, 0).UTC().Format(time.RFC3339Nano)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// getProvider extracts Provider Name from the record's System dict.
func getProvider(dict *ordereddict.Dict) string {
	val, ok := ordereddict.GetAny(dict, "Event.System.Provider")
	if !ok {
		return ""
	}
	switch v := val.(type) {
	case string:
		return v
	case *ordereddict.Dict:
		if name, found := v.GetString("Name"); found {
			return name
		}
		if name, found := v.Get("Name"); found {
			return fmt.Sprintf("%v", name)
		}
	}
	return fmt.Sprintf("%v", val)
}

// getChannel extracts Channel from the record's System dict.
func getChannel(dict *ordereddict.Dict) string {
	val, ok := ordereddict.GetString(dict, "Event.System.Channel")
	if ok {
		return val
	}
	val2, ok2 := ordereddict.GetAny(dict, "Event.System.Channel")
	if ok2 {
		return fmt.Sprintf("%v", val2)
	}
	return ""
}

// getComputer extracts Computer from the record's System dict.
func getComputer(dict *ordereddict.Dict) string {
	val, ok := ordereddict.GetString(dict, "Event.System.Computer")
	if ok {
		return val
	}
	val2, ok2 := ordereddict.GetAny(dict, "Event.System.Computer")
	if ok2 {
		return fmt.Sprintf("%v", val2)
	}
	return ""
}

// getLevel extracts Level from the record's System dict.
func getLevel(dict *ordereddict.Dict) string {
	val, ok := ordereddict.GetAny(dict, "Event.System.Level")
	if !ok {
		return ""
	}
	switch v := val.(type) {
	case float64:
		return fmt.Sprintf("%.0f", v)
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case uint8:
		return strconv.Itoa(int(v))
	default:
		return fmt.Sprintf("%v", v)
	}
}

// getEventData serializes EventData or UserData map as a JSON string.
func getEventData(dict *ordereddict.Dict) string {
	if eventDataVal, ok := ordereddict.GetAny(dict, "Event.EventData"); ok && eventDataVal != nil {
		if bytes, err := json.Marshal(eventDataVal); err == nil {
			return string(bytes)
		}
	}
	if userDataVal, ok := ordereddict.GetAny(dict, "Event.UserData"); ok && userDataVal != nil {
		if bytes, err := json.Marshal(userDataVal); err == nil {
			return string(bytes)
		}
	}
	return ""
}
