package analyzer

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// IISLogParser reads IIS artifacts collected by the iis_collection module and
// produces two lab-report CSVs:
//
//   - iis/iis_requests.csv — every request line from the collected W3C Extended
//     Log Format files, normalized to a fixed column set regardless of which
//     #Fields each site logged. This is the raw request record an analyst pivots
//     on in the Artifact Explorer.
//   - iis/web_files.csv — every script file collected from the site web roots,
//     with a SHA-256 and a lab-side content scan for web-shell indicators. This
//     is where the web-shell hunt starts: a script in a web root carrying shell
//     tokens is the strongest single web-compromise artifact.
//
// Consistent with the collection/analysis separation (architecture principle
// #1), the on-target collector only copies raw bytes; all interpretation —
// parsing the log grammar, scanning file content for attacker tokens — happens
// here in the lab. Naming attacker techniques (web shells, LOLBins) is detection
// vocabulary, exactly as in the behavioral rules that consume these CSVs.
type IISLogParser struct{}

func (p *IISLogParser) Name() string { return "iis" }

// normalizedRequestColumns is the fixed output schema for iis_requests.csv. W3C
// logs declare their own column set per file via a #Fields directive and it can
// differ between sites (or even change mid-file), so every row is projected onto
// this stable schema; a field a given log did not record is emitted empty. The
// behavioral IIS rules read these exact column names.
var normalizedRequestColumns = []string{
	"datetime_utc",
	"site",
	"server_ip",
	"server_port",
	"method",
	"uri_stem",
	"uri_query",
	"protocol_status",
	"substatus",
	"win32_status",
	"bytes_sent",
	"bytes_received",
	"time_taken_ms",
	"client_ip",
	"username",
	"user_agent",
	"referer",
	"host",
	"source_log",
}

// w3cFieldMap translates a W3C field token (as it appears after #Fields:) to the
// normalized column it feeds. The "date" and "time" tokens are handled
// separately because two source fields compose the single datetime_utc column.
// Anything not mapped here is ignored for the normalized view — the raw log file
// itself is still collected and hashed.
var w3cFieldMap = map[string]string{
	"s-sitename":      "site",
	"s-ip":            "server_ip",
	"s-port":          "server_port",
	"cs-method":       "method",
	"cs-uri-stem":     "uri_stem",
	"cs-uri-query":    "uri_query",
	"sc-status":       "protocol_status",
	"sc-substatus":    "substatus",
	"sc-win32-status": "win32_status",
	"sc-bytes":        "bytes_sent",
	"cs-bytes":        "bytes_received",
	"time-taken":      "time_taken_ms",
	"c-ip":            "client_ip",
	"cs-username":     "username",
	"cs(user-agent)":  "user_agent",
	"cs(referer)":     "referer",
	"cs-host":         "host",
	"cs(host)":        "host",
}

func (p *IISLogParser) Parse(caseDir, labReportDir string, report ProgressFunc) ([]string, ParseStats, []error) {
	stats := ParseStats{}

	root := firstGlob(caseDir, filepath.Join("modules", "*_iis_collection"))
	if root == "" {
		// No IIS collection in this case — legitimately produce nothing.
		return nil, stats, nil
	}

	outDir := filepath.Join(labReportDir, "iis")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, nil, []error{fmt.Errorf("create iis output dir: %w", err)}
	}

	var outputs []string
	var errs []error

	if out, n, perr := p.parseRequests(root, outDir, report); len(perr) > 0 {
		errs = append(errs, perr...)
		if out != "" {
			outputs = append(outputs, out)
			stats["requests"] = n
		}
	} else if out != "" {
		outputs = append(outputs, out)
		stats["requests"] = n
	}

	if out, n, scored, perr := p.scanWebFiles(root, outDir); len(perr) > 0 {
		errs = append(errs, perr...)
		if out != "" {
			outputs = append(outputs, out)
			stats["web_files"] = n
			stats["web_files_flagged"] = scored
		}
	} else if out != "" {
		outputs = append(outputs, out)
		stats["web_files"] = n
		stats["web_files_flagged"] = scored
	}

	return outputs, stats, errs
}

// parseRequests walks every *.log under the collection output and writes the
// normalized iis_requests.csv. Rows are streamed straight to the writer so a
// large log set never has to be held in memory. Returns the output path (or ""
// when no request rows were produced) and the row count.
func (p *IISLogParser) parseRequests(root, outDir string, report ProgressFunc) (string, int, []error) {
	logFiles := findFilesByExt(root, ".log")
	if len(logFiles) == 0 {
		return "", 0, nil
	}

	csvPath := filepath.Join(outDir, "iis_requests.csv")
	f, err := os.Create(csvPath)
	if err != nil {
		return "", 0, []error{fmt.Errorf("create iis_requests.csv: %w", err)}
	}

	w := csv.NewWriter(f)
	if err := w.Write(normalizedRequestColumns); err != nil {
		f.Close()
		return "", 0, []error{fmt.Errorf("write header: %w", err)}
	}

	var errs []error
	total := 0
	for i, lf := range logFiles {
		if report != nil {
			report(i, len(logFiles))
		}
		n, perr := parseOneW3CLog(lf, w)
		total += n
		if perr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", filepath.Base(lf), perr))
		}
	}

	w.Flush()
	if werr := w.Error(); werr != nil {
		errs = append(errs, fmt.Errorf("flush iis_requests.csv: %w", werr))
	}
	f.Close()

	if total == 0 {
		// Logs existed but yielded no parseable request rows — don't leave an
		// empty CSV behind (matches the prefetch parser's behavior).
		_ = os.Remove(csvPath)
		return "", 0, errs
	}
	return csvPath, total, errs
}

// parseOneW3CLog parses a single W3C Extended Log Format file and writes one
// normalized row per request line. The #Fields directive defines the column
// order and may appear more than once in a file (IIS re-emits the header block
// whenever logging is reconfigured), so the active layout is rebuilt each time a
// #Fields line is seen.
func parseOneW3CLog(path string, w *csv.Writer) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	source := filepath.Base(path)
	sc := bufio.NewScanner(f)
	// W3C rows are short, but a cs(Cookie) field can be long; grow the buffer so
	// a legitimately long line is not truncated into a parse error.
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	// For the active #Fields layout:
	//   colToNorm[i] — normalized column field i feeds, or "" to ignore.
	//   dateIdx/timeIdx — indices of the raw "date"/"time" fields, or -1.
	var colToNorm []string
	dateIdx, timeIdx := -1, -1
	haveFields := false
	count := 0

	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		if line[0] == '#' {
			if strings.HasPrefix(strings.ToLower(line), "#fields:") {
				fields := strings.Fields(line[len("#Fields:"):])
				colToNorm = make([]string, len(fields))
				dateIdx, timeIdx = -1, -1
				for i, fld := range fields {
					lf := strings.ToLower(fld)
					switch lf {
					case "date":
						dateIdx = i
					case "time":
						timeIdx = i
					default:
						colToNorm[i] = w3cFieldMap[lf]
					}
				}
				haveFields = true
			}
			continue
		}
		if !haveFields {
			continue // data before any #Fields — cannot map it
		}

		parts := strings.Fields(line)
		if len(parts) != len(colToNorm) {
			// Field-count mismatch (a corrupt or partially-written trailing
			// line). Skip rather than emit a misaligned row.
			continue
		}

		vals := make(map[string]string, len(normalizedRequestColumns))
		for i, raw := range parts {
			if colToNorm[i] == "" {
				continue
			}
			if raw == "-" {
				continue
			}
			vals[colToNorm[i]] = raw
		}

		date := fieldValue(parts, dateIdx)
		tm := fieldValue(parts, timeIdx)
		vals["datetime_utc"] = combineW3CDateTime(date, tm)
		vals["source_log"] = source

		row := make([]string, len(normalizedRequestColumns))
		for i, col := range normalizedRequestColumns {
			row[i] = csvSafe(vals[col])
		}
		if err := w.Write(row); err != nil {
			return count, err
		}
		count++
	}
	if err := sc.Err(); err != nil {
		return count, err
	}
	return count, nil
}

// fieldValue returns parts[idx] with the W3C empty marker ("-") normalized to
// "", or "" when idx is out of range.
func fieldValue(parts []string, idx int) string {
	if idx < 0 || idx >= len(parts) {
		return ""
	}
	if parts[idx] == "-" {
		return ""
	}
	return parts[idx]
}

// combineW3CDateTime joins the W3C "date" (YYYY-MM-DD) and "time" (HH:MM:SS,
// UTC) fields into an RFC3339 timestamp the supertimeline and rules understand.
// Returns "" when either component is missing or unparseable.
func combineW3CDateTime(date, tm string) string {
	if date == "" || tm == "" {
		return ""
	}
	t, err := time.Parse("2006-01-02 15:04:05", date+" "+tm)
	if err != nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// findFilesByExt returns every regular file under root whose name ends with ext
// (case-insensitive), sorted for deterministic output.
func findFilesByExt(root, ext string) []string {
	var out []string
	extLower := strings.ToLower(ext)
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(info.Name()), extLower) {
			out = append(out, path)
		}
		return nil
	})
	sort.Strings(out)
	return out
}
